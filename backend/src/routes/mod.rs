//! Router assembly — the single auth chokepoint (BACK-01, CAUTH-06, CAUTH-05).
//!
//! Two subtrees hang off a root that injects shared state into every `Depot`:
//!
//! - **PUBLIC** (NO auth hoop): `GET /`, `GET /health`, `GET /api/console/state`,
//!   `POST /setup` (rate-limit + uninitialized + origin hoops), `POST /login`
//!   (rate-limit + origin hoops). GitHub routes attach here in Plan 02-04 via
//!   the `attach_github` extension point when `cfg.github.is_some()`.
//! - **PROTECTED** (`auth_guard` then `csrf_guard` hoops): `POST /logout`,
//!   `GET /api/console/me`. Phase 3+ Ory wrapper routes mount here.
//!
//! Pitfall 7: the rate-limit hoop is ONLY on the pre-auth endpoints; the
//! auth+csrf hoops are ONLY on the protected subtree.
//!
//! Rate limit quota: **10 requests/min per connection IP** (Claude's discretion,
//! CONTEXT 5-10/min) keyed off the DIRECT connection IP. `X-Forwarded-For` is
//! deliberately NOT trusted (threat T-02-23 / Pitfall 7) — a future reverse
//! proxy phase must revisit this.

pub mod state;

use std::net::{IpAddr, Ipv4Addr};

use salvo::affix_state;
use salvo::prelude::*;
use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter};
use salvo::Handler;
use sqlx::PgPool;

use crate::auth::github;
use crate::auth::login;
use crate::auth::middleware::{auth_guard, csrf_guard};
use crate::auth::setup;
use crate::config::Config;

/// Per-connection-IP rate quota for the pre-auth endpoints (CONTEXT 5-10/min).
const RATE_PER_MINUTE: usize = 10;

/// Sentinel key used when the direct connection IP is unavailable (e.g. the
/// in-process `TestClient`, which leaves `remote_addr` as `Unknown`). Keying all
/// such requests to one bucket keeps the limiter functional (and testable)
/// instead of `RemoteIpIssuer`'s behavior of rejecting an un-keyable request
/// with a 400. Real over-TCP requests always carry a connection IP.
const FALLBACK_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Liveness/readiness probe. Public — no auth hoop (CAUTH-06 public set).
#[handler]
async fn health(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(serde_json::json!({ "status": "ok" })));
}

/// Root placeholder so a manual `GET /` does not 404 during smoke checks.
#[handler]
async fn index() -> &'static str {
    "ory-console-backend: ok"
}

/// Extract the request origin: the `Origin` header, falling back to the origin
/// (scheme://host[:port]) parsed out of `Referer`. Returns `None` if neither is
/// present.
fn request_origin(req: &Request) -> Option<String> {
    if let Some(origin) = req.header::<String>("origin") {
        if !origin.is_empty() && origin != "null" {
            return Some(origin);
        }
    }
    // Referer fallback: keep only scheme://host[:port] (strip path/query).
    let referer = req.header::<String>("referer")?;
    let after_scheme = referer.find("://")? + 3;
    let rest = &referer[after_scheme..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    Some(format!("{}{}", &referer[..after_scheme], &rest[..host_end]))
}

/// Pre-session Origin allowlist hoop (Plan-checker Warning 2). Mounted on the
/// pre-auth state-changing endpoints (`/setup`, `/login`, and the GitHub
/// callback in Plan 04) where a per-session CSRF token cannot yet exist. Rejects
/// a request whose `Origin`/`Referer` origin is not in the configured allowlist
/// with 403. An EMPTY allowlist disables the check (documented dev posture).
#[handler]
pub async fn origin_guard(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let cfg = match depot.obtain::<Config>() {
        Ok(c) => c.clone(),
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            ctrl.skip_rest();
            return;
        }
    };

    // IN-04 (secure-by-default): the check is fully disabled ONLY under the dev
    // escape hatch (empty allowlist AND CONSOLE_INSECURE_COOKIES). In the
    // production posture an empty allowlist no longer means "allow any" — a
    // present cross-site Origin is rejected by `origin_allowed`.
    if cfg.origin_check_disabled() {
        return;
    }

    let allowed = match request_origin(req) {
        // A cross-site browser form post always sends an Origin; with the check
        // enabled it must be in the allowlist (fail-closed for browser CSRF).
        Some(origin) => cfg.origin_allowed(&origin),
        // An ABSENT Origin is an API client or a same-origin post that omits it
        // (browsers do not send Origin for same-origin GET/navigations, and many
        // omit it for same-origin POSTs). Allowing it preserves first-run /setup
        // from a server-side client / curl; cross-site browser CSRF is what
        // always carries an Origin and is what we block.
        None => true,
    };

    if !allowed {
        res.status_code(StatusCode::FORBIDDEN);
        res.render(Json(serde_json::json!({ "error": "forbidden_origin" })));
        ctrl.skip_rest();
    }
}

/// Construct a fresh rate limiter for one pre-auth route. Keyed by the direct
/// connection IP (XFF NOT trusted); falls back to a single bucket when the IP is
/// unknown so the limiter still functions under the test transport.
///
/// WR-01 (KNOWN LIMITATION — documented, NOT silently mitigated): under the
/// shipped docker-compose topology the backend observes the connecting peer's
/// IP, which behind Docker's published-port NAT / userland proxy is commonly the
/// bridge GATEWAY IP rather than the real external client. When that happens this
/// per-IP limiter collapses toward a SINGLE shared bucket for all externally
/// originated traffic — so it bounds total pre-auth request volume but does not
/// isolate per-attacker. We deliberately do NOT trust `X-Forwarded-For` to
/// compensate (a forgeable header would let an attacker mint unlimited buckets
/// and defeat the limit entirely). The correct fix is a vetted reverse proxy
/// that sets a TRUSTED forwarded header, keyed off ONLY when the immediate peer
/// is the known proxy — revisit when such a proxy + XFF trust policy is
/// configured (documented in the README threat model). Until then the limiter is
/// a global brute-force throttle, complemented by the one-time setup token and
/// constant-time credential checks.
fn pre_auth_limiter() -> impl Handler {
    let store: MokaStore<IpAddr, FixedGuard> = MokaStore::default();
    RateLimiter::new(
        FixedGuard::default(),
        store,
        // Closure issuer (blanket `RateIssuer` impl): direct connection IP, or
        // the fallback sentinel when unavailable. We never read X-Forwarded-For.
        |req: &mut Request, _: &Depot| Some(req.remote_addr().ip().unwrap_or(FALLBACK_IP)),
        BasicQuota::per_minute(RATE_PER_MINUTE),
    )
}

/// GitHub OAuth route extension point (CAUTH-04). Conditionally pushes
/// `GET /auth/github/login` + `GET /auth/github/callback` onto the public
/// subtree ONLY when `cfg.github.is_some()`. When GitHub is unconfigured the
/// router is returned UNCHANGED, so the routes do not exist and a request 404s
/// (and `GET /api/console/state` reports `github_oauth_enabled:false`).
///
/// The callback carries a rate-limit hoop (Pitfall 7 — pre-auth, attacker-
/// reachable). It does NOT carry the pre-session `origin_guard`: the request is
/// a top-level GET navigation arriving FROM github.com (no same-origin Origin
/// header), and OAuth CSRF is instead defended by the constant-time `state`
/// nonce verified inside the handler (T-02-30). Adding the origin guard here
/// would reject every legitimate GitHub redirect.
pub fn attach_github(public: Router, cfg: &Config) -> Router {
    if cfg.github.is_some() {
        public
            .push(Router::with_path("auth/github/login").get(github::github_login))
            .push(
                Router::with_path("auth/github/callback")
                    .hoop(pre_auth_limiter())
                    .get(github::github_callback),
            )
    } else {
        public
    }
}

/// Build the application router (RESEARCH Pattern 5).
pub fn build(pool: PgPool, cfg: Config) -> Router {
    // PUBLIC subtree — no auth hoop (CAUTH-06 public set).
    let mut public = Router::new()
        .push(Router::with_path("health").get(health))
        .push(
            // WR-06: the first-run `initialized` signal is needed by the frontend
            // redirect, so the endpoint stays public and the body stays minimal
            // (`{initialized, github_oauth_enabled}` — no token/secret). To keep
            // the uninitialized-window signal from being cheaply polled, the same
            // pre-auth rate limiter as /setup,/login is applied.
            Router::with_path("api/console/state")
                .hoop(pre_auth_limiter())
                .get(state::console_state),
        )
        .push(
            // POST /setup: rate-limit -> uninitialized 404 guard -> origin -> handler.
            Router::with_path("setup")
                .hoop(pre_auth_limiter())
                .hoop(setup::require_uninitialized)
                .hoop(origin_guard)
                .post(setup::setup),
        )
        .push(
            // POST /login: rate-limit -> origin -> handler.
            Router::with_path("login")
                .hoop(pre_auth_limiter())
                .hoop(origin_guard)
                .post(login::login),
        );
    // GitHub routes (Plan 02-04 fills this in when env-configured).
    public = attach_github(public, &cfg);

    // PROTECTED subtree — the single auth chokepoint + per-session CSRF guard.
    let protected = Router::new()
        .hoop(auth_guard)
        .hoop(csrf_guard)
        .push(Router::with_path("logout").post(login::logout))
        .push(Router::with_path("api/console/me").get(state::me));

    // Phase 3 (BACK-02): build the Ory Admin clients from Config BEFORE cfg is
    // moved into the affix_state hoop, then inject them into every Depot
    // alongside the pool + config (RESEARCH Pattern 2). Handlers obtain them with
    // `depot.obtain::<OryClients>()`. Wrapper routes mount in Plan 02.
    let ory_clients = crate::ory::clients::OryClients::from_config(&cfg);

    // Root: inject shared state, then the public index + both subtrees.
    Router::new()
        .hoop(affix_state::inject(pool).inject(cfg).inject(ory_clients))
        .get(index)
        .push(public)
        .push(protected)
}
