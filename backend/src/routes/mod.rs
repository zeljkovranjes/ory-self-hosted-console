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

/// Phase 12 (FLAG-01) keystone probe handler. A trivial 200 JSON behind the
/// `FeatureFlagHoop::new("saml")` gate. When `saml` is OFF (the seeded default)
/// the hoop 404s before this ever runs; when ON it returns 200 — that pair is the
/// full FLAG-01 proof. It carries NO logic of its own and touches no Ory service
/// (preserving the v1 no-direct-Ory invariant).
#[handler]
async fn feature_probe(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(serde_json::json!({ "probe": "ok" })));
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
    // WR-03: parse with `url::Url` (already a dependency) instead of hand-rolled
    // byte-index slicing. An attacker controls `Referer` on the unauthenticated
    // `/setup` + `/login` hoop, so a malformed/multibyte value must never panic
    // (Rust string slicing panics on a non-char-boundary index) or mis-parse —
    // `url::Url` reconstructs the origin from validated components safely.
    let referer = req.header::<String>("referer")?;
    let url = url::Url::parse(&referer).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
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
///
/// Phase 12 (FLAG-01): `flags` is the boot-loaded in-process feature-flag cache,
/// injected into every `Depot` (alongside the pool/cfg/clients) so the
/// `FeatureFlagHoop` on the protected subtree can read it. The cache is loaded in
/// `main.rs` AFTER migrate and BEFORE serve (Pitfall 5) so no gated route is ever
/// reachable with an empty cache.
pub fn build(
    pool: PgPool,
    cfg: Config,
    flags: crate::features::FeatureFlags,
) -> Result<Router, crate::error::AppError> {
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
    //
    // Phase 11 (ACT-04 / WR-05): the audit hoop runs FIRST, AHEAD of auth_guard +
    // csrf_guard. It is a RESPONSE-PHASE hoop (`ctrl.call_next` first), so it still
    // wraps every downstream handler AND both guards, then records the FINAL
    // outcome. This is the WR-05 fix: when `auth_guard` (401) or `csrf_guard` (403)
    // calls `skip_rest()`, control unwinds back THROUGH the audit hoop (which sits
    // above them), so a REJECTED state-changing attempt — failed auth, missing/
    // forged CSRF token — is still recorded with `outcome:"failure"`. The actor is
    // read best-effort from the Depot `Session`: on a 401 the session was never
    // injected, so actor_id is NULL (never fabricated, T-11-14); on a 403 CSRF
    // failure the session IS present (auth_guard ran first inside call_next), so the
    // probing actor is captured. GET/HEAD/OPTIONS are still not audited. The insert
    // is best-effort and never blocks or fails the user-facing response.
    let protected = Router::new()
        .hoop(crate::audit::audit_hoop)
        .hoop(auth_guard)
        .hoop(csrf_guard)
        .push(Router::with_path("logout").post(login::logout))
        .push(Router::with_path("api/console/me").get(state::me))
        // Phase 11 (ACT-04 / PROJ-01 / ACT-03): console-OWNED read views. All
        // inherit `auth_guard` (401 unauth) and are GET-only (csrf-exempt).
        //   - audit: read-only, append-only log view (NO create/edit/delete route,
        //     T-11-13). Written only by the response-phase audit hoop above.
        //   - overview: version + health aggregation for all four services; an
        //     unreachable service yields reachable:false, never a 500 (PROJ-01).
        //   - activity: derived recent-activity (sessions + courier), no new
        //     persistence (ACT-03 v1).
        .push(Router::with_path("api/console/audit").get(crate::audit::routes::list_audit))
        .push(Router::with_path("api/overview").get(crate::overview::get_overview))
        .push(Router::with_path("api/activity").get(crate::activity::get_activity))
        // Phase 11 (PROJ-02 / PROJ-04): console API keys + members. API keys are
        // ONE-WAY SHA-256 hashed at rest (raw shown once on issue, masked on list,
        // revoke flips revoked_at) — the INVERSE of the recoverable webhook secret
        // (T-11-11). Members lists console operator accounts mapped to a secret-
        // free DTO (no password_hash, T-11-12); multiple operators permitted (the
        // single-admin guard was dropped in 11-01). Issue/revoke are state changes
        // (csrf_guard 403, T-11-17); list + members are GET (csrf-exempt). The
        // most-specific `{id}/revoke` path is mounted FIRST so it is not captured
        // by the broader `api-keys` match.
        .push(
            Router::with_path("api/console/api-keys/{id}/revoke")
                .post(crate::apikeys::routes::revoke_api_key), // PROJ-02 revoke (CSRF-guarded)
        )
        .push(
            Router::with_path("api/console/api-keys")
                .get(crate::apikeys::routes::list_api_keys) // PROJ-02 list (masked)
                .post(crate::apikeys::routes::issue_api_key), // PROJ-02 issue (one-time reveal)
        )
        .push(Router::with_path("api/console/members").get(crate::members::list_members))
        // Phase 12 (FLAG-02 / FLAG-04): feature-flag MANAGEMENT routes. These
        // read/toggle flags and are therefore NEVER themselves FeatureFlagHoop-
        // gated. Both inherit auth_guard (401); the PUT inherits csrf_guard (403)
        // and is auto-audited by the response-phase audit_hoop. The most-specific
        // `{key}` path is mounted FIRST (mirrors the api-keys `{id}/revoke`-before-
        // `api-keys` ordering) so it is not captured by the broader match.
        .push(
            Router::with_path("api/console/features/{key}")
                .put(crate::features::routes::set_feature), // FLAG-04 toggle (CSRF-guarded, audited)
        )
        .push(
            Router::with_path("api/console/features")
                .get(crate::features::routes::list_features), // FLAG-02 read (seeded set + meta)
        )
        // Phase 12 (FLAG-01): the KEYSTONE gated probe. A minimal self-contained
        // route mounted INSIDE the protected subtree (so it sits AFTER the
        // audit/auth/csrf hoops) and gated by FeatureFlagHoop::new("saml") — which
        // is seeded OFF. A request reaching it has ALREADY passed auth_guard (valid
        // session) and csrf_guard (valid CSRF), yet a flag-OFF still 404s: that
        // ordering IS the FLAG-01 security guarantee. This probe is the permanent
        // keystone-test anchor; later phases mount real feature routes against the
        // same hoop. GET + POST so the keystone test can prove the gate beats BOTH
        // a csrf-exempt read and a csrf-guarded state change.
        .push(
            Router::with_path("api/features/_probe")
                .hoop(crate::features::FeatureFlagHoop::new("saml"))
                .get(feature_probe)
                .post(feature_probe),
        )
        // Phase 3 (BACK-02) Ory Admin proof wrappers. GET-only, so `csrf_guard`
        // auto-exempts them; they inherit `auth_guard` (401 when unauthenticated)
        // by sitting on this protected subtree. Thin pass-throughs to the typed
        // per-service crates — full CRUD is deferred to phases 6/8/9.
        // Phase 6 (IDENT-01/02/04) Kratos identity data path. All inherit
        // `auth_guard` (401 unauth); GET is csrf-exempt, while POST/PUT/DELETE
        // require `X-CSRF-Token` via `csrf_guard` (Pitfall 7 — `lib/api.ts`
        // echoes it, no new wiring). List replaces the Phase-3 first-page proof
        // with the Link-header keyset cursor; import is the CLI-compatible
        // bulk-import endpoint (bare-array -> batch wrapper, 1000/200 limits).
        .push(
            Router::with_path("api/kratos/identities")
                .get(crate::ory::kratos::list_identities) // IDENT-01 list (cursor)
                .post(crate::ory::kratos::create_identity), // IDENT-02 create
        )
        .push(
            Router::with_path("api/kratos/identities/import")
                .post(crate::ory::kratos::batch_import), // IDENT-04 bulk import
        )
        .push(
            Router::with_path("api/kratos/identities/{id}")
                .get(crate::ory::kratos::get_identity) // IDENT-01 detail
                .put(crate::ory::kratos::update_identity) // IDENT-02 update (state required)
                .delete(crate::ory::kratos::delete_identity), // IDENT-02 delete
        )
        // Phase 10 (ACT-01 / ACT-02) Kratos Activity data path: sessions
        // (list/detail/single-session revoke) + courier messages (list/detail,
        // read-only). All inherit `auth_guard` (401 unauth); GET (list/detail) is
        // csrf-exempt, while the session-revoke DELETE requires `X-CSRF-Token` via
        // `csrf_guard` (T-10-revoke — `lib/api.ts` echoes it, no new wiring).
        // Revoke calls `disable_session` (single-session deactivate), NEVER the
        // all-sessions delete (Pitfall 4). Courier is read-only — list + get only.
        .push(
            Router::with_path("api/kratos/sessions")
                .get(crate::ory::kratos::list_sessions), // ACT-01 list (active filter + cursor)
        )
        .push(
            Router::with_path("api/kratos/sessions/{id}")
                .get(crate::ory::kratos::get_session) // ACT-01 detail (identity + devices)
                .delete(crate::ory::kratos::disable_session), // ACT-01 revoke (CSRF-guarded)
        )
        .push(
            Router::with_path("api/kratos/courier/messages")
                .get(crate::ory::kratos::list_courier_messages), // ACT-02 list (status/recipient)
        )
        .push(
            Router::with_path("api/kratos/courier/messages/{id}")
                .get(crate::ory::kratos::get_courier_message), // ACT-02 detail (read-only)
        )
        // Phase 10 (BRAND-03) console-OWNED branding asset store. This is a
        // [CUSTOM] concern: it makes NO Ory call and never touches any service
        // YAML (T-10-14 / CONTEXT invariant) — the console stores its own shell
        // logo on the mounted console-data volume. All inherit `auth_guard` (401
        // unauth); the state-changing POST (upload) + DELETE (reset) require
        // `X-CSRF-Token` via `csrf_guard` (403, T-10-12 — `lib/api.ts` echoes it),
        // while the GET serve/settings are csrf-exempt. The upload handler is
        // hardened: size cap before read (T-10-10), magic-byte sniff not the
        // spoofable content-type (T-10-upload), a SERVER-DEFINED canonical path so
        // the client filename can never traverse (T-10-09), and the serve route
        // pins the content-type + a CSP sandbox so a stored SVG cannot run script
        // (T-10-11). The `{service}/{section}` config allowlist is NEVER reached.
        .push(
            Router::with_path("api/console/branding/logo")
                .post(crate::branding::upload_logo) // BRAND-03 upload (CSRF-guarded)
                .get(crate::branding::serve_logo) // BRAND-03 serve (404 -> default)
                .delete(crate::branding::reset_logo), // BRAND-03 reset (CSRF-guarded)
        )
        .push(
            Router::with_path("api/console/branding")
                .get(crate::branding::get_branding), // BRAND-03 state (custom|default)
        )
        // Phase 8 (OAUTH2-01) Hydra OAuth2 client data path. All inherit
        // `auth_guard` (401 unauth); GET is csrf-exempt, while POST/PUT/DELETE
        // require `X-CSRF-Token` via `csrf_guard` (T-08-AUTHZ — `lib/api.ts`
        // echoes it, no new wiring). List replaces the Phase-3 first-page proof
        // with the Hydra Link-header cursor; update PUTs the full object with
        // `client_secret=None` so an edit can never blank the stored secret
        // (#2869 / T-08-SECRET); GET/list strip the secret (T-08-LEAK).
        .push(
            Router::with_path("api/hydra/clients")
                .get(crate::ory::hydra::list_clients) // OAUTH2-01 list (cursor)
                .post(crate::ory::hydra::create_client), // OAUTH2-01 create (one-time secret)
        )
        .push(
            Router::with_path("api/hydra/clients/{id}")
                .get(crate::ory::hydra::get_client) // OAUTH2-01 detail (secret masked)
                .put(crate::ory::hydra::update_client) // OAUTH2-01 update (#2869 preserve)
                .delete(crate::ory::hydra::delete_client), // OAUTH2-01 delete
        )
        // Phase 8 (OAUTH2-02) Hydra token & flow inspection. All inherit
        // `auth_guard` (401 unauth, T-08-AUTHZ). `introspect` and `revoke` are
        // POST: `csrf_guard` enforces `X-CSRF-Token` (403) — `revoke` is the
        // state-changing action (T-08-REVOKE-CSRF). The three flow-request
        // lookups are GET (csrf-exempt, read-only): they look up a PENDING
        // login/consent/logout request by `?challenge=`; the console NEVER
        // accepts/rejects the grant (T-08-GRANT — out of scope, the end-user
        // provider app owns it). A bogus challenge maps cleanly via
        // `map_hydra_err` (no 500/leak, T-08-ERRLEAK).
        .push(
            Router::with_path("api/hydra/oauth2/introspect")
                .post(crate::ory::hydra::introspect_token), // OAUTH2-02 introspect
        )
        .push(
            Router::with_path("api/hydra/oauth2/revoke")
                .post(crate::ory::hydra::revoke_token), // OAUTH2-02 revoke (CSRF-guarded)
        )
        .push(
            Router::with_path("api/hydra/oauth2/login")
                .get(crate::ory::hydra::get_login_request), // OAUTH2-02 flow lookup (read-only)
        )
        .push(
            Router::with_path("api/hydra/oauth2/consent")
                .get(crate::ory::hydra::get_consent_request), // OAUTH2-02 flow lookup (read-only)
        )
        .push(
            Router::with_path("api/hydra/oauth2/logout")
                .get(crate::ory::hydra::get_logout_request), // OAUTH2-02 flow lookup (read-only)
        )
        // Phase 9 (PERM-02 / PERM-03) Keto relation-tuple data path. All inherit
        // `auth_guard` (401 unauth); GET (list/query) is csrf-exempt, while
        // POST (create) / DELETE (delete) require `X-CSRF-Token` via `csrf_guard`
        // (T-9-csrf — `lib/api.ts` echoes it, no new wiring). Replaces the Phase-3
        // first-page proof slice with cursor + server-side filters. Create/delete
        // route to keto_write (:4467); list routes to keto_read (:4466).
        .push(
            Router::with_path("api/keto/relationships")
                .get(crate::ory::keto::list_relationships) // PERM-02/03 list+query (READ :4466)
                .post(crate::ory::keto::create_relationship) // PERM-02 create (WRITE :4467)
                .delete(crate::ory::keto::delete_relationship), // PERM-02 delete (WRITE :4467)
        )
        // PERM-03 check + expand — READ path (keto_read :4466), GET (csrf-exempt,
        // read-only). check uses check_permission (200+{allowed}, never the
        // deny-as-error variant — T-9-deny-vs-error).
        .push(Router::with_path("api/keto/check").get(crate::ory::keto::check_permission))
        .push(Router::with_path("api/keto/expand").get(crate::ory::keto::expand_permission))
        // PERM-01 OPL syntax-validate passthrough — OPL path (keto_opl :4469),
        // POST (csrf-guarded). Validate ONLY; never writes a file. The 09-02
        // Permission-Model editor calls this before the gated file write.
        .push(Router::with_path("api/keto/opl/validate").post(crate::ory::keto::validate_opl))
        // Phase 9 (PERM-01): the Permission-Model (OPL/namespaces) editor. A
        // DEDICATED route (NOT the {service}/{section} allowlist) so it can only
        // read/write the OPL FILE (config/keto/namespaces.ts), never an arbitrary
        // keto.yml key (config-injection guard, T-9-path-traversal /
        // T-9-section-bypass). GET returns the current model source (csrf-exempt);
        // PUT pre-validates the OPL on :4469 (populated errors -> 422, NO disk
        // touch — Pitfall 4), atomic-writes the RAW text, restarts Keto ONLY via
        // the broker, and rolls back on health failure. PUT is state-changing so
        // `csrf_guard` enforces `X-CSRF-Token` (403 — T-9-csrf-file); both inherit
        // `auth_guard` (401 unauth).
        .push(
            Router::with_path("api/keto/permission-model")
                .get(crate::config_edit::routes::get_permission_model)
                .put(crate::config_edit::routes::put_permission_model),
        )
        // Phase 9 (OATH-01): the Access-Rules editor. A DEDICATED route (NOT the
        // {service}/{section} allowlist) so it can only read/write the rules FILE
        // (config/oathkeeper/rules.json), never an arbitrary config.yaml key
        // (config-injection guard, T-9-path-traversal / T-9-section-bypass). GET
        // returns the current rules JSON (csrf-exempt); PUT structurally pre-checks
        // a JSON array (non-array -> 422, NO disk touch — T-9-rules), atomic-writes
        // pretty JSON, restarts Oathkeeper ONLY, and rolls back on health failure
        // (polling /health/alive — Pitfall 5/A1). This is DISTINCT from the
        // read-only `api/oathkeeper/rules` list below (that lists via the api_api;
        // this edits the file). PUT is state-changing so `csrf_guard` enforces
        // `X-CSRF-Token` (403 — T-9-csrf-file); both inherit `auth_guard` (401).
        .push(
            Router::with_path("api/config/oathkeeper/rules")
                .get(crate::config_edit::routes::get_oathkeeper_rules)
                .put(crate::config_edit::routes::put_oathkeeper_rules),
        )
        // Optional bonus (CONTEXT): the READ-ONLY rules LIST via the Oathkeeper
        // api_api (:4456) — exercises the 4th crate end-to-end and is RETAINED for
        // the 09-04 post-restart list confirmation. Distinct from the file editor
        // above (`api/config/oathkeeper/rules`), which writes the rules FILE.
        .push(Router::with_path("api/oathkeeper/rules").get(crate::ory::oathkeeper::list_rules))
        // Phase 4 (BACK-04 / BACK-06): the config-edit API. GET reads current
        // allowlisted values; PUT runs the full transactional flow. Both inherit
        // `auth_guard` (401) by sitting here; PUT is state-changing so `csrf_guard`
        // enforces `X-CSRF-Token` (403) — deliberately NOT exempted (T-04-11). The
        // `<service>`/`<section>` segments are parsed through the closed allowlist
        // + `Service` enum inside the handlers (SSRF guard, T-04-12).
        // Phase 8 (OAUTH2-04 secret half): the dedicated write-only Hydra OIDC
        // `pairwise.salt` setter. Registered BEFORE the generic
        // `api/config/{service}/{section}` route so the literal `pairwise-salt`
        // path segment matches this dedicated handler and never falls through to
        // the generic allowlist dispatch (which would 404 on an unknown section).
        // A DEDICATED route because the salt is write-only — changing it
        // invalidates every existing pairwise subject ID, so it is masked exactly
        // like the SMTP URI (threat T-08-SALT). GET reports `{set:bool}` (never the
        // salt value, csrf-exempt); PUT sets a real value, preserves on the masked
        // sentinel, or clears, restarts Hydra ONLY, and rolls back on health
        // failure. PUT is state-changing so `csrf_guard` enforces `X-CSRF-Token`
        // (403); both inherit `auth_guard` (401 unauth).
        .push(
            Router::with_path("api/config/hydra/pairwise-salt")
                .get(crate::config_edit::routes::get_pairwise_salt)
                .put(crate::config_edit::routes::put_pairwise_salt),
        )
        // Phase 4 (BACK-04 / BACK-06): the config-edit API. GET reads current
        // allowlisted values; PUT runs the full transactional flow. Both inherit
        // `auth_guard` (401) by sitting here; PUT is state-changing so `csrf_guard`
        // enforces `X-CSRF-Token` (403) — deliberately NOT exempted (T-04-11). The
        // `<service>`/`<section>` segments are parsed through the closed allowlist
        // + `Service` enum inside the handlers (SSRF guard, T-04-12).
        .push(
            Router::with_path("api/config/{service}/{section}")
                .get(crate::config_edit::routes::get_config)
                .put(crate::config_edit::routes::put_config),
        )
        // Phase 6 (IDENT-03): the identity-schema editor. A DEDICATED route (NOT
        // the {service}/{section} allowlist) so it can only read/write the schema
        // FILE, never an arbitrary kratos.yml key (config-injection guard,
        // T-06-10). GET returns the active schema (csrf-exempt); PUT validates as
        // draft-07 + properties.traits, atomic-writes the .json, restarts Kratos
        // via the broker, and rolls back on health failure (Pitfall 5). PUT is
        // state-changing so `csrf_guard` enforces `X-CSRF-Token` (T-06-14); both
        // inherit `auth_guard` (401 unauth, T-06-13).
        .push(
            Router::with_path("api/kratos/identity-schema")
                .get(crate::ory::kratos::get_active_schema)
                .put(crate::config_edit::routes::put_identity_schema),
        )
        // Phase 7 (AUTH-09 secret half): the dedicated write-only SMTP
        // `connection_uri` setter. A DEDICATED route (NOT the {service}/{section}
        // allowlist) because the URI is on the hard `SENSITIVE_PREFIXES` denylist
        // and carries the SMTP password — this handler is the ONLY writer and can
        // only ever touch that one pointer (Pitfall 2 / T-07-07). GET reports
        // `{set:bool}` MASKED (never the URI, csrf-exempt); PUT sets a real value
        // or preserves a stored one on the masked sentinel, restarts Kratos, and
        // rolls back on health failure. PUT is state-changing so `csrf_guard`
        // enforces `X-CSRF-Token` (403); both inherit `auth_guard` (401 unauth).
        .push(
            Router::with_path("api/kratos/smtp-connection")
                .get(crate::config_edit::routes::get_smtp_connection)
                .put(crate::config_edit::routes::put_smtp_connection),
        )
        // Phase 11 (HOOK-01/02/03) the webhook dispatcher — console-OWNED state,
        // NO Ory call (like branding). All inherit `auth_guard` (401 unauth); GET
        // (list/detail) is csrf-exempt, while every state change (create/update/
        // delete/rotate-secret/redeliver) requires `X-CSRF-Token` via `csrf_guard`
        // (403, T-11-10). The signing `secret` is write-only end-to-end: create +
        // rotate-secret reveal it ONCE; GET/list return the masked `secret_set`
        // badge only (T-11-05). `create`/`update` SSRF-validate the URL for fast
        // 422 feedback; the worker re-validates authoritatively at delivery time
        // (DNS-rebind defense, T-11-01/02). Most specific paths FIRST so the
        // literal `deliveries` segment is not captured by `{id}`.
        .push(
            Router::with_path("api/webhooks/deliveries")
                .get(crate::webhooks::routes::list_deliveries), // HOOK-03 delivery-log list
        )
        .push(
            Router::with_path("api/webhooks/deliveries/{id}/redeliver")
                .post(crate::webhooks::routes::redeliver), // HOOK-03 re-enqueue (CSRF-guarded)
        )
        .push(
            Router::with_path("api/webhooks/deliveries/{id}")
                .get(crate::webhooks::routes::get_delivery), // HOOK-03 delivery detail
        )
        .push(
            Router::with_path("api/webhooks/{id}/rotate-secret")
                .post(crate::webhooks::routes::rotate_secret), // HOOK-02 rotate (one-time reveal)
        )
        .push(
            Router::with_path("api/webhooks/{id}")
                .get(crate::webhooks::routes::get_webhook) // HOOK-03 detail (masked secret)
                .put(crate::webhooks::routes::update_webhook) // HOOK-03 update (never blanks secret)
                .delete(crate::webhooks::routes::delete_webhook), // HOOK-03 delete
        )
        .push(
            Router::with_path("api/webhooks")
                .get(crate::webhooks::routes::list_webhooks) // HOOK-03 list (masked secret)
                .post(crate::webhooks::routes::create_webhook), // HOOK-02/03 create (one-time secret)
        );

    // Phase 3 (BACK-02): build the Ory Admin clients from Config BEFORE cfg is
    // moved into the affix_state hoop, then inject them into every Depot
    // alongside the pool + config (RESEARCH Pattern 2). Handlers obtain them with
    // `depot.obtain::<OryClients>()`.
    //
    // WR-03: `from_config` now validates the five admin URLs and can fail; the
    // `?` surfaces a malformed URL as a boot-time `AppError::Config` rather than
    // an opaque per-request 502.
    let ory_clients = crate::ory::clients::OryClients::from_config(&cfg)?;

    // Root: inject shared state, then the public index + both subtrees.
    // Phase 12 (FLAG-01): the FeatureFlags cache rides the same affix_state chain
    // as the pool/cfg/clients; the FeatureFlagHoop reads it via depot.obtain.
    Ok(Router::new()
        .hoop(affix_state::inject(pool).inject(cfg).inject(ory_clients).inject(flags))
        .get(index)
        .push(public)
        .push(protected))
}
