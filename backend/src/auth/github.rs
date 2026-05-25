//! Optional, env-gated GitHub OAuth login (CAUTH-04).
//!
//! Mounted ONLY when `cfg.github.is_some()` (both `GITHUB_OAUTH_CLIENT_ID` and
//! `GITHUB_OAUTH_CLIENT_SECRET` present). When unset the routes do not exist and
//! `GET /api/console/state` reports `github_oauth_enabled:false` (T-02-34).
//!
//! Flow (RESEARCH Pattern 4, oauth2 5.0 typestate client):
//!
//! 1. `github_login` builds the authorize URL with a random `CsrfToken` state
//!    and the `read:user` + `user:email` scopes, stores the state nonce in a
//!    dedicated short-lived `SameSite=Lax` cookie DISTINCT from the session
//!    cookie (Pitfall 1 — the session cookie must NOT carry the OAuth state),
//!    and 302-redirects to GitHub.
//! 2. `github_callback` constant-time-compares the returned `state` against the
//!    nonce cookie (T-02-30 OAuth CSRF), clears the nonce, exchanges the code
//!    over an SSRF-guarded `reqwest` client (`redirect(Policy::none())`,
//!    T-02-31), fetches the GitHub user id + verified primary email, finds an
//!    existing admin (by `github_user_id`, then by verified primary email) and
//!    on a match persists the id + regenerates the session; on NO match it
//!    DENIES (403) — auto-provisioning is OFF (T-02-32, no open self-register).
//!
//! Secrets: the client secret and the GitHub bearer token are NEVER logged and
//! NEVER serialized into a response (BACK-07).

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use salvo::http::cookie::time::Duration as CookieDuration;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use serde::Deserialize;
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use crate::auth::session;
use crate::config::{Config, GithubCfg};
use crate::db::queries;
use crate::error::AppError;

/// GitHub OAuth endpoints (RESEARCH Pattern 4 / docs.github.com).
const GH_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GH_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GH_USER_URL: &str = "https://api.github.com/user";
const GH_EMAILS_URL: &str = "https://api.github.com/user/emails";

/// Dedicated short-lived cookie carrying the OAuth `state` nonce. DISTINCT from
/// the session cookie (Pitfall 1). Lives only for the round-trip to GitHub.
const STATE_COOKIE: &str = "console_oauth_state";
/// Nonce lifetime: the GitHub authorization code expires in 10 minutes; the
/// state nonce only needs to outlive the user's consent click — 10 min is ample.
const STATE_TTL_SECS: i64 = 600;

/// A required-User-Agent header for the GitHub REST API (it 403s requests with
/// no User-Agent). Identifies this console; carries no secret.
const GH_USER_AGENT: &str = "ory-self-hosted-console";

/// Build the oauth2 5.0 typestate `BasicClient`. Verified against RESEARCH
/// Pattern 4: `new(ClientId)` then the fluent `set_*` setters, each returning a
/// further-specialized typestate. The redirect URI defaults to the public
/// `/auth/github/callback` path when not explicitly configured.
fn build_client(
    cfg: &GithubCfg,
) -> Result<
    BasicClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
    AppError,
> {
    let redirect = cfg
        .redirect_url
        .clone()
        .unwrap_or_else(|| "http://localhost:8080/auth/github/callback".to_string());

    let client = BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_client_secret(ClientSecret::new(cfg.client_secret.clone()))
        .set_auth_uri(
            AuthUrl::new(GH_AUTHORIZE_URL.to_string())
                .map_err(|e| AppError::Internal(format!("bad github auth url: {e}")))?,
        )
        .set_token_uri(
            TokenUrl::new(GH_TOKEN_URL.to_string())
                .map_err(|e| AppError::Internal(format!("bad github token url: {e}")))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect)
                .map_err(|e| AppError::Internal(format!("bad github redirect url: {e}")))?,
        );
    Ok(client)
}

/// SSRF-guarded HTTP client for the oauth2 **code exchange**. oauth2 5.0
/// implements `AsyncHttpClient` for its OWN bundled `oauth2::reqwest::Client`
/// (reqwest 0.12) — NOT for this crate's reqwest 0.13 (the two are distinct
/// versions in the dependency graph), so the token exchange must use this
/// client. Follows NO redirects (`Policy::none()`) so a poisoned redirect cannot
/// point the backend at an internal address (T-02-31, oauth2 5.0 docs warning).
fn exchange_http_client() -> Result<oauth2::reqwest::Client, AppError> {
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(format!("oauth exchange client build failed: {e}")))
}

/// SSRF-guarded HTTP client for the GitHub user/email REST fetch (this crate's
/// reqwest 0.13). Same redirect-none guard (T-02-31).
fn api_http_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(format!("oauth api client build failed: {e}")))
}

/// Set the short-lived state-nonce cookie. Mirrors the session cookie's Secure
/// posture (dropped only under the dev escape hatch) but is a SEPARATE cookie.
fn set_state_cookie(res: &mut Response, state: &str, cfg: &Config) {
    let mut builder = Cookie::build((STATE_COOKIE, state.to_owned()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(STATE_TTL_SECS));
    builder = builder.secure(!cfg.insecure_cookies);
    res.add_cookie(builder.build());
}

/// Clear the state-nonce cookie once consumed (single-use). WR-05: emit an
/// explicit expired cookie mirroring the SET attributes (Path=/, HttpOnly,
/// SameSite=Lax, Secure in the hardened posture) so the overwrite is reliably
/// honored rather than a name-only removal the browser may ignore.
fn clear_state_cookie(res: &mut Response, cfg: &Config) {
    let mut builder = Cookie::build((STATE_COOKIE, ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(0));
    builder = builder.secure(!cfg.insecure_cookies);
    res.add_cookie(builder.build());
}

/// `GET /auth/github/login` — start the OAuth dance. Builds the authorize URL
/// with a random state nonce, stows the nonce in its own cookie, 302-redirects.
#[handler]
pub async fn github_login(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();
    let gh = cfg
        .github
        .as_ref()
        .ok_or_else(|| AppError::Internal("github login mounted without config".into()))?;

    let client = build_client(gh)?;
    let (auth_url, csrf) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    // Store the state nonce server-side-of-the-cookie (NOT in the session
    // cookie). Verified constant-time on callback.
    set_state_cookie(res, csrf.secret(), &cfg);

    res.status_code(StatusCode::FOUND);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        auth_url
            .to_string()
            .parse()
            .map_err(|_| AppError::Internal("bad authorize url header".into()))?,
    );
    Ok(())
}

/// Callback query: `?code=...&state=...`.
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

/// A GitHub `/user` response (only the fields we consume).
#[derive(Debug, Deserialize)]
struct GithubUser {
    id: i64,
    /// May be absent / unverified — we rely on `/user/emails` for a trusted
    /// primary, but keep this as a low-priority hint only.
    #[serde(default)]
    email: Option<String>,
}

/// A GitHub `/user/emails` entry.
#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Constant-time string compare (avoids a timing side-channel on the state).
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// `GET /auth/github/callback` — verify state, exchange code, link-or-deny.
#[handler]
pub async fn github_callback(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();
    let gh = cfg
        .github
        .as_ref()
        .ok_or_else(|| AppError::Internal("github callback mounted without config".into()))?
        .clone();

    let query: CallbackQuery = req
        .parse_queries()
        .map_err(|_| AppError::BadRequest("missing code/state".into()))?;

    // OAuth-CSRF: the returned state MUST equal the nonce we set, compared in
    // constant time (T-02-30). A missing/empty nonce cookie denies.
    let nonce = req
        .cookie(STATE_COOKIE)
        .map(|c| c.value().to_owned())
        .filter(|v| !v.is_empty())
        .ok_or(AppError::Forbidden)?;
    // Single-use: clear the nonce regardless of the outcome below.
    clear_state_cookie(res, &cfg);
    if !ct_eq(&query.state, &nonce) {
        return Err(AppError::Forbidden);
    }

    // Exchange the authorization code over the SSRF-guarded oauth2 client (T-02-31).
    let exchange_http = exchange_http_client()?;
    let client = build_client(&gh)?;
    let token = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(&exchange_http)
        .await
        .map_err(|_| AppError::Unauthorized)?; // never echo the oauth error detail
    let access_token = oauth2::TokenResponse::access_token(&token).secret().clone();

    // Fetch the GitHub user (id) + verified primary email over the SSRF-guarded
    // REST client. The bearer token is sent in the Authorization header and
    // NEVER logged.
    let api_http = api_http_client()?;
    let user = github_get::<GithubUser>(&api_http, GH_USER_URL, &access_token).await?;
    let emails = github_get::<Vec<GithubEmail>>(&api_http, GH_EMAILS_URL, &access_token)
        .await
        .unwrap_or_default();
    let verified_primary = emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email.clone())
        // Fall back to a single verified email if no flagged primary exists.
        .or_else(|| emails.iter().find(|e| e.verified).map(|e| e.email.clone()))
        .or_else(|| user.email.clone());

    // Link-or-deny (T-02-32): match an existing admin by github_user_id, then by
    // verified primary email. NEVER auto-provision a new admin.
    let admin = match queries::find_admin_by_github_id(&pool, user.id).await? {
        // Already linked by the durable numeric id — the unambiguous, trusted path.
        Some(a) => a,
        None => match &verified_primary {
            // WR-04: email-fallback linking is a one-time bootstrap convenience
            // and is UNAMBIGUOUS only while a single admin exists. Once Phase 11
            // introduces multiple admins, a GitHub account whose verified primary
            // email coincides with an admin's email must NOT be able to link in
            // by email coincidence alone — so restrict the fallback to the
            // single-admin case and deny otherwise (operator must link while
            // logged in, proving ownership by the password session).
            Some(email) => {
                if queries::count_admins(&pool).await? != 1 {
                    return Err(AppError::Forbidden);
                }
                let candidate = queries::find_admin_by_email(&pool, email)
                    .await?
                    .ok_or(AppError::Forbidden)?;
                // Refuse to MOVE an existing link: if the matched admin is
                // already bound to a DIFFERENT GitHub id, deny rather than
                // silently overwriting which GitHub account owns this admin.
                if let Some(existing) = candidate.github_user_id {
                    if existing != user.id {
                        return Err(AppError::Forbidden);
                    }
                }
                candidate
            }
            None => return Err(AppError::Forbidden),
        },
    };

    // Persist the GitHub id on first link only. If the admin is already linked to
    // a DIFFERENT non-null id we never reach a relink here (the by-id lookup above
    // returned this admin only for an exact id match; the email path denied a
    // mismatch), so this is a no-op on re-login and a first-time bind otherwise.
    match admin.github_user_id {
        Some(existing) if existing != user.id => return Err(AppError::Forbidden),
        Some(_) => {} // already linked to this id — idempotent no-op.
        None => queries::link_github(&pool, admin.id, user.id).await?,
    }

    // Regenerate-on-auth: clear stale sessions, mint a fresh one, set the cookie.
    queries::delete_sessions_for_admin(&pool, admin.id).await?;
    queries::update_last_login(&pool, admin.id).await?;

    let ip = req.remote_addr().to_string();
    let user_agent = req.header::<String>("user-agent");
    let minted =
        session::mint_session(&pool, admin.id, Some(ip.as_str()), user_agent.as_deref(), &cfg)
            .await?;
    session::set_session_cookie(res, &minted.raw_token, cfg.session_absolute_secs, &cfg);

    // Land the browser back at the app root (top-level GET nav — Lax cookie is
    // delivered). Frontend routing is Phase 5; root is a safe default.
    res.status_code(StatusCode::FOUND);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        "/".parse()
            .map_err(|_| AppError::Internal("bad redirect header".into()))?,
    );
    Ok(())
}

/// GET a GitHub API resource with the bearer token + required User-Agent and
/// deserialize the JSON body. Maps any failure to a generic 401 so no GitHub
/// error detail (or token) leaks to the client.
async fn github_get<T: for<'de> serde::Deserialize<'de>>(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<T, AppError> {
    let resp = http
        .get(url)
        .bearer_auth(access_token)
        .header(reqwest::header::USER_AGENT, GH_USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if !resp.status().is_success() {
        return Err(AppError::Unauthorized);
    }
    resp.json::<T>().await.map_err(|_| AppError::Unauthorized)
}
