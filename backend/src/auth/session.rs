//! DB-backed opaque sessions + the hardened `__Host-` cookie (CAUTH-05).
//!
//! Lifecycle (RESEARCH Pattern 3, OWASP session management):
//!
//! 1. **Mint** — generate a 256-bit base64url session token and a separate
//!    256-bit base64url CSRF token; INSERT a `sessions` row storing only
//!    `token_hash = sha256_hex(raw)` (the raw token lives ONLY in the cookie),
//!    `expires_at = now + absolute`, `last_seen_at = now`. Return the raw token
//!    + CSRF to the caller.
//! 2. **Validate** — SHA-256 the cookie value, look up the row, reject if past
//!    the absolute `expires_at` or the sliding idle window, else slide
//!    `last_seen_at` and return the row.
//! 3. **Cookie** — `__Host-console_session`, HttpOnly + Secure + SameSite=Lax +
//!    Path=/. The dev escape hatch (`insecure_cookies`) drops the `__Host-`
//!    prefix and Secure so the cookie survives plain-HTTP localhost (Pitfall 6).
//! 4. **Delete** — logout removes the row and clears the cookie.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use salvo::http::cookie::time::Duration as CookieDuration;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::db::models::Session;
use crate::db::queries;
use crate::error::AppError;

/// Hardened cookie name. The `__Host-` prefix is browser-enforced: it requires
/// Secure + Path=/ + no Domain, pinning the cookie to this exact host.
pub const COOKIE_HOST: &str = "__Host-console_session";
/// Dev-only cookie name (no `__Host-` prefix) used when `insecure_cookies` is
/// set so the cookie is accepted over plain-HTTP localhost.
pub const COOKIE_DEV: &str = "console_session";

/// Result of minting a session: the raw values handed to the client. The raw
/// token goes into the cookie; `csrf_token` is surfaced to the SPA for the
/// `X-CSRF-Token` header (wired into the CSRF guard in Plan 02-03).
pub struct MintedSession {
    pub raw_token: String,
    pub csrf_token: String,
}

/// The cookie name in force for this config (dev vs hardened).
pub fn cookie_name(cfg: &Config) -> &'static str {
    if cfg.insecure_cookies {
        COOKIE_DEV
    } else {
        COOKIE_HOST
    }
}

/// Generate a 256-bit (32-byte) base64url-no-pad token. `rand::rng()` is the
/// thread-local ChaCha-based CSPRNG (seeded from the OS, `CryptoRng`) — the
/// idiomatic rand 0.10 cryptographic generator (RESEARCH: `rand::rng()`
/// replaces the old `thread_rng()`).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint a new session for `admin_id`: insert the row (storing only the token
/// hash) and return the raw token + CSRF token. The session is regenerated on
/// every authentication (OWASP) — callers delete any prior session first.
pub async fn mint_session(
    pool: &PgPool,
    admin_id: Uuid,
    ip: Option<&str>,
    user_agent: Option<&str>,
    cfg: &Config,
) -> Result<MintedSession, AppError> {
    let raw_token = generate_token();
    let csrf_token = generate_token();
    let token_hash = crate::auth::password::sha256_hex(&raw_token);

    queries::insert_session(
        pool,
        &token_hash,
        admin_id,
        cfg.session_absolute_secs,
        ip,
        user_agent,
        &csrf_token,
    )
    .await?;

    Ok(MintedSession {
        raw_token,
        csrf_token,
    })
}

/// Validate the raw cookie token: hash it, find a non-expired row, enforce the
/// idle window, then slide `last_seen_at`. Returns `None` for any miss/expiry
/// (the auth guard turns that into a 401). DB errors also collapse to `None`
/// (fail-closed — a blip never authenticates a request).
pub async fn validate_session(pool: &PgPool, raw_token: &str, cfg: &Config) -> Option<Session> {
    let token_hash = crate::auth::password::sha256_hex(raw_token);

    let session = match queries::get_active_session(pool, &token_hash).await {
        Ok(Some(s)) => s,
        _ => return None,
    };

    // Idle window: reject if the last activity is older than the sliding window.
    let now = time::OffsetDateTime::now_utc();
    let idle = now - session.last_seen_at;
    if idle.whole_seconds() > cfg.session_idle_secs {
        return None;
    }

    // Slide last_seen_at on success. A failure here fails closed (no auth).
    if queries::touch_session(pool, &token_hash).await.is_err() {
        return None;
    }

    Some(session)
}

/// Delete the session identified by the raw cookie token (logout).
pub async fn delete_session(pool: &PgPool, raw_token: &str) -> Result<(), AppError> {
    let token_hash = crate::auth::password::sha256_hex(raw_token);
    queries::delete_session_by_hash(pool, &token_hash).await
}

/// Set the session cookie on the response. Hardened by default
/// (`__Host-console_session`, Secure); the dev escape hatch drops the prefix +
/// Secure (Pitfall 6). `max_age_secs` should be the absolute session lifetime.
pub fn set_session_cookie(res: &mut Response, raw_token: &str, max_age_secs: i64, cfg: &Config) {
    let name = cookie_name(cfg);
    let mut builder = Cookie::build((name, raw_token.to_owned()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(max_age_secs));

    // Secure is MANDATORY for the `__Host-` prefix; dropped only in dev.
    builder = builder.secure(!cfg.insecure_cookies);

    res.add_cookie(builder.build());
}

/// Clear the session cookie (logout). WR-05: emit an explicit EXPIRED cookie
/// that mirrors the SET attributes (same name, Path=/, HttpOnly, SameSite=Lax,
/// and Secure in the hardened posture) with an empty value + Max-Age=0. A bare
/// name-only `remove_cookie` can be ignored by the browser for a `__Host-`
/// prefixed cookie (the clearing Set-Cookie must itself satisfy Secure+Path=/),
/// leaving a stale cookie behind. Building the overwrite explicitly guarantees
/// the browser drops the matching cookie.
pub fn clear_session_cookie(res: &mut Response, cfg: &Config) {
    let name = cookie_name(cfg);
    let mut builder = Cookie::build((name, ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(0));
    // Secure must match the SET cookie so the overwrite is accepted (mandatory
    // for the `__Host-` prefix; dropped only under the dev escape hatch).
    builder = builder.secure(!cfg.insecure_cookies);
    res.add_cookie(builder.build());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(insecure: bool) -> Config {
        Config {
            console_database_url: String::new(),
            bind_addr: "0.0.0.0:8080".into(),
            session_idle_secs: 604_800,
            session_absolute_secs: 2_592_000,
            insecure_cookies: insecure,
            allowed_origins: Vec::new(),
            github: None,
            kratos_admin_url: "http://kratos:4434".into(),
            hydra_admin_url: "http://hydra:4445".into(),
            hydra_public_url: "http://hydra:4444".into(),
            keto_read_url: "http://keto:4466".into(),
            keto_write_url: "http://keto:4467".into(),
            keto_opl_url: "http://keto:4469".into(),
            oathkeeper_api_url: "http://oathkeeper:4456".into(),
            restart_broker_url: "http://restart-broker:2375".into(),
            config_dir: "/etc/config".into(),
            polis_admin_url: "http://polis:5225".into(),
            polis_api_key: None,
            polis_external_url: None,
            webhook_allow_private_targets: false,
        }
    }

    #[test]
    fn generated_tokens_are_unique_and_urlsafe() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        // base64url-no-pad of 32 bytes is 43 chars, only URL-safe alphabet.
        assert_eq!(a.len(), 43);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn cookie_name_switches_on_insecure_flag() {
        assert_eq!(cookie_name(&cfg(false)), COOKIE_HOST);
        assert_eq!(cookie_name(&cfg(true)), COOKIE_DEV);
        assert_eq!(COOKIE_HOST, "__Host-console_session");
    }

    #[test]
    fn hardened_cookie_has_host_prefix_httponly_secure_lax() {
        let mut res = Response::new();
        set_session_cookie(&mut res, "rawtokenvalue", 3600, &cfg(false));
        let c = res
            .cookies()
            .get(COOKIE_HOST)
            .expect("hardened cookie set under __Host- name");
        assert_eq!(c.name(), "__Host-console_session");
        assert_eq!(c.value(), "rawtokenvalue");
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Lax));
        assert_eq!(c.path(), Some("/"));
    }

    #[test]
    fn clear_session_cookie_overwrites_with_expired_hardened_attrs() {
        // WR-05: the logout Set-Cookie must carry the SAME attributes as the set
        // cookie (name, Path=/, Secure, HttpOnly, Lax) with an empty value, so a
        // `__Host-` prefixed cookie is actually overwritten.
        let mut res = Response::new();
        clear_session_cookie(&mut res, &cfg(false));
        let c = res
            .cookies()
            .get(COOKIE_HOST)
            .expect("clear emits a Set-Cookie under the hardened name");
        assert_eq!(c.name(), "__Host-console_session");
        assert_eq!(c.value(), "");
        assert_eq!(c.path(), Some("/"));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Lax));
        // Expired immediately (Max-Age=0).
        assert_eq!(c.max_age(), Some(CookieDuration::seconds(0)));
    }

    #[test]
    fn clear_session_cookie_dev_drops_secure() {
        let mut res = Response::new();
        clear_session_cookie(&mut res, &cfg(true));
        let c = res
            .cookies()
            .get(COOKIE_DEV)
            .expect("clear emits a Set-Cookie under the dev name");
        assert_eq!(c.value(), "");
        assert_eq!(c.path(), Some("/"));
        assert_ne!(c.secure(), Some(true));
    }

    #[test]
    fn dev_cookie_drops_prefix_and_secure() {
        let mut res = Response::new();
        set_session_cookie(&mut res, "rawtokenvalue", 3600, &cfg(true));
        let c = res
            .cookies()
            .get(COOKIE_DEV)
            .expect("dev cookie set under prefix-free name");
        assert_eq!(c.name(), "console_session");
        assert_eq!(c.http_only(), Some(true));
        // Secure dropped so plain-HTTP localhost accepts it.
        assert_ne!(c.secure(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Lax));
    }
}
