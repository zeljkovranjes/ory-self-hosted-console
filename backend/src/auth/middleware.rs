//! The single auth chokepoint (CAUTH-06, BACK-01) + per-session CSRF guard
//! (CAUTH-05), implemented as two Salvo `hoop` handlers (RESEARCH Pattern 5).
//!
//! - `auth_guard` — the SOLE authentication boundary for the protected subtree.
//!   It reads the `__Host-console_session` (or dev `console_session`) cookie,
//!   validates it against the `sessions` table, and on success injects the
//!   `Session` into the `Depot` for downstream handlers. Any miss — no cookie,
//!   unknown/expired token, DB blip — yields `401 {"error":"unauthenticated"}`
//!   and `skip_rest()` so the protected handler NEVER runs (fail-closed).
//! - `csrf_guard` — runs AFTER `auth_guard` on the protected subtree. Safe
//!   methods (GET/HEAD/OPTIONS) pass untouched. State-changing methods
//!   (POST/PUT/PATCH/DELETE) must carry an `X-CSRF-Token` header that matches
//!   the injected session's `csrf_token` (constant-time compare); a missing or
//!   mismatched token yields `403 {"error":"csrf"}` + `skip_rest()`.
//!
//! Pitfall 7: both hoops are mounted ONLY on the protected subtree (the public
//! set has neither). Pitfall 4 / BACK-07: cookie and header VALUES are never
//! logged.

use salvo::prelude::*;
use subtle::ConstantTimeEq;

use crate::auth::session;
use crate::config::Config;
use crate::db::models::Session;

/// The authenticated identity of an API-key request (Phase 19 / CLI-02).
///
/// Injected into the `Depot` by [`api_key_or_session`] ONLY after the presented
/// `Authorization: Api-Key <raw>` verified against a known, non-revoked key
/// (constant-time, via `apikeys::queries::verify_api_key`). Its presence in the
/// Depot is the SOLE signal that a request authenticated by api-key rather than
/// by session cookie — `csrf_guard` reads it to exempt the request from CSRF
/// (the key IS the credential, T-19-05) and the `audit_hoop` reads it to record
/// the api-key owner as actor (T-19-06). Carries ONLY the key id; the raw key is
/// never stored here and NEVER logged (BACK-07).
#[derive(Clone)]
pub struct ApiKeyPrincipal {
    pub key_id: uuid::Uuid,
}

/// Render a deny response (`status` + `{"error": code}` JSON) and stop the
/// handler chain so the guarded handler never executes (fail-closed).
fn deny(res: &mut Response, ctrl: &mut FlowCtrl, status: StatusCode, code: &'static str) {
    res.status_code(status);
    res.render(Json(serde_json::json!({ "error": code })));
    ctrl.skip_rest();
}

/// Authentication chokepoint hoop (CAUTH-06, BACK-01).
///
/// Reads the session cookie, validates it, and on success injects the `Session`
/// into the `Depot`. On ANY failure path returns `401` JSON + `skip_rest()`.
#[handler]
pub async fn auth_guard(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // Pool + Config are injected by the root `affix_state` hoop. A missing
    // dependency is an internal wiring fault — fail closed (treat as unauth).
    let pool = match depot.obtain::<sqlx::PgPool>() {
        Ok(p) => p.clone(),
        Err(_) => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };
    let cfg = match depot.obtain::<Config>() {
        Ok(c) => c.clone(),
        Err(_) => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };

    // Read the in-force cookie (hardened `__Host-` name, or dev name). Never
    // log the value (Pitfall 4).
    let name = session::cookie_name(&cfg);
    let raw = match req.cookie(name).map(|c| c.value().to_owned()) {
        Some(v) if !v.is_empty() => v,
        _ => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };

    // validate_session is itself fail-closed (DB errors -> None).
    match session::validate_session(&pool, &raw, &cfg).await {
        Some(sess) => {
            // Make the session (and thus the admin id + csrf_token) available to
            // the csrf_guard and the downstream handlers.
            depot.inject(sess);
        }
        None => deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    }
}

/// Combined API-key OR session authenticator (Phase 19 / CLI-02, RESEARCH
/// Pattern 1). REPLACES `auth_guard` on the protected subtree.
///
/// It tries the `Authorization: Api-Key <raw>` machine-client credential FIRST,
/// then falls back to the EXISTING session-cookie path — both branches share the
/// fail-closed posture of `auth_guard`.
///
///   1. If an `Authorization` header carries the `Api-Key ` scheme with a
///      non-empty raw value: verify it via `apikeys::queries::verify_api_key`
///      (which already does prefix-bounded lookup, per-candidate constant-time
///      `subtle` compare, a dummy-compare timing-oracle kill on no-match, revoked
///      rejection, and a `last_used_at` stamp — REUSED verbatim, no re-rolled
///      crypto). On `Ok(Some(id))` inject [`ApiKeyPrincipal`] and CONTINUE. On
///      `Ok(None)` (unknown/revoked) or `Err(_)` (DB blip): 401 + `skip_rest()`.
///      Once the `Api-Key` scheme is PRESENT we NEVER fall through to the cookie
///      path (T-19-04) — a bad key can never silently retry as a session.
///   2. If NO `Api-Key` scheme is present: run the EXACT live `auth_guard`
///      session logic (cookie_name → req.cookie → validate_session → inject
///      Session, else 401). This branch is byte-for-byte the session path, so the
///      existing session behavior is provably unchanged (T-19-07).
///
/// A request with neither a valid Api-Key nor a valid session is 401 exactly as
/// `auth_guard` is today. The raw key and the cookie value are NEVER logged
/// (BACK-07 / Pitfall 4).
#[handler]
pub async fn api_key_or_session(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // Pool + Config are injected by the root `affix_state` hoop. A missing
    // dependency is an internal wiring fault — fail closed (treat as unauth),
    // identical to `auth_guard`.
    let pool = match depot.obtain::<sqlx::PgPool>() {
        Ok(p) => p.clone(),
        Err(_) => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };
    let cfg = match depot.obtain::<Config>() {
        Ok(c) => c.clone(),
        Err(_) => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };

    // 1) API-key path FIRST. The header name + scheme prefix come from
    //    `console_core` (the single source of truth shared with the CLI). The raw
    //    value is never logged.
    let scheme_prefix = format!("{} ", console_core::API_KEY_SCHEME);
    let presented = req
        .header::<String>(console_core::API_KEY_HEADER)
        .and_then(|h| h.strip_prefix(&scheme_prefix).map(|v| v.trim().to_owned()))
        .filter(|v| !v.is_empty());
    if let Some(raw) = presented {
        // Once the Api-Key scheme is presented we commit to the api-key path:
        // any non-match (unknown/revoked) or DB error is a 401, NEVER a silent
        // fall-through to the cookie path (T-19-04 fail-closed).
        match crate::apikeys::queries::verify_api_key(&pool, &raw).await {
            Ok(Some(key_id)) => {
                depot.inject(ApiKeyPrincipal { key_id });
            }
            Ok(None) | Err(_) => deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
        }
        return;
    }

    // 2) Session path — the EXACT live `auth_guard` logic, unchanged (T-19-07).
    //    Read the in-force cookie (hardened `__Host-` name, or dev name). Never
    //    log the value (Pitfall 4).
    let name = session::cookie_name(&cfg);
    let raw = match req.cookie(name).map(|c| c.value().to_owned()) {
        Some(v) if !v.is_empty() => v,
        _ => return deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    };

    // validate_session is itself fail-closed (DB errors -> None).
    match session::validate_session(&pool, &raw, &cfg).await {
        Some(sess) => {
            // Make the session (and thus the admin id + csrf_token) available to
            // the csrf_guard and the downstream handlers.
            depot.inject(sess);
        }
        None => deny(res, ctrl, StatusCode::UNAUTHORIZED, "unauthenticated"),
    }
}

/// Whether an HTTP method is "safe" (no state change) and therefore exempt from
/// the CSRF check (RESEARCH Anti-Pattern: never CSRF-guard GET/HEAD).
fn is_safe_method(method: &salvo::http::Method) -> bool {
    use salvo::http::Method;
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Per-session CSRF guard hoop (CAUTH-05). Runs after `auth_guard`.
///
/// Safe methods pass untouched. State-changing methods must carry an
/// `X-CSRF-Token` header equal (constant-time) to the injected session's
/// `csrf_token`; otherwise `403 {"error":"csrf"}` + `skip_rest()`.
#[handler]
pub async fn csrf_guard(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // Safe methods are exempt (reads must stay side-effect free).
    if is_safe_method(req.method()) {
        return;
    }

    // Phase 19 (CLI-02, RESEARCH Pattern 2 / T-19-05): an api-key request is
    // exempt from CSRF. CSRF defends a BROWSER that auto-attaches a cookie; an
    // api-key client never auto-attaches anything — an attacker cannot make a
    // victim's browser send the operator's `Authorization: Api-Key` header, so
    // the check is meaningless for it (not a real defense being removed). The
    // exemption fires ONLY when `api_key_or_session` injected an
    // `ApiKeyPrincipal`; the session branch below keeps FULL X-CSRF-Token
    // enforcement, so the session path is byte-for-byte unchanged.
    if depot.obtain::<ApiKeyPrincipal>().is_ok() {
        return;
    }

    // The session was injected by auth_guard, which always runs first on the
    // protected subtree. Its absence means the chain is misordered — fail closed.
    let session_csrf = match depot.obtain::<Session>() {
        Ok(s) => s.csrf_token.clone(),
        Err(_) => return deny(res, ctrl, StatusCode::FORBIDDEN, "csrf"),
    };

    // Header token (never logged). Missing -> 403.
    let header_token = req
        .header::<String>("X-CSRF-Token")
        .filter(|t| !t.is_empty());
    let header_token = match header_token {
        Some(t) => t,
        None => return deny(res, ctrl, StatusCode::FORBIDDEN, "csrf"),
    };

    // Constant-time compare (never `==` on a secret). Length-mismatch is a
    // mismatch; ConstantTimeEq over equal-length byte slices avoids leaking it.
    let a = header_token.as_bytes();
    let b = session_csrf.as_bytes();
    let matches = a.len() == b.len() && a.ct_eq(b).into();
    if !matches {
        return deny(res, ctrl, StatusCode::FORBIDDEN, "csrf");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::http::Method;

    #[test]
    fn safe_methods_are_csrf_exempt() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        assert!(is_safe_method(&Method::OPTIONS));
    }

    #[test]
    fn state_changing_methods_are_not_csrf_exempt() {
        assert!(!is_safe_method(&Method::POST));
        assert!(!is_safe_method(&Method::PUT));
        assert!(!is_safe_method(&Method::PATCH));
        assert!(!is_safe_method(&Method::DELETE));
    }
}
