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
