//! Console audit log (ACT-04).
//!
//! A response-phase Salvo hoop attached to the PROTECTED subtree records every
//! STATE-CHANGING request (POST/PUT/PATCH/DELETE) as an append-only row in
//! `console_audit_log`, capturing:
//!   - the actor — read best-effort from the `Session` the `auth_guard` injected
//!     into the Depot (NEVER a client-supplied field — T-11-14 spoofing
//!     mitigation); NULL when no session is present (e.g. a rejected 401),
//!   - the HTTP method + path,
//!   - the outcome — `success` on a 2xx, otherwise `failure`.
//!
//! The hoop runs the handler FIRST (`ctrl.call_next`) so the outcome reflects
//! the real status, then records best-effort: a failed insert is logged and
//! swallowed so auditing NEVER blocks or fails the user's response.
//!
//! WR-05: the hoop is mounted AHEAD of `auth_guard`/`csrf_guard` (it sits at the
//! top of the protected subtree and wraps them via `call_next`), so a REJECTED
//! state change — failed auth (401) or missing/forged CSRF (403) — is recorded
//! with `outcome:"failure"`, not just handler-level 4xx/5xx. On a 401 the actor
//! is NULL (the session was never injected); on a 403 CSRF failure the session is
//! present (auth ran first), so the probing actor is captured.
//!
//! Safe methods (GET/HEAD/OPTIONS) are NOT audited (reads are side-effect free).
//! The log is append-only: there is a read-only list route ([`routes`]) and an
//! age-based backend prune, but NO update/delete-by-id route (T-11-13).

pub mod queries;
pub mod routes;

use salvo::http::Method;
use salvo::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::models::Session;
use crate::error::AppError;

/// The secret-free audit-log row returned by the read-only list view. The
/// `console_audit_log` table has NO secret column — only the actor id/email,
/// the method/path, the target, the outcome, and free-form jsonb metadata
/// (T-11-12). Safe to derive `Serialize`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditView {
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub action: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: String,
    pub metadata: Option<serde_json::Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Whether an HTTP method is "safe" (no state change) and therefore NOT audited
/// (mirrors `auth::middleware::is_safe_method`).
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Compute the audit outcome from the response status: `success` on a 2xx (or an
/// unset status, which Salvo renders as 200), `failure` otherwise.
fn outcome_for(status: Option<StatusCode>) -> &'static str {
    match status {
        Some(code) if code.is_success() => "success",
        None => "success", // unset == implicit 200 OK
        _ => "failure",
    }
}

/// Response-phase audit hoop (ACT-04 / RESEARCH Pattern 5 / WR-05).
///
/// Mounted at the TOP of the protected subtree, AHEAD of `auth_guard`/`csrf_guard`.
/// Runs the downstream chain (both guards + the handler) FIRST via `call_next`,
/// then (for state-changing methods only) records the actor + method + path +
/// outcome into `console_audit_log`. Because it wraps the guards, a 401/403
/// rejection is still audited with `outcome:"failure"`. The actor is read
/// best-effort from the Depot `Session` (`auth_guard`-injected) — never from the
/// request body (T-11-14); a rejected-before-auth request records a NULL actor
/// rather than fabricating one. The insert is best-effort: a DB failure is logged
/// at `warn` and swallowed so auditing can never block or fail the user-facing
/// response.
#[handler]
pub async fn audit_hoop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // 1. Run the handler (and any nested hoops) FIRST so we audit the real
    //    outcome. Capture the method/path up front (req is borrowed afterwards).
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    ctrl.call_next(req, depot, res).await;

    // 2. Only state-changing requests are audited (T-11-13 append-only log of
    //    mutations; reads are side-effect free).
    if is_safe_method(&method) {
        return;
    }

    // 3. Actor from the injected Session — NEVER a client-supplied value
    //    (T-11-14). A missing session (e.g. a 401 that never reached the handler)
    //    records a NULL actor rather than fabricating one.
    let actor_id = depot.obtain::<Session>().ok().map(|s| s.admin_id);

    // 4. Resolve the actor email best-effort for a human-readable log. Failure to
    //    resolve is non-fatal — the id is the authoritative actor.
    let pool = match depot.obtain::<sqlx::PgPool>() {
        Ok(p) => p.clone(),
        Err(_) => {
            tracing::warn!("audit hoop: pool missing from depot; skipping audit row");
            return;
        }
    };
    let actor_email = match actor_id {
        Some(id) => crate::db::queries::get_admin_by_id(&pool, id)
            .await
            .ok()
            .flatten()
            .map(|a| a.email),
        None => None,
    };

    let outcome = outcome_for(res.status_code);
    // `action` is the coarse "<METHOD> <path>" label; richer target_type/target_id
    // are reserved for explicit `audit()` calls in high-value handlers.
    let action = format!("{method} {path}");

    if let Err(e) = queries::insert_audit(
        &pool,
        actor_id,
        actor_email.as_deref(),
        &action,
        Some(method.as_str()),
        Some(&path),
        None,
        None,
        outcome,
        None,
    )
    .await
    {
        // Best-effort: never block/fail the response on an audit write failure.
        tracing::warn!(error = %e, "audit hoop: failed to record audit row");
    }
}

/// Explicit, richer audit helper for high-value handlers that want to record a
/// `target_type`/`target_id` (e.g. identity delete, client delete, webhook
/// change) beyond what the blanket hoop captures. Best-effort + secret-free.
///
/// `actor` is the authenticated session (the caller passes the Depot `Session`),
/// so the actor can never be spoofed from request input (T-11-14).
#[allow(clippy::too_many_arguments)]
pub async fn audit(
    pool: &sqlx::PgPool,
    actor: Option<&Session>,
    actor_email: Option<&str>,
    action: &str,
    method: Option<&str>,
    path: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    outcome: &str,
    metadata: Option<&serde_json::Value>,
) -> Result<Uuid, AppError> {
    queries::insert_audit(
        pool,
        actor.map(|s| s.admin_id),
        actor_email,
        action,
        method,
        path,
        target_type,
        target_id,
        outcome,
        metadata,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_methods_are_not_audited() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        assert!(is_safe_method(&Method::OPTIONS));
        assert!(!is_safe_method(&Method::POST));
        assert!(!is_safe_method(&Method::PUT));
        assert!(!is_safe_method(&Method::PATCH));
        assert!(!is_safe_method(&Method::DELETE));
    }

    #[test]
    fn outcome_maps_2xx_to_success_else_failure() {
        assert_eq!(outcome_for(Some(StatusCode::OK)), "success");
        assert_eq!(outcome_for(Some(StatusCode::NO_CONTENT)), "success");
        assert_eq!(outcome_for(None), "success");
        assert_eq!(outcome_for(Some(StatusCode::BAD_REQUEST)), "failure");
        assert_eq!(outcome_for(Some(StatusCode::INTERNAL_SERVER_ERROR)), "failure");
        assert_eq!(outcome_for(Some(StatusCode::FORBIDDEN)), "failure");
    }
}
