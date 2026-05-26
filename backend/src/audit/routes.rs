//! Read-only audit-log view (ACT-04).
//!
//! `GET /api/console/audit` returns a newest-first, filtered, paginated list of
//! [`AuditView`] rows. There is DELIBERATELY no create/update/delete route — the
//! log is append-only (written only by the response-phase hoop) and tamper-
//! resistant (T-11-13). Pruning is age-based and backend-only.

use salvo::prelude::*;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

use super::{queries, AuditView};

/// Default/maximum page size for the audit list (bounded so a single read can
/// never pull an unbounded result set).
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Obtain the console pool from the Depot, cloning BEFORE any await.
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// Parse an optional RFC3339 timestamp query param (`after`/`before`); a present
/// but malformed value is a 400 (operator-safe), an absent value is `None`.
fn ts_query(req: &mut Request, key: &str) -> Result<Option<OffsetDateTime>, AppError> {
    match req.query::<String>(key) {
        Some(raw) if !raw.is_empty() => OffsetDateTime::parse(&raw, &Rfc3339)
            .map(Some)
            .map_err(|_| AppError::BadRequest(format!("invalid {key} timestamp (want RFC3339)"))),
        _ => Ok(None),
    }
}

/// `GET /api/console/audit` — read-only, filtered, paginated audit log.
///
/// Query params (all optional): `actor_id` (uuid), `action`, `outcome`,
/// `after`/`before` (RFC3339), `limit` (clamped to [1, 500]).
#[handler]
pub async fn list_audit(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Vec<AuditView>>, AppError> {
    let pool = pool(depot)?;

    let actor_id = req
        .query::<String>("actor_id")
        .and_then(|s| Uuid::parse_str(&s).ok());
    let action = req.query::<String>("action").filter(|s| !s.is_empty());
    let outcome = req.query::<String>("outcome").filter(|s| !s.is_empty());
    let after = ts_query(req, "after")?;
    let before = ts_query(req, "before")?;
    let limit = req
        .query::<i64>("limit")
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);

    let rows = queries::list_audit(
        &pool,
        actor_id,
        action.as_deref(),
        outcome.as_deref(),
        after,
        before,
        limit,
    )
    .await?;
    Ok(Json(rows))
}
