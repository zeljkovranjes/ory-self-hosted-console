//! Console API-key handlers (PROJ-02).
//!
//! All routes sit on the PROTECTED subtree (inherit `auth_guard` 401 +
//! `csrf_guard` 403 on state changes — T-11-17). The key is write-only after
//! issue:
//!   - issue  → mints a raw key, returns it EXACTLY ONCE in the issue response.
//!   - GET/list → [`ApiKeyView`] only (masked `key_prefix` + dots).
//!   - revoke → flips `revoked_at`; the masked view's `state` becomes "Revoked".
//!
//! The key is ONE-WAY SHA-256 hashed at rest (T-11-11) — the INVERSE of the
//! recoverable webhook secret. There is no rotate/reveal-again path: a lost key
//! is re-issued, never recovered.

use salvo::prelude::*;
use serde::Deserialize;
use uuid::Uuid;

use crate::db::models::Session;
use crate::error::AppError;

use super::{queries, ApiKeyView};

/// Obtain the console pool from the Depot, cloning BEFORE any await.
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// The authenticated admin id from the Depot `Session` (auth_guard-injected),
/// recorded as `created_by`. `None` only if the session is somehow absent.
fn actor_id(depot: &mut Depot) -> Option<Uuid> {
    depot.obtain::<Session>().ok().map(|s| s.admin_id)
}

#[derive(Debug, Deserialize)]
struct IssueBody {
    name: String,
}

/// POST /api/console/api-keys — issue a key. Returns the RAW key EXACTLY ONCE
/// (the `key` field is present only in this response), alongside the masked view.
#[handler]
pub async fn issue_api_key(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let created_by = actor_id(depot);
    let pool = pool(depot)?;
    let body: IssueBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid api-key body: {e}")))?;
    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("API key name is required.".into()));
    }

    let issued = queries::issue_api_key(&pool, body.name.trim(), created_by).await?;

    // The ONE-TIME raw reveal: forwarded here and only here (mirrors the Hydra
    // create-secret one-time-forward shape). The persisted view never carries it.
    let mut value = serde_json::to_value(&issued.view)
        .map_err(|e| AppError::Internal(format!("serialize api key: {e}")))?;
    value["key"] = serde_json::Value::String(issued.raw);
    Ok(Json(value))
}

/// GET /api/console/api-keys — masked list (no raw, no hash).
#[handler]
pub async fn list_api_keys(depot: &mut Depot) -> Result<Json<Vec<ApiKeyView>>, AppError> {
    let pool = pool(depot)?;
    let rows = queries::list_api_keys(&pool).await?;
    Ok(Json(rows))
}

/// POST /api/console/api-keys/{id}/revoke — flip `revoked_at` (state change →
/// CSRF-guarded). Returns the updated masked view; 404 if no such key.
#[handler]
pub async fn revoke_api_key(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<ApiKeyView>, AppError> {
    let pool = pool(depot)?;
    let raw = req.param::<String>("id").ok_or(AppError::NotFound)?;
    let id = Uuid::parse_str(&raw).map_err(|_| AppError::NotFound)?;
    let view = queries::revoke_api_key(&pool, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(view))
}
