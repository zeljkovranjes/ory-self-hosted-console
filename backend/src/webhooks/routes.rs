//! Webhook CRUD + delivery-log + redeliver handlers (HOOK-03).
//!
//! All routes sit on the PROTECTED subtree (inherit `auth_guard` 401 +
//! `csrf_guard` 403 on state changes). The signing secret is write-only:
//!   - create  → mints a secret, returns it ONCE in the create response.
//!   - GET/list → [`super::WebhookView`] only (masked `secret_set` badge).
//!   - update  → never touches the secret (cannot blank it on a routine edit).
//!   - rotate  → mints + returns a NEW secret ONCE.
//!
//! The SSRF guard validates the URL at create/update for fast 422 feedback; the
//! worker re-validates authoritatively at delivery time.

use salvo::prelude::*;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::session::generate_token;
use crate::error::AppError;

use super::{queries, ssrf, WebhookView};

/// Obtain the console pool from the Depot, cloning BEFORE any await (the Depot
/// pattern — never hold a borrow across `.await`).
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

#[derive(Debug, Deserialize)]
struct CreateWebhookBody {
    name: String,
    url: String,
    events: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct UpdateWebhookBody {
    name: String,
    url: String,
    events: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

/// POST /api/webhooks — create. Validates the URL (fast 422), mints the signing
/// secret, and returns it EXACTLY ONCE (`secret` field present only here).
#[handler]
pub async fn create_webhook(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = pool(depot)?;
    let body: CreateWebhookBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid webhook body: {e}")))?;

    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("Webhook name is required.".into()));
    }
    if body.events.is_empty() {
        return Err(AppError::BadRequest(
            "Select at least one event.".into(),
        ));
    }
    // Fast-feedback SSRF check at create (the worker re-validates at delivery).
    ssrf::validate_url(&body.url).await?;

    let secret = generate_token();
    let row = queries::create_webhook(
        &pool,
        body.name.trim(),
        &body.url,
        &body.events,
        &secret,
        body.enabled,
    )
    .await?;

    // The ONE-TIME secret reveal: forwarded here and only here.
    let view: WebhookView = row.into();
    let mut value = serde_json::to_value(&view)
        .map_err(|e| AppError::Internal(format!("serialize webhook: {e}")))?;
    value["secret"] = serde_json::Value::String(secret);
    Ok(Json(value))
}

/// GET /api/webhooks — list (secret-free views).
#[handler]
pub async fn list_webhooks(depot: &mut Depot) -> Result<Json<Vec<WebhookView>>, AppError> {
    let pool = pool(depot)?;
    let rows = queries::list_webhooks(&pool).await?;
    Ok(Json(rows))
}

/// GET /api/webhooks/{id} — detail (secret-free view).
#[handler]
pub async fn get_webhook(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<WebhookView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let row = queries::get_webhook(&pool, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(row.into()))
}

/// PUT /api/webhooks/{id} — update name/url/events/enabled. The secret is NEVER
/// touched here (cannot be blanked); rotate is a separate explicit action.
#[handler]
pub async fn update_webhook(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<WebhookView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let body: UpdateWebhookBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid webhook body: {e}")))?;

    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("Webhook name is required.".into()));
    }
    if body.events.is_empty() {
        return Err(AppError::BadRequest("Select at least one event.".into()));
    }
    // Re-validate the (possibly changed) URL.
    ssrf::validate_url(&body.url).await?;

    let row = queries::update_webhook(
        &pool,
        id,
        body.name.trim(),
        &body.url,
        &body.events,
        body.enabled,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row.into()))
}

/// DELETE /api/webhooks/{id}.
#[handler]
pub async fn delete_webhook(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    if queries::delete_webhook(&pool, id).await? {
        res.status_code(StatusCode::NO_CONTENT);
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// POST /api/webhooks/{id}/rotate-secret — mint + return a NEW secret ONCE.
#[handler]
pub async fn rotate_secret(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let secret = generate_token();
    let row = queries::rotate_secret(&pool, id, &secret)
        .await?
        .ok_or(AppError::NotFound)?;
    let view: WebhookView = row.into();
    let mut value = serde_json::to_value(&view)
        .map_err(|e| AppError::Internal(format!("serialize webhook: {e}")))?;
    value["secret"] = serde_json::Value::String(secret);
    Ok(Json(value))
}

/// GET /api/webhooks/deliveries — list (optional ?webhook_id= & ?status= filter).
#[handler]
pub async fn list_deliveries(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Vec<super::DeliveryView>>, AppError> {
    let pool = pool(depot)?;
    let webhook_id = req
        .query::<String>("webhook_id")
        .and_then(|s| Uuid::parse_str(&s).ok());
    let status = req.query::<String>("status");
    let rows =
        queries::list_deliveries(&pool, webhook_id, status.as_deref(), 200).await?;
    Ok(Json(rows))
}

/// GET /api/webhooks/deliveries/{id} — detail.
#[handler]
pub async fn get_delivery(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<super::DeliveryView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let row = queries::get_delivery(&pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// POST /api/webhooks/deliveries/{id}/redeliver — re-enqueue a fresh pending
/// delivery from an existing one (a state change → CSRF-guarded).
#[handler]
pub async fn redeliver(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let existing = queries::get_delivery(&pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let new_id =
        queries::insert_delivery(&pool, existing.webhook_id, &existing.event, &existing.payload)
            .await?;
    Ok(Json(serde_json::json!({ "id": new_id })))
}

/// Parse the `{id}` path param into a Uuid (404 on a malformed id).
fn path_id(req: &mut Request) -> Result<Uuid, AppError> {
    let raw = req
        .param::<String>("id")
        .ok_or(AppError::NotFound)?;
    Uuid::parse_str(&raw).map_err(|_| AppError::NotFound)
}
