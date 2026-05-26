//! Parameterized console-DB queries for `webhooks` / `webhook_deliveries`.
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation (threat
//! T-11-09 / SQL injection). Secret-bearing rows map to [`WebhookRow`] (no
//! `Serialize`); GET/list map to [`WebhookView`] which carries no secret.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

use super::{DeliveryView, WebhookRow, WebhookView};

/// A row claimed off the delivery queue (the worker's working set). Carries only
/// what the worker needs to deliver — NOT the secret (it fetches that via the
/// owning webhook so a disabled/deleted webhook short-circuits).
#[derive(Debug, Clone)]
pub struct ClaimedDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub attempt: i32,
    pub max_attempts: i32,
}

// --- webhooks CRUD ----------------------------------------------------------

/// Create a webhook. The `secret` is the freshly-minted recoverable signing key
/// (the caller mints it via `auth::session::generate_token`).
pub async fn create_webhook(
    pool: &PgPool,
    name: &str,
    url: &str,
    events: &[String],
    secret: &str,
    enabled: bool,
) -> Result<WebhookRow, AppError> {
    let row = sqlx::query_as!(
        WebhookRow,
        r#"
        INSERT INTO webhooks (name, url, events, secret, enabled)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, url, events, secret, enabled, created_at, updated_at
        "#,
        name,
        url,
        events,
        secret,
        enabled
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// List all webhooks as secret-free views (newest first).
pub async fn list_webhooks(pool: &PgPool) -> Result<Vec<WebhookView>, AppError> {
    // Compute the masked badge in SQL so the secret never enters a Rust value
    // that could be accidentally serialized.
    let rows = sqlx::query!(
        r#"
        SELECT id, name, url, events, (secret <> '') AS "secret_set!",
               enabled, created_at, updated_at
        FROM webhooks
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WebhookView {
            id: r.id,
            name: r.name,
            url: r.url,
            events: r.events,
            secret_set: r.secret_set,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

/// Fetch the full row (incl. secret) by id, if present. Used internally by the
/// update merge and the worker — NEVER rendered to a response directly.
pub async fn get_webhook(pool: &PgPool, id: Uuid) -> Result<Option<WebhookRow>, AppError> {
    let row = sqlx::query_as!(
        WebhookRow,
        r#"
        SELECT id, name, url, events, secret, enabled, created_at, updated_at
        FROM webhooks WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Update mutable fields. `secret` is intentionally NOT a parameter here — the
/// secret can only be changed via [`rotate_secret`], so an edit can NEVER blank
/// it (preserve-on-blank is enforced by not exposing it on this path).
pub async fn update_webhook(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    url: &str,
    events: &[String],
    enabled: bool,
) -> Result<Option<WebhookRow>, AppError> {
    let row = sqlx::query_as!(
        WebhookRow,
        r#"
        UPDATE webhooks
        SET name = $2, url = $3, events = $4, enabled = $5, updated_at = now()
        WHERE id = $1
        RETURNING id, name, url, events, secret, enabled, created_at, updated_at
        "#,
        id,
        name,
        url,
        events,
        enabled
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Rotate the signing secret to a new recoverable value. Returns the updated row
/// (the caller reveals the new secret exactly once).
pub async fn rotate_secret(
    pool: &PgPool,
    id: Uuid,
    new_secret: &str,
) -> Result<Option<WebhookRow>, AppError> {
    let row = sqlx::query_as!(
        WebhookRow,
        r#"
        UPDATE webhooks
        SET secret = $2, updated_at = now()
        WHERE id = $1
        RETURNING id, name, url, events, secret, enabled, created_at, updated_at
        "#,
        id,
        new_secret
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete a webhook (its deliveries cascade).
pub async fn delete_webhook(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
    let res = sqlx::query!("DELETE FROM webhooks WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

// --- deliveries -------------------------------------------------------------

/// Enqueue a delivery (status 'pending', due now). Used by event producers and
/// the redeliver route.
pub async fn insert_delivery(
    pool: &PgPool,
    webhook_id: Uuid,
    event: &str,
    payload: &serde_json::Value,
) -> Result<Uuid, AppError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO webhook_deliveries (webhook_id, event, payload)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        webhook_id,
        event,
        payload
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// List deliveries (optionally filtered by webhook_id and/or status), newest
/// first, bounded.
pub async fn list_deliveries(
    pool: &PgPool,
    webhook_id: Option<Uuid>,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<DeliveryView>, AppError> {
    // A single parameterized query with NULL-guarded optional filters — no
    // string interpolation (T-11-09).
    let rows = sqlx::query_as!(
        DeliveryView,
        r#"
        SELECT id, webhook_id, event, payload, status, attempt, max_attempts,
               next_attempt_at, last_status_code, last_error, created_at, updated_at
        FROM webhook_deliveries
        WHERE ($1::uuid IS NULL OR webhook_id = $1)
          AND ($2::text IS NULL OR status = $2)
        ORDER BY created_at DESC
        LIMIT $3
        "#,
        webhook_id,
        status,
        limit
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetch a single delivery by id.
pub async fn get_delivery(pool: &PgPool, id: Uuid) -> Result<Option<DeliveryView>, AppError> {
    let row = sqlx::query_as!(
        DeliveryView,
        r#"
        SELECT id, webhook_id, event, payload, status, attempt, max_attempts,
               next_attempt_at, last_status_code, last_error, created_at, updated_at
        FROM webhook_deliveries WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically claim up to `limit` due deliveries with FOR UPDATE SKIP LOCKED.
///
/// SKIP LOCKED means a concurrent worker (or a worker that restarted mid-flight)
/// NEVER picks the same row — the 'delivering' transition is committed before any
/// outbound HTTP, so a crash leaves the row 'delivering' (the stale reaper
/// recovers it) and never double-delivers (T-11-06).
pub async fn claim_due_deliveries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ClaimedDelivery>, AppError> {
    let rows = sqlx::query!(
        r#"
        UPDATE webhook_deliveries
        SET status = 'delivering', updated_at = now()
        WHERE id IN (
            SELECT id FROM webhook_deliveries
            WHERE status IN ('pending', 'failed') AND next_attempt_at <= now()
            ORDER BY next_attempt_at
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        RETURNING id, webhook_id, event, payload, attempt, max_attempts
        "#,
        limit
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ClaimedDelivery {
            id: r.id,
            webhook_id: r.webhook_id,
            event: r.event,
            payload: r.payload,
            attempt: r.attempt,
            max_attempts: r.max_attempts,
        })
        .collect())
}

/// Record the outcome of a delivery attempt: set the new status, the next
/// attempt time (for retries), and the last status code / error.
pub async fn record_delivery_result(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    attempt: i32,
    next_attempt_at: OffsetDateTime,
    last_status_code: Option<i32>,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        UPDATE webhook_deliveries
        SET status = $2, attempt = $3, next_attempt_at = $4,
            last_status_code = $5, last_error = $6, updated_at = now()
        WHERE id = $1
        "#,
        id,
        status,
        attempt,
        next_attempt_at,
        last_status_code,
        last_error
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete terminal (delivered/dead) deliveries older than `older_than`. Returns
/// the number of rows pruned (HOOK-03 retention; mirrors delete_expired_sessions).
pub async fn prune_terminal_deliveries(
    pool: &PgPool,
    older_than: OffsetDateTime,
) -> Result<u64, AppError> {
    let res = sqlx::query!(
        r#"
        DELETE FROM webhook_deliveries
        WHERE status IN ('delivered', 'dead') AND updated_at < $1
        "#,
        older_than
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Return rows stuck in 'delivering' past `stale_before` (a worker crashed
/// mid-flight) back to 'failed' so they are re-claimed (Pitfall 5 / T-11-06).
pub async fn reap_stale_delivering(
    pool: &PgPool,
    stale_before: OffsetDateTime,
) -> Result<u64, AppError> {
    let res = sqlx::query!(
        r#"
        UPDATE webhook_deliveries
        SET status = 'failed', updated_at = now()
        WHERE status = 'delivering' AND updated_at < $1
        "#,
        stale_before
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
