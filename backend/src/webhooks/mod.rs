//! Webhook dispatcher (Phase 11 — HOOK-01/02/03).
//!
//! The security-critical centerpiece of the milestone. Entirely in the backend's
//! OWN `console` Postgres schema — there is NO Ory webhook primitive. Composed of:
//!   - [`ssrf`]    — the outbound trust-boundary guard (resolve, classify, pin).
//!   - [`hmac`]    — the `X-Console-Signature` HMAC-SHA256 signer.
//!   - [`worker`]  — the durable FOR-UPDATE-SKIP-LOCKED claim loop, backoff, dead-letter, retention pruning.
//!   - [`queries`] — sqlx wrappers for `webhooks` / `webhook_deliveries`.
//!   - [`routes`]  — CRUD + delivery-log + redeliver handlers (protected subtree).
//!
//! CRITICAL secret discipline (BACK-07 / Pattern 6 / T-11-05): the per-webhook
//! `secret` is RECOVERABLE (the worker must read it to sign), so [`WebhookRow`]
//! carries it — and therefore deliberately does NOT derive `Serialize`, so the
//! compiler makes `res.render(Json(row))` impossible. Every API response maps to
//! [`WebhookView`], which has NO secret-bearing field (only a `secret_set` bool).
//! The raw secret is revealed exactly once, in the create/rotate response.

pub mod hmac;
pub mod queries;
pub mod routes;
pub mod ssrf;
pub mod worker;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// A full `webhooks` row, INCLUDING the recoverable `secret`.
///
/// Deliberately NOT `Serialize` (mirrors `db::models` discipline): because the
/// secret column lives here, the type cannot be rendered into a response body —
/// secrets physically cannot leak. Handlers map it to [`WebhookView`] for any
/// GET/list, and read `.secret` only inside the worker to sign a delivery.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// The secret-free DTO returned by every GET/list. `secret_set` is a masked
/// badge ("Set"/"Not set") — the raw secret is NEVER serialized here.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookView {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    /// Masked badge only — true when a signing secret is stored. The raw value
    /// is never present in this DTO (T-11-05).
    pub secret_set: bool,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<WebhookRow> for WebhookView {
    fn from(row: WebhookRow) -> Self {
        WebhookView {
            id: row.id,
            name: row.name,
            url: row.url,
            events: row.events,
            secret_set: !row.secret.is_empty(),
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// A `webhook_deliveries` row for the delivery-log view. Carries no secret, so
/// it is safe to `Serialize` directly.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DeliveryView {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempt: i32,
    pub max_attempts: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub next_attempt_at: OffsetDateTime,
    pub last_status_code: Option<i32>,
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
