//! Event-stream sinks (Phase 17 — EVT-01/02/03).
//!
//! Streams the Phase-11 console audit log (`console_audit_log`) to operator-
//! configured external sinks. This module EXTENDS the shipped webhook dispatcher
//! (`crate::webhooks`) rather than reinventing anything security-critical:
//!   - [`sinks::webhook`] — the DEFAULT sink, reusing `webhooks::{ssrf, hmac}`
//!     (zero new deps): resolve-validate-pin SSRF guard + HMAC-SHA256 signing.
//!   - [`sinks::nats`]    — `#[cfg(feature = "events-nats")]` async-nats adapter.
//!   - [`sinks::kafka`]   — `#[cfg(feature = "events-kafka")]` rdkafka adapter.
//!   - [`redact`]         — the PII/secret redaction pass (EVT-03), applied BEFORE
//!     enqueue so the durable queue never stores raw PII.
//!   - [`queries`]        — sqlx wrappers for `event_sinks` / `event_deliveries`
//!     + the per-sink audit cursor.
//!
//! CRITICAL secret discipline (BACK-07 / T-17-01 — mirrors the `WebhookRow`
//! pattern): each sink's `secret` is RECOVERABLE (the worker must read it to sign
//! / authenticate), so [`EventSinkRow`] carries it — and therefore deliberately
//! does NOT derive `Serialize`, so the compiler makes `res.render(Json(row))`
//! impossible. Every API response maps to [`EventSinkView`], which has NO secret-
//! bearing field (only `secret_set` / `sasl_username_set` masked badges).
//!
//! REGISTRY (EVT-01 / T-17-06): the dispatch surface is a feature-gated `enum`
//! [`Sink`] (no `async-trait`, no `dyn`, no heap alloc) — a disabled adapter is an
//! ABSENT `#[cfg]` variant AND an absent match arm in [`Sink::build`], so the
//! default build never NAMES the missing crate. A sink kind whose adapter feature
//! is not compiled in is a clean recorded error, never a panic.

pub mod queries;
pub mod redact;
pub mod sinks;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// A full `event_sinks` row, INCLUDING the recoverable `secret` + `sasl_username`.
///
/// Deliberately NOT `Serialize` (mirrors [`crate::webhooks::WebhookRow`]): because
/// the secret-bearing columns live here, the type cannot be rendered into a
/// response body — credentials physically cannot leak (T-17-01). Handlers map it
/// to [`EventSinkView`] for any GET/list, and read `.secret` only inside the sink
/// adapter to sign / authenticate a delivery.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventSinkRow {
    pub id: Uuid,
    pub name: String,
    /// One of `webhook` | `nats` | `kafka`. A kind whose adapter feature is not
    /// compiled is rejected by [`Sink::build`], never delivered.
    pub kind: String,
    /// Webhook URL / NATS broker_url / Kafka brokers list.
    pub target: String,
    /// NATS subject / Kafka topic. `None` for webhook sinks.
    pub subject: Option<String>,
    /// Subscribed audit-action allowlist.
    pub events: Vec<String>,
    /// RECOVERABLE credential — webhook HMAC secret / NATS creds-or-token /
    /// Kafka SASL password. Never serialized (this row is not `Serialize`).
    pub secret: String,
    /// Optional SASL / NATS username (paired with `secret` as the password).
    pub sasl_username: Option<String>,
    /// Whether to request TLS to the broker.
    pub tls: bool,
    pub enabled: bool,
    /// Per-sink cursor into `console_audit_log` (Pitfall 5): the id of the last
    /// audit row fanned out to this sink. `None` only transiently before the
    /// first tick; `create_sink` seeds the cursor timestamp to now().
    pub last_event_id: Option<Uuid>,
    /// Per-sink cursor timestamp — initialized to now() on create so a new sink
    /// streams only events AFTER it was created (no historical replay).
    pub last_event_cursor_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// The credential-free DTO returned by every GET/list. `secret_set` /
/// `sasl_username_set` are masked badges — the raw values are NEVER serialized
/// here (T-17-01).
#[derive(Debug, Clone, Serialize)]
pub struct EventSinkView {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub subject: Option<String>,
    pub events: Vec<String>,
    /// Masked badge only — true when a credential is stored.
    pub secret_set: bool,
    /// Masked badge only — true when a SASL/NATS username is stored.
    pub sasl_username_set: bool,
    pub tls: bool,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<EventSinkRow> for EventSinkView {
    fn from(row: EventSinkRow) -> Self {
        EventSinkView {
            id: row.id,
            name: row.name,
            kind: row.kind,
            target: row.target,
            subject: row.subject,
            events: row.events,
            secret_set: !row.secret.is_empty(),
            sasl_username_set: row.sasl_username.as_deref().is_some_and(|u| !u.is_empty()),
            tls: row.tls,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// One already-redacted event ready to be delivered to a sink.
///
/// `id` is the idempotency key (EVT-02) — it IS the source `console_audit_log`
/// row's UUID, so an at-least-once retry carries the SAME id and consumers dedupe
/// on it. `data` is the PII-redacted payload (EVT-03) produced by [`redact::redact`].
#[derive(Debug, Clone, Serialize)]
pub struct OutboundEvent {
    /// Idempotency key = the source audit row id (EVT-02).
    pub id: Uuid,
    /// Event name (the audit `action`).
    pub event: String,
    /// When the source event occurred (the audit row `created_at`).
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The redacted payload — no raw PII / secrets (EVT-03).
    pub data: serde_json::Value,
}
