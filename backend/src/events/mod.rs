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
pub mod routes;
pub mod sinks;
pub mod worker;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;
use sinks::webhook::WebhookSink;
#[cfg(feature = "events-nats")]
use sinks::nats::NatsSink;
#[cfg(feature = "events-kafka")]
use sinks::kafka::KafkaSink;

/// Runtime sink-dispatch registry (EVT-01).
///
/// An ENUM (not `Box<dyn EventSink>`): native async-fn-in-trait is stable on the
/// 1.95 toolchain, so we get async dispatch with NO `async-trait`, NO `dyn`, and
/// NO heap allocation, and the compiler proves match exhaustiveness. Crucially, a
/// disabled adapter is an ABSENT `#[cfg]` variant AND an absent match arm
/// ([`Sink::build`]), so the default build never references the missing crate
/// (T-17-06).
#[derive(Debug)]
pub enum Sink {
    /// The DEFAULT sink — always present, zero new deps (reuses
    /// `webhooks::{ssrf, hmac}`).
    Webhook(WebhookSink),
    #[cfg(feature = "events-nats")]
    Nats(NatsSink),
    #[cfg(feature = "events-kafka")]
    Kafka(KafkaSink),
}

impl Sink {
    /// Construct the concrete sink for a stored row, dispatching on `row.kind`.
    ///
    /// A kind whose adapter feature is NOT compiled in (or an unknown kind) falls
    /// through to a clean `BadRequest("... not available in this build")` — a
    /// recorded error, NEVER a panic (EVT-01).
    pub fn build(row: &EventSinkRow) -> Result<Self, AppError> {
        match row.kind.as_str() {
            "webhook" => Ok(Sink::Webhook(WebhookSink::from_row(row)?)),
            #[cfg(feature = "events-nats")]
            "nats" => Ok(Sink::Nats(NatsSink::from_row(row)?)),
            #[cfg(feature = "events-kafka")]
            "kafka" => Ok(Sink::Kafka(KafkaSink::from_row(row)?)),
            other => Err(AppError::BadRequest(format!(
                "sink type '{other}' is not available in this build"
            ))),
        }
    }

    /// Deliver one already-redacted event through the concrete sink.
    ///
    /// `allow_private` is the test/CI escape hatch forwarded to the SSRF guard —
    /// production callers pass `false`. Errors are recorded by the worker as
    /// retry/dead exactly like a webhook non-2xx/transport failure.
    pub async fn deliver(
        &self,
        event: &OutboundEvent,
        allow_private: bool,
    ) -> Result<(), AppError> {
        match self {
            Sink::Webhook(s) => s.deliver(event, allow_private).await,
            #[cfg(feature = "events-nats")]
            Sink::Nats(s) => s.deliver(event, allow_private).await,
            #[cfg(feature = "events-kafka")]
            Sink::Kafka(s) => s.deliver(event, allow_private).await,
        }
    }
}

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// A single `event_deliveries` row for the delivery-log view. Safe to serialize:
/// the `payload` is the ALREADY-REDACTED [`OutboundEvent`] (EVT-03), and the table
/// carries no credential column.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct EventDeliveryView {
    pub id: Uuid,
    pub sink_id: Uuid,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `EventSinkRow` for registry/view tests.
    fn row(kind: &str, target: &str, secret: &str) -> EventSinkRow {
        let now = OffsetDateTime::now_utc();
        EventSinkRow {
            id: Uuid::new_v4(),
            name: "test".into(),
            kind: kind.into(),
            target: target.into(),
            subject: None,
            events: vec!["identity.created".into()],
            secret: secret.into(),
            sasl_username: None,
            tls: false,
            enabled: true,
            last_event_id: None,
            last_event_cursor_at: Some(now),
            created_at: now,
            updated_at: now,
        }
    }

    /// `Sink::build` resolves the always-present webhook adapter.
    #[test]
    fn build_resolves_webhook() {
        let s = Sink::build(&row("webhook", "https://example.com/hook", "sek"));
        assert!(matches!(s, Ok(Sink::Webhook(_))));
    }

    /// A sink kind whose adapter feature is NOT compiled in is a clean
    /// `BadRequest` naming the build, NEVER a panic (registry_unavailable_sink_type).
    #[cfg(not(feature = "events-nats"))]
    #[test]
    fn build_rejects_feature_absent_nats() {
        let err = Sink::build(&row("nats", "nats://broker.example.com:4222", "creds"))
            .unwrap_err();
        match err {
            AppError::BadRequest(m) => {
                assert!(m.contains("not available in this build"), "msg: {m}");
                assert!(m.contains("nats"), "msg: {m}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[cfg(not(feature = "events-kafka"))]
    #[test]
    fn build_rejects_feature_absent_kafka() {
        let err = Sink::build(&row("kafka", "broker.example.com:9092", "sasl-pw"))
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// An unknown kind is rejected, never panics.
    #[test]
    fn build_rejects_unknown_kind() {
        let err = Sink::build(&row("smoke-signals", "x", "")).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// EventSinkView never carries the raw secret — only the masked badges
    /// (T-17-01). (Compile-time: EventSinkRow has no Serialize derive.)
    #[test]
    fn view_masks_secret_and_username() {
        let mut r = row("webhook", "https://example.com/hook", "the-secret");
        r.sasl_username = Some("svc-user".into());
        let v = EventSinkView::from(r);
        assert!(v.secret_set);
        assert!(v.sasl_username_set);
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("the-secret"), "secret leaked into view JSON: {json}");
        assert!(!json.contains("svc-user"), "username leaked into view JSON: {json}");
    }

    /// An empty secret / absent username produce `false` badges.
    #[test]
    fn view_badges_false_when_empty() {
        let v = EventSinkView::from(row("webhook", "https://example.com/hook", ""));
        assert!(!v.secret_set);
        assert!(!v.sasl_username_set);
    }

    /// The webhook sink rejects a loopback target through the SHARED ssrf guard
    /// when allow_private = false (proves reuse, not reimplementation).
    #[tokio::test]
    async fn webhook_delivery_blocked_by_shared_ssrf_guard() {
        let sink = WebhookSink {
            url: "http://127.0.0.1/hook".into(),
            secret: "sek".into(),
        };
        let event = OutboundEvent {
            id: Uuid::new_v4(),
            event: "identity.created".into(),
            occurred_at: OffsetDateTime::now_utc(),
            data: serde_json::json!({"ok": true}),
        };
        let err = sink.deliver(&event, false).await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
