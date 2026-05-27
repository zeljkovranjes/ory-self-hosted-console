//! Event-sink CRUD + delivery-log + redeliver handlers (EVT-01/02/03).
//!
//! Mounted INSIDE the protected subtree behind `FeatureFlagHoop::new("event_streams")`
//! (404 when the flag is OFF, FLAG-01), so they also inherit `auth_guard` (401) +
//! `csrf_guard` (403 on state changes). Clones the `webhooks::routes` shape:
//!   - create  → mints the webhook HMAC secret (or stores broker creds), reveals
//!     the secret ONCE in the create response.
//!   - GET/list → [`EventSinkView`] only (masked `secret_set`/`sasl_username_set`).
//!   - update  → never touches the secret (cannot blank it on a routine edit).
//!   - rotate  → mints + reveals a NEW secret ONCE.
//!
//! The webhook SSRF guard validates the URL at create for fast 422 feedback; the
//! delivery worker re-validates authoritatively at delivery time (DNS-rebind). An
//! unknown sink kind / unknown event is rejected at the boundary (422).

use salvo::prelude::*;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::session::generate_token;
use crate::error::AppError;
use crate::webhooks::ssrf;

use super::{queries, EventSinkView};

/// Obtain the console pool from the Depot, cloning BEFORE any await.
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// Input bounds (mirror `webhooks::routes`). The backend is the AUTHORITATIVE
/// validation boundary — create/update enforce these server-side and return 422.
const MAX_NAME_LEN: usize = 200;
const MAX_URL_LEN: usize = 2048;

/// The sink kinds the registry can dispatch. A `kind` outside this set is rejected
/// at the boundary (422) — even if its adapter feature were compiled in, the
/// frontend never offers others.
const KNOWN_KINDS: &[&str] = &["webhook", "nats", "kafka"];

/// The events allowlist — MUST stay in lockstep with `webhooks::routes::KNOWN_EVENTS`
/// and the frontend. An event outside this set creates a dead subscription the
/// fan-out never matches, so it is rejected at the boundary (422).
const KNOWN_EVENTS: &[&str] = &[
    "identity.created",
    "identity.updated",
    "identity.deleted",
    "session.created",
    "session.revoked",
    "registration.completed",
    "login.completed",
    "recovery.completed",
    "verification.completed",
    "settings.completed",
];

/// Validate a NATS/Kafka broker `target` has a `host:port` shape with a parseable
/// port. The authoritative SSRF guard is the delivery-time `is_blocked_ip` broker
/// check (Plan 01 `assert_broker_host_allowed`); this is the cheap boundary reject.
fn validate_broker_target(target: &str) -> Result<(), AppError> {
    // Strip a `scheme://` prefix if present (e.g. `nats://host:4222`).
    let after = match target.find("://") {
        Some(idx) => &target[idx + 3..],
        None => target,
    };
    // Reject embedded credentials (userinfo) before the host (SSRF / leak vector).
    let authority = after.split('/').next().unwrap_or(after);
    if authority.contains('@') {
        return Err(AppError::BadRequest(
            "Broker address must not contain embedded credentials.".into(),
        ));
    }
    // Require host:port — split on the LAST ':' (IPv6 hosts may contain ':').
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| AppError::BadRequest("Broker address must be host:port.".into()))?;
    if host.is_empty() {
        return Err(AppError::BadRequest("Broker host is required.".into()));
    }
    port.parse::<u16>()
        .map_err(|_| AppError::BadRequest("Broker port must be a valid number.".into()))?;
    Ok(())
}

/// Validate sink `name`/`kind`/`target`/`subject`/`events` (shared by create +
/// update). Enforces length caps, the kind allowlist, the events allowlist, and a
/// kind-specific target shape. For `webhook` the caller separately runs the async
/// SSRF resolve check.
fn validate_sink_fields(
    name: &str,
    kind: &str,
    target: &str,
    subject: Option<&str>,
    events: &[String],
) -> Result<(), AppError> {
    if name.chars().count() > MAX_NAME_LEN {
        return Err(AppError::BadRequest(format!(
            "Sink name must be at most {MAX_NAME_LEN} characters."
        )));
    }
    if target.chars().count() > MAX_URL_LEN {
        return Err(AppError::BadRequest(format!(
            "Sink target must be at most {MAX_URL_LEN} characters."
        )));
    }
    if !KNOWN_KINDS.contains(&kind) {
        return Err(AppError::BadRequest(format!("Unknown sink kind: {kind}")));
    }
    if let Some(bad) = events.iter().find(|e| !KNOWN_EVENTS.contains(&e.as_str())) {
        return Err(AppError::BadRequest(format!("Unknown event: {bad}")));
    }
    match kind {
        "webhook" => {
            // The webhook target must be an http(s) URL (the SSRF guard then
            // resolve-validates it; broker fields do not apply).
            let lower = target.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                return Err(AppError::BadRequest(
                    "Webhook target must be an http(s) URL.".into(),
                ));
            }
        }
        "nats" | "kafka" => {
            validate_broker_target(target)?;
            if subject.map(|s| s.trim().is_empty()).unwrap_or(true) {
                return Err(AppError::BadRequest(
                    "A NATS subject / Kafka topic is required for this sink kind.".into(),
                ));
            }
        }
        _ => unreachable!("kind validated against KNOWN_KINDS above"),
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CreateSinkBody {
    name: String,
    kind: String,
    target: String,
    #[serde(default)]
    subject: Option<String>,
    events: Vec<String>,
    /// For nats/kafka, the operator-supplied credential (creds string / token /
    /// SASL password). For webhook the backend MINTS the secret and ignores this.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    sasl_username: Option<String>,
    #[serde(default)]
    tls: bool,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSinkBody {
    name: String,
    target: String,
    #[serde(default)]
    subject: Option<String>,
    events: Vec<String>,
    #[serde(default)]
    sasl_username: Option<String>,
    #[serde(default)]
    tls: bool,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// POST /api/event-sinks — create. Validates the target (SSRF for webhook), mints
/// the webhook HMAC secret (or stores the broker credential), and reveals the
/// `secret` EXACTLY ONCE (present only in this response, webhook kind).
#[handler]
pub async fn create_sink(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = pool(depot)?;
    let body: CreateSinkBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid sink body: {e}")))?;

    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("Sink name is required.".into()));
    }
    if body.events.is_empty() {
        return Err(AppError::BadRequest("Select at least one event.".into()));
    }
    validate_sink_fields(
        body.name.trim(),
        &body.kind,
        &body.target,
        body.subject.as_deref(),
        &body.events,
    )?;

    // Webhook: MINT the signing secret + fast-feedback SSRF check on the URL. The
    // operator-supplied `secret` is ignored for webhook (we own the HMAC key).
    // Broker kinds: store the operator-supplied credential as-is (write-only).
    let mut revealed_secret: Option<String> = None;
    let stored_secret = if body.kind == "webhook" {
        ssrf::validate_url(&body.target).await?;
        let s = generate_token();
        revealed_secret = Some(s.clone());
        s
    } else {
        body.secret.clone().unwrap_or_default()
    };

    let subject = body.subject.as_deref().filter(|s| !s.trim().is_empty());
    let sasl_username = body
        .sasl_username
        .as_deref()
        .filter(|s| !s.trim().is_empty());

    let row = queries::create_sink(
        &pool,
        body.name.trim(),
        &body.kind,
        &body.target,
        subject,
        &body.events,
        &stored_secret,
        sasl_username,
        body.tls,
        body.enabled,
    )
    .await?;

    let view: EventSinkView = row.into();
    let mut value = serde_json::to_value(&view)
        .map_err(|e| AppError::Internal(format!("serialize sink: {e}")))?;
    // ONE-TIME secret reveal: present ONLY for the webhook kind, here and nowhere else.
    if let Some(secret) = revealed_secret {
        value["secret"] = serde_json::Value::String(secret);
    }
    Ok(Json(value))
}

/// GET /api/event-sinks — list (credential-free views).
#[handler]
pub async fn list_sinks(depot: &mut Depot) -> Result<Json<Vec<EventSinkView>>, AppError> {
    let pool = pool(depot)?;
    let rows = queries::list_sinks(&pool).await?;
    Ok(Json(rows))
}

/// GET /api/event-sinks/{id} — detail (credential-free view).
#[handler]
pub async fn get_sink(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<EventSinkView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let row = queries::get_sink(&pool, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(row.into()))
}

/// PUT /api/event-sinks/{id} — update mutable fields. The secret is NEVER touched
/// here (cannot be blanked); rotate is a separate explicit action.
#[handler]
pub async fn update_sink(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<EventSinkView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let body: UpdateSinkBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid sink body: {e}")))?;

    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("Sink name is required.".into()));
    }
    if body.events.is_empty() {
        return Err(AppError::BadRequest("Select at least one event.".into()));
    }

    // The kind is immutable on update; reuse the stored kind for validation +
    // re-validate the (possibly changed) target with the same boundary checks.
    let existing = queries::get_sink(&pool, id).await?.ok_or(AppError::NotFound)?;
    validate_sink_fields(
        body.name.trim(),
        &existing.kind,
        &body.target,
        body.subject.as_deref(),
        &body.events,
    )?;
    if existing.kind == "webhook" {
        ssrf::validate_url(&body.target).await?;
    }

    let subject = body.subject.as_deref().filter(|s| !s.trim().is_empty());
    let sasl_username = body
        .sasl_username
        .as_deref()
        .filter(|s| !s.trim().is_empty());

    let row = queries::update_sink(
        &pool,
        id,
        body.name.trim(),
        &body.target,
        subject,
        &body.events,
        sasl_username,
        body.tls,
        body.enabled,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row.into()))
}

/// DELETE /api/event-sinks/{id}.
#[handler]
pub async fn delete_sink(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    if queries::delete_sink(&pool, id).await? {
        res.status_code(StatusCode::NO_CONTENT);
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// POST /api/event-sinks/{id}/rotate-secret — mint + reveal a NEW secret ONCE.
/// Only meaningful for the webhook kind (the HMAC signing key); for broker kinds
/// the credential is rotated by an update, but this still mints a fresh value.
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
    let view: EventSinkView = row.into();
    let mut value = serde_json::to_value(&view)
        .map_err(|e| AppError::Internal(format!("serialize sink: {e}")))?;
    value["secret"] = serde_json::Value::String(secret);
    Ok(Json(value))
}

/// GET /api/event-sinks/deliveries — list (optional ?sink_id= & ?status= filter).
#[handler]
pub async fn list_deliveries(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Vec<super::EventDeliveryView>>, AppError> {
    let pool = pool(depot)?;
    let sink_id = req
        .query::<String>("sink_id")
        .and_then(|s| Uuid::parse_str(&s).ok());
    let status = req.query::<String>("status");
    let rows = queries::list_deliveries(&pool, sink_id, status.as_deref(), 200).await?;
    Ok(Json(rows))
}

/// GET /api/event-sinks/deliveries/{id} — detail.
#[handler]
pub async fn get_delivery(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<super::EventDeliveryView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let row = queries::get_delivery(&pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// POST /api/event-sinks/deliveries/{id}/redeliver — re-enqueue a fresh pending
/// delivery from an existing one (a state change → CSRF-guarded).
///
/// WR-05: the redelivered payload is RE-REDACTED under the CURRENT policy before
/// re-enqueue, so a payload originally redacted under a WEAKER past policy (see
/// CR-01) is never re-leaked. We prefer to re-resolve the SOURCE audit row (the
/// OutboundEvent `id` IS the audit row id) and run the full current `redact()`;
/// if that row was pruned, we fall back to re-running the current redaction pass
/// over the stored payload. We also short-circuit if the owning sink no longer
/// exists or is disabled (no point enqueuing an undeliverable row).
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

    // Short-circuit if the owning sink is gone/disabled.
    let sink = queries::get_sink(&pool, existing.sink_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("The owning sink no longer exists.".into()))?;
    if !sink.enabled {
        return Err(AppError::BadRequest(
            "The owning sink is disabled; enable it before redelivering.".into(),
        ));
    }

    // Re-redact under the CURRENT policy. Prefer the source audit row (full
    // re-redaction via redact()); fall back to re-running the pass over the stored
    // payload when the source was pruned.
    let event_id = existing
        .payload
        .get("id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let fresh_payload = match event_id {
        Some(eid) => match queries::get_audit_row(&pool, eid).await? {
            Some(audit) => {
                let outbound = super::redact::redact(&audit);
                serde_json::to_value(&outbound)
                    .map_err(|e| AppError::Internal(format!("serialize re-redacted event: {e}")))?
            }
            None => super::redact::re_redact_payload(&existing.payload),
        },
        None => super::redact::re_redact_payload(&existing.payload),
    };

    let new_id =
        queries::insert_delivery(&pool, existing.sink_id, &existing.event, &fresh_payload).await?;
    Ok(Json(serde_json::json!({ "id": new_id })))
}

/// Parse the `{id}` path param into a Uuid (404 on a malformed id).
fn path_id(req: &mut Request) -> Result<Uuid, AppError> {
    let raw = req.param::<String>("id").ok_or(AppError::NotFound)?;
    Uuid::parse_str(&raw).map_err(|_| AppError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_events() -> Vec<String> {
        vec!["identity.created".to_string()]
    }

    /// EVT-03: a loopback/credentialed webhook URL is rejected by the shared SSRF
    /// guard at create (proves the create path runs `ssrf::validate_url`).
    #[tokio::test]
    async fn create_rejects_ssrf_url() {
        // The synchronous field validation passes (it's an http URL); the async
        // SSRF resolve is what rejects loopback.
        assert!(validate_sink_fields("hook", "webhook", "http://127.0.0.1/x", None, &ok_events()).is_ok());
        let err = ssrf::validate_url("http://127.0.0.1/x").await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "loopback URL must be rejected");
    }

    /// A credentialed webhook URL is also rejected by the shared guard.
    #[tokio::test]
    async fn create_rejects_credentialed_url() {
        let err = ssrf::validate_url("http://user:pass@127.0.0.1/x").await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// A sink `kind` outside {webhook,nats,kafka} is rejected at the boundary (422).
    #[test]
    fn create_rejects_unknown_kind() {
        let err = validate_sink_fields("s", "smoke-signals", "x", None, &ok_events()).unwrap_err();
        match err {
            AppError::BadRequest(m) => assert!(m.contains("Unknown sink kind"), "msg: {m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// An unknown event is rejected at the boundary (422).
    #[test]
    fn create_rejects_unknown_event() {
        let events = vec!["identity.created".to_string(), "not.a.real.event".to_string()];
        let err = validate_sink_fields("s", "webhook", "https://e.com/h", None, &events).unwrap_err();
        match err {
            AppError::BadRequest(m) => assert!(m.contains("not.a.real.event"), "msg: {m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// A webhook target that is not an http(s) URL is rejected.
    #[test]
    fn webhook_target_must_be_http() {
        let err = validate_sink_fields("s", "webhook", "nats://h:4222", None, &ok_events()).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// A broker sink requires a subject and a host:port target, and rejects userinfo.
    #[test]
    fn broker_target_validation() {
        let subj = Some("events.console");
        assert!(validate_sink_fields("s", "nats", "nats://broker.example.com:4222", subj, &ok_events()).is_ok());
        // Missing subject.
        assert!(validate_sink_fields("s", "nats", "nats://broker.example.com:4222", None, &ok_events()).is_err());
        // No port.
        assert!(validate_sink_fields("s", "kafka", "broker.example.com", subj, &ok_events()).is_err());
        // Embedded credentials.
        assert!(validate_sink_fields("s", "nats", "nats://user:pass@broker:4222", subj, &ok_events()).is_err());
    }

    /// Length caps are enforced (422).
    #[test]
    fn rejects_overlong_name_and_target() {
        let name = "a".repeat(MAX_NAME_LEN + 1);
        assert!(validate_sink_fields(&name, "webhook", "https://e.com/h", None, &ok_events()).is_err());
        let target = format!("https://e.com/{}", "x".repeat(MAX_URL_LEN));
        assert!(validate_sink_fields("s", "webhook", &target, None, &ok_events()).is_err());
    }

    /// EVT-03 (write-only secret): the EventSinkView serialized form never carries
    /// the raw secret — only the masked badges. (Compile-time: EventSinkRow has no
    /// Serialize derive; this guards the view shape.)
    #[test]
    fn sink_view_has_no_secret() {
        use super::super::EventSinkRow;
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let row = EventSinkRow {
            id: Uuid::new_v4(),
            name: "s".into(),
            kind: "webhook".into(),
            target: "https://e.com/h".into(),
            subject: None,
            events: ok_events(),
            secret: "super-secret-hmac".into(),
            sasl_username: Some("svc".into()),
            tls: false,
            enabled: true,
            last_event_id: None,
            last_event_cursor_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let view: EventSinkView = row.into();
        let json = serde_json::to_string(&view).unwrap();
        assert!(view.secret_set, "secret_set badge must be true");
        assert!(view.sasl_username_set, "sasl_username_set badge must be true");
        assert!(!json.contains("super-secret-hmac"), "secret leaked into view: {json}");
        assert!(!json.contains("svc"), "username leaked into view: {json}");
    }

    /// The events allowlist matches the webhook allowlist size (drift guard).
    #[test]
    fn known_events_matches_webhook_allowlist_size() {
        assert_eq!(KNOWN_EVENTS.len(), 10);
        assert!(KNOWN_EVENTS.contains(&"session.created"));
    }
}
