//! PII/secret redaction pass (EVT-03).
//!
//! [`redact`] shapes a `console_audit_log` row ([`crate::audit::AuditView`]) into
//! an [`OutboundEvent`] with PII/secrets MASKED before enqueue, so the durable
//! `event_deliveries` queue + the delivery-log view never store raw PII/secrets
//! (Pattern 3). The source audit row's UUID is PRESERVED as the idempotency key
//! (EVT-02) — an at-least-once retry carries the SAME id and consumers dedupe.
//!
//! Redaction policy (mirrors the Phase-16 Alloy masking discipline):
//!   - `actor_email` is reduced to a domain-only form (`***@domain.tld`) — enough
//!     to debug routing without exfiltrating the local-part identity.
//!   - the `metadata` jsonb is walked recursively; any VALUE whose KEY looks
//!     secret-bearing (token/secret/password/key/authorization/credential/cookie/
//!     session) or whose STRING VALUE looks like a connection URI / bearer token is
//!     replaced with `"[redacted]"`.

use crate::audit::AuditView;
use crate::events::OutboundEvent;

/// The masked placeholder written in place of a redacted value.
const REDACTED: &str = "[redacted]";

/// Shape an audit row into a redacted [`OutboundEvent`].
///
/// `id` = the audit row id (idempotency key, EVT-02); `event` = the audit
/// `action`; `occurred_at` = the audit `created_at`; `data` = a redacted JSON
/// object carrying the non-secret audit fields + the masked metadata.
pub fn redact(row: &AuditView) -> OutboundEvent {
    let mut data = serde_json::Map::new();
    data.insert("action".into(), serde_json::json!(row.action));
    data.insert("outcome".into(), serde_json::json!(row.outcome));
    if let Some(actor_id) = &row.actor_id {
        data.insert("actor_id".into(), serde_json::json!(actor_id));
    }
    if let Some(email) = &row.actor_email {
        data.insert("actor_email".into(), serde_json::json!(mask_email(email)));
    }
    if let Some(method) = &row.method {
        data.insert("method".into(), serde_json::json!(method));
    }
    if let Some(path) = &row.path {
        data.insert("path".into(), serde_json::json!(path));
    }
    if let Some(tt) = &row.target_type {
        data.insert("target_type".into(), serde_json::json!(tt));
    }
    if let Some(ti) = &row.target_id {
        data.insert("target_id".into(), serde_json::json!(ti));
    }
    if let Some(metadata) = &row.metadata {
        data.insert("metadata".into(), redact_value(metadata, false));
    }

    OutboundEvent {
        id: row.id,
        event: row.action.clone(),
        occurred_at: row.created_at,
        data: serde_json::Value::Object(data),
    }
}

/// Reduce an email to a domain-only form (`***@domain`). A value without an `@`
/// is fully masked (it is not a well-formed email — do not pass it through).
fn mask_email(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((_local, domain)) if !domain.is_empty() => format!("***@{domain}"),
        _ => REDACTED.to_string(),
    }
}

/// Whether a metadata KEY names a secret-bearing field (case-insensitive
/// substring match against a small denylist).
fn key_is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "secret",
        "token",
        "password",
        "passwd",
        "authorization",
        "credential",
        "cookie",
        "session",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
    ];
    NEEDLES.iter().any(|n| k.contains(n))
}

/// Whether a STRING VALUE looks secret-shaped (a connection URI with embedded
/// credentials, or a bearer token) and must be masked regardless of its key.
fn value_looks_secret(s: &str) -> bool {
    // Connection URI with userinfo: scheme://user:pass@host
    if let Some(idx) = s.find("://") {
        let after = &s[idx + 3..];
        if let Some(at) = after.find('@') {
            // userinfo present before the first '@' and before any path '/'
            let host_start = after.find('/').unwrap_or(after.len());
            if at < host_start && after[..at].contains(':') {
                return true;
            }
        }
    }
    // Bearer token header value.
    let lower = s.to_ascii_lowercase();
    lower.starts_with("bearer ") || lower.starts_with("basic ")
}

/// Recursively redact a JSON value. `parent_key_secret` forces masking of the
/// value when its owning key was secret-bearing.
fn redact_value(v: &serde_json::Value, parent_key_secret: bool) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, val) in map {
                let secret_here = key_is_secret(k);
                out.insert(k.clone(), redact_value(val, secret_here));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter().map(|x| redact_value(x, parent_key_secret)).collect(),
        ),
        serde_json::Value::String(s) => {
            if parent_key_secret || value_looks_secret(s) {
                serde_json::json!(REDACTED)
            } else {
                v.clone()
            }
        }
        // Non-string scalars under a secret key are still masked (e.g. numeric PIN).
        other if parent_key_secret => {
            let _ = other;
            serde_json::json!(REDACTED)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn audit_row(metadata: Option<serde_json::Value>) -> AuditView {
        AuditView {
            id: Uuid::new_v4(),
            actor_id: Some(Uuid::new_v4()),
            actor_email: Some("alice@example.com".into()),
            action: "identity.created".into(),
            method: Some("POST".into()),
            path: Some("/api/identities".into()),
            target_type: Some("identity".into()),
            target_id: Some("id-123".into()),
            outcome: "success".into(),
            metadata,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    /// EVT-03: the serialized event contains neither the raw email local-part nor
    /// any secret value.
    #[test]
    fn redacts_email_and_secrets() {
        let row = audit_row(Some(serde_json::json!({
            "token": "super-secret-jwt-abc123",
            "nested": { "client_secret": "shh", "ok": "visible" },
            "dsn": "postgres://user:pass@db.example.com/console",
            "headers": { "authorization": "Bearer leakme" },
            "count": 7
        })));
        let ev = redact(&row);
        let json = serde_json::to_string(&ev).unwrap();

        // Email reduced to domain-only.
        assert!(!json.contains("alice@example.com"), "raw email leaked: {json}");
        assert!(json.contains("***@example.com"), "domain-only email missing: {json}");

        // Secrets masked.
        assert!(!json.contains("super-secret-jwt-abc123"), "token leaked: {json}");
        assert!(!json.contains("shh"), "client_secret leaked: {json}");
        assert!(!json.contains("user:pass@db.example.com"), "DSN creds leaked: {json}");
        assert!(!json.contains("leakme"), "bearer token leaked: {json}");

        // Non-secret values preserved.
        assert!(json.contains("visible"), "non-secret value dropped: {json}");
        assert!(json.contains("identity.created"));
    }

    /// EVT-02: the OutboundEvent id IS the source audit row id (idempotency key).
    #[test]
    fn event_carries_idempotency_id() {
        let row = audit_row(None);
        let ev = redact(&row);
        assert_eq!(ev.id, row.id);
        assert_eq!(ev.event, "identity.created");
        assert_eq!(ev.occurred_at, row.created_at);
    }

    #[test]
    fn mask_email_domain_only() {
        assert_eq!(mask_email("bob@corp.io"), "***@corp.io");
        assert_eq!(mask_email("nodomain"), REDACTED);
    }

    #[test]
    fn value_looks_secret_detects_uri_and_bearer() {
        assert!(value_looks_secret("postgres://u:p@h/db"));
        assert!(value_looks_secret("Bearer abc.def.ghi"));
        assert!(value_looks_secret("basic dXNlcjpwYXNz"));
        assert!(!value_looks_secret("https://example.com/path"));
        assert!(!value_looks_secret("just a string"));
    }
}
