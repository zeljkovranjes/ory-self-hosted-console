//! PII/secret redaction pass (EVT-03).
//!
//! [`redact`] shapes a `console_audit_log` row ([`crate::audit::AuditView`]) into
//! an [`OutboundEvent`] with PII/secrets MASKED before enqueue, so the durable
//! `event_deliveries` queue + the delivery-log view never store raw PII/secrets
//! (Pattern 3). The source audit row's UUID is PRESERVED as the idempotency key
//! (EVT-02) — an at-least-once retry carries the SAME id and consumers dedupe.
//!
//! Redaction policy (mirrors the Phase-16 Alloy masking discipline):
//!   - The non-PII ENVELOPE the consumer needs is always emitted verbatim: the
//!     idempotency `id` (the source audit UUID), the `event` name (audit `action`),
//!     the `occurred_at` timestamp, plus the non-PII audit fields `action`,
//!     `outcome`, `actor_id`, `method`, `path`, `target_type`, `target_id`.
//!   - `actor_email` is reduced to a domain-only form (`***@domain.tld`) — enough
//!     to debug routing without exfiltrating the local-part identity.
//!   - the `metadata` jsonb is an ALLOWLIST (CR-01). `metadata` is free-form jsonb
//!     populated by future explicit `audit()` calls — a denylist that must be kept
//!     in lockstep with every future metadata producer is a standing
//!     PII-exfiltration risk to an EXTERNAL sink (the T-17-02 threat). So at the
//!     metadata ROOT only keys in [`METADATA_ALLOW`] survive (each is a small,
//!     known-safe, non-PII/non-secret counter/status field); EVERY other key — and
//!     anything nested under an allowed key that is not itself a plain scalar — is
//!     replaced with `"[redacted]"`. A future handler that stores a JWT / opaque
//!     token / email under ANY benign key (`value`, `data`, `assertion`, `jwt`, …)
//!     therefore CANNOT leak: the key is simply not on the allowlist.
//!
//! INVARIANT: to emit a NEW metadata field to sinks, add its key to
//! [`METADATA_ALLOW`] **and** confirm it can never carry PII/secrets. Until a key
//! is allowlisted, `metadata` MUST NOT be relied on to carry it downstream.

use crate::audit::AuditView;
use crate::events::OutboundEvent;

/// The masked placeholder written in place of a redacted value.
const REDACTED: &str = "[redacted]";

/// The ALLOWLIST of metadata keys that are known-safe to emit to an external sink
/// (CR-01). These are coarse, non-PII/non-secret operational counters/status
/// fields. ANY metadata key NOT in this set is dropped (masked) — a future
/// handler that stores a token/email/PII under a benign key cannot leak, because
/// the key is not on this list.
///
/// To add a key: confirm the value can NEVER carry PII/secrets, then append it.
const METADATA_ALLOW: &[&str] = &["count", "duration_ms", "page", "per_page", "status_code"];

/// Shape an audit row into a redacted [`OutboundEvent`].
///
/// `id` = the audit row id (idempotency key, EVT-02); `event` = the audit
/// `action`; `occurred_at` = the audit `created_at`; `data` = a redacted JSON
/// object carrying the non-secret audit fields + the allowlisted metadata.
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
        data.insert("metadata".into(), redact_metadata_root(metadata));
    }

    OutboundEvent {
        id: row.id,
        event: row.action.clone(),
        occurred_at: row.created_at,
        data: serde_json::Value::Object(data),
    }
}

/// Re-run the CURRENT redaction policy over an already-stored payload (WR-05).
///
/// Used by `redeliver` when the SOURCE audit row can no longer be re-resolved
/// (it was pruned): a delivery stored under a WEAKER past policy must not be
/// re-shipped verbatim. This re-applies the current metadata allowlist to
/// `data.metadata` and re-masks `data.actor_email` in place, so the redelivered
/// payload reflects today's policy. Unknown shapes are left untouched (the worker
/// still re-validates SSRF at delivery and the payload was redacted at least once).
pub fn re_redact_payload(payload: &serde_json::Value) -> serde_json::Value {
    let mut out = payload.clone();
    if let Some(data) = out.get_mut("data").and_then(|d| d.as_object_mut()) {
        if let Some(meta) = data.get("metadata") {
            let masked = redact_metadata_root(meta);
            data.insert("metadata".into(), masked);
        }
        if let Some(serde_json::Value::String(email)) = data.get("actor_email") {
            // Re-mask: if it is still a raw email, reduce to domain-only; an
            // already-masked `***@domain` is idempotent under mask_email.
            let masked = mask_email(email);
            data.insert("actor_email".into(), serde_json::json!(masked));
        }
    }
    out
}

/// Reduce an email to a domain-only form (`***@domain`). A value without an `@`
/// is fully masked (it is not a well-formed email — do not pass it through).
fn mask_email(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((_local, domain)) if !domain.is_empty() => format!("***@{domain}"),
        _ => REDACTED.to_string(),
    }
}

/// Redact the `metadata` jsonb as an ALLOWLIST (CR-01).
///
/// `metadata` is normally a JSON object. At the ROOT we keep ONLY the keys in
/// [`METADATA_ALLOW`]; every other key is dropped (its value never appears, not
/// even masked, so no shape/length is leaked). An allowed key's value is then
/// passed through [`allowed_value`], which permits only plain non-PII scalars and
/// shallow arrays/objects of such scalars — a string/array/object that does not
/// pass is masked to `"[redacted]"`. A non-object metadata (array/scalar/null at
/// the root) carries no allowlistable keys, so the whole thing is masked.
fn redact_metadata_root(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if METADATA_ALLOW.contains(&k.as_str()) {
                    out.insert(k.clone(), allowed_value(val));
                }
                // Any non-allowlisted key is dropped entirely — it never ships.
            }
            serde_json::Value::Object(out)
        }
        // A metadata root that is not an object cannot be allowlisted by key.
        _ => serde_json::json!(REDACTED),
    }
}

/// The value of an allowlisted metadata key. Allowlisting the KEY is necessary
/// but not sufficient: the VALUE must also be a plain non-PII scalar (number /
/// bool / null) or a short string that does not look secret-shaped, or a shallow
/// array/object of such values. Anything richer is masked — defense in depth so an
/// allowlisted key cannot become a smuggling channel for a structured secret.
fn allowed_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) | serde_json::Value::Null => {
            v.clone()
        }
        serde_json::Value::String(s) => {
            if value_looks_secret(s) {
                serde_json::json!(REDACTED)
            } else {
                v.clone()
            }
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(allowed_value).collect())
        }
        // A nested object under an allowlisted key is itself allowlist-filtered.
        serde_json::Value::Object(_) => redact_metadata_root(v),
    }
}

/// Whether a STRING VALUE looks secret/PII-shaped (a connection URI with embedded
/// credentials, a bearer token, or an email address) and must be masked even when
/// it appears under an allowlisted key. This is a belt-and-suspenders check ON TOP
/// of the key allowlist — the allowlist is the primary, closed defense.
fn value_looks_secret(s: &str) -> bool {
    // Connection URI with userinfo: scheme://user:pass@host
    if let Some(idx) = s.find("://") {
        let after = &s[idx + 3..];
        if let Some(at) = after.find('@') {
            let host_start = after.find('/').unwrap_or(after.len());
            if at < host_start && after[..at].contains(':') {
                return true;
            }
        }
    }
    // Bearer/basic auth header value.
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") {
        return true;
    }
    // Email-shaped: a single '@' with a non-empty local part and a dotted domain.
    if let Some((local, domain)) = s.rsplit_once('@') {
        if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') {
            return true;
        }
    }
    false
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
    /// any secret value, and only allowlisted metadata keys survive.
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

        // Secrets masked (their keys are NOT on the metadata allowlist).
        assert!(!json.contains("super-secret-jwt-abc123"), "token leaked: {json}");
        assert!(!json.contains("shh"), "client_secret leaked: {json}");
        assert!(!json.contains("user:pass@db.example.com"), "DSN creds leaked: {json}");
        assert!(!json.contains("leakme"), "bearer token leaked: {json}");
        // The non-allowlisted "ok":"visible" under a non-allowlisted parent is dropped.
        assert!(!json.contains("visible"), "non-allowlisted value leaked: {json}");

        // The allowlisted scalar survives, and the envelope event name is present.
        assert!(json.contains("\"count\":7"), "allowlisted count dropped: {json}");
        assert!(json.contains("identity.created"));
    }

    /// CR-01: a bare JWT / opaque token / email stored under a BENIGN (non-secret)
    /// key — `value`, `data`, `assertion`, `jwt`, `q`, `param` — does NOT appear in
    /// the redacted output, because the key is not on the allowlist (the open set
    /// is closed by inversion). This is the regression a denylist could never prove.
    #[test]
    fn benign_key_secrets_are_dropped_by_allowlist() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.s1gn4tur3";
        let opaque = "AKIAIOSFODNN7EXAMPLE0xDEADBEEFcafef00d";
        let email = "victim@private-domain.example";
        let row = audit_row(Some(serde_json::json!({
            "value": jwt,
            "data": opaque,
            "assertion": jwt,
            "jwt": jwt,
            "q": opaque,
            "param": email,
            "SAMLResponse": opaque,
            "id_token": jwt,
            "code": opaque,
            "access": opaque,
            "nested": { "value": jwt, "email": email }
        })));
        let ev = redact(&row);
        let json = serde_json::to_string(&ev).unwrap();

        assert!(!json.contains(jwt), "JWT under a benign key leaked: {json}");
        assert!(!json.contains(opaque), "opaque token under a benign key leaked: {json}");
        assert!(!json.contains(email), "email under a benign key leaked: {json}");
        // The metadata object survives but is EMPTY (no allowlisted keys present).
        assert!(json.contains("\"metadata\":{}"), "metadata not emptied: {json}");
    }

    /// CR-01: the idempotency UUID id IS present in the redacted output (the
    /// consumer needs it to dedupe) — redaction never strips the envelope.
    #[test]
    fn idempotency_id_survives_redaction() {
        let row = audit_row(Some(serde_json::json!({ "value": "secret-stuff" })));
        let ev = redact(&row);
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(ev.id, row.id, "outbound id must equal the source audit row id");
        assert!(json.contains(&row.id.to_string()), "UUID id missing from output: {json}");
        assert!(!json.contains("secret-stuff"), "benign-key value leaked: {json}");
    }

    /// An allowlisted key whose value is somehow secret-shaped is STILL masked
    /// (defense in depth on top of the key allowlist).
    #[test]
    fn allowlisted_key_with_secret_value_is_masked() {
        let row = audit_row(Some(serde_json::json!({
            "status_code": "Bearer leak-via-allowed-key",
            "count": 3
        })));
        let ev = redact(&row);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("leak-via-allowed-key"), "secret value under allowed key leaked: {json}");
        assert!(json.contains("\"count\":3"), "plain allowlisted scalar dropped: {json}");
    }

    /// A non-object metadata root carries no allowlistable key → fully masked.
    #[test]
    fn non_object_metadata_is_masked() {
        let row = audit_row(Some(serde_json::json!("eyJhbGciOiJIUzI1NiJ9.payload.sig")));
        let ev = redact(&row);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("payload.sig"), "scalar metadata leaked: {json}");
        assert!(json.contains(REDACTED), "scalar metadata not masked: {json}");
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
    fn value_looks_secret_detects_uri_bearer_and_email() {
        assert!(value_looks_secret("postgres://u:p@h/db"));
        assert!(value_looks_secret("Bearer abc.def.ghi"));
        assert!(value_looks_secret("basic dXNlcjpwYXNz"));
        assert!(value_looks_secret("alice@example.com"));
        assert!(!value_looks_secret("https://example.com/path"));
        assert!(!value_looks_secret("just a string"));
        assert!(!value_looks_secret("no-at-sign-here"));
    }
}
