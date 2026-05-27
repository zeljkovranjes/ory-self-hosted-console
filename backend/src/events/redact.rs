//! PII/secret redaction pass (EVT-03) — placeholder filled in Task 3.
//!
//! `redact()` shapes a `console_audit_log` row into an [`crate::events::OutboundEvent`]
//! with PII/secrets masked BEFORE enqueue, so the durable queue + delivery-log
//! view never store raw PII. The source audit row's UUID is preserved as the
//! idempotency key (EVT-02).
