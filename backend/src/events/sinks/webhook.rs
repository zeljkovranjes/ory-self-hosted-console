//! The DEFAULT webhook sink (EVT-01) — placeholder filled in Task 2.
//!
//! Reuses `crate::webhooks::{ssrf, hmac}` (zero new deps). See Task 2 for the
//! delivery implementation that mirrors `webhooks::worker::deliver_one`.

use crate::error::AppError;
use crate::events::{EventSinkRow, OutboundEvent};

/// HTTP-webhook sink — owns its target URL + recoverable HMAC secret.
#[derive(Debug, Clone)]
pub struct WebhookSink {
    pub url: String,
    pub secret: String,
}

impl WebhookSink {
    /// Build a webhook sink from a stored row.
    pub fn from_row(row: &EventSinkRow) -> Result<Self, AppError> {
        Ok(WebhookSink {
            url: row.target.clone(),
            secret: row.secret.clone(),
        })
    }

    /// Deliver one already-redacted event. Filled in Task 2.
    pub async fn deliver(
        &self,
        _event: &OutboundEvent,
        _allow_private: bool,
    ) -> Result<(), AppError> {
        Err(AppError::Internal("webhook sink not yet implemented".into()))
    }
}
