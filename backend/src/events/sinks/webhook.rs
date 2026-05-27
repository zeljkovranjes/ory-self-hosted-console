//! The DEFAULT webhook sink (EVT-01) — zero new deps.
//!
//! Mirrors `crate::webhooks::worker::deliver_one`'s send path: the DELIVERY-time
//! SSRF guard (`webhooks::ssrf::build_pinned_client` — resolve-validate-pin,
//! redirects off, DNS-rebind defense, T-17-03) + HMAC-SHA256 signing
//! (`webhooks::hmac::sign` → `X-Console-Signature`, T-17-05). The SSRF classifier
//! and the signer are REUSED verbatim — never reimplemented.

use crate::error::AppError;
use crate::events::{EventSinkRow, OutboundEvent};
use crate::webhooks::{hmac, ssrf};

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

    /// Deliver one already-redacted event.
    ///
    /// `allow_private` is forwarded to the shared SSRF guard — production callers
    /// pass `false`, fully enforcing the classifier. On a non-2xx response or a
    /// transport error this returns `Err`, so the worker (Plan 02) records a
    /// retry/dead exactly like a v1 webhook delivery.
    pub async fn deliver(
        &self,
        event: &OutboundEvent,
        allow_private: bool,
    ) -> Result<(), AppError> {
        // DELIVERY-time SSRF guard (authoritative — DNS-rebind defense). A blocked
        // target is an explicit reject; we NEVER POST to it.
        let (client, _addrs) = ssrf::build_pinned_client(&self.url, allow_private).await?;

        let raw_body = serde_json::to_vec(event)
            .map_err(|e| AppError::Internal(format!("serialize outbound event: {e}")))?;
        let signature = hmac::sign(self.secret.as_bytes(), &raw_body);

        let resp = client
            .post(&self.url)
            .header(hmac::SIGNATURE_HEADER, signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(raw_body)
            .send()
            .await
            .map_err(|e| {
                // Never echo the full transport error (may carry the URL) — a short tag.
                let tag = if e.is_timeout() {
                    "request timed out"
                } else {
                    "request failed"
                };
                AppError::Upstream(format!("webhook sink delivery: {tag}"))
            })?;

        let code = resp.status().as_u16();
        // Drain a little so the connection closes cleanly; we don't use the body.
        let _ = resp.bytes().await;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(AppError::Upstream(format!(
                "webhook sink delivery: non-2xx response ({code})"
            )))
        }
    }
}
