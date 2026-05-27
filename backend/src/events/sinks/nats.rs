//! NATS event-stream sink (EVT-01) — `#[cfg(feature = "events-nats")]`.
//!
//! Compiled ONLY under the OFF-by-default `events-nats` feature, which pulls
//! `async-nats` (pure-Rust, rustls/ring — no C toolchain). All async-nats imports
//! live INSIDE this module so the default build never names the crate.
//!
//! Security: the broker host is SSRF-checked via the shared
//! `super::assert_broker_host_allowed` (resolve + `webhooks::ssrf::is_blocked_ip`,
//! Pitfall 4 / T-17-04) before connecting. Credentials come from the recoverable,
//! never-serialized `secret` column and are NEVER logged (Pitfall 3).
//!
//! ConnectOptions auth methods verified against docs.rs/async-nats/0.49.0
//! (17-RESEARCH Code Examples): `with_credentials`, `user_and_password`, `token`,
//! `require_tls`, `connect_with_options`, `publish`, `flush`.

use crate::error::AppError;
use crate::events::{EventSinkRow, OutboundEvent};

/// NATS publisher sink — owns its broker URL, subject, and optional creds.
#[derive(Debug, Clone)]
pub struct NatsSink {
    /// `nats://host:port` (or comma-separated) broker URL.
    pub broker_url: String,
    /// The subject to publish to.
    pub subject: String,
    /// Optional JWT/nkey creds string OR a bearer token (the recoverable secret).
    pub credentials: Option<String>,
    /// Optional username (paired with `password`).
    pub username: Option<String>,
    /// Optional password (used with `username` for user+password auth).
    pub password: Option<String>,
    /// Whether to require TLS to the broker.
    pub tls: bool,
}

impl NatsSink {
    /// Build a NATS sink from a stored row.
    ///
    /// The recoverable `secret` is interpreted as a creds/token string when there
    /// is NO `sasl_username`, or as the password when a username is present.
    pub fn from_row(row: &EventSinkRow) -> Result<Self, AppError> {
        let subject = row
            .subject
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::BadRequest("NATS sink requires a subject.".to_string()))?;
        let username = row.sasl_username.clone().filter(|u| !u.is_empty());
        let (credentials, password) = if username.is_some() {
            (None, (!row.secret.is_empty()).then(|| row.secret.clone()))
        } else {
            ((!row.secret.is_empty()).then(|| row.secret.clone()), None)
        };
        Ok(NatsSink {
            broker_url: row.target.clone(),
            subject,
            credentials,
            username,
            password,
            tls: row.tls,
        })
    }

    /// Deliver one already-redacted event by publishing to the subject.
    pub async fn deliver(
        &self,
        event: &OutboundEvent,
        allow_private: bool,
    ) -> Result<(), AppError> {
        // SSRF-check every broker host:port before connecting (Pitfall 4).
        for url in self.broker_url.split(',') {
            let url = url.trim();
            if url.is_empty() {
                continue;
            }
            let (host, port) = parse_nats_host_port(url)?;
            super::assert_broker_host_allowed(&host, port, allow_private).await?;
        }

        let mut opts = async_nats::ConnectOptions::new();
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            opts = opts.user_and_password(u.clone(), p.clone());
        } else if let Some(creds) = &self.credentials {
            // A JWT/nkey creds string. Never log it (Pitfall 3).
            opts = async_nats::ConnectOptions::with_credentials(creds)
                .map_err(|_| AppError::BadRequest("Invalid NATS credentials.".to_string()))?;
        }
        if self.tls {
            opts = opts.require_tls(true);
        }

        let client = async_nats::connect_with_options(&self.broker_url, opts)
            .await
            // Never echo the connect error (may carry the URL/creds) — generic.
            .map_err(|_| AppError::Upstream("nats sink: connect failed".to_string()))?;

        let payload = serde_json::to_vec(event)
            .map_err(|e| AppError::Internal(format!("serialize outbound event: {e}")))?;

        client
            .publish(self.subject.clone(), payload.into())
            .await
            .map_err(|e| AppError::Upstream(format!("nats sink delivery: {e}")))?;
        // Ensure the message is flushed to the wire before recording delivered.
        client
            .flush()
            .await
            .map_err(|e| AppError::Upstream(format!("nats sink flush: {e}")))?;
        Ok(())
    }
}

/// Parse a `nats://host:port` URL into (host, port). Defaults to the NATS client
/// port 4222 when no port is given.
fn parse_nats_host_port(url: &str) -> Result<(String, u16), AppError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| AppError::BadRequest("NATS broker URL is not valid.".to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("NATS broker URL has no host.".to_string()))?
        .to_string();
    let port = parsed.port().unwrap_or(4222);
    Ok((host, port))
}
