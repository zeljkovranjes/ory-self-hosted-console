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
        // WR-02/WR-03: validate the EXACT broker list we will dial, then dial a
        // CANONICAL list reconstructed from the validated (host, port) tuples —
        // never the raw operator string. async-nats does its own parsing of the
        // string we hand it; if we validated url::Url's view but dialed the raw
        // string, a value that parses differently (an empty segment we skipped, a
        // form normalized differently) would be a TOCTOU/parser-differential SSRF
        // bypass. So: reject empty/extra segments (no silent `continue`), and build
        // the dialed string ourselves from exactly what passed the guard.
        let mut canonical: Vec<String> = Vec::new();
        for url in self.broker_url.split(',') {
            let url = url.trim();
            if url.is_empty() {
                // An empty segment (leading/trailing/double comma) is NOT silently
                // skipped — it means the raw string the client would parse differs
                // from what we validated. Reject the whole target.
                return Err(AppError::BadRequest(
                    "NATS broker list contains an empty segment.".to_string(),
                ));
            }
            let (host, port) = parse_nats_host_port(url)?;
            super::assert_broker_host_allowed(&host, port, allow_private).await?;
            // Canonical, scheme-prefixed, host:port — the only thing we dial.
            let scheme = if self.tls { "tls" } else { "nats" };
            canonical.push(format!("{scheme}://{host}:{port}"));
        }
        if canonical.is_empty() {
            return Err(AppError::BadRequest(
                "NATS sink has no broker address.".to_string(),
            ));
        }
        let dial = canonical.join(",");

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

        // Dial the CANONICAL validated list (WR-02), never the raw broker_url, so
        // the string async-nats parses is byte-for-byte what the SSRF guard checked.
        // NOTE: brokers are SSRF-guarded at resolve time only (no IP pin like the
        // webhook path's resolve_to_addrs) — a DNS-rebind window exists between this
        // resolve and async-nats's own connect-time resolution. The webhook sink
        // closes that window via build_pinned_client; the broker clients do not
        // expose an equivalent resolve-pin hook, so this residual window is the
        // documented limitation for the (off-by-default) broker adapters.
        let client = async_nats::connect_with_options(&dial, opts)
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
