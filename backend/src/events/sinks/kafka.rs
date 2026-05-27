//! Kafka event-stream sink (EVT-01) — `#[cfg(feature = "events-kafka")]`.
//!
//! Compiled ONLY under the OFF-by-default `events-kafka` feature, which pulls
//! `rdkafka` (and its bundled-librdkafka C toolchain). All rdkafka imports live
//! INSIDE this module so the default build never names the crate.
//!
//! Security: the broker host is SSRF-checked via the shared
//! `super::assert_broker_host_allowed` (resolve + `webhooks::ssrf::is_blocked_ip`,
//! Pitfall 4 / T-17-04) before producing. SASL credentials come from the
//! recoverable, never-serialized `secret` column and are NEVER logged (Pitfall 3).

use std::time::Duration;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};

use crate::error::AppError;
use crate::events::{EventSinkRow, OutboundEvent};

/// Per-produce timeout (caps a slow/unreachable broker).
const PRODUCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Kafka producer sink — owns its brokers list, topic, and optional SASL creds.
#[derive(Debug, Clone)]
pub struct KafkaSink {
    /// Comma-separated brokers list (`host:port[,host:port...]`).
    pub brokers: String,
    /// Destination topic.
    pub topic: String,
    /// Optional SASL username (paired with `password`).
    pub username: Option<String>,
    /// Optional SASL password (the recoverable, never-serialized secret).
    pub password: Option<String>,
    /// Whether to request TLS (SASL_SSL vs SASL_PLAINTEXT / SSL vs PLAINTEXT).
    pub tls: bool,
}

impl KafkaSink {
    /// Build a Kafka sink from a stored row.
    pub fn from_row(row: &EventSinkRow) -> Result<Self, AppError> {
        let topic = row
            .subject
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::BadRequest("Kafka sink requires a topic.".to_string()))?;
        let password = if row.secret.is_empty() {
            None
        } else {
            Some(row.secret.clone())
        };
        Ok(KafkaSink {
            brokers: row.target.clone(),
            topic,
            username: row.sasl_username.clone().filter(|u| !u.is_empty()),
            password,
            tls: row.tls,
        })
    }

    /// Deliver one already-redacted event by producing to the topic.
    pub async fn deliver(
        &self,
        event: &OutboundEvent,
        allow_private: bool,
    ) -> Result<(), AppError> {
        // WR-02/WR-03: validate the EXACT broker list we will hand to rdkafka, then
        // set bootstrap.servers to a CANONICAL list reconstructed from the validated
        // (host, port) tuples — never the raw operator string. rdkafka does its own
        // parsing of bootstrap.servers; validating a subset of split(',') while
        // handing it the raw string (skipping empty segments) is a
        // parser-differential SSRF bypass. So: reject empty/extra segments (no
        // silent `continue`) and feed rdkafka exactly what passed the guard.
        let mut canonical: Vec<String> = Vec::new();
        for broker in self.brokers.split(',') {
            let broker = broker.trim();
            if broker.is_empty() {
                return Err(AppError::BadRequest(
                    "Kafka broker list contains an empty segment.".to_string(),
                ));
            }
            let (host, port) = parse_host_port(broker)?;
            super::assert_broker_host_allowed(&host, port, allow_private).await?;
            canonical.push(format!("{host}:{port}"));
        }
        if canonical.is_empty() {
            return Err(AppError::BadRequest(
                "Kafka sink has no broker address.".to_string(),
            ));
        }
        let bootstrap = canonical.join(",");

        let mut cfg = ClientConfig::new();
        // bootstrap.servers is the CANONICAL validated list (WR-02), never the raw
        // brokers string. NOTE: brokers are SSRF-guarded at resolve time only (no
        // IP pin like the webhook path) — a DNS-rebind window exists between this
        // resolve and rdkafka's own connect-time resolution. This residual window
        // is the documented limitation for the off-by-default broker adapters.
        cfg.set("bootstrap.servers", &bootstrap);
        cfg.set("message.timeout.ms", "10000");
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => {
                cfg.set(
                    "security.protocol",
                    if self.tls { "SASL_SSL" } else { "SASL_PLAINTEXT" },
                );
                cfg.set("sasl.mechanism", "PLAIN");
                cfg.set("sasl.username", u);
                cfg.set("sasl.password", p);
            }
            _ if self.tls => {
                cfg.set("security.protocol", "SSL");
            }
            _ => {}
        }

        let producer: FutureProducer = cfg
            .create()
            // Never echo the config (carries the SASL password) — generic message.
            .map_err(|_| AppError::Upstream("kafka sink: producer create failed".to_string()))?;

        let payload = serde_json::to_vec(event)
            .map_err(|e| AppError::Internal(format!("serialize outbound event: {e}")))?;
        let key = event.id.to_string();
        let record = FutureRecord::to(&self.topic).payload(&payload).key(&key);

        producer
            .send(record, PRODUCE_TIMEOUT)
            .await
            .map_err(|(e, _msg)| AppError::Upstream(format!("kafka sink delivery: {e}")))?;
        Ok(())
    }
}

/// Parse a `host:port` broker spec. Kafka brokers are bare host:port (no scheme),
/// so we split on the LAST colon to tolerate IPv6 literals in brackets.
fn parse_host_port(broker: &str) -> Result<(String, u16), AppError> {
    let (host, port) = broker
        .rsplit_once(':')
        .ok_or_else(|| AppError::BadRequest("Kafka broker must be host:port.".to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| AppError::BadRequest("Kafka broker port is invalid.".to_string()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    if host.is_empty() {
        return Err(AppError::BadRequest("Kafka broker host is empty.".to_string()));
    }
    Ok((host, port))
}
