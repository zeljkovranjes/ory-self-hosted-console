//! Event-sink adapter implementations (EVT-01).
//!
//! The DEFAULT [`webhook`] sink is always compiled (zero new deps — reuses
//! `crate::webhooks::{ssrf, hmac}`). The [`nats`] / [`kafka`] adapters compile
//! ONLY under their OFF-by-default features, so the default build never names the
//! `async-nats` / `rdkafka` crates. All adapter-specific imports live INSIDE the
//! `#[cfg]` modules.

pub mod webhook;

#[cfg(feature = "events-nats")]
pub mod nats;

#[cfg(feature = "events-kafka")]
pub mod kafka;

/// Broker-host SSRF check for the NATS/Kafka adapters (Pitfall 4 / T-17-04).
///
/// NATS (`nats://`) and Kafka (`host:port`) use NON-http schemes, so
/// `webhooks::ssrf::validate_url` (which requires http/https) cannot be used
/// directly. This factors the host:port-level guard: resolve every A/AAAA record
/// for `host:port` and reject if ANY resolved IP is blocked by the SHARED
/// `webhooks::ssrf::is_blocked_ip` classifier. `allow_private` is the test/CI
/// escape hatch (production passes `false`). Compiled ONLY when a broker adapter
/// feature is on, so the default build never references it.
#[cfg(any(feature = "events-nats", feature = "events-kafka"))]
pub async fn assert_broker_host_allowed(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<(), crate::error::AppError> {
    use crate::error::AppError;
    use crate::webhooks::ssrf::is_blocked_ip;

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| AppError::BadRequest("Broker host could not be resolved.".to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(AppError::BadRequest(
            "Broker host could not be resolved.".to_string(),
        ));
    }
    for sa in &addrs {
        if !allow_private && is_blocked_ip(sa.ip()) {
            return Err(AppError::BadRequest(
                "This broker address resolves to a private, loopback, link-local, or cloud-metadata address and is not allowed."
                    .to_string(),
            ));
        }
    }
    Ok(())
}
