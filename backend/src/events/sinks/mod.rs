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
