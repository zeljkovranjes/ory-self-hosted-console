//! Observability console surface (Phase 16, OBS-03/04/05 + FLAG-04).
//!
//! The backend half of the opt-in `observability` profile: everything the
//! console talks to so the operator can see metrics, logs, and Grafana WITHOUT
//! ever reaching Prometheus/Loki/Grafana directly (BACK-01). Four pieces:
//!
//!   - [`probe`] — the TOLERANT health-probe handshake (FLAG-04). A
//!     short-timeout reqwest-0.13 GET to each profiled service's readiness path;
//!     any transport/non-2xx failure folds into a structured
//!     `profile_not_running` state, NEVER a raw 502/500. This is the guarantee
//!     that flag-ON + profile-DOWN is a CLEAN state (T-16-08).
//!   - [`prometheus`] — a PARAMETERIZED PromQL query passthrough (OBS-03). The
//!     frontend selects a CLOSED dashboard intent + a time range; the backend
//!     builds the `query`/`query_range` — there is NO raw operator PromQL
//!     passthrough (T-16-09 / Security V5).
//!   - [`loki`] — the same shape for a CLOSED LogQL intent (OBS-04).
//!   - [`grafana_proxy`] — an authenticated reverse-proxy to the internal
//!     Grafana origin, injecting `X-WEBAUTH-USER` from the Depot `Session`
//!     (OBS-05). Path-traversal-safe; the client never supplies the host.
//!
//! All four are mounted INSIDE the protected subtree (AFTER auth/csrf) behind
//! `FeatureFlagHoop::new("observability")`, so a flag-OFF request 404s even with
//! a valid session + matching CSRF (FLAG-01 / T-16-12).
//!
//! ## reqwest-0.13 isolation
//!
//! Like `ory::fallback`, these query/proxy clients use the backend's reqwest
//! **0.13** transport against FIXED `Config` base URLs (never client input — no
//! SSRF surface). They do NOT import any Ory crate's generated client (the
//! 0.12/0.13 split stays contained).

pub mod grafana_proxy;
pub mod loki;
pub mod probe;
pub mod prometheus;

pub use grafana_proxy::grafana_proxy as grafana_proxy_handler;
pub use loki::get_logs;
pub use probe::{probe_profile, ProfileState};
pub use prometheus::get_metrics_activity;
