//! Tolerant observability-profile health probe (FLAG-04 / T-16-08).
//!
//! The single guarantee of this module: when the `observability` flag is ON but
//! the profiled services are DOWN, every observability route returns a
//! STRUCTURED `profile_not_running` state — NEVER a raw 502/500. This mirrors the
//! `overview/mod.rs` tolerant-probe shape (an unreachable upstream becomes a
//! `reachable:false` entry, never a 500 for the whole aggregate).
//!
//! [`probe_profile`] issues a short-timeout reqwest-0.13 GET to each service's
//! READINESS endpoint:
//!   - Prometheus `GET /-/ready`        (200 once the server can serve queries)
//!   - Loki       `GET /ready`          (200 once ingester+store are ready)
//!   - Grafana    `GET /api/health`     (200 `{"database":"ok",...}` when up)
//!
//! Any transport failure OR non-2xx marks THAT service down and the aggregate
//! `profile_not_running`. The probe reads FIXED `Config` URLs only — never client
//! input (no SSRF surface). It NEVER returns an `Err` that maps to 500/502: the
//! tolerant `ProfileState` IS the contract.

use serde::Serialize;

use crate::config::Config;

/// A short connect+request timeout for the readiness probes. Kept tight so a
/// stuck/absent upstream resolves to `profile_not_running` quickly rather than
/// hanging the console request behind it.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The aggregate state of the observability profile.
///
/// `state` is `"running"` only when ALL probed services answer 2xx on their
/// readiness path; otherwise `"profile_not_running"`. `services` carries the
/// per-service `reachable` breakdown so the frontend can show WHICH service is
/// down without any raw upstream body/URL ever leaking (BACK-07).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProfileState {
    /// `"running"` (all services 2xx) or `"profile_not_running"` (any down).
    pub state: &'static str,
    /// Per-service reachability.
    pub services: Vec<ServiceProbe>,
}

impl ProfileState {
    /// Whether the whole profile is up (every service reachable).
    pub fn is_running(&self) -> bool {
        self.state == "running"
    }
}

/// One service's readiness result. NON-SECRET: just a name + a bool — never the
/// upstream body, the internal URL, or a status detail (T-16-13 / BACK-07).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceProbe {
    /// `prometheus` | `loki` | `grafana`.
    pub name: &'static str,
    /// `true` when the readiness GET returned 2xx; `false` on transport/non-2xx.
    pub reachable: bool,
}

/// Fold per-service reachability into the aggregate [`ProfileState`].
///
/// Pure (no IO) so the running/profile_not_running decision is unit-testable
/// without a live stack: the profile is `running` ONLY when every service is
/// reachable; a SINGLE down service flips the aggregate to `profile_not_running`.
fn aggregate(services: Vec<ServiceProbe>) -> ProfileState {
    let all_up = services.iter().all(|s| s.reachable);
    ProfileState {
        state: if all_up { "running" } else { "profile_not_running" },
        services,
    }
}

/// Probe the observability profile tolerantly (FLAG-04).
///
/// Issues a short-timeout readiness GET to Prometheus/Loki/Grafana using their
/// FIXED `Config` URLs. NEVER returns an `Err`: a transport failure or a non-2xx
/// status marks that service `reachable:false` and the aggregate
/// `profile_not_running` (T-16-08). The caller renders the returned state as a
/// 200-class JSON payload — there is no 502/500 path here.
pub async fn probe_profile(cfg: &Config) -> ProfileState {
    // A fresh short-timeout client per probe call (cheap; mirrors the
    // `ory::fallback::fallback_client` pattern). If the client cannot even be
    // built (effectively never), treat the whole profile as not-running rather
    // than erroring — the tolerant contract holds.
    let client = match reqwest::Client::builder().timeout(PROBE_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => {
            return aggregate(vec![
                ServiceProbe { name: "prometheus", reachable: false },
                ServiceProbe { name: "loki", reachable: false },
                ServiceProbe { name: "grafana", reachable: false },
            ]);
        }
    };

    let prometheus = ServiceProbe {
        name: "prometheus",
        reachable: probe_one(&client, &cfg.prometheus_url, "/-/ready").await,
    };
    let loki = ServiceProbe {
        name: "loki",
        reachable: probe_one(&client, &cfg.loki_url, "/ready").await,
    };
    let grafana = ServiceProbe {
        name: "grafana",
        reachable: probe_one(&client, &cfg.grafana_url, "/api/health").await,
    };

    aggregate(vec![prometheus, loki, grafana])
}

/// Probe ONE service's readiness path. `true` ONLY on a 2xx; any transport
/// failure (DNS/connect/timeout) OR non-2xx status is `false`. The error is
/// swallowed deliberately — a down service is the EXPECTED `profile_not_running`
/// signal, not an error to propagate (T-16-08). `base_url` is a FIXED `Config`
/// value (never client input).
async fn probe_one(client: &reqwest::Client, base_url: &str, ready_path: &str) -> bool {
    let url = format!("{}{}", base_url.trim_end_matches('/'), ready_path);
    match client.get(url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All-reachable folds to `running`.
    #[test]
    fn aggregate_all_up_is_running() {
        let state = aggregate(vec![
            ServiceProbe { name: "prometheus", reachable: true },
            ServiceProbe { name: "loki", reachable: true },
            ServiceProbe { name: "grafana", reachable: true },
        ]);
        assert!(state.is_running());
        assert_eq!(state.state, "running");
    }

    /// A SINGLE down service flips the aggregate to `profile_not_running` — the
    /// FLAG-04 guarantee that a partial-down profile is a CLEAN state.
    #[test]
    fn aggregate_one_down_is_not_running() {
        let state = aggregate(vec![
            ServiceProbe { name: "prometheus", reachable: true },
            ServiceProbe { name: "loki", reachable: false },
            ServiceProbe { name: "grafana", reachable: true },
        ]);
        assert!(!state.is_running());
        assert_eq!(state.state, "profile_not_running");
    }

    /// All-down folds to `profile_not_running` (never an error/panic).
    #[test]
    fn aggregate_all_down_is_not_running() {
        let state = aggregate(vec![
            ServiceProbe { name: "prometheus", reachable: false },
            ServiceProbe { name: "loki", reachable: false },
            ServiceProbe { name: "grafana", reachable: false },
        ]);
        assert!(!state.is_running());
    }

    /// THE FLAG-04 unit proof: probing an UNREACHABLE host returns
    /// `profile_not_running` tolerantly — NEVER an `Err`, NEVER a panic, NEVER a
    /// 502. The probe folds the transport failure into the structured state.
    #[tokio::test]
    async fn probe_unreachable_host_is_profile_not_running_never_errors() {
        // RFC 5737 TEST-NET-1, port 9 (discard) — a guaranteed connect failure.
        let cfg = Config {
            prometheus_url: "http://192.0.2.1:9".to_string(),
            loki_url: "http://192.0.2.1:9".to_string(),
            grafana_url: "http://192.0.2.1:9".to_string(),
            ..test_cfg()
        };

        // No Result here — probe_profile cannot fail; it returns the state.
        let state = probe_profile(&cfg).await;
        assert_eq!(
            state.state, "profile_not_running",
            "an unreachable profile must be profile_not_running, never an error"
        );
        assert!(
            state.services.iter().all(|s| !s.reachable),
            "every unreachable service is marked down"
        );
    }

    /// `probe_one` against an unreachable host is `false` (transport failure
    /// swallowed), never a panic.
    #[tokio::test]
    async fn probe_one_unreachable_is_false() {
        let client = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .build()
            .expect("build probe client");
        let up = probe_one(&client, "http://192.0.2.1:9", "/-/ready").await;
        assert!(!up, "an unreachable readiness probe is false, not an error");
    }

    /// A minimal valid `Config` for the probe tests (only the URL fields matter
    /// here; the rest take the internal-network defaults).
    fn test_cfg() -> Config {
        Config {
            console_database_url: String::new(),
            bind_addr: "0.0.0.0:8080".to_string(),
            session_idle_secs: 604_800,
            session_absolute_secs: 2_592_000,
            insecure_cookies: true,
            allowed_origins: Vec::new(),
            github: None,
            kratos_admin_url: "http://kratos:4434".to_string(),
            hydra_admin_url: "http://hydra:4445".to_string(),
            hydra_public_url: "http://hydra:4444".to_string(),
            keto_read_url: "http://keto:4466".to_string(),
            keto_write_url: "http://keto:4467".to_string(),
            keto_opl_url: "http://keto:4469".to_string(),
            oathkeeper_api_url: "http://oathkeeper:4456".to_string(),
            restart_broker_url: "http://restart-broker:2375".to_string(),
            config_dir: "/etc/config".to_string(),
            prometheus_url: "http://prometheus:9090".to_string(),
            loki_url: "http://loki:3100".to_string(),
            grafana_url: "http://grafana:3000".to_string(),
            polis_admin_url: "http://polis:5225".to_string(),
            polis_api_key: None,
            polis_external_url: None,
            webhook_allow_private_targets: false,
        }
    }
}
