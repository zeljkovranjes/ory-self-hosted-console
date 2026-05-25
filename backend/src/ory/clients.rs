//! `OryClients` — one OpenAPI-generated `Configuration` per Ory service, built
//! once from [`Config`](crate::config::Config) at startup and injected into the
//! Salvo `Depot` alongside the `PgPool` + `Config` (RESEARCH Pattern 1 + 2).
//!
//! Each `Configuration` is `Clone` and its `client: reqwest::Client` is
//! internally `Arc`-backed, so cloning per request is cheap and shares the
//! connection pool. Handlers obtain the struct with
//! `depot.obtain::<OryClients>()?.clone()` (mirrors the Phase-2 pool/cfg pattern
//! in `auth/middleware.rs`) and then call the generated async fns.
//!
//! reqwest 0.12 vs 0.13 (RESEARCH Pitfall 1): the Ory crates depend on
//! reqwest ^0.12 and their `Configuration.client` is a `reqwest_0.12::Client` —
//! a DIFFERENT type from the backend's own reqwest 0.13 client. We therefore let
//! each `Configuration` keep its OWN default 0.12 client via `..::new()` and do
//! NOT attempt to inject the 0.13 client (it would not compile). The 0.13 client
//! stays for the future fallback module.

use ory_hydra_client::apis::configuration::Configuration as HydraCfg;
use ory_keto_client::apis::configuration::Configuration as KetoCfg;
use ory_kratos_client::apis::configuration::Configuration as KratosCfg;
use ory_oathkeeper_client::apis::configuration::Configuration as OathCfg;

use crate::config::Config;

/// The set of configured Ory Admin clients, one `Configuration` per service.
///
/// Keto is split into separate READ (`:4466`) and WRITE (`:4467`) clients
/// because Keto serves its read and write APIs on distinct ports.
#[derive(Clone)]
pub struct OryClients {
    /// Kratos Admin (`KRATOS_ADMIN_URL`, default `http://kratos:4434`).
    pub kratos: KratosCfg,
    /// Hydra OAuth2 Admin (`HYDRA_ADMIN_URL`, default `http://hydra:4445`).
    pub hydra: HydraCfg,
    /// Keto READ API (`KETO_READ_URL`, default `http://keto:4466`).
    pub keto_read: KetoCfg,
    /// Keto WRITE API (`KETO_WRITE_URL`, default `http://keto:4467`).
    pub keto_write: KetoCfg,
    /// Oathkeeper API (`OATHKEEPER_API_URL`, default `http://oathkeeper:4456`).
    pub oathkeeper: OathCfg,
}

impl OryClients {
    /// Build one `Configuration` per service from the runtime `Config`.
    ///
    /// `base_path` is the bare `scheme://host:port` from `Config` with NO
    /// `/admin` suffix — the generated path templates already prepend the route
    /// (RESEARCH Pitfall 2). Every other field (incl. `bearer_access_token`)
    /// keeps its `::new()` default: self-hosted OSS Ory Admin APIs require no
    /// admin credential and are reachable only on the internal network
    /// (RESEARCH A2). `..::new()` also supplies the default reqwest 0.12 client.
    pub fn from_config(cfg: &Config) -> Self {
        OryClients {
            kratos: KratosCfg {
                base_path: cfg.kratos_admin_url.clone(),
                ..KratosCfg::new()
            },
            hydra: HydraCfg {
                base_path: cfg.hydra_admin_url.clone(),
                ..HydraCfg::new()
            },
            keto_read: KetoCfg {
                base_path: cfg.keto_read_url.clone(),
                ..KetoCfg::new()
            },
            keto_write: KetoCfg {
                base_path: cfg.keto_write_url.clone(),
                ..KetoCfg::new()
            },
            oathkeeper: OathCfg {
                base_path: cfg.oathkeeper_api_url.clone(),
                ..OathCfg::new()
            },
        }
    }
}
