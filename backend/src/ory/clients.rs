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
//! a DIFFERENT type from the backend's own reqwest 0.13 client. The 0.13 client
//! stays for the fallback module. WR-01: rather than relying on `..::new()`'s
//! UNBOUNDED default 0.12 client (a hung upstream would block an async worker
//! with no upper limit), we build ONE explicit reqwest 0.12 client with a
//! bounded connect + request timeout and inject it into every
//! `Configuration.client`. This mirrors the protection `fallback.rs` already
//! sets on its 0.13 client. The renamed `reqwest_012` dep lets us name that
//! 0.12 `Client` type; it shares the same 0.12.x resolution the crates pull in.

use std::time::Duration;

use ory_hydra_client::apis::configuration::Configuration as HydraCfg;
use ory_keto_client::apis::configuration::Configuration as KetoCfg;
use ory_kratos_client::apis::configuration::Configuration as KratosCfg;
use ory_oathkeeper_client::apis::configuration::Configuration as OathCfg;

use crate::config::Config;
use crate::error::AppError;

/// WR-01: how long to wait for a TCP connection to an Ory admin service before
/// giving up. Short — the services live on the internal Docker network.
const ORY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// WR-01: overall per-request deadline for a typed Ory admin call. Bounds a
/// hung/slow upstream so it cannot hold an async worker open indefinitely.
const ORY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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

/// WR-03: validate an admin base URL at startup. The five admin URLs are taken
/// verbatim from env; a typo (missing scheme, `kratos;4434`, empty) would
/// otherwise boot clean and then fail EVERY call to that service with an opaque
/// 502 at request time — hard to diagnose because the error body is (correctly)
/// detail-free and never echoes the URL. Given the "zero manual plumbing / just
/// works" mandate we fail FAST and loudly at boot instead.
///
/// `value` is the configured base URL; `env_key` names the env var so the
/// operator-facing message points at exactly what to fix. The message carries
/// NO secret (admin URLs are non-secret per BACK-02). We require a parseable URL
/// with an `http`/`https` scheme and a non-empty host.
fn validate_admin_url(env_key: &str, value: &str) -> Result<(), AppError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| AppError::Config(format!("{env_key} is not a valid URL")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::Config(format!(
                "{env_key} must use an http or https scheme"
            )))
        }
    }
    if parsed.host_str().map(str::is_empty).unwrap_or(true) {
        return Err(AppError::Config(format!("{env_key} must include a host")));
    }
    Ok(())
}

impl OryClients {
    /// Build one `Configuration` per service from the runtime `Config`.
    ///
    /// `base_path` is the bare `scheme://host:port` from `Config` with NO
    /// `/admin` suffix — the generated path templates already prepend the route
    /// (RESEARCH Pitfall 2). Every other field (incl. `bearer_access_token`)
    /// keeps its `::new()` default: self-hosted OSS Ory Admin APIs require no
    /// admin credential and are reachable only on the internal network
    /// (RESEARCH A2).
    ///
    /// WR-03: each of the five admin URLs is validated first; a malformed/empty
    /// URL fails the boot with an operator-facing [`AppError::Config`] rather
    /// than degrading to opaque per-request 502s.
    ///
    /// WR-01: a single bounded-timeout reqwest 0.12 client is built and shared
    /// across all `Configuration`s (the client is internally `Arc`-backed, so
    /// the shared connection pool is reused), replacing each crate's UNBOUNDED
    /// `::new()` default client.
    pub fn from_config(cfg: &Config) -> Result<Self, AppError> {
        // WR-03: fail fast on a malformed admin URL.
        validate_admin_url("KRATOS_ADMIN_URL", &cfg.kratos_admin_url)?;
        validate_admin_url("HYDRA_ADMIN_URL", &cfg.hydra_admin_url)?;
        validate_admin_url("KETO_READ_URL", &cfg.keto_read_url)?;
        validate_admin_url("KETO_WRITE_URL", &cfg.keto_write_url)?;
        validate_admin_url("OATHKEEPER_API_URL", &cfg.oathkeeper_api_url)?;

        // WR-01: one bounded-timeout reqwest 0.12 client shared by every
        // Configuration. Cloning it shares the underlying Arc'd connection pool.
        let http = reqwest_012::Client::builder()
            .connect_timeout(ORY_CONNECT_TIMEOUT)
            .timeout(ORY_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AppError::Internal(format!("build ory http client: {e}")))?;

        Ok(OryClients {
            kratos: KratosCfg {
                base_path: cfg.kratos_admin_url.clone(),
                client: http.clone(),
                ..KratosCfg::new()
            },
            hydra: HydraCfg {
                base_path: cfg.hydra_admin_url.clone(),
                client: http.clone(),
                ..HydraCfg::new()
            },
            keto_read: KetoCfg {
                base_path: cfg.keto_read_url.clone(),
                client: http.clone(),
                ..KetoCfg::new()
            },
            keto_write: KetoCfg {
                base_path: cfg.keto_write_url.clone(),
                client: http.clone(),
                ..KetoCfg::new()
            },
            oathkeeper: OathCfg {
                base_path: cfg.oathkeeper_api_url.clone(),
                client: http,
                ..OathCfg::new()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_internal_http_url() {
        assert!(validate_admin_url("KRATOS_ADMIN_URL", "http://kratos:4434").is_ok());
    }

    #[test]
    fn accepts_https_url() {
        assert!(validate_admin_url("HYDRA_ADMIN_URL", "https://hydra.internal:4445").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_admin_url("KETO_READ_URL", ""),
            Err(AppError::Config(_))
        ));
    }

    #[test]
    fn rejects_missing_scheme() {
        // No scheme: `url::Url::parse` fails outright on a bare host:port.
        assert!(matches!(
            validate_admin_url("KETO_WRITE_URL", "keto:4467"),
            Err(AppError::Config(_))
        ));
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(matches!(
            validate_admin_url("OATHKEEPER_API_URL", "ftp://oathkeeper:4456"),
            Err(AppError::Config(_))
        ));
    }
}
