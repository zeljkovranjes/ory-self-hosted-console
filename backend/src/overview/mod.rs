//! Project overview / service-health aggregation (PROJ-01).
//!
//! `GET /api/overview` aggregates, for each of the four Ory services, its
//! version (via `metadata_api::get_version`) and its health (via `is_ready` for
//! Kratos/Hydra/Keto, and `is_alive` for Oathkeeper — reusing the Phase-9
//! health-path nuance: Oathkeeper's `/health/ready` 503s for the stateless
//! from-file config, which would false-flag "Unhealthy").
//!
//! CRITICAL (PROJ-01 / UI-SPEC): an UNREACHABLE or erroring service yields
//! `reachable:false` + `health:"Unreachable"` for THAT entry — the whole
//! aggregate is NEVER a 500. The other services still render. This is read-only:
//! NO Ory config write, NO restart.

use ory_hydra_client::apis::metadata_api as hydra_meta;
use ory_keto_client::apis::metadata_api as keto_meta;
use ory_kratos_client::apis::metadata_api as kratos_meta;
use ory_oathkeeper_client::apis::metadata_api as oath_meta;

use salvo::prelude::*;
use serde::Serialize;

use crate::error::AppError;
use crate::ory::clients::OryClients;

/// One service's overview entry.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceOverview {
    /// Display name (`kratos`/`hydra`/`keto`/`oathkeeper`).
    pub name: &'static str,
    /// Reported version string, or `None` when the service is unreachable.
    pub version: Option<String>,
    /// `"Healthy"` (version + health both OK), `"Unhealthy"` (reachable but the
    /// health probe did not report ok), or `"Unreachable"` (transport/decode
    /// failure — the version probe itself failed).
    pub health: &'static str,
    /// `false` when the version probe failed (transport/decode/non-2xx).
    pub reachable: bool,
}

/// Obtain the injected [`OryClients`] from the Depot, cloning BEFORE any await
/// (the Depot pattern — never hold a borrow across `.await`).
fn ory_clients(depot: &mut Depot) -> Result<OryClients, AppError> {
    Ok(depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients missing from depot".into()))?
        .clone())
}

/// `GET /api/overview` — aggregate version + health for all four services.
///
/// Read-only. An individual service failing maps to a `reachable:false` /
/// `"Unreachable"` entry, NEVER a 500 for the whole response (PROJ-01).
#[handler]
pub async fn get_overview(depot: &mut Depot) -> Result<Json<Vec<ServiceOverview>>, AppError> {
    let clients = ory_clients(depot)?;

    // Each probe is independent — one service being down must not poison the
    // others. We await them sequentially (four internal-network calls, fast) and
    // fold each into a tolerant entry.
    let entries = vec![
        kratos_overview(&clients).await,
        hydra_overview(&clients).await,
        keto_overview(&clients).await,
        oathkeeper_overview(&clients).await,
    ];
    Ok(Json(entries))
}

/// Build an entry from a version result + a "health ok" bool. A failed version
/// probe (transport/non-2xx) is `Unreachable`; a reachable service whose health
/// probe did not report ok is `Unhealthy`; otherwise `Healthy`.
fn entry(name: &'static str, version: Option<String>, health_ok: bool) -> ServiceOverview {
    let (health, reachable) = match (&version, health_ok) {
        (Some(_), true) => ("Healthy", true),
        (Some(_), false) => ("Unhealthy", true),
        (None, _) => ("Unreachable", false),
    };
    ServiceOverview {
        name,
        version,
        health,
        reachable,
    }
}

async fn kratos_overview(clients: &OryClients) -> ServiceOverview {
    let version = kratos_meta::get_version(&clients.kratos)
        .await
        .ok()
        .map(|v| v.version);
    // Kratos/Hydra/Keto: ready is the meaningful probe.
    let health_ok = kratos_meta::is_ready(&clients.kratos)
        .await
        .map(|r| r.status == "ok")
        .unwrap_or(false);
    entry("kratos", version, health_ok)
}

async fn hydra_overview(clients: &OryClients) -> ServiceOverview {
    // Hydra's GetVersion200Response.version is Option<String> (the other crates'
    // is a bare String) — flatten so a present-but-null version is treated as no
    // version, consistent with the other entries.
    let version = hydra_meta::get_version(&clients.hydra)
        .await
        .ok()
        .and_then(|v| v.version);
    // Hydra's is_ready returns IsReady200Response { status: Option<String> }
    // (distinct from the other crates' IsAlive200Response { status: String });
    // treat a successful 2xx decode reporting "ok" as healthy.
    let health_ok = hydra_meta::is_ready(&clients.hydra)
        .await
        .map(|r| r.status.as_deref() == Some("ok"))
        .unwrap_or(false);
    entry("hydra", version, health_ok)
}

async fn keto_overview(clients: &OryClients) -> ServiceOverview {
    // Keto's metadata/version lives on the READ port (:4466).
    let version = keto_meta::get_version(&clients.keto_read)
        .await
        .ok()
        .map(|v| v.version);
    let health_ok = keto_meta::is_ready(&clients.keto_read)
        .await
        .map(|r| r.status == "ok")
        .unwrap_or(false);
    entry("keto", version, health_ok)
}

async fn oathkeeper_overview(clients: &OryClients) -> ServiceOverview {
    let version = oath_meta::get_version(&clients.oathkeeper)
        .await
        .ok()
        .map(|v| v.version);
    // PHASE-9 NUANCE (restart.rs Service::health_path): Oathkeeper's
    // `/health/ready` 503s for the stateless from-file config, so poll
    // `/health/alive` (is_alive) — a 200 there means the binary is up and
    // serving. Using is_ready would FALSE-flag a healthy Oathkeeper as Unhealthy.
    let health_ok = oath_meta::is_alive(&clients.oathkeeper)
        .await
        .map(|r| r.status == "ok")
        .unwrap_or(false);
    entry("oathkeeper", version, health_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_when_version_probe_fails() {
        let e = entry("kratos", None, false);
        assert!(!e.reachable);
        assert_eq!(e.health, "Unreachable");
        assert!(e.version.is_none());
    }

    #[test]
    fn healthy_when_version_and_health_ok() {
        let e = entry("hydra", Some("v26.2.0".into()), true);
        assert!(e.reachable);
        assert_eq!(e.health, "Healthy");
    }

    #[test]
    fn unhealthy_when_reachable_but_health_probe_not_ok() {
        let e = entry("keto", Some("v26.2.0".into()), false);
        assert!(e.reachable);
        assert_eq!(e.health, "Unhealthy");
    }
}
