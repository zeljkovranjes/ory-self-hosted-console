//! Oathkeeper proof wrapper — `GET /api/oathkeeper/rules`.
//!
//! Thin pass-through to the typed `ory_oathkeeper_client` crate exercising the
//! fourth Ory crate. CONTEXT marks the Oathkeeper proof as OPTIONAL (the
//! required proofs are Kratos/Hydra/Keto); this low-cost read confirms the
//! 4th client wires end-to-end. Oathkeeper RULE AUTHORING is file-based and is
//! deferred to Phase 9 — this handler only LISTS the currently loaded rules.
//!
//! Signature verified against the vendored `ory-oathkeeper-client` 26.2.0
//! source: `api_api::list_rules(configuration, limit: Option<i64>,
//! offset: Option<i64>) -> Result<Vec<Rule>, Error<ListRulesError>>`.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401. GET is auto-exempt from
//! `csrf_guard`.

use ory_oathkeeper_client::apis::api_api;
use salvo::prelude::*;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_oathkeeper_err;

/// `GET /api/oathkeeper/rules` — list loaded access rules (proof read, bonus).
///
/// Calls `api_api::list_rules` for the first 50 rules, maps any crate `Error<T>`
/// to `AppError::Upstream` (502), and re-serialises the typed `Vec<Rule>` to
/// JSON. An empty array is a valid live response on a stack with no rules loaded.
#[handler]
pub async fn list_rules(
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))?
        .clone();

    // list_rules(configuration, limit, offset)
    let rules = api_api::list_rules(&clients.oathkeeper, Some(50), Some(0))
        .await
        .map_err(map_oathkeeper_err)?;

    Ok(Json(serde_json::to_value(rules).map_err(|e| {
        AppError::Internal(format!("serialize ory response: {e}"))
    })?))
}
