//! Kratos Admin proof wrapper — `GET /api/kratos/identities`.
//!
//! Thin pass-through to the typed `ory_kratos_client` crate proving the live
//! Kratos data path (BACK-02 success criterion 1). Full identity CRUD + schema +
//! bulk import is deferred to Phase 6 — this handler only LISTS.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401 before this handler runs. The
//! GET method is auto-exempt from `csrf_guard` (safe method).

use ory_kratos_client::apis::identity_api;
use salvo::prelude::*;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_kratos_err;

/// `GET /api/kratos/identities` — list identities (proof read).
///
/// Calls `identity_api::list_identities` with the FIRST page of 50 and all other
/// filters unset, maps any crate `Error<T>` to `AppError::Upstream` (502), and
/// re-serialises the typed `Vec<Identity>` into a uniform JSON envelope.
#[handler]
pub async fn list_identities(
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    // Clone-before-await (RESEARCH Pitfall 6): `Configuration` is Clone and its
    // client is Arc-backed, so the owned clone is cheap and avoids holding a
    // Depot borrow across the `.await`.
    let clients = depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))?
        .clone();

    // list_identities(configuration, per_page, page, page_size, page_token,
    //   consistency, ids, credentials_identifier,
    //   preview_credentials_identifier_similar, include_credential, organization_id)
    let identities = identity_api::list_identities(
        &clients.kratos,
        Some(50), // per_page
        Some(1),  // page
        None, None, None, None, None, None, None, None,
    )
    .await
    .map_err(map_kratos_err)?;

    // Re-serialise to Value for a uniform envelope. A serialize failure MUST
    // surface as Internal — never silently coerced to a `null` default.
    Ok(Json(serde_json::to_value(identities).map_err(|e| {
        AppError::Internal(format!("serialize ory response: {e}"))
    })?))
}
