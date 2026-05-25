//! Hydra OAuth2 Admin proof wrapper — `GET /api/hydra/clients`.
//!
//! Thin pass-through to the typed `ory_hydra_client` crate proving the live
//! Hydra data path (BACK-02 success criterion 1). Full OAuth2 client CRUD +
//! token introspect/revoke is deferred to Phase 8 — this handler only LISTS.
//!
//! A fresh Hydra returns an EMPTY array — that is a VALID live response
//! (RESEARCH Pitfall 4), not an error.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401. GET is auto-exempt from
//! `csrf_guard`.

use ory_hydra_client::apis::o_auth2_api;
use salvo::prelude::*;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_hydra_err;

/// `GET /api/hydra/clients` — list OAuth2 clients (proof read).
///
/// Calls `o_auth2_api::list_o_auth2_clients` for the first page of 50, maps any
/// crate `Error<T>` to `AppError::Upstream` (502), and re-serialises the typed
/// `Vec<OAuth2Client>` to JSON.
#[handler]
pub async fn list_clients(
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))?
        .clone();

    // list_o_auth2_clients(configuration, page_size, page_token, client_name, owner)
    let oauth2_clients =
        o_auth2_api::list_o_auth2_clients(&clients.hydra, Some(50), None, None, None)
            .await
            .map_err(map_hydra_err)?;

    Ok(Json(serde_json::to_value(oauth2_clients).map_err(|e| {
        AppError::Internal(format!("serialize ory response: {e}"))
    })?))
}
