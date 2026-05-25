//! Keto permissions proof wrapper — `GET /api/keto/relationships`.
//!
//! Thin pass-through to the typed `ory_keto_client` crate proving the live Keto
//! READ data path (BACK-02 success criterion 1). Relation-tuple CRUD +
//! check/expand + OPL editing is deferred to Phase 9 — this handler only LISTS.
//!
//! Uses `keto_read` (`:4466`) — Keto splits its read and write APIs across
//! distinct ports; a READ MUST NEVER use the write client (`:4467`). A fresh
//! store returns `{relation_tuples: [], ...}` — valid (RESEARCH Pitfall 4).
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401. GET is auto-exempt from
//! `csrf_guard`.

use ory_keto_client::apis::relationship_api;
use salvo::prelude::*;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_keto_err;

/// `GET /api/keto/relationships` — list relation tuples (proof read).
///
/// Calls `relationship_api::get_relationships` against `keto_read` (:4466) for
/// the first page of 50 with all filters unset, maps any crate `Error<T>` to
/// `AppError::Upstream` (502), and re-serialises the typed `Relationships` to
/// JSON.
#[handler]
pub async fn list_relationships(
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))?
        .clone();

    // get_relationships(configuration, page_size, page_token, namespace, object,
    //   relation, subject_id, subject_set_namespace, subject_set_object,
    //   subject_set_relation) — READ path uses keto_read (:4466).
    let relationships = relationship_api::get_relationships(
        &clients.keto_read,
        Some(50), // page_size
        None, None, None, None, None, None, None, None,
    )
    .await
    .map_err(map_keto_err)?;

    Ok(Json(serde_json::to_value(relationships).map_err(|e| {
        AppError::Internal(format!("serialize ory response: {e}"))
    })?))
}
