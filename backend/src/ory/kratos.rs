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
use crate::ory::DEFAULT_LIST_PAGE_SIZE;

/// `GET /api/kratos/identities` — list identities (proof read).
///
/// Calls `identity_api::list_identities` with the FIRST page (size
/// [`DEFAULT_LIST_PAGE_SIZE`]) and all other filters unset, maps any crate
/// `Error<T>` to `AppError::Upstream` (502), and re-serialises the typed
/// `Vec<Identity>` into a uniform JSON envelope. WR-02: this returns ONLY the
/// first page — a store with more identities is silently truncated; full cursor
/// pagination is deferred (see TODO below).
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
    //
    // Kratos `page` is ZERO-BASED (token-style pagination): passing `page=1`
    // requests the SECOND page, which is EMPTY whenever the store holds fewer
    // than `per_page+1` identities — i.e. a non-empty store would wrongly return
    // `[]`. We therefore OMIT `page` (let Kratos serve the first page) and only
    // bound the size with `per_page=50`; the first page is what a list view wants.
    // TODO(P6): expose the pagination cursor (page_token) and stop truncating at
    // DEFAULT_LIST_PAGE_SIZE — this proof slice returns the FIRST page only.
    let identities = identity_api::list_identities(
        &clients.kratos,
        Some(DEFAULT_LIST_PAGE_SIZE), // per_page (first page; `page` omitted — see note above)
        None, // page: omitted (0-based; `Some(1)` would skip to an empty 2nd page)
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
