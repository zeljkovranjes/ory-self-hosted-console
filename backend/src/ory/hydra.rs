//! Hydra OAuth2 Admin data path — client list / detail / CRUD (OAUTH2-01).
//!
//! Every handler is a thin, typed pass-through to `ory_hydra_client`'s
//! `o_auth2_api` (08-RESEARCH Pattern 1/3): obtain [`OryClients`] from the
//! `Depot`, CLONE before the `.await` (never hold a `Depot` borrow across an
//! await), call the typed fn, map any crate `Error<T>` to [`AppError::Upstream`]
//! (502) with `map_hydra_err`, and serialise the result into a uniform JSON
//! envelope.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401 before any handler runs. GET is
//! auto-exempt from `csrf_guard`; create/update/delete (POST/PUT/DELETE) require
//! a matching `X-CSRF-Token` (T-08-AUTHZ) — the frontend `lib/api.ts` echoes it,
//! so no new wiring is needed here.
//!
//! ## Security invariants
//!
//! - **T-08-SECRET (#2869 — the headline correctness requirement):** an edit can
//!   NEVER blank an existing `client_secret`. [`update_client`] GETs the stored
//!   client, applies only the operator's non-secret edits, sets
//!   `client_secret = None` — which is `#[serde(skip_serializing_if =
//!   "Option::is_none")]`, so it is OMITTED on the wire (Hydra's documented
//!   preserve contract) — then PUTs the full object via `set_o_auth2_client`.
//!   `patch_o_auth2_client` is NEVER used (it is the #2869 bug surface).
//! - **T-08-LEAK (no credential leak on read):** every GET/list response is
//!   passed through [`shape_client_value`], which strips `client_secret` AND
//!   `registration_access_token`. ONLY the create response forwards the generated
//!   secret — exactly ONCE (it is unrecoverable). A unit test asserts a
//!   synthesised secret never survives shaping.
//! - **T-08-ERRLEAK (no upstream body/URL leak):** `map_hydra_err` →
//!   `AppError::Upstream(502)`, body/URL-free (BACK-07).

use ory_hydra_client::apis::o_auth2_api;
use ory_hydra_client::models::OAuth2Client;
use salvo::prelude::*;
use serde::Deserialize;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_hydra_err;
use crate::ory::fallback;
use crate::ory::DEFAULT_LIST_PAGE_SIZE;

// =============================================================================
// OAUTH2-02 request bodies (token introspect / revoke)
// =============================================================================

/// Body for `POST /api/hydra/oauth2/introspect`: the token to introspect and an
/// optional space-separated `scope` to assert against (RFC 7662). The token is
/// untrusted operator input — it is forwarded to Hydra's introspection endpoint,
/// never logged.
#[derive(Debug, Deserialize)]
struct IntrospectTokenBody {
    token: String,
    #[serde(default)]
    scope: Option<String>,
}

/// Body for `POST /api/hydra/oauth2/revoke`: the token to revoke plus the
/// optional client credentials Hydra's revoke endpoint accepts (RFC 7009). All
/// fields are untrusted operator input forwarded to Hydra; none are logged.
#[derive(Debug, Deserialize)]
struct RevokeTokenBody {
    token: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

// =============================================================================
// Response shaping — strip credential material (T-08-LEAK)
// =============================================================================

/// Shape a serialised `OAuth2Client` JSON value so it NEVER carries credential
/// material: drop `client_secret` (unrecoverable; only the create response ever
/// forwards it, once) and `registration_access_token` (08-RESEARCH Pitfall 3/5).
///
/// Operates on `serde_json::Value` (not the typed model) so it is identical for
/// the typed `get_client`/`update_client` responses AND the reqwest-list rows.
/// Idempotent and total — a value without those keys is unchanged.
pub fn shape_client_value(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("client_secret");
        obj.remove("registration_access_token");
    }
    v
}

/// Serialise a typed value and run it through [`shape_client_value`]. A
/// serialise failure surfaces as `Internal` (500) — never silently coerced.
fn shaped_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, AppError> {
    let raw = serde_json::to_value(value)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(shape_client_value(raw))
}

/// Obtain the injected [`OryClients`], cloned (never hold a `Depot` borrow across
/// the subsequent `.await`).
fn ory_clients(depot: &mut Depot) -> Result<OryClients, AppError> {
    depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))
        .cloned()
}

/// The Hydra Admin base URL the typed `Configuration` was built with — the bare
/// `scheme://host:port` (no `/admin` suffix; the fallback wrapper appends the
/// path).
fn clients_hydra_base(clients: &OryClients) -> String {
    clients.hydra.base_path.clone()
}

// =============================================================================
// OAUTH2-01: list (Link-header cursor) + detail
// =============================================================================

/// `GET /api/hydra/clients` — list one page of OAuth2 clients (OAUTH2-01).
///
/// Reads optional `page_size` (default [`DEFAULT_LIST_PAGE_SIZE`]) and
/// `page_token` query params and returns `{rows, next_token}` where `next_token`
/// is the OPAQUE Hydra offset cursor for the NEXT page parsed from the `Link`
/// header (08-RESEARCH Pitfall 2 — the typed `list_o_auth2_clients` drops it), or
/// `null` on the last page.
///
/// The cursor lives in a response header the typed list call drops, so this ONE
/// list path goes through the isolated reqwest-0.13
/// [`fallback::list_o_auth2_clients_paged`] wrapper. Each row is shaped to strip
/// `client_secret` + `registration_access_token` (T-08-LEAK) before it reaches
/// the client.
#[handler]
pub async fn list_clients(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let page_size = req
        .query::<i64>("page_size")
        .filter(|n| *n > 0 && *n <= 1000)
        .unwrap_or(DEFAULT_LIST_PAGE_SIZE);
    let page_token = req.query::<String>("page_token");

    // The Hydra Admin base URL is fixed backend config (no SSRF surface). Build a
    // bounded reqwest-0.13 client for the one list call.
    let http = fallback::fallback_client()?;
    let (rows, next_token) = fallback::list_o_auth2_clients_paged(
        &http,
        &clients_hydra_base(&clients),
        page_size,
        page_token.as_deref(),
    )
    .await?;

    // Strip credential material from EVERY row (T-08-LEAK).
    let shaped: Vec<serde_json::Value> = rows.into_iter().map(shape_client_value).collect();

    Ok(Json(serde_json::json!({
        "rows": shaped,
        "next_token": next_token,
    })))
}

/// `GET /api/hydra/clients/{id}` — one OAuth2 client (OAUTH2-01 detail).
///
/// A Hydra 404 surfaces as the mapped upstream error. The response is shaped to
/// strip `client_secret` + `registration_access_token` (T-08-LEAK) — the secret
/// is write-only and never returned on a read.
#[handler]
pub async fn get_client(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    let client = o_auth2_api::get_o_auth2_client(&clients.hydra, &id)
        .await
        .map_err(map_hydra_err)?;

    Ok(Json(shaped_json(client)?))
}

/// `POST /api/hydra/clients` — create one OAuth2 client (OAUTH2-01).
///
/// Accepts the crate `OAuth2Client` model (CLI-interchangeable — generated from
/// the same Hydra OpenAPI spec the `ory` CLI uses). A malformed body is a 400
/// (never a silent default).
///
/// Hydra returns the generated `client_secret` in the create response EXACTLY
/// ONCE — it is kept hashed and unrecoverable thereafter. This is therefore the
/// ONLY response that is NOT passed through [`shape_client_value`]: the one-time
/// secret is forwarded to the frontend's one-time-reveal block. Every subsequent
/// GET masks it (T-08-LEAK).
#[handler]
pub async fn create_client(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let body: OAuth2Client = req
        .parse_json::<OAuth2Client>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid create client body: {e}")))?;

    let created = o_auth2_api::create_o_auth2_client(&clients.hydra, body)
        .await
        .map_err(map_hydra_err)?;

    // DELIBERATELY NOT shaped — the one-time client_secret is forwarded here and
    // only here (08-RESEARCH Pattern 3). It is unrecoverable; the frontend reveals
    // it exactly once.
    let value = serde_json::to_value(created)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(Json(value))
}

/// `PUT /api/hydra/clients/{id}` — update one OAuth2 client, PRESERVING its
/// secret (OAUTH2-01, T-08-SECRET / ory-hydra #2869 — the headline correctness
/// requirement).
///
/// Flow (08-RESEARCH Pattern 1, the fail-closed #2869 guard):
/// 1. GET the stored client so we PUT a full, valid object.
/// 2. Apply the operator's edits from the request body (parsed as the crate
///    `OAuth2Client`).
/// 3. Force `client_secret = None`. Because the field is
///    `#[serde(skip_serializing_if = "Option::is_none")]`, `None` OMITS it on the
///    wire — Hydra's documented contract preserves the stored secret when the
///    field is absent. The update path therefore STRUCTURALLY cannot transmit a
///    blank/sentinel secret.
/// 4. PUT the full object via `set_o_auth2_client`.
///
/// `patch_o_auth2_client` is NEVER used — it is the #2869 bug surface. Rotation
/// is a SEPARATE explicit action (the client carries an explicit `client_secret`
/// on a deliberate rotate). The response is shaped to strip the secret (T-08-LEAK)
/// — even after a rotate, the new secret is surfaced via the create/rotate path,
/// not echoed on this update response.
#[handler]
pub async fn update_client(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    // Parse the operator's edits as the crate model (CLI-interchangeable). A
    // malformed body is a 400.
    let mut body: OAuth2Client = req
        .parse_json::<OAuth2Client>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid update client body: {e}")))?;

    // Load the current client server-side so the PUT carries a full, valid object
    // (a partial PUT would clear unspecified fields). We keep the operator's edits
    // from `body` and only adopt the immutable/server-managed identity from the
    // stored copy.
    let stored = o_auth2_api::get_o_auth2_client(&clients.hydra, &id)
        .await
        .map_err(map_hydra_err)?;

    // The client_id is immutable; always carry the stored id (ignore any body id).
    body.client_id = stored.client_id;

    // CRITICAL (T-08-SECRET / #2869): NEVER carry a secret through the edit path.
    // `None` omits the field on the wire -> Hydra preserves the stored secret.
    // This is the structural fail-closed guard — do NOT remove.
    body.client_secret = None;

    // Drop server-managed credential echoes that must not be re-sent on a PUT.
    body.registration_access_token = None;

    let updated = o_auth2_api::set_o_auth2_client(&clients.hydra, &id, body)
        .await
        .map_err(map_hydra_err)?;

    Ok(Json(shaped_json(updated)?))
}

/// `DELETE /api/hydra/clients/{id}` — delete one OAuth2 client (OAUTH2-01).
///
/// Returns 204 No Content on success.
#[handler]
pub async fn delete_client(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    o_auth2_api::delete_o_auth2_client(&clients.hydra, &id)
        .await
        .map_err(map_hydra_err)?;

    res.status_code(StatusCode::NO_CONTENT);
    Ok(())
}

// =============================================================================
// OAUTH2-02: token introspection / revoke + read-only flow-request lookup
// =============================================================================
//
// The console INSPECTS and REVOKES only. Accepting or rejecting a grant
// (`accept_*`/`reject_*` on the crate's `o_auth2_api`) is DELIBERATELY NOT wired
// here — the grant decision belongs to the end-user login/consent provider app,
// not the console (T-08-GRANT; a grep gate proves `accept_o_auth2`/`reject_o_auth2`
// never appear in this module). Introspection and the flow-request lookups are
// read-only; `revoke_token` is the single state-changing action and inherits the
// protected subtree's `csrf_guard` (T-08-REVOKE-CSRF). Every upstream failure is
// mapped through `map_hydra_err` (no body/URL leak, T-08-ERRLEAK).

/// `POST /api/hydra/oauth2/introspect` — introspect an OAuth2 token (OAUTH2-02).
///
/// Parses `{token, scope?}` and forwards Hydra's `IntrospectedOAuth2Token`
/// verbatim. Hydra reports an unknown/expired/revoked token as `{active:false}`
/// (a normal 200 response, not an error), so an operator pasting a stale token
/// sees an inactive result rather than a failure. The introspection response
/// carries NO secret material (no `client_secret`), so it is forwarded as-is.
#[handler]
pub async fn introspect_token(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let body = req
        .parse_json::<IntrospectTokenBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid introspect body: {e}")))?;

    let introspected = o_auth2_api::introspect_o_auth2_token(
        &clients.hydra,
        &body.token,
        body.scope.as_deref(),
    )
    .await
    .map_err(map_hydra_err)?;

    let value = serde_json::to_value(introspected)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(Json(value))
}

/// `POST /api/hydra/oauth2/revoke` — revoke an OAuth2 token (OAUTH2-02).
///
/// This is the ONLY state-changing action in the inspector; it sits on the
/// protected subtree so `csrf_guard` requires a matching `X-CSRF-Token` (403
/// otherwise — T-08-REVOKE-CSRF). Parses `{token, client_id?, client_secret?}`
/// and calls `revoke_o_auth2_token`; on success returns 200 `{revoked:true}`.
/// Revocation is idempotent on Hydra's side — revoking an already-invalid token
/// is not an error.
#[handler]
pub async fn revoke_token(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let body = req
        .parse_json::<RevokeTokenBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid revoke body: {e}")))?;

    o_auth2_api::revoke_o_auth2_token(
        &clients.hydra,
        &body.token,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    )
    .await
    .map_err(map_hydra_err)?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}

/// Read the required `challenge` query param shared by the three flow lookups; a
/// missing/empty challenge is a 400 (never a silent upstream call).
fn flow_challenge(req: &Request) -> Result<String, AppError> {
    req.query::<String>("challenge")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AppError::BadRequest("missing `challenge` query parameter".into()))
}

/// `GET /api/hydra/oauth2/login?challenge=…` — look up a pending login request
/// (OAUTH2-02, READ-ONLY). Forwards Hydra's `OAuth2LoginRequest`. A bogus/expired
/// challenge surfaces as a mapped upstream error (not a 500); the console NEVER
/// accepts or rejects the login (T-08-GRANT).
#[handler]
pub async fn get_login_request(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let challenge = flow_challenge(req)?;

    let request = o_auth2_api::get_o_auth2_login_request(&clients.hydra, &challenge)
        .await
        .map_err(map_hydra_err)?;

    let value = serde_json::to_value(request)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(Json(value))
}

/// `GET /api/hydra/oauth2/consent?challenge=…` — look up a pending consent
/// request (OAUTH2-02, READ-ONLY). Forwards Hydra's `OAuth2ConsentRequest`. The
/// console NEVER accepts or rejects the consent grant (T-08-GRANT).
#[handler]
pub async fn get_consent_request(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let challenge = flow_challenge(req)?;

    let request = o_auth2_api::get_o_auth2_consent_request(&clients.hydra, &challenge)
        .await
        .map_err(map_hydra_err)?;

    let value = serde_json::to_value(request)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(Json(value))
}

/// `GET /api/hydra/oauth2/logout?challenge=…` — look up a pending logout request
/// (OAUTH2-02, READ-ONLY). Forwards Hydra's `OAuth2LogoutRequest`. The console
/// NEVER accepts or rejects the logout (T-08-GRANT).
#[handler]
pub async fn get_logout_request(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let challenge = flow_challenge(req)?;

    let request = o_auth2_api::get_o_auth2_logout_request(&clients.hydra, &challenge)
        .await
        .map_err(map_hydra_err)?;

    let value = serde_json::to_value(request)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(Json(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-08-LEAK: a synthesised client_secret + registration_access_token never
    /// survive shaping; the non-secret fields are preserved.
    #[test]
    fn shaping_strips_client_secret_and_registration_token() {
        let secret = "SUPER_SECRET_CLIENT_SECRET_should_never_leak";
        let reg_token = "REGISTRATION_ACCESS_TOKEN_should_never_leak";
        let raw = serde_json::json!({
            "client_id": "abc-123",
            "client_name": "My App",
            "client_secret": secret,
            "registration_access_token": reg_token,
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
        });
        let shaped = shape_client_value(raw);
        let text = serde_json::to_string(&shaped).unwrap();

        // The non-secret fields survive...
        assert_eq!(shaped["client_id"], serde_json::json!("abc-123"));
        assert_eq!(shaped["client_name"], serde_json::json!("My App"));
        assert!(text.contains("authorization_code"), "grant types should survive: {text}");
        // ...but neither credential field does.
        assert!(!text.contains(secret), "client_secret leaked: {text}");
        assert!(!text.contains(reg_token), "registration_access_token leaked: {text}");
        assert!(shaped.get("client_secret").is_none());
        assert!(shaped.get("registration_access_token").is_none());
    }

    /// Shaping is a no-op (and total) for a client value carrying no credential
    /// material.
    #[test]
    fn shaping_is_noop_without_credential_fields() {
        let raw = serde_json::json!({ "client_id": "abc", "client_name": "x" });
        assert_eq!(shape_client_value(raw.clone()), raw);
    }

    /// The #2869 fail-closed guard, exercised at the model level: setting
    /// `client_secret = None` on an OAuth2Client OMITS the field from the
    /// serialised body entirely (skip_serializing_if), so a PUT carrying this
    /// object cannot transmit a blank/sentinel secret — Hydra preserves the
    /// stored one. This mirrors exactly what `update_client` does before
    /// `set_o_auth2_client`.
    #[test]
    fn none_secret_is_omitted_on_the_wire_preserving_it() {
        let mut client = OAuth2Client::new();
        client.client_id = Some("abc-123".to_string());
        client.client_name = Some("My App".to_string());
        // The headline guard:
        client.client_secret = None;

        let serialized = serde_json::to_string(&client).unwrap();
        assert!(
            !serialized.contains("client_secret"),
            "client_secret=None must be OMITTED from the PUT body (preserve, #2869): {serialized}"
        );

        // And the inverse: an explicit (rotate) secret IS transmitted.
        let mut rotated = OAuth2Client::new();
        rotated.client_id = Some("abc-123".to_string());
        rotated.client_secret = Some("a-new-rotated-secret".to_string());
        let serialized = serde_json::to_string(&rotated).unwrap();
        assert!(
            serialized.contains("client_secret"),
            "an explicit secret (rotate) must be transmitted: {serialized}"
        );
    }
}
