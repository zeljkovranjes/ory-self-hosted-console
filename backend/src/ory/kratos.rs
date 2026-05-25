//! Kratos Admin identity data path — list / detail / CRUD + CLI-compatible
//! bulk import (IDENT-01, IDENT-02, IDENT-04).
//!
//! Every handler is a thin, typed pass-through to `ory_kratos_client`'s
//! `identity_api` (RESEARCH Pattern 1/2/3): obtain [`OryClients`] from the
//! `Depot`, CLONE before the `.await` (Pitfall 6 — never hold a `Depot` borrow
//! across an await), call the typed fn, map any crate `Error<T>` to
//! [`AppError::Upstream`] (502) with `map_kratos_err`, and serialise the result
//! into a uniform JSON envelope.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401 before any handler runs. GET is
//! auto-exempt from `csrf_guard`; create/update/delete/import (POST/PUT/DELETE)
//! require a matching `X-CSRF-Token` (Pitfall 7) — the frontend `lib/api.ts`
//! echoes it, so no new wiring is needed here.
//!
//! ## Security invariants
//!
//! - **T-06-01 (no credential-secret leak):** `Identity.credentials` is a
//!   `HashMap<type, IdentityCredentials>` whose `config` field carries password
//!   hashes / recovery codes, and whose `identifiers` can echo addresses — the
//!   typed model SERIALIZES both by default. Every response is therefore passed
//!   through [`shape_identity_value`], which strips the credential `config` and
//!   `identifiers`, keeping ONLY the credential-type keys (e.g. `password`,
//!   `oidc`). A unit test asserts a synthesised secret never survives shaping.
//! - **T-06-02 (import DoS):** [`enforce_import_limits`] rejects `>1000` patches
//!   always, and `>200` when ANY record carries a cleartext password, with a 422
//!   BEFORE any Kratos call.
//! - **T-06-06 (no secret logging):** cleartext `password` / `hashed_password`
//!   are NEVER written to logs (BACK-07).

use ory_kratos_client::apis::identity_api;
use ory_kratos_client::models::{
    CreateIdentityBody, IdentityPatch, PatchIdentitiesBody, UpdateIdentityBody,
};
use salvo::prelude::*;

use crate::config::Config;
use crate::config_edit::routes::identity_schema_path;
use crate::config_edit::schema::FieldError;
use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_kratos_err;
use crate::ory::fallback;
use crate::ory::DEFAULT_LIST_PAGE_SIZE;

/// IDENT-04 limit: at most this many patches per batch when EVERY credential is
/// pre-hashed (`hashed_password`) — Kratos does no hashing work.
/// `[CITED: ory.com import-user-accounts-identities]`
const MAX_BATCH_HASHED: usize = 1000;
/// IDENT-04 limit: at most this many patches per batch when ANY record carries a
/// CLEARTEXT password — Kratos must hash each, an expensive operation, so the
/// ceiling is lower (DoS guard, T-06-02).
const MAX_BATCH_CLEARTEXT: usize = 200;

// =============================================================================
// Response shaping — strip credential secrets (T-06-01)
// =============================================================================

/// Shape a serialised `Identity` JSON value so it NEVER carries credential
/// secret material: for each entry under `credentials`, drop the `config`
/// (password hashes, recovery codes) and `identifiers` sub-fields, keeping the
/// credential TYPE key and its non-secret metadata (`type`, timestamps,
/// `version`). The detail UI surfaces credential NAMES only (UI-SPEC §2).
///
/// Operates on `serde_json::Value` (not the typed model) so it is identical for
/// the typed `get_identity`/`create`/`update` responses AND the reqwest-list
/// rows. Idempotent and total — an identity without `credentials` is unchanged.
pub fn shape_identity_value(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(creds) = v.get_mut("credentials").and_then(|c| c.as_object_mut()) {
        for (_type_key, cred) in creds.iter_mut() {
            if let Some(obj) = cred.as_object_mut() {
                // The two secret-bearing fields. `config` holds the password
                // hash / recovery codes; `identifiers` can echo addresses.
                obj.remove("config");
                obj.remove("identifiers");
            }
        }
    }
    v
}

/// Serialise a typed value and run it through [`shape_identity_value`]. A
/// serialise failure surfaces as `Internal` (500) — never silently coerced.
fn shaped_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, AppError> {
    let raw = serde_json::to_value(value)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))?;
    Ok(shape_identity_value(raw))
}

/// Obtain the injected [`OryClients`], cloned (Pitfall 6 — no `Depot` borrow held
/// across the subsequent `.await`).
fn ory_clients(depot: &mut Depot) -> Result<OryClients, AppError> {
    depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))
        .cloned()
}

// =============================================================================
// IDENT-01: list (keyset cursor) + detail
// =============================================================================

/// `GET /api/kratos/identities` — list one keyset page (IDENT-01).
///
/// Reads optional `page_size` (default [`DEFAULT_LIST_PAGE_SIZE`]) and
/// `page_token` query params and returns `{rows, next_token, total}` where
/// `next_token` is the keyset cursor for the NEXT page parsed from the Kratos
/// `Link` header (RESEARCH Pitfall 3) and `total` is `rows.len()` (Kratos no
/// longer guarantees `X-Total-Count`; the count is the forward-compatible
/// DataTable contract, not an authoritative grand total).
///
/// The keyset cursor lives in a response header the typed `list_identities`
/// drops, so this ONE list path goes through the isolated reqwest-0.13
/// [`fallback::list_identities_paged`] wrapper. Each row is shaped to strip
/// credential secrets (T-06-01) before it reaches the client.
#[handler]
pub async fn list_identities(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let page_size = req
        .query::<i64>("page_size")
        .filter(|n| *n > 0 && *n <= 1000)
        .unwrap_or(DEFAULT_LIST_PAGE_SIZE);
    let page_token = req.query::<String>("page_token");
    // IDENT-01 / WR-01: optional exact-match search filter from the Users-list
    // search box. Kratos's `GET /admin/identities` accepts `credentials_identifier`;
    // we forward a non-empty (trimmed) term and treat blank/whitespace as no
    // filter so an empty search box returns the full page rather than nothing.
    let credentials_identifier = req
        .query::<String>("credentials_identifier")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // The Kratos Admin base URL is fixed backend config (no SSRF surface). Build
    // a bounded reqwest-0.13 client for the one list call.
    let http = fallback::fallback_client()?;
    let (rows, next_token) = fallback::list_identities_paged(
        &http,
        &clients_kratos_base(&clients),
        page_size,
        page_token.as_deref(),
        credentials_identifier.as_deref(),
    )
    .await?;

    // Strip credential secrets from EVERY row (T-06-01).
    let shaped: Vec<serde_json::Value> =
        rows.into_iter().map(shape_identity_value).collect();
    let total = shaped.len();

    Ok(Json(serde_json::json!({
        "rows": shaped,
        "next_token": next_token,
        "total": total,
    })))
}

/// The Kratos Admin base URL the typed `Configuration` was built with. The
/// `OryClients.kratos.base_path` is the bare `scheme://host:port` (no `/admin`
/// suffix — the fallback wrapper appends the path).
fn clients_kratos_base(clients: &OryClients) -> String {
    clients.kratos.base_path.clone()
}

/// `GET /api/kratos/identities/{id}` — one identity (IDENT-01 detail).
///
/// A Kratos 404 surfaces as the mapped upstream error. The response is shaped to
/// strip credential secrets (T-06-01) — only credential-type keys survive.
#[handler]
pub async fn get_identity(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    // get_identity(configuration, id, include_credential). We pass `None` for
    // include_credential — we never want Kratos to expand credential CONFIG, and
    // shaping strips it regardless (defense in depth).
    let identity = identity_api::get_identity(&clients.kratos, &id, None)
        .await
        .map_err(map_kratos_err)?;

    Ok(Json(shaped_json(identity)?))
}

/// `POST /api/kratos/identities` — create one identity (IDENT-02).
///
/// Accepts `{schema_id, traits, metadata_public?, metadata_admin?, credentials?,
/// state?}`. `schema_id` + `traits` are REQUIRED (a body missing either is a 400,
/// never a silent default). `metadata_*` honour the double-`Option` contract
/// (Pitfall 4): absent => omit (`None`), explicit JSON `null` => `Some(None)`,
/// value => `Some(Some(v))` — preserved automatically by deserialising straight
/// into the typed `CreateIdentityBody` (its `serde_with::double_option`).
/// Credentials accept the PHC `hashed_password` OR cleartext `password`; the
/// backend NEVER hashes and NEVER logs either (BACK-07).
#[handler]
pub async fn create_identity(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    // Deserialise directly into the typed body so field names + the
    // double-Option metadata semantics come straight from the crate. A missing
    // required field (schema_id / traits) is a 400 with a value-free message.
    let body: CreateIdentityBody = req
        .parse_json::<CreateIdentityBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid create identity body: {e}")))?;

    let identity = identity_api::create_identity(&clients.kratos, Some(body))
        .await
        .map_err(map_kratos_err)?;

    Ok(Json(shaped_json(identity)?))
}

/// `PUT /api/kratos/identities/{id}` — replace one identity (IDENT-02).
///
/// `UpdateIdentityBody.state` is REQUIRED (`StateEnum`, NOT `Option` — RESEARCH
/// anti-pattern): a body lacking `state` fails deserialisation => 400, never a
/// silent default. `schema_id` + `traits` are likewise required; `metadata_*`
/// honour the double-`Option` contract (Pitfall 4).
#[handler]
pub async fn update_identity(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    // Deserialise into the typed body. Because `state` is a non-Option
    // `StateEnum`, a body omitting it FAILS here -> 400 (never a default).
    let body: UpdateIdentityBody = req
        .parse_json::<UpdateIdentityBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid update identity body: {e}")))?;

    let identity = identity_api::update_identity(&clients.kratos, &id, Some(body))
        .await
        .map_err(map_kratos_err)?;

    Ok(Json(shaped_json(identity)?))
}

/// `DELETE /api/kratos/identities/{id}` — delete one identity (IDENT-02).
///
/// Returns 204 No Content on success. There is no batch-delete (the crate's
/// `IdentityPatch` only supports `create` in 26.2.0, Pitfall 2) — deletes are
/// always one-at-a-time here.
#[handler]
pub async fn delete_identity(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let clients = ory_clients(depot)?;
    let id = req.param::<String>("id").ok_or(AppError::NotFound)?;

    identity_api::delete_identity(&clients.kratos, &id)
        .await
        .map_err(map_kratos_err)?;

    res.status_code(StatusCode::NO_CONTENT);
    Ok(())
}

// =============================================================================
// IDENT-03: read the active identity schema (for schema-driven form generation)
// =============================================================================

/// `GET /api/kratos/identity-schema` — return the ACTIVE identity schema JSON
/// (IDENT-03 read side).
///
/// Reads the server-defined file `{config_dir}/kratos/identity.schema.json` (the
/// SAME file [`crate::config_edit::routes::put_identity_schema`] writes) and
/// returns it verbatim as JSON, so the frontend can derive the create/edit form
/// fields from `properties.traits` (RESEARCH Pattern 6). The path is fixed from
/// `Config::config_dir`, never client input.
///
/// On the protected subtree (`auth_guard` -> 401 unauth); GET is auto-exempt from
/// `csrf_guard`. The schema is not secret material, but it is NOT the place to
/// leak file paths: a read/parse failure maps to a generic [`AppError`] without
/// echoing the path (BACK-07).
#[handler]
pub async fn get_active_schema(
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?;

    let path = identity_schema_path(&cfg.config_dir);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        // Never echo the path in the client-facing body (BACK-07); log it server-side.
        tracing::error!(error = %e, "identity schema read failed");
        AppError::Internal("identity schema read failed".into())
    })?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        tracing::error!(error = %e, "identity schema parse failed");
        AppError::Internal("identity schema parse failed".into())
    })?;

    Ok(Json(value))
}

// =============================================================================
// IDENT-04: CLI bare-array <-> batch wrapper + limit enforcement + import
// =============================================================================

/// Convert the `ory`-CLI bare-array import form into the Kratos batch wrapper
/// (IDENT-04 / CLI-01 foreshadow, RESEARCH Pattern 4 / Pitfall 1).
///
/// The `ory import identities` CLI consumes a BARE ARRAY of identity objects
/// `[{schema_id, traits, credentials?}, …]`, while the Kratos batch endpoint
/// wants `{"identities":[{"create":{…}}]}` — each identity wrapped in an
/// `IdentityPatch.create`. They share the inner object verbatim, so conversion
/// is a pure top-level wrap. Each patch gets a generated `patch_id` so the
/// per-record response can be correlated.
pub fn cli_array_to_patch_body(bare: Vec<CreateIdentityBody>) -> PatchIdentitiesBody {
    let identities = bare
        .into_iter()
        .map(|create| IdentityPatch {
            create: Some(Box::new(create)),
            patch_id: Some(uuid::Uuid::new_v4().to_string()),
        })
        .collect();
    PatchIdentitiesBody {
        identities: Some(identities),
    }
}

/// Unwrap a Kratos batch [`PatchIdentitiesBody`] back into the `ory`-CLI
/// bare-array form (for export-shape parity / CLI-01 foreshadow). Each patch's
/// inner `create` object is emitted; a patch with no `create` (not produced by
/// this backend, but possible from an arbitrary body) is skipped.
///
/// A single-record round-trip through `cli_array_to_patch_body` then this fn is
/// identity-preserving for the inner object (the `patch_id` wrapper is dropped).
pub fn patch_body_to_cli_array(body: &PatchIdentitiesBody) -> Vec<serde_json::Value> {
    body.identities
        .iter()
        .flatten()
        .filter_map(|p| p.create.as_ref())
        .filter_map(|create| serde_json::to_value(&**create).ok())
        .collect()
}

/// Whether a `CreateIdentityBody` carries a CLEARTEXT password (vs only a
/// pre-hashed `hashed_password`). A cleartext password forces Kratos to hash it,
/// which is the expensive path the lower batch ceiling guards against.
///
/// NEVER logs the password value (T-06-06) — it only inspects presence.
fn has_cleartext_password(body: &CreateIdentityBody) -> bool {
    body.credentials
        .as_ref()
        .and_then(|c| c.password.as_ref())
        .and_then(|p| p.config.as_ref())
        .map(|cfg| cfg.password.is_some())
        .unwrap_or(false)
}

/// Enforce the IDENT-04 batch limits SERVER-SIDE and authoritatively, BEFORE any
/// Kratos call (T-06-02 DoS guard): reject `>1000` records always, and `>200`
/// records when ANY carries a cleartext password. Returns
/// [`AppError::Validation`] (422) with a value-free [`FieldError`] on violation.
pub fn enforce_import_limits(records: &[CreateIdentityBody]) -> Result<(), AppError> {
    let count = records.len();
    if count == 0 {
        return Err(AppError::Validation(vec![FieldError {
            path: String::new(),
            message: "import requires at least one identity".into(),
        }]));
    }
    if count > MAX_BATCH_HASHED {
        return Err(AppError::Validation(vec![FieldError {
            path: String::new(),
            message: format!(
                "import exceeds the maximum of {MAX_BATCH_HASHED} identities per request"
            ),
        }]));
    }
    let any_cleartext = records.iter().any(has_cleartext_password);
    if any_cleartext && count > MAX_BATCH_CLEARTEXT {
        return Err(AppError::Validation(vec![FieldError {
            path: String::new(),
            message: format!(
                "import with any cleartext password is limited to {MAX_BATCH_CLEARTEXT} identities per request"
            ),
        }]));
    }
    Ok(())
}

/// `POST /api/kratos/identities/import` — CLI-compatible bulk import (IDENT-04).
///
/// Accepts the `ory`-CLI BARE ARRAY of identity objects (what the operator would
/// feed `ory import identities`). Flow: parse bare array -> [`enforce_import_limits`]
/// (422 before any Kratos call) -> [`cli_array_to_patch_body`] ->
/// `batch_patch_identities` -> map the per-record response to `{results:[…]}`.
///
/// Each result carries the `patch_id`, `action` (`create`/`error`), and the
/// created `identity` id — NEVER any credential material (the response model has
/// no secret field; we serialise it as-is). Cleartext/hashed passwords are never
/// logged (T-06-06).
#[handler]
pub async fn batch_import(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let records: Vec<CreateIdentityBody> = req
        .parse_json::<Vec<CreateIdentityBody>>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid import array: {e}")))?;

    // Authoritative limit check BEFORE any upstream call (T-06-02).
    enforce_import_limits(&records)?;

    let body = cli_array_to_patch_body(records);
    let resp = identity_api::batch_patch_identities(&clients.kratos, Some(body))
        .await
        .map_err(map_kratos_err)?;

    // Map per-patch outcomes. The response carries NO credential material, so a
    // direct serialise is safe; we still wrap it in a `results` envelope.
    let results = serde_json::to_value(resp.identities.unwrap_or_default())
        .map_err(|e| AppError::Internal(format!("serialize batch response: {e}")))?;

    Ok(Json(serde_json::json!({ "results": results })))
}

// =============================================================================
// Helper so external callers (tests) can name the limit constants.
// =============================================================================

/// The batch ceilings (hashed, cleartext) — exposed for test assertions.
pub const fn batch_limits() -> (usize, usize) {
    (MAX_BATCH_HASHED, MAX_BATCH_CLEARTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ory_kratos_client::models::{
        IdentityWithCredentials, IdentityWithCredentialsPassword,
        IdentityWithCredentialsPasswordConfig,
    };

    /// Build a minimal hashed-credential record.
    fn hashed_record() -> CreateIdentityBody {
        let mut b = CreateIdentityBody::new(
            "default".into(),
            serde_json::json!({ "email": "u@example.com" }),
        );
        b.credentials = Some(Box::new(IdentityWithCredentials {
            password: Some(Box::new(IdentityWithCredentialsPassword {
                config: Some(Box::new(IdentityWithCredentialsPasswordConfig {
                    hashed_password: Some("$2a$10$abcdefghijklmnopqrstuv".into()),
                    password: None,
                    use_password_migration_hook: None,
                })),
            })),
            oidc: None,
            saml: None,
        }));
        b
    }

    /// Build a minimal cleartext-credential record.
    fn cleartext_record() -> CreateIdentityBody {
        let mut b = CreateIdentityBody::new(
            "default".into(),
            serde_json::json!({ "email": "c@example.com" }),
        );
        b.credentials = Some(Box::new(IdentityWithCredentials {
            password: Some(Box::new(IdentityWithCredentialsPassword {
                config: Some(Box::new(IdentityWithCredentialsPasswordConfig {
                    hashed_password: None,
                    password: Some("super-secret-cleartext".into()),
                    use_password_migration_hook: None,
                })),
            })),
            oidc: None,
            saml: None,
        }));
        b
    }

    // --- T-06-01: credential secrets never survive shaping ------------------

    #[test]
    fn shaping_strips_credential_config_and_identifiers() {
        let secret_hash = "$argon2id$v=19$SECRET_HASH_NEVER_LEAKS";
        let secret_id = "leak@example.com";
        let raw = serde_json::json!({
            "id": "abc",
            "schema_id": "default",
            "traits": { "email": "u@example.com" },
            "credentials": {
                "password": {
                    "type": "password",
                    "identifiers": [secret_id],
                    "config": { "hashed_password": secret_hash },
                    "version": 0
                }
            }
        });
        let shaped = shape_identity_value(raw);
        let text = serde_json::to_string(&shaped).unwrap();

        // The credential TYPE key survives...
        assert!(text.contains("\"password\""), "type key should survive: {text}");
        assert!(shaped["credentials"]["password"]["type"] == serde_json::json!("password"));
        // ...but neither the config hash nor the identifiers do.
        assert!(!text.contains(secret_hash), "hashed_password leaked: {text}");
        assert!(!text.contains(secret_id), "identifier leaked: {text}");
        assert!(shaped["credentials"]["password"].get("config").is_none());
        assert!(shaped["credentials"]["password"].get("identifiers").is_none());
    }

    #[test]
    fn shaping_is_noop_without_credentials() {
        let raw = serde_json::json!({ "id": "abc", "traits": { "email": "x" } });
        assert_eq!(shape_identity_value(raw.clone()), raw);
    }

    // --- IDENT-04: CLI conversion both directions ---------------------------

    #[test]
    fn cli_round_trip_is_identity_preserving() {
        let original = CreateIdentityBody::new(
            "default".into(),
            serde_json::json!({ "email": "rt@example.com" }),
        );
        let original_value = serde_json::to_value(&original).unwrap();

        let body = cli_array_to_patch_body(vec![original]);
        // The wrapper shape is {identities:[{create:{…}, patch_id}]}.
        let patches = body.identities.as_ref().unwrap();
        assert_eq!(patches.len(), 1);
        assert!(patches[0].create.is_some());
        assert!(patches[0].patch_id.is_some(), "patch_id must be generated");

        let back = patch_body_to_cli_array(&body);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], original_value, "inner object must round-trip");
    }

    #[test]
    fn cli_conversion_wraps_each_record_in_create() {
        let recs = vec![hashed_record(), cleartext_record()];
        let body = cli_array_to_patch_body(recs);
        let patches = body.identities.unwrap();
        assert_eq!(patches.len(), 2);
        for p in &patches {
            assert!(p.create.is_some(), "each patch must carry `create`");
        }
    }

    // --- IDENT-04: limit enforcement (T-06-02) ------------------------------

    #[test]
    fn limit_rejects_empty() {
        assert!(matches!(
            enforce_import_limits(&[]),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn limit_rejects_1001_hashed() {
        let recs: Vec<_> = (0..1001).map(|_| hashed_record()).collect();
        assert!(matches!(
            enforce_import_limits(&recs),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn limit_allows_1000_hashed() {
        let recs: Vec<_> = (0..1000).map(|_| hashed_record()).collect();
        assert!(enforce_import_limits(&recs).is_ok());
    }

    #[test]
    fn limit_rejects_201_with_one_cleartext() {
        let mut recs: Vec<_> = (0..200).map(|_| hashed_record()).collect();
        recs.push(cleartext_record()); // 201 total, one cleartext
        assert!(matches!(
            enforce_import_limits(&recs),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn limit_allows_200_cleartext() {
        let recs: Vec<_> = (0..200).map(|_| cleartext_record()).collect();
        assert!(enforce_import_limits(&recs).is_ok());
    }

    #[test]
    fn cleartext_detection() {
        assert!(has_cleartext_password(&cleartext_record()));
        assert!(!has_cleartext_password(&hashed_record()));
        let bare = CreateIdentityBody::new("default".into(), serde_json::json!({}));
        assert!(!has_cleartext_password(&bare));
    }

    #[test]
    fn limits_constants_exposed() {
        let (h, c) = batch_limits();
        assert_eq!((h, c), (1000, 200));
    }
}
