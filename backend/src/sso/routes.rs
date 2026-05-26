//! SAML connection CRUD route handlers (SSO-02/03/04/07 — the Phase-14 security
//! crux end-to-end).
//!
//! Three handlers, all mounted INSIDE the protected subtree behind
//! `FeatureFlagHoop::new("saml")` (SSO-07 — 404 when the flag is OFF, even with a
//! valid session + CSRF token). The response-phase audit hoop already on the
//! protected subtree auto-audits the state-changing create/delete (actor-from-
//! session) — we add NO second audit path.
//!
//! ## create_connection (POST api/sso/connections)
//!   1. (SSO-04) if a `metadataUrl` is supplied, call `ssrf::validate_url` FIRST
//!      (internal/credentialed host → 422, NO fetch). The PREFERRED path is the
//!      operator-uploaded XML (base64 `encodedRawMetadata`, no fetch at all).
//!   2. (SSO-02) `metadata::require_signing_cert` on the uploaded XML BEFORE any
//!      Polis POST → 422 if no signing cert.
//!   3. `POST /api/v1/sso` (Api-Key) → a `Connection { clientID, clientSecret, … }`.
//!   4. (SSO-03) write a Kratos `provider: generic` entry via the AUTH-04
//!      `providers[]` array-root path: stable id `saml-<tenant>`, issuer_url = the
//!      Polis EXTERNAL_URL, client_id/secret from the Connection, scope
//!      [openid,email,profile], `mapper_url = base64://<gated Jsonnet>`. Existing
//!      providers' masked secrets are PRESERVED (`merge_array_by_id`). Restart
//!      Kratos ONLY, health-poll, rollback on failure.
//!   5. The response surfaces `clientID` + `idpMetadata` (entityID/thumbprint/
//!      provider); `clientSecret` is NEVER serialized back (write-only, BACK-07).
//!
//! ## list_connections (GET api/sso/connections)
//!   GET the Polis `(tenant, product)` connections and return them with every
//!   `clientSecret` STRIPPED (no GET/list body ever carries a secret value).
//!
//! ## delete_connection (DELETE api/sso/connections/{id})
//!   TWO-SIDED (Pitfall 5 / A6), Kratos-FIRST (CR-02): remove the matching Kratos
//!   `providers[]` entry (array-root replace via merge, preserving the other
//!   providers' masked secrets) + Kratos restart, and ONLY THEN `DELETE
//!   /api/v1/sso` (Polis). The Kratos side is the failure-prone, locally
//!   recoverable side, so removing it first means a partial failure can never
//!   strand a `saml-<tenant>` provider pointing at a deleted Polis connection. The
//!   Polis delete is idempotent (a 404 = already-deleted success), so a retry after
//!   a half-finished delete completes cleanly. Neither side dangles.

use std::path::PathBuf;
use std::time::Duration;

use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::Config;
use crate::config_edit::schema::FieldError;
use crate::config_edit::{jsonnet, locks, restart, secret_merge, yaml};
use crate::error::AppError;
use crate::sso::{mapper, metadata, polis_admin, provider_id, POLIS_PRODUCT};
use crate::webhooks::ssrf;

/// The array-root JSON-Pointer the Kratos OIDC providers live at (the ONLY
/// allowlisted pointer — per-index pointers are NEVER used; A: array-root replace).
const PROVIDERS_POINTER: &str = "/selfservice/methods/oidc/config/providers";
/// Toggle that enables the OIDC method (so a written provider is actually usable).
const OIDC_ENABLED_POINTER: &str = "/selfservice/methods/oidc/enabled";

/// Health-poll timeout for the Kratos restart after a provider write (mirrors the
/// config-edit engine's `HEALTH_TIMEOUT`).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// The scopes the generic provider requests from Polis (RESEARCH Pattern 4).
const PROVIDER_SCOPES: &[&str] = &["openid", "email", "profile"];

/// Hard cap on a fetched IdP-metadata document (CR-01). A SAML EntityDescriptor
/// is a few KB; 1 MiB is generous while bounding a hostile/oversized response on
/// the channel the BACKEND now performs itself.
const MAX_METADATA_BYTES: usize = 1024 * 1024;

/// The Kratos config file path (`<config_dir>/kratos/kratos.yml`). Fixed segments
/// only — never client input (mirrors `config_edit::routes::config_file_path`).
fn kratos_config_path(config_dir: &str) -> PathBuf {
    PathBuf::from(config_dir).join("kratos").join("kratos.yml")
}

/// Obtain the injected [`Config`] clone from the depot.
fn config_from(depot: &Depot) -> Result<Config, AppError> {
    depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))
}

/// Resolve the Polis admin credentials, mapping a missing key/issuer to a 502
/// (the SAML feature is mis-provisioned — we NEVER call Polis unauthenticated).
fn polis_creds(cfg: &Config) -> Result<(String, String, String), AppError> {
    let api_key = cfg.polis_api_key.clone().ok_or_else(|| {
        tracing::warn!("saml create: POLIS_API_KEY not configured");
        AppError::Upstream("polis admin api not configured".into())
    })?;
    let issuer = cfg.polis_external_url.clone().ok_or_else(|| {
        tracing::warn!("saml create: POLIS_EXTERNAL_URL not configured");
        AppError::Upstream("polis issuer not configured".into())
    })?;
    Ok((cfg.polis_admin_url.clone(), api_key, issuer))
}

/// Map an SSRF/fetch failure on the `metadata_url` path to a 422 `Validation`
/// keyed on `metadata_url` (WR-02) so the SAML form surfaces the operator-safe
/// reason VERBATIM through the SAME 422 path the signing-cert reject uses — the
/// most security-relevant reject must be the clearest, never a generic 400/502.
/// The `message` is value-free (the SSRF category, or a generic fetch-failed
/// string); it NEVER echoes the URL, the resolved IP, or the response body.
fn metadata_url_field_error(message: impl Into<String>) -> AppError {
    AppError::Validation(vec![FieldError {
        path: "metadata_url".into(),
        message: message.into(),
    }])
}

/// CR-01: the BACKEND fetches the IdP metadata ITSELF through the authoritative
/// SSRF-guarded client (`ssrf::build_pinned_client` — re-resolve + PIN the
/// just-validated addresses + redirects OFF), reads the body under a hard byte
/// cap, and returns the raw XML. This collapses the URL path onto the safe
/// fetch-free `encodedRawMetadata` branch: Polis NEVER fetches a URL, so the
/// DNS-rebind/redirect TOCTOU window that existed when we handed Polis a
/// `metadataUrl` is gone, and the WR-01 signing-cert pre-flight now runs on
/// URL-sourced metadata too (WR-03). Any block/transport/oversize failure becomes
/// a value-free 422 on `metadata_url` (WR-02) — never a Polis call.
async fn fetch_metadata_xml(url: &str) -> Result<String, AppError> {
    // `build_pinned_client(url, false)` re-resolves the host, rejects ANY resolved
    // IP in a blocked range, then pins the connection to exactly those addresses
    // with `Policy::none()` (redirects off). A blocked host is `AppError::BadRequest`
    // carrying the operator-safe SSRF category message — re-key it onto
    // `metadata_url` so the form shows it verbatim via the 422 path (WR-02).
    let (client, _addrs) = ssrf::build_pinned_client(url, false).await.map_err(|e| {
        let msg = match e {
            AppError::BadRequest(m) => m,
            _ => "The metadata URL could not be validated.".to_string(),
        };
        metadata_url_field_error(msg)
    })?;

    let resp = client.get(url).send().await.map_err(|e| {
        // Value-free: never echo the URL/host/IP into the client-facing message.
        tracing::warn!(error = %e, "saml metadata fetch transport error");
        metadata_url_field_error("The IdP metadata URL could not be fetched.")
    })?;

    if !resp.status().is_success() {
        // A non-2xx (incl. a 3xx that, with redirects OFF, is surfaced as-is) is a
        // fetch failure — never a Polis call. Value-free.
        let status = resp.status();
        tracing::warn!(status = %status, "saml metadata fetch non-2xx");
        return Err(metadata_url_field_error(
            "The IdP metadata URL did not return a fetchable document.",
        ));
    }

    // Read the body under a HARD cap so a hostile/oversized receiver cannot make
    // the backend buffer an unbounded document (the channel we now own).
    let mut body: Vec<u8> = Vec::new();
    let mut resp = resp;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_METADATA_BYTES {
                    tracing::warn!("saml metadata fetch exceeded the size cap");
                    return Err(metadata_url_field_error(
                        "The IdP metadata document is too large.",
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "saml metadata fetch body read error");
                return Err(metadata_url_field_error(
                    "The IdP metadata URL could not be fetched.",
                ));
            }
        }
    }

    String::from_utf8(body).map_err(|_| {
        metadata_url_field_error("The IdP metadata document is not valid UTF-8 XML.")
    })
}

/// The create-connection request body. Exactly ONE metadata source must be set:
/// `metadata_xml` (operator-uploaded IdP XML, PREFERRED) OR `metadata_url`.
#[derive(Debug, Deserialize)]
struct CreateBody {
    /// Stable connection id; becomes the Polis `tenant` and the `saml-<tenant>`
    /// Kratos provider id. In Phase 15 this is the Organization id.
    tenant: String,
    /// Operator-uploaded IdP metadata XML (PREFERRED — no fetch, no SSRF surface).
    #[serde(default)]
    metadata_xml: Option<String>,
    /// A metadataUrl (SSRF-guarded). Used only when `metadata_xml` is absent.
    #[serde(default)]
    metadata_url: Option<String>,
    /// Post-login default redirect (the AX/console callback). Required.
    default_redirect_url: String,
    /// Allowed redirect URLs. Required (a JSON array).
    redirect_url: Vec<String>,
    /// Optional human label.
    #[serde(default)]
    name: Option<String>,
}

/// Strip the `clientSecret` from a Polis connection value so no GET/list body ever
/// carries the secret (BACK-07 / T-14-04). Returns the object with the field
/// removed (and a `clientSecret_set` badge so the UI can show it exists).
fn strip_client_secret(mut conn: Value) -> Value {
    if let Value::Object(map) = &mut conn {
        let had = map.remove("clientSecret").is_some();
        map.insert("clientSecret_set".into(), Value::Bool(had));
    }
    conn
}

/// Build the Kratos `provider: generic` entry for a Polis connection. The
/// `mapper_url` is the base64-encoded `email_verified`-gated Jsonnet (SSO-03). The
/// `client_secret` is the REAL Polis secret here (it is masked on every subsequent
/// GET by `secret_merge::OIDC_SPEC`, and never returned to the frontend).
fn build_provider_entry(
    id: &str,
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Value {
    let mapper_url = jsonnet::encode_base64_uri(&mapper::generate_gated_mapper());
    json!({
        "id": id,
        "provider": "generic",
        "label": id,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": PROVIDER_SCOPES,
        "mapper_url": mapper_url,
    })
}

/// Read the current providers array from a loaded Kratos doc (empty if absent or
/// not an array).
fn read_providers(doc: &Value) -> Vec<Value> {
    doc.pointer(PROVIDERS_POINTER)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Compute the new providers array for an UPSERT of `entry` (by its `id`),
/// preserving every OTHER provider's stored secret via the merge-by-id regime.
/// The incoming array is (existing minus same-id) + the fresh entry; existing
/// items carry the MASKED sentinel for their secret so the merge re-inherits the
/// real stored value (never clobbered — Pitfall 3).
fn upsert_providers(stored: &[Value], entry: Value) -> Result<Vec<Value>, AppError> {
    let id = entry["id"].as_str().unwrap_or_default().to_string();
    // Build the incoming array: every OTHER stored provider with its secret MASKED
    // (so the merge preserves it), then our fresh entry with its real secret.
    let mut incoming = secret_merge::mask_array_secrets(stored, &secret_merge::OIDC_SPEC)
        .into_iter()
        .filter(|p| p.get("id").and_then(Value::as_str) != Some(id.as_str()))
        .collect::<Vec<_>>();
    incoming.push(entry);
    merge_providers(stored, &incoming)
}

/// Compute the new providers array for a DELETE of provider `id`, preserving every
/// remaining provider's stored secret. The incoming array is all stored providers
/// EXCEPT `id`, each with its secret masked so the merge re-inherits it.
fn remove_provider(stored: &[Value], id: &str) -> Result<Vec<Value>, AppError> {
    let incoming = secret_merge::mask_array_secrets(stored, &secret_merge::OIDC_SPEC)
        .into_iter()
        .filter(|p| p.get("id").and_then(Value::as_str) != Some(id))
        .collect::<Vec<_>>();
    merge_providers(stored, &incoming)
}

/// Run `merge_array_by_id` over the providers, mapping a fail-closed
/// `MaskWithoutStored` to a value-free 422 (an existing provider whose stored
/// secret could not be re-inherited — should not happen for our generated ids, but
/// fail closed rather than write a sentinel literal).
fn merge_providers(stored: &[Value], incoming: &[Value]) -> Result<Vec<Value>, AppError> {
    secret_merge::merge_array_by_id(stored, incoming, &secret_merge::OIDC_SPEC).map_err(|e| {
        let which = e
            .item_id
            .as_deref()
            .map(|id| format!("'{id}'"))
            .unwrap_or_else(|| "a provider".to_string());
        AppError::Validation(vec![FieldError {
            path: String::new(),
            message: format!(
                "re-enter the client secret for {which} (its identifier changed, so the stored secret cannot be preserved)"
            ),
        }])
    })
}

/// Write the merged providers array (+ enable the OIDC method) into the Kratos doc
/// and run the transactional restart flow: backup → write_atomic → restart Kratos
/// ONLY → health-poll → rollback on failure. Mirrors the config-edit engine.
async fn write_providers_and_restart(
    cfg: &Config,
    new_providers: Vec<Value>,
) -> Result<(), AppError> {
    let svc = restart::Service::Kratos;
    let path = kratos_config_path(&cfg.config_dir);

    // Share the per-service write lock with put_config so a provider write and a
    // kratos config edit can never interleave.
    let _guard = locks::try_acquire("kratos").await?;

    let mut merged = yaml::load(&path)?;
    let patch = vec![
        (PROVIDERS_POINTER.to_string(), Value::Array(new_providers)),
        (OIDC_ENABLED_POINTER.to_string(), Value::Bool(true)),
    ];
    yaml::apply_patch(&mut merged, &patch)?;

    yaml::backup(&path)?;
    if !yaml::backup_exists(&path) {
        tracing::error!(service = svc.key(), "saml provider write: backup missing; refusing write");
        return Err(AppError::Internal("kratos config backup missing".into()));
    }
    let serialized = yaml::serialize(&merged)?;
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "saml provider write: written");

    let http = restart::restart_client()?;
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        tracing::warn!(service = svc.key(), "saml provider write: broker restart failed; restoring disk");
        let _ = yaml::restore(&path);
        return Err(e);
    }
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "saml provider write: healthy");
        return Ok(());
    }
    tracing::warn!(service = svc.key(), "saml provider write: health failed; rolling back");
    if let Ok(yaml::RestoreOutcome::Restored) = yaml::restore(&path) {
        let _ = restart::restart(&http, &cfg.restart_broker_url, svc).await;
        let _ = restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await;
    }
    Err(AppError::HealthFailed)
}

/// `POST api/sso/connections` — create a SAML connection (SSO-02/03/04).
#[handler]
pub async fn create_connection(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let (polis_base, api_key, issuer) = polis_creds(&cfg)?;

    let body: CreateBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    if body.tenant.trim().is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            path: "tenant".into(),
            message: "tenant (connection id) is required".into(),
        }]));
    }
    if body.redirect_url.is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            path: "redirect_url".into(),
            message: "at least one redirect URL is required".into(),
        }]));
    }

    // Resolve the metadata source. PREFERRED: operator-uploaded XML (no fetch).
    let metadata_source = match (&body.metadata_xml, &body.metadata_url) {
        (Some(xml), _) if !xml.trim().is_empty() => {
            // SSO-02: mandatory signing-cert pre-flight BEFORE any Polis call.
            metadata::require_signing_cert(xml)?;
            polis_admin::MetadataSource::Encoded(metadata::encode_metadata(xml))
        }
        (_, Some(url)) if !url.trim().is_empty() => {
            // SSO-04 / CR-01: the BACKEND fetches the metadata ITSELF through the
            // authoritative SSRF-guarded, redirects-off, address-pinned client
            // (DNS-rebind defense) and reads it under a byte cap — Polis NEVER
            // fetches a URL. A blocked host / fetch failure is a value-free 422 on
            // `metadata_url` (WR-02), surfaced verbatim in the form.
            let xml = fetch_metadata_xml(url).await?;
            // SSO-02 / WR-03: the signing-cert pre-flight now runs on URL-sourced
            // metadata too (the backend has the actual XML). 422 if no signing cert.
            metadata::require_signing_cert(&xml)?;
            // Collapse onto the safe fetch-free path: send Polis base64 XML, never a URL.
            polis_admin::MetadataSource::Encoded(metadata::encode_metadata(&xml))
        }
        _ => {
            return Err(AppError::Validation(vec![FieldError {
                path: "metadata_xml".into(),
                message: "provide IdP metadata XML (preferred) or a metadataUrl".into(),
            }]));
        }
    };

    // (SSO-02 done above for the XML path.) POST the connection to Polis.
    let params = polis_admin::CreateParams {
        tenant: body.tenant.clone(),
        product: POLIS_PRODUCT.to_string(),
        default_redirect_url: body.default_redirect_url.clone(),
        redirect_url: body.redirect_url.clone(),
        metadata: metadata_source,
        name: body.name.clone(),
    };
    let conn = polis_admin::create_connection(&polis_base, &api_key, &params).await?;

    // SSO-03: write the Kratos generic provider entry (gated mapper) via the
    // AUTH-04 providers[] path; restart Kratos only.
    let id = provider_id(&body.tenant);
    let entry = build_provider_entry(&id, &issuer, &conn.client_id, &conn.client_secret);
    let path = kratos_config_path(&cfg.config_dir);
    let stored = read_providers(&yaml::load(&path)?);
    let new_providers = upsert_providers(&stored, entry)?;
    write_providers_and_restart(&cfg, new_providers).await?;

    // Response: surface the public connection facts; clientSecret is NEVER returned
    // (write-only — it now lives only in the Kratos provider entry, masked on GET).
    let mut out = Map::new();
    out.insert("tenant".into(), json!(body.tenant));
    out.insert("product".into(), json!(POLIS_PRODUCT));
    out.insert("provider_id".into(), json!(id));
    out.insert("clientID".into(), json!(conn.client_id));
    out.insert("idpMetadata".into(), conn.idp_metadata.clone());
    out.insert("clientSecret_set".into(), Value::Bool(true));
    Ok(Json(Value::Object(out)))
}

/// `GET api/sso/connections?tenant=` — list a tenant's connections (csrf-exempt),
/// with every `clientSecret` STRIPPED before the body leaves the backend.
#[handler]
pub async fn list_connections(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let (polis_base, api_key, _issuer) = polis_creds(&cfg)?;

    // The tenant to list (Phase 15 passes the Organization id). Required.
    let tenant = req
        .query::<String>("tenant")
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("tenant query parameter is required".into()))?;

    let items = polis_admin::list_connections(&polis_base, &api_key, &tenant, POLIS_PRODUCT).await?;
    let stripped: Vec<Value> = items.into_iter().map(strip_client_secret).collect();
    Ok(Json(json!({ "connections": stripped })))
}

/// `DELETE api/sso/connections/{id}` — TWO-SIDED delete (Polis connection + Kratos
/// `providers[]` entry). The `{id}` path segment is the connection `tenant`.
#[handler]
pub async fn delete_connection(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let (polis_base, api_key, _issuer) = polis_creds(&cfg)?;

    let tenant = req
        .param::<String>("id")
        .filter(|t| !t.trim().is_empty())
        .ok_or(AppError::NotFound)?;

    // CR-02: ORDER MATTERS — remove the SECURITY-RELEVANT Kratos provider entry
    // FIRST, then delete the Polis connection. The Kratos side (config write +
    // restart + health-poll) is the failure-prone but LOCALLY RECOVERABLE side:
    // if it fails, NOTHING was destroyed (Polis is untouched) and the operator can
    // retry the same endpoint. The previous Polis-first order could strand a
    // `saml-<tenant>` provider in kratos.yml pointing at a deleted Polis connection
    // — a broken sign-in path the UI could not clear (a retry's Polis delete 404'd
    // *before* the Kratos cleanup ran). With Kratos-first + idempotent Polis delete
    // (a 404 is treated as success), no partial failure leaves a dangling provider:
    //   - Kratos remove fails  → Polis intact, provider intact → retry is clean.
    //   - Kratos remove ok, Polis delete fails → provider already gone (the
    //     security-relevant side is clean); a retry finds no provider, then the
    //     idempotent Polis delete completes (404 = success).

    // Side 1 (security-relevant, recoverable): remove the matching Kratos
    // providers[] entry (array-root replace, preserving the other providers'
    // masked secrets) + restart Kratos. If it fails, Polis is still intact.
    let id = provider_id(&tenant);
    let path = kratos_config_path(&cfg.config_dir);
    let stored = read_providers(&yaml::load(&path)?);
    if stored.iter().any(|p| p.get("id").and_then(Value::as_str) == Some(id.as_str())) {
        let new_providers = remove_provider(&stored, &id)?;
        write_providers_and_restart(&cfg, new_providers).await?;
    } else {
        tracing::info!(provider = %id, "saml delete: no matching kratos provider entry (already absent)");
    }

    // Side 2: only now delete the Polis connection. The Polis delete is idempotent
    // (a 404 is treated as success), so a retry after a Kratos-first partial
    // failure still completes cleanly.
    polis_admin::delete_connection(&polis_base, &api_key, &tenant, POLIS_PRODUCT, None).await?;

    Ok(Json(json!({ "deleted": tenant, "provider_id": id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(id: &str, secret: &str) -> Value {
        json!({
            "id": id,
            "provider": "generic",
            "client_id": format!("cid-{id}"),
            "client_secret": secret,
            "scope": ["openid"],
            "mapper_url": "base64://Zm9v"
        })
    }

    #[test]
    fn build_provider_entry_carries_gated_mapper_and_no_unconditional_email() {
        let entry = build_provider_entry("saml-org1", "https://sso.example", "cid", "csecret");
        assert_eq!(entry["id"], "saml-org1");
        assert_eq!(entry["provider"], "generic");
        assert_eq!(entry["issuer_url"], "https://sso.example");
        assert_eq!(entry["client_secret"], "csecret");
        // The mapper_url is a base64:// URI whose decoded source is the gated mapper.
        let mapper_url = entry["mapper_url"].as_str().unwrap();
        assert!(mapper_url.starts_with("base64://"), "mapper must be inline base64://");
        let decoded = jsonnet::decode_base64_uri(mapper_url).unwrap();
        assert!(decoded.contains("email_verified: false"), "gated mapper missing default-false");
        assert!(decoded.contains(mapper::EMAIL_GATE), "gated mapper missing the email gate");
    }

    #[test]
    fn upsert_preserves_other_providers_secrets() {
        // An existing google provider must keep its real secret when we add a new
        // saml provider (the merge re-inherits the masked stored value).
        let stored = vec![provider("google", "REAL-google-secret")];
        let entry = build_provider_entry("saml-org1", "https://sso", "cid", "new-saml-secret");
        let merged = upsert_providers(&stored, entry).expect("upsert ok");
        assert_eq!(merged.len(), 2);
        let google = merged.iter().find(|p| p["id"] == "google").unwrap();
        assert_eq!(google["client_secret"], "REAL-google-secret", "existing secret preserved");
        let saml = merged.iter().find(|p| p["id"] == "saml-org1").unwrap();
        assert_eq!(saml["client_secret"], "new-saml-secret", "new secret kept");
    }

    #[test]
    fn upsert_replaces_existing_same_id() {
        // Re-creating the same connection id replaces its entry (no duplicate).
        let stored = vec![provider("saml-org1", "OLD"), provider("github", "gh-secret")];
        let entry = build_provider_entry("saml-org1", "https://sso", "cid2", "NEW");
        let merged = upsert_providers(&stored, entry).expect("upsert ok");
        assert_eq!(merged.len(), 2, "no duplicate saml-org1");
        let saml: Vec<_> = merged.iter().filter(|p| p["id"] == "saml-org1").collect();
        assert_eq!(saml.len(), 1);
        assert_eq!(saml[0]["client_secret"], "NEW");
        // github's secret preserved.
        let gh = merged.iter().find(|p| p["id"] == "github").unwrap();
        assert_eq!(gh["client_secret"], "gh-secret");
    }

    #[test]
    fn remove_provider_drops_only_target_and_preserves_rest() {
        let stored = vec![
            provider("saml-org1", "saml-secret"),
            provider("google", "REAL-google-secret"),
        ];
        let merged = remove_provider(&stored, "saml-org1").expect("remove ok");
        assert_eq!(merged.len(), 1, "the saml entry is removed");
        assert_eq!(merged[0]["id"], "google");
        assert_eq!(merged[0]["client_secret"], "REAL-google-secret", "other secret preserved");
    }

    #[test]
    fn strip_client_secret_removes_value_and_adds_badge() {
        let conn = json!({
            "clientID": "cid",
            "clientSecret": "SUPER-SECRET",
            "idpMetadata": { "entityID": "e" }
        });
        let stripped = strip_client_secret(conn);
        assert!(stripped.get("clientSecret").is_none(), "secret value removed");
        assert_eq!(stripped["clientSecret_set"], json!(true), "badge present");
        assert_eq!(stripped["clientID"], "cid", "non-secret fields kept");
        // No secret value survives anywhere in the serialized form.
        let s = serde_json::to_string(&stripped).unwrap();
        assert!(!s.contains("SUPER-SECRET"), "clientSecret leaked: {s}");
    }

    #[test]
    fn strip_client_secret_when_absent_sets_false_badge() {
        let conn = json!({ "clientID": "cid", "idpMetadata": {} });
        let stripped = strip_client_secret(conn);
        assert_eq!(stripped["clientSecret_set"], json!(false));
    }
}
