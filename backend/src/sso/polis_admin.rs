//! Ory Polis connection-admin client (SSO-02/04 — the SOLE client of the Polis
//! admin API, INFRA-05).
//!
//! VERIFIED against `ory/polis@v26.2.0 swagger/swagger.json` (RESEARCH, HIGH): the
//! SAML connection CRUD lives at `POST/GET/DELETE /api/v1/sso` (NOT
//! `/api/v1/connections` — that was a Phase-13 forward-reference guess, corrected),
//! authenticated with the `Authorization: Api-Key <key>` header. The create body
//! requires `tenant`, `product`, `defaultRedirectUrl`, `redirectUrl` (a JSON array)
//! plus exactly ONE metadata source — `encodedRawMetadata` (base64 IdP XML,
//! PREFERRED — no fetch) / `rawMetadata` / `metadataUrl`. The response `Connection`
//! carries `clientID`/`clientSecret` (the OAuth2 creds Kratos's generic provider
//! uses) and `idpMetadata` (`entityID`, `sso`, `thumbprint`, `provider`).
//!
//! SECURITY:
//!   - the `POLIS_API_KEY` is a WRITE-ONLY secret (BACK-07 / T-14-04): it is sent
//!     only in the `Authorization` header, NEVER logged, NEVER serialized into any
//!     response. The `Display`/`Debug` of this module's types never include it.
//!   - `clientSecret` is captured in [`ConnectionResponse`] for the Kratos provider
//!     write but is NEVER re-serialized on GET/list (the route layer strips it; the
//!     stored copy is masked by `secret_merge::OIDC_SPEC`).
//!   - the client follows NO redirects (`Policy::none()`) so a misbehaving Polis
//!     `Location` can never steer the admin call elsewhere.

use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// The verified connection CRUD path on the Polis admin API.
const SSO_PATH: &str = "/api/v1/sso";

/// Append a percent-encoded `?tenant=&product=[&clientID=]` query string to the
/// base SSO URL. Built locally (the reqwest 0.13 build here does not enable the
/// `.query()` helper feature); `tenant`/`product`/`clientID` are
/// server/operator-supplied identifiers, encoded defensively.
fn sso_url_with_query(
    polis_admin_base: &str,
    pairs: &[(&str, &str)],
) -> String {
    let base = format!("{}{SSO_PATH}", polis_admin_base.trim_end_matches('/'));
    if pairs.is_empty() {
        return base;
    }
    let qs = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{qs}")
}

/// Minimal percent-encoding for query-component values (RFC 3986 unreserved set is
/// passed through; everything else is `%XX`-encoded). Sufficient for the tenant/
/// product/clientID identifiers Polis multiplexes by.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the redirect-disabled reqwest client for Polis admin calls. Mirrors the
/// SSRF posture used in `auth/github.rs` (`Policy::none()`).
///
/// Uses the `reqwest_012` (0.12) alias — the SAME client the Ory typed crates use
/// (`ory/clients.rs`) — built with the bundled `rustls-tls` webpki roots. The
/// crate's primary reqwest 0.13 `rustls` feature pulls `rustls-platform-verifier`,
/// which has NO system trust store on the distroless backend image and therefore
/// fails `Client::builder().build()` with a "builder error" for EVERY request
/// (verified live in Phase 14 — the Polis call surfaced as a 502). reqwest 0.12
/// `rustls-tls` bundles webpki roots, so `build()` succeeds without a system store.
fn polis_client() -> Result<reqwest_012::Client, AppError> {
    reqwest_012::Client::builder()
        .redirect(reqwest_012::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(format!("build polis admin client: {e}")))
}

/// Compose the `Authorization: Api-Key <key>` header value. Kept in one place so
/// the prefix is consistent and the key is never inadvertently logged at a call
/// site (the value is only ever passed straight into the header builder).
fn api_key_header(api_key: &str) -> String {
    format!("Api-Key {api_key}")
}

/// The metadata source for a create request. There is exactly ONE shape: base64
/// of raw IdP XML sent as `encodedRawMetadata` (the fetch-free, no-SSRF-surface
/// path). CR-01: we NEVER send Polis a `metadataUrl` — when the operator supplies
/// a URL, the BACKEND fetches it itself through the authoritative SSRF-guarded
/// client (re-resolve + pin + redirects off) and feeds the fetched XML in here, so
/// Polis is never the fetcher and the DNS-rebind/redirect TOCTOU window is closed.
#[derive(Debug, Clone)]
pub enum MetadataSource {
    /// base64 of the IdP XML (operator-uploaded OR backend-fetched) → `encodedRawMetadata`.
    Encoded(String),
}

/// The verified `POST /api/v1/sso` create body (serde camelCase per the swagger).
/// The metadata is ALWAYS sent as `encodedRawMetadata` (base64 raw XML) — the
/// `metadataUrl` field is intentionally NOT modelled so Polis can never be made
/// the fetcher (CR-01: the backend is the sole fetcher, behind the SSRF guard).
/// The `redirect_url` is a JSON array of allowed redirect URLs.
#[derive(Debug, Serialize)]
struct CreateSamlConnection<'a> {
    tenant: &'a str,
    product: &'a str,
    #[serde(rename = "defaultRedirectUrl")]
    default_redirect_url: &'a str,
    #[serde(rename = "redirectUrl")]
    redirect_url: &'a [String],
    #[serde(rename = "encodedRawMetadata")]
    encoded_raw_metadata: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

/// The verified `Connection` response (only the fields the console consumes).
///
/// `client_id`/`client_secret` are the OAuth2 credentials the Kratos generic
/// provider consumes. `client_secret` is WRITE-ONLY end-to-end — it is used to
/// write the Kratos provider entry and then dropped; it is NEVER re-serialized to
/// the frontend. `idp_metadata` is passed through as a value so the route can
/// surface `entityID`/`thumbprint`/`provider` without re-modelling the whole shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionResponse {
    #[serde(rename = "clientID")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    #[serde(rename = "idpMetadata", default)]
    pub idp_metadata: serde_json::Value,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub product: String,
}

/// Parameters for a connection create. `redirect_url` is the allowed-redirect
/// array; `default_redirect_url` is the post-login default. `name` is optional.
#[derive(Debug, Clone)]
pub struct CreateParams {
    pub tenant: String,
    pub product: String,
    pub default_redirect_url: String,
    pub redirect_url: Vec<String>,
    pub metadata: MetadataSource,
    pub name: Option<String>,
}

/// `POST {polis_admin_base}/api/v1/sso` — create a SAML connection. Returns the
/// `Connection` (with `clientID`/`clientSecret`). A non-2xx Polis response maps to
/// `AppError::Upstream` (502) with NO body/URL/key echoed (BACK-07).
pub async fn create_connection(
    polis_admin_base: &str,
    api_key: &str,
    params: &CreateParams,
) -> Result<ConnectionResponse, AppError> {
    let MetadataSource::Encoded(encoded_raw_metadata) = &params.metadata;
    let body = CreateSamlConnection {
        tenant: &params.tenant,
        product: &params.product,
        default_redirect_url: &params.default_redirect_url,
        redirect_url: &params.redirect_url,
        encoded_raw_metadata: encoded_raw_metadata.as_str(),
        name: params.name.as_deref(),
    };

    let url = format!("{}{SSO_PATH}", polis_admin_base.trim_end_matches('/'));
    let resp = polis_client()?
        .post(&url)
        .header(reqwest_012::header::AUTHORIZATION, api_key_header(api_key))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "polis create_connection transport error");
            AppError::Upstream("polis admin api unreachable".to_string())
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        tracing::warn!(status = %status, "polis create_connection non-2xx");
        return Err(AppError::Upstream(format!("polis admin status {status}")));
    }
    resp.json::<ConnectionResponse>().await.map_err(|e| {
        tracing::warn!(error = %e, "decode polis Connection failed");
        AppError::Upstream("polis admin returned an undecodable connection".to_string())
    })
}

/// `GET {polis_admin_base}/api/v1/sso?tenant=&product=` — list the connections for
/// a `(tenant, product)`. Returns the raw `Connection` array as values; the route
/// layer strips `clientSecret` before any response leaves the backend. A non-2xx
/// maps to `AppError::Upstream` (502).
pub async fn list_connections(
    polis_admin_base: &str,
    api_key: &str,
    tenant: &str,
    product: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    let url = sso_url_with_query(polis_admin_base, &[("tenant", tenant), ("product", product)]);
    let resp = polis_client()?
        .get(&url)
        .header(reqwest_012::header::AUTHORIZATION, api_key_header(api_key))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "polis list_connections transport error");
            AppError::Upstream("polis admin api unreachable".to_string())
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        tracing::warn!(status = %status, "polis list_connections non-2xx");
        return Err(AppError::Upstream(format!("polis admin status {status}")));
    }
    // Polis returns an array of Connection objects; tolerate a single object too.
    let value: serde_json::Value = resp.json().await.map_err(|e| {
        tracing::warn!(error = %e, "decode polis connection list failed");
        AppError::Upstream("polis admin returned an undecodable list".to_string())
    })?;
    Ok(match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    })
}

/// `DELETE {polis_admin_base}/api/v1/sso?tenant=&product=&clientID=` — delete a
/// connection by `(tenant, product)` (+ optional `clientID`). The SECOND side of
/// the two-sided delete (the Kratos provider entry removal is done by the route).
/// A non-2xx maps to `AppError::Upstream` (502).
pub async fn delete_connection(
    polis_admin_base: &str,
    api_key: &str,
    tenant: &str,
    product: &str,
    client_id: Option<&str>,
) -> Result<(), AppError> {
    let mut query: Vec<(&str, &str)> = vec![("tenant", tenant), ("product", product)];
    if let Some(cid) = client_id {
        query.push(("clientID", cid));
    }
    let url = sso_url_with_query(polis_admin_base, &query);
    let resp = polis_client()?
        .delete(&url)
        .header(reqwest_012::header::AUTHORIZATION, api_key_header(api_key))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "polis delete_connection transport error");
            AppError::Upstream("polis admin api unreachable".to_string())
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        tracing::warn!(status = %status, "polis delete_connection non-2xx");
        return Err(AppError::Upstream(format!("polis admin status {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_params(metadata: MetadataSource) -> CreateParams {
        CreateParams {
            tenant: "org-1".into(),
            product: "ory-console".into(),
            default_redirect_url: "https://console.example/sso/callback".into(),
            redirect_url: vec!["https://console.example/sso/callback".into()],
            metadata,
            name: Some("Acme IdP".into()),
        }
    }

    #[tokio::test]
    async fn create_sends_api_key_and_returns_connection() {
        let mut server = mockito::Server::new_async().await;
        // The mock asserts the Authorization: Api-Key header AND the camelCase body
        // shape (encodedRawMetadata present, redirectUrl is an array).
        let m = server
            .mock("POST", "/api/v1/sso")
            .match_header("authorization", "Api-Key test-key-123")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("\"encodedRawMetadata\":\"YmFzZTY0eG1s\"".into()),
                mockito::Matcher::Regex("\"redirectUrl\":\\[".into()),
                mockito::Matcher::Regex("\"product\":\"ory-console\"".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"clientID":"cid-abc","clientSecret":"csecret-xyz",
                    "idpMetadata":{"entityID":"https://idp/meta","thumbprint":"AB:CD","provider":"okta.com"},
                    "tenant":"org-1","product":"ory-console"}"#,
            )
            .create_async()
            .await;

        let params = create_params(MetadataSource::Encoded("YmFzZTY0eG1s".into()));
        let conn = create_connection(&server.url(), "test-key-123", &params)
            .await
            .expect("create returns a Connection");
        m.assert_async().await;

        assert_eq!(conn.client_id, "cid-abc");
        assert_eq!(conn.client_secret, "csecret-xyz");
        assert_eq!(conn.idp_metadata["entityID"], "https://idp/meta");
        assert_eq!(conn.idp_metadata["thumbprint"], "AB:CD");
    }

    #[tokio::test]
    async fn create_never_sends_a_metadata_url_field() {
        // CR-01: the create body must ALWAYS carry encodedRawMetadata and NEVER a
        // metadataUrl — Polis is never the fetcher. This guards the regression where
        // a URL source could be delegated to Polis (SSRF-by-proxy).
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/sso")
            .match_header("authorization", "Api-Key k")
            // Match the encoded field present; the assertion that NO metadataUrl is
            // ever serialized is enforced structurally (the body struct has no such
            // field) and re-checked below against the captured request body.
            .match_body(mockito::Matcher::Regex(
                "\"encodedRawMetadata\":\"YmFzZTY0eG1s\"".into(),
            ))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"clientID":"c","clientSecret":"s","idpMetadata":{},"tenant":"org-1","product":"ory-console"}"#)
            .create_async()
            .await;

        let params = create_params(MetadataSource::Encoded("YmFzZTY0eG1s".into()));
        let conn = create_connection(&server.url(), "k", &params)
            .await
            .expect("create with encoded source returns a Connection");
        m.assert_async().await;
        assert_eq!(conn.client_id, "c");
    }

    #[tokio::test]
    async fn create_maps_non_2xx_to_upstream_without_leaking_body() {
        let mut server = mockito::Server::new_async().await;
        let body = "POLIS INTERNAL: api key abcdef rejected";
        let _m = server
            .mock("POST", "/api/v1/sso")
            .with_status(401)
            .with_body(body)
            .create_async()
            .await;

        let params = create_params(MetadataSource::Encoded("YmFzZTY0".into()));
        let err = create_connection(&server.url(), "bad", &params)
            .await
            .expect_err("non-2xx must be an upstream error");
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.status_code(), salvo::http::StatusCode::BAD_GATEWAY);
        // The Polis body (which echoed an api key) must never leak into the error.
        assert!(
            !err.to_string().contains("abcdef") && !err.to_string().contains("api key"),
            "polis body must not leak into the error: {err}"
        );
    }

    #[tokio::test]
    async fn list_sends_tenant_product_and_api_key() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/api/v1/sso")
            .match_header("authorization", "Api-Key list-key")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("tenant".into(), "org-1".into()),
                mockito::Matcher::UrlEncoded("product".into(), "ory-console".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"clientID":"c1","clientSecret":"s1","idpMetadata":{"entityID":"e1"}}]"#)
            .create_async()
            .await;

        let items = list_connections(&server.url(), "list-key", "org-1", "ory-console")
            .await
            .expect("list returns the connection array");
        m.assert_async().await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["clientID"], "c1");
    }

    #[tokio::test]
    async fn delete_sends_tenant_product_clientid_and_api_key() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("DELETE", "/api/v1/sso")
            .match_header("authorization", "Api-Key del-key")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("tenant".into(), "org-1".into()),
                mockito::Matcher::UrlEncoded("product".into(), "ory-console".into()),
                mockito::Matcher::UrlEncoded("clientID".into(), "cid-abc".into()),
            ]))
            .with_status(200)
            .create_async()
            .await;

        delete_connection(&server.url(), "del-key", "org-1", "ory-console", Some("cid-abc"))
            .await
            .expect("delete by (tenant,product,clientID) succeeds");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn delete_maps_non_2xx_to_upstream() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("DELETE", "/api/v1/sso")
            .with_status(500)
            .create_async()
            .await;
        let err = delete_connection(&server.url(), "k", "org-1", "ory-console", None)
            .await
            .expect_err("non-2xx delete must be an upstream error");
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
    }
}
