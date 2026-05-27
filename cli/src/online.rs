//! ONLINE-mode handlers (CLI-03/05/06) — HTTP ONLY.
//!
//! Every handler issues exactly ONE request to an EXISTING backend route through
//! the [`crate::client::ApiClient`] (Api-Key header, no CSRF). It NEVER writes
//! YAML or the console DB — the backend stays the single writer. This module
//! imports NEITHER `sqlx` NOR a YAML writer (T-19-11 / Pitfall 4 — a source-scan
//! test asserts the absence).
//!
//! Command → route map (verified against the live router, 19-RESEARCH):
//!   * `feature list`             → GET  /api/console/features
//!   * `feature enable|disable k` → PUT  /api/console/features/{k}  {"enabled":bool}
//!   * `observability on|off`     → PUT  /api/console/features/observability
//!   * `sso add-saml`             → POST /api/sso/connections        (SsoCreateBody)
//!   * `sso add-oidc`             → PUT  /api/config/kratos/oidc      (config-edit, A1)
//!   * `org add`                  → POST /api/organizations          (CreateOrgBody)
//!   * `admin list`               → GET  /api/console/members

use console_core::{CreateOrgBody, SsoCreateBody, ToggleRequest};
use serde_json::json;

use crate::client::ApiClient;
use crate::{
    CliError, FeatureAction, ObservabilityAction, OrgAction, SsoAction,
};

/// A1 (RESOLVED): Kratos OIDC providers are written through the config-edit
/// allowlist engine at the ARRAY-ROOT pointer. Confirmed in
/// `backend/src/config_edit/allowlist.rs::KRATOS_OIDC` and reused verbatim from
/// `backend/src/sso/routes.rs::PROVIDERS_POINTER` — the CLI invents NO new route.
const OIDC_PROVIDERS_POINTER: &str = "/selfservice/methods/oidc/config/providers";
const OIDC_ENABLED_POINTER: &str = "/selfservice/methods/oidc/enabled";

/// `feature` subcommand → GET (list) or PUT (enable/disable).
pub async fn feature(client: &ApiClient, action: FeatureAction) -> Result<(), CliError> {
    match action {
        FeatureAction::List => {
            let body = client.get("/api/console/features").await?;
            print!("{body}");
            Ok(())
        }
        FeatureAction::Enable { key } => set_flag(client, &key, true).await,
        FeatureAction::Disable { key } => set_flag(client, &key, false).await,
    }
}

/// `observability on|off` → PUT /api/console/features/observability {enabled}.
pub async fn observability(
    client: &ApiClient,
    action: ObservabilityAction,
) -> Result<(), CliError> {
    let enabled = matches!(action, ObservabilityAction::On);
    set_flag(client, "observability", enabled).await
}

/// PUT /api/console/features/{key} with the shared `ToggleRequest` DTO — the
/// CLI-02 "never a second writer" exemplar (goes through the route, not the DB).
async fn set_flag(client: &ApiClient, key: &str, enabled: bool) -> Result<(), CliError> {
    let path = format!("/api/console/features/{key}");
    let body = client.put_json(&path, &ToggleRequest { enabled }).await?;
    print!("{body}");
    Ok(())
}

/// `sso` subcommand → POST /api/sso/connections (add-saml) or PUT config-edit
/// (add-oidc, A1). Both reuse existing validated routes.
pub async fn sso(client: &ApiClient, action: SsoAction) -> Result<(), CliError> {
    match action {
        SsoAction::AddSaml {
            tenant,
            metadata_xml_file,
            metadata_url,
            default_redirect_url,
            redirect_url,
            name,
        } => {
            // SECURITY: the metadata XML is read from a FILE, never argv (the XML
            // can be large and the operator-uploaded path is preferred — no SSRF).
            let metadata_xml = match metadata_xml_file {
                Some(path) => Some(
                    std::fs::read_to_string(&path)
                        .map_err(|e| CliError::Io(format!("reading {path}: {e}")))?,
                ),
                None => None,
            };
            if metadata_xml.is_none() && metadata_url.is_none() {
                return Err(CliError::Backend(
                    "provide --metadata-xml-file (preferred) or --metadata-url".into(),
                ));
            }
            let body = SsoCreateBody {
                tenant,
                metadata_xml,
                metadata_url,
                default_redirect_url,
                redirect_url,
                name,
            };
            let resp = client.post_json("/api/sso/connections", &body).await?;
            print!("{resp}");
            Ok(())
        }
        SsoAction::AddOidc {
            id,
            provider,
            client_id,
            client_secret_file,
            issuer_url,
            mapper_url,
            scope,
        } => {
            // SECURITY: the client secret is read from a FILE / env / prompt,
            // NEVER an argv value (Pitfall 2).
            let client_secret = crate::bootstrap::read_secret(
                client_secret_file.as_deref(),
                "OIDC_CLIENT_SECRET",
                "OIDC client secret",
            )?;
            let scopes = if scope.is_empty() {
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ]
            } else {
                scope
            };
            // Build ONE provider object. The whole providers array is the single
            // allowlisted value at the array-root pointer (the backend merges by
            // id, preserving other providers' secrets — Pattern 1 / Pitfall 3).
            let mut provider_obj = json!({
                "id": id,
                "provider": provider,
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scopes,
            });
            if let Some(iss) = issuer_url {
                provider_obj["issuer_url"] = json!(iss);
            }
            if let Some(m) = mapper_url {
                provider_obj["mapper_url"] = json!(m);
            }
            // The config-edit PUT body is a FLAT JSON-Pointer object (verified:
            // `config_edit::routes::body_to_patch`). Enable the method + write the
            // single-provider array at the array-root pointer.
            let body = json!({
                OIDC_ENABLED_POINTER: true,
                OIDC_PROVIDERS_POINTER: [provider_obj],
            });
            let resp = client.put_json("/api/config/kratos/oidc", &body).await?;
            print!("{resp}");
            Ok(())
        }
    }
}

/// `org add` → POST /api/organizations with the shared `CreateOrgBody`.
pub async fn org(client: &ApiClient, action: OrgAction) -> Result<(), CliError> {
    match action {
        OrgAction::Add {
            label,
            domain,
            sso_connection_tenant,
        } => {
            let body = CreateOrgBody {
                label,
                domains: domain,
                sso_connection_tenant,
            };
            let resp = client.post_json("/api/organizations", &body).await?;
            print!("{resp}");
            Ok(())
        }
    }
}

/// `admin list` → GET /api/console/members (secret-free MemberView).
pub async fn admin_list(client: &ApiClient) -> Result<(), CliError> {
    let body = client.get("/api/console/members").await?;
    print!("{body}");
    Ok(())
}
