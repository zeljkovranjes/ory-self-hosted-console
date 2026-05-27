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
use crate::ui::Ui;
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
///
/// PRESENTATION ONLY differs by [`Ui`] mode — the HTTP method/path/body/headers
/// are byte-for-byte UNCHANGED (the `cli_commands.rs` route matchers still pass).
/// `list` renders an aligned semantic table (`feature` + `enabled` ✓/✗) via
/// [`Ui::table`]; enable/disable render a [`Ui::status_ok`] line instead of dumping
/// the raw response body. When `enable`/`disable` is invoked WITHOUT a key on a
/// Rich TTY, an interactive [`crate::ui::Prompter::select`] of the valid keys is
/// offered (CLI-07 omitted-positional picker); on a non-TTY the omission errors
/// clearly (it never hangs).
pub async fn feature(
    client: &ApiClient,
    action: FeatureAction,
    ui: Ui,
) -> Result<(), CliError> {
    match action {
        FeatureAction::List => {
            let body = client.get("/api/console/features").await?;
            render_feature_table(&body, ui);
            Ok(())
        }
        FeatureAction::Enable { key } => {
            let key = resolve_feature_key(client, key, ui, true).await?;
            set_flag(client, &key, true, ui).await
        }
        FeatureAction::Disable { key } => {
            let key = resolve_feature_key(client, key, ui, false).await?;
            set_flag(client, &key, false, ui).await
        }
    }
}

/// Resolve the feature key for an enable/disable: the explicit arg if given, else
/// an interactive `Select` of the current valid keys on a Rich TTY. On a Plain /
/// non-TTY path a missing key is a CLEAR error (no widget, no hang).
async fn resolve_feature_key(
    client: &ApiClient,
    key: Option<String>,
    ui: Ui,
    _enable: bool,
) -> Result<String, CliError> {
    if let Some(k) = key {
        return Ok(k);
    }
    if ui.mode != crate::ui::OutputMode::Rich {
        return Err(CliError::Backend(
            "no feature key given — pass the key (e.g. `feature enable saml`). \
             (Interactive key selection needs a TTY.)"
                .into(),
        ));
    }
    // Rich TTY: fetch the current flags and present a Select of the keys.
    let body = client.get("/api/console/features").await?;
    let keys = feature_keys(&body);
    if keys.is_empty() {
        return Err(CliError::Backend(
            "no feature keys returned by the backend to choose from".into(),
        ));
    }
    let items: Vec<&str> = keys.iter().map(String::as_str).collect();
    let idx = ui.prompter().select("Which feature?", &items, 0)?;
    Ok(keys[idx].clone())
}

/// `observability on|off` → PUT /api/console/features/observability {enabled}.
pub async fn observability(
    client: &ApiClient,
    action: ObservabilityAction,
    ui: Ui,
) -> Result<(), CliError> {
    let enabled = matches!(action, ObservabilityAction::On);
    set_flag(client, "observability", enabled, ui).await
}

/// PUT /api/console/features/{key} with the shared `ToggleRequest` DTO — the
/// CLI-02 "never a second writer" exemplar (goes through the route, not the DB).
/// The request is UNCHANGED; only the result rendering routes through [`Ui`].
async fn set_flag(client: &ApiClient, key: &str, enabled: bool, ui: Ui) -> Result<(), CliError> {
    let path = format!("/api/console/features/{key}");
    let _body = client.put_json(&path, &ToggleRequest { enabled }).await?;
    let verb = if enabled { "enabled" } else { "disabled" };
    ui.status_ok(&format!("{key} {verb}"));
    Ok(())
}

/// Extract the feature keys from a `GET /api/console/features` body. Tolerates
/// either a top-level `{"features": {k: bool}}` envelope or a bare `{k: bool}` map.
fn feature_keys(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let map = v.get("features").unwrap_or(&v);
    match map.as_object() {
        Some(obj) => obj.keys().cloned().collect(),
        None => Vec::new(),
    }
}

/// Render the feature flags as an aligned `feature` / `enabled` table. Untrusted
/// backend strings (the feature keys) are placed in table CELLS only — never used
/// as a format/control string (T-20-ANSI). In Plain mode [`Ui::table`] emits a
/// borderless, colorless table → zero ANSI bytes. A body that does not parse falls
/// back to printing it verbatim (still no ui-added color).
fn render_feature_table(body: &str, ui: Ui) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        print!("{body}");
        return;
    };
    let map = v.get("features").unwrap_or(&v);
    let Some(obj) = map.as_object() else {
        print!("{body}");
        return;
    };
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            // WR-05: distinguish a non-bool value from `false`. A non-bool shape
            // renders as `?` (unknown) — never a misleading `✗` — and the coercion
            // is logged. Semantic glyph in the cell; comfy-table colors nothing in
            // Plain.
            let mark = match obj.get(*k).and_then(|x| x.as_bool()) {
                Some(true) => "✓",
                Some(false) => "✗",
                None => {
                    eprintln!(
                        "warning: feature `{k}` has a non-bool value — shown as `?` \
                         (not coerced to disabled)"
                    );
                    "?"
                }
            };
            vec![(*k).clone(), mark.to_string()]
        })
        .collect();
    ui.table(&["feature", "enabled"], &rows);
}

/// `sso` subcommand → POST /api/sso/connections (add-saml) or PUT config-edit
/// (add-oidc, A1). Both reuse existing validated routes.
pub async fn sso(client: &ApiClient, action: SsoAction, ui: Ui) -> Result<(), CliError> {
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
            let _resp = client.post_json("/api/sso/connections", &body).await?;
            ui.status_ok("SAML connection created");
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
            let _resp = client.put_json("/api/config/kratos/oidc", &body).await?;
            ui.status_ok(&format!("OIDC provider `{id}` written"));
            Ok(())
        }
    }
}

/// `org add` → POST /api/organizations with the shared `CreateOrgBody`.
pub async fn org(client: &ApiClient, action: OrgAction, ui: Ui) -> Result<(), CliError> {
    match action {
        OrgAction::Add {
            label,
            domain,
            sso_connection_tenant,
        } => {
            let body = CreateOrgBody {
                label: label.clone(),
                domains: domain,
                sso_connection_tenant,
            };
            let _resp = client.post_json("/api/organizations", &body).await?;
            ui.status_ok(&format!("organization `{label}` created"));
            Ok(())
        }
    }
}

/// `admin list` → GET /api/console/members (secret-free MemberView). Renders an
/// aligned table; the request is UNCHANGED. Untrusted member strings (email, name)
/// are placed in table CELLS only (T-20-ANSI).
pub async fn admin_list(client: &ApiClient, ui: Ui) -> Result<(), CliError> {
    let body = client.get("/api/console/members").await?;
    render_member_table(&body, ui);
    Ok(())
}

/// Render the console members as an aligned `email` / `name` / `role` table.
/// Tolerates a top-level array or a `{"members": [...]}` envelope; an unparseable
/// body falls back to printing it verbatim.
fn render_member_table(body: &str, ui: Ui) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        print!("{body}");
        return;
    };
    let arr = v.get("members").unwrap_or(&v);
    let Some(items) = arr.as_array() else {
        print!("{body}");
        return;
    };
    let cell = |m: &serde_json::Value, k: &str| {
        m.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|m| vec![cell(m, "email"), cell(m, "name"), cell(m, "role")])
        .collect();
    ui.table(&["email", "name", "role"], &rows);
}
