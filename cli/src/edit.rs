//! GUIDED `edit` command group (CLI-09).
//!
//! Three guided editors, each mutating ONLY through an EXISTING channel — `edit`
//! is NEVER a second writer of the console DB or service YAML:
//!
//!   * `edit features` — the `[x]`/`[ ]` MultiSelect (Req 2) PRE-CHECKED to the
//!     current effective flag state, diffed via [`crate::ui::diff_features`], and
//!     applied per CHANGED key via the EXISTING PUT `/api/console/features/{key}`
//!     route ([`console_core::ToggleRequest`]). ONLINE only — no direct DB write.
//!     A bare Enter (no toggles) is a NO-OP (zero PUTs); a missing key / unreachable
//!     backend BLOCKS with a clear diagnostic BEFORE any apply.
//!   * `edit services` / `edit config` — re-pick service modes + BYO URLs (and the
//!     postgres/observability backing stores) via the SAME `ui` Select/Input flow
//!     `init` uses, PRE-DEFAULTED to the current config, then re-write ONLY the
//!     gitignored `.env` (via [`crate::emit::emit_env_from_config`]) +
//!     `console.config.toml` (via [`config_model::to_toml_string`] +
//!     [`crate::wizard::write_config_out`]). Any newly-required secret is filled
//!     idempotently via [`crate::wizard::generate_missing_secrets`]; any BYO secret
//!     routes through [`crate::bootstrap::read_secret`] (env / `--*-file` / masked
//!     prompt) into `.env` ONLY — never argv, never the toml. NO console-DB or
//!     service-YAML write (the backend stays the single writer of service YAML).
//!
//! `edit` adds NO new write path: every mutation is either the EXISTING features
//! PUT or the EXISTING config/`.env` emitters. The module imports NO `sqlx` and NO
//! YAML writer — the lean-default-build + single-writer invariants hold by
//! construction.

use console_core::ToggleRequest;

use crate::client::ApiClient;
use crate::config_model::{
    self, ConsoleConfig, ObservabilityConfig, ObservabilityMode, ObservabilityModeField,
    PostgresConfig, PostgresMode, PostgresModeField, ServiceConfig, ServiceMode, ServiceModeField,
    SERVICES,
};
use crate::ui::{self, OutputMode, Prompter, Ui};
use crate::{emit, wizard, CliError, EditAction};

/// The default `console.config.toml` path resolved when no `--config` is given
/// (mirrors `init`'s `--config-out` default + `check`'s `DEFAULT_CONFIG_PATH`).
const DEFAULT_CONFIG_PATH: &str = "console.config.toml";
/// The default `.env` target re-written by `edit services`/`config` (mirrors
/// `init`'s `--env-file` default). Must be a gitignored path (the emitters guard).
const DEFAULT_ENV_PATH: &str = ".env";

/// Dispatch an `edit` action.
///
/// `edit features` is ONLINE (it needs `api_url`/`api_key`); `edit services`/
/// `config` are filesystem-only (they re-write `.env` + the toml via the existing
/// writers and ignore the ONLINE credentials).
pub async fn run_edit(
    action: EditAction,
    api_url: &str,
    api_key: Option<&str>,
    ui: Ui,
) -> Result<(), CliError> {
    match action {
        EditAction::Features => edit_features(api_url, api_key, ui).await,
        EditAction::Services { config } => edit_services(config, ui),
        EditAction::Config { config } => edit_config(config, ui),
    }
}

// ─── edit features — the [x]/[ ] MultiSelect → diff → EXISTING PUT route ────────

/// `edit features` (CLI-09 centerpiece): GET the current effective flags, present
/// the `[x]`/`[ ]` MultiSelect PRE-CHECKED to that state, diff the result, and
/// apply each CHANGED key via the EXISTING PUT `/api/console/features/{key}`.
///
/// * A bare Enter (no toggles) → an EMPTY diff → ZERO PUTs (the no-op invariant).
/// * Backend unreachable / missing api key → BLOCK with a clear diagnostic BEFORE
///   any apply (no partial write).
/// * Plain / non-TTY → a clear "use `feature enable/disable <key>`" error (the
///   MultiSelect needs a TTY; never a hang).
async fn edit_features(api_url: &str, api_key: Option<&str>, ui: Ui) -> Result<(), CliError> {
    ui.heading("edit features");

    // 1. Build the ONLINE client (a missing api key is the existing MissingApiKey
    //    BLOCK) + GET the current flags. A GET failure BLOCKS before any apply.
    let client = ApiClient::new(api_url, api_key)?;
    let body = match client.get("/api/console/features").await {
        Ok(b) => b,
        Err(e) => {
            ui.status_err(&format!(
                "cannot edit features — backend unreachable or features unavailable: {e}"
            ));
            return Err(e);
        }
    };
    // Ordered (key, enabled) list — sorted for a deterministic row order, mirroring
    // the `Features` BTreeMap ordering.
    let current = parse_feature_flags(&body);
    if current.is_empty() {
        ui.status_err("the backend returned no feature flags to edit");
        return Err(CliError::Backend(
            "no feature flags returned by the backend".into(),
        ));
    }
    let ordered_keys: Vec<String> = current.iter().map(|(k, _)| k.clone()).collect();
    let features = config_model::Features(current.iter().cloned().collect());

    // 2. The MultiSelect needs a Rich TTY — Plain/non-TTY directs to the day-2 verb
    //    (never constructs a widget off a Rich path, never hangs).
    if ui.mode != OutputMode::Rich {
        return Err(CliError::Backend(
            "interactive `edit features` needs a TTY. Non-interactively, toggle a \
             single flag with `feature enable <key>` / `feature disable <key>`."
                .into(),
        ));
    }

    let before_mask = ui::feature_default_mask(&features, &ordered_keys);
    let labels: Vec<&str> = ordered_keys.iter().map(String::as_str).collect();
    let after_indices = ui.prompter().multiselect(
        "Features — Space toggles [x], Enter confirms",
        &labels,
        &before_mask,
    )?;
    let changed = ui::diff_features(&before_mask, &after_indices, &ordered_keys);

    // 3. Apply each CHANGED key via the EXISTING PUT route (no-op when empty).
    apply_feature_changes(&client, &changed, ui).await
}

/// Apply a feature diff via the EXISTING PUT `/api/console/features/{key}` route —
/// exactly one PUT per CHANGED key with `{"enabled": new_state}`
/// ([`console_core::ToggleRequest`], the SAME body `edit_features_calls_put_route`
/// pins). An EMPTY diff issues ZERO PUTs and reports a "no changes" warning.
async fn apply_feature_changes(
    client: &ApiClient,
    changed: &[(String, bool)],
    ui: Ui,
) -> Result<(), CliError> {
    if changed.is_empty() {
        ui.status_warn("no changes — every flag left as it was (no requests sent)");
        return Ok(());
    }
    for (key, enabled) in changed {
        let path = format!("/api/console/features/{key}");
        client
            .put_json(&path, &ToggleRequest { enabled: *enabled })
            .await?;
        let verb = if *enabled { "enabled" } else { "disabled" };
        ui.status_ok(&format!("{key} {verb}"));
    }
    Ok(())
}

/// Parse a `GET /api/console/features` body into a sorted `(key, enabled)` list.
/// Tolerates either a `{"features": {k: bool}}` envelope or a bare `{k: bool}` map.
/// Unparseable / non-object bodies yield an empty list (the caller BLOCKS).
fn parse_feature_flags(body: &str) -> Vec<(String, bool)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let map = v.get("features").unwrap_or(&v);
    let Some(obj) = map.as_object() else {
        return Vec::new();
    };
    let mut pairs: Vec<(String, bool)> = obj
        .iter()
        .map(|(k, val)| (k.clone(), val.as_bool().unwrap_or(false)))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

// ─── edit services / edit config — re-pick → re-write via the EXISTING writers ──

/// `edit services`: load the current config (or the all-in-stack default with a
/// warning when absent), re-pick every service's mode + BYO URLs + the postgres /
/// observability backing stores PRE-DEFAULTED to the current values, then re-write
/// ONLY `.env` + `console.config.toml` via the EXISTING writers. NO DB / YAML write.
fn edit_services(config_arg: Option<String>, ui: Ui) -> Result<(), CliError> {
    ui.heading("edit services");
    edit_via_repick(config_arg, ui)
}

/// `edit config` (Open Question 1): the SIMPLEST intuitive form REUSES the
/// `edit services` Select/Input flow over the loaded config — same single-writer
/// path, same EXISTING writers. (A distinct raw-TOML editor would invent a new
/// write surface; this does not.)
fn edit_config(config_arg: Option<String>, ui: Ui) -> Result<(), CliError> {
    ui.heading("edit config");
    edit_via_repick(config_arg, ui)
}

/// The shared re-pick → re-write core for `edit services`/`config`. PRE-DEFAULTS
/// every prompt to the CURRENT config so a bare Enter keeps the present value, then
/// writes through the EXISTING emitters ONLY.
fn edit_via_repick(config_arg: Option<String>, ui: Ui) -> Result<(), CliError> {
    let path = config_arg.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string());

    // The current config: the on-disk file, or the all-in-stack default (with a
    // warning) when absent — so a first-time `edit` still works.
    let current = match config_model::load_config(&path) {
        Ok(cfg) => cfg,
        Err(_) => {
            ui.status_warn(&format!(
                "no readable {path} — starting from the all-in-stack defaults"
            ));
            ConsoleConfig::all_in_stack_default()
        }
    };

    // The MultiSelect/Select prompts need a Rich TTY — Plain/non-TTY directs the
    // operator to the file-based path (never constructs a widget off a Rich path).
    if ui.mode != OutputMode::Rich {
        return Err(CliError::Io(format!(
            "interactive `edit` needs a TTY. Non-interactively, edit {path} directly \
             and re-apply it with `init --config {path}`."
        )));
    }

    let prompter = ui.prompter();
    let new_cfg = repick_config(prompter.as_ref(), &current)?;

    // Re-write ONLY through the EXISTING writers — NO new write path:
    //   1. console.config.toml via to_toml_string + write_config_out (no secret).
    //   2. .env via emit_env_from_config (CONSOLE_SERVICE_* + byo URLs + profiles).
    //   3. generate_missing_secrets fills any newly-required secret (idempotent —
    //      never rotates a present one).
    let toml = config_model::to_toml_string(&new_cfg)?;
    wizard::write_config_out(&path, &toml)?;
    ui.status_ok(&format!("re-wrote {path}"));

    emit::emit_env_from_config(&new_cfg, DEFAULT_ENV_PATH)?;
    ui.status_ok(&format!("re-emitted {DEFAULT_ENV_PATH} (CONSOLE_SERVICE_* + byo URLs + COMPOSE_PROFILES)"));

    wizard::generate_missing_secrets(&new_cfg, DEFAULT_ENV_PATH)?;

    // The restart/apply boundary: `edit` writes config + `.env` and then GUIDES the
    // operator — it does NOT directly restart a service (the backend remains the
    // single writer of service YAML; an apply is the existing `init`/orchestrate
    // path or a `docker compose up`).
    ui.hint(
        "next: re-run `docker compose up -d` (or `init --config <path>`) to apply the \
         new service selection. `edit` itself does not restart services.",
    );
    Ok(())
}

/// Re-pick a whole [`ConsoleConfig`] interactively, PRE-DEFAULTED to `current` so a
/// bare Enter keeps each present value. Mirrors the wizard's per-service flow but
/// every default index/value comes from the CURRENT config.
fn repick_config(prompter: &dyn Prompter, current: &ConsoleConfig) -> Result<ConsoleConfig, CliError> {
    let mut services = config_model::Services::default();
    for svc in SERVICES {
        let mode = repick_service_mode(prompter, svc, current.mode_of(svc))?;
        let mut cfg = ServiceConfig {
            mode: Some(ServiceModeField(mode)),
            ..Default::default()
        };
        if mode == ServiceMode::Byo {
            repick_byo_urls(prompter, svc, current, &mut cfg)?;
        }
        services.set(svc, cfg);
    }

    let postgres = repick_postgres(prompter, current)?;
    let observability = repick_observability(prompter, current)?;

    // Features are NOT re-picked here — they are mutated via `edit features` (the
    // dedicated ONLINE flow). Carry the current effective set forward unchanged so a
    // services/config edit never silently flips a flag.
    let features = current.effective_features();

    Ok(ConsoleConfig {
        services,
        postgres: Some(postgres),
        observability: Some(observability),
        features: Some(features),
    })
}

/// Re-pick one service's mode via a Select PRE-DEFAULTED to its current mode index.
fn repick_service_mode(
    prompter: &dyn Prompter,
    service: &str,
    current: ServiceMode,
) -> Result<ServiceMode, CliError> {
    let default = match current {
        ServiceMode::InStack => 0,
        ServiceMode::Byo => 1,
        ServiceMode::Off => 2,
    };
    let idx = prompter.select(
        &format!("Service `{service}` mode"),
        &["in-stack", "byo", "off"],
        default,
    )?;
    Ok(match idx {
        0 => ServiceMode::InStack,
        1 => ServiceMode::Byo,
        _ => ServiceMode::Off,
    })
}

/// Re-pick the BYO external URL slot(s) for a service, PRE-DEFAULTED to the current
/// values so a bare Enter keeps each present URL. Empty answers leave the slot unset.
fn repick_byo_urls(
    prompter: &dyn Prompter,
    service: &str,
    current: &ConsoleConfig,
    cfg: &mut ServiceConfig,
) -> Result<(), CliError> {
    let cur = current_service_cfg(current, service);
    match service {
        "kratos" => {
            cfg.admin_url = opt(prompter.input("  kratos admin URL", def(cur.and_then(|c| c.admin_url.as_ref())))?);
        }
        "hydra" => {
            cfg.admin_url = opt(prompter.input("  hydra admin URL", def(cur.and_then(|c| c.admin_url.as_ref())))?);
            cfg.public_url = opt(prompter.input("  hydra public URL", def(cur.and_then(|c| c.public_url.as_ref())))?);
        }
        "keto" => {
            cfg.read_url = opt(prompter.input("  keto read URL", def(cur.and_then(|c| c.read_url.as_ref())))?);
            cfg.write_url = opt(prompter.input("  keto write URL", def(cur.and_then(|c| c.write_url.as_ref())))?);
        }
        "oathkeeper" => {
            cfg.admin_url = opt(prompter.input("  oathkeeper API URL", def(cur.and_then(|c| c.admin_url.as_ref())))?);
        }
        "polis" => {
            cfg.admin_url = opt(prompter.input("  polis admin URL", def(cur.and_then(|c| c.admin_url.as_ref())))?);
            cfg.external_url = opt(prompter.input("  polis external (OIDC issuer) URL", def(cur.and_then(|c| c.external_url.as_ref())))?);
            // The Polis API key is a SECRET — read via read_secret (env/file/masked
            // prompt), upserted to .env ONLY, NEVER stored in console.config.toml /
            // NEVER on argv. Surfaced here; nothing is stored in the model.
            eprintln!(
                "  (POLIS_API_KEY is a secret — provide it via the POLIS_API_KEY env var \
                 or a --*-file at run time; it is never stored in console.config.toml)"
            );
        }
        _ => {}
    }
    Ok(())
}

/// The current per-service config (the URL slots to pre-fill), if present.
fn current_service_cfg<'a>(current: &'a ConsoleConfig, service: &str) -> Option<&'a ServiceConfig> {
    match service {
        "kratos" => current.services.kratos.as_ref(),
        "hydra" => current.services.hydra.as_ref(),
        "keto" => current.services.keto.as_ref(),
        "oathkeeper" => current.services.oathkeeper.as_ref(),
        "polis" => current.services.polis.as_ref(),
        _ => None,
    }
}

/// Re-pick the Postgres backing store PRE-DEFAULTED to the current mode + values.
fn repick_postgres(prompter: &dyn Prompter, current: &ConsoleConfig) -> Result<PostgresConfig, CliError> {
    let cur = current.postgres.as_ref();
    let default = match current.postgres_mode() {
        PostgresMode::InStack => 0,
        PostgresMode::Byo => 1,
    };
    let mode = match prompter.select("Postgres backing store", &["in-stack", "byo"], default)? {
        0 => PostgresMode::InStack,
        _ => PostgresMode::Byo,
    };
    let mut cfg = PostgresConfig {
        mode: Some(PostgresModeField(mode)),
        ..Default::default()
    };
    if mode == PostgresMode::Byo {
        let def = |f: Option<&String>, fallback: &str| f.map(String::as_str).unwrap_or(fallback).to_string();
        cfg.host = opt(prompter.input("  postgres host", &def(cur.and_then(|c| c.host.as_ref()), ""))?);
        cfg.port = opt(prompter.input("  postgres port", &def(cur.and_then(|c| c.port.as_ref()), "5432"))?);
        cfg.sslmode = opt(prompter.input("  postgres sslmode", &def(cur.and_then(|c| c.sslmode.as_ref()), "require"))?);
        // The DB password(s) are SECRETS — never collected here / never argv (read
        // via read_secret into .env only at run time).
        eprintln!(
            "  (POSTGRES_PASSWORD + the per-service *_DB_PASSWORD values are SECRETS — provide \
             them via env / a --*-file at run time; they are never stored in console.config.toml.)"
        );
    }
    Ok(cfg)
}

/// Re-pick the observability backing store PRE-DEFAULTED to the current mode + URLs.
fn repick_observability(
    prompter: &dyn Prompter,
    current: &ConsoleConfig,
) -> Result<ObservabilityConfig, CliError> {
    let cur = current.observability.as_ref();
    let default = match current.observability_mode() {
        ObservabilityMode::Off => 0,
        ObservabilityMode::InStack => 1,
        ObservabilityMode::Byo => 2,
    };
    let mode = match prompter.select(
        "Observability (Prometheus/Grafana/Loki)",
        &["off", "in-stack", "byo"],
        default,
    )? {
        0 => ObservabilityMode::Off,
        1 => ObservabilityMode::InStack,
        _ => ObservabilityMode::Byo,
    };
    let mut cfg = ObservabilityConfig {
        mode: Some(ObservabilityModeField(mode)),
        ..Default::default()
    };
    if mode == ObservabilityMode::Byo {
        cfg.prometheus_url = opt(prompter.input("  Prometheus base URL", def(cur.and_then(|c| c.prometheus_url.as_ref())))?);
        cfg.loki_url = opt(prompter.input("  Loki base URL", def(cur.and_then(|c| c.loki_url.as_ref())))?);
        cfg.grafana_url = opt(prompter.input("  Grafana base URL", def(cur.and_then(|c| c.grafana_url.as_ref())))?);
        eprintln!(
            "  (EXTERNAL Grafana enforces its OWN auth — the console reverse-proxy forwards to \
             it but does NOT inject the in-stack X-WEBAUTH-USER identity. Configure auth on your Grafana.)"
        );
    }
    Ok(cfg)
}

/// The `&str` default for a prompt: the current value, or `""` when unset.
fn def(field: Option<&String>) -> &str {
    field.map(String::as_str).unwrap_or("")
}

/// `Some(s)` when non-empty after trimming, else `None` (mirrors `wizard::opt`).
fn opt(s: String) -> Option<String> {
    let t = s.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{OutputMode, ScriptedPrompter, Ui};

    fn plain_ui() -> Ui {
        Ui::new(OutputMode::Plain)
    }

    fn scripted(script: &str) -> ScriptedPrompter {
        ScriptedPrompter::new(std::io::Cursor::new(script.as_bytes().to_vec()))
    }

    // ── edit features: the EXISTING PUT route, the no-op invariant ──────────────

    #[test]
    fn parse_feature_flags_handles_envelope_and_bare_map_sorted() {
        let env = parse_feature_flags(r#"{"features":{"saml":true,"identities":false}}"#);
        assert_eq!(env, vec![("identities".into(), false), ("saml".into(), true)]);
        let bare = parse_feature_flags(r#"{"b":false,"a":true}"#);
        assert_eq!(bare, vec![("a".into(), true), ("b".into(), false)]);
        assert!(parse_feature_flags("not json").is_empty());
    }

    /// A toggled key issues EXACTLY one PUT with the right body to the right path —
    /// the EXISTING route `edit_features_calls_put_route` pins (CLI-09 apply path).
    #[tokio::test]
    async fn apply_feature_changes_issues_one_put_per_changed_key() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("PUT", "/api/console/features/saml")
            .match_header("authorization", "Api-Key k")
            .match_header("x-csrf-token", mockito::Matcher::Missing)
            .match_body(mockito::Matcher::Json(serde_json::json!({"enabled": true})))
            .with_status(200)
            .with_body(r#"{"key":"saml","enabled":true}"#)
            .expect(1)
            .create_async()
            .await;

        let client = ApiClient::new(&server.url(), Some("k")).unwrap();
        apply_feature_changes(&client, &[("saml".into(), true)], plain_ui())
            .await
            .expect("apply must succeed via the EXISTING PUT route");
        m.assert_async().await;
    }

    /// An EMPTY diff (a bare-Enter no-op) issues ZERO PUTs — the Req-2 no-op
    /// invariant. The mock is registered with `expect(0)` so any call fails the test.
    #[tokio::test]
    async fn apply_feature_changes_empty_diff_issues_zero_puts() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("PUT", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let client = ApiClient::new(&server.url(), Some("k")).unwrap();
        apply_feature_changes(&client, &[], plain_ui())
            .await
            .expect("an empty diff is a successful no-op");
        m.assert_async().await; // zero calls
    }

    /// `edit features` on a non-TTY (Plain) errors clearly and never constructs a
    /// widget — but only AFTER a reachable GET (the BLOCK-on-unreachable path is
    /// covered by `edit_features_get_failure_blocks`).
    #[tokio::test]
    async fn edit_features_non_tty_errors_without_hanging() {
        let mut server = mockito::Server::new_async().await;
        let _g = server
            .mock("GET", "/api/console/features")
            .with_status(200)
            .with_body(r#"{"saml":false,"identities":true}"#)
            .create_async()
            .await;
        // No PUT may ever be issued on the non-TTY error path.
        let no_put = server
            .mock("PUT", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let err = edit_features(&server.url(), Some("k"), plain_ui())
            .await
            .expect_err("Plain mode cannot run the MultiSelect");
        let msg = err.to_string();
        assert!(msg.contains("TTY"), "directs to a TTY/day-2 verb: {msg}");
        assert!(msg.contains("feature enable") || msg.contains("feature disable"), "{msg}");
        no_put.assert_async().await;
    }

    /// An unreachable backend BLOCKS before any apply — the GET failure surfaces a
    /// clear diagnostic and NO PUT is attempted.
    #[tokio::test]
    async fn edit_features_get_failure_blocks() {
        let mut server = mockito::Server::new_async().await;
        let _g = server
            .mock("GET", "/api/console/features")
            .with_status(503)
            .with_body("down")
            .create_async()
            .await;
        let no_put = server
            .mock("PUT", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let err = edit_features(&server.url(), Some("k"), plain_ui())
            .await
            .expect_err("an unreachable backend BLOCKS");
        // It is a backend error (not a panic / not a partial write).
        assert!(matches!(err, CliError::Backend(_)));
        no_put.assert_async().await;
    }

    // ── edit services: re-write ONLY .env + console.config.toml, no secret in toml ─

    /// `edit services` driven by a ScriptedPrompter re-writes ONLY the tempdir
    /// `.env` + `console.config.toml`; the emitted toml carries NO password/secret
    /// key (T-20-SECRET-ECHO) and no other path is written. Drives `repick_config`
    /// directly (the TTY gate is in `edit_via_repick`; the re-pick + write is the
    /// behavior under test).
    #[test]
    fn edit_services_repick_rewrites_only_env_and_toml_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("console.config.toml");
        let env_path = dir.path().join(".env");

        // Start from a known config on disk.
        let start = ConsoleConfig::all_in_stack_default();
        std::fs::write(&cfg_path, config_model::to_toml_string(&start).unwrap()).unwrap();

        // Re-pick: kratos → byo (admin URL), the rest Enter (keep), postgres Enter
        // (in-stack), observability Enter (off). Script per prompt in order:
        //   kratos mode = "byo" → admin URL → hydra Enter → keto Enter →
        //   oathkeeper Enter → polis Enter → postgres Enter → observability Enter.
        let script = "byo\n\
            https://kratos.ext/admin\n\
            \n\
            \n\
            \n\
            \n\
            \n\
            \n";
        let prompter = scripted(script);
        let new_cfg = repick_config(&prompter, &start).expect("re-pick");
        assert_eq!(new_cfg.mode_of("kratos"), ServiceMode::Byo, "kratos flipped to byo");
        assert_eq!(new_cfg.mode_of("hydra"), ServiceMode::InStack, "Enter kept hydra");

        // Re-write through the EXISTING writers (the same calls edit_via_repick makes).
        let toml = config_model::to_toml_string(&new_cfg).unwrap();
        wizard::write_config_out(cfg_path.to_str().unwrap(), &toml).unwrap();
        emit::emit_env_from_config(&new_cfg, env_path.to_str().unwrap()).unwrap();

        // The toml round-trips and carries NO secret key.
        let written_toml = std::fs::read_to_string(&cfg_path).unwrap();
        let lower = written_toml.to_ascii_lowercase();
        assert!(!lower.contains("password"), "no password in toml: {written_toml}");
        assert!(!lower.contains("secret"), "no secret in toml: {written_toml}");
        assert!(written_toml.contains("byo"), "the byo kratos mode is persisted");

        // The .env got the CONSOLE_SERVICE_* + the byo URL, no secret.
        let written_env = std::fs::read_to_string(&env_path).unwrap();
        assert!(written_env.contains("CONSOLE_SERVICE_KRATOS=byo"), "{written_env}");
        assert!(written_env.contains("KRATOS_ADMIN_URL=https://kratos.ext/admin"), "{written_env}");
        assert!(!written_env.to_ascii_lowercase().contains("polis_api_key"), "no secret: {written_env}");

        // No OTHER file was written into the tempdir.
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for name in &entries {
            assert!(
                name == "console.config.toml" || name == ".env",
                "unexpected file written: {name} (only .env + the toml are allowed)"
            );
        }
    }

    /// `edit services` on a non-TTY (Plain) errors clearly and writes NOTHING.
    #[test]
    fn edit_services_non_tty_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("console.config.toml");
        std::fs::write(&cfg_path, "[services.kratos]\nmode = \"in-stack\"\n").unwrap();

        let err = edit_services(Some(cfg_path.to_string_lossy().into_owned()), plain_ui())
            .expect_err("Plain mode cannot run the interactive re-pick");
        assert!(err.to_string().contains("TTY"), "directs to file-based edit: {err}");
        // Nothing new was written (only the fixture exists).
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "no .env or other file written on the error path");
    }
}
