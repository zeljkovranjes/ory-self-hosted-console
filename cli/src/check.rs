//! READ-ONLY `check` command group (CLI-08).
//!
//! `check status`/`services`/`config`/`features` inspect stack health, configured
//! modes, config validity, and effective feature flags by REUSING the existing
//! probe/db_probe/online/config_model paths — writing absolutely NOTHING. There is
//! no `bootstrap::upsert_env`, no config write, no PUT/POST, no DB write anywhere
//! in this module: it issues only readiness GETs (probes), a `SELECT 1` DB poke,
//! an ONLINE `GET /api/console/features`, and `console.config.toml` / `.env`
//! PARSING. The read-only / no-second-writer invariant (T-20-WRITE) therefore
//! holds BY CONSTRUCTION, and the `check_is_read_only_no_mtime_change` test is the
//! falsifiable mtime guard.
//!
//! The PURE verdict core [`overall_exit_code`] maps a set of [`ProbeResult`]s to a
//! process exit code (`0` iff every result is ok; `1` when any failed). `check
//! status`/`services` compute it and, on a non-zero verdict, return
//! [`CliError::CheckFailed`] which `main` maps to that exit code VERBATIM — so the
//! command is scriptable in BOTH Rich and Plain modes.
//!
//! INFRA-05 degradation: when no Docker daemon is reachable, in-stack reachability
//! rows that would require the daemon to be UP are rendered as `skipped (no
//! docker)` and do NOT count as failures — ONLINE/HTTP reachability + config
//! validation still run and still drive the verdict.

use crate::config_model::{self, ConsoleConfig, ServiceMode, SERVICES};
use crate::probe::{self, ProbeResult};
use crate::ui::Ui;
use crate::{CheckAction, CliError, InitArgs};

/// The default `console.config.toml` path resolved when no `--config` is given.
const DEFAULT_CONFIG_PATH: &str = "console.config.toml";
/// The default `.env` path inspected by `check config` for required-key presence.
const DEFAULT_ENV_PATH: &str = ".env";

/// The PURE verdict core (CLI-08b): `0` iff EVERY result is `ok`, `1` if ANY
/// failed. Reuses the [`probe::should_block`]-style "any failure → block"
/// semantics (with `skip_checks = false`, since a verdict never skips). An EMPTY
/// slice is vacuously healthy → `0` (nothing selected/expected can fail).
///
/// This is what `check status`/`services` map onto the process exit code; it is
/// deterministic and the `check_exit_code_reflects_health` Wave-0 test pins it.
pub fn overall_exit_code(results: &[ProbeResult]) -> i32 {
    if probe::should_block(results, false).is_some() {
        1
    } else {
        0
    }
}

/// True only when a Docker daemon is reachable from THIS process (the INFRA-05
/// detector). A `check` run never passes `--no-docker`, so we reuse
/// [`crate::orchestrate::docker_available`] with default [`InitArgs`]. When the
/// daemon is NOT reachable, in-stack readiness rows degrade to `skipped (no
/// docker)` instead of failing the verdict.
fn docker_reachable() -> bool {
    crate::orchestrate::docker_available(&InitArgs::default())
}

/// A `skipped (no docker)` row for an in-stack service whose container the daemon
/// would have to be running for — it is `ok = true` so it does NOT drag the
/// verdict to non-zero (INFRA-05), and its status text names the reason.
fn skipped_no_docker_row(service: &str) -> ProbeResult {
    ProbeResult {
        service: service.to_string(),
        url: String::new(),
        ok: true,
        status_or_error: "skipped (no docker)".to_string(),
        hint: String::new(),
    }
}

/// Render a per-service `service | configured mode | health` table from a config +
/// a set of probe results (keyed by service name), and return the verdict slice
/// (the probe results that DRIVE [`overall_exit_code`]). The configured-mode column
/// comes from the config; the health column from the matching probe result (or
/// `not probed` when a service has no row, e.g. an `off` service).
fn render_status_table(config: &ConsoleConfig, results: &[ProbeResult], ui: Ui) {
    let seed = config.to_service_seed();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for svc in SERVICES {
        let mode = seed
            .get(svc)
            .map(|m| match m {
                ServiceMode::InStack => "in-stack",
                ServiceMode::Byo => "byo",
                ServiceMode::Off => "off",
            })
            .unwrap_or("in-stack");
        let health = match results.iter().find(|r| r.service == svc) {
            Some(r) if r.ok => r.status_or_error.clone(),
            Some(r) => format!("UNREACHABLE — {}", r.status_or_error),
            None => "not probed (off)".to_string(),
        };
        rows.push(vec![svc.to_string(), mode.to_string(), health]);
    }
    // Any extra synthetic rows (observability / postgres) that are not in SERVICES.
    for r in results {
        if SERVICES.contains(&r.service.as_str()) {
            continue;
        }
        let health = if r.ok {
            r.status_or_error.clone()
        } else {
            format!("UNREACHABLE — {}", r.status_or_error)
        };
        rows.push(vec![r.service.clone(), "—".to_string(), health]);
    }
    ui.table(&["service", "configured mode", "health"], &rows);
}

/// Probe reachability for every non-`off` service + observability, degrading
/// in-stack rows to `skipped (no docker)` when no daemon is reachable (INFRA-05).
/// Returns the verdict slice — the results that DRIVE [`overall_exit_code`].
///
/// Read-only: every call here is a single readiness GET (redirects off, short
/// timeout) or — for postgres, only when a password is resolvable WITHOUT
/// prompting — a `SELECT 1`. NOTHING is written.
async fn gather_reachability(config: &ConsoleConfig, ui: Ui) -> Vec<ProbeResult> {
    let docker_up = docker_reachable();
    let sp = ui.spinner("probing services…");
    let mut results: Vec<ProbeResult> = Vec::new();

    // HTTP readiness for every non-off service. An in-stack service whose container
    // is only reachable when the daemon is up degrades to `skipped (no docker)`
    // (INFRA-05) — a byo service points at an EXTERNAL URL, so it is always probed
    // (its reachability does not depend on the local Docker daemon).
    for svc in SERVICES {
        let mode = config.mode_of(svc);
        if mode == ServiceMode::Off {
            continue;
        }
        if mode == ServiceMode::InStack && !docker_up {
            results.push(skipped_no_docker_row(svc));
            continue;
        }
        if let Some(r) = probe::probe_service(svc, config, probe::DEFAULT_PROBE_TIMEOUT).await {
            results.push(r);
        }
    }

    // Observability (Prometheus/Loki/Grafana) — same in-stack/no-docker degradation.
    if config.observability_mode() != config_model::ObservabilityMode::Off {
        let in_stack = config.observability_mode() == config_model::ObservabilityMode::InStack;
        if in_stack && !docker_up {
            results.push(skipped_no_docker_row("observability"));
        } else if let Some(r) =
            probe::probe_observability(config, probe::DEFAULT_PROBE_TIMEOUT).await
        {
            results.push(r);
        }
    }

    sp.finish_ok("probes complete");
    results
}

/// Print the overall verdict line (a green ✓ when healthy, a red ✗ + the failing
/// services when not) and return the non-zero process exit code via
/// [`CliError::CheckFailed`] when unhealthy. A healthy verdict returns `Ok(())`.
fn finish_verdict(results: &[ProbeResult], ui: Ui) -> Result<(), CliError> {
    let code = overall_exit_code(results);
    if code == 0 {
        ui.status_ok("all selected checks healthy");
        Ok(())
    } else {
        let failing: Vec<&str> = results
            .iter()
            .filter(|r| !r.ok)
            .map(|r| r.service.as_str())
            .collect();
        ui.status_err(&format!("unhealthy: {}", failing.join(", ")));
        Err(CliError::CheckFailed(code))
    }
}

/// Dispatch a `check` action. READ-ONLY: writes NOTHING (T-20-WRITE).
pub async fn run_check(
    action: CheckAction,
    api_url: &str,
    api_key: Option<&str>,
    ui: Ui,
) -> Result<(), CliError> {
    match action {
        CheckAction::Status => check_status(ui).await,
        CheckAction::Services => check_services(ui).await,
        CheckAction::Config { config } => check_config(config, ui),
        CheckAction::Features => check_features(api_url, api_key, ui).await,
    }
}

/// Load the config from the default `console.config.toml` path when present; else
/// fall back to the all-in-stack default with a warning. READ-ONLY (parse only).
fn load_config_or_default(ui: Ui) -> ConsoleConfig {
    match config_model::load_config(DEFAULT_CONFIG_PATH) {
        Ok(cfg) => cfg,
        Err(_) => {
            ui.status_warn(&format!(
                "no readable {DEFAULT_CONFIG_PATH} — assuming all-in-stack defaults for this inspection"
            ));
            ConsoleConfig::all_in_stack_default()
        }
    }
}

/// `check status` — per-service health/mode table + overall verdict; the process
/// exit code reflects health (CLI-08b).
async fn check_status(ui: Ui) -> Result<(), CliError> {
    ui.heading("check status");
    let config = load_config_or_default(ui);
    let results = gather_reachability(&config, ui).await;
    render_status_table(&config, &results, ui);
    finish_verdict(&results, ui)
}

/// `check services` — configured mode (in-stack/byo/off) + per-service
/// reachability table; same verdict/exit-code rule as `check status`.
async fn check_services(ui: Ui) -> Result<(), CliError> {
    ui.heading("check services");
    let config = load_config_or_default(ui);
    let results = gather_reachability(&config, ui).await;
    render_status_table(&config, &results, ui);
    finish_verdict(&results, ui)
}

/// `check config` — validate `console.config.toml` shape (clear ✓/✗ on parse) +
/// report `.env` required-key PRESENCE/shape WITHOUT printing any secret value
/// (only `present`/`missing`/`empty`). An invalid config or a missing required key
/// yields a non-zero verdict. READ-ONLY (parse + presence scan only).
fn check_config(config_arg: Option<String>, ui: Ui) -> Result<(), CliError> {
    ui.heading("check config");
    let path = config_arg.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string());

    // 1. Validate the console.config.toml shape (parse only — never written back).
    let config = match config_model::load_config(&path) {
        Ok(cfg) => {
            ui.status_ok(&format!("{path} is valid"));
            cfg
        }
        Err(e) => {
            // A parse / read error is a non-zero verdict. The message is already
            // clear + secret-free (the model has no secret fields).
            ui.status_err(&format!("{path} is invalid: {e}"));
            return Err(CliError::CheckFailed(1));
        }
    };

    // 2. Report `.env` required-key PRESENCE/shape — NEVER a secret value. The
    //    required-key set mirrors `wizard::generate_missing_secrets`: always
    //    POSTGRES_PASSWORD, plus HYDRA_SECRETS_SYSTEM (hydra in-stack) and the two
    //    Polis secrets (polis in-stack).
    let required = required_env_keys(&config);
    let presence = scan_env_key_presence(DEFAULT_ENV_PATH, &required);

    let rows: Vec<Vec<String>> = presence
        .iter()
        .map(|(key, state)| vec![key.clone(), state.label().to_string()])
        .collect();
    ui.table(&["required .env key", "presence"], &rows);

    let any_missing = presence.iter().any(|(_, s)| *s != KeyPresence::Present);
    if any_missing {
        let bad: Vec<&str> = presence
            .iter()
            .filter(|(_, s)| *s != KeyPresence::Present)
            .map(|(k, _)| k.as_str())
            .collect();
        ui.status_err(&format!(
            "missing/empty required .env key(s): {} (set them via env / a --*-file at run time)",
            bad.join(", ")
        ));
        return Err(CliError::CheckFailed(1));
    }
    ui.status_ok(&format!("all required .env keys present in {DEFAULT_ENV_PATH}"));
    Ok(())
}

/// The required `.env` key set for a config (mirrors
/// `wizard::generate_missing_secrets`'s required-always + per-in-stack-service
/// set). These are SECRET keys whose VALUE is never printed — only their presence.
fn required_env_keys(config: &ConsoleConfig) -> Vec<String> {
    let mut keys: Vec<String> = vec!["POSTGRES_PASSWORD".to_string()];
    if config.mode_of("hydra") == ServiceMode::InStack {
        keys.push("HYDRA_SECRETS_SYSTEM".to_string());
    }
    if config.mode_of("polis") == ServiceMode::InStack {
        keys.push("POLIS_CLIENT_SECRET_VERIFY".to_string());
        keys.push("POLIS_DB_ENCRYPTION_KEY".to_string());
    }
    keys
}

/// The per-key presence verdict for the `.env` scan. NEVER carries the value —
/// only whether the key is present-with-a-value, present-but-empty, or missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyPresence {
    /// The key exists with a non-empty value (we do NOT inspect the value).
    Present,
    /// The key line exists but its value is empty.
    Empty,
    /// The key is absent from the `.env` file.
    Missing,
}

impl KeyPresence {
    fn label(self) -> &'static str {
        match self {
            KeyPresence::Present => "present",
            KeyPresence::Empty => "empty",
            KeyPresence::Missing => "missing",
        }
    }
}

/// Scan an `.env` file for each required key's PRESENCE only. Reads the file
/// (read-only) and classifies each key as present (non-empty value) / empty
/// (key with no value) / missing. The VALUE is NEVER captured into the result —
/// only the [`KeyPresence`] classification (T-20-SECRET-ECHO). A missing/unreadable
/// `.env` file classifies every required key as `Missing`.
fn scan_env_key_presence(env_path: &str, required: &[String]) -> Vec<(String, KeyPresence)> {
    // Build a set of keys that are present-with-a-value vs present-but-empty.
    let mut nonempty: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut empty: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(env_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                if v.trim().is_empty() {
                    empty.insert(key);
                } else {
                    // Only the KEY is recorded — the value is dropped here.
                    nonempty.insert(key);
                }
            }
        }
    }
    required
        .iter()
        .map(|k| {
            let state = if nonempty.contains(k) {
                KeyPresence::Present
            } else if empty.contains(k) {
                KeyPresence::Empty
            } else {
                KeyPresence::Missing
            };
            (k.clone(), state)
        })
        .collect()
}

/// `check features` — render the current EFFECTIVE feature flags from the ONLINE
/// `GET /api/console/features`. An unreachable backend / missing key is reported
/// clearly (no hang, no prompt). A features check is EXPLICITLY requested, so an
/// unreachable backend is a non-zero verdict (the "selected/expected" rule —
/// documented in the SUMMARY).
async fn check_features(api_url: &str, api_key: Option<&str>, ui: Ui) -> Result<(), CliError> {
    ui.heading("check features");
    // Build the ONLINE client. A missing api key is reported as a non-zero verdict
    // (the features check was explicitly requested but cannot run).
    let client = match crate::client::ApiClient::new(api_url, api_key) {
        Ok(c) => c,
        Err(e) => {
            ui.status_err(&format!("cannot check features: {e}"));
            return Err(CliError::CheckFailed(1));
        }
    };
    let sp = ui.spinner("fetching effective feature flags…");
    let body = match client.get("/api/console/features").await {
        Ok(b) => {
            sp.finish_ok("fetched");
            b
        }
        Err(e) => {
            sp.finish_err("unreachable");
            ui.status_err(&format!("backend unreachable / features unavailable: {e}"));
            return Err(CliError::CheckFailed(1));
        }
    };
    render_features_table(&body, ui);
    Ok(())
}

/// Render the effective feature flags as a `feature | enabled` table (✓/✗ glyph in
/// the CELL only — never a control string; T-20-ANSI). Tolerates a top-level
/// `{"features": {k: bool}}` envelope or a bare `{k: bool}` map; an unparseable
/// body is printed verbatim (still no ui-added color).
fn render_features_table(body: &str, ui: Ui) {
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
            // WR-05: distinguish a non-bool value from `false`. A key the backend
            // returned with a non-bool shape renders as `?` (unknown) — never a
            // misleading `✗` — and the coercion is logged. Only a genuine JSON
            // bool drives the ✓/✗ glyph.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_model::parse_config;

    fn pr(service: &str, ok: bool) -> ProbeResult {
        ProbeResult {
            service: service.to_string(),
            url: "u".to_string(),
            ok,
            status_or_error: if ok { "200".into() } else { "503".into() },
            hint: String::new(),
        }
    }

    // ── overall_exit_code (the LOCKED Wave-0 verdict contract) ──────────────────

    #[test]
    fn overall_exit_code_empty_is_zero() {
        // Vacuously healthy: nothing selected/expected can fail.
        assert_eq!(overall_exit_code(&[]), 0);
    }

    #[test]
    fn overall_exit_code_all_ok_is_zero() {
        assert_eq!(overall_exit_code(&[pr("kratos", true), pr("hydra", true)]), 0);
    }

    #[test]
    fn overall_exit_code_any_failure_is_nonzero() {
        let code = overall_exit_code(&[pr("kratos", true), pr("hydra", false)]);
        assert_ne!(code, 0, "one failure → non-zero");
        assert_eq!(code, 1, "the verdict code is 1");
    }

    #[test]
    fn overall_exit_code_skipped_no_docker_row_is_not_a_failure() {
        // An INFRA-05 `skipped (no docker)` row is ok=true → it never drags the
        // verdict to non-zero, even when it is the only row.
        let skipped = skipped_no_docker_row("kratos");
        assert!(skipped.ok, "a skipped row is ok=true");
        assert_eq!(overall_exit_code(std::slice::from_ref(&skipped)), 0);
        // Mixed with a real failure → still non-zero (the failure drives it).
        assert_eq!(overall_exit_code(&[skipped, pr("hydra", false)]), 1);
    }

    // ── finish_verdict maps the verdict onto Ok / CheckFailed ───────────────────

    #[test]
    fn finish_verdict_ok_when_all_healthy() {
        let ui = Ui::new(crate::ui::OutputMode::Plain);
        assert!(finish_verdict(&[pr("kratos", true)], ui).is_ok());
    }

    #[test]
    fn finish_verdict_check_failed_when_unhealthy() {
        let ui = Ui::new(crate::ui::OutputMode::Plain);
        match finish_verdict(&[pr("kratos", false)], ui) {
            Err(CliError::CheckFailed(code)) => assert_eq!(code, 1),
            other => panic!("expected CheckFailed(1), got {other:?}"),
        }
    }

    // ── required_env_keys mirrors generate_missing_secrets ──────────────────────

    #[test]
    fn required_env_keys_in_stack_includes_hydra_and_polis_secrets() {
        let cfg = ConsoleConfig::all_in_stack_default();
        let keys = required_env_keys(&cfg);
        assert!(keys.contains(&"POSTGRES_PASSWORD".to_string()));
        assert!(keys.contains(&"HYDRA_SECRETS_SYSTEM".to_string()));
        assert!(keys.contains(&"POLIS_CLIENT_SECRET_VERIFY".to_string()));
        assert!(keys.contains(&"POLIS_DB_ENCRYPTION_KEY".to_string()));
    }

    #[test]
    fn required_env_keys_byo_hydra_drops_hydra_secret() {
        let cfg = parse_config(
            r#"
[services.hydra]
mode = "byo"
[services.polis]
mode = "off"
"#,
        )
        .unwrap();
        let keys = required_env_keys(&cfg);
        assert!(keys.contains(&"POSTGRES_PASSWORD".to_string()));
        assert!(
            !keys.contains(&"HYDRA_SECRETS_SYSTEM".to_string()),
            "byo hydra needs no in-stack system secret"
        );
        assert!(
            !keys.contains(&"POLIS_CLIENT_SECRET_VERIFY".to_string()),
            "off polis needs no polis secret"
        );
    }

    // ── scan_env_key_presence classifies presence WITHOUT capturing the value ───

    #[test]
    fn scan_env_classifies_present_empty_missing() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "POSTGRES_PASSWORD=super-secret-value\nHYDRA_SECRETS_SYSTEM=\n# a comment\n",
        )
        .unwrap();
        let required = vec![
            "POSTGRES_PASSWORD".to_string(),
            "HYDRA_SECRETS_SYSTEM".to_string(),
            "POLIS_DB_ENCRYPTION_KEY".to_string(),
        ];
        let presence: std::collections::HashMap<_, _> =
            scan_env_key_presence(env_path.to_str().unwrap(), &required)
                .into_iter()
                .collect();
        assert_eq!(presence.get("POSTGRES_PASSWORD"), Some(&KeyPresence::Present));
        assert_eq!(presence.get("HYDRA_SECRETS_SYSTEM"), Some(&KeyPresence::Empty));
        assert_eq!(presence.get("POLIS_DB_ENCRYPTION_KEY"), Some(&KeyPresence::Missing));
    }

    #[test]
    fn scan_env_never_returns_the_secret_value() {
        // T-20-SECRET-ECHO: the scan classifies presence only; the secret VALUE is
        // never carried in the result (the result is a presence enum, not a value).
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "POSTGRES_PASSWORD=LEAK_CANARY_98765\n").unwrap();
        let required = vec!["POSTGRES_PASSWORD".to_string()];
        let result = scan_env_key_presence(env_path.to_str().unwrap(), &required);
        // Render the entire result via Debug and assert the canary never appears.
        let dbg = format!("{result:?}");
        assert!(
            !dbg.contains("LEAK_CANARY_98765"),
            "the presence scan must never carry the secret value: {dbg}"
        );
        assert_eq!(result[0].1, KeyPresence::Present);
    }

    #[test]
    fn scan_env_missing_file_is_all_missing() {
        let required = vec!["POSTGRES_PASSWORD".to_string()];
        let result =
            scan_env_key_presence("/definitely/not/a/real/.env/path-xyz", &required);
        assert_eq!(result[0].1, KeyPresence::Missing);
    }

    // ── check_config end-to-end: valid + invalid (read-only, no panic) ──────────

    #[test]
    fn check_config_invalid_toml_is_check_failed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("console.config.toml");
        std::fs::write(&cfg_path, "[services.kratos]\nmode = \"nonsense\"\n").unwrap();
        let ui = Ui::new(crate::ui::OutputMode::Plain);
        match check_config(Some(cfg_path.to_string_lossy().into_owned()), ui) {
            Err(CliError::CheckFailed(1)) => {}
            other => panic!("invalid config must be CheckFailed(1), got {other:?}"),
        }
    }

    #[test]
    fn render_features_table_handles_envelope_and_bare_map() {
        // Just assert neither shape panics (rendering goes to stdout).
        let ui = Ui::new(crate::ui::OutputMode::Plain);
        render_features_table(r#"{"features":{"saml":true,"identities":false}}"#, ui);
        render_features_table(r#"{"saml":false}"#, ui);
        render_features_table("not json", ui);
    }
}
