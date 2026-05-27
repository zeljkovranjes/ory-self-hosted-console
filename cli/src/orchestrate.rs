//! HYBRID first-run orchestration (CLI-builder Wave 3 / HYBRID, FIRST-RUN).
//!
//! After the wizard has written `console.config.toml` + `.env` (+ generated
//! secrets), this module brings the operator to a working, login-ready console —
//! adapting to whether Docker is reachable from THIS process:
//!
//!   * HOST PATH (Docker reachable, not `--no-docker`):
//!       pre-boot BYO probes → `docker compose up -d --wait` (the host shell, the
//!       emitted COMPOSE_PROFILES) → post-boot in-stack probes → ONLINE feature
//!       apply (advanced flags) → first-run admin via `/setup` → optional
//!       SMTP/SMS/GitHub-OAuth guidance.
//!   * CONFIG-ONLY PATH (no Docker socket — INFRA-05 in-container, or `--no-docker`):
//!       pre-boot BYO probes ALWAYS run; the `compose up` + post-boot in-stack
//!       steps are SKIPPED and the EXACT day-2 ONLINE command sequence is printed
//!       for the operator to run once they bring the stack up themselves.
//!
//! SECURITY:
//!   * T-CB-C01: every docker/compose invocation is a FIXED argv `Vec` via
//!     `std::process::Command` — NO shell, NO string interpolation of operator
//!     input. COMPOSE_PROFILES is passed through the child's ENV, never spliced
//!     into a command line.
//!   * T-CB-C02: NO secret is ever placed on a docker/compose argv. Secrets live
//!     in the gitignored `.env` (read by compose itself) and the first-run admin
//!     password/token come from env/`--*-file`/prompt via `bootstrap::read_secret`.
//!   * T-CB-C04: pre-boot probes are GET-only; `up -d --wait` is non-destructive
//!     (no `down -v`); the admin + feature writes reuse the EXISTING validated
//!     single-writer routes — never a direct DB/YAML write.
//!   * T-CB-C05: a failed connection check BLOCKS (via `probe::should_block`)
//!     unless `--skip-checks`, and that choice is surfaced in the output.

use std::path::Path;
use std::process::Command;

use crate::config_model::{ConsoleConfig, ObservabilityMode, PostgresMode, ServiceMode, SERVICES};
use crate::db_probe::{self, DbCheckTarget, DEFAULT_DB_TIMEOUT};
use crate::probe::{self, ProbeResult, DEFAULT_PROBE_TIMEOUT};
use crate::{bootstrap, CliError, InitArgs};

/// True only when a Docker daemon is reachable from THIS process AND `--no-docker`
/// was not passed. We require BOTH the `docker` binary on PATH and a successful
/// `docker info` (a present binary with no reachable daemon — e.g. the
/// in-container INFRA-05 CLI with no socket — returns non-zero and degrades).
pub fn docker_available(args: &InitArgs) -> bool {
    if args.no_docker {
        return false;
    }
    // `docker info` exits 0 only when the daemon is actually reachable. A missing
    // binary surfaces as an Err from `output()`. Fixed argv, no shell.
    match Command::new("docker").arg("info").output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Orchestrate the post-write boot flow per the HYBRID model.
pub async fn orchestrate(
    config: &ConsoleConfig,
    args: &InitArgs,
    api_url: &str,
    api_key: Option<&str>,
) -> Result<(), CliError> {
    // PRE-BOOT (always): probe BYO/external services. In-stack services are NOT
    // probed here — their containers are not up yet (host path) or never come up
    // in this process (config-only path).
    preboot_byo_probes(config, args.skip_checks).await?;

    // PRE-BOOT DB check: when postgres is BYO the external DB is reachable NOW
    // (before any boot), so verify it with a REAL SELECT 1 and block-on-fail. For
    // in-stack postgres the container isn't up yet — that check is deferred to the
    // POST-BOOT step in host_path (mirrors the HTTP in-stack-vs-byo probe split).
    preboot_db_check(config, args.skip_checks).await?;

    if docker_available(args) {
        host_path(config, args, api_url, api_key).await
    } else {
        config_only_path(config, args);
        Ok(())
    }
}

/// PRE-BOOT: probe ONLY the `byo` services (reachable now, before any boot). A
/// failure BLOCKS unless `--skip-checks` (the choice is surfaced).
async fn preboot_byo_probes(config: &ConsoleConfig, skip_checks: bool) -> Result<(), CliError> {
    let byo: Vec<ProbeResult> = {
        let mut out = Vec::new();
        for svc in SERVICES {
            if config.mode_of(svc) == ServiceMode::Byo {
                if let Some(r) = probe::probe_service(svc, config, DEFAULT_PROBE_TIMEOUT).await {
                    out.push(r);
                }
            }
        }
        // BYO observability is an EXTERNAL Prometheus/Loki/Grafana — reachable now
        // (before any boot), so probe it here. In-stack observability comes up with
        // the profile and is probed post-boot (mirrors the Ory in-stack-vs-byo split).
        if config.observability_mode() == ObservabilityMode::Byo {
            if let Some(r) = probe::probe_observability(config, DEFAULT_PROBE_TIMEOUT).await {
                out.push(r);
            }
        }
        out
    };
    if byo.is_empty() {
        return Ok(());
    }
    eprintln!("pre-boot connection checks (BYO/external services):");
    report_probes(&byo);
    block_or_warn(&byo, skip_checks, "pre-boot")
}

/// PRE-BOOT DB check (BYO postgres only): the external DB is reachable now, so run
/// a REAL `SELECT 1` and block-on-fail. The superuser role (`POSTGRES_USER`, def
/// `ory`) + `POSTGRES_PASSWORD` (via `read_secret` — env/`--*-file`/prompt, never
/// argv) connect to the `postgres` default DB. In-stack postgres is skipped here
/// (its container is not up yet). On `--skip-checks` a missing password is a soft
/// skip (we cannot check without it) rather than a hard error.
async fn preboot_db_check(config: &ConsoleConfig, skip_checks: bool) -> Result<(), CliError> {
    if config.postgres_mode() != PostgresMode::Byo {
        return Ok(());
    }
    run_db_check(config, skip_checks, "pre-boot").await
}

/// POST-BOOT DB check (in-stack postgres only): the bundled container is up now, so
/// verify it with a REAL `SELECT 1` (same superuser path). BYO was already checked
/// pre-boot. Honors `--skip-checks` identically.
async fn postboot_db_check(config: &ConsoleConfig, skip_checks: bool) -> Result<(), CliError> {
    if config.postgres_mode() != PostgresMode::InStack {
        return Ok(());
    }
    run_db_check(config, skip_checks, "post-boot").await
}

/// Shared DB-check body: resolve the superuser target (+ password via read_secret),
/// run `db_probe::check`, and feed the result through the SAME block_or_warn policy
/// the HTTP probes use. A missing `POSTGRES_PASSWORD` is surfaced as a blocking
/// failure unless `--skip-checks` (then a soft skip with a warning).
async fn run_db_check(config: &ConsoleConfig, skip_checks: bool, phase: &str) -> Result<(), CliError> {
    // POSTGRES_USER defaults to `ory` (mirrors compose). The password comes from
    // read_secret — env/`--*-file`/prompt, NEVER argv. No `--*-file` flag exists on
    // InitArgs (the clap guard holds); env/prompt are the ingress here.
    let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "ory".to_string());
    let password = match bootstrap::read_secret(None, "POSTGRES_PASSWORD", "POSTGRES_PASSWORD") {
        Ok(p) => p,
        Err(e) => {
            if skip_checks {
                eprintln!(
                    "  WARNING: --skip-checks set — skipping the {phase} DB SELECT 1 check \
                     (no POSTGRES_PASSWORD available: {e})."
                );
                return Ok(());
            }
            return Err(CliError::Io(format!(
                "{phase} DB check needs POSTGRES_PASSWORD (set the env var or pass --skip-checks): {e}"
            )));
        }
    };

    // Connect as the superuser to the default `postgres` DB — a reachability +
    // auth verify that does not depend on any per-service role existing yet.
    let target = DbCheckTarget::from_config(config, &user, "postgres", password);
    eprintln!("{phase} DB connection check (SELECT 1): {}", target.display());
    let result = db_probe::check(&target, DEFAULT_DB_TIMEOUT).await;
    let probe = db_probe::as_probe_result(&result, phase);
    report_probes(std::slice::from_ref(&probe));
    block_or_warn(std::slice::from_ref(&probe), skip_checks, phase)
}

/// HOST PATH: compose up + post-boot in-stack probes + feature apply + first-run admin.
async fn host_path(
    config: &ConsoleConfig,
    args: &InitArgs,
    api_url: &str,
    api_key: Option<&str>,
) -> Result<(), CliError> {
    eprintln!("Docker is reachable — orchestrating the stack end-to-end.");

    // 1. `docker compose up -d --wait`. COMPOSE_PROFILES is read from the emitted
    //    .env by compose itself; we ALSO pass it through the child env explicitly
    //    so the selection is honored even if compose's .env loading is disabled.
    //    FIXED argv (T-CB-C01); the profile string is an ENV value, never argv.
    let profiles = config.to_compose_profiles().join(",");
    compose_up(&args.env_file, &profiles)?;

    // 2. POST-BOOT in-stack probes (now the containers are up). Block-on-fail.
    let in_stack: Vec<ProbeResult> = {
        let mut out = Vec::new();
        for svc in SERVICES {
            if config.mode_of(svc) == ServiceMode::InStack {
                if let Some(r) = probe::probe_service(svc, config, DEFAULT_PROBE_TIMEOUT).await {
                    out.push(r);
                }
            }
        }
        out
    };
    if !in_stack.is_empty() {
        eprintln!("post-boot connection checks (in-stack services):");
        report_probes(&in_stack);
        block_or_warn(&in_stack, args.skip_checks, "post-boot")?;
    }

    // POST-BOOT observability check (in-stack only): the bundled
    // Prometheus/Loki/Grafana containers are up now (the `observability` profile),
    // so verify their readiness. BYO observability was already checked pre-boot.
    if config.observability_mode() == ObservabilityMode::InStack {
        if let Some(r) = probe::probe_observability(config, DEFAULT_PROBE_TIMEOUT).await {
            eprintln!("post-boot observability check (in-stack Prometheus/Loki/Grafana):");
            report_probes(std::slice::from_ref(&r));
            block_or_warn(std::slice::from_ref(&r), args.skip_checks, "post-boot")?;
        }
    }

    // POST-BOOT DB check: the in-stack postgres container is up now → verify it
    // with a REAL SELECT 1 (BYO postgres was already checked pre-boot).
    postboot_db_check(config, args.skip_checks).await?;

    // 3. APPLY the advanced feature set via the EXISTING ONLINE route. The Plan-A
    //    boot reconcile already seeds the service-domain flags from CONSOLE_SERVICE_*;
    //    this layer applies the operator's advanced on/off choices on top. Requires
    //    an api key — for a brand-new stack the operator mints one AFTER /setup, so
    //    when no key is available we DEFER the apply to the printed day-2 sequence.
    apply_advanced_features(config, api_url, api_key).await;

    // 4. First-run admin via the single-writer /setup route. Password + bootstrap
    //    token come from env/`--*-file`/prompt (read_secret) — never argv. We
    //    GUIDE rather than force: if the inputs are not present we print the exact
    //    command instead of failing the whole orchestration.
    first_run_admin_guidance(api_url);

    // 5. OPTIONAL SMTP/SMS/GitHub-OAuth — surfaced as day-2 steps over the existing
    //    commands (no new endpoints invented).
    print_optional_steps(&args.env_file);

    eprintln!("\nStack is up. Complete the first-run admin at /setup, then mint an API key for ONLINE day-2 commands.");
    Ok(())
}

/// CONFIG-ONLY PATH (INFRA-05 / `--no-docker`): skip compose + post-boot, print the
/// exact day-2 ONLINE command sequence the operator runs after bringing the stack
/// up themselves.
fn config_only_path(config: &ConsoleConfig, args: &InitArgs) {
    eprintln!(
        "\nDocker is NOT reachable from here (in-container INFRA-05, or --no-docker) — \
         config-only mode."
    );
    eprintln!(
        "Wrote {} + {} (incl. generated secrets). Bring the stack up on the host, then run the day-2 steps below.",
        args.config_out, args.env_file
    );
    eprintln!("\nDay-1 (host shell, where Docker IS available):");
    eprintln!("  COMPOSE_PROFILES=$(grep '^COMPOSE_PROFILES=' {} | cut -d= -f2) \\", args.env_file);
    eprintln!("    docker compose up -d --wait");

    eprintln!("\nDay-2 (ONLINE — after /setup mints your console + an API key):");
    eprintln!("  # first-run admin (single-writer /setup; password+token via env/--*-file/prompt):");
    eprintln!("  CONSOLE_ADMIN_PASSWORD=… CONSOLE_BOOTSTRAP_TOKEN=… \\");
    eprintln!("    ory-console admin create --via-setup --email you@example.com --name 'You'");

    let advanced = advanced_to_apply(config);
    if !advanced.is_empty() {
        eprintln!("  # apply the advanced feature choices (CONSOLE_API_KEY set):");
        for (key, on) in advanced {
            let verb = if on { "enable" } else { "disable" };
            eprintln!("  ory-console feature {verb} {key}");
        }
    }
    eprintln!("  # optional SMTP/SMS/GitHub-OAuth: see `ory-console oauth github set --help` + the courier config pages.");
}

/// Run `docker compose up -d --wait` with a FIXED argv and COMPOSE_PROFILES passed
/// via the child ENV (never spliced into the command line — T-CB-C01). `--env-file`
/// points compose at the gitignored `.env` the wizard just wrote. NO secret on argv.
fn compose_up(env_file: &str, profiles: &str) -> Result<(), CliError> {
    eprintln!("running: docker compose --env-file {env_file} up -d --wait  (COMPOSE_PROFILES={profiles})");
    let status = Command::new("docker")
        .args(["compose", "--env-file", env_file, "up", "-d", "--wait"])
        // COMPOSE_PROFILES via env, NOT argv — and never a secret.
        .env("COMPOSE_PROFILES", profiles)
        .status()
        .map_err(|e| CliError::Io(format!("spawning docker compose: {e}")))?;
    if !status.success() {
        return Err(CliError::Io(format!(
            "`docker compose up -d --wait` exited with {status}. Inspect `docker compose ps` / logs, \
             fix the failing service, and re-run `ory-console init` (or pass --skip-checks)."
        )));
    }
    Ok(())
}

/// The operator's advanced feature on/off choices (the keys orchestration applies
/// on top of the Plan-A boot reconcile). Only the advanced (opt-in) keys are
/// surfaced — the ON-by-default service flags are seeded by the reconcile.
fn advanced_to_apply(config: &ConsoleConfig) -> Vec<(String, bool)> {
    let feats = config.effective_features();
    ["saml", "organizations", "observability", "event_streams"]
        .iter()
        .filter_map(|k| feats.0.get(*k).map(|on| (k.to_string(), *on)))
        .collect()
}

/// APPLY the advanced feature flags via the EXISTING ONLINE route (`PUT
/// /api/console/features/{key}`). Best-effort: a missing api key (brand-new stack,
/// no key minted yet) DEFERS to the printed day-2 sequence rather than failing.
async fn apply_advanced_features(config: &ConsoleConfig, api_url: &str, api_key: Option<&str>) {
    let advanced = advanced_to_apply(config);
    if advanced.is_empty() {
        return;
    }
    let client = match crate::client::ApiClient::new(api_url, api_key) {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "(no CONSOLE_API_KEY yet — deferring the advanced feature apply to day-2: \
                 mint a key after /setup, then `ory-console feature enable|disable <key>`)"
            );
            return;
        }
    };
    for (key, on) in advanced {
        let action = if on {
            crate::FeatureAction::Enable { key: key.clone() }
        } else {
            crate::FeatureAction::Disable { key: key.clone() }
        };
        match crate::online::feature(&client, action).await {
            Ok(()) => eprintln!("  applied feature {key} = {on}"),
            Err(e) => eprintln!("  (could not apply feature {key}: {e} — apply it day-2)"),
        }
    }
}

/// Print the first-run admin step (single-writer /setup via the existing command).
/// Secrets stay on env/`--*-file`/prompt — we never collect them on argv here.
fn first_run_admin_guidance(api_url: &str) {
    eprintln!("\nFirst-run admin (single-writer /setup):");
    eprintln!(
        "  CONSOLE_ADMIN_PASSWORD=… CONSOLE_BOOTSTRAP_TOKEN=… \\\n    \
         ory-console --api-url {api_url} admin create --via-setup --email you@example.com --name 'You'"
    );
    eprintln!("  (password + bootstrap token via env / --password-file / --token-file / prompt — never argv)");
}

/// Surface the OPTIONAL post-boot steps over the EXISTING commands (no new routes).
fn print_optional_steps(env_file: &str) {
    eprintln!("\nOptional setup (run when you want them):");
    eprintln!(
        "  GitHub login OAuth:  GITHUB_OAUTH_CLIENT_SECRET=… ory-console oauth github set --client-id … --env-file {env_file}"
    );
    eprintln!("  SMTP / SMS courier:  configure via the courier config pages (the existing config-edit ONLINE path).");
}

/// Print every probe result line (secret-free).
fn report_probes(results: &[ProbeResult]) {
    for r in results {
        let mark = if r.ok { "ok  " } else { "FAIL" };
        eprintln!("  [{mark}] {}: {}", r.service, r.status_or_error);
        if !r.ok && !r.hint.is_empty() {
            eprintln!("         hint: {}", r.hint);
        }
    }
}

/// Apply the BLOCK-on-failure policy: a failure STOPS unless `--skip-checks`, in
/// which case the override is surfaced loudly. `phase` labels the diagnostic.
fn block_or_warn(results: &[ProbeResult], skip_checks: bool, phase: &str) -> Result<(), CliError> {
    match probe::should_block(results, skip_checks) {
        Some(failures) => {
            let names: Vec<&str> = failures.iter().map(|r| r.service.as_str()).collect();
            Err(CliError::Io(format!(
                "{phase} connection check FAILED for: {}. Fix the URL(s)/container(s) and re-run, \
                 or pass --skip-checks to proceed anyway.",
                names.join(", ")
            )))
        }
        None => {
            if skip_checks && results.iter().any(|r| !r.ok) {
                eprintln!(
                    "  WARNING: --skip-checks set — proceeding past {phase} connection failures."
                );
            }
            Ok(())
        }
    }
}

/// (Defense-in-depth) reject a compose env-file path that does not look like a
/// gitignored `.env` — mirrors the bootstrap writer's discipline so orchestration
/// can't be pointed at an unexpected file. Currently advisory (compose reads it),
/// reused by tests.
#[allow(dead_code)]
fn looks_like_env_file(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    name == ".env" || name.starts_with(".env.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_model::parse_config;

    #[test]
    fn no_docker_forces_unavailable() {
        let args = InitArgs {
            no_docker: true,
            ..Default::default()
        };
        assert!(!docker_available(&args), "--no-docker forces config-only");
    }

    #[test]
    fn advanced_to_apply_lists_only_advanced_keys() {
        let cfg = parse_config(
            r#"
[observability]
mode = "byo"
prometheus_url = "https://p.ext"
[features]
saml = true
organizations = false
"#,
        )
        .unwrap();
        let adv = advanced_to_apply(&cfg);
        let map: std::collections::HashMap<_, _> = adv.into_iter().collect();
        assert_eq!(map.get("saml"), Some(&true));
        // observability is DERIVED from the byo mode (not the [features] table).
        assert_eq!(map.get("observability"), Some(&true));
        assert_eq!(map.get("organizations"), Some(&false));
        assert_eq!(map.get("event_streams"), Some(&false), "default OFF");
        // No ON-by-default service flag leaks into the advanced apply set.
        assert!(!map.contains_key("identities"));
        assert!(!map.contains_key("oauth2"));
    }

    #[test]
    fn block_or_warn_blocks_on_failure_then_passes_with_skip() {
        let bad = ProbeResult {
            service: "hydra".into(),
            url: "u".into(),
            ok: false,
            status_or_error: "503".into(),
            hint: "fix".into(),
        };
        // default → block.
        assert!(block_or_warn(&[bad.clone()], false, "pre-boot").is_err());
        // --skip-checks → proceed (Ok).
        assert!(block_or_warn(&[bad], true, "pre-boot").is_ok());
        // all-ok → proceed.
        let ok = ProbeResult {
            service: "kratos".into(),
            url: "u".into(),
            ok: true,
            status_or_error: "200".into(),
            hint: String::new(),
        };
        assert!(block_or_warn(&[ok], false, "post-boot").is_ok());
    }

    #[test]
    fn env_file_recognition() {
        assert!(looks_like_env_file(".env"));
        assert!(looks_like_env_file("/app/.env"));
        assert!(looks_like_env_file(".env.local"));
        assert!(!looks_like_env_file("config/kratos.yml"));
    }
}
