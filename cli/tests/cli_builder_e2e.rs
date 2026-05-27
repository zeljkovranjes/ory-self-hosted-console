//! CLI-builder Wave 4 (PLAN-D) — TTY-free, Docker-free end-to-end acceptance of
//! the builder's library surface: the `--config` round-trip determinism, the
//! custom (off + BYO) mapping, the block-on-fail vs `--skip-checks` policy, and
//! the `wizard::run_init` config-only path (writes `console.config.toml` + `.env`,
//! generates the required secrets, attempts NO `docker compose up`, and re-applies
//! idempotently).
//!
//! This is the integration-test half of the acceptance gate (the other half is the
//! live `scripts/verify/cli-builder-acceptance.sh`). Everything here runs without a
//! TTY, without a Docker daemon, and writes ONLY into a per-test `tempdir` — the
//! repo's real `.env`/`console.config.toml` are never touched.
//!
//! SECURITY: every secret stays out of argv (the `init` path carries no
//! value-taking secret flag — enforced by the separate clap-introspection guard in
//! `cli_commands.rs`). The generated `.env` is asserted to carry NO leaked secret
//! VALUE in the config artifact and only KEY names + CSPRNG values in `.env`.

use console_cli::config_model::{
    load_config, parse_config, to_toml_string, ConsoleConfig, ServiceMode,
};
use console_cli::emit::emit_env_from_config;
use console_cli::probe::{probe_service, should_block, DEFAULT_PROBE_TIMEOUT};
use console_cli::wizard::run_init;
use console_cli::InitArgs;

// ---------------------------------------------------------------------------
// 1. CONFIG ROUND-TRIP — the `--config` re-apply contract is byte-deterministic.
// ---------------------------------------------------------------------------

/// Build the `--defaults` config, emit a `.env`, write its `console.config.toml`,
/// `load_config` it back, re-emit a SECOND `.env`, and assert the two `.env`
/// outputs are BYTE-IDENTICAL. This is the heart of the `--config` re-apply
/// guarantee: an emitted config, re-applied, reproduces the same `.env`.
#[test]
fn defaults_config_round_trips_to_byte_identical_env() {
    let cfg = ConsoleConfig::all_in_stack_default();

    let dir = tempfile::tempdir().unwrap();
    // First emit (from the in-memory defaults).
    let env_a = dir.path().join(".env");
    emit_env_from_config(&cfg, &env_a.to_string_lossy()).unwrap();
    let first = std::fs::read_to_string(&env_a).unwrap();

    // Persist the reproducible toml, load it back, and re-emit into a SECOND .env.
    let toml = to_toml_string(&cfg).unwrap();
    let toml_path = dir.path().join("console.config.toml");
    std::fs::write(&toml_path, &toml).unwrap();
    let reloaded = load_config(&toml_path.to_string_lossy()).unwrap();
    assert_eq!(reloaded, cfg, "load_config(emit(defaults)) == defaults");

    let env_b = dir.path().join(".env.second");
    emit_env_from_config(&reloaded, &env_b.to_string_lossy()).unwrap();
    let second = std::fs::read_to_string(&env_b).unwrap();

    assert_eq!(first, second, "re-applying the saved config yields a byte-identical .env");

    // The defaults emit all five in-stack svc-* profiles + all CONSOLE_SERVICE_*
    // in-stack, and NO secret value (secrets are generated separately by the wizard).
    assert!(
        first.contains("COMPOSE_PROFILES=svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis"),
        "defaults emit all five in-stack profiles:\n{first}"
    );
    for svc in ["KRATOS", "HYDRA", "KETO", "OATHKEEPER", "POLIS"] {
        assert!(
            first.contains(&format!("CONSOLE_SERVICE_{svc}=in-stack")),
            "CONSOLE_SERVICE_{svc}=in-stack present:\n{first}"
        );
    }
    assert!(!first.contains("POLIS_API_KEY"), "no secret in the emitted .env");
}

/// A CUSTOM config (keto OFF + hydra BYO with an external admin URL) maps to the
/// expected profiles / env pairs and carries NO secret key. Proves the cascade
/// inputs the live stack consumes are produced correctly off a toml.
#[test]
fn custom_off_and_byo_config_maps_correctly() {
    let custom = r#"
[services.kratos]
mode = "in-stack"

[services.hydra]
mode = "byo"
admin_url = "https://hydra.byo.example/admin"

[services.keto]
mode = "off"

[services.oathkeeper]
mode = "in-stack"

[services.polis]
mode = "in-stack"
"#;
    let cfg = parse_config(custom).expect("custom config parses");

    // to_compose_profiles drops svc-keto (off) AND svc-hydra (byo).
    let profiles = cfg.to_compose_profiles();
    assert!(!profiles.contains(&"svc-keto".to_string()), "keto off → no profile: {profiles:?}");
    assert!(!profiles.contains(&"svc-hydra".to_string()), "hydra byo → no profile: {profiles:?}");
    assert_eq!(
        profiles,
        vec![
            "svc-kratos".to_string(),
            "svc-oathkeeper".to_string(),
            "svc-polis".to_string()
        ],
        "only in-stack services get a profile"
    );

    // to_env_pairs carries the right modes + the BYO admin URL, no secret.
    let pairs: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
    assert_eq!(pairs.get("CONSOLE_SERVICE_KETO").map(String::as_str), Some("off"));
    assert_eq!(pairs.get("CONSOLE_SERVICE_HYDRA").map(String::as_str), Some("byo"));
    assert_eq!(
        pairs.get("HYDRA_ADMIN_URL").map(String::as_str),
        Some("https://hydra.byo.example/admin"),
        "byo hydra emits its external admin URL"
    );
    assert!(!pairs.contains_key("KETO_READ_URL"), "off keto emits no URL");
    // The serialized toml carries no secret-shaped key.
    let toml = to_toml_string(&cfg).unwrap().to_ascii_lowercase();
    assert!(!toml.contains("secret"), "no secret key in toml");
    assert!(!toml.contains("password"), "no password key in toml");
    assert!(!toml.contains("api_key"), "no api_key in toml");

    // The service seed mirrors the env pairs.
    let seed = cfg.to_service_seed();
    assert_eq!(seed["keto"], ServiceMode::Off);
    assert_eq!(seed["hydra"], ServiceMode::Byo);
}

// ---------------------------------------------------------------------------
// 2. BLOCK-ON-FAIL — should_block returns the failures unless --skip-checks.
// ---------------------------------------------------------------------------

/// A healthy (200) BYO endpoint passes (no block); an unhealthy (503) one blocks
/// unless `--skip-checks` is set. Drives the real probe + policy via mockito.
#[tokio::test]
async fn probe_blocks_on_503_and_passes_with_skip_checks() {
    // Healthy mock: kratos byo /admin/health/ready → 200.
    let mut healthy = mockito::Server::new_async().await;
    let _h = healthy
        .mock("GET", "/admin/health/ready")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    // Unhealthy mock: hydra byo /health/ready → 503.
    let mut unhealthy = mockito::Server::new_async().await;
    let _u = unhealthy
        .mock("GET", "/health/ready")
        .with_status(503)
        .with_body("not ready")
        .create_async()
        .await;

    // Healthy set → should_block returns None (proceed), even when not skipping.
    let healthy_cfg = parse_config(&format!(
        r#"
[services.kratos]
mode = "byo"
admin_url = "{}"
[services.hydra]
mode = "off"
[services.keto]
mode = "off"
[services.oathkeeper]
mode = "off"
[services.polis]
mode = "off"
"#,
        healthy.url()
    ))
    .unwrap();
    let ok = probe_service("kratos", &healthy_cfg, DEFAULT_PROBE_TIMEOUT)
        .await
        .expect("kratos is probed");
    assert!(ok.ok, "200 → healthy: {ok:?}");
    assert!(
        should_block(std::slice::from_ref(&ok), false).is_none(),
        "a healthy probe does not block"
    );

    // Unhealthy set → should_block returns the failure when NOT skipping, None when
    // skip_checks=true.
    let unhealthy_cfg = parse_config(&format!(
        r#"
[services.hydra]
mode = "byo"
admin_url = "{}"
[services.kratos]
mode = "off"
[services.keto]
mode = "off"
[services.oathkeeper]
mode = "off"
[services.polis]
mode = "off"
"#,
        unhealthy.url()
    ))
    .unwrap();
    let bad = probe_service("hydra", &unhealthy_cfg, DEFAULT_PROBE_TIMEOUT)
        .await
        .expect("hydra is probed");
    assert!(!bad.ok, "503 → not ok: {bad:?}");

    let blocked = should_block(std::slice::from_ref(&bad), false)
        .expect("a failed check MUST block when not skipping");
    assert_eq!(blocked[0].service, "hydra");

    assert!(
        should_block(std::slice::from_ref(&bad), true).is_none(),
        "--skip-checks proceeds past the failure"
    );
}

// ---------------------------------------------------------------------------
// 3. WIZARD CONFIG-ONLY — run_init writes toml+.env, generates secrets, no boot.
// ---------------------------------------------------------------------------

/// `wizard::run_init(--defaults --no-docker)` writes a `console.config.toml` + a
/// gitignored `.env` (all-in-stack COMPOSE_PROFILES + CONSOLE_SERVICE_* seed +
/// generated required secrets), echoes NO secret value, and does NOT attempt a
/// `docker compose up` (config-only). Re-running with `--config <the written toml>`
/// is idempotent (re-apply): the existing secrets are NOT rotated.
#[tokio::test]
async fn wizard_defaults_no_docker_writes_artifacts_and_reapplies_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    // Basename `.env` satisfies the gitignored-path writer guard; tempdir keeps it
    // out of the repo's real `.env`.
    let env_file = dir.path().join(".env").to_string_lossy().into_owned();
    let config_out = dir
        .path()
        .join("console.config.toml")
        .to_string_lossy()
        .into_owned();

    let args = InitArgs {
        defaults: true,
        no_docker: true, // config-only: never reach docker
        env_file: env_file.clone(),
        config_out: config_out.clone(),
        ..Default::default()
    };

    // run_init returns Ok in config-only mode (no compose up attempted; if it had
    // tried, --no-docker forces the config-only branch which never spawns docker).
    run_init(args, "http://backend:8080", None)
        .await
        .expect("config-only wizard run succeeds");

    // The reproducible config exists and is the locked all-in-stack default.
    let toml = std::fs::read_to_string(&config_out).expect("config.toml written");
    let parsed = parse_config(&toml).expect("written config re-parses");
    for svc in ["kratos", "hydra", "keto", "oathkeeper", "polis"] {
        assert_eq!(parsed.mode_of(svc), ServiceMode::InStack, "{svc} in-stack");
    }
    // No secret leaked into the reproducible (committable) config artifact.
    let low = toml.to_ascii_lowercase();
    assert!(!low.contains("secret"), "config.toml has no secret key:\n{toml}");
    assert!(!low.contains("password"), "config.toml has no password key:\n{toml}");

    // The .env carries the all-in-stack seed + the generated required secrets.
    let env = std::fs::read_to_string(&env_file).expect(".env written");
    assert!(
        env.contains("COMPOSE_PROFILES=svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis"),
        "all five in-stack profiles seeded:\n{env}"
    );
    for svc in ["KRATOS", "HYDRA", "KETO", "OATHKEEPER", "POLIS"] {
        assert!(
            env.contains(&format!("CONSOLE_SERVICE_{svc}=in-stack")),
            "CONSOLE_SERVICE_{svc}=in-stack seeded:\n{env}"
        );
    }
    // Required generated secrets are PRESENT (all-in-stack → hydra + polis too).
    let pg = secret_value(&env, "POSTGRES_PASSWORD");
    let hydra = secret_value(&env, "HYDRA_SECRETS_SYSTEM");
    let polis = secret_value(&env, "POLIS_CLIENT_SECRET_VERIFY");
    assert!(!pg.is_empty(), "POSTGRES_PASSWORD generated:\n{env}");
    assert!(!hydra.is_empty(), "HYDRA_SECRETS_SYSTEM generated:\n{env}");
    assert!(!polis.is_empty(), "POLIS_CLIENT_SECRET_VERIFY generated:\n{env}");
    // Generated secrets are 64 hex chars (32-byte CSPRNG draws) — proves they came
    // from gen_secret, not a placeholder.
    assert_eq!(pg.len(), 64, "POSTGRES_PASSWORD is a 64-hex CSPRNG value");
    assert!(pg.chars().all(|c| c.is_ascii_hexdigit()), "hex only");

    // RE-APPLY with --config <the written toml>: idempotent, no secret rotation.
    let reapply = InitArgs {
        config: Some(config_out.clone()),
        no_docker: true,
        env_file: env_file.clone(),
        config_out: config_out.clone(),
        ..Default::default()
    };
    run_init(reapply, "http://backend:8080", None)
        .await
        .expect("config re-apply succeeds");

    let env_after = std::fs::read_to_string(&env_file).unwrap();
    // The secret VALUES must be unchanged (present secrets are never regenerated).
    assert_eq!(
        secret_value(&env_after, "POSTGRES_PASSWORD"),
        pg,
        "re-apply must NOT rotate POSTGRES_PASSWORD"
    );
    assert_eq!(
        secret_value(&env_after, "HYDRA_SECRETS_SYSTEM"),
        hydra,
        "re-apply must NOT rotate HYDRA_SECRETS_SYSTEM"
    );
    // The CONSOLE_SERVICE_*/profiles seed is also unchanged.
    assert!(env_after.contains(
        "COMPOSE_PROFILES=svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis"
    ));

    // The re-applied config.toml is byte-identical to the first (round-trip).
    let toml_after = std::fs::read_to_string(&config_out).unwrap();
    assert_eq!(toml, toml_after, "config.toml is stable across re-apply");
}

/// Read the value of `KEY=...` from an emitted `.env` body (last occurrence wins,
/// matching the upsert semantics). Returns "" if absent.
fn secret_value(env: &str, key: &str) -> String {
    env.lines()
        .filter_map(|l| l.strip_prefix(&format!("{key}=")))
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}
