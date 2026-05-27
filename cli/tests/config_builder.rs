//! CLI-builder Wave 2 end-to-end: a representative `console.config.toml` flows
//! parse -> round-trip -> emit (.env / COMPOSE_PROFILES / CONSOLE_SERVICE_*) and a
//! live readiness probe blocks-on-fail / passes-on-success. This is the
//! TTY-free, full-pipeline verification the plan's <verification> calls for —
//! the same library functions Plan C (the interactive wizard) will drive.

use console_cli::config_model::{load_config, parse_config, to_toml_string, ServiceMode};
use console_cli::emit::emit_env_from_config;
use console_cli::probe::{probe_all, probe_service, should_block, DEFAULT_PROBE_TIMEOUT};

/// A representative stack: kratos in-stack, hydra byo, keto off, oathkeeper
/// in-stack (implicit default via omission would also work; declared here),
/// polis byo + an opt-in feature toggled on.
const SAMPLE: &str = r#"
[services.kratos]
mode = "in-stack"

[services.hydra]
mode = "byo"
admin_url = "https://hydra.ext.example/admin"
public_url = "https://hydra.ext.example"

[services.keto]
mode = "off"

[services.oathkeeper]
mode = "in-stack"

[services.polis]
mode = "byo"
admin_url = "https://polis.ext.example"
external_url = "https://sso.example.com"

[features]
saml = true
organizations = true
"#;

#[test]
fn config_round_trips_and_emits_expected_env_profile_seed() {
    let cfg = parse_config(SAMPLE).expect("sample parses");

    // 1. Round-trip (the --config re-apply contract).
    let serialized = to_toml_string(&cfg).unwrap();
    assert_eq!(cfg, parse_config(&serialized).unwrap(), "round-trip equal");

    // 2. load_config from a real file path (not just parse_config).
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("console.config.toml");
    std::fs::write(&cfg_path, SAMPLE).unwrap();
    let loaded = load_config(&cfg_path.to_string_lossy()).unwrap();
    assert_eq!(loaded, cfg, "load_config matches parse_config");

    // 3. Service seed.
    let seed = cfg.to_service_seed();
    assert_eq!(seed["kratos"], ServiceMode::InStack);
    assert_eq!(seed["hydra"], ServiceMode::Byo);
    assert_eq!(seed["keto"], ServiceMode::Off);
    assert_eq!(seed["oathkeeper"], ServiceMode::InStack);
    assert_eq!(seed["polis"], ServiceMode::Byo);

    // 4. Emit a real .env and assert the exact Wave-1 contract lines.
    let env_path = dir.path().join(".env");
    emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
    let env = std::fs::read_to_string(&env_path).unwrap();

    for line in [
        "CONSOLE_SERVICE_KRATOS=in-stack",
        "CONSOLE_SERVICE_HYDRA=byo",
        "CONSOLE_SERVICE_KETO=off",
        "CONSOLE_SERVICE_OATHKEEPER=in-stack",
        "CONSOLE_SERVICE_POLIS=byo",
        "HYDRA_ADMIN_URL=https://hydra.ext.example/admin",
        "HYDRA_PUBLIC_URL=https://hydra.ext.example",
        "POLIS_ADMIN_URL=https://polis.ext.example",
        "POLIS_EXTERNAL_URL=https://sso.example.com",
        // svc-postgres FIRST (no [postgres] table → in-stack default), then the
        // in-stack svc-* (NOT byo hydra/polis, NOT off keto).
        "COMPOSE_PROFILES=svc-postgres,svc-kratos,svc-oathkeeper",
    ] {
        assert!(env.contains(line), "missing `{line}` in:\n{env}");
    }
    // byo-only URLs: in-stack/off emit none; no secret.
    assert!(!env.contains("KRATOS_ADMIN_URL="), "in-stack → no URL");
    assert!(!env.contains("KETO_READ_URL="), "off → no URL");
    assert!(!env.contains("POLIS_API_KEY"), "no secret in emitted .env");
    // In-stack postgres (default) → no POSTGRES_* override (byte-identical compose).
    assert!(!env.contains("POSTGRES_HOST="), "in-stack pg → no host override");
}

/// A BYO-Postgres SAMPLE flows parse → round-trip → emit and yields the
/// POSTGRES_HOST/PORT/SSLMODE overrides + a COMPOSE_PROFILES line WITHOUT
/// svc-postgres, with the [postgres] table round-tripping losslessly and carrying
/// no password. The TTY-free half of the live back-to-back DB check (IUX-BYO-PG).
#[test]
fn byo_postgres_config_round_trips_and_emits_overrides_without_svc_postgres() {
    const BYO_PG: &str = r#"
[services.kratos]
mode = "in-stack"

[postgres]
mode = "byo"
host = "db.external.example.com"
port = "6543"
sslmode = "require"
"#;
    let cfg = parse_config(BYO_PG).expect("byo-postgres sample parses");

    // Round-trip lossless + no password.
    let serialized = to_toml_string(&cfg).unwrap();
    assert_eq!(cfg, parse_config(&serialized).unwrap(), "round-trip equal");
    assert!(
        !serialized.to_ascii_lowercase().contains("password"),
        "no password in serialized byo-postgres config: {serialized}"
    );

    // Emit a real .env and assert the BYO overrides + svc-postgres absence.
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
    let env = std::fs::read_to_string(&env_path).unwrap();

    for line in [
        "POSTGRES_HOST=db.external.example.com",
        "POSTGRES_PORT=6543",
        "POSTGRES_SSLMODE=require",
    ] {
        assert!(env.contains(line), "missing `{line}` in:\n{env}");
    }
    let prof = env
        .lines()
        .find(|l| l.starts_with("COMPOSE_PROFILES="))
        .expect("a COMPOSE_PROFILES line");
    assert!(prof.contains("svc-kratos"), "{prof}");
    assert!(!prof.contains("svc-postgres"), "byo postgres drops svc-postgres: {prof}");
}

/// A BYO-observability SAMPLE flows parse → round-trip → emit and yields the
/// PROMETHEUS_URL/LOKI_URL/GRAFANA_URL overrides + the observability FEATURE ON,
/// with NO `observability` compose profile (external backends) and no secret key.
/// Mirrors the BYO-Postgres pipeline test (quick-260527-k0j).
#[test]
fn byo_observability_config_round_trips_emits_urls_no_profile_feature_on() {
    use console_cli::config_model::ObservabilityMode;

    const BYO_OBS: &str = r#"
[services.kratos]
mode = "in-stack"

[observability]
mode = "byo"
prometheus_url = "https://prometheus.ext.example"
loki_url = "https://loki.ext.example"
grafana_url = "https://grafana.ext.example"
"#;
    let cfg = parse_config(BYO_OBS).expect("byo-observability sample parses");
    assert_eq!(cfg.observability_mode(), ObservabilityMode::Byo);

    // Round-trip lossless + no secret.
    let serialized = to_toml_string(&cfg).unwrap();
    assert_eq!(cfg, parse_config(&serialized).unwrap(), "round-trip equal");
    let lower = serialized.to_ascii_lowercase();
    assert!(!lower.contains("secret"), "no secret in serialized config: {serialized}");
    assert!(!lower.contains("password"), "no password: {serialized}");

    // Emit a real .env and assert the 3 URL overrides + no observability profile.
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
    let env = std::fs::read_to_string(&env_path).unwrap();

    for line in [
        "PROMETHEUS_URL=https://prometheus.ext.example",
        "LOKI_URL=https://loki.ext.example",
        "GRAFANA_URL=https://grafana.ext.example",
    ] {
        assert!(env.contains(line), "missing `{line}` in:\n{env}");
    }
    let prof = env
        .lines()
        .find(|l| l.starts_with("COMPOSE_PROFILES="))
        .expect("a COMPOSE_PROFILES line");
    assert!(!prof.contains("observability"), "byo → no observability profile: {prof}");
    // The observability FEATURE is ON (console surfaces work against the externals).
    assert_eq!(cfg.effective_features().0.get("observability"), Some(&true));
}

/// The DEFAULT (observability off / absent) emits NO observability artifacts —
/// byte-identical to today. The guard that the new feature is invisible by default.
#[test]
fn default_observability_off_emits_no_urls_or_profile() {
    let cfg = parse_config(
        r#"
[services.kratos]
mode = "in-stack"
"#,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
    let env = std::fs::read_to_string(&env_path).unwrap();
    assert!(!env.contains("PROMETHEUS_URL"), "default → no PROMETHEUS_URL: {env}");
    assert!(!env.contains("LOKI_URL"), "default → no LOKI_URL: {env}");
    assert!(!env.contains("GRAFANA_URL"), "default → no GRAFANA_URL: {env}");
    let prof = env.lines().find(|l| l.starts_with("COMPOSE_PROFILES=")).unwrap();
    assert!(!prof.contains("observability"), "default → no observability profile: {prof}");
}

/// A live probe that PASSES (mock 200) does not block; flipping to 503 blocks
/// unless --skip-checks. Drives the real probe + policy path end-to-end.
#[tokio::test]
async fn probe_pipeline_blocks_on_fail_passes_on_success() {
    // Two mock servers: one healthy (kratos byo), one not-ready (hydra byo).
    let mut ok_server = mockito::Server::new_async().await;
    let _ok = ok_server
        .mock("GET", "/admin/health/ready")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let mut bad_server = mockito::Server::new_async().await;
    let _bad = bad_server
        .mock("GET", "/health/ready")
        .with_status(503)
        .with_body("not ready")
        .create_async()
        .await;

    // All-pass config: only the healthy kratos endpoint, everything else off.
    let pass_cfg = parse_config(&format!(
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
        ok_server.url()
    ))
    .unwrap();

    let results = probe_all(&pass_cfg, DEFAULT_PROBE_TIMEOUT).await;
    // off services are skipped → only kratos was probed.
    assert_eq!(results.len(), 1, "only the one non-off service is probed");
    assert!(results[0].ok, "healthy kratos passes: {:?}", results[0]);
    assert!(
        should_block(&results, false).is_none(),
        "all-pass must not block"
    );

    // Now a config with the not-ready hydra → must BLOCK (unless skip).
    let fail_cfg = parse_config(&format!(
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
        bad_server.url()
    ))
    .unwrap();

    let r = probe_service("hydra", &fail_cfg, DEFAULT_PROBE_TIMEOUT)
        .await
        .unwrap();
    assert!(!r.ok, "503 hydra is not ok");
    let blocked = should_block(std::slice::from_ref(&r), false)
        .expect("a failure must block when not skipping");
    assert_eq!(blocked[0].service, "hydra");
    assert!(blocked[0].hint.contains("byo"), "byo fix hint present");
    // --skip-checks overrides the block.
    assert!(
        should_block(std::slice::from_ref(&r), true).is_none(),
        "--skip-checks proceeds past the failure"
    );
}
