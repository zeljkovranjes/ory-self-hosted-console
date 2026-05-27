//! The deterministic `.env` + `COMPOSE_PROFILES` emitter (CLI-builder Wave 2 / EMIT).
//!
//! Turns a parsed [`ConsoleConfig`] into the gitignored `.env` state Wave-1's
//! backend + compose consume:
//!   * a `CONSOLE_SERVICE_<SVC>` line for every service,
//!   * the admin-URL override key(s) for `byo` services,
//!   * a single `COMPOSE_PROFILES=<comma-joined svc-*>` line for the `in-stack`
//!     services.
//!
//! It REUSES `bootstrap::upsert_env` VERBATIM (atomic temp-file + rename, WR-01
//! newline/NUL/`=` injection guard, gitignored-target refusal) — it does NOT
//! duplicate the write logic. No secret value is ever written here (T-CB-B02):
//! the config model has no secret fields, and POLIS_API_KEY is upserted separately
//! by the Plan-C secret flow via `bootstrap::read_secret`.

use crate::bootstrap::upsert_env;
use crate::config_model::ConsoleConfig;
use crate::CliError;

/// The compose-profile selector env key (Wave-1 contract).
const COMPOSE_PROFILES_KEY: &str = "COMPOSE_PROFILES";

/// Write the config's `CONSOLE_SERVICE_*` lines, the `byo` admin-URL overrides,
/// and the `COMPOSE_PROFILES` line into the gitignored `env_file` (upsert —
/// preserving every other line, atomic). Refuses a non-gitignored target. Re-
/// running with the same config is idempotent (each key replaced in place).
pub fn emit_env_from_config(config: &ConsoleConfig, env_file: &str) -> Result<(), CliError> {
    // 1. The CONSOLE_SERVICE_* + byo URL pairs (owned Strings).
    let mut owned: Vec<(String, String)> = config.to_env_pairs();
    // 2. The COMPOSE_PROFILES line (comma-joined in-stack svc-* profiles). An
    //    empty profile set (every service byo/off) yields `COMPOSE_PROFILES=`,
    //    which is a valid, explicit "no in-stack Ory services" selection.
    owned.push((
        COMPOSE_PROFILES_KEY.to_string(),
        config.to_compose_profiles().join(","),
    ));

    // Borrow into the &[(&str, &str)] shape upsert_env expects. upsert_env applies
    // the WR-01 guard + gitignored-target refusal + atomic write — NOT duplicated.
    let pairs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    upsert_env(env_file, &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_model::parse_config;

    fn mixed_config() -> ConsoleConfig {
        parse_config(
            r#"
[services.kratos]
mode = "in-stack"

[services.hydra]
mode = "byo"
admin_url = "https://hydra.ext/admin"
public_url = "https://hydra.ext"

[services.keto]
mode = "off"

[services.oathkeeper]
mode = "in-stack"

[services.polis]
mode = "byo"
admin_url = "https://polis.ext"
external_url = "https://sso.example.com"
"#,
        )
        .unwrap()
    }

    #[test]
    fn emit_writes_console_service_byo_urls_and_compose_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let env_str = env_path.to_string_lossy().into_owned();

        emit_env_from_config(&mixed_config(), &env_str).expect("emit should write .env");
        let written = std::fs::read_to_string(&env_path).unwrap();

        // CONSOLE_SERVICE_* for every service, with the right modes.
        assert!(written.contains("CONSOLE_SERVICE_KRATOS=in-stack"), "{written}");
        assert!(written.contains("CONSOLE_SERVICE_HYDRA=byo"), "{written}");
        assert!(written.contains("CONSOLE_SERVICE_KETO=off"), "{written}");
        assert!(written.contains("CONSOLE_SERVICE_OATHKEEPER=in-stack"), "{written}");
        assert!(written.contains("CONSOLE_SERVICE_POLIS=byo"), "{written}");

        // byo admin-URL overrides.
        assert!(written.contains("HYDRA_ADMIN_URL=https://hydra.ext/admin"), "{written}");
        assert!(written.contains("HYDRA_PUBLIC_URL=https://hydra.ext"), "{written}");
        assert!(written.contains("POLIS_ADMIN_URL=https://polis.ext"), "{written}");
        assert!(written.contains("POLIS_EXTERNAL_URL=https://sso.example.com"), "{written}");

        // in-stack/off services emit NO admin URL.
        assert!(!written.contains("KRATOS_ADMIN_URL="), "in-stack → no URL: {written}");
        assert!(!written.contains("KETO_READ_URL="), "off → no URL: {written}");
        assert!(!written.contains("OATHKEEPER_API_URL="), "in-stack → no URL: {written}");

        // COMPOSE_PROFILES = svc-postgres FIRST (no [postgres] → in-stack default)
        // then the in-stack svc-* profiles (kratos, oathkeeper).
        assert!(
            written.contains("COMPOSE_PROFILES=svc-postgres,svc-kratos,svc-oathkeeper"),
            "compose profiles: {written}"
        );
        // In-stack postgres → NO POSTGRES_* override (byte-identical compose default).
        assert!(!written.contains("POSTGRES_HOST="), "in-stack pg → no host override: {written}");

        // NO secret ever written (T-CB-B02).
        assert!(!written.contains("POLIS_API_KEY"), "no secret: {written}");
        let lower = written.to_ascii_lowercase();
        assert!(!lower.contains("password"), "no password: {written}");
    }

    #[test]
    fn emit_byo_postgres_writes_overrides_and_drops_svc_postgres() {
        let cfg = parse_config(
            r#"
[services.kratos]
mode = "in-stack"
[postgres]
mode = "byo"
host = "db.ext.example.com"
port = "6543"
sslmode = "require"
"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
        let written = std::fs::read_to_string(&env_path).unwrap();

        // POSTGRES_* overrides emitted for byo.
        assert!(written.contains("POSTGRES_HOST=db.ext.example.com"), "{written}");
        assert!(written.contains("POSTGRES_PORT=6543"), "{written}");
        assert!(written.contains("POSTGRES_SSLMODE=require"), "{written}");

        // COMPOSE_PROFILES has svc-kratos but NOT svc-postgres (byo drops it).
        let prof_line = written
            .lines()
            .find(|l| l.starts_with("COMPOSE_PROFILES="))
            .expect("a COMPOSE_PROFILES line");
        assert!(prof_line.contains("svc-kratos"), "{prof_line}");
        assert!(!prof_line.contains("svc-postgres"), "byo drops svc-postgres: {prof_line}");

        // No password ever written.
        let lower = written.to_ascii_lowercase();
        assert!(!lower.contains("password"), "no password: {written}");
    }

    #[test]
    fn emit_is_idempotent_and_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let env_str = env_path.to_string_lossy().into_owned();
        // A pre-existing unrelated key must survive the upsert.
        std::fs::write(&env_path, "EXISTING_KEY=keepme\nCONSOLE_SERVICE_KRATOS=stale\n").unwrap();

        emit_env_from_config(&mixed_config(), &env_str).unwrap();
        // Second emit with the SAME config → idempotent.
        emit_env_from_config(&mixed_config(), &env_str).unwrap();
        let written = std::fs::read_to_string(&env_path).unwrap();

        assert!(written.contains("EXISTING_KEY=keepme"), "unrelated key preserved: {written}");
        // The stale value was replaced, not duplicated.
        assert_eq!(
            written.matches("CONSOLE_SERVICE_KRATOS=").count(),
            1,
            "no duplicate key after two emits: {written}"
        );
        assert!(written.contains("CONSOLE_SERVICE_KRATOS=in-stack"), "value upserted: {written}");
        assert_eq!(
            written.matches("COMPOSE_PROFILES=").count(),
            1,
            "single COMPOSE_PROFILES line: {written}"
        );
    }

    #[test]
    fn emit_refuses_non_gitignored_target() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("kratos.yml"); // not a .env/secret path
        let err = emit_env_from_config(&mixed_config(), &bad.to_string_lossy())
            .expect_err("a non-gitignored target must be refused");
        assert!(err.to_string().contains("gitignored"), "got: {err}");
        assert!(!bad.exists(), "nothing written to the refused path");
    }

    #[test]
    fn emit_all_byo_or_off_yields_empty_compose_profiles() {
        let cfg = parse_config(
            r#"
[services.kratos]
mode = "byo"
admin_url = "https://k.ext"
[services.hydra]
mode = "off"
[services.keto]
mode = "off"
[services.oathkeeper]
mode = "off"
[services.polis]
mode = "off"
[postgres]
mode = "byo"
host = "db.ext"
"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        emit_env_from_config(&cfg, &env_path.to_string_lossy()).unwrap();
        let written = std::fs::read_to_string(&env_path).unwrap();
        // Explicit empty selection — valid (the backend comes up with zero in-stack
        // svcs; postgres byo too → svc-postgres also dropped).
        assert!(written.contains("COMPOSE_PROFILES=\n") || written.ends_with("COMPOSE_PROFILES="),
            "empty profiles line present: {written}");
    }
}
