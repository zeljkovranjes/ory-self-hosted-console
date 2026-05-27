//! The guided first-run BUILDER wizard (CLI-builder Wave 3 / WIZARD, DEFAULTS,
//! CONFIG-REAPPLY).
//!
//! `ory-console init` resolves a [`ConsoleConfig`] one of THREE ways, then writes
//! the reproducible `console.config.toml` + the gitignored `.env`, generates any
//! MISSING required secrets, and hands off to [`crate::orchestrate`] for the
//! HYBRID boot / config-only-degradation flow:
//!
//!   1. `--config <path>` → re-apply a saved config ([`config_model::load_config`]).
//!   2. `--defaults`      → the locked all-in-stack-on default
//!                          ([`ConsoleConfig::all_in_stack_default`]), no prompts.
//!   3. interactive       → a per-service `in-stack | byo | off` prompt (+ BYO
//!                          URLs) and a per-advanced-feature on/off prompt, each
//!                          with a sensible default so a bare Enter accepts it.
//!
//! SECURITY: this module adds NO value-taking secret argv flag (the clap guard
//! holds). Generated secrets (DB role passwords, HYDRA_SECRETS_SYSTEM, Polis keys)
//! are produced with the OS CSPRNG (`getrandom::fill`), written ONLY to the
//! gitignored `.env` via [`bootstrap::upsert_env`], and NEVER echoed. An
//! already-present secret is left untouched (idempotent re-runs). BYO secrets such
//! as `POLIS_API_KEY` are routed through [`bootstrap::read_secret`]
//! (env / `--*-file` / prompt), never argv.
//!
//! The prompts use plain stdin lines (the zero-new-dep posture from
//! `bootstrap::read_secret`) — NO interactive-prompt crate is added (T-CB-SC).

use std::io::{IsTerminal, Write};

use crate::config_model::{
    self, ConsoleConfig, ObservabilityConfig, ObservabilityMode, ObservabilityModeField,
    PostgresConfig, PostgresMode, PostgresModeField, ServiceConfig, ServiceMode, ServiceModeField,
    SERVICES,
};
use crate::{bootstrap, emit, orchestrate, InitArgs, CliError};

/// The advanced (opt-in, OFF-by-default) FEATURE-flag toggles the interactive path
/// prompts for. `observability` is NOT here — it has its own dedicated mode prompt
/// (in-stack/byo/off) because byo also collects the three external URLs, and the
/// feature flag is DERIVED from that mode (see `prompt_observability` +
/// `ConsoleConfig::effective_features`). The ON-by-default service/console features
/// are not prompted — they follow the service selection + the locked defaults.
const ADVANCED_FEATURES: [&str; 3] = ["saml", "organizations", "event_streams"];

/// Run the `init` builder wizard end-to-end.
///
/// `api_url` / `api_key` are the global ONLINE credentials forwarded to the
/// post-boot orchestration steps (feature apply / first-run admin guidance).
pub async fn run_init(
    args: InitArgs,
    api_url: &str,
    api_key: Option<&str>,
) -> Result<(), CliError> {
    // 1. RESOLVE the ConsoleConfig (three ways).
    let config = resolve_config(&args)?;

    // 2. WRITE the reproducible console.config.toml (secrets excluded by the model)
    //    + emit the deterministic .env (CONSOLE_SERVICE_* + byo URLs + COMPOSE_PROFILES).
    let toml = config_model::to_toml_string(&config)?;
    write_config_out(&args.config_out, &toml)?;
    eprintln!("wrote reproducible config to {}", args.config_out);

    emit::emit_env_from_config(&config, &args.env_file)?;
    eprintln!(
        "emitted .env to {} (CONSOLE_SERVICE_* + byo URLs + COMPOSE_PROFILES)",
        args.env_file
    );

    // 3. GENERATE + upsert any MISSING required secrets into .env (never echoed,
    //    never regenerated if already present).
    generate_missing_secrets(&config, &args.env_file)?;

    // 4. Hand off to the HYBRID orchestration (host end-to-end vs config-only).
    orchestrate::orchestrate(&config, &args, api_url, api_key).await
}

/// Resolve a [`ConsoleConfig`] from the flags: `--config` re-apply, `--defaults`
/// fast path, or the interactive prompt path.
fn resolve_config(args: &InitArgs) -> Result<ConsoleConfig, CliError> {
    if let Some(path) = &args.config {
        eprintln!("re-applying saved config: {path}");
        return config_model::load_config(path);
    }
    if args.defaults {
        eprintln!("using the locked defaults (all five services in-stack ON; advanced features OFF)");
        return Ok(ConsoleConfig::all_in_stack_default());
    }
    interactive_config()
}

/// Build a [`ConsoleConfig`] by prompting per service + per advanced feature.
/// Every prompt has a default so a bare Enter accepts it. Requires a TTY — when
/// stdin is not a terminal we cannot prompt, so we direct the operator to
/// `--defaults` or `--config` (rather than silently picking values).
fn interactive_config() -> Result<ConsoleConfig, CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Io(
            "interactive `init` needs a TTY. Non-interactively, pass --defaults \
             (locked all-in-stack-on default) or --config <console.config.toml>."
                .into(),
        ));
    }
    // Delegate to the reader-generic core so the prompt FLOW is unit-testable
    // without a TTY (the only TTY-specific part is the guard above).
    let stdin = std::io::stdin();
    build_interactive(&mut stdin.lock())
}

/// The reader-generic interactive build: prompt per service (+ BYO URLs) and per
/// advanced feature off a `BufRead`. Pure of any TTY assumption so a test can feed
/// a scripted answer stream (proving the same flow the live binary runs).
fn build_interactive<R: std::io::BufRead>(reader: &mut R) -> Result<ConsoleConfig, CliError> {
    eprintln!("Interactive setup — press Enter to accept the [default] for each prompt.");
    let mut services = config_model::Services::default();

    for svc in SERVICES {
        let mode = prompt_service_mode(reader, svc)?;
        let mut cfg = ServiceConfig {
            mode: Some(ServiceModeField(mode)),
            ..Default::default()
        };
        if mode == ServiceMode::Byo {
            prompt_byo_urls(reader, svc, &mut cfg)?;
        }
        services.set(svc, cfg);
    }

    // Postgres — the always-required backing store (in-stack bundled DB, or BYO
    // external). Prompted AFTER the services so its place in the flow is stable.
    let postgres = prompt_postgres(reader)?;

    // Observability — the OPTIONAL metrics+logs backing store (off/in-stack/byo).
    // Prompted with the other backing stores (after postgres, before the feature
    // toggles) since byo collects URLs much like a byo service.
    let observability = prompt_observability(reader)?;

    // Advanced features — default OFF (locked CONTEXT default). The ON-by-default
    // set is not prompted; it follows from the service selection + the defaults.
    let mut features = config_model::Features::with_defaults();
    for key in ADVANCED_FEATURES {
        let on = prompt_yes_no(reader, &format!("Enable advanced feature `{key}`?"), false)?;
        features.0.insert(key.to_string(), on);
    }

    Ok(ConsoleConfig {
        services,
        postgres: Some(postgres),
        observability: Some(observability),
        features: Some(features),
    })
}

/// Prompt for the Postgres backing store: `in-stack` (the bundled container, the
/// default) or `byo` (external — prompt host/port/sslmode). The DB password is a
/// SECRET (POSTGRES_PASSWORD + the per-service `*_DB_PASSWORD`) read via
/// env/`--*-file`/prompt — NEVER prompted as a config value here / never argv.
fn prompt_postgres<R: std::io::BufRead>(reader: &mut R) -> Result<PostgresConfig, CliError> {
    let mode = loop {
        let ans = prompt_line(reader, "Postgres — in-stack (bundled) / byo (external)", "in-stack")?;
        match ans.as_str() {
            "in-stack" => break PostgresMode::InStack,
            "byo" => break PostgresMode::Byo,
            other => eprintln!("  `{other}` is not one of in-stack/byo — try again."),
        }
    };

    let mut cfg = PostgresConfig {
        mode: Some(PostgresModeField(mode)),
        ..Default::default()
    };

    if mode == PostgresMode::Byo {
        cfg.host = opt(prompt_line(reader, "  postgres host", "")?);
        cfg.port = opt(prompt_line(reader, "  postgres port", "5432")?);
        // External Postgres usually mandates TLS → default sslmode=require.
        cfg.sslmode = opt(prompt_line(reader, "  postgres sslmode", "require")?);
        // The DB password(s) are SECRETS — never collected here / never argv.
        eprintln!(
            "  (POSTGRES_PASSWORD + the per-service *_DB_PASSWORD values are SECRETS — provide \
             them via env / a --*-file / prompt at run time; for a BYO target they MUST match \
             the login roles you pre-provisioned on the external instance. They are never stored \
             in console.config.toml.)"
        );
    }
    Ok(cfg)
}

/// Prompt for the observability backing store: `off` (the DEFAULT — opt-in,
/// matches today's behavior), `in-stack` (the bundled Prometheus/Grafana/Loki/Alloy
/// via the `observability` compose profile), or `byo` (point the backend at
/// EXTERNAL Prometheus/Loki/Grafana — prompt the 3 URLs).
///
/// BYO-GRAFANA AUTH CAVEAT (documented precisely here + in the SUMMARY): the
/// in-stack Grafana is provisioned for AUTH-PROXY header auth — the backend injects
/// `X-WEBAUTH-USER` and Grafana trusts it ONLY from the backend's pinned static
/// internal IP (`GF_AUTH_PROXY_WHITELIST=172.30.0.10`). An EXTERNAL Grafana will
/// NOT honor that header (it is not configured for auth-proxy, and the source IP
/// will not match), so the backend reverse-proxy still FORWARDS requests but the
/// external Grafana enforces ITS OWN authentication (its login/session/SSO). This
/// is the minimal correct behavior: nothing in the console silently bypasses an
/// external Grafana's auth — the operator configures auth on their own Grafana.
/// Prometheus/Loki (PromQL/LogQL queries) need only the URL — no auth caveat.
fn prompt_observability<R: std::io::BufRead>(
    reader: &mut R,
) -> Result<ObservabilityConfig, CliError> {
    let mode = loop {
        let ans = prompt_line(
            reader,
            "Observability (Prometheus/Grafana/Loki) — off / in-stack / byo",
            "off",
        )?;
        match ans.as_str() {
            "off" => break ObservabilityMode::Off,
            "in-stack" => break ObservabilityMode::InStack,
            "byo" => break ObservabilityMode::Byo,
            other => eprintln!("  `{other}` is not one of off/in-stack/byo — try again."),
        }
    };

    let mut cfg = ObservabilityConfig {
        mode: Some(ObservabilityModeField(mode)),
        ..Default::default()
    };

    if mode == ObservabilityMode::Byo {
        cfg.prometheus_url = opt(prompt_line(reader, "  Prometheus base URL", "")?);
        cfg.loki_url = opt(prompt_line(reader, "  Loki base URL", "")?);
        cfg.grafana_url = opt(prompt_line(reader, "  Grafana base URL", "")?);
        // The byo-Grafana auth caveat (surfaced so the operator is not surprised the
        // console does not auto-authenticate them into an external Grafana).
        eprintln!(
            "  (Prometheus/Loki need only the URL. EXTERNAL Grafana enforces its OWN \
             auth — the console reverse-proxy forwards to it but does NOT inject the \
             in-stack X-WEBAUTH-USER auth-proxy identity, which only the bundled Grafana \
             trusts from the backend's pinned internal IP. Configure auth on your Grafana.)"
        );
    }
    Ok(cfg)
}

/// Prompt for one service's mode (`in-stack | byo | off`), defaulting to in-stack.
fn prompt_service_mode<R: std::io::BufRead>(
    reader: &mut R,
    service: &str,
) -> Result<ServiceMode, CliError> {
    loop {
        let ans = prompt_line(
            reader,
            &format!("Service `{service}` — in-stack / byo / off"),
            "in-stack",
        )?;
        match ans.as_str() {
            "in-stack" => return Ok(ServiceMode::InStack),
            "byo" => return Ok(ServiceMode::Byo),
            "off" => return Ok(ServiceMode::Off),
            other => eprintln!("  `{other}` is not one of in-stack/byo/off — try again."),
        }
    }
}

/// Prompt for the BYO external URL slot(s) for a service. Empty answers leave the
/// slot unset (the probe then falls back to the in-stack default for that slot).
fn prompt_byo_urls<R: std::io::BufRead>(
    reader: &mut R,
    service: &str,
    cfg: &mut ServiceConfig,
) -> Result<(), CliError> {
    match service {
        "kratos" => cfg.admin_url = opt(prompt_line(reader, "  kratos admin URL", "")?),
        "hydra" => {
            cfg.admin_url = opt(prompt_line(reader, "  hydra admin URL", "")?);
            cfg.public_url = opt(prompt_line(reader, "  hydra public URL", "")?);
        }
        "keto" => {
            cfg.read_url = opt(prompt_line(reader, "  keto read URL", "")?);
            cfg.write_url = opt(prompt_line(reader, "  keto write URL", "")?);
        }
        "oathkeeper" => cfg.admin_url = opt(prompt_line(reader, "  oathkeeper API URL", "")?),
        "polis" => {
            cfg.admin_url = opt(prompt_line(reader, "  polis admin URL", "")?);
            cfg.external_url = opt(prompt_line(reader, "  polis external (OIDC issuer) URL", "")?);
            // The Polis API key is a SECRET — read via read_secret (env/file/prompt),
            // NEVER from a config field or argv. We surface the requirement here but
            // store nothing in the config; orchestration upserts it into .env.
            eprintln!(
                "  (POLIS_API_KEY is a secret — provide it via the POLIS_API_KEY env var \
                 or a --*-file at run time; it is never stored in console.config.toml)"
            );
        }
        _ => {}
    }
    Ok(())
}

/// `Some(s)` when non-empty after trimming, else `None`.
fn opt(s: String) -> Option<String> {
    let t = s.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// A yes/no prompt with a default. Accepts y/yes/n/no (case-insensitive).
fn prompt_yes_no<R: std::io::BufRead>(
    reader: &mut R,
    question: &str,
    default: bool,
) -> Result<bool, CliError> {
    let def_str = if default { "y" } else { "n" };
    loop {
        let ans = prompt_line(reader, question, def_str)?;
        match ans.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            other => eprintln!("  please answer y or n (got `{other}`)"),
        }
    }
}

/// Read a single trimmed line from `reader`, showing `[default]`. A bare Enter
/// returns the default. NEVER used for secrets (those go through read_secret).
fn prompt_line<R: std::io::BufRead>(
    reader: &mut R,
    label: &str,
    default: &str,
) -> Result<String, CliError> {
    if default.is_empty() {
        eprint!("{label}: ");
    } else {
        eprint!("{label} [{default}]: ");
    }
    std::io::stderr().flush().ok();

    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| CliError::Io(format!("reading stdin: {e}")))?;
    if n == 0 {
        // EOF before an answer → fall back to the default (a scripted/piped stream
        // that ran out, or a closed stdin: accept the default rather than loop).
        return Ok(default.to_string());
    }
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed)
    }
}

/// Write the reproducible `console.config.toml`. Unlike the `.env` writer this is
/// a NON-secret artifact (the model has no secret fields — asserted by the Wave-2
/// round-trip test), so it is written wherever the operator points `--config-out`
/// (typically the repo root, tracked or not — it carries no secret to leak).
fn write_config_out(path: &str, contents: &str) -> Result<(), CliError> {
    std::fs::write(path, contents)
        .map_err(|e| CliError::Io(format!("writing {path}: {e}")))
}

/// Generate + upsert any MISSING required secrets into the gitignored `.env`:
///   * `POSTGRES_PASSWORD`         — the DB role password (always required).
///   * `HYDRA_SECRETS_SYSTEM`      — Hydra's system secret (when hydra is in-stack).
///   * `POLIS_CLIENT_SECRET_VERIFY`/`POLIS_DB_ENCRYPTION_KEY` — Polis secrets
///                                   (when polis is in-stack).
///
/// A secret already present in `.env` is LEFT UNTOUCHED (idempotent re-runs never
/// rotate a live credential). Generated values use the OS CSPRNG and are NEVER
/// echoed — only the KEY names that were filled are reported.
fn generate_missing_secrets(config: &ConsoleConfig, env_file: &str) -> Result<(), CliError> {
    // The required-always + per-service-in-stack secret keys.
    let mut required: Vec<&str> = vec!["POSTGRES_PASSWORD"];
    if config.mode_of("hydra") == ServiceMode::InStack {
        required.push("HYDRA_SECRETS_SYSTEM");
    }
    if config.mode_of("polis") == ServiceMode::InStack {
        required.push("POLIS_CLIENT_SECRET_VERIFY");
        required.push("POLIS_DB_ENCRYPTION_KEY");
    }

    let existing = read_existing_keys(env_file);
    let mut generated: Vec<&str> = Vec::new();
    // Hold owned secret strings so the &str pairs borrow validly through upsert.
    let mut owned: Vec<(&str, String)> = Vec::new();
    for key in required {
        if existing.contains(&key.to_string()) {
            continue; // never regenerate a present secret
        }
        owned.push((key, gen_secret()?));
        generated.push(key);
    }

    if owned.is_empty() {
        eprintln!("all required secrets already present in {env_file} — none generated");
        return Ok(());
    }

    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    bootstrap::upsert_env(env_file, &pairs)?;
    // NEVER echo the values — only the keys filled.
    eprintln!(
        "generated {} missing secret(s) into {env_file} (values not echoed): {}",
        generated.len(),
        generated.join(", ")
    );
    Ok(())
}

/// The set of `KEY` names already present (non-empty) in an existing `.env`.
fn read_existing_keys(env_file: &str) -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(env_file) {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if !v.trim().is_empty() {
                    keys.insert(k.trim().to_string());
                }
            }
        }
    }
    keys
}

/// Generate a fresh URL-safe secret from the OS CSPRNG (32 bytes → 64 hex chars).
/// Hex (not base64) keeps the value free of `=`/`+`/`/` so it can never trip the
/// `upsert_env` WR-01 injection guard.
fn gen_secret() -> Result<String, CliError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| CliError::Io(format!("OS CSPRNG unavailable: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_resolve_to_all_in_stack() {
        let args = InitArgs {
            defaults: true,
            ..Default::default()
        };
        let cfg = resolve_config(&args).expect("defaults must resolve");
        for svc in SERVICES {
            assert_eq!(cfg.mode_of(svc), ServiceMode::InStack, "{svc} in-stack");
        }
        let feats = cfg.effective_features();
        assert_eq!(feats.0.get("identities"), Some(&true));
        assert_eq!(feats.0.get("saml"), Some(&false), "advanced OFF by default");
    }

    #[test]
    fn gen_secret_is_64_hex_chars_and_unique() {
        let a = gen_secret().unwrap();
        let b = gen_secret().unwrap();
        assert_eq!(a.len(), 64, "32 bytes → 64 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "hex only: {a}");
        // No '=' / newline → can never trip the upsert WR-01 guard.
        assert!(!a.contains(['=', '\n', '\r', '\0']));
        assert_ne!(a, b, "two draws differ (CSPRNG)");
    }

    #[test]
    fn generate_missing_secrets_is_idempotent_and_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let env_str = env_path.to_string_lossy().into_owned();
        let cfg = ConsoleConfig::all_in_stack_default();

        generate_missing_secrets(&cfg, &env_str).unwrap();
        let first = std::fs::read_to_string(&env_path).unwrap();
        // Hydra + Polis in-stack → their secrets generated alongside POSTGRES_PASSWORD.
        assert!(first.contains("POSTGRES_PASSWORD="), "{first}");
        assert!(first.contains("HYDRA_SECRETS_SYSTEM="), "{first}");
        assert!(first.contains("POLIS_CLIENT_SECRET_VERIFY="), "{first}");

        // Re-run → present secrets are NOT rotated (byte-identical for those keys).
        generate_missing_secrets(&cfg, &env_str).unwrap();
        let second = std::fs::read_to_string(&env_path).unwrap();
        assert_eq!(first, second, "idempotent: present secrets never regenerated");
    }

    #[test]
    fn build_interactive_assembles_config_from_scripted_answers() {
        // Scripted answer stream (one line each, in prompt order):
        //   kratos = <Enter> → in-stack
        //   hydra  = byo, admin URL, public URL
        //   keto   = off
        //   oathkeeper = <Enter> → in-stack
        //   polis  = <Enter> → in-stack
        //   postgres = <Enter> → in-stack
        //   observability = <Enter> → off (the locked default)
        //   advanced: saml=y, organizations=<Enter>(n), event_streams=<Enter>(n)
        let script = "\n\
            byo\n\
            http://hydra.ext/admin\n\
            http://hydra.ext\n\
            off\n\
            \n\
            \n\
            \n\
            \n\
            y\n\
            \n\
            \n";
        let mut reader = std::io::Cursor::new(script.as_bytes());
        let cfg = build_interactive(&mut reader).expect("interactive build");

        assert_eq!(cfg.mode_of("kratos"), ServiceMode::InStack, "Enter → in-stack");
        assert_eq!(cfg.mode_of("hydra"), ServiceMode::Byo);
        assert_eq!(cfg.mode_of("keto"), ServiceMode::Off);
        assert_eq!(cfg.mode_of("oathkeeper"), ServiceMode::InStack);
        assert_eq!(cfg.mode_of("polis"), ServiceMode::InStack);
        // postgres = <Enter> → in-stack (the bundled DB default).
        assert_eq!(cfg.postgres_mode(), PostgresMode::InStack, "Enter → in-stack pg");

        // BYO URLs captured for hydra.
        assert_eq!(
            cfg.services.hydra.as_ref().unwrap().admin_url.as_deref(),
            Some("http://hydra.ext/admin")
        );
        assert_eq!(
            cfg.services.hydra.as_ref().unwrap().public_url.as_deref(),
            Some("http://hydra.ext")
        );

        // Observability = off (Enter) → mode off + feature OFF.
        assert_eq!(cfg.observability_mode(), ObservabilityMode::Off, "Enter → observability off");

        // Advanced features: saml ON (operator chose y), the rest OFF.
        let feats = cfg.effective_features();
        assert_eq!(feats.0.get("saml"), Some(&true), "saml turned ON");
        assert_eq!(feats.0.get("organizations"), Some(&false));
        // observability feature is DERIVED from the off mode.
        assert_eq!(feats.0.get("observability"), Some(&false));
        assert_eq!(feats.0.get("event_streams"), Some(&false));
        // ON-by-default service features remain ON.
        assert_eq!(feats.0.get("identities"), Some(&true));

        // The assembled config maps to the right compose profiles: svc-postgres
        // FIRST (in-stack pg) then the in-stack Ory svc-* (no hydra/keto).
        assert_eq!(
            cfg.to_compose_profiles(),
            vec![
                "svc-postgres".to_string(),
                "svc-kratos".to_string(),
                "svc-oathkeeper".to_string(),
                "svc-polis".to_string()
            ]
        );
    }

    #[test]
    fn build_interactive_byo_postgres_produces_byo_config() {
        // All five services in-stack (Enter x5), then postgres = byo with host /
        // port / sslmode, then observability=off (Enter) + the 3 advanced features
        // default OFF (Enter x3) → 4 trailing Enters.
        let script = "\n\
            \n\
            \n\
            \n\
            \n\
            byo\n\
            db.external.example.com\n\
            6543\n\
            require\n\
            \n\
            \n\
            \n\
            \n";
        let mut reader = std::io::Cursor::new(script.as_bytes());
        let cfg = build_interactive(&mut reader).expect("interactive build");

        assert_eq!(cfg.postgres_mode(), PostgresMode::Byo, "byo postgres selected");
        let pg = cfg.postgres.as_ref().expect("postgres config set");
        assert_eq!(pg.host.as_deref(), Some("db.external.example.com"));
        assert_eq!(pg.port.as_deref(), Some("6543"));
        assert_eq!(pg.sslmode.as_deref(), Some("require"));
        // No password field exists on the model at all (T-BYO-02).
        let serialized = config_model::to_toml_string(&cfg).unwrap();
        assert!(!serialized.to_ascii_lowercase().contains("password"), "{serialized}");
        // byo postgres → svc-postgres dropped from the profiles.
        assert!(!cfg.to_compose_profiles().contains(&"svc-postgres".to_string()));
    }

    #[test]
    fn build_interactive_byo_observability_collects_urls_and_feature_on() {
        // 5 services in-stack (Enter x5), postgres in-stack (Enter), observability =
        // byo with the 3 URLs, then 3 advanced features default OFF (Enter x3).
        let script = "\n\
            \n\
            \n\
            \n\
            \n\
            \n\
            byo\n\
            https://prom.ext\n\
            https://loki.ext\n\
            https://grafana.ext\n\
            \n\
            \n\
            \n";
        let mut reader = std::io::Cursor::new(script.as_bytes());
        let cfg = build_interactive(&mut reader).expect("interactive build");

        assert_eq!(cfg.observability_mode(), ObservabilityMode::Byo, "byo observability");
        let obs = cfg.observability.as_ref().expect("observability config set");
        assert_eq!(obs.prometheus_url.as_deref(), Some("https://prom.ext"));
        assert_eq!(obs.loki_url.as_deref(), Some("https://loki.ext"));
        assert_eq!(obs.grafana_url.as_deref(), Some("https://grafana.ext"));

        // byo → URLs emitted, feature ON, NO observability compose profile, no secret.
        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert_eq!(map.get("PROMETHEUS_URL").map(String::as_str), Some("https://prom.ext"));
        assert_eq!(map.get("GRAFANA_URL").map(String::as_str), Some("https://grafana.ext"));
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&true));
        assert!(!cfg.to_compose_profiles().contains(&"observability".to_string()));
        let serialized = config_model::to_toml_string(&cfg).unwrap();
        assert!(!serialized.to_ascii_lowercase().contains("secret"), "{serialized}");
        assert!(!serialized.to_ascii_lowercase().contains("password"), "{serialized}");
    }

    #[test]
    fn build_interactive_in_stack_observability_adds_profile() {
        // 5 services + postgres all in-stack (Enter x6), observability = in-stack,
        // 3 advanced default OFF (Enter x3).
        let script = "\n\
            \n\
            \n\
            \n\
            \n\
            \n\
            in-stack\n\
            \n\
            \n\
            \n";
        let mut reader = std::io::Cursor::new(script.as_bytes());
        let cfg = build_interactive(&mut reader).expect("interactive build");

        assert_eq!(cfg.observability_mode(), ObservabilityMode::InStack);
        // in-stack → the observability profile is appended (after svc-postgres + svc-*).
        assert!(cfg.to_compose_profiles().contains(&"observability".to_string()));
        // No URL override (uses the compose-default internal URLs); feature ON.
        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert!(!map.contains_key("PROMETHEUS_URL"), "in-stack → no URL override");
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&true));
    }

    #[test]
    fn defaults_keep_observability_off() {
        // The locked --defaults path keeps observability off (no prompt).
        let args = InitArgs {
            defaults: true,
            ..Default::default()
        };
        let cfg = resolve_config(&args).expect("defaults resolve");
        assert_eq!(cfg.observability_mode(), ObservabilityMode::Off);
        assert!(!cfg.to_compose_profiles().contains(&"observability".to_string()));
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&false));
    }

    #[test]
    fn generate_missing_secrets_skips_off_service_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let env_str = env_path.to_string_lossy().into_owned();
        // hydra + polis OFF → only POSTGRES_PASSWORD generated.
        let cfg = config_model::parse_config(
            r#"
[services.hydra]
mode = "off"
[services.polis]
mode = "off"
"#,
        )
        .unwrap();
        generate_missing_secrets(&cfg, &env_str).unwrap();
        let written = std::fs::read_to_string(&env_path).unwrap();
        assert!(written.contains("POSTGRES_PASSWORD="), "{written}");
        assert!(!written.contains("HYDRA_SECRETS_SYSTEM="), "hydra off → no secret: {written}");
        assert!(!written.contains("POLIS_CLIENT_SECRET_VERIFY="), "polis off → no secret: {written}");
    }
}
