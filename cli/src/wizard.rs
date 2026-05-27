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
//! Phase 20 (CLI-07): the prompts now route through the `ui::Prompter`
//! abstraction — arrow-key `Select` for every mode (no typed-literal answer) and a
//! single `[x]`/`[ ]` `MultiSelect` for the advanced features, pre-checked to the
//! current state. `build_interactive` stays the pure decision FLOW (it takes a
//! `&dyn ui::Prompter`), so the scripted-flow tests drive it via a
//! `ui::ScriptedPrompter` over a `Cursor` answer stream with NO TTY.

use std::io::IsTerminal;

use crate::config_model::{
    self, ConsoleConfig, ObservabilityConfig, ObservabilityMode, ObservabilityModeField,
    PostgresConfig, PostgresMode, PostgresModeField, ServiceConfig, ServiceMode, ServiceModeField,
    SERVICES,
};
use crate::ui::{self, Prompter};
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
    // We are on a TTY → build the Rich `DialoguerPrompter` (arrow-key widgets) and
    // drive the reader-generic flow. The flow itself is widget-agnostic so the
    // scripted tests drive it with a `ScriptedPrompter` instead (no TTY).
    let prompter = ui::DialoguerPrompter;
    build_interactive(&prompter)
}

/// The prompter-generic interactive build: prompt per service (+ BYO URLs) via the
/// `ui::Prompter` abstraction. Pure of any TTY assumption — a test feeds a
/// `ScriptedPrompter`, the live binary feeds a `DialoguerPrompter`, and BOTH run
/// the exact same decision FLOW.
fn build_interactive(prompter: &dyn Prompter) -> Result<ConsoleConfig, CliError> {
    eprintln!("Interactive setup — arrow keys move, Enter accepts the highlighted default.");
    let mut services = config_model::Services::default();

    for svc in SERVICES {
        let mode = prompt_service_mode(prompter, svc)?;
        let mut cfg = ServiceConfig {
            mode: Some(ServiceModeField(mode)),
            ..Default::default()
        };
        if mode == ServiceMode::Byo {
            prompt_byo_urls(prompter, svc, &mut cfg)?;
        }
        services.set(svc, cfg);
    }

    // Postgres — the always-required backing store (in-stack bundled DB, or BYO
    // external). Prompted AFTER the services so its place in the flow is stable.
    let postgres = prompt_postgres(prompter)?;

    // Observability — the OPTIONAL metrics+logs backing store (off/in-stack/byo).
    // Prompted with the other backing stores (after postgres, before the feature
    // toggles) since byo collects URLs much like a byo service.
    let observability = prompt_observability(prompter)?;

    // Advanced features — a SINGLE `[x]`/`[ ]` MultiSelect pre-checked to the
    // current default state (Req 2 / CLI-07b). The list is the locked advanced
    // feature set; a bare Enter keeps exactly the pre-checked rows (a no-op). The
    // resolved enabled set equals exactly the rows left `[x]`.
    let mut features = config_model::Features::with_defaults();
    let ordered_keys: Vec<String> = ADVANCED_FEATURES.iter().map(|s| s.to_string()).collect();
    // Pre-check mask = current default state of each advanced key (all OFF by the
    // locked default; `feature_default_mask` reads whatever is currently set).
    let defaults = ui::feature_default_mask(&features, &ordered_keys);
    let labels: Vec<&str> = ADVANCED_FEATURES.to_vec();
    let chosen = prompter.multiselect(
        "Advanced features — Space toggles [x], Enter confirms",
        &labels,
        &defaults,
    )?;
    // The enabled set is EXACTLY the rows left checked; everything else is OFF.
    let checked: std::collections::HashSet<usize> = chosen.into_iter().collect();
    for (i, key) in ADVANCED_FEATURES.iter().enumerate() {
        features.0.insert((*key).to_string(), checked.contains(&i));
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
fn prompt_postgres(prompter: &dyn Prompter) -> Result<PostgresConfig, CliError> {
    // Arrow-key Select (index → mode), default in-stack (index 0). No typed literal.
    let mode = match prompter.select("Postgres backing store", &["in-stack", "byo"], 0)? {
        0 => PostgresMode::InStack,
        _ => PostgresMode::Byo,
    };

    let mut cfg = PostgresConfig {
        mode: Some(PostgresModeField(mode)),
        ..Default::default()
    };

    if mode == PostgresMode::Byo {
        cfg.host = opt(prompter.input("  postgres host", "")?);
        cfg.port = opt(prompter.input("  postgres port", "5432")?);
        // External Postgres usually mandates TLS → default sslmode=require.
        cfg.sslmode = opt(prompter.input("  postgres sslmode", "require")?);
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
fn prompt_observability(prompter: &dyn Prompter) -> Result<ObservabilityConfig, CliError> {
    // Arrow-key Select (index → mode), default off (index 0). No typed literal.
    let mode = match prompter.select(
        "Observability (Prometheus/Grafana/Loki)",
        &["off", "in-stack", "byo"],
        0,
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
        cfg.prometheus_url = opt(prompter.input("  Prometheus base URL", "")?);
        cfg.loki_url = opt(prompter.input("  Loki base URL", "")?);
        cfg.grafana_url = opt(prompter.input("  Grafana base URL", "")?);
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

/// Prompt for one service's mode via an arrow-key Select (index → mode),
/// defaulting to in-stack (index 0). No typed-literal answer is possible.
fn prompt_service_mode(prompter: &dyn Prompter, service: &str) -> Result<ServiceMode, CliError> {
    let idx = prompter.select(
        &format!("Service `{service}` mode"),
        &["in-stack", "byo", "off"],
        0,
    )?;
    Ok(match idx {
        0 => ServiceMode::InStack,
        1 => ServiceMode::Byo,
        _ => ServiceMode::Off,
    })
}

/// Prompt for the BYO external URL slot(s) for a service. Empty answers leave the
/// slot unset (the probe then falls back to the in-stack default for that slot).
fn prompt_byo_urls(
    prompter: &dyn Prompter,
    service: &str,
    cfg: &mut ServiceConfig,
) -> Result<(), CliError> {
    match service {
        "kratos" => cfg.admin_url = opt(prompter.input("  kratos admin URL", "")?),
        "hydra" => {
            cfg.admin_url = opt(prompter.input("  hydra admin URL", "")?);
            cfg.public_url = opt(prompter.input("  hydra public URL", "")?);
        }
        "keto" => {
            cfg.read_url = opt(prompter.input("  keto read URL", "")?);
            cfg.write_url = opt(prompter.input("  keto write URL", "")?);
        }
        "oathkeeper" => cfg.admin_url = opt(prompter.input("  oathkeeper API URL", "")?),
        "polis" => {
            cfg.admin_url = opt(prompter.input("  polis admin URL", "")?);
            cfg.external_url = opt(prompter.input("  polis external (OIDC issuer) URL", "")?);
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

/// Write the reproducible `console.config.toml`. Unlike the `.env` writer this is
/// a NON-secret artifact (the model has no secret fields — asserted by the Wave-2
/// round-trip test), so it is written wherever the operator points `--config-out`
/// (typically the repo root, tracked or not — it carries no secret to leak).
pub(crate) fn write_config_out(path: &str, contents: &str) -> Result<(), CliError> {
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
pub(crate) fn generate_missing_secrets(config: &ConsoleConfig, env_file: &str) -> Result<(), CliError> {
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
            // WR-06: strip a leading `export ` token (a common shell-sourced `.env`
            // grammar) before splitting on `=`, so `export KEY=val` records the key
            // `KEY` (present) rather than `export KEY` — otherwise a present secret
            // is treated as absent and `generate_missing_secrets` would re-generate
            // it, rotating a live credential.
            let line = line.trim();
            let line = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
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

    /// Build a `ScriptedPrompter` over a scripted line-answer stream (the test seam
    /// that drives the SAME `build_interactive` flow the live `DialoguerPrompter`
    /// does — proving the prompt FLOW without a TTY).
    fn scripted(script: &str) -> ui::ScriptedPrompter {
        ui::ScriptedPrompter::new(std::io::Cursor::new(script.as_bytes().to_vec()))
    }

    #[test]
    fn build_interactive_assembles_config_from_scripted_answers() {
        // Scripted answer stream (one line per PROMPT, in prompt order). Select
        // prompts accept the literal item label or the 1-based index; a bare line
        // (\n) accepts the highlighted default. The advanced-feature step is now a
        // SINGLE MultiSelect — `"1"` checks index 0-based 0? NO: the ScriptedPrompter
        // multiselect takes 1-based indices, so `"1"` checks the FIRST row (saml).
        //   kratos = <Enter> → in-stack
        //   hydra  = byo, admin URL, public URL
        //   keto   = off
        //   oathkeeper = <Enter> → in-stack
        //   polis  = <Enter> → in-stack
        //   postgres = <Enter> → in-stack
        //   observability = <Enter> → off (the locked default)
        //   advanced MultiSelect: "1" → check saml only (org/event_streams left OFF)
        let script = "\n\
            byo\n\
            http://hydra.ext/admin\n\
            http://hydra.ext\n\
            off\n\
            \n\
            \n\
            \n\
            \n\
            1\n";
        let prompter = scripted(script);
        let cfg = build_interactive(&prompter).expect("interactive build");

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
        // port / sslmode, then observability=off (Enter) + the advanced MultiSelect
        // left at its defaults (bare Enter → all advanced OFF).
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
            \n";
        let prompter = scripted(script);
        let cfg = build_interactive(&prompter).expect("interactive build");

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
        // byo with the 3 URLs, then the advanced MultiSelect at its defaults (bare
        // Enter → all advanced OFF).
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
            \n";
        let prompter = scripted(script);
        let cfg = build_interactive(&prompter).expect("interactive build");

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
        // advanced MultiSelect at its defaults (bare Enter → all advanced OFF).
        let script = "\n\
            \n\
            \n\
            \n\
            \n\
            \n\
            in-stack\n\
            \n";
        let prompter = scripted(script);
        let cfg = build_interactive(&prompter).expect("interactive build");

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
