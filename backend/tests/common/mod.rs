//! Shared integration-test fixtures.
//!
//! Wave-0 scaffolding (Plans 02-02..04 extend this): a test-local router
//! assembler, a migration runner for `#[sqlx::test]` pools, and stub helpers
//! for seeding an admin / obtaining a session cookie / minting a CSRF token.
//! The stubs are deliberately no-op (return `None`/`Ok(())`) so THIS plan's
//! tests compile without the auth subsystem; later plans replace the bodies.
//!
//! Test DB approach: `#[sqlx::test]` provisions an isolated temp database per
//! test against `DATABASE_URL` and hands the test a `PgPool`. Handler/middleware
//! behavior is exercised with Salvo's in-process `TestClient`.

#![allow(dead_code)] // stubs are referenced by later plans, not all used yet.

use salvo::prelude::*;
use sqlx::PgPool;

/// Build a test router against a provided pool.
///
/// Forward-compatible with `routes::build`: we construct a minimal `Config`
/// from env defaults (no DSN required at this layer — the pool is already
/// built) and delegate to the real assembler so tests exercise the SAME router
/// the binary serves. Plans 02-02..04 extend `routes::build`; this helper rides
/// along automatically.
pub fn build_test_router(pool: PgPool) -> Router {
    build_test_router_cfg(pool, default_test_cfg())
}

/// Build a [`FeatureFlags`](ory_console_backend::features::FeatureFlags) cache
/// matching the `0007` migration seed (Phase 12 FLAG-01/04). The `#[sqlx::test]`
/// harness applies `0007` to the temp DB, so the seeded enabled state is known
/// statically: external-setup features OFF, `opl_live_validation` ON. Building the
/// cache from this canonical seed (instead of an async DB read) keeps
/// `build_test_router` synchronous — and stays consistent with the binary because
/// toggles in the tests go through the PUT route, which refreshes THIS same cache
/// instance held by the router. The keystone probe is gated by `saml` (OFF here),
/// so a flag-OFF request 404s and a PUT-toggle ON makes it 200.
pub fn seeded_test_flags() -> ory_console_backend::features::FeatureFlags {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("saml".to_string(), false);
    map.insert("organizations".to_string(), false);
    map.insert("account_experience".to_string(), false);
    map.insert("observability".to_string(), false);
    map.insert("event_streams".to_string(), false);
    map.insert("opl_live_validation".to_string(), true);
    ory_console_backend::features::FeatureFlags::from_map(map)
}

/// Hardened-default test config. `insecure_cookies = true` because the
/// in-process `TestClient` speaks plain HTTP (the `__Host-`/Secure cookie would
/// otherwise be a production-only flag the test transport cannot model).
pub fn default_test_cfg() -> ory_console_backend::config::Config {
    ory_console_backend::config::Config {
        console_database_url: String::new(),
        bind_addr: "0.0.0.0:8080".to_string(),
        session_idle_secs: 604_800,
        session_absolute_secs: 2_592_000,
        insecure_cookies: true,
        // Empty allowlist => the pre-session origin check is disabled by default,
        // so the existing setup/login tests (which send no Origin) still pass.
        // The origin-rejection test sets a non-empty allowlist explicitly.
        allowed_origins: Vec::new(),
        github: None,
        // Phase 3 (BACK-02): internal Ory Admin base URLs — same defaults as
        // `Config::from_env` so the literal compiles and live tests can point
        // these at the compose services via env if needed.
        kratos_admin_url: "http://kratos:4434".to_string(),
        hydra_admin_url: "http://hydra:4445".to_string(),
        hydra_public_url: "http://hydra:4444".to_string(),
        keto_read_url: "http://keto:4466".to_string(),
        keto_write_url: "http://keto:4467".to_string(),
        keto_opl_url: "http://keto:4469".to_string(),
        oathkeeper_api_url: "http://oathkeeper:4456".to_string(),
        // Phase 4 (BACK-04 / BACK-05): config-edit subsystem — same defaults as
        // `Config::from_env`.
        restart_broker_url: "http://restart-broker:2375".to_string(),
        config_dir: "/etc/config".to_string(),
        // Phase 16 (OBS-03/04/05): observability-profile internal base URLs — same
        // defaults as `Config::from_env`. The probe/query/proxy tests override
        // these (e.g. to a mockito base or an unreachable host) on a per-test cfg.
        prometheus_url: "http://prometheus:9090".to_string(),
        loki_url: "http://loki:3100".to_string(),
        grafana_url: "http://grafana:3000".to_string(),
        // Phase 14 (SSO-02/04): Polis admin base + write-only api key + issuer.
        // The router fixtures do not call Polis; defaults mirror `Config::from_env`
        // (the key/issuer are absent so the SAML routes 502 rather than calling
        // Polis unauthenticated — exercised by the dedicated sso route tests).
        polis_admin_url: "http://polis:5225".to_string(),
        polis_api_key: None,
        polis_external_url: None,
        // Phase 11 (HOOK-01/02): the webhook SSRF relaxation raw flag. Production
        // default is false; the effective posture is double-gated by
        // `webhook_allow_private_targets()` (also requires insecure_cookies). The
        // worker tests pass `allow_private` explicitly to `build_pinned_client`,
        // so the router fixture keeps the production-safe false here.
        webhook_allow_private_targets: false,
    }
}

/// Build the test router with an explicit config. As of Plan 02-03 the real
/// `routes::build` assembles the full production public/protected router (with
/// the auth + CSRF + rate-limit + origin hoops and the `/setup`,`/login`,
/// `/logout`, `/api/console/state`, `/api/console/me` routes), so this helper
/// simply delegates — the integration tests exercise the SAME router the binary
/// serves (no test-only route mounting).
pub fn build_test_router_cfg(pool: PgPool, cfg: ory_console_backend::config::Config) -> Router {
    // WR-03: `routes::build` is now fallible (it validates the Ory admin URLs).
    // The test `Config` always uses the valid internal-network defaults, so this
    // never fails in practice; `expect` surfaces a misconfigured fixture loudly.
    // Phase 12: pass the seeded feature-flag cache so the test router matches the
    // binary (FeatureFlagHoop on the protected subtree reads it via the Depot).
    ory_console_backend::routes::build(pool, cfg, seeded_test_flags())
        .expect("test router build (valid admin URLs)")
}

/// Run the embedded console migrations against a test pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

// --- Live Ory client helper (Phase 3 BACK-02) --------------------------------

use ory_console_backend::ory::clients::OryClients;

/// Build an [`OryClients`] whose per-service `base_path`s come from the same env
/// vars the production `Config` reads (`KRATOS_ADMIN_URL`, `HYDRA_ADMIN_URL`,
/// `KETO_READ_URL`, `KETO_WRITE_URL`, `KETO_OPL_URL`, `OATHKEEPER_API_URL`), each
/// falling back to the internal-network default. Live tests (`ORY_LIVE_TESTS=1`) use this to talk
/// to the running compose stack — e.g. to SEED one Kratos identity directly via
/// the typed admin crate so the wrapper read is non-empty.
///
/// Thin reuse of `OryClients::from_config`: it builds a `Config` from the same
/// env defaults so there is ONE source of truth for the admin URLs. Under
/// `docker compose`, `KRATOS_ADMIN_URL=http://kratos:4434` etc. are set; from a
/// host-side `cargo test` the defaults resolve to the internal DNS names, so the
/// caller is expected to either run inside the network or override the env to
/// `http://localhost:<port>` if the admin ports were temporarily published.
pub fn ory_clients_from_env() -> OryClients {
    fn url(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    }
    let cfg = default_test_cfg();
    let cfg = ory_console_backend::config::Config {
        kratos_admin_url: url("KRATOS_ADMIN_URL", &cfg.kratos_admin_url),
        hydra_admin_url: url("HYDRA_ADMIN_URL", &cfg.hydra_admin_url),
        hydra_public_url: url("HYDRA_PUBLIC_URL", &cfg.hydra_public_url),
        keto_read_url: url("KETO_READ_URL", &cfg.keto_read_url),
        keto_write_url: url("KETO_WRITE_URL", &cfg.keto_write_url),
        keto_opl_url: url("KETO_OPL_URL", &cfg.keto_opl_url),
        oathkeeper_api_url: url("OATHKEEPER_API_URL", &cfg.oathkeeper_api_url),
        ..cfg
    };
    // WR-03: `from_config` validates the admin URLs and is now fallible. Live
    // tests pass valid http(s) URLs (defaults or env overrides), so `expect`
    // only fires on a genuinely malformed override — surfacing it loudly.
    OryClients::from_config(&cfg).expect("ory clients from env (valid admin URLs)")
}

// --- Fixtures (implemented in 02-02; CSRF helper remains a 02-03 stub) -------

use ory_console_backend::auth::password;
use ory_console_backend::db::queries;

/// Seed a console admin with an Argon2id password hash and return its id.
/// Implemented in 02-02 now that the password primitives exist.
pub async fn seed_admin(pool: &PgPool, email: &str, plaintext_password: &str) -> uuid::Uuid {
    let hash = password::hash_password(plaintext_password).expect("hash seed admin password");
    queries::insert_admin(pool, email, "Seed Admin", &hash)
        .await
        .expect("insert seed admin")
}

/// Extract the session cookie VALUE (the raw opaque token) from a `Set-Cookie`
/// header on a TestClient response. Matches either the hardened `__Host-`
/// name or the dev `console_session` name. Returns `None` if absent.
pub fn obtain_session_cookie(response: &Response) -> Option<String> {
    for c in response.cookies().iter() {
        if c.name() == "__Host-console_session" || c.name() == "console_session" {
            return Some(c.value().to_owned());
        }
    }
    None
}

/// Look up the per-session CSRF token for a session identified by its raw
/// (cookie) token. The session layer stores only `sha256(raw)` as `token_hash`,
/// so we hash the raw token and read the row's `csrf_token`. Used by the CSRF
/// guard tests to supply a MATCHING `X-CSRF-Token` header.
pub async fn csrf_for_raw_token(pool: &PgPool, raw_token: &str) -> String {
    let token_hash = password::sha256_hex(raw_token);
    let row = sqlx::query!(
        "SELECT csrf_token FROM sessions WHERE token_hash = $1",
        token_hash
    )
    .fetch_one(pool)
    .await
    .expect("session row for raw token");
    row.csrf_token
}

// --- Config-edit temp fixture (Phase 4 BACK-04 / BACK-06) --------------------

/// The live no-`session:`/no-`dsn` Kratos doc, mirrored verbatim for the
/// config-edit integration tests so "file unchanged"/"no disk write" assertions
/// run against a deterministic TEMP file (never the live mount, and never the
/// real broker). The shape matches `config/kratos/kratos.yml`: it OMITS `dsn`
/// (env-injected at runtime) and ships NO `session:` block (so a `/session/...`
/// edit exercises the absent-parent path), while carrying `secrets` + `serve`
/// (so a GET must omit them — they are not allowlisted).
pub const KRATOS_FIXTURE_YAML: &str = r#"serve:
  public:
    base_url: http://kratos:4433/
  admin:
    base_url: http://kratos:4434/

identity:
  default_schema_id: default
  schemas:
    - id: default
      url: file:///etc/config/kratos/identity.schema.json

secrets:
  cookie:
    - PLACEHOLDERcookieSECRET0123456789AB
  cipher:
    - PLACEHOLDERcipherSECRET0123456AB
"#;

/// Phase-7 auth-config fixture: a Kratos doc that DOES carry a `courier` block
/// (but NO `smtp.connection_uri` — so the SMTP GET reports `{set:false}`) AND a
/// `selfservice.methods.oidc.config.providers` array whose single provider carries
/// a real `client_secret` and a `base64://` `mapper_url` (so the OIDC GET must mask
/// the secret and decode the mapper). The base64 mapper decodes to a small Jsonnet
/// source. Like the default fixture it OMITS `dsn` (env-injected) and `session`.
pub const KRATOS_AUTH_FIXTURE_YAML: &str = r#"serve:
  public:
    base_url: http://kratos:4433/
  admin:
    base_url: http://kratos:4434/

identity:
  default_schema_id: default
  schemas:
    - id: default
      url: file:///etc/config/kratos/identity.schema.json

selfservice:
  default_browser_return_url: http://localhost:3000/
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: google
            provider: google
            client_id: public-client-id
            client_secret: REAL-OIDC-SECRET-DO-NOT-LEAK
            mapper_url: "base64://bG9jYWwgY2xhaW1zID0gc3RkLmV4dFZhcigiY2xhaW1zIik7IHsgaWRlbnRpdHk6IHsgdHJhaXRzOiB7IGVtYWlsOiBjbGFpbXMuZW1haWwgfSB9IH0="

courier:
  smtp:
    from_address: noreply@example.com
    from_name: Example

secrets:
  cookie:
    - PLACEHOLDERcookieSECRET0123456789AB
  cipher:
    - PLACEHOLDERcipherSECRET0123456AB
"#;

/// The plaintext Jsonnet source the `KRATOS_AUTH_FIXTURE_YAML` mapper decodes to
/// (so the OIDC GET test can assert the decode round-trip).
pub const KRATOS_AUTH_FIXTURE_MAPPER_SRC: &str =
    r#"local claims = std.extVar("claims"); { identity: { traits: { email: claims.email } } }"#;

/// A valid draft-07 identity schema WITH `properties.traits` — the deterministic
/// "last-known-good" the IDENT-03 schema-editor tests seed and assert is left
/// untouched after a rejected PUT. Mirrors the shape of the shipped
/// `config/kratos/identity.schema.json`.
pub const IDENTITY_SCHEMA_FIXTURE_JSON: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Person",
  "type": "object",
  "properties": {
    "traits": {
      "type": "object",
      "properties": {
        "email": { "type": "string", "format": "email", "title": "E-Mail" }
      },
      "required": ["email"],
      "additionalProperties": false
    }
  }
}
"#;

/// A throwaway config-dir holding `kratos/kratos.yml` for the config-edit tests.
///
/// The directory is removed on drop, so each `#[sqlx::test]` gets an isolated,
/// deterministic fixture. `kratos_yml()` is the path the engine resolves from
/// the closed `Service` enum (`<config_dir>/kratos/kratos.yml`). It ALSO seeds
/// `kratos/identity.schema.json` (a valid draft-07 schema) so the IDENT-03
/// schema-editor tests have a deterministic last-known-good file.
pub struct ConfigFixture {
    root: std::path::PathBuf,
}

impl ConfigFixture {
    /// Create a fresh temp config-dir seeded with the no-session/no-dsn Kratos doc
    /// AND a valid identity schema file.
    pub fn new() -> Self {
        Self::with_kratos_yaml(KRATOS_FIXTURE_YAML)
    }

    /// Create a fresh temp config-dir seeded with a CUSTOM `kratos.yml` body (plus
    /// the same valid identity schema file). Used by the Phase-7 auth-config tests
    /// to seed a doc that carries `courier`/`selfservice.methods.oidc.config.providers`
    /// blocks the default `KRATOS_FIXTURE_YAML` omits.
    pub fn with_kratos_yaml(kratos_yaml: &str) -> Self {
        // Unique per call: pid + nanos avoids collisions across parallel tests.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ory-cfg-test-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(root.join("kratos")).expect("create temp kratos dir");
        std::fs::write(root.join("kratos").join("kratos.yml"), kratos_yaml)
            .expect("seed temp kratos.yml");
        std::fs::write(
            root.join("kratos").join("identity.schema.json"),
            IDENTITY_SCHEMA_FIXTURE_JSON,
        )
        .expect("seed temp identity.schema.json");
        Self { root }
    }

    /// Absolute path to the seeded `kratos/kratos.yml` (the engine's PUT target).
    pub fn kratos_yml(&self) -> std::path::PathBuf {
        self.root.join("kratos").join("kratos.yml")
    }

    /// Absolute path to the seeded `kratos/identity.schema.json` (the IDENT-03
    /// schema-editor PUT target).
    pub fn identity_schema_json(&self) -> std::path::PathBuf {
        self.root.join("kratos").join("identity.schema.json")
    }

    /// The `config_dir` string to put on a test `Config`.
    pub fn config_dir(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

impl Drop for ConfigFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A test `Config` whose `config_dir` points at a [`ConfigFixture`] temp dir, so
/// the config-edit routes read/write the fixture rather than the live mount.
pub fn cfg_with_config_dir(config_dir: String) -> ory_console_backend::config::Config {
    ory_console_backend::config::Config {
        config_dir,
        ..default_test_cfg()
    }
}
