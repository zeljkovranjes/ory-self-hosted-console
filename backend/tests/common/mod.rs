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
        keto_read_url: "http://keto:4466".to_string(),
        keto_write_url: "http://keto:4467".to_string(),
        oathkeeper_api_url: "http://oathkeeper:4456".to_string(),
        // Phase 4 (BACK-04 / BACK-05): config-edit subsystem — same defaults as
        // `Config::from_env`.
        restart_broker_url: "http://restart-broker:2375".to_string(),
        config_dir: "/etc/config".to_string(),
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
    ory_console_backend::routes::build(pool, cfg).expect("test router build (valid admin URLs)")
}

/// Run the embedded console migrations against a test pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

// --- Live Ory client helper (Phase 3 BACK-02) --------------------------------

use ory_console_backend::ory::clients::OryClients;

/// Build an [`OryClients`] whose per-service `base_path`s come from the same env
/// vars the production `Config` reads (`KRATOS_ADMIN_URL`, `HYDRA_ADMIN_URL`,
/// `KETO_READ_URL`, `KETO_WRITE_URL`, `OATHKEEPER_API_URL`), each falling back to
/// the internal-network default. Live tests (`ORY_LIVE_TESTS=1`) use this to talk
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
        keto_read_url: url("KETO_READ_URL", &cfg.keto_read_url),
        keto_write_url: url("KETO_WRITE_URL", &cfg.keto_write_url),
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
