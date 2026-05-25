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
    // Minimal hardened-default config for the router's affix_state. `console_
    // database_url` is unused by handlers (they obtain the pool), but kept
    // non-empty so the struct is valid.
    let cfg = ory_console_backend::config::Config {
        console_database_url: String::new(),
        bind_addr: "0.0.0.0:8080".to_string(),
        session_idle_secs: 604_800,
        session_absolute_secs: 2_592_000,
        insecure_cookies: true, // tests run over plain HTTP TestClient
        github: None,
    };
    ory_console_backend::routes::build(pool, cfg)
}

/// Run the embedded console migrations against a test pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

// --- Stubs for later plans (CAUTH-02..06) -----------------------------------
// These return inert values so 02-01 tests compile. Plans 02-02..04 implement
// them once /setup, /login, and the session/CSRF subsystem exist.

/// Seed a console admin. Stub: implemented in 02-02 (setup/login).
pub async fn seed_admin(_pool: &PgPool) -> Option<uuid::Uuid> {
    None
}

/// Log in and return the `__Host-console_session` cookie value. Stub: 02-02.
pub fn obtain_session_cookie(_client_response: &Response) -> Option<String> {
    None
}

/// Mint a CSRF token bound to a session. Stub: 02-03 (CSRF guard).
pub fn mint_csrf(_session_id: uuid::Uuid) -> Option<String> {
    None
}
