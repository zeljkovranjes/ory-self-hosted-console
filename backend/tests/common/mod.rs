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
        github: None,
    }
}

/// Build the test router with an explicit config, mounting the public auth
/// routes (`/setup`, `/login`, `/logout`) onto the real `routes::build`
/// skeleton. Plan 02-03 assembles the production public/protected router with
/// the auth + CSRF + rate-limit hoops; until then the integration tests mount
/// the handlers here so the Task-2 behaviors are exercisable now (per PLAN
/// "mount them in the test router").
pub fn build_test_router_cfg(pool: PgPool, cfg: ory_console_backend::config::Config) -> Router {
    use ory_console_backend::auth::{login, setup};

    let base = ory_console_backend::routes::build(pool, cfg);
    base.push(
        Router::with_path("setup")
            .hoop(setup::require_uninitialized)
            .post(setup::setup),
    )
    .push(Router::with_path("login").post(login::login))
    .push(Router::with_path("logout").post(login::logout))
}

/// Run the embedded console migrations against a test pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
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

/// Mint a CSRF token bound to a session. Stub: 02-03 (CSRF guard).
pub fn mint_csrf(_session_id: uuid::Uuid) -> Option<String> {
    None
}
