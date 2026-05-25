//! Integration tests for the DB-backed opaque session layer (CAUTH-05).
//!
//! Uses `#[sqlx::test]` which provisions an isolated temp database per test and
//! runs the embedded migrations, then exercises `mint_session`/`validate_session`
//! /`delete_session` against the real `sessions` table. Cookie-flag assertions
//! live as unit tests in `auth::session`; here we prove the DB invariants:
//! the row stores the HASH not the raw token, idle/absolute expiry, and logout.

mod common;

use ory_console_backend::auth::password::sha256_hex;
use ory_console_backend::auth::session;
use ory_console_backend::config::Config;
use sqlx::PgPool;

fn test_cfg() -> Config {
    Config {
        console_database_url: String::new(),
        bind_addr: "0.0.0.0:8080".into(),
        session_idle_secs: 604_800,
        session_absolute_secs: 2_592_000,
        insecure_cookies: true,
        allowed_origins: Vec::new(),
        github: None,
        kratos_admin_url: "http://kratos:4434".into(),
        hydra_admin_url: "http://hydra:4445".into(),
        keto_read_url: "http://keto:4466".into(),
        keto_write_url: "http://keto:4467".into(),
        oathkeeper_api_url: "http://oathkeeper:4456".into(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn minted_session_stores_hash_not_raw_token(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let cfg = test_cfg();

    let minted = session::mint_session(&pool, admin_id, Some("127.0.0.1"), Some("test-ua"), &cfg)
        .await
        .expect("mint session");

    // The row must store sha256(raw), and that stored value must NOT equal raw.
    let expected_hash = sha256_hex(&minted.raw_token);
    let row = sqlx::query!(
        r#"SELECT token_hash, csrf_token FROM sessions WHERE admin_id = $1"#,
        admin_id
    )
    .fetch_one(&pool)
    .await
    .expect("session row exists");

    assert_eq!(row.token_hash, expected_hash, "stored hash = sha256(raw)");
    assert_ne!(
        row.token_hash, minted.raw_token,
        "the RAW token must never be persisted"
    );
    assert_eq!(row.csrf_token, minted.csrf_token);
    assert_ne!(minted.raw_token, minted.csrf_token, "token != csrf token");
}

#[sqlx::test(migrations = "./migrations")]
async fn validate_session_returns_row_then_logout_deletes_it(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let cfg = test_cfg();

    let minted = session::mint_session(&pool, admin_id, None, None, &cfg)
        .await
        .expect("mint session");

    // Valid token validates and resolves to the seeded admin.
    let validated = session::validate_session(&pool, &minted.raw_token, &cfg).await;
    assert!(validated.is_some(), "fresh session validates");
    assert_eq!(validated.unwrap().admin_id, admin_id);

    // A garbage token never validates.
    assert!(session::validate_session(&pool, "not-a-real-token", &cfg)
        .await
        .is_none());

    // Logout deletes the row; subsequent validation fails.
    session::delete_session(&pool, &minted.raw_token)
        .await
        .expect("delete session");
    assert!(
        session::validate_session(&pool, &minted.raw_token, &cfg)
            .await
            .is_none(),
        "deleted session no longer validates"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn idle_window_exceeded_rejects(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    // Idle window of 1s, absolute still long so we isolate the idle path.
    let cfg = Config {
        session_idle_secs: 1,
        ..test_cfg()
    };

    let minted = session::mint_session(&pool, admin_id, None, None, &cfg)
        .await
        .expect("mint session");

    // Force last_seen_at into the past beyond the idle window.
    sqlx::query!(
        "UPDATE sessions SET last_seen_at = now() - interval '10 seconds' WHERE admin_id = $1",
        admin_id
    )
    .execute(&pool)
    .await
    .expect("age last_seen_at");

    assert!(
        session::validate_session(&pool, &minted.raw_token, &cfg)
            .await
            .is_none(),
        "session past the idle window is rejected"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn absolute_expiry_rejects(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let cfg = test_cfg();

    let minted = session::mint_session(&pool, admin_id, None, None, &cfg)
        .await
        .expect("mint session");

    // Force the absolute expiry into the past.
    sqlx::query!(
        "UPDATE sessions SET expires_at = now() - interval '1 second' WHERE admin_id = $1",
        admin_id
    )
    .execute(&pool)
    .await
    .expect("expire session");

    assert!(
        session::validate_session(&pool, &minted.raw_token, &cfg)
            .await
            .is_none(),
        "absolutely-expired session is rejected"
    );
}
