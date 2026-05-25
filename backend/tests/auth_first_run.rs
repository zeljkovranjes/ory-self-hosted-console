//! Integration tests for `/setup` and `/login`/`/logout` (CAUTH-01..03, CAUTH-05).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs migrations; Salvo's
//! in-process `TestClient` drives the mounted handlers. The cookie name under
//! test is the dev `console_session` (the test config sets `insecure_cookies`
//! so the plain-HTTP TestClient transport accepts it); the hardened
//! `__Host-`/Secure flag matrix is asserted as a unit test in `auth::session`.

mod common;

use ory_console_backend::auth::password::sha256_hex;
use ory_console_backend::db::queries;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Persist a known bootstrap token hash (uninitialized console) and return the
/// raw token the operator would have copied from stdout.
async fn seed_bootstrap_token(pool: &PgPool) -> String {
    let raw = "test-bootstrap-token-value-1234567890";
    queries::insert_console_settings(pool, &sha256_hex(raw))
        .await
        .expect("seed bootstrap token");
    raw.to_string()
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_without_token_is_rejected(pool: PgPool) {
    seed_bootstrap_token(&pool).await;
    let service = Service::new(common::build_test_router(pool));

    let resp = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Owner",
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;

    // No token -> 403 (never reveals whether the field existed).
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_with_wrong_token_is_rejected(pool: PgPool) {
    seed_bootstrap_token(&pool).await;
    let service = Service::new(common::build_test_router(pool));

    let resp = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Owner",
            "email": "owner@example.com",
            "password": "a-very-long-password",
            "token": "WRONG-token"
        }))
        .send(&service)
        .await;

    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_with_correct_token_creates_argon2id_admin(pool: PgPool) {
    let raw = seed_bootstrap_token(&pool).await;
    let service = Service::new(common::build_test_router(pool.clone()));

    let mut resp = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Owner",
            "email": "owner@example.com",
            "password": "a-very-long-password",
            "token": raw
        }))
        .send(&service)
        .await;

    assert_eq!(resp.status_code, Some(StatusCode::CREATED));

    // Secret-free body: id/email/name only — NO secrets.
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("owner@example.com"));
    for forbidden in ["password_hash", "token", "bootstrap", "client_secret"] {
        assert!(
            !body.contains(forbidden),
            "setup body must not contain `{forbidden}`: {body}"
        );
    }

    // Stored admin has an Argon2id PHC hash.
    let row = sqlx::query!(r#"SELECT password_hash FROM admins WHERE email = 'owner@example.com'"#)
        .fetch_one(&pool)
        .await
        .expect("admin row");
    assert!(row
        .password_hash
        .as_deref()
        .unwrap()
        .starts_with("$argon2id$"));

    // initialized flipped + bootstrap hash cleared.
    assert!(queries::is_initialized(&pool).await.unwrap());
    let settings = queries::get_console_settings(&pool).await.unwrap().unwrap();
    assert!(settings.bootstrap_token_hash.is_none());

    // A session cookie was set.
    assert!(common::obtain_session_cookie(&resp).is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_after_init_returns_404(pool: PgPool) {
    let raw = seed_bootstrap_token(&pool).await;
    let service = Service::new(common::build_test_router(pool.clone()));

    // First setup succeeds.
    let resp = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Owner",
            "email": "owner@example.com",
            "password": "a-very-long-password",
            "token": raw
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::CREATED));

    // Second attempt -> 404 (require_uninitialized guard, CAUTH-01).
    let resp2 = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Other",
            "email": "other@example.com",
            "password": "another-long-password",
            "token": raw
        }))
        .send(&service)
        .await;
    assert_eq!(resp2.status_code, Some(StatusCode::NOT_FOUND));
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_short_password_is_rejected(pool: PgPool) {
    let raw = seed_bootstrap_token(&pool).await;
    let service = Service::new(common::build_test_router(pool));

    let resp = TestClient::post("http://127.0.0.1:8080/setup")
        .json(&serde_json::json!({
            "name": "Owner",
            "email": "owner@example.com",
            "password": "short",
            "token": raw
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::BAD_REQUEST));
}

#[sqlx::test(migrations = "./migrations")]
async fn login_valid_sets_session_cookie(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool));

    let mut resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;

    assert_eq!(resp.status_code, Some(StatusCode::OK));
    assert!(
        common::obtain_session_cookie(&resp).is_some(),
        "login must set the session cookie"
    );

    let body = resp.take_string().await.unwrap();
    for forbidden in ["password_hash", "token", "bootstrap", "client_secret"] {
        assert!(
            !body.contains(forbidden),
            "login body must not contain `{forbidden}`: {body}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn login_invalid_password_is_401(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool));

    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "wrong-password-here"
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[sqlx::test(migrations = "./migrations")]
async fn login_unknown_email_is_401(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));

    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "nobody@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_deletes_the_session_row(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));

    // Log in to get a session cookie.
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;
    let token = common::obtain_session_cookie(&resp).expect("session cookie");

    let before = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!" FROM sessions WHERE admin_id = $1"#,
        admin_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before.n, 1);

    // Logout carrying the dev session cookie.
    let resp2 = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={token}"), true)
        .send(&service)
        .await;
    assert_eq!(resp2.status_code, Some(StatusCode::OK));

    let after = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!" FROM sessions WHERE admin_id = $1"#,
        admin_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after.n, 0, "logout deletes the session row");
}
