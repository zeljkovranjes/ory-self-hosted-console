//! Secret-absence assertions for auth/state endpoints (BACK-07, Plan 02-04).
//!
//! Closes BACK-07 with an explicit, code-level gate: the serialized response
//! body of every auth/state endpoint MUST contain NONE of the secret markers
//! (`password_hash`, `token_hash`, `bootstrap`, `client_secret`, `$argon2`, a
//! `postgres://` DSN). Each assertion ALSO fails on an EMPTY body — an empty
//! body cannot prove secret-absence (anti-false-green, mirrors the live gate's
//! `assert_no_secret_in_body`).
//!
//! Endpoints covered: `GET /api/console/state` (public), `POST /login`
//! (success path — returns the secret-free admin DTO + Set-Cookie), and
//! `GET /api/console/me` (protected — authenticated profile). The `Set-Cookie`
//! header carries only the OPAQUE session token (never a hash), so the cookie
//! value is expected; we assert the JSON BODY carries no secret.

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Secret substrings that must NEVER appear in a response body (BACK-07).
const SECRET_MARKERS: &[&str] = &[
    "password_hash",
    "token_hash",
    "bootstrap",
    "client_secret",
    "$argon2",
    "postgres://",
];

/// Assert `body` is non-empty AND contains none of the secret markers.
fn assert_no_secret(label: &str, body: &str) {
    assert!(
        !body.is_empty(),
        "{label}: empty body cannot confirm secret-absence (anti-false-green)"
    );
    for marker in SECRET_MARKERS {
        assert!(
            !body.contains(marker),
            "{label}: response body must not contain secret marker `{marker}`: {body}"
        );
    }
}

/// Log in the seeded admin and return its raw session cookie token.
async fn login(service: &Service) -> (String, String) {
    let mut resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "login should succeed");
    let raw = common::obtain_session_cookie(&resp).expect("session cookie");
    let body = resp.take_string().await.unwrap();
    (raw, body)
}

#[sqlx::test(migrations = "./migrations")]
async fn state_body_carries_no_secret(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/state")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    assert_no_secret("GET /api/console/state", &body);
}

#[sqlx::test(migrations = "./migrations")]
async fn login_body_carries_no_secret(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (_raw, body) = login(&service).await;
    assert_no_secret("POST /login", &body);
}

#[sqlx::test(migrations = "./migrations")]
async fn me_body_carries_no_secret(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _login_body) = login(&service).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/me")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    // Sanity: the body really is the admin profile (not an empty/error body),
    // so the secret-absence assertion is meaningful.
    assert!(
        body.contains("owner@example.com"),
        "me body is the admin profile: {body}"
    );
    assert_no_secret("GET /api/console/me", &body);
}
