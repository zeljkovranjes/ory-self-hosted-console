//! Integration tests for the production router assembly (Plan 02-03):
//! the single auth chokepoint (CAUTH-06/BACK-01), the per-session CSRF guard
//! (CAUTH-05), the pre-auth IP rate limiter, the pre-session Origin allowlist
//! (Plan-checker Warning 2), and the `/api/console/state` + `/api/console/me`
//! endpoints.
//!
//! `#[sqlx::test]` provisions an isolated DB + runs migrations; Salvo's
//! in-process `TestClient` drives the SAME router the binary serves
//! (`common::build_test_router*` delegates to `routes::build`). The dev cookie
//! name `console_session` is in force (test config sets `insecure_cookies`).

mod common;

use ory_console_backend::config::Config;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Log in the seeded admin and return (raw session token, csrf token).
async fn login_and_get_session(service: &Service, pool: &PgPool) -> (String, String) {
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "login should succeed");
    let raw = common::obtain_session_cookie(&resp).expect("session cookie");
    let csrf = common::csrf_for_raw_token(pool, &raw).await;
    (raw, csrf)
}

// --- Public set reachable without a cookie -----------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn health_is_public(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let resp = TestClient::get("http://127.0.0.1:8080/health")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
}

#[sqlx::test(migrations = "./migrations")]
async fn console_state_is_public_and_secret_free(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/state")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));

    let body = resp.take_string().await.unwrap();
    assert!(body.contains("initialized"), "state has initialized: {body}");
    assert!(
        body.contains("github_oauth_enabled"),
        "state has github_oauth_enabled: {body}"
    );
    for forbidden in ["password_hash", "token", "bootstrap", "client_secret", "csrf"] {
        assert!(
            !body.contains(forbidden),
            "state body must not contain `{forbidden}`: {body}"
        );
    }
}

// --- Protected route requires a valid session (401 JSON) ---------------------

#[sqlx::test(migrations = "./migrations")]
async fn me_without_cookie_is_401_json(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/me")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    let body = resp.take_string().await.unwrap();
    assert!(
        body.contains("unauthenticated"),
        "401 body is JSON {{error:unauthenticated}}: {body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn me_with_valid_session_is_200(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/me")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));

    let body = resp.take_string().await.unwrap();
    assert!(body.contains("owner@example.com"), "me returns the admin: {body}");
    for forbidden in ["password_hash", "token", "bootstrap", "client_secret"] {
        assert!(
            !body.contains(forbidden),
            "me body must not contain `{forbidden}`: {body}"
        );
    }
}

// --- CSRF guard on a protected state-changing route --------------------------

#[sqlx::test(migrations = "./migrations")]
async fn logout_without_csrf_token_is_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    // Authenticated POST /logout WITHOUT X-CSRF-Token -> 403.
    let mut resp = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("csrf"), "403 body is JSON {{error:csrf}}: {body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_with_matching_csrf_token_is_200(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    let resp = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_with_wrong_csrf_token_is_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let resp = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", "this-is-not-the-right-token", true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
}

// --- Pre-session Origin allowlist (Warning 2 fold-in) ------------------------

/// Test config WITH a non-empty allowlist so the origin guard is active.
fn cfg_with_allowlist() -> Config {
    let mut cfg = common::default_test_cfg();
    cfg.allowed_origins = vec!["https://console.example.com".to_string()];
    cfg
}

#[sqlx::test(migrations = "./migrations")]
async fn login_with_foreign_origin_is_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_allowlist()));

    let mut resp = TestClient::post("http://127.0.0.1:8080/login")
        .add_header("Origin", "https://evil.example.org", true)
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(
        body.contains("forbidden_origin"),
        "foreign-origin login is rejected: {body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn login_with_allowed_origin_passes_origin_check(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_allowlist()));

    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .add_header("Origin", "https://console.example.com", true)
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(&service)
        .await;
    // Allowed origin -> passes the origin gate and the credentials succeed (200).
    assert_eq!(resp.status_code, Some(StatusCode::OK));
}

// --- IP rate limiting on /login (429 past the quota) -------------------------

#[sqlx::test(migrations = "./migrations")]
async fn login_is_rate_limited(pool: PgPool) {
    // No admin needed: the limiter hoop runs BEFORE the handler, so even failing
    // logins consume the quota. Fire >10/min from the (shared fallback) IP.
    let service = Service::new(common::build_test_router(pool));

    let mut saw_429 = false;
    for _ in 0..15 {
        let resp = TestClient::post("http://127.0.0.1:8080/login")
            .json(&serde_json::json!({
                "email": "nobody@example.com",
                "password": "a-very-long-password"
            }))
            .send(&service)
            .await;
        if resp.status_code == Some(StatusCode::TOO_MANY_REQUESTS) {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, ">10 POST /login within a minute must yield at least one 429");
}
