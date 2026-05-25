//! Integration tests for the env-gated GitHub OAuth login (CAUTH-04, Plan 02-04).
//!
//! Two router configurations are exercised WITHOUT contacting real github.com:
//!
//! - **GitHub UNSET** (`cfg.github = None`): `/auth/github/login` does not exist
//!   (404) and `GET /api/console/state` reports `github_oauth_enabled:false`.
//! - **GitHub SET** (`cfg.github = Some(stub)`): `/auth/github/login` 302-
//!   redirects to `github.com/login/oauth/authorize` carrying a `state` param,
//!   sets the dedicated state-nonce cookie, and `github_oauth_enabled:true`.
//!   The callback's OAuth-CSRF guard denies (403) when the `state` does not
//!   match the nonce cookie (the link-or-deny path's first gate — exercised
//!   without a real code exchange).
//!
//! The real GitHub round-trip is the documented manual check in 02-VALIDATION.

mod common;

use ory_console_backend::config::{Config, GithubCfg};
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Test config WITH a stub GitHub OAuth configuration (id+secret present), so
/// `attach_github` mounts the routes and `github_oauth_enabled` is true.
fn cfg_with_github() -> Config {
    let mut cfg = common::default_test_cfg();
    cfg.github = Some(GithubCfg {
        client_id: "stub-client-id".to_string(),
        client_secret: "stub-client-secret".to_string(),
        redirect_url: Some("http://localhost:8080/auth/github/callback".to_string()),
    });
    cfg
}

// --- GitHub UNSET: routes absent + state flag false --------------------------

#[sqlx::test(migrations = "./migrations")]
async fn github_login_is_404_when_unconfigured(pool: PgPool) {
    // Default test cfg has github = None.
    let service = Service::new(common::build_test_router(pool));
    let resp = TestClient::get("http://127.0.0.1:8080/auth/github/login")
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "github login route must not exist when unconfigured"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn state_reports_github_disabled_when_unconfigured(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/state")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    assert!(
        body.contains("\"github_oauth_enabled\":false"),
        "state must report github disabled: {body}"
    );
}

// --- GitHub SET: login 302 with state nonce + state flag true ----------------

#[sqlx::test(migrations = "./migrations")]
async fn github_login_redirects_to_github_with_state(pool: PgPool) {
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_github()));
    let resp = TestClient::get("http://127.0.0.1:8080/auth/github/login")
        .send(&service)
        .await;

    assert_eq!(
        resp.status_code,
        Some(StatusCode::FOUND),
        "configured github login must 302 to github.com"
    );

    // Location header points at the GitHub authorize endpoint with a state param.
    let location = resp
        .headers
        .get(salvo::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header present")
        .to_string();
    assert!(
        location.starts_with("https://github.com/login/oauth/authorize"),
        "redirect targets github authorize: {location}"
    );
    assert!(
        location.contains("state="),
        "authorize URL carries a state param: {location}"
    );
    assert!(
        location.contains("read%3Auser") || location.contains("read:user"),
        "authorize URL requests read:user scope: {location}"
    );

    // The state nonce is stored in its OWN cookie, NOT the session cookie.
    let has_state_cookie = resp
        .cookies()
        .iter()
        .any(|c| c.name() == "console_oauth_state");
    assert!(
        has_state_cookie,
        "login sets the dedicated state-nonce cookie"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn state_reports_github_enabled_when_configured(pool: PgPool) {
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_github()));
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/state")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    assert!(
        body.contains("\"github_oauth_enabled\":true"),
        "state must report github enabled: {body}"
    );
}

// --- Callback OAuth-CSRF / link-or-deny gate ---------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn callback_with_missing_state_nonce_is_403(pool: PgPool) {
    // No state-nonce cookie set => the OAuth-CSRF guard denies before any code
    // exchange (never contacts github.com).
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_github()));
    let resp = TestClient::get("http://127.0.0.1:8080/auth/github/callback?code=abc&state=xyz")
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::FORBIDDEN),
        "callback without a matching state nonce must be denied (deny path)"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_with_mismatched_state_is_403(pool: PgPool) {
    // A state-nonce cookie is present but does NOT match the returned `state`
    // query param => OAuth-CSRF deny (constant-time compare fails). No exchange.
    let service = Service::new(common::build_test_router_cfg(pool, cfg_with_github()));
    let resp =
        TestClient::get("http://127.0.0.1:8080/auth/github/callback?code=abc&state=returned-state")
            .add_header("Cookie", "console_oauth_state=different-nonce", true)
            .send(&service)
            .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::FORBIDDEN),
        "mismatched state must be denied without auto-provisioning"
    );
}
