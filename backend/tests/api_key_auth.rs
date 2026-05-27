//! Integration tests for the Phase-19 (CLI-02) combined `api_key_or_session`
//! authenticator hoop on the protected subtree.
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations, then
//! drives the REAL production router (`common::build_test_router`) via Salvo's
//! in-process `TestClient`. We assert the load-bearing CLI-02 invariants WITHOUT
//! the live stack:
//!   - a valid `Authorization: Api-Key <raw>` request to a protected
//!     state-changing route SUCCEEDS (200) WITHOUT any X-CSRF-Token (csrf-exempt);
//!   - a revoked key → 401; a syntactically-plausible unknown key → 401;
//!   - no auth at all → 401 (unchanged);
//!   - the SESSION path is unchanged: a valid session doing the SAME PUT WITHOUT
//!     an X-CSRF-Token still 403s (CSRF only exempt for api-key);
//!   - the feature gate still applies: an api-key request to a saml-gated route
//!     while `saml` is OFF still 404s (FeatureFlagHoop runs after the
//!     authenticator — Pitfall 6).
//!
//! The header convention (`Authorization: Api-Key <raw>`) comes from
//! `console_core` — the single source of truth shared with the CLI.

mod common;

use ory_console_backend::apikeys::queries;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Compose the `Authorization: Api-Key <raw>` header value from the shared
/// console-core scheme constant.
fn api_key_header(raw: &str) -> String {
    format!("{} {}", console_core::API_KEY_SCHEME, raw)
}

/// Log in the seeded admin and return (raw session token, csrf token). Mirrors
/// `auth_middleware.rs` so the session-unchanged assertion uses the same path.
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

/// Read a feature flag's persisted enabled state directly (the source of truth)
/// so we can prove the api-key PUT actually flipped it through the route.
async fn flag_enabled(pool: &PgPool, key: &str) -> bool {
    let row = sqlx::query!(
        "SELECT enabled FROM feature_flags WHERE key = $1",
        key
    )
    .fetch_optional(pool)
    .await
    .expect("feature query");
    row.map(|r| r.enabled).unwrap_or(false)
}

#[sqlx::test(migrations = "./migrations")]
async fn valid_api_key_put_is_csrf_exempt_and_flips_the_flag(pool: PgPool) {
    // CLI-02 exemplar: api-key auth + csrf-exempt + goes through the real route.
    let issued = queries::issue_api_key(&pool, "cli-key", None)
        .await
        .expect("issue key");
    let service = Service::new(common::build_test_router(pool.clone()));

    // `account_experience` is a known, seeded-OFF flag that is NOT itself gated
    // (the features management route is never FeatureFlagHoop-gated). Toggle it ON
    // with NO X-CSRF-Token — the api-key path is CSRF-exempt.
    assert!(!flag_enabled(&pool, "account_experience").await, "seeded OFF");
    let resp = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .add_header("Authorization", api_key_header(&issued.raw), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "a valid api-key PUT with NO CSRF token succeeds (csrf-exempt)"
    );
    assert!(
        flag_enabled(&pool, "account_experience").await,
        "the PUT actually flipped the flag through the route (no second writer)"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoked_api_key_is_401(pool: PgPool) {
    let issued = queries::issue_api_key(&pool, "revoke-key", None)
        .await
        .expect("issue key");
    queries::revoke_api_key(&pool, issued.view.id)
        .await
        .expect("revoke")
        .expect("key exists");
    let service = Service::new(common::build_test_router(pool.clone()));

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .add_header("Authorization", api_key_header(&issued.raw), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "a revoked key is rejected (never falls through to the session path)"
    );
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("unauthenticated"), "401 JSON: {body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_api_key_is_401(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool.clone()));

    // A syntactically plausible but unknown raw key → 401 (fail-closed).
    let resp = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .add_header(
            "Authorization",
            api_key_header("zz-totally-unknown-but-plausible-key-0123456789"),
            true,
        )
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "an unknown key with the Api-Key scheme present is 401, not a session fall-through"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn no_auth_at_all_is_401(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));

    // Neither an Api-Key header nor a session cookie → 401 exactly as before.
    let resp = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[sqlx::test(migrations = "./migrations")]
async fn session_path_still_requires_csrf_token(pool: PgPool) {
    // T-19-05/T-19-07: the CSRF exemption is api-key-ONLY. A SESSION-authenticated
    // state change with NO X-CSRF-Token still 403s — the session path is unchanged.
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let resp = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::FORBIDDEN),
        "a session PUT without X-CSRF-Token still 403s (CSRF exemption is api-key-only)"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn api_key_to_flag_off_route_is_404(pool: PgPool) {
    // Pitfall 6 / T-19-08: the FeatureFlagHoop runs AFTER the authenticator, so an
    // api-key request to a saml-gated route while `saml` is OFF still 404s — the
    // api-key path does NOT bypass the feature gate. `GET /api/sso/connections` is
    // saml-gated and csrf-exempt (read), so a valid key reaching it still 404s.
    let issued = queries::issue_api_key(&pool, "flag-key", None)
        .await
        .expect("issue key");
    let service = Service::new(common::build_test_router(pool.clone()));

    let resp = TestClient::get("http://127.0.0.1:8080/api/sso/connections")
        .add_header("Authorization", api_key_header(&issued.raw), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "a saml-OFF gated route 404s even with a valid api-key (flag gate still applies)"
    );
}
