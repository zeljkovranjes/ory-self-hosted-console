//! Integration tests for the Phase-12 feature-toggle keystone (FLAG-01/02/04).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (incl. `0007`, which seeds saml=OFF … opl_live_validation=ON). Salvo's
//! in-process `TestClient` drives the SAME router the binary serves
//! (`common::build_test_router` delegates to `routes::build` with the seeded
//! feature-flag cache). The dev cookie name `console_session` is in force
//! (test config sets `insecure_cookies`).
//!
//! The SINGLE most important assertion of the phase is FLAG-01: a flag-OFF gated
//! route returns 404 from the backend EVEN WITH a valid session cookie AND a
//! matching X-CSRF-Token — proving the gate is server-side, sits INSIDE the
//! protected subtree (after auth_guard/csrf_guard), and survives both guards.

mod common;

use ory_console_backend::features::queries;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Log in the seeded admin and return (raw session token, matching csrf token).
/// Mirrors `auth_middleware.rs::login_and_get_session`.
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

// --- FLAG-01: the keystone -----------------------------------------------------

/// THE keystone assertion. A state-changing POST to the gated probe carrying a
/// VALID session cookie AND a matching X-CSRF-Token returns 404 (NOT 401/403)
/// while `saml` is seeded OFF — the gate beats BOTH guards. Also exercises the
/// csrf-exempt GET to prove a read past auth is gated the same way.
#[sqlx::test(migrations = "./migrations")]
async fn flag_off_returns_404_with_valid_session_and_csrf(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // State-changing verb + a VALID session + a MATCHING CSRF token. If the gate
    // were merely auth/CSRF this would be 200; because the saml flag is OFF and the
    // FeatureFlagHoop sits AFTER both guards, it is 404.
    let resp = TestClient::post("http://127.0.0.1:8080/api/features/_probe")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "flag-OFF gated route must 404 past a valid session + matching CSRF (FLAG-01)"
    );

    // The csrf-exempt GET (also authenticated) is gated identically.
    let resp_get = TestClient::get("http://127.0.0.1:8080/api/features/_probe")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp_get.status_code,
        Some(StatusCode::NOT_FOUND),
        "flag-OFF gated GET must 404 for an authenticated request"
    );
}

/// Positive control: after toggling `saml` ON via the PUT route (which refreshes
/// the router-held cache), the gated probe falls through to its handler → 200.
#[sqlx::test(migrations = "./migrations")]
async fn flag_on_serves_route(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // Toggle saml ON through the management PUT (refreshes the same cache the
    // probe's hoop reads).
    let put = TestClient::put("http://127.0.0.1:8080/api/console/features/saml")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(put.status_code, Some(StatusCode::OK), "toggle saml ON");

    // Now the gated probe runs.
    let mut resp = TestClient::get("http://127.0.0.1:8080/api/features/_probe")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "flag-ON gated route falls through to the handler (200)"
    );
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("probe"), "the probe handler ran: {body}");
}

// --- FLAG-02: GET /api/console/features ----------------------------------------

/// The read route returns the full seeded set with enabled + label, and
/// `observability` carries `requires_runtime: true`.
#[sqlx::test(migrations = "./migrations")]
async fn get_features_returns_seeded_set(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/features")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let json: serde_json::Value = resp.take_json().await.expect("features json");
    let features = &json["features"];

    // All six seeded keys present with enabled + label.
    for key in [
        "saml",
        "organizations",
        "account_experience",
        "observability",
        "event_streams",
        "opl_live_validation",
    ] {
        assert!(features.get(key).is_some(), "key {key} present");
        assert!(features[key]["label"].is_string(), "{key} has a label");
    }

    // Seeded states: external-setup OFF, opl_live_validation ON.
    assert_eq!(features["saml"]["enabled"], serde_json::json!(false));
    assert_eq!(
        features["opl_live_validation"]["enabled"],
        serde_json::json!(true)
    );

    // observability carries requires_runtime:true; a non-runtime flag omits it.
    assert_eq!(
        features["observability"]["requires_runtime"],
        serde_json::json!(true),
        "observability advertises requires_runtime"
    );
    assert!(
        features["saml"].get("requires_runtime").is_none(),
        "a non-runtime flag omits requires_runtime (skip_serializing_if)"
    );
}

// --- FLAG-04: idempotent seed --------------------------------------------------

/// Running the migrations a second time leaves the seed intact and errors on
/// neither run (idempotent `ON CONFLICT DO NOTHING`).
#[sqlx::test(migrations = "./migrations")]
async fn seed_defaults_idempotent(pool: PgPool) {
    // First state (already applied by the harness).
    let first = queries::load_all(&pool).await.expect("load_all");
    assert_eq!(first.get("saml"), Some(&false), "saml seeded OFF");
    assert_eq!(
        first.get("opl_live_validation"),
        Some(&true),
        "opl_live_validation seeded ON"
    );
    assert_eq!(first.len(), 6, "exactly six seeded flags");

    // Re-run migrations — must not error and must not change the seed.
    common::run_migrations(&pool)
        .await
        .expect("re-running migrations is idempotent");

    let second = queries::load_all(&pool).await.expect("load_all after re-run");
    assert_eq!(first, second, "the seed is unchanged after a re-run");
}

// --- FLAG-04: PUT toggle + audit + unknown-key ---------------------------------

/// PUT toggles a flag (reflected on a re-read via the query layer) and an unknown
/// key returns 404 (never creates a row). The state-changing PUT is recorded by
/// the existing response-phase audit hoop (asserted via the audit log table).
#[sqlx::test(migrations = "./migrations")]
async fn put_toggles_and_audits(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // Toggle organizations ON.
    let put = TestClient::put("http://127.0.0.1:8080/api/console/features/organizations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(put.status_code, Some(StatusCode::OK), "toggle succeeds");

    // The DB reflects the new state on a re-read.
    let state = queries::load_all(&pool).await.expect("reload");
    assert_eq!(
        state.get("organizations"),
        Some(&true),
        "the toggle is persisted"
    );

    // The response-phase audit hoop recorded the state-changing PUT.
    let audit_count = sqlx::query!(
        "SELECT count(*) AS n FROM console_audit_log WHERE method = 'PUT' AND path LIKE '%features%'"
    )
    .fetch_one(&pool)
    .await
    .expect("audit query");
    assert!(
        audit_count.n.unwrap_or(0) >= 1,
        "the PUT toggle is recorded by the audit hoop"
    );

    // An unknown key → 404 (never creates a row).
    let unknown = TestClient::put("http://127.0.0.1:8080/api/console/features/not_a_real_flag")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        unknown.status_code,
        Some(StatusCode::NOT_FOUND),
        "an unknown flag key returns 404"
    );
    let after = queries::load_all(&pool).await.expect("reload after unknown");
    assert_eq!(after.len(), 6, "no row was created for the unknown key");
}

// --- FLAG-04 / T-12-07: requires_runtime never 502 -----------------------------

/// Flipping a `requires_runtime` flag (`observability`) ON returns 2xx — this
/// phase stores the marker only and wires NO 502 path (Phase 16 owns the probe).
#[sqlx::test(migrations = "./migrations")]
async fn requires_runtime_never_502(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    let resp = TestClient::put("http://127.0.0.1:8080/api/console/features/observability")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "a requires_runtime flag turned ON must NOT 502 in this phase (T-12-07)"
    );
    assert_ne!(
        resp.status_code,
        Some(StatusCode::BAD_GATEWAY),
        "no 502 path is wired this phase"
    );
}
