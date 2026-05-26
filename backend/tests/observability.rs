//! Integration tests for the Phase-16 observability console surfaces
//! (OBS-03/04/05 + FLAG-04 / FLAG-01).
//!
//! Extends the `feature_flags` TestClient harness. The `#[sqlx::test]` harness
//! seeds the `0007` flags (observability OFF by default); the flag-ON tests
//! toggle it ON through the management PUT (which refreshes the SAME cache the
//! router holds), exactly like `feature_flags.rs::flag_on_serves_route`.
//!
//! The four guarantees asserted here:
//!   - FLAG-01 / T-16-12: with observability OFF, the activity/logs/grafana
//!     routes 404 EVEN WITH a valid session + matching CSRF (the gate sits inside
//!     the protected subtree, after auth/csrf).
//!   - FLAG-04 / T-16-08: with observability ON but the profile DOWN (the default
//!     internal-DNS URLs are unreachable from the host test), the routes return a
//!     structured `profile_not_running` payload — status NOT 502/500.
//!   - T-16-09: an unknown PromQL/LogQL intent → 422 (no raw passthrough); this
//!     check runs BEFORE any upstream call.
//!   - T-16-10/11: the Grafana proxy injects X-WEBAUTH-USER (asserted against a
//!     mockito upstream) and rejects a `..` traversal in the wildcard path.

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Log in the seeded admin and return (raw session token, matching csrf token).
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

/// Toggle the `observability` flag ON through the management PUT (refreshes the
/// router-held cache so the gate opens for subsequent requests).
async fn enable_observability(service: &Service, raw: &str, csrf: &str) {
    let put = TestClient::put("http://127.0.0.1:8080/api/console/features/observability")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.to_string(), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(service)
        .await;
    assert_eq!(put.status_code, Some(StatusCode::OK), "toggle observability ON");
}

// --- FLAG-01 / T-16-12: flag-OFF → 404 past a valid session + CSRF -------------

/// With observability OFF (the seeded default), every observability route 404s
/// even with a valid session cookie + matching CSRF token — the gate beats both
/// guards (it sits inside the protected subtree after auth/csrf).
#[sqlx::test(migrations = "./migrations")]
async fn flag_off_returns_404_on_all_observability_routes(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    for path in [
        "/api/console/metrics/activity",
        "/api/console/logs",
        "/api/console/grafana/d/abc",
    ] {
        let resp = TestClient::get(format!("http://127.0.0.1:8080{path}"))
            .add_header("Cookie", format!("console_session={raw}"), true)
            .send(&service)
            .await;
        assert_eq!(
            resp.status_code,
            Some(StatusCode::NOT_FOUND),
            "flag-OFF {path} must 404 for an authenticated request (FLAG-01)"
        );
    }
}

// --- FLAG-04 / T-16-08: flag-ON + profile-DOWN → profile_not_running, not 502 --

/// With observability ON but the profile DOWN (the default `prometheus:9090`
/// etc. internal-DNS URLs are unreachable from the host test), the Activity route
/// returns a structured `profile_not_running` payload — status 200, NEVER 502/500.
#[sqlx::test(migrations = "./migrations")]
async fn activity_profile_down_is_profile_not_running_not_502(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/metrics/activity")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "profile-down Activity must be a 200 (tolerant), not a 502"
    );
    assert_ne!(resp.status_code, Some(StatusCode::BAD_GATEWAY), "never a raw 502");
    let json: serde_json::Value = resp.take_json().await.expect("activity json");
    assert_eq!(
        json["state"], "profile_not_running",
        "a down profile yields the structured profile_not_running state (FLAG-04)"
    );
    assert!(json["result"].is_null(), "no series when the profile is down");
}

/// The same FLAG-04 guarantee for the Loki logs route.
#[sqlx::test(migrations = "./migrations")]
async fn logs_profile_down_is_profile_not_running_not_502(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/logs")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "profile-down logs is a 200");
    assert_ne!(resp.status_code, Some(StatusCode::BAD_GATEWAY), "never a 502");
    let json: serde_json::Value = resp.take_json().await.expect("logs json");
    assert_eq!(json["state"], "profile_not_running");
}

// --- T-16-09: unknown intent → 422 (no raw PromQL/LogQL passthrough) -----------

/// An unknown Activity intent is rejected 422 BEFORE any upstream call — proving
/// the closed-intent parameterization (no raw operator PromQL passthrough).
#[sqlx::test(migrations = "./migrations")]
async fn unknown_activity_intent_is_422(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    // A raw PromQL string is NOT a known intent → 400-class rejection, never a
    // passthrough to Prometheus. (BadRequest renders as 400.)
    let resp = TestClient::get(
        "http://127.0.0.1:8080/api/console/metrics/activity?intent=up%7Bjob%3D%22kratos%22%7D",
    )
    .add_header("Cookie", format!("console_session={raw}"), true)
    .send(&service)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "an unknown intent is rejected, never passed through as raw PromQL (T-16-09)"
    );
}

/// An unknown Logs intent is likewise rejected (no raw LogQL passthrough).
#[sqlx::test(migrations = "./migrations")]
async fn unknown_logs_intent_is_rejected(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    let resp = TestClient::get(
        "http://127.0.0.1:8080/api/console/logs?intent=%7Bjob%3D%22x%22%7D%20%7C%3D%20%22secret%22",
    )
    .add_header("Cookie", format!("console_session={raw}"), true)
    .send(&service)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "an unknown log intent is rejected, never passed through as raw LogQL"
    );
}

// --- OBS-05 / T-16-10/11: Grafana proxy header injection + traversal reject ----

/// The Grafana proxy injects X-WEBAUTH-USER for the authenticated operator and
/// forwards to the FIXED Grafana origin. Asserted against a mockito upstream that
/// REQUIRES the header to match — if the proxy did not inject it, mockito would
/// not match and the proxy would surface a non-2xx.
#[sqlx::test(migrations = "./migrations")]
async fn grafana_proxy_injects_x_webauth_user(pool: PgPool) {
    let mut server = mockito::Server::new_async().await;

    // The mockito upstream stands in for Grafana. The proxy targets
    // {grafana_url}/grafana/{path}; we mock that path and REQUIRE the
    // X-WEBAUTH-USER header to be present (any value) — proving injection.
    let m = server
        .mock("GET", "/grafana/d/abc")
        .match_header("x-webauth-user", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "text/html")
        .with_body("<html>grafana</html>")
        .create_async()
        .await;

    // Build a test router whose grafana_url points at the mockito server.
    let cfg = ory_console_backend::config::Config {
        grafana_url: server.url(),
        ..common::default_test_cfg()
    };
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/grafana/d/abc")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;

    m.assert_async().await; // the upstream got the request WITH X-WEBAUTH-USER
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "the proxy forwards the upstream 200 back"
    );
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("grafana"), "the upstream body is forwarded: {body}");
}

/// A client-supplied X-WEBAUTH-USER header is STRIPPED and replaced by the
/// session-derived operator — a caller cannot spoof a different Grafana user
/// (T-16-10). The mockito upstream requires the header to NOT equal the spoofed
/// value.
#[sqlx::test(migrations = "./migrations")]
async fn grafana_proxy_strips_client_supplied_webauth_header(pool: PgPool) {
    let mut server = mockito::Server::new_async().await;
    // The injected operator is the session's admin_id — a UUID. The mock matches
    // ONLY when X-WEBAUTH-USER looks like a UUID (hex+dashes), which the spoofed
    // literal "attacker" can NEVER satisfy — so a match proves the proxy stripped
    // the client header and injected its own. (Rust's regex has no lookahead, so
    // we match the POSITIVE UUID shape rather than a negative-of-"attacker".)
    let m = server
        .mock("GET", "/grafana/home")
        .match_header(
            "x-webauth-user",
            mockito::Matcher::Regex("^[0-9a-fA-F-]{36}$".to_string()),
        )
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let cfg = ory_console_backend::config::Config {
        grafana_url: server.url(),
        ..common::default_test_cfg()
    };
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    let resp = TestClient::get("http://127.0.0.1:8080/api/console/grafana/home")
        .add_header("Cookie", format!("console_session={raw}"), true)
        // The attacker tries to spoof a Grafana identity — it must be stripped.
        .add_header("X-WEBAUTH-USER", "attacker", true)
        .send(&service)
        .await;

    m.assert_async().await; // matched only because the spoofed header was stripped
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "the proxy stripped the client X-WEBAUTH-USER and injected the operator's"
    );
}

/// A `..` traversal in the wildcard path is rejected (400) so the proxy can never
/// escape the Grafana origin (T-16-11). No upstream call is made.
#[sqlx::test(migrations = "./migrations")]
async fn grafana_proxy_rejects_path_traversal(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_observability(&service, &raw, &csrf).await;

    // Encoded `../../etc/passwd` in the wildcard segment. The proxy normalizes +
    // rejects the parent traversal before any upstream call.
    let resp = TestClient::get(
        "http://127.0.0.1:8080/api/console/grafana/..%2f..%2fetc%2fpasswd",
    )
    .add_header("Cookie", format!("console_session={raw}"), true)
    .send(&service)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "a path-traversal attempt is rejected, never proxied (T-16-11)"
    );
}
