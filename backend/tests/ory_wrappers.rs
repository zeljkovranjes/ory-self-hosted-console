//! Wave-0 integration tests for the Phase 3 Ory Admin proof wrappers (BACK-02).
//!
//! Two tiers:
//!
//! 1. `ory_routes_require_auth` — ALWAYS runs, NO live stack needed. Drives the
//!    SAME production router via Salvo's in-process `TestClient` and asserts that
//!    an UNAUTHENTICATED `GET` to each of the three proof routes returns 401
//!    (the `auth_guard` chokepoint, T-03-10). A 200 here is a hard FAIL
//!    (anti-false-green): the wrappers must never be reachable without a session.
//!
//! 2. `kratos_identities_live` / `hydra_clients_live` / `keto_read_live` — gated
//!    behind `ORY_LIVE_TESTS=1`. They require `docker compose up -d --wait`. When
//!    the gate is unset they print an explicit `SKIP:` line and return — a skip is
//!    NEVER a silent pass (RESEARCH anti-false-green). When enabled they seed an
//!    admin + obtain a session cookie, seed ONE Kratos identity via the typed
//!    admin crate (so the list is non-empty — Criterion 2 seed step), then GET the
//!    wrapper route WITH the cookie and assert 200 AND a well-formed JSON body of
//!    the expected shape (Kratos: a NON-empty array; Hydra: an array, possibly
//!    empty — Pitfall 4; Keto: an object with `relation_tuples`). Each also
//!    asserts the response body leaks NO admin host:port (`4434`/`4445`/`4466`).

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// The three REQUIRED proof routes (Oathkeeper is an optional bonus, not gated).
const PROOF_ROUTES: [&str; 3] = [
    "http://127.0.0.1:8080/api/kratos/identities",
    "http://127.0.0.1:8080/api/hydra/clients",
    "http://127.0.0.1:8080/api/keto/relationships",
];

// =============================================================================
// Tier 1 — ALWAYS-ON: unauthenticated wrapper routes -> 401 (no live stack).
// =============================================================================

/// Proves T-03-10 (EoP — unauthenticated reach): each Ory wrapper sits on the
/// protected subtree behind `auth_guard`, so a request with NO session cookie is
/// rejected with 401 BEFORE the handler runs (it never touches a live Ory
/// service). A 200/2xx is a hard FAIL — the route must not be reachable unauthed.
#[sqlx::test(migrations = "./migrations")]
async fn ory_routes_require_auth(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));

    for route in PROOF_ROUTES {
        let resp = TestClient::get(route).send(&service).await;
        assert_eq!(
            resp.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "unauthenticated GET {route} must be 401 (auth_guard); a non-401 means the wrapper is reachable without a session"
        );
    }

    // Bonus route gets the same treatment (defense in depth, not gated).
    let resp = TestClient::get("http://127.0.0.1:8080/api/oathkeeper/rules")
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "unauthenticated GET /api/oathkeeper/rules must be 401 (auth_guard)"
    );
}

// =============================================================================
// Tier 2 — ORY_LIVE_TESTS-gated live data-path reads (need `compose up --wait`).
// =============================================================================

/// True only when `ORY_LIVE_TESTS` is set. When false, the caller MUST print a
/// `SKIP:` line and return — a gated test never silently passes.
fn live_enabled() -> bool {
    std::env::var("ORY_LIVE_TESTS").is_ok()
}

/// Seed an admin, log in, and return the raw session-cookie token for an
/// authenticated GET. Mirrors the Phase-2 `auth_middleware` flow. GET routes are
/// csrf-exempt, so no `X-CSRF-Token` is needed.
async fn authed_cookie(service: &Service, pool: &PgPool) -> String {
    common::seed_admin(pool, "live-owner@example.com", "a-very-long-password").await;
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "live-owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "live login should succeed");
    common::obtain_session_cookie(&resp).expect("session cookie after login")
}

/// Assert the response body contains NONE of the admin host:port URLs — the
/// wrapper must surface Ory RESOURCE data, never the internal ADMIN URLs.
///
/// We match the admin URL `host:port` shape (e.g. `kratos:4434`, `:4445`), NOT a
/// bare port-number substring: a legitimately-returned resource UUID can contain
/// digits like `4434` by chance (e.g. a recovery-address id), which is not a URL
/// leak. The defense is against an internal ADMIN endpoint URL escaping into the
/// client-facing body — that always carries the service host and `:port`.
fn assert_no_admin_url_leak(body: &str) {
    // The admin URLs the backend holds are `http://<svc>:<adminport>`. Kratos's
    // PUBLIC base (`:4433`) legitimately appears in `schema_url`; only the ADMIN
    // host:port pairs below must never leak.
    for marker in [
        "kratos:4434",
        "hydra:4445",
        "keto:4466",
        "keto:4467",
        "oathkeeper:4456",
    ] {
        assert!(
            !body.contains(marker),
            "wrapper response body leaked an admin URL `{marker}`: {body}"
        );
    }
}

/// Criterion 1 (Kratos): seed ONE identity via the typed admin crate so the list
/// is non-empty, then the authenticated wrapper GET returns 200 + a NON-empty
/// JSON array. Gated on `ORY_LIVE_TESTS`.
#[sqlx::test(migrations = "./migrations")]
async fn kratos_identities_live(pool: PgPool) {
    if !live_enabled() {
        println!("SKIP: kratos_identities_live (set ORY_LIVE_TESTS=1 with the stack up to run)");
        return;
    }

    // Seed one identity matching config/kratos/identity.schema.json (schema_id
    // "default", required trait `email`). A 409 (already seeded on re-run) is fine.
    let clients = common::ory_clients_from_env();
    let body = ory_kratos_client::models::CreateIdentityBody::new(
        "default".to_string(),
        serde_json::json!({ "email": "seed@example.com" }),
    );
    match ory_kratos_client::apis::identity_api::create_identity(&clients.kratos, Some(body)).await {
        Ok(_) => {}
        Err(ory_kratos_client::apis::Error::ResponseError(rc))
            if rc.status == reqwest::StatusCode::CONFLICT =>
        {
            // Already present from a prior run — the list is still non-empty.
        }
        Err(e) => panic!("seed identity failed: {e:?}"),
    }

    let service = Service::new(common::build_test_router(pool.clone()));
    let cookie = authed_cookie(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/kratos/identities")
        .add_header("Cookie", format!("console_session={cookie}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "authed GET /api/kratos/identities should be 200 against the live stack"
    );
    let text = resp.take_string().await.expect("kratos body");
    let json: serde_json::Value = serde_json::from_str(&text).expect("kratos body is JSON");
    let arr = json.as_array().expect("kratos identities is a JSON array");
    assert!(
        !arr.is_empty(),
        "kratos identity list must be NON-empty after seeding (anti-false-green): {text}"
    );
    assert_no_admin_url_leak(&text);
}

/// Criterion 1 (Hydra): the authenticated wrapper GET returns 200 + a JSON array.
/// An EMPTY array is a VALID live response on a fresh Hydra (Pitfall 4). Gated.
#[sqlx::test(migrations = "./migrations")]
async fn hydra_clients_live(pool: PgPool) {
    if !live_enabled() {
        println!("SKIP: hydra_clients_live (set ORY_LIVE_TESTS=1 with the stack up to run)");
        return;
    }

    let service = Service::new(common::build_test_router(pool.clone()));
    let cookie = authed_cookie(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/hydra/clients")
        .add_header("Cookie", format!("console_session={cookie}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "authed GET /api/hydra/clients should be 200 against the live stack"
    );
    let text = resp.take_string().await.expect("hydra body");
    let json: serde_json::Value = serde_json::from_str(&text).expect("hydra body is JSON");
    assert!(
        json.is_array(),
        "hydra clients must be a JSON array (empty is valid — Pitfall 4): {text}"
    );
    assert_no_admin_url_leak(&text);
}

/// Criterion 1 (Keto): the authenticated wrapper GET returns 200 + a JSON object
/// carrying `relation_tuples`. An empty tuple list is valid on a fresh store. Gated.
#[sqlx::test(migrations = "./migrations")]
async fn keto_read_live(pool: PgPool) {
    if !live_enabled() {
        println!("SKIP: keto_read_live (set ORY_LIVE_TESTS=1 with the stack up to run)");
        return;
    }

    let service = Service::new(common::build_test_router(pool.clone()));
    let cookie = authed_cookie(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/keto/relationships")
        .add_header("Cookie", format!("console_session={cookie}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "authed GET /api/keto/relationships should be 200 against the live stack"
    );
    let text = resp.take_string().await.expect("keto body");
    let json: serde_json::Value = serde_json::from_str(&text).expect("keto body is JSON");
    assert!(
        json.get("relation_tuples").is_some(),
        "keto relationships response must carry `relation_tuples` (empty is valid): {text}"
    );
    assert_no_admin_url_leak(&text);
}
