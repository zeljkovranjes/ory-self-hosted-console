//! Integration tests for the config-edit API (`GET`/`PUT
//! /api/config/<service>/<section>`) — BACK-04 / BACK-06.
//!
//! `#[sqlx::test]` provisions an isolated DB + runs migrations; Salvo's
//! in-process `TestClient` drives the SAME production router the binary serves
//! (`common::build_test_router_cfg` -> `routes::build`). We point the test
//! `Config`'s `config_dir` at a throwaway [`common::ConfigFixture`] holding a
//! copy of the live no-`session:`/no-`dsn` `config/kratos/kratos.yml`, so every
//! "file unchanged" assertion is deterministic and the LIVE restart broker /
//! Ory stack are NOT required (the valid-apply-restarts-healthy proof is the
//! live `scripts/verify/phase4-acceptance.sh` gate's job — see that script).
//!
//! These tests cover exactly the behaviors that do NOT need the live stack:
//!   - unauthenticated GET/PUT -> 401 `unauthenticated`
//!   - authenticated GET omits the ABSENT allowlisted pointers (no null) and
//!     never surfaces a secret/denylisted value (`dsn`/`secrets`/`serve.admin`)
//!   - authenticated PUT without `X-CSRF-Token` -> 403 `csrf`
//!   - authenticated PUT + matching CSRF + a SCHEMA-INVALID body -> 422
//!     `validation_failed` with a non-empty `fields[].path` AND the on-disk file
//!     UNCHANGED (validation rejects before disk; the dsn overlay does not mask a
//!     real schema error)
//!   - authenticated PUT of an OUT-OF-SCOPE / sensitive pointer -> 403
//!     `forbidden_key` with the file UNCHANGED (BACK-06)
//!   - concurrency: a held per-service lock makes a concurrent PUT -> 409
//!     `config_busy`

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;
use tokio::sync::Mutex;

/// Process-wide serialization for tests that issue an authenticated PUT which
/// reaches the handler's STEP 1 (`locks::try_acquire("kratos")`).
///
/// `#[sqlx::test]` runs tests concurrently within ONE process, and the config
/// lock registry is a process-wide `static` (correct for production: one backend
/// instance). A test that deliberately HOLDS the kratos lock to prove the 409
/// `config_busy` path would otherwise make a parallel PUT test see 409 instead
/// of its own expected 403/422. Serializing the PUT-issuing tests through this
/// mutex removes that cross-test interference WITHOUT weakening any assertion —
/// each test still exercises the real production handler end-to-end.
static PUT_TEST_SERIAL: Mutex<()> = Mutex::const_new(());

/// Log in the seeded admin and return `(raw session token, csrf token)`.
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

/// Read the on-disk bytes of the fixture's kratos.yml (for unchanged assertions).
fn read_fixture(fixture: &common::ConfigFixture) -> Vec<u8> {
    std::fs::read(fixture.kratos_yml()).expect("read fixture kratos.yml")
}

// --- Unauthenticated GET/PUT -> 401 (single auth chokepoint) -----------------

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_get_is_401(pool: PgPool) {
    let fixture = common::ConfigFixture::new();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/config/kratos/session")
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
async fn unauthenticated_put_is_401(pool: PgPool) {
    let fixture = common::ConfigFixture::new();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/session")
        .json(&serde_json::json!({ "/session/lifespan": "24h" }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    // The unauthenticated PUT never reaches the engine, so the file is untouched.
    assert_eq!(read_fixture(&fixture), before, "unauth PUT must not write");
}

// --- Authenticated GET: omit-absent + secret-free ----------------------------

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_get_omits_absent_and_leaks_no_secret(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/config/kratos/session")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();

    // The fixture ships NO `session:` block, so the response is an EMPTY object:
    // every allowlisted pointer is ABSENT and therefore OMITTED (no null, no key).
    let json: serde_json::Value = serde_json::from_str(&body).expect("GET returns JSON");
    let obj = json.as_object().expect("object response");
    assert!(obj.is_empty(), "all absent allowlisted pointers omitted: {obj:?}");
    assert!(!body.contains("/session/lifespan"), "absent pointer must be omitted");
    assert!(!body.contains("null"), "no null emitted for an absent pointer");

    // ...and the response never carries a secret/denylisted value even though the
    // fixture contains them (the response is built solely from the allowlist).
    assert!(!body.contains("dsn"), "dsn must never appear: {body}");
    assert!(!body.contains("secrets"), "secrets must never appear: {body}");
    assert!(!body.contains("PLACEHOLDERcookie"), "secret value must never appear");
    assert!(!body.contains("base_url"), "serve.admin must never appear");
}

// --- Authenticated PUT without CSRF -> 403 csrf -------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_without_csrf_is_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    // Authenticated PUT WITHOUT X-CSRF-Token -> 403 (state-changing, not exempted).
    let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/session")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&serde_json::json!({ "/session/lifespan": "24h" }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("csrf"), "403 body is JSON {{error:csrf}}: {body}");
    // The CSRF guard runs before the handler, so nothing is written.
    assert_eq!(read_fixture(&fixture), before, "CSRF-rejected PUT must not write");
}

// --- Authenticated PUT, schema-INVALID -> 422 + file unchanged ----------------

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_invalid_is_422_no_write(pool: PgPool) {
    // Serialize vs. the lock-holding concurrency test (process-wide lock registry).
    let _serial = PUT_TEST_SERIAL.lock().await;
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // `/session/lifespan` is a duration string matching `^([0-9]+(ns|us|ms|s|m|h))+$`.
    // A non-duration string FAILS the schema pattern. Crucially the dsn overlay
    // (effective_for_validation) supplies the env-injected `dsn` required key —
    // it does NOT paper over this real shape error, so we still get a 422.
    let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/session")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({ "/session/lifespan": "not-a-valid-duration" }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "schema-invalid value must be 422 even with the dsn overlay applied"
    );
    let body = resp.take_string().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).expect("422 returns JSON");
    assert_eq!(json["error"], "validation_failed", "422 machine code: {body}");
    let fields = json["fields"].as_array().expect("fields array present");
    assert!(!fields.is_empty(), "validation 422 carries field errors: {body}");
    assert!(
        fields.iter().any(|f| f["path"].as_str().is_some_and(|p| !p.is_empty())),
        "at least one field error has a non-empty path: {body}"
    );
    // No secret/value leak in the field errors.
    assert!(!body.contains("dsn"), "dsn must never appear in 422 body: {body}");
    assert!(!body.contains("postgres://"), "no DSN value in 422 body");

    // Success criterion 1: validation rejects BEFORE any disk write.
    assert_eq!(read_fixture(&fixture), before, "invalid PUT must not write to disk");
}

// --- Authenticated PUT, OUT-OF-SCOPE / sensitive -> 403 forbidden_key ---------

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_forbidden_key_is_403_no_write(pool: PgPool) {
    // Serialize vs. the lock-holding concurrency test (process-wide lock registry).
    let _serial = PUT_TEST_SERIAL.lock().await;
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // Each of these is rejected by the allowlist/denylist BEFORE merge/disk:
    //   - `/dsn`                -> hard sensitive denylist (env-injected secret)
    //   - `/secrets/cookie/0`   -> hard sensitive denylist (crypto secret)
    //   - `/serve/admin/base_url` -> hard sensitive denylist (admin listener)
    //   - `/identity/default_schema_id` -> out-of-scope (not in the section allowlist)
    for ptr in [
        "/dsn",
        "/secrets/cookie/0",
        "/serve/admin/base_url",
        "/identity/default_schema_id",
    ] {
        let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/session")
            .add_header("Cookie", format!("console_session={raw}"), true)
            .add_header("X-CSRF-Token", csrf.clone(), true)
            .json(&serde_json::json!({ ptr: "anything" }))
            .send(&service)
            .await;
        assert_eq!(
            resp.status_code,
            Some(StatusCode::FORBIDDEN),
            "{ptr} must be rejected with 403 forbidden_key"
        );
        let body = resp.take_string().await.unwrap();
        assert!(
            body.contains("forbidden"),
            "403 body is JSON {{error:forbidden}} for {ptr}: {body}"
        );
        // The rejected pointer's value is never echoed.
        assert!(!body.contains("anything"), "rejected value must not be echoed: {body}");
    }

    // BACK-06: no out-of-scope/sensitive PUT ever wrote to disk.
    assert_eq!(read_fixture(&fixture), before, "forbidden_key PUT must not write");
}

// --- Concurrency: a held lock -> the concurrent PUT is 409 config_busy --------

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_put_is_409_config_busy(pool: PgPool) {
    use ory_console_backend::config_edit::locks;

    // Serialize vs. the other PUT tests: this test deliberately HOLDS the global
    // kratos lock, which would otherwise make their PUTs see 409 (process-wide
    // lock registry shared by all tests in this binary).
    let _serial = PUT_TEST_SERIAL.lock().await;
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // Hold the per-service write lock to simulate a save already in progress for
    // `kratos`. The PUT handler's step 1 (`locks::try_acquire`) must then fail
    // WITHOUT waiting -> 409 config_busy, exercising the busy path without a real
    // restart. (The lock registry is process-wide, shared with the handler.)
    let guard = locks::try_acquire("kratos").await.expect("hold the kratos lock");

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/session")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({ "/session/lifespan": "24h" }))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::CONFLICT),
        "a PUT while the kratos lock is held must be 409 config_busy"
    );
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("conflict"), "409 body is JSON {{error:conflict}}: {body}");

    // Releasing the held lock frees the service for a later write.
    drop(guard);
    assert!(
        locks::try_acquire("kratos").await.is_ok(),
        "kratos re-acquires after the held guard is dropped"
    );
}
