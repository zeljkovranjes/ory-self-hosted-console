//! Integration + unit tests for the identity-schema editor (IDENT-03) — the
//! dedicated `GET`/`PUT /api/kratos/identity-schema` route that reuses the
//! Phase-4 config-edit engine (validate -> backup -> atomic-write -> restart ->
//! health-poll -> rollback) but validates the operator JSON AS a draft-07 JSON
//! Schema (Pitfall 5 / A3) and writes the schema FILE with serde_json (not YAML).
//!
//! Mirrors `config_edit_api.rs`: Salvo's in-process `TestClient` drives the SAME
//! production router the binary serves (`common::build_test_router_cfg` ->
//! `routes::build`); the test `Config`'s `config_dir` points at a throwaway
//! [`common::ConfigFixture`] that seeds a valid `kratos/identity.schema.json`, so
//! "file unchanged" assertions are deterministic and the LIVE restart broker / Ory
//! stack are NOT required for the offline tier.
//!
//! Tier-1 (always-on, no live stack):
//!   - unauthenticated GET/PUT -> 401 `unauthenticated`
//!   - authenticated PUT without `X-CSRF-Token` -> 403 `csrf` (file unchanged)
//!   - authenticated PUT of an INVALID schema (non-draft-07 OR missing
//!     `properties.traits`) -> 422 `validation_failed`, file UNCHANGED (no broker
//!     call, no disk write — validation rejects before any side effect)
//!   - offline unit coverage delegating to `validate_identity_schema`
//!
//! Tier-2 (ORY_LIVE_TESTS=1): write -> restart -> healthy, and the rollback path.
//! An explicit SKIP line is printed when the gate is unset (no silent pass).

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

use ory_console_backend::config_edit::schema::validate_identity_schema;

/// A valid draft-07 identity schema (with properties.traits) the operator might PUT.
fn valid_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Person",
        "type": "object",
        "properties": {
            "traits": {
                "type": "object",
                "properties": {
                    "email": { "type": "string", "format": "email", "title": "E-Mail" },
                    "name": { "type": "string", "title": "Name" }
                },
                "required": ["email"],
                "additionalProperties": false
            }
        }
    })
}

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

/// Read the on-disk bytes of the fixture's identity.schema.json (unchanged checks).
fn read_schema_file(fixture: &common::ConfigFixture) -> Vec<u8> {
    std::fs::read(fixture.identity_schema_json()).expect("read fixture identity.schema.json")
}

// =============================================================================
// Tier-1: offline unit coverage of validate_identity_schema (reject paths)
// =============================================================================

#[test]
fn unit_valid_schema_accepted() {
    assert!(
        validate_identity_schema(&valid_schema()).is_ok(),
        "a draft-07-valid schema with properties.traits must validate"
    );
}

#[test]
fn unit_non_schema_rejected_layer1() {
    // `{"type": 123}` is not a valid JSON Schema -> Layer 1 (metaschema) rejects.
    let bad = serde_json::json!({ "type": 123, "properties": { "traits": { "type": "object" } } });
    let errs = validate_identity_schema(&bad).expect_err("non-schema must be rejected");
    assert!(!errs.is_empty(), "expected metaschema field errors");
    // Value-free: the offending value must not be echoed.
    for e in &errs {
        assert!(!e.message.contains("123"), "message must be value-free: {}", e.message);
    }
}

#[test]
fn unit_missing_traits_rejected_layer2() {
    // A draft-07-valid schema WITHOUT properties.traits -> Layer 2 rejects at
    // /properties/traits (Kratos requires it, A3).
    let no_traits = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": { "not_traits": { "type": "string" } }
    });
    let errs =
        validate_identity_schema(&no_traits).expect_err("missing properties.traits rejected");
    assert!(
        errs.iter().any(|e| e.path == "/properties/traits"),
        "expected a /properties/traits field error; got {errs:?}"
    );
}

// =============================================================================
// Tier-1: unauthenticated GET/PUT -> 401 (single auth chokepoint, T-06-13)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_get_schema_is_401(pool: PgPool) {
    let fixture = common::ConfigFixture::new();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/kratos/identity-schema")
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
async fn unauthenticated_put_schema_is_401_no_write(pool: PgPool) {
    let fixture = common::ConfigFixture::new();
    let before = read_schema_file(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let resp = TestClient::put("http://127.0.0.1:8080/api/kratos/identity-schema")
        .json(&valid_schema())
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    // The unauthenticated PUT never reaches the engine -> file untouched.
    assert_eq!(
        read_schema_file(&fixture),
        before,
        "unauth PUT must not write the schema file"
    );
}

// =============================================================================
// Tier-1: authenticated PUT without CSRF -> 403 csrf (T-06-14)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_schema_without_csrf_is_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_schema_file(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/kratos/identity-schema")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&valid_schema())
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("csrf"), "403 body is JSON {{error:csrf}}: {body}");
    // The CSRF guard runs before the handler -> nothing written.
    assert_eq!(
        read_schema_file(&fixture),
        before,
        "CSRF-rejected PUT must not write the schema file"
    );
}

// =============================================================================
// Tier-1: authenticated PUT, INVALID schema -> 422 + file unchanged (Pitfall 5)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_invalid_schema_is_422_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_schema_file(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // A draft-07-VALID schema that omits properties.traits: rejected by Layer 2
    // (422) BEFORE any backup/write/broker call. (No mockito broker is wired here
    // precisely because a validation failure must never reach the restart broker.)
    let invalid = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": { "not_traits": { "type": "string" } }
    });

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/kratos/identity-schema")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&invalid)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "an invalid identity schema must be 422"
    );
    let body = resp.take_string().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).expect("422 returns JSON");
    assert_eq!(json["error"], "validation_failed", "422 machine code: {body}");
    let fields = json["fields"].as_array().expect("fields array present");
    assert!(!fields.is_empty(), "validation 422 carries field errors: {body}");
    assert!(
        fields
            .iter()
            .any(|f| f["path"].as_str() == Some("/properties/traits")),
        "the missing-traits error must carry the /properties/traits path: {body}"
    );

    // Success criterion: validation rejects BEFORE any disk write.
    assert_eq!(
        read_schema_file(&fixture),
        before,
        "invalid-schema PUT must not write the schema file"
    );
    // No backup is created either (validation precedes the backup step). The
    // engine's backup path is `<file>.bak` (yaml::backup appends ".bak").
    let mut bak = fixture.identity_schema_json().into_os_string();
    bak.push(".bak");
    assert!(
        !std::path::Path::new(&bak).exists(),
        "no .bak should be created on a pre-write validation failure"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_put_non_schema_is_422_no_write(pool: PgPool) {
    // A body that is valid JSON but NOT a valid JSON Schema (Layer 1 reject).
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let before = read_schema_file(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    let non_schema = serde_json::json!({ "type": 123, "properties": { "traits": { "type": "object" } } });

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/kratos/identity-schema")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&non_schema)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let body = resp.take_string().await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
        "validation_failed"
    );
    // Value-free: the offending value (123) must never appear in the 422 body.
    assert!(!body.contains("123"), "422 body must be value-free: {body}");
    assert_eq!(
        read_schema_file(&fixture),
        before,
        "non-schema PUT must not write the schema file"
    );
}

// =============================================================================
// Tier-1: authenticated GET returns the active schema verbatim
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_get_returns_active_schema(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = common::ConfigFixture::new();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/kratos/identity-schema")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).expect("GET returns JSON");
    // The active schema's properties.traits is what drives the form (RESEARCH P6).
    assert!(
        json["properties"]["traits"].is_object(),
        "GET must return the active schema with properties.traits: {body}"
    );
    assert_eq!(
        json["properties"]["traits"]["properties"]["email"]["format"],
        serde_json::json!("email"),
        "the seeded schema's email trait must round-trip through GET: {body}"
    );
}

// =============================================================================
// Tier-2: live write -> restart -> healthy + rollback (ORY_LIVE_TESTS=1)
// =============================================================================

/// Live IDENT-03 write/restart/rollback. Requires `ORY_LIVE_TESTS=1` AND a running
/// compose stack (Kratos + restart broker reachable on the internal network).
/// Prints an explicit SKIP line when the gate is unset (no silent pass).
#[tokio::test]
async fn live_schema_write_restart_recover() {
    if std::env::var("ORY_LIVE_TESTS").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_schema_write_restart_recover: ORY_LIVE_TESTS!=1 \
             (gated write->restart->healthy + rollback against the live Kratos stack)"
        );
        return;
    }

    // When the gate IS set the test must run against the compose stack. The live
    // write/restart/rollback round-trip (valid schema -> healthy 200; GET reflects
    // it; a Kratos-rejecting schema -> health-timeout rollback to last-known-good)
    // is exercised by `scripts/verify/phase6-acceptance.sh`, which brings up the
    // stack with a writable mounted schema file and a reachable restart broker —
    // an environment a host-side `cargo test` does not provide. Failing loudly
    // here (rather than silently passing) makes the gating contract explicit.
    panic!(
        "ORY_LIVE_TESTS=1 set: run the live IDENT-03 write/restart/rollback via \
         scripts/verify/phase6-acceptance.sh (needs the compose stack + writable \
         schema mount + restart broker), not a host-side cargo test"
    );
}
