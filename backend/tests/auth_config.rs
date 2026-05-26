//! Integration + unit tests for the Phase-7 auth-config backend (07-02) — the
//! highest-risk plan's request-layer + secret-handling contracts.
//!
//! Mirrors `config_edit_api.rs` / `identity_schema.rs`: Salvo's in-process
//! `TestClient` drives the SAME production router the binary serves
//! (`common::build_test_router_cfg` -> `routes::build`), pointed at a throwaway
//! [`common::ConfigFixture`] seeded with the Phase-7 auth fixture
//! (`KRATOS_AUTH_FIXTURE_YAML`: a `courier` block with NO `connection_uri` and an
//! OIDC providers array carrying a real `client_secret` + a `base64://` mapper).
//!
//! Tier-1 (always-on, no live stack) — the contracts that do NOT need the broker:
//!   - unauthenticated GET/PUT on `api/kratos/smtp-connection` + `api/config/kratos/oidc`
//!     -> 401 `unauthenticated`, no write
//!   - authenticated PUT without `X-CSRF-Token` -> 403 `csrf`, no write
//!   - authenticated PUT of a per-index / out-of-scope OIDC pointer -> 403
//!     `forbidden_key` (allowlist), file unchanged
//!   - authenticated GET `api/kratos/smtp-connection` -> `{set:false}` and the body
//!     leaks NO `://`/`@`/`smtp` substring (T-07-05)
//!   - authenticated GET `api/config/kratos/oidc` masks `client_secret` (sentinel
//!     present, real value absent) and DECODES the `base64://` mapper to source
//!   - a unit assertion that a PUT-merge preserves a stored secret left masked
//!     (reuses the `secret_merge` helpers — the merge core is also unit-tested in
//!     the lib; this file pins the request-layer + masking contracts)
//!
//! Tier-2 (`ORY_LIVE_TESTS=1`): a loud gated test delegating the real
//! write/restart/rollback to `scripts/verify/phase7-acceptance.sh` (Plan 05).

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

use ory_console_backend::config_edit::jsonnet::encode_base64_uri;
use ory_console_backend::config_edit::secret_merge::{self, merge_array_by_id, MASKED, OIDC_SPEC};

/// Build a fixture seeded with the Phase-7 auth-config kratos.yml.
fn auth_fixture() -> common::ConfigFixture {
    common::ConfigFixture::with_kratos_yaml(common::KRATOS_AUTH_FIXTURE_YAML)
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

fn read_fixture(fixture: &common::ConfigFixture) -> Vec<u8> {
    std::fs::read(fixture.kratos_yml()).expect("read fixture kratos.yml")
}

// =============================================================================
// Tier-1: unauthenticated GET/PUT -> 401 (single auth chokepoint)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_smtp_get_is_401(pool: PgPool) {
    let fixture = auth_fixture();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/kratos/smtp-connection")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("unauthenticated"), "401 body: {body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_smtp_put_is_401_no_write(pool: PgPool) {
    let fixture = auth_fixture();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let resp = TestClient::put("http://127.0.0.1:8080/api/kratos/smtp-connection")
        .json(&serde_json::json!({ "connection_uri": "smtps://u:p@smtp:465" }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(read_fixture(&fixture), before, "unauth PUT must not write");
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_oidc_get_is_401(pool: PgPool) {
    let fixture = auth_fixture();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool, cfg));

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/config/kratos/oidc")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("unauthenticated"), "401 body: {body}");
}

// =============================================================================
// Tier-1: authenticated PUT without CSRF -> 403 csrf (no write)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn smtp_put_without_csrf_is_403_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = auth_fixture();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/kratos/smtp-connection")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&serde_json::json!({ "connection_uri": "smtps://u:p@smtp:465" }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("csrf"), "403 body is {{error:csrf}}: {body}");
    assert_eq!(read_fixture(&fixture), before, "CSRF-rejected PUT must not write");
}

#[sqlx::test(migrations = "./migrations")]
async fn oidc_put_without_csrf_is_403_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = auth_fixture();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/oidc")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&serde_json::json!({
            "/selfservice/methods/oidc/config/providers": []
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert!(body.contains("csrf"), "403 body is {{error:csrf}}: {body}");
    assert_eq!(read_fixture(&fixture), before, "CSRF-rejected PUT must not write");
}

// =============================================================================
// Tier-1: authed PUT of a per-index / out-of-scope OIDC pointer -> 403 (allowlist)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn oidc_put_per_index_pointer_is_403_forbidden_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = auth_fixture();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // A per-index pointer (NOT the array-root) must be rejected by the allowlist
    // (whole-array replace only, Pitfall 4) BEFORE any disk touch.
    let mut resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/oidc")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({
            "/selfservice/methods/oidc/config/providers/0/client_secret": "leaked"
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    let body = resp.take_string().await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
        "forbidden",
        "per-index pointer is forbidden_key: {body}"
    );
    assert_eq!(read_fixture(&fixture), before, "forbidden PUT must not write");
}

#[sqlx::test(migrations = "./migrations")]
async fn oidc_put_sensitive_dsn_pointer_is_403_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = auth_fixture();
    let before = read_fixture(&fixture);
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // An out-of-scope / sensitive pointer through the oidc section -> 403.
    let resp = TestClient::put("http://127.0.0.1:8080/api/config/kratos/oidc")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::json!({ "/dsn": "postgres://evil@db/x" }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::FORBIDDEN));
    assert_eq!(read_fixture(&fixture), before, "sensitive PUT must not write");
}

// =============================================================================
// Tier-1: SMTP GET reports {set:false} with NO URI leak (T-07-05)
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn smtp_get_reports_unset_with_no_uri_leak(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    // The auth fixture's courier block has NO connection_uri -> {set:false}.
    let fixture = auth_fixture();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/kratos/smtp-connection")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).expect("GET returns JSON");
    assert_eq!(json["set"], serde_json::json!(false), "no connection_uri -> set:false: {body}");
    // No URI / credential substring may appear (T-07-05).
    assert!(!body.contains("://"), "SMTP GET body must contain no `://`: {body}");
    assert!(!body.contains('@'), "SMTP GET body must contain no `@`: {body}");
    assert!(!body.contains("smtp"), "SMTP GET body must contain no `smtp`: {body}");
}

// =============================================================================
// Tier-1: OIDC GET masks client_secret + decodes the base64:// mapper
// =============================================================================

#[sqlx::test(migrations = "./migrations")]
async fn oidc_get_masks_secret_and_decodes_mapper(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = auth_fixture();
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    let service = Service::new(common::build_test_router_cfg(pool.clone(), cfg));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/config/kratos/oidc")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).expect("GET returns JSON");

    let providers = json["/selfservice/methods/oidc/config/providers"]
        .as_array()
        .expect("providers array present in GET");
    let google = &providers[0];
    // The secret is masked (sentinel present)...
    assert_eq!(google["client_secret"], serde_json::json!(MASKED), "secret masked: {body}");
    // ...and the real value never appears anywhere in the body (T-07-06 leak guard).
    assert!(
        !body.contains("REAL-OIDC-SECRET-DO-NOT-LEAK"),
        "the real client_secret must never appear on GET: {body}"
    );
    // The base64:// mapper is decoded to plaintext Jsonnet source for the editor.
    assert_eq!(
        google["mapper_url"],
        serde_json::json!(common::KRATOS_AUTH_FIXTURE_MAPPER_SRC),
        "mapper_url must be decoded to source: {body}"
    );
    assert!(
        !body.contains("base64://"),
        "the stored base64:// form must not appear on GET (it is decoded): {body}"
    );
    // The non-secret enabled toggle is also returned (scalar pointer in the section).
    assert_eq!(
        json["/selfservice/methods/oidc/enabled"],
        serde_json::json!(true),
        "oidc.enabled returned alongside the array: {body}"
    );
}

// =============================================================================
// Tier-1: unit — PUT-merge preserves a stored secret left masked (Pitfall 3)
// =============================================================================

#[test]
fn unit_merge_preserves_masked_oidc_secret() {
    let stored = vec![serde_json::json!({
        "id": "google", "provider": "google", "client_id": "pub",
        "client_secret": "REAL", "mapper_url": encode_base64_uri("x;")
    })];
    let incoming = vec![serde_json::json!({
        "id": "google", "provider": "google", "client_id": "pub-edited",
        "client_secret": MASKED, "mapper_url": "x;"
    })];
    let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC).expect("merge ok");
    assert_eq!(
        merged[0]["client_secret"],
        serde_json::json!("REAL"),
        "a masked incoming secret must inherit the stored value (never clobbered)"
    );
    assert_eq!(merged[0]["client_id"], serde_json::json!("pub-edited"));

    // Retyping the secret overwrites.
    let incoming2 = vec![serde_json::json!({
        "id": "google", "provider": "google", "client_id": "pub",
        "client_secret": "NEW", "mapper_url": "x;"
    })];
    let merged2 = merge_array_by_id(&stored, &incoming2, &OIDC_SPEC).expect("merge ok");
    assert_eq!(merged2[0]["client_secret"], serde_json::json!("NEW"));

    // CR-01 fail-closed: renaming the id while leaving the secret masked has no
    // stored value to inherit -> the merge refuses (the sentinel is never written).
    let incoming3 = vec![serde_json::json!({
        "id": "g00gle", "provider": "google", "client_id": "pub",
        "client_secret": MASKED, "mapper_url": "x;"
    })];
    let err = merge_array_by_id(&stored, &incoming3, &OIDC_SPEC)
        .expect_err("renamed-id + masked secret must fail closed (CR-01)");
    assert_eq!(err.item_id.as_deref(), Some("g00gle"));
}

#[test]
fn unit_sentinel_is_the_pinned_contract_literal() {
    // The cross-plan contract: the sentinel literal is pinned HERE. A change must
    // be deliberate (FE + live gate echo it from a GET, never re-declare it).
    assert_eq!(secret_merge::MASKED, "__ory_console_masked__");
}

// =============================================================================
// Tier-2: live write -> restart -> healthy + rollback (ORY_LIVE_TESTS=1)
// =============================================================================

/// Live Phase-7 SMTP/OIDC write/restart/rollback. Requires `ORY_LIVE_TESTS=1` AND
/// a running compose stack (Kratos + restart broker on the internal network).
/// Prints an explicit SKIP line when the gate is unset (no silent pass).
#[tokio::test]
async fn live_auth_config_write_restart_recover() {
    if std::env::var("ORY_LIVE_TESTS").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_auth_config_write_restart_recover: ORY_LIVE_TESTS!=1 \
             (gated SMTP connection_uri + OIDC array write->restart->healthy + \
             rollback against the live Kratos stack)"
        );
        return;
    }
    // When the gate IS set the real write/restart/rollback round-trip needs the
    // compose stack (writable mounted kratos.yml + reachable restart broker) — an
    // environment a host-side `cargo test` does not provide. It is exercised by
    // scripts/verify/phase7-acceptance.sh (Plan 05). Fail loudly here rather than
    // silently pass so the gating contract is explicit.
    panic!(
        "ORY_LIVE_TESTS=1 set: run the live Phase-7 SMTP/OIDC write/restart/rollback \
         via scripts/verify/phase7-acceptance.sh (needs the compose stack + writable \
         kratos.yml mount + restart broker), not a host-side cargo test"
    );
}
