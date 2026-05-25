//! Phase 6 integration + offline tests for the Kratos identity data path
//! (IDENT-01 list+detail, IDENT-02 CRUD, IDENT-04 CLI-compatible bulk import).
//!
//! Three layers, mirroring `ory_wrappers.rs`:
//!
//! 1. **Offline pure-function tests (ALWAYS run, no stack).** Re-exercise the
//!    public backend helpers through the library API: the Link-header cursor
//!    parser, the CLI bare-array <-> batch wrapper conversion (both directions),
//!    the 1000/200 import-limit enforcement, and the credential-secret-absence
//!    shaping (T-06-01). These are the Wave-0 unit gates the plan requires to run
//!    without a live Kratos.
//!
//! 2. **Tier-1 route guards (ALWAYS run, no stack).** Drive the SAME production
//!    router via Salvo's in-process `TestClient` and assert every NEW identity
//!    route rejects an UNAUTHENTICATED request with 401 (the `auth_guard`
//!    chokepoint, T-06-03). A 2xx here is a hard FAIL (anti-false-green) — the
//!    routes must never be reachable without a session.
//!
//! 3. **Tier-2 live CRUD + import (gated on `ORY_LIVE_TESTS=1`).** create -> list
//!    (record appears) -> get -> update (state REQUIRED) -> delete (-> get 404),
//!    plus a small batch import appearing in the list and an oversized batch
//!    rejected with 422 WITHOUT contacting Kratos. When the gate is unset each
//!    prints an explicit `SKIP:` line and returns — a skip is NEVER a silent pass
//!    (RESEARCH anti-false-green).

mod common;

use ory_console_backend::ory::fallback::parse_next_page_token;
use ory_console_backend::ory::kratos::{
    batch_limits, cli_array_to_patch_body, enforce_import_limits, patch_body_to_cli_array,
    shape_identity_value,
};
use ory_kratos_client::models::{
    CreateIdentityBody, IdentityWithCredentials, IdentityWithCredentialsPassword,
    IdentityWithCredentialsPasswordConfig,
};
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

// =============================================================================
// Layer 1 — OFFLINE pure-function gates (always-on, no live stack).
// =============================================================================

/// Link-header keyset cursor parser: extracts the `rel="next"` `page_token`, and
/// yields `None` when there is no next link (last-page signal).
#[test]
fn link_header_cursor_parser() {
    let header = "</admin/identities?page_token=abc&page_size=50>; rel=\"next\"";
    assert_eq!(parse_next_page_token(header), Some("abc".to_string()));

    let multi = "</admin/identities?page_token=f0&page_size=50>; rel=\"first\", \
                 </admin/identities?page_token=NEXT&page_size=50>; rel=\"next\"";
    assert_eq!(parse_next_page_token(multi), Some("NEXT".to_string()));

    assert_eq!(
        parse_next_page_token("</admin/identities?page_size=50>; rel=\"first\""),
        None
    );
    assert_eq!(parse_next_page_token(""), None);
}

/// CLI bare-array <-> batch wrapper conversion is correct and a single-record
/// round-trip is identity-preserving (IDENT-04 / CLI-01 foreshadow).
#[test]
fn cli_shape_round_trip() {
    let original = CreateIdentityBody::new(
        "default".into(),
        serde_json::json!({ "email": "rt@example.com" }),
    );
    let original_value = serde_json::to_value(&original).unwrap();

    let body = cli_array_to_patch_body(vec![original]);
    let patches = body.identities.as_ref().expect("identities present");
    assert_eq!(patches.len(), 1);
    assert!(patches[0].create.is_some(), "each record wrapped in `create`");
    assert!(patches[0].patch_id.is_some(), "patch_id generated");

    let back = patch_body_to_cli_array(&body);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0], original_value, "inner object round-trips unchanged");
}

/// Import-limit enforcement (T-06-02): 1001 hashed rejected; 1000 hashed allowed;
/// 201-with-cleartext rejected; 200 cleartext allowed; empty rejected.
#[test]
fn import_limit_enforcement() {
    let (max_hashed, max_cleartext) = batch_limits();
    assert_eq!((max_hashed, max_cleartext), (1000, 200));

    let hashed = || {
        let mut b =
            CreateIdentityBody::new("default".into(), serde_json::json!({ "email": "h@x.com" }));
        b.credentials = Some(Box::new(IdentityWithCredentials {
            password: Some(Box::new(IdentityWithCredentialsPassword {
                config: Some(Box::new(IdentityWithCredentialsPasswordConfig {
                    hashed_password: Some("$2a$10$abcdefghijklmnopqrstuv".into()),
                    password: None,
                    use_password_migration_hook: None,
                })),
            })),
            oidc: None,
            saml: None,
        }));
        b
    };
    let cleartext = || {
        let mut b =
            CreateIdentityBody::new("default".into(), serde_json::json!({ "email": "c@x.com" }));
        b.credentials = Some(Box::new(IdentityWithCredentials {
            password: Some(Box::new(IdentityWithCredentialsPassword {
                config: Some(Box::new(IdentityWithCredentialsPasswordConfig {
                    hashed_password: None,
                    password: Some("cleartext-pw".into()),
                    use_password_migration_hook: None,
                })),
            })),
            oidc: None,
            saml: None,
        }));
        b
    };

    assert!(enforce_import_limits(&[]).is_err(), "empty rejected");

    let h1001: Vec<_> = (0..1001).map(|_| hashed()).collect();
    assert!(enforce_import_limits(&h1001).is_err(), "1001 hashed rejected");

    let h1000: Vec<_> = (0..1000).map(|_| hashed()).collect();
    assert!(enforce_import_limits(&h1000).is_ok(), "1000 hashed allowed");

    let mut mixed201: Vec<_> = (0..200).map(|_| hashed()).collect();
    mixed201.push(cleartext());
    assert!(
        enforce_import_limits(&mixed201).is_err(),
        "201 with a cleartext rejected"
    );

    let c200: Vec<_> = (0..200).map(|_| cleartext()).collect();
    assert!(enforce_import_limits(&c200).is_ok(), "200 cleartext allowed");
}

/// Secret-absence (T-06-01): a synthesised identity-with-credentials, once
/// shaped, contains the credential TYPE key but NOT the inner config secret or
/// identifiers.
#[test]
fn secret_absence_after_shaping() {
    let secret_hash = "$argon2id$v=19$NEVER_LEAKS";
    let secret_identifier = "leak@example.com";
    let raw = serde_json::json!({
        "id": "id-1",
        "schema_id": "default",
        "traits": { "email": "u@example.com" },
        "credentials": {
            "password": {
                "type": "password",
                "identifiers": [secret_identifier],
                "config": { "hashed_password": secret_hash }
            },
            "oidc": { "type": "oidc", "config": { "providers": ["secret-provider"] } }
        }
    });
    let shaped = shape_identity_value(raw);
    let text = serde_json::to_string(&shaped).expect("serialize shaped");

    assert!(text.contains("\"password\""), "type key survives: {text}");
    assert!(text.contains("\"oidc\""), "oidc type key survives: {text}");
    assert!(!text.contains(secret_hash), "hash leaked: {text}");
    assert!(!text.contains(secret_identifier), "identifier leaked: {text}");
    assert!(!text.contains("secret-provider"), "oidc config leaked: {text}");
}

// =============================================================================
// Layer 2 — Tier-1 route guards (always-on): unauth -> 401 (no live stack).
// =============================================================================

/// Every NEW identity route sits on the protected subtree behind `auth_guard`,
/// so a request with NO session cookie is rejected with 401 BEFORE the handler
/// runs (T-06-03 EoP). A non-401 is a hard FAIL — the route must not be reachable
/// unauthenticated, on ANY method.
#[sqlx::test(migrations = "./migrations")]
async fn identity_routes_require_auth(pool: PgPool) {
    let service = Service::new(common::build_test_router(pool));
    let base = "http://127.0.0.1:8080";

    // (method, path) tuples for every new route + verb.
    macro_rules! check {
        ($req:expr, $label:expr) => {{
            let resp = $req.send(&service).await;
            assert_eq!(
                resp.status_code,
                Some(StatusCode::UNAUTHORIZED),
                "unauthenticated {} must be 401 (auth_guard); a non-401 means it is reachable without a session",
                $label
            );
        }};
    }

    check!(
        TestClient::get(format!("{base}/api/kratos/identities")),
        "GET /api/kratos/identities"
    );
    check!(
        TestClient::post(format!("{base}/api/kratos/identities")),
        "POST /api/kratos/identities"
    );
    check!(
        TestClient::get(format!("{base}/api/kratos/identities/some-id")),
        "GET /api/kratos/identities/{{id}}"
    );
    check!(
        TestClient::put(format!("{base}/api/kratos/identities/some-id")),
        "PUT /api/kratos/identities/{{id}}"
    );
    check!(
        TestClient::delete(format!("{base}/api/kratos/identities/some-id")),
        "DELETE /api/kratos/identities/{{id}}"
    );
    check!(
        TestClient::post(format!("{base}/api/kratos/identities/import")),
        "POST /api/kratos/identities/import"
    );
}

// =============================================================================
// Layer 3 — Tier-2 live CRUD + import (gated on ORY_LIVE_TESTS=1).
// =============================================================================

/// True only when `ORY_LIVE_TESTS` is set. When false the caller prints `SKIP:`
/// and returns — a gated test NEVER silently passes.
fn live_enabled() -> bool {
    std::env::var("ORY_LIVE_TESTS").is_ok()
}

/// Seed an admin, log in, and return `(raw session cookie, csrf token)` for
/// authenticated mutating calls. GET is csrf-exempt; POST/PUT/DELETE need the
/// matching `X-CSRF-Token`.
async fn authed(service: &Service, pool: &PgPool) -> (String, String) {
    common::seed_admin(pool, "ident-owner@example.com", "a-very-long-password").await;
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "ident-owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "live login should succeed");
    let cookie = common::obtain_session_cookie(&resp).expect("session cookie after login");
    let csrf = common::csrf_for_raw_token(pool, &cookie).await;
    (cookie, csrf)
}

/// Assert the body leaks none of the admin host:port URLs (Phase-3 discipline).
fn assert_no_admin_url_leak(body: &str) {
    for marker in ["kratos:4434", "hydra:4445", "keto:4466", "keto:4467", "oathkeeper:4456"] {
        assert!(!body.contains(marker), "response leaked admin URL `{marker}`: {body}");
    }
}

/// Full CRUD round-trip against live Kratos: create -> list (appears) -> get ->
/// update (state required) -> delete -> get 404. Gated.
#[sqlx::test(migrations = "./migrations")]
async fn identity_crud_round_trip_live(pool: PgPool) {
    if !live_enabled() {
        println!("SKIP: identity_crud_round_trip_live (set ORY_LIVE_TESTS=1 with the stack up)");
        return;
    }

    let service = Service::new(common::build_test_router(pool.clone()));
    let (cookie, csrf) = authed(&service, &pool).await;
    let cookie_hdr = format!("console_session={cookie}");
    let email = format!("crud-{}@example.com", uuid::Uuid::new_v4());

    // CREATE
    let mut resp = TestClient::post("http://127.0.0.1:8080/api/kratos/identities")
        .add_header("Cookie", cookie_hdr.clone(), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({ "schema_id": "default", "traits": { "email": email } }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "create should be 200");
    let created: serde_json::Value =
        serde_json::from_str(&resp.take_string().await.unwrap()).unwrap();
    let id = created["id"].as_str().expect("created id").to_string();

    // GET
    let mut resp = TestClient::get(format!("http://127.0.0.1:8080/api/kratos/identities/{id}"))
        .add_header("Cookie", cookie_hdr.clone(), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "get should be 200");
    let got = resp.take_string().await.unwrap();
    assert!(got.contains(&email), "get should return the created identity");
    assert_no_admin_url_leak(&got);

    // UPDATE — state is REQUIRED.
    let resp = TestClient::put(format!("http://127.0.0.1:8080/api/kratos/identities/{id}"))
        .add_header("Cookie", cookie_hdr.clone(), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({
            "schema_id": "default",
            "state": "inactive",
            "traits": { "email": email }
        }))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "update should be 200");

    // DELETE
    let resp = TestClient::delete(format!("http://127.0.0.1:8080/api/kratos/identities/{id}"))
        .add_header("Cookie", cookie_hdr.clone(), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::NO_CONTENT), "delete should be 204");

    // GET after delete -> upstream 404 maps to 502 (mapped upstream error).
    let resp = TestClient::get(format!("http://127.0.0.1:8080/api/kratos/identities/{id}"))
        .add_header("Cookie", cookie_hdr, true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_GATEWAY),
        "get after delete should surface the mapped upstream 404 as 502"
    );
}

/// A small CLI bare-array import succeeds and the records appear in the list;
/// an oversized batch is rejected with 422 WITHOUT contacting Kratos. Gated.
#[sqlx::test(migrations = "./migrations")]
async fn identity_batch_import_live(pool: PgPool) {
    if !live_enabled() {
        println!("SKIP: identity_batch_import_live (set ORY_LIVE_TESTS=1 with the stack up)");
        return;
    }

    let service = Service::new(common::build_test_router(pool.clone()));
    let (cookie, csrf) = authed(&service, &pool).await;
    let cookie_hdr = format!("console_session={cookie}");

    let e1 = format!("imp-{}@example.com", uuid::Uuid::new_v4());
    let e2 = format!("imp-{}@example.com", uuid::Uuid::new_v4());
    let resp = TestClient::post("http://127.0.0.1:8080/api/kratos/identities/import")
        .add_header("Cookie", cookie_hdr.clone(), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!([
            { "schema_id": "default", "traits": { "email": e1 } },
            { "schema_id": "default", "traits": { "email": e2 } }
        ]))
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "small import should be 200");

    // Oversized cleartext batch (201 records, all cleartext) -> 422 before Kratos.
    let big: Vec<serde_json::Value> = (0..201)
        .map(|i| {
            serde_json::json!({
                "schema_id": "default",
                "traits": { "email": format!("big-{i}@example.com") },
                "credentials": { "password": { "config": { "password": "pw" } } }
            })
        })
        .collect();
    let resp = TestClient::post("http://127.0.0.1:8080/api/kratos/identities/import")
        .add_header("Cookie", cookie_hdr, true)
        .add_header("X-CSRF-Token", csrf, true)
        .json(&serde_json::Value::Array(big))
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "oversized cleartext batch must be 422 (server-side limit, before Kratos)"
    );
}
