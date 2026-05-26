//! Integration tests for the ACT-04 audit hoop + read-only audit view.
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (incl. 0005 console_audit_log), then drives the REAL production router via
//! Salvo's in-process `TestClient`. We assert:
//!   - a state-changing request through the protected subtree (POST /logout)
//!     writes ONE audit row with the correct actor (the session admin_id),
//!     method=POST, path=/logout, outcome=success;
//!   - a GET (safe method) on a protected route writes NO audit row;
//!   - `list_audit` filters by outcome.
//!
//! The actor is read from the Depot `Session` (auth_guard-injected), never from a
//! client field (T-11-14), so we assert the recorded actor_id equals the seeded
//! admin's id.

mod common;

use ory_console_backend::audit::queries as audit_q;
use salvo::prelude::*;
use salvo::test::TestClient;
use sqlx::PgPool;
use uuid::Uuid;

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

/// Count audit rows directly via the read-only query layer.
async fn all_audit(pool: &PgPool) -> Vec<ory_console_backend::audit::AuditView> {
    audit_q::list_audit(pool, None, None, None, None, None, 500)
        .await
        .expect("list audit")
}

#[sqlx::test(migrations = "./migrations")]
async fn state_change_writes_audit_row_with_session_actor(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;

    // A state-changing protected request: POST /logout with a matching CSRF token.
    let resp = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf, true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "logout should succeed");

    let rows = all_audit(&pool).await;
    let logout_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.path.as_deref() == Some("/logout"))
        .collect();
    assert_eq!(
        logout_rows.len(),
        1,
        "exactly one audit row for the POST /logout state change; got {rows:?}"
    );
    let row = logout_rows[0];
    assert_eq!(row.actor_id, Some(admin_id), "actor is the session admin_id");
    assert_eq!(
        row.actor_email.as_deref(),
        Some("owner@example.com"),
        "actor email resolved from the admins table"
    );
    assert_eq!(row.method.as_deref(), Some("POST"));
    assert_eq!(row.path.as_deref(), Some("/logout"));
    assert_eq!(row.outcome, "success", "2xx -> success");
}

#[sqlx::test(migrations = "./migrations")]
async fn csrf_rejected_mutation_is_audited_as_failure(pool: PgPool) {
    // WR-05: a state change that CLEARS auth but FAILS csrf (missing X-CSRF-Token)
    // must still be audited, with outcome=failure and the actor captured (the
    // session was injected by auth_guard before csrf_guard rejected).
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    // POST /logout with a valid session cookie but NO CSRF header -> 403.
    let resp = TestClient::post("http://127.0.0.1:8080/logout")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::FORBIDDEN),
        "missing CSRF token is rejected with 403"
    );

    let rows = all_audit(&pool).await;
    let logout_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.path.as_deref() == Some("/logout"))
        .collect();
    assert_eq!(
        logout_rows.len(),
        1,
        "the CSRF-denied POST /logout is still audited; got {rows:?}"
    );
    let row = logout_rows[0];
    assert_eq!(row.outcome, "failure", "a 403 rejection is outcome=failure");
    assert_eq!(row.method.as_deref(), Some("POST"));
    assert_eq!(
        row.actor_id,
        Some(admin_id),
        "the probing actor is captured (auth cleared, csrf failed)"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_mutation_is_audited_with_null_actor(pool: PgPool) {
    // WR-05: a state change with NO/invalid session -> 401 must still be audited,
    // with a NULL actor (the session was never injected; never fabricated).
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));

    // POST /logout with no cookie at all -> 401.
    let resp = TestClient::post("http://127.0.0.1:8080/logout")
        .send(&service)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "no session is rejected with 401"
    );

    let rows = all_audit(&pool).await;
    let logout_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.path.as_deref() == Some("/logout"))
        .collect();
    assert_eq!(
        logout_rows.len(),
        1,
        "the unauthenticated POST /logout is still audited; got {rows:?}"
    );
    let row = logout_rows[0];
    assert_eq!(row.outcome, "failure", "a 401 rejection is outcome=failure");
    assert_eq!(row.actor_id, None, "no actor is fabricated on a 401");
}

#[sqlx::test(migrations = "./migrations")]
async fn safe_get_writes_no_audit_row(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let service = Service::new(common::build_test_router(pool.clone()));
    let (raw, _csrf) = login_and_get_session(&service, &pool).await;

    // A safe GET on a protected route: must NOT produce an audit row.
    let resp = TestClient::get("http://127.0.0.1:8080/api/console/me")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));

    let rows = all_audit(&pool).await;
    assert!(
        rows.is_empty(),
        "a safe GET must write no audit row; got {rows:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_audit_filters_by_outcome(pool: PgPool) {
    let admin_id = common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;

    // Seed two rows directly: one success, one failure.
    audit_q::insert_audit(
        &pool,
        Some(admin_id),
        Some("owner@example.com"),
        "POST /api/webhooks",
        Some("POST"),
        Some("/api/webhooks"),
        None,
        None,
        "success",
        None,
    )
    .await
    .expect("insert success row");
    audit_q::insert_audit(
        &pool,
        Some(admin_id),
        Some("owner@example.com"),
        "DELETE /api/webhooks/abc",
        Some("DELETE"),
        Some("/api/webhooks/abc"),
        None,
        None,
        "failure",
        None,
    )
    .await
    .expect("insert failure row");

    let successes = audit_q::list_audit(&pool, None, None, Some("success"), None, None, 500)
        .await
        .expect("list successes");
    assert_eq!(successes.len(), 1, "exactly one success row");
    assert_eq!(successes[0].outcome, "success");

    let failures = audit_q::list_audit(&pool, None, None, Some("failure"), None, None, 500)
        .await
        .expect("list failures");
    assert_eq!(failures.len(), 1, "exactly one failure row");
    assert_eq!(failures[0].outcome, "failure");

    // An actor filter that matches nothing returns empty (parameterized, no
    // interpolation — T-11-15).
    let none = audit_q::list_audit(&pool, Some(Uuid::nil()), None, None, None, None, 500)
        .await
        .expect("list by unknown actor");
    assert!(none.is_empty(), "unknown actor filter returns no rows");
}
