//! Integration tests for the PROJ-04 console members list (secret-free DTO,
//! multi-operator permitted post single-admin-guard drop).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (incl. 0006 drop_single_admin_guard), then drives the REAL production router
//! via Salvo's in-process `TestClient`. We assert:
//!   - GET /api/console/members lists BOTH a local-admin AND a github-only admin
//!     (multi-admin allowed now that the guard is dropped);
//!   - each is mapped to a secret-free MemberView with the correct account_type;
//!   - no password_hash appears anywhere in the serialized response (T-11-12).

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Log in the seeded local admin and return the raw session cookie token.
async fn login(service: &Service, email: &str) -> String {
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({ "email": email, "password": "a-very-long-password" }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "login should succeed");
    common::obtain_session_cookie(&resp).expect("session cookie")
}

/// Insert a GitHub-only admin (password_hash NULL, github_user_id set) directly.
async fn seed_github_admin(pool: &PgPool, email: &str, github_user_id: i64) {
    sqlx::query!(
        r#"
        INSERT INTO admins (email, name, password_hash, github_user_id)
        VALUES ($1, $2, NULL, $3)
        "#,
        email,
        "GitHub Operator",
        github_user_id
    )
    .execute(pool)
    .await
    .expect("seed github admin");
}

#[sqlx::test(migrations = "./migrations")]
async fn members_lists_multiple_admins_secret_free(pool: PgPool) {
    // A local admin (has password_hash) and a github-only admin (has github_user_id
    // only) — both must list now that the single-admin guard is dropped (0006).
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    seed_github_admin(&pool, "octo@example.com", 4242).await;

    let service = Service::new(common::build_test_router(pool.clone()));
    let raw = login(&service, "owner@example.com").await;

    let mut resp = TestClient::get("http://127.0.0.1:8080/api/console/members")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body = resp.take_string().await.unwrap();

    // Both operators are listed (multi-admin allowed).
    assert!(body.contains("owner@example.com"), "local admin listed: {body}");
    assert!(body.contains("octo@example.com"), "github admin listed: {body}");

    // Correct account_type labels.
    assert!(body.contains("Local admin"), "local-admin account_type: {body}");
    assert!(body.contains("GitHub"), "github account_type: {body}");

    // SECRET-FREE: no password_hash / Argon2 PHC ever leaks (T-11-12).
    for forbidden in ["password_hash", "$argon2", "token_hash", "bootstrap"] {
        assert!(
            !body.contains(forbidden),
            "members body must not contain `{forbidden}`: {body}"
        );
    }

    // The response is a JSON array of exactly two members.
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("members is JSON");
    assert_eq!(
        parsed.as_array().map(|a| a.len()),
        Some(2),
        "exactly two members listed: {body}"
    );
}
