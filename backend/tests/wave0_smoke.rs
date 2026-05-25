//! Wave-0 smoke tests (BACK-01 health-preserved, BACK-03 migrations/tables).
//!
//! Run with a live `DATABASE_URL` (compose Postgres or any reachable PG):
//!   DATABASE_URL=postgres://... cargo test --locked
//! `#[sqlx::test]` provisions an isolated temp database per test and applies
//! the embedded migrations from `./migrations` automatically.

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// BACK-03: after migrations run, the v1 tables exist in the test DB.
#[sqlx::test(migrations = "./migrations")]
async fn migrations_create_v1_tables(pool: PgPool) {
    for table in ["admins", "sessions", "console_settings", "settings_history"] {
        let regclass: Option<String> =
            sqlx::query_scalar("SELECT to_regclass($1)::text")
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("query to_regclass");
        assert_eq!(
            regclass.as_deref(),
            Some(table),
            "expected table `{table}` to exist after migrations"
        );
    }
}

/// BACK-01: `GET /health` returns 200 with `{"status":"ok"}` through the real
/// router (affix_state + health route preserved from the Phase-1 skeleton).
#[sqlx::test(migrations = "./migrations")]
async fn health_returns_200(pool: PgPool) {
    let router = common::build_test_router(pool);
    let service = Service::new(router);

    let mut res = TestClient::get("http://127.0.0.1:8080/health")
        .send(&service)
        .await;

    assert_eq!(res.status_code, Some(StatusCode::OK));
    let body = res.take_string().await.expect("read body");
    assert!(
        body.contains("\"status\":\"ok\""),
        "health body should report ok, got: {body}"
    );
}
