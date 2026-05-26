//! Integration tests for the Phase-16 backend Prometheus exporter (OBS-02).
//!
//! Two load-bearing assertions:
//!   1. `GET /metrics` returns 200 with a `text/plain` Prometheus exposition body
//!      carrying at least one console-owned counter family.
//!   2. The rendered body carries NO per-identity label key — `email`,
//!      `identity_id`, `session_id`, `subject`, or any `*_id` — so a scrape can
//!      never leak PII or blow up Prometheus cardinality (T-16-04).
//!
//! The endpoint is mounted on the ROOT/public subtree (NO auth/CSRF/feature hoop)
//! because Prometheus scrapes it container-to-container on the internal network;
//! it is internal-only by topology, not by an auth gate. These tests therefore
//! drive it WITHOUT a session cookie — and assert it is reachable unauthenticated
//! (a scrape carries no console session), which is the correct posture for an
//! internal scrape target.
//!
//! `install_recorder()` is re-entrant (it tolerates an already-set global
//! recorder), so calling it here is safe even though the integration suite shares
//! one process and another test may have installed first.

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// Forbidden per-identity label KEYS that must never appear in the rendered text.
/// A Prometheus label appears as `key="value"`; we grep for the key form. `_id`
/// catches `identity_id`, `session_id`, `subject_id`, etc. as a label key.
const FORBIDDEN_LABEL_KEYS: &[&str] = &[
    "email=",
    "identity_id=",
    "session_id=",
    "subject=",
    "_id=",
];

#[sqlx::test(migrations = "./migrations")]
async fn metrics_endpoint_returns_prometheus_text(pool: PgPool) {
    // Install the global recorder so the render handle is live (re-entrant — safe
    // if another test installed first; the global registry is shared).
    ory_console_backend::metrics::install_recorder();
    // Touch a console counter so at least one series is guaranteed present even if
    // a different test's recorder won the global-install race (the family is then
    // registered against the live global registry).
    ory_console_backend::metrics::record_login_attempt(true);
    ory_console_backend::metrics::record_login_attempt(false);

    let service = Service::new(common::build_test_router(pool.clone()));

    let mut resp = TestClient::get("http://127.0.0.1:8080/metrics")
        .send(&service)
        .await;

    // (1) 200 + text/plain, reachable WITHOUT auth (a scrape carries no session).
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "GET /metrics must return 200 unauthenticated (internal scrape target)"
    );
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ctype.starts_with("text/plain"),
        "GET /metrics must be text/plain Prometheus exposition (got '{ctype}')"
    );

    let body = resp.take_string().await.expect("metrics body");

    // (1b) At least one console-owned counter family is rendered. The exposition
    // format prints a `# TYPE <name> counter` line and the series itself.
    assert!(
        body.contains("console_login_attempts_total"),
        "the rendered body must contain a console-owned counter family; got:\n{body}"
    );

    // (2) THE no-per-identity-label assertion (T-16-04): none of the forbidden
    // label keys appears anywhere in the rendered text.
    for key in FORBIDDEN_LABEL_KEYS {
        assert!(
            !body.contains(key),
            "rendered /metrics body must carry NO per-identity label key '{key}' \
             (counts/buckets only — T-16-04); offending body:\n{body}"
        );
    }
}

/// The recorder install is re-entrant: a second call in the same process does not
/// panic (the global recorder can be set only once; the second `set` errors and is
/// tolerated). This mirrors the binary calling it once at boot while the test
/// suite calls it from multiple tests in one process.
#[sqlx::test(migrations = "./migrations")]
async fn install_recorder_is_reentrant(_pool: PgPool) {
    ory_console_backend::metrics::install_recorder();
    // A second call must NOT panic.
    ory_console_backend::metrics::install_recorder();
}
