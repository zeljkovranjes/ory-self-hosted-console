//! Integration tests for the durable webhook worker (HOOK-01/02).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations, then
//! drives `webhooks::worker::tick` against the real `webhooks` /
//! `webhook_deliveries` tables and an in-process `mockito` receiver. The live
//! end-to-end delivery (against the running stack + an echo sidecar) is the
//! `scripts/verify/phase11-acceptance.sh` gate's job; here we prove the DB +
//! security invariants without the live stack:
//!   - a delivery to a 2xx receiver → 'delivered' AND the request carried a valid
//!     X-Console-Signature HMAC over the body keyed by the webhook secret
//!   - a delivery to a 5xx receiver → backoff (growing next_attempt_at) → 'dead'
//!   - a delivery whose target is SSRF-blocked → recorded failure, NO outbound
//!     POST to the blocked target
//!   - claim_due_deliveries with SKIP LOCKED never double-claims a row
//!   - prune_terminal_deliveries deletes an old terminal row

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use ory_console_backend::webhooks::{queries, worker};

type HmacSha256 = Hmac<Sha256>;

/// Insert a webhook directly (bypassing the route) and return (id, secret).
async fn seed_webhook(pool: &PgPool, url: &str, secret: &str, enabled: bool) -> Uuid {
    let row = queries::create_webhook(
        pool,
        "test-hook",
        url,
        &["identity.created".to_string()],
        secret,
        enabled,
    )
    .await
    .expect("create webhook");
    row.id
}

/// Enqueue a delivery and return its id.
async fn seed_delivery(pool: &PgPool, webhook_id: Uuid) -> Uuid {
    let payload = serde_json::json!({"event": "identity.created", "id": "abc-123"});
    queries::insert_delivery(pool, webhook_id, "identity.created", &payload)
        .await
        .expect("insert delivery")
}

async fn delivery_status(pool: &PgPool, id: Uuid) -> (String, i32, Option<i32>) {
    let d = queries::get_delivery(pool, id)
        .await
        .expect("get delivery")
        .expect("delivery exists");
    (d.status, d.attempt, d.last_status_code)
}

#[sqlx::test(migrations = "./migrations")]
async fn delivers_to_2xx_with_valid_hmac_signature(pool: PgPool) {
    let mut server = mockito::Server::new_async().await;
    let secret = "super-secret-key";

    let url = format!("{}/hook", server.url());
    let webhook_id = seed_webhook(&pool, &url, secret, true).await;
    let delivery_id = seed_delivery(&pool, webhook_id).await;

    // The worker signs the payload AS IT ROUND-TRIPS through jsonb (Postgres does
    // not preserve key order), so compute the expected signature over the SAME
    // bytes the worker will serialize from the stored row.
    let stored = queries::get_delivery(&pool, delivery_id).await.unwrap().unwrap();
    let raw_body = serde_json::to_vec(&stored.payload).unwrap();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&raw_body);
    let expected_hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let expected_sig = format!("sha256={expected_hex}");

    let m = server
        .mock("POST", "/hook")
        .match_header("x-console-signature", expected_sig.as_str())
        .with_status(200)
        .create_async()
        .await;

    // allow_private = true: the mockito receiver binds loopback, which the SSRF
    // guard correctly blocks in production. The pin + redirects-off still apply.
    worker::tick_with(&pool, true).await.expect("worker tick");

    m.assert_async().await; // the receiver got a request WITH the valid signature
    let (status, attempt, code) = delivery_status(&pool, delivery_id).await;
    assert_eq!(status, "delivered", "2xx receiver -> delivered");
    assert_eq!(attempt, 1);
    assert_eq!(code, Some(200));
}

#[sqlx::test(migrations = "./migrations")]
async fn backoff_then_dead_on_persistent_5xx(pool: PgPool) {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/hook")
        .with_status(500)
        .expect_at_least(1)
        .create_async()
        .await;

    let url = format!("{}/hook", server.url());
    let webhook_id = seed_webhook(&pool, &url, "k", true).await;

    // Set max_attempts low so the test reaches 'dead' quickly, and make every
    // attempt immediately due by zeroing next_attempt_at after each tick.
    let payload = serde_json::json!({"e": 1});
    let delivery_id = queries::insert_delivery(&pool, webhook_id, "identity.created", &payload)
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE webhook_deliveries SET max_attempts = 3 WHERE id = $1",
        delivery_id
    )
    .execute(&pool)
    .await
    .unwrap();

    let mut last_next: Option<OffsetDateTime> = None;
    for i in 0..3 {
        // allow_private: the 5xx receiver runs on loopback; we are testing the
        // backoff/dead state machine on a genuine non-2xx HTTP response.
        worker::tick_with(&pool, true).await.expect("tick");
        let d = queries::get_delivery(&pool, delivery_id).await.unwrap().unwrap();
        if i < 2 {
            assert_eq!(d.status, "failed", "attempt {i}: still retryable");
            // next_attempt_at must grow with each backoff.
            if let Some(prev) = last_next {
                assert!(d.next_attempt_at > prev, "backoff should grow");
            }
            last_next = Some(d.next_attempt_at);
            // Force the next attempt to be due now.
            sqlx::query!(
                "UPDATE webhook_deliveries SET next_attempt_at = now() WHERE id = $1",
                delivery_id
            )
            .execute(&pool)
            .await
            .unwrap();
        } else {
            assert_eq!(d.status, "dead", "reaches dead at max_attempts");
            assert_eq!(d.attempt, 3);
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn ssrf_blocked_target_is_not_delivered(pool: PgPool) {
    // A loopback target must NEVER be POSTed to; the delivery is recorded failed.
    let webhook_id = seed_webhook(&pool, "http://127.0.0.1:9/hook", "k", true).await;
    let delivery_id = seed_delivery(&pool, webhook_id).await;

    worker::tick(&pool).await.expect("tick");

    let (status, _attempt, code) = delivery_status(&pool, delivery_id).await;
    assert_eq!(status, "failed", "SSRF-blocked -> recorded failure, not delivered");
    assert_eq!(code, None, "no HTTP status because no request was sent");
    let d = queries::get_delivery(&pool, delivery_id).await.unwrap().unwrap();
    assert!(
        d.last_error.unwrap_or_default().contains("not allowed"),
        "SSRF reason recorded"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn metadata_target_is_blocked(pool: PgPool) {
    let webhook_id = seed_webhook(&pool, "http://169.254.169.254/latest", "k", true).await;
    let delivery_id = seed_delivery(&pool, webhook_id).await;
    worker::tick(&pool).await.expect("tick");
    let (status, _a, code) = delivery_status(&pool, delivery_id).await;
    assert_eq!(status, "failed");
    assert_eq!(code, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn skip_locked_claim_does_not_double_claim(pool: PgPool) {
    let webhook_id = seed_webhook(&pool, "http://example.com/hook", "k", true).await;
    // Enqueue 4 due deliveries.
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(seed_delivery(&pool, webhook_id).await);
    }

    // Open a transaction that claims a batch and HOLDS the lock; a concurrent
    // claim on a separate connection must get a DISJOINT set (SKIP LOCKED).
    let mut tx = pool.begin().await.unwrap();
    let first = sqlx::query!(
        r#"
        UPDATE webhook_deliveries SET status='delivering', updated_at=now()
        WHERE id IN (
            SELECT id FROM webhook_deliveries
            WHERE status IN ('pending','failed') AND next_attempt_at <= now()
            ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 2
        ) RETURNING id
        "#
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    let first_ids: Vec<Uuid> = first.into_iter().map(|r| r.id).collect();
    assert_eq!(first_ids.len(), 2);

    // Concurrent claim on the pool (separate connection) — must skip the 2 locked.
    let second = queries::claim_due_deliveries(&pool, 10).await.unwrap();
    let second_ids: Vec<Uuid> = second.into_iter().map(|d| d.id).collect();
    assert_eq!(second_ids.len(), 2, "claims the OTHER 2 rows");
    for id in &second_ids {
        assert!(!first_ids.contains(id), "no row claimed twice");
    }

    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn prune_removes_old_terminal_rows(pool: PgPool) {
    let webhook_id = seed_webhook(&pool, "http://example.com/hook", "k", true).await;
    let delivery_id = seed_delivery(&pool, webhook_id).await;
    // Mark it 'dead' and backdate updated_at well past the retention window.
    sqlx::query!(
        "UPDATE webhook_deliveries SET status='dead', updated_at = now() - interval '60 days' WHERE id = $1",
        delivery_id
    )
    .execute(&pool)
    .await
    .unwrap();

    let cutoff = OffsetDateTime::now_utc() - worker::RETENTION;
    let pruned = queries::prune_terminal_deliveries(&pool, cutoff).await.unwrap();
    assert_eq!(pruned, 1, "old terminal row pruned");
    assert!(
        queries::get_delivery(&pool, delivery_id).await.unwrap().is_none(),
        "row gone"
    );
}
