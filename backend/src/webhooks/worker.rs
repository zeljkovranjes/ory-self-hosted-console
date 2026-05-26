//! Durable webhook delivery worker (HOOK-01).
//!
//! Boot-spawned tokio tasks (mirroring the session reaper in `main.rs`) drive:
//!   - [`tick`] — claim due deliveries (SKIP LOCKED), SSRF-guard the target,
//!     HMAC-sign the body, POST, and record the outcome (delivered | retry | dead).
//!   - [`prune_tick`] — delete terminal rows older than the retention window.
//!   - [`reap_stale_tick`] — return crashed 'delivering' rows to 'failed'.
//!
//! Every tick is fallible-but-non-panicking: the caller's loop logs an `Err` and
//! continues (a transient DB blip must not kill the worker).

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::AppError;

use super::{hmac, queries, ssrf};

/// Backoff base: `next_attempt_at = now() + base * 2^attempt`.
const BACKOFF_BASE: Duration = Duration::from_secs(30);
/// Backoff cap (1h) so a long-failing endpoint still retries at a bounded cadence.
const BACKOFF_CAP: Duration = Duration::from_secs(3600);
/// Max deliveries claimed per tick.
const CLAIM_BATCH: i64 = 10;
/// Retention window for terminal rows (delivered/dead) — pruned after 30 days.
pub const RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
/// A delivery stuck 'delivering' longer than this is considered crashed and is
/// returned to 'failed' for re-claim.
pub const STALE_DELIVERING: Duration = Duration::from_secs(300);

/// Compute the next attempt time for a retry: `now() + min(base*2^attempt, cap)`.
/// `attempt` is the number of attempts ALREADY made (so the first retry uses
/// `attempt = 1`).
fn backoff_next(attempt: i32) -> OffsetDateTime {
    let shift = attempt.clamp(0, 16) as u32;
    let secs = BACKOFF_BASE
        .as_secs()
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_CAP.as_secs());
    OffsetDateTime::now_utc() + Duration::from_secs(secs)
}

/// One delivery sweep: claim due rows and attempt each. Never panics the loop.
///
/// `allow_private` is forwarded to the delivery-time SSRF guard; production
/// callers (`main.rs`) MUST pass `false`. See [`ssrf::build_pinned_client`].
pub async fn tick_with(pool: &PgPool, allow_private: bool) -> Result<(), AppError> {
    let claimed = queries::claim_due_deliveries(pool, CLAIM_BATCH).await?;
    for d in claimed {
        deliver_one(pool, d, allow_private).await;
    }
    Ok(())
}

/// Production sweep — SSRF guard fully enforced (no private/loopback targets).
pub async fn tick(pool: &PgPool) -> Result<(), AppError> {
    tick_with(pool, false).await
}

/// Attempt a single claimed delivery and record the result. Self-contained: any
/// error becomes a recorded failure/dead row, never a propagated error (so one
/// bad delivery cannot abort the batch).
async fn deliver_one(pool: &PgPool, d: queries::ClaimedDelivery, allow_private: bool) {
    let next_attempt = d.attempt + 1;
    let is_last = next_attempt >= d.max_attempts;

    // Fetch the owning webhook (need its secret + url). A deleted/missing webhook
    // → dead (nothing to deliver to).
    let webhook = match queries::get_webhook(pool, d.webhook_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            record(pool, d.id, "dead", next_attempt, None, Some("webhook no longer exists")).await;
            return;
        }
        Err(e) => {
            // Transient DB error — schedule a retry (or dead at max).
            let status = if is_last { "dead" } else { "failed" };
            tracing::warn!(error = %e, "webhook worker: fetch owning webhook failed");
            record(pool, d.id, status, next_attempt, None, Some("internal error fetching webhook")).await;
            return;
        }
    };

    if !webhook.enabled {
        // A disabled webhook is terminal for this delivery — do not deliver.
        record(pool, d.id, "dead", next_attempt, None, Some("webhook is disabled")).await;
        return;
    }

    // Serialize the payload to the RAW body we will sign and send.
    let raw_body = match serde_json::to_vec(&d.payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "webhook worker: payload serialize failed");
            record(pool, d.id, "dead", next_attempt, None, Some("payload serialize error")).await;
            return;
        }
    };

    // SSRF guard at DELIVERY time (authoritative — DNS-rebind defense). On reject
    // NEVER POST to the target; record a failure (or dead at max) with the reason.
    let (client, _addrs) = match ssrf::build_pinned_client(&webhook.url, allow_private).await {
        Ok(c) => c,
        Err(e) => {
            let reason = match &e {
                AppError::BadRequest(m) => m.clone(),
                other => format!("ssrf guard error: {other}"),
            };
            let status = if is_last { "dead" } else { "failed" };
            let next = if is_last {
                OffsetDateTime::now_utc()
            } else {
                backoff_next(next_attempt)
            };
            tracing::warn!(reason = %reason, "webhook delivery blocked by SSRF guard");
            queries::record_delivery_result(pool, d.id, status, next_attempt, next, None, Some(&reason))
                .await
                .ok();
            return;
        }
    };

    // HMAC-sign the raw body and POST with the signature header.
    let signature = hmac::sign(webhook.secret.as_bytes(), &raw_body);
    let result = client
        .post(&webhook.url)
        .header(hmac::SIGNATURE_HEADER, signature)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(raw_body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let code = resp.status().as_u16() as i32;
            // Bound the response read (T-11-08); we don't use the body, just drain
            // a little so the connection closes cleanly.
            let _ = resp.bytes().await;
            if (200..300).contains(&code) {
                record(pool, d.id, "delivered", next_attempt, Some(code), None).await;
            } else {
                let status = if is_last { "dead" } else { "failed" };
                let next = if is_last {
                    OffsetDateTime::now_utc()
                } else {
                    backoff_next(next_attempt)
                };
                queries::record_delivery_result(
                    pool, d.id, status, next_attempt, next, Some(code),
                    Some("non-2xx response"),
                )
                .await
                .ok();
            }
        }
        Err(e) => {
            let status = if is_last { "dead" } else { "failed" };
            let next = if is_last {
                OffsetDateTime::now_utc()
            } else {
                backoff_next(next_attempt)
            };
            // Never echo the full transport error (may carry the URL) — a short tag.
            let tag = if e.is_timeout() { "request timed out" } else { "request failed" };
            tracing::warn!(error = %e, "webhook delivery transport error");
            queries::record_delivery_result(pool, d.id, status, next_attempt, next, None, Some(tag))
                .await
                .ok();
        }
    }
}

/// Helper that schedules a backoff retry (or terminal now) and records the result.
async fn record(
    pool: &PgPool,
    id: uuid::Uuid,
    status: &str,
    attempt: i32,
    code: Option<i32>,
    err: Option<&str>,
) {
    let next = if status == "failed" {
        backoff_next(attempt)
    } else {
        OffsetDateTime::now_utc()
    };
    queries::record_delivery_result(pool, id, status, attempt, next, code, err)
        .await
        .ok();
}

/// Prune terminal deliveries older than the retention window.
pub async fn prune_tick(pool: &PgPool) -> Result<(), AppError> {
    let cutoff = OffsetDateTime::now_utc() - RETENTION;
    let n = queries::prune_terminal_deliveries(pool, cutoff).await?;
    if n > 0 {
        tracing::info!(pruned = n, "webhook deliveries pruned");
    }
    Ok(())
}

/// Return crashed 'delivering' rows to 'failed' so they are re-claimed.
pub async fn reap_stale_tick(pool: &PgPool) -> Result<(), AppError> {
    let cutoff = OffsetDateTime::now_utc() - STALE_DELIVERING;
    let n = queries::reap_stale_delivering(pool, cutoff).await?;
    if n > 0 {
        tracing::warn!(recovered = n, "stale 'delivering' webhook deliveries recovered");
    }
    Ok(())
}
