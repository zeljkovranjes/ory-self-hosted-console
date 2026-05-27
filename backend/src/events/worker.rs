//! Event-stream workers (Phase 17 — EVT-01/02/03).
//!
//! Three boot-spawned tokio ticks (mirroring `webhooks::worker`, spawned from
//! `main.rs`) drive the audit→sink pipeline:
//!
//!   - [`fan_out_tick`] — for each ENABLED sink, read `console_audit_log` rows
//!     PAST the sink's per-sink cursor, filter by the sink's `events` allowlist,
//!     [`redact`](super::redact::redact) the payload, enqueue ONE `event_deliveries`
//!     row per (sink, event), then advance the cursor past the latest processed
//!     row. A new sink's cursor is seeded to now() (Plan 01), so history is NEVER
//!     replayed.
//!   - [`delivery_tick_with`] — claim due `event_deliveries` (SKIP LOCKED),
//!     dispatch through [`Sink::deliver`](super::Sink::deliver), and record
//!     delivered | backoff retry | dead EXACTLY like `webhooks::worker::deliver_one`.
//!   - [`prune_tick`] / [`reap_stale_tick`] — retention + crash recovery for
//!     `event_deliveries`, cloned from the webhook versions.
//!
//! Every tick is fallible-but-non-panicking: the caller's loop logs an `Err` and
//! continues (a transient DB blip must not kill a worker). Within the delivery
//! tick, ONE bad delivery never aborts the batch — each failure is RECORDED, never
//! propagated.

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::AppError;

use super::{queries, redact, Sink};

/// Backoff base: `next_attempt_at = now() + base * 2^attempt` (matches the webhook
/// worker so the two queues retry at the same cadence).
const BACKOFF_BASE: Duration = Duration::from_secs(30);
/// Backoff cap (1h).
const BACKOFF_CAP: Duration = Duration::from_secs(3600);
/// Max deliveries claimed per delivery tick.
const CLAIM_BATCH: i64 = 10;
/// Max audit rows fanned out per sink per fan-out tick (bounds a burst).
pub const FANOUT_BATCH: i64 = 100;
/// Retention window for terminal rows (delivered/dead) — pruned after 30 days.
pub const RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
/// A delivery stuck 'delivering' longer than this is considered crashed and is
/// returned to 'failed' for re-claim.
pub const STALE_DELIVERING: Duration = Duration::from_secs(300);

/// Compute the next attempt time for a retry: `now() + min(base*2^attempt, cap)`.
/// `attempt` is the number of attempts ALREADY made.
fn backoff_next(attempt: i32) -> OffsetDateTime {
    let shift = attempt.clamp(0, 16) as u32;
    let secs = BACKOFF_BASE
        .as_secs()
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_CAP.as_secs());
    OffsetDateTime::now_utc() + Duration::from_secs(secs)
}

// --- fan-out (audit → event_deliveries) -------------------------------------

/// One fan-out sweep: for every ENABLED sink, stream new audit rows past its
/// cursor, filter by its `events` allowlist, redact, enqueue one delivery per
/// (sink, event), and advance the cursor. Never panics the loop.
///
/// `batch` bounds how many audit rows are read per sink per tick.
pub async fn fan_out_tick(pool: &PgPool, batch: i64) -> Result<(), AppError> {
    // Only enabled sinks fan out; a disabled sink keeps its cursor frozen so it
    // does NOT backfill a flood when re-enabled (it resumes from where it paused —
    // acceptable for an audit stream; the cursor was seeded to now() on create).
    let sinks = queries::list_enabled_sinks(pool).await?;
    for sink in sinks {
        if let Err(e) = fan_out_sink(pool, &sink, batch).await {
            // A bad sink must not abort the whole sweep.
            tracing::warn!(sink_id = %sink.id, error = %e, "event fan-out failed for sink");
        }
    }
    Ok(())
}

/// Fan out new audit rows to a SINGLE sink. Reads rows past the cursor, enqueues
/// the allowlisted ones, and advances the cursor past the LAST row read (so even a
/// row filtered OUT advances the cursor and is never re-scanned).
async fn fan_out_sink(
    pool: &PgPool,
    sink: &super::EventSinkRow,
    batch: i64,
) -> Result<(), AppError> {
    let rows = queries::read_new_audit_since(
        pool,
        sink.last_event_cursor_at,
        sink.last_event_id,
        batch,
    )
    .await?;
    if rows.is_empty() {
        return Ok(());
    }

    for row in &rows {
        // Filter by the sink's events allowlist. An empty allowlist subscribes to
        // NOTHING (the operator must opt in explicitly) — matches the webhook
        // create-time "select at least one event" requirement.
        if !sink.events.iter().any(|e| e == &row.action) {
            continue;
        }
        let outbound = redact::redact(row);
        let payload = serde_json::to_value(&outbound)
            .map_err(|e| AppError::Internal(format!("serialize outbound event: {e}")))?;
        queries::insert_delivery(pool, sink.id, &outbound.event, &payload).await?;
    }

    // Advance the cursor past the LAST row read (rows are oldest-first), so the
    // next tick never re-scans these — filtered-out rows included.
    if let Some(last) = rows.last() {
        queries::advance_sink_cursor(pool, sink.id, last.id, last.created_at).await?;
    }
    Ok(())
}

// --- delivery (claim → dispatch via Sink) -----------------------------------

/// One delivery sweep: claim due rows and attempt each through `Sink::deliver`.
/// Never panics the loop.
///
/// `allow_private` is forwarded to each sink's delivery-time SSRF guard;
/// production callers (`main.rs`) MUST pass `false`.
pub async fn delivery_tick_with(pool: &PgPool, allow_private: bool) -> Result<(), AppError> {
    let claimed = queries::claim_due_deliveries(pool, CLAIM_BATCH).await?;
    for d in claimed {
        deliver_one(pool, d, allow_private).await;
    }
    Ok(())
}

/// Production delivery sweep — SSRF guard fully enforced.
pub async fn delivery_tick(pool: &PgPool) -> Result<(), AppError> {
    delivery_tick_with(pool, false).await
}

/// Attempt a single claimed delivery and record the result. Self-contained: any
/// error becomes a recorded failure/dead row, never a propagated error (so one bad
/// delivery cannot abort the batch). Mirrors `webhooks::worker::deliver_one`.
async fn deliver_one(pool: &PgPool, d: queries::ClaimedEventDelivery, allow_private: bool) {
    let next_attempt = d.attempt + 1;
    let is_last = next_attempt >= d.max_attempts;

    // Fetch the owning sink (need its kind + credential to build the adapter). A
    // deleted/missing sink → dead (nothing to deliver to).
    let sink_row = match queries::get_sink(pool, d.sink_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            record(pool, d.id, "dead", next_attempt, None, Some("sink no longer exists")).await;
            return;
        }
        Err(e) => {
            let status = if is_last { "dead" } else { "failed" };
            tracing::warn!(error = %e, "event worker: fetch owning sink failed");
            record(pool, d.id, status, next_attempt, None, Some("internal error fetching sink")).await;
            return;
        }
    };

    if !sink_row.enabled {
        // A disabled sink is terminal for this delivery — do not deliver.
        record(pool, d.id, "dead", next_attempt, None, Some("sink is disabled")).await;
        return;
    }

    // Build the concrete adapter. A feature-absent / unknown sink kind is a clean
    // recorded 'dead' (never a panic) — the adapter was not compiled into this
    // build, so the delivery can never succeed.
    let sink = match Sink::build(&sink_row) {
        Ok(s) => s,
        Err(e) => {
            let reason = match &e {
                AppError::BadRequest(m) => m.clone(),
                other => format!("sink build error: {other}"),
            };
            record(pool, d.id, "dead", next_attempt, None, Some(&reason)).await;
            return;
        }
    };

    // Reconstruct the OutboundEvent from the stored (already-redacted) payload.
    let outbound = match serde_json::from_value::<super::OutboundEvent>(d.payload.clone()) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, "event worker: stored payload is not an OutboundEvent");
            record(pool, d.id, "dead", next_attempt, None, Some("payload deserialize error")).await;
            return;
        }
    };

    // Dispatch through the registry. The webhook sink SSRF-re-validates at delivery
    // time (DNS-rebind defense); brokers re-check host:port. Ok → delivered; Err →
    // backoff retry, or dead at max.
    match sink.deliver(&outbound, allow_private).await {
        Ok(()) => {
            record(pool, d.id, "delivered", next_attempt, None, None).await;
        }
        Err(e) => {
            let reason = match &e {
                AppError::BadRequest(m) => m.clone(),
                AppError::Upstream(m) => m.clone(),
                other => format!("delivery error: {other}"),
            };
            let status = if is_last { "dead" } else { "failed" };
            tracing::warn!(sink_id = %d.sink_id, reason = %reason, "event delivery failed");
            record(pool, d.id, status, next_attempt, None, Some(&reason)).await;
        }
    }
}

/// Schedule a backoff retry (for 'failed') or a terminal now() (delivered/dead) and
/// record the result. Mirrors `webhooks::worker::record`.
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

// --- maintenance (retention + crash recovery) -------------------------------

/// Prune terminal event deliveries older than the retention window.
pub async fn prune_tick(pool: &PgPool) -> Result<(), AppError> {
    let cutoff = OffsetDateTime::now_utc() - RETENTION;
    let n = queries::prune_terminal_deliveries(pool, cutoff).await?;
    if n > 0 {
        tracing::info!(pruned = n, "event deliveries pruned");
    }
    Ok(())
}

/// Return crashed 'delivering' rows to 'failed' so they are re-claimed.
pub async fn reap_stale_tick(pool: &PgPool) -> Result<(), AppError> {
    let cutoff = OffsetDateTime::now_utc() - STALE_DELIVERING;
    let n = queries::reap_stale_delivering(pool, cutoff).await?;
    if n > 0 {
        tracing::warn!(recovered = n, "stale 'delivering' event deliveries recovered");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Create an enabled webhook sink subscribed to the given events, and seed its
    /// cursor to the EARLIEST possible time (so a row inserted in the test IS seen).
    async fn make_sink(pool: &PgPool, events: &[&str]) -> Uuid {
        let events: Vec<String> = events.iter().map(|s| s.to_string()).collect();
        let row = queries::create_sink(
            pool,
            "fanout-sink",
            "webhook",
            "https://example.com/hook",
            None,
            &events,
            "sek",
            None,
            false,
            true,
        )
        .await
        .expect("create sink");
        // The sink's cursor was seeded to now(); for fan-out tests we rewind it to
        // the epoch so rows inserted just before/after are all visible to the test.
        sqlx::query!(
            "UPDATE event_sinks SET last_event_cursor_at = '1970-01-01T00:00:00Z', last_event_id = NULL WHERE id = $1",
            row.id
        )
        .execute(pool)
        .await
        .unwrap();
        row.id
    }

    async fn count_deliveries(pool: &PgPool, sink_id: Uuid) -> i64 {
        sqlx::query!(
            "SELECT count(*) AS \"n!\" FROM event_deliveries WHERE sink_id = $1",
            sink_id
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .n
    }

    /// EVT-01/02: the fan-out tick enqueues exactly one delivery per allowlisted
    /// audit row and advances the cursor past the latest row.
    #[sqlx::test(migrations = "./migrations")]
    async fn fan_out_enqueues_per_sink_event(pool: PgPool) {
        let sink_id = make_sink(&pool, &["identity.created"]).await;
        let id1 = crate::audit::queries::insert_audit(
            &pool, None, None, "identity.created", Some("POST"), Some("/a"), None, None, "success", None,
        )
        .await
        .unwrap();
        let id2 = crate::audit::queries::insert_audit(
            &pool, None, None, "identity.created", Some("POST"), Some("/b"), None, None, "success", None,
        )
        .await
        .unwrap();

        fan_out_tick(&pool, FANOUT_BATCH).await.unwrap();

        assert_eq!(count_deliveries(&pool, sink_id).await, 2, "expected one delivery per event");

        // Cursor advanced past the latest row → a second tick enqueues nothing new.
        fan_out_tick(&pool, FANOUT_BATCH).await.unwrap();
        assert_eq!(count_deliveries(&pool, sink_id).await, 2, "cursor did not advance (history replayed)");

        let sink = queries::get_sink(&pool, sink_id).await.unwrap().unwrap();
        assert!(
            sink.last_event_id == Some(id2) || sink.last_event_id == Some(id1),
            "cursor not advanced to a processed row"
        );
    }

    /// EVT-01: an audit row whose action is NOT in the sink's allowlist is NOT
    /// enqueued (but still advances the cursor so it is never re-scanned).
    #[sqlx::test(migrations = "./migrations")]
    async fn fan_out_respects_events_allowlist(pool: PgPool) {
        let sink_id = make_sink(&pool, &["identity.created"]).await;
        crate::audit::queries::insert_audit(
            &pool, None, None, "session.revoked", Some("DELETE"), Some("/s"), None, None, "success", None,
        )
        .await
        .unwrap();

        fan_out_tick(&pool, FANOUT_BATCH).await.unwrap();
        assert_eq!(count_deliveries(&pool, sink_id).await, 0, "non-allowlisted event was enqueued");
    }

    /// EVT-02: the enqueued payload's `id` equals the source audit row id.
    #[sqlx::test(migrations = "./migrations")]
    async fn event_carries_idempotency_id(pool: PgPool) {
        let sink_id = make_sink(&pool, &["identity.created"]).await;
        let audit_id = crate::audit::queries::insert_audit(
            &pool, None, None, "identity.created", Some("POST"), Some("/a"), None, None, "success", None,
        )
        .await
        .unwrap();

        fan_out_tick(&pool, FANOUT_BATCH).await.unwrap();

        let payload = sqlx::query!(
            "SELECT payload FROM event_deliveries WHERE sink_id = $1 LIMIT 1",
            sink_id
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .payload;
        let ev: super::super::OutboundEvent = serde_json::from_value(payload).unwrap();
        assert_eq!(ev.id, audit_id, "outbound event id must equal the source audit row id");
    }

    /// EVT-03: a delivery whose sink targets a loopback URL with allow_private=false
    /// is recorded 'failed'/'dead' (NEVER delivered), proving the shared SSRF guard
    /// runs at delivery time.
    #[sqlx::test(migrations = "./migrations")]
    async fn delivery_blocked_by_ssrf(pool: PgPool) {
        // A sink pointing at loopback.
        let row = queries::create_sink(
            &pool,
            "ssrf-sink",
            "webhook",
            "http://127.0.0.1/hook",
            None,
            &["identity.created".to_string()],
            "sek",
            None,
            false,
            true,
        )
        .await
        .unwrap();
        let did = queries::insert_delivery(&pool, row.id, "identity.created", &serde_json::json!({
            "id": Uuid::new_v4(), "event": "identity.created",
            "occurred_at": "2026-01-01T00:00:00Z", "data": {}
        }))
        .await
        .unwrap();

        // allow_private = false → the shared guard rejects loopback; nothing is POSTed.
        delivery_tick_with(&pool, false).await.unwrap();

        let row = sqlx::query!(
            "SELECT status FROM event_deliveries WHERE id = $1",
            did
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            row.status == "failed" || row.status == "dead",
            "SSRF-blocked delivery should be failed/dead, got {}",
            row.status
        );
        assert_ne!(row.status, "delivered", "SSRF-blocked target must never be delivered");
    }

    /// EVT-02: a delivery at the last attempt records 'dead' on failure.
    #[sqlx::test(migrations = "./migrations")]
    async fn exhausts_to_dead(pool: PgPool) {
        let row = queries::create_sink(
            &pool,
            "dead-sink",
            "webhook",
            "http://127.0.0.1/hook",
            None,
            &["identity.created".to_string()],
            "sek",
            None,
            false,
            true,
        )
        .await
        .unwrap();
        let did = queries::insert_delivery(&pool, row.id, "identity.created", &serde_json::json!({
            "id": Uuid::new_v4(), "event": "identity.created",
            "occurred_at": "2026-01-01T00:00:00Z", "data": {}
        }))
        .await
        .unwrap();
        // Drive attempt to max_attempts-1 so the NEXT failure is terminal.
        sqlx::query!(
            "UPDATE event_deliveries SET attempt = max_attempts - 1 WHERE id = $1",
            did
        )
        .execute(&pool)
        .await
        .unwrap();

        delivery_tick_with(&pool, false).await.unwrap();

        let status = sqlx::query!("SELECT status FROM event_deliveries WHERE id = $1", did)
            .fetch_one(&pool)
            .await
            .unwrap()
            .status;
        assert_eq!(status, "dead", "the last attempt must record 'dead' on failure");
    }
}
