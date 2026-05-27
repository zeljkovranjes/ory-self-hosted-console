//! Parameterized console-DB queries for `event_sinks` / `event_deliveries`
//! (EVT-02) + the per-sink audit cursor.
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation. The
//! delivery-queue functions are a clone of `webhooks::queries`, keyed on `sink_id`.
//! Secret-bearing rows map to [`EventSinkRow`] (no `Serialize`); GET/list map to
//! [`EventSinkView`] which carries only masked badges.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::AuditView;
use crate::error::AppError;

use super::{EventSinkRow, EventSinkView};

/// A row claimed off the delivery queue (the worker's working set). Carries only
/// what the worker needs to deliver — NOT the credential (it fetches the owning
/// sink so a disabled/deleted sink short-circuits).
#[derive(Debug, Clone)]
pub struct ClaimedEventDelivery {
    pub id: Uuid,
    pub sink_id: Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub attempt: i32,
    pub max_attempts: i32,
}

// --- event_sinks CRUD -------------------------------------------------------

/// Create an event sink. The cursor is initialized to now() (stream-from-now,
/// Pitfall 5) so a new sink does NOT replay the entire audit history.
#[allow(clippy::too_many_arguments)]
pub async fn create_sink(
    pool: &PgPool,
    name: &str,
    kind: &str,
    target: &str,
    subject: Option<&str>,
    events: &[String],
    secret: &str,
    sasl_username: Option<&str>,
    tls: bool,
    enabled: bool,
) -> Result<EventSinkRow, AppError> {
    let row = sqlx::query_as!(
        EventSinkRow,
        r#"
        INSERT INTO event_sinks
            (name, kind, target, subject, events, secret, sasl_username, tls,
             enabled, last_event_cursor_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
        RETURNING id, name, kind, target, subject, events, secret, sasl_username,
                  tls, enabled, last_event_id, last_event_cursor_at,
                  created_at, updated_at
        "#,
        name,
        kind,
        target,
        subject,
        events,
        secret,
        sasl_username,
        tls,
        enabled
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// List all sinks as credential-free views (newest first). The masked badges are
/// computed in SQL so the secret never enters a Rust value.
pub async fn list_sinks(pool: &PgPool) -> Result<Vec<EventSinkView>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, name, kind, target, subject, events,
               (secret <> '') AS "secret_set!",
               (sasl_username IS NOT NULL AND sasl_username <> '') AS "sasl_username_set!",
               tls, enabled, created_at, updated_at
        FROM event_sinks
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| EventSinkView {
            id: r.id,
            name: r.name,
            kind: r.kind,
            target: r.target,
            subject: r.subject,
            events: r.events,
            secret_set: r.secret_set,
            sasl_username_set: r.sasl_username_set,
            tls: r.tls,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

/// List every ENABLED sink as a full row (incl. cursor + credential) for the
/// fan-out worker. NEVER rendered to a response (EventSinkRow is not `Serialize`).
pub async fn list_enabled_sinks(pool: &PgPool) -> Result<Vec<EventSinkRow>, AppError> {
    let rows = sqlx::query_as!(
        EventSinkRow,
        r#"
        SELECT id, name, kind, target, subject, events, secret, sasl_username,
               tls, enabled, last_event_id, last_event_cursor_at,
               created_at, updated_at
        FROM event_sinks
        WHERE enabled = true
        ORDER BY created_at ASC
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetch the full row (incl. credential) by id. Used by the worker + update merge
/// — NEVER rendered to a response directly (EventSinkRow is not `Serialize`).
pub async fn get_sink(pool: &PgPool, id: Uuid) -> Result<Option<EventSinkRow>, AppError> {
    let row = sqlx::query_as!(
        EventSinkRow,
        r#"
        SELECT id, name, kind, target, subject, events, secret, sasl_username,
               tls, enabled, last_event_id, last_event_cursor_at,
               created_at, updated_at
        FROM event_sinks WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Update mutable fields. `secret` is intentionally NOT a parameter here — the
/// credential can only be changed via [`rotate_secret`], so an edit can NEVER
/// blank it.
#[allow(clippy::too_many_arguments)]
pub async fn update_sink(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    target: &str,
    subject: Option<&str>,
    events: &[String],
    sasl_username: Option<&str>,
    tls: bool,
    enabled: bool,
) -> Result<Option<EventSinkRow>, AppError> {
    let row = sqlx::query_as!(
        EventSinkRow,
        r#"
        UPDATE event_sinks
        SET name = $2, target = $3, subject = $4, events = $5,
            sasl_username = $6, tls = $7, enabled = $8, updated_at = now()
        WHERE id = $1
        RETURNING id, name, kind, target, subject, events, secret, sasl_username,
                  tls, enabled, last_event_id, last_event_cursor_at,
                  created_at, updated_at
        "#,
        id,
        name,
        target,
        subject,
        events,
        sasl_username,
        tls,
        enabled
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Rotate the credential to a new recoverable value. Returns the updated row (the
/// caller reveals the new secret exactly once).
pub async fn rotate_secret(
    pool: &PgPool,
    id: Uuid,
    new_secret: &str,
) -> Result<Option<EventSinkRow>, AppError> {
    let row = sqlx::query_as!(
        EventSinkRow,
        r#"
        UPDATE event_sinks
        SET secret = $2, updated_at = now()
        WHERE id = $1
        RETURNING id, name, kind, target, subject, events, secret, sasl_username,
                  tls, enabled, last_event_id, last_event_cursor_at,
                  created_at, updated_at
        "#,
        id,
        new_secret
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete a sink (its deliveries cascade).
pub async fn delete_sink(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
    let res = sqlx::query!("DELETE FROM event_sinks WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

// --- per-sink audit cursor --------------------------------------------------

/// Read `console_audit_log` rows NEWER than the per-sink cursor (mirrors
/// `audit::queries::list_audit`'s parameterized shape), oldest-first so the cursor
/// advances monotonically. A NULL cursor reads from the beginning — but
/// [`create_sink`] seeds the cursor to now(), so a live sink never sees NULL.
pub async fn read_new_audit_since(
    pool: &PgPool,
    after_at: Option<OffsetDateTime>,
    after_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<AuditView>, AppError> {
    let rows = sqlx::query_as!(
        AuditView,
        r#"
        SELECT id, actor_id, actor_email, action, method, path,
               target_type, target_id, outcome, metadata, created_at
        FROM console_audit_log
        WHERE ($1::timestamptz IS NULL OR created_at > $1
               OR (created_at = $1 AND ($2::uuid IS NULL OR id > $2)))
        ORDER BY created_at ASC, id ASC
        LIMIT $3
        "#,
        after_at,
        after_id,
        limit
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Advance the per-sink cursor after fanning out a batch.
pub async fn advance_sink_cursor(
    pool: &PgPool,
    sink_id: Uuid,
    last_event_id: Uuid,
    last_event_cursor_at: OffsetDateTime,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        UPDATE event_sinks
        SET last_event_id = $2, last_event_cursor_at = $3, updated_at = now()
        WHERE id = $1
        "#,
        sink_id,
        last_event_id,
        last_event_cursor_at
    )
    .execute(pool)
    .await?;
    Ok(())
}

// --- event_deliveries (clone of webhooks::queries, keyed on sink_id) ---------

/// Enqueue a delivery (status 'pending', due now).
pub async fn insert_delivery(
    pool: &PgPool,
    sink_id: Uuid,
    event: &str,
    payload: &serde_json::Value,
) -> Result<Uuid, AppError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO event_deliveries (sink_id, event, payload)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        sink_id,
        event,
        payload
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Atomically claim up to `limit` due deliveries with FOR UPDATE SKIP LOCKED.
/// The 'delivering' transition commits before any outbound I/O (crash-safety;
/// the stale reaper recovers a crashed row).
pub async fn claim_due_deliveries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ClaimedEventDelivery>, AppError> {
    let rows = sqlx::query!(
        r#"
        UPDATE event_deliveries
        SET status = 'delivering', updated_at = now()
        WHERE id IN (
            SELECT id FROM event_deliveries
            WHERE status IN ('pending', 'failed') AND next_attempt_at <= now()
            ORDER BY next_attempt_at
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        RETURNING id, sink_id, event, payload, attempt, max_attempts
        "#,
        limit
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ClaimedEventDelivery {
            id: r.id,
            sink_id: r.sink_id,
            event: r.event,
            payload: r.payload,
            attempt: r.attempt,
            max_attempts: r.max_attempts,
        })
        .collect())
}

/// Record the outcome of a delivery attempt.
pub async fn record_delivery_result(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    attempt: i32,
    next_attempt_at: OffsetDateTime,
    last_status_code: Option<i32>,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        UPDATE event_deliveries
        SET status = $2, attempt = $3, next_attempt_at = $4,
            last_status_code = $5, last_error = $6, updated_at = now()
        WHERE id = $1
        "#,
        id,
        status,
        attempt,
        next_attempt_at,
        last_status_code,
        last_error
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete terminal (delivered/dead) deliveries older than `older_than`. Returns
/// the number pruned (retention; mirrors `prune_terminal_deliveries`).
pub async fn prune_terminal_deliveries(
    pool: &PgPool,
    older_than: OffsetDateTime,
) -> Result<u64, AppError> {
    let res = sqlx::query!(
        r#"
        DELETE FROM event_deliveries
        WHERE status IN ('delivered', 'dead') AND updated_at < $1
        "#,
        older_than
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Return rows stuck in 'delivering' past `stale_before` back to 'failed' so they
/// are re-claimed (crash recovery).
pub async fn reap_stale_delivering(
    pool: &PgPool,
    stale_before: OffsetDateTime,
) -> Result<u64, AppError> {
    let res = sqlx::query!(
        r#"
        UPDATE event_deliveries
        SET status = 'failed', updated_at = now()
        WHERE status = 'delivering' AND updated_at < $1
        "#,
        stale_before
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a webhook sink for delivery-queue tests.
    async fn make_sink(pool: &PgPool) -> Uuid {
        let row = create_sink(
            pool,
            "test-sink",
            "webhook",
            "https://example.com/hook",
            None,
            &["identity.created".to_string()],
            "sek",
            None,
            false,
            true,
        )
        .await
        .expect("create sink");
        // Pitfall 5: a fresh sink's cursor is seeded to now() (NOT NULL).
        assert!(row.last_event_cursor_at.is_some(), "cursor not initialized to now()");
        row.id
    }

    /// EVT-02: claim_due_deliveries claims a 'pending' row (-> 'delivering') and
    /// skips a not-yet-due row.
    #[sqlx::test(migrations = "./migrations")]
    async fn claim_skips_not_due(pool: PgPool) {
        let sink = make_sink(&pool).await;
        let due = insert_delivery(&pool, sink, "identity.created", &serde_json::json!({"a":1}))
            .await
            .unwrap();
        // A not-yet-due row (future next_attempt_at).
        let not_due = insert_delivery(&pool, sink, "identity.created", &serde_json::json!({"b":2}))
            .await
            .unwrap();
        record_delivery_result(
            &pool,
            not_due,
            "failed",
            1,
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            None,
            Some("retry later"),
        )
        .await
        .unwrap();

        let claimed = claim_due_deliveries(&pool, 10).await.unwrap();
        let ids: Vec<Uuid> = claimed.iter().map(|c| c.id).collect();
        assert!(ids.contains(&due), "due row not claimed");
        assert!(!ids.contains(&not_due), "not-yet-due row was claimed");
    }

    /// EVT-02: a row at attempt = max_attempts-1 records 'dead' on the next failure.
    #[sqlx::test(migrations = "./migrations")]
    async fn exhausts_to_dead(pool: PgPool) {
        let sink = make_sink(&pool).await;
        let id = insert_delivery(&pool, sink, "identity.created", &serde_json::json!({}))
            .await
            .unwrap();
        // Simulate the last attempt: record 'dead'.
        record_delivery_result(&pool, id, "dead", 8, OffsetDateTime::now_utc(), None, Some("max"))
            .await
            .unwrap();
        // A 'dead' row is terminal — not re-claimed.
        let claimed = claim_due_deliveries(&pool, 10).await.unwrap();
        assert!(!claimed.iter().any(|c| c.id == id), "dead row was re-claimed");
    }

    /// EVT-02: prune removes a terminal row older than the cutoff, keeps a fresh one.
    #[sqlx::test(migrations = "./migrations")]
    async fn prune_terminal_removes_old_keeps_fresh(pool: PgPool) {
        let sink = make_sink(&pool).await;
        let old = insert_delivery(&pool, sink, "identity.created", &serde_json::json!({}))
            .await
            .unwrap();
        // Mark delivered + backdate updated_at well past the cutoff.
        sqlx::query!(
            "UPDATE event_deliveries SET status='delivered', updated_at = now() - interval '40 days' WHERE id = $1",
            old
        )
        .execute(&pool)
        .await
        .unwrap();
        let fresh = insert_delivery(&pool, sink, "identity.created", &serde_json::json!({}))
            .await
            .unwrap();
        sqlx::query!(
            "UPDATE event_deliveries SET status='delivered' WHERE id = $1",
            fresh
        )
        .execute(&pool)
        .await
        .unwrap();

        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(30);
        let pruned = prune_terminal_deliveries(&pool, cutoff).await.unwrap();
        assert_eq!(pruned, 1, "expected exactly the old row pruned");
        assert!(get_remaining(&pool, fresh).await, "fresh row was pruned");
        assert!(!get_remaining(&pool, old).await, "old row not pruned");
    }

    /// EVT-03 cursor: a new sink (cursor = now()) does NOT replay a pre-existing
    /// audit row, but DOES see one inserted after.
    #[sqlx::test(migrations = "./migrations")]
    async fn cursor_streams_from_now(pool: PgPool) {
        // An audit row that exists BEFORE the sink is created.
        crate::audit::queries::insert_audit(
            &pool, None, None, "old.event", Some("POST"), Some("/x"), None, None, "success", None,
        )
        .await
        .unwrap();

        let sink_id = make_sink(&pool).await;
        let sink = get_sink(&pool, sink_id).await.unwrap().unwrap();
        let cursor_at = sink.last_event_cursor_at;

        // Reading since the (now()) cursor must NOT include the pre-existing row.
        let before = read_new_audit_since(&pool, cursor_at, sink.last_event_id, 100)
            .await
            .unwrap();
        assert!(
            before.iter().all(|r| r.action != "old.event"),
            "new sink replayed historical audit row"
        );

        // A NEW audit row after the sink is created IS visible.
        let new_id = crate::audit::queries::insert_audit(
            &pool, None, None, "new.event", Some("POST"), Some("/y"), None, None, "success", None,
        )
        .await
        .unwrap();
        let after = read_new_audit_since(&pool, cursor_at, sink.last_event_id, 100)
            .await
            .unwrap();
        assert!(after.iter().any(|r| r.id == new_id), "new audit row not streamed");

        // Advancing the cursor past it means it is no longer re-read.
        if let Some(last) = after.last() {
            advance_sink_cursor(&pool, sink_id, last.id, last.created_at)
                .await
                .unwrap();
            let again = read_new_audit_since(&pool, Some(last.created_at), Some(last.id), 100)
                .await
                .unwrap();
            assert!(again.iter().all(|r| r.id != new_id), "cursor did not advance past row");
        }
    }

    async fn get_remaining(pool: &PgPool, id: Uuid) -> bool {
        sqlx::query!("SELECT id FROM event_deliveries WHERE id = $1", id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .is_some()
    }
}
