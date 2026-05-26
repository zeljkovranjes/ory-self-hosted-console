//! Parameterized console-DB queries for `console_audit_log` (ACT-04).
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation (threat
//! T-11-15 / SQL injection). The log is APPEND-ONLY: there is an `insert` and a
//! read-only `list` (+ an age-based `prune` for retention), but NO update/delete
//! by id (T-11-13 — repudiation / tamper resistance).

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

use super::AuditView;

/// Insert one audit row. `metadata` is the jsonb column (free-form). Every
/// argument is bound as a parameter — no interpolation (T-11-15). Returns the
/// new row id.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    actor_email: Option<&str>,
    action: &str,
    method: Option<&str>,
    path: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    outcome: &str,
    metadata: Option<&serde_json::Value>,
) -> Result<Uuid, AppError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO console_audit_log
            (actor_id, actor_email, action, method, path,
             target_type, target_id, outcome, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        actor_id,
        actor_email,
        action,
        method,
        path,
        target_type,
        target_id,
        outcome,
        metadata
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Read-only, filtered, paginated listing of the audit log (newest first).
///
/// Each filter is NULL-guarded so a single parameterized query serves every
/// combination — no string interpolation (T-11-15). `before`/`after` bound the
/// `created_at` range. The actor email/id are returned, but NO secret column
/// exists on this table (T-11-12).
#[allow(clippy::too_many_arguments)]
pub async fn list_audit(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    action: Option<&str>,
    outcome: Option<&str>,
    after: Option<OffsetDateTime>,
    before: Option<OffsetDateTime>,
    limit: i64,
) -> Result<Vec<AuditView>, AppError> {
    let rows = sqlx::query_as!(
        AuditView,
        r#"
        SELECT id, actor_id, actor_email, action, method, path,
               target_type, target_id, outcome, metadata, created_at
        FROM console_audit_log
        WHERE ($1::uuid IS NULL OR actor_id = $1)
          AND ($2::text IS NULL OR action = $2)
          AND ($3::text IS NULL OR outcome = $3)
          AND ($4::timestamptz IS NULL OR created_at >= $4)
          AND ($5::timestamptz IS NULL OR created_at <= $5)
        ORDER BY created_at DESC
        LIMIT $6
        "#,
        actor_id,
        action,
        outcome,
        after,
        before,
        limit
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Age-based retention prune (backend-only, never a route — T-11-13). Deletes
/// rows older than `older_than`; returns the number pruned. Mirrors the
/// `delete_expired_sessions` shape.
pub async fn prune_audit(
    pool: &PgPool,
    older_than: OffsetDateTime,
) -> Result<u64, AppError> {
    let res = sqlx::query!(
        "DELETE FROM console_audit_log WHERE created_at < $1",
        older_than
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
