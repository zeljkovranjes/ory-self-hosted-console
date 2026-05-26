//! Parameterized console-DB queries for `feature_flags` (FLAG-02 / FLAG-04).
//!
//! All SQL goes through sqlx `query!` (compile-time checked against the committed
//! `.sqlx` offline metadata) — NEVER string interpolation. The table is the
//! single console-owned source of truth for feature-toggle state; the in-process
//! [`super::FeatureFlags`] cache is loaded from `load_all` at boot and refreshed
//! by the PUT handler after `set_enabled`.

use std::collections::HashMap;

use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::AppError;

/// The post-toggle state returned by [`set_enabled`]: the flag key, its new
/// enabled state, and the write timestamp. `None` (at the call site) means the
/// key did not exist — the unknown-key → 404 path (never INSERT from input).
pub struct FlagState {
    pub key: String,
    pub enabled: bool,
    pub updated_at: OffsetDateTime,
}

/// Load every flag row into a `HashMap<key, enabled>` for the boot-time cache
/// seed. The label + `requires_runtime` metadata are NOT stored here (code-side
/// `FEATURE_META` map) — only the persisted enabled state.
pub async fn load_all(pool: &PgPool) -> Result<HashMap<String, bool>, AppError> {
    let rows = sqlx::query!("SELECT key, enabled FROM feature_flags")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| (r.key, r.enabled)).collect())
}

/// Toggle a flag: `UPDATE ... RETURNING` the new state. Returns `None` when no
/// such flag row exists (the unknown-key → 404 path). Mirrors
/// `apikeys::queries::revoke_api_key` (UPDATE-returning-optional). NEVER creates
/// a row from caller input (T-12-06).
pub async fn set_enabled(
    pool: &PgPool,
    key: &str,
    enabled: bool,
) -> Result<Option<FlagState>, AppError> {
    let row = sqlx::query!(
        r#"
        UPDATE feature_flags
        SET enabled = $1, updated_at = now()
        WHERE key = $2
        RETURNING key, enabled, updated_at
        "#,
        enabled,
        key
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| FlagState {
        key: r.key,
        enabled: r.enabled,
        updated_at: r.updated_at,
    }))
}
