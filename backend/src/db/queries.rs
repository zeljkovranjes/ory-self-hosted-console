//! Parameterized console-DB queries used in Phase 2.
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — never string interpolation
//! (threat T-02-03 / SQL injection). Secret-bearing rows map to the non-
//! `Serialize` models in `super::models`.

use sqlx::PgPool;

use super::models::ConsoleSettings;
use crate::error::AppError;

/// Whether the console has completed first-run setup (CAUTH-01). Fails CLOSED:
/// the caller treats an error as "initialized" so a DB blip cannot re-open
/// `/setup`. Returns the boolean from the singleton `console_settings` row, or
/// `false` when no row exists yet (fresh DB → setup is open).
pub async fn is_initialized(pool: &PgPool) -> Result<bool, AppError> {
    let row = sqlx::query!("SELECT initialized FROM console_settings WHERE id = true")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.initialized).unwrap_or(false))
}

/// Count existing admins. Used at boot to decide whether to generate a
/// first-run bootstrap token.
pub async fn count_admins(pool: &PgPool) -> Result<i64, AppError> {
    let row = sqlx::query!(r#"SELECT COUNT(*) AS "count!" FROM admins"#)
        .fetch_one(pool)
        .await?;
    Ok(row.count)
}

/// Insert (or update) the singleton console-settings row with the bootstrap
/// token hash, leaving `initialized = false`. Idempotent on the single row.
pub async fn insert_console_settings(
    pool: &PgPool,
    bootstrap_token_hash: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        INSERT INTO console_settings (id, initialized, bootstrap_token_hash)
        VALUES (true, false, $1)
        ON CONFLICT (id) DO UPDATE
            SET bootstrap_token_hash = EXCLUDED.bootstrap_token_hash,
                initialized = false
        "#,
        bootstrap_token_hash
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch the singleton console-settings row, if present.
pub async fn get_console_settings(pool: &PgPool) -> Result<Option<ConsoleSettings>, AppError> {
    let settings = sqlx::query_as!(
        ConsoleSettings,
        r#"
        SELECT initialized, bootstrap_token_hash, created_at
        FROM console_settings
        WHERE id = true
        "#
    )
    .fetch_optional(pool)
    .await?;
    Ok(settings)
}
