//! Console-DB persistence layer (BACK-03).
//!
//! `build_pool` is the single place a `PgPool` is constructed; `models` holds
//! the `sqlx::FromRow` structs (deliberately NOT `Serialize` — Pattern 6 /
//! BACK-07), and `queries` holds the parameterized `query!`/`query_as!`
//! wrappers used this phase.

pub mod models;
pub mod queries;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::AppError;

/// Maximum pooled connections. Modest cap: the console is a low-concurrency
/// admin tool, and the Phase-1 console role is least-privilege.
const MAX_CONNECTIONS: u32 = 10;

/// Build the console-DB connection pool from the DSN. The DSN is a secret and
/// is never logged here (errors map to the generic `AppError::Db`).
pub async fn build_pool(dsn: &str) -> Result<PgPool, AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect(dsn)
        .await?;
    Ok(pool)
}
