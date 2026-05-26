//! Console members (PROJ-04).
//!
//! `GET /api/console/members` lists the console OPERATOR accounts from the
//! Phase-2 `admins` table — these are console logins (local-admin password or
//! linked GitHub OAuth), NOT Ory identities. The single-admin guard index was
//! DROPPED in 11-01 (migration 0006), so multiple operators are now permitted.
//!
//! CRITICAL (BACK-07 / T-11-12): the [`crate::db::models::Admin`] model carries
//! `password_hash` and is deliberately NOT `Serialize`. We NEVER serialize it;
//! the query selects only non-secret columns and maps them to the secret-free
//! [`MemberView`] (no `password_hash`). `account_type` is derived: "Local admin"
//! when a password hash exists, else "GitHub" when a github_user_id is linked,
//! else "Unknown" (an account with neither — should not occur, surfaced rather
//! than hidden).
//!
//! v1 is LIST-ONLY: the `admins` schema does not cleanly support add/remove
//! without more work, and the "console accounts vs Ory identities" framing is
//! rendered by the frontend (RESEARCH leaves management depth to discretion).

use salvo::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

/// A secret-free console-operator DTO. Carries NO `password_hash` (T-11-12).
#[derive(Debug, Clone, Serialize)]
pub struct MemberView {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    /// "Local admin" | "GitHub" | "Unknown" — the login type, NOT a role.
    pub account_type: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

/// Obtain the console pool from the Depot, cloning BEFORE any await.
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// Derive the login type label from the secret-free presence flags. The
/// password_hash VALUE is never read here — only whether it exists.
fn account_type(has_password: bool, has_github: bool) -> &'static str {
    match (has_password, has_github) {
        (true, _) => "Local admin",
        (false, true) => "GitHub",
        (false, false) => "Unknown",
    }
}

/// `GET /api/console/members` — list console operator accounts (PROJ-04).
///
/// Maps `admins` rows to the secret-free [`MemberView`]. Multiple operators are
/// permitted (single-admin guard dropped in 11-01). The query selects only
/// non-secret columns + a `password_hash IS NOT NULL` flag, so the hash value
/// never leaves Postgres (T-11-12).
#[handler]
pub async fn list_members(depot: &mut Depot) -> Result<Json<Vec<MemberView>>, AppError> {
    let pool = pool(depot)?;

    let rows = sqlx::query!(
        r#"
        SELECT id,
               email::text AS "email!",
               name,
               (password_hash IS NOT NULL) AS "has_password!",
               (github_user_id IS NOT NULL) AS "has_github!",
               created_at,
               last_login_at
        FROM admins
        ORDER BY created_at ASC
        "#
    )
    .fetch_all(&pool)
    .await?;

    let members = rows
        .into_iter()
        .map(|r| MemberView {
            id: r.id,
            email: r.email,
            name: r.name,
            account_type: account_type(r.has_password, r.has_github),
            created_at: r.created_at,
            last_login_at: r.last_login_at,
        })
        .collect();
    Ok(Json(members))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_type_prefers_local_then_github_then_unknown() {
        assert_eq!(account_type(true, false), "Local admin");
        assert_eq!(account_type(true, true), "Local admin");
        assert_eq!(account_type(false, true), "GitHub");
        assert_eq!(account_type(false, false), "Unknown");
    }
}
