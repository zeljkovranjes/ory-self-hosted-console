//! Parameterized console-DB queries used in Phase 2.
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — never string interpolation
//! (threat T-02-03 / SQL injection). Secret-bearing rows map to the non-
//! `Serialize` models in `super::models`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::models::{Admin, ConsoleSettings, Session};
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

/// Count existing admins. IN-01: now WIRED — used by the GitHub callback's
/// verified-primary-email fallback (WR-04) to assert that email-based linking
/// only ever binds to the SINGLE v1 admin (never an ambiguous match once Phase
/// 11 introduces multiple admins).
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

/// Mark the console initialized and clear the bootstrap token hash (so the
/// one-time token can never be reused after `/setup` succeeds). Idempotent on
/// the singleton row.
pub async fn mark_initialized(pool: &PgPool) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        UPDATE console_settings
        SET initialized = true, bootstrap_token_hash = NULL
        WHERE id = true
        "#
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a new local admin with an Argon2id PHC password hash. Returns the new
/// admin id. Used by test seeding and (historically) `/setup`.
///
/// WR-03: a unique-constraint violation (`23505` on `email`/`github_user_id`, or
/// the `admins_single_row_guard` cap) maps to a 4xx conflict instead of a 500 —
/// a duplicate is a client/state condition, not a server fault.
pub async fn insert_admin(
    pool: &PgPool,
    email: &str,
    name: &str,
    password_hash: &str,
) -> Result<Uuid, AppError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO admins (email, name, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        email,
        name,
        password_hash
    )
    .fetch_one(pool)
    .await
    .map_err(map_unique_violation)?;
    Ok(row.id)
}

/// Map a Postgres unique-constraint violation (SQLSTATE `23505`) to a 4xx
/// conflict (`AppError::BadRequest`); any other sqlx error stays a 500-class
/// `AppError::Db`. Centralizes WR-03 so every admin-write path classifies a
/// duplicate the same way. The message is operator-safe (no secret, no raw
/// constraint detail beyond the generic cause).
fn map_unique_violation(e: sqlx::Error) -> AppError {
    match e.as_database_error().and_then(|d| d.code()).as_deref() {
        Some("23505") => {
            AppError::BadRequest("email or github account already in use".into())
        }
        _ => AppError::Db(e),
    }
}

/// CR-01: atomically create the first console admin and close the setup window
/// in ONE transaction. This is the SOLE path `/setup` uses to create an admin.
///
/// Steps inside the transaction (all-or-nothing):
///   1. `SELECT ... FOR UPDATE` the `console_settings` singleton (serializes
///      concurrent `/setup` POSTs on the row lock).
///   2. Re-check `initialized` INSIDE the lock — abort with `NotFound` (404,
///      matching the post-init guard) if already initialized.
///   3. Verify the submitted bootstrap token against the stored hash; abort
///      `Forbidden` on mismatch / no stored hash.
///   4. Belt-and-suspenders: abort `Forbidden` if any admin already exists.
///   5. INSERT the admin (the `admins_single_row_guard` unique index is the hard
///      DB cap; a violation maps to a 4xx via `map_unique_violation`).
///   6. Conditional `UPDATE ... WHERE initialized = false` — MUST affect exactly
///      one row, else abort (a concurrent winner already flipped it).
///   7. Commit. Two concurrent valid-token POSTs therefore yield EXACTLY one
///      admin: the loser blocks on the row lock, then sees `initialized = true`
///      at step 2 (or a 0-row update at step 6) and is rejected.
///
/// `verify_token` is injected (the constant-time SHA-256 compare lives in the
/// auth layer) to keep this module free of the crypto dependency.
pub async fn create_first_admin_atomic(
    pool: &PgPool,
    submitted_token: &str,
    email: &str,
    name: &str,
    password_hash: &str,
    verify_token: impl Fn(&str, &str) -> bool,
) -> Result<Uuid, AppError> {
    let mut tx = pool.begin().await?;

    // 1 + 2: lock the singleton and re-check inside the lock. No row => not in a
    // setup state at all (fail-closed Forbidden); initialized => closed (404).
    let row = sqlx::query!(
        r#"
        SELECT initialized, bootstrap_token_hash
        FROM console_settings
        WHERE id = true
        FOR UPDATE
        "#
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;

    if row.initialized {
        return Err(AppError::NotFound);
    }

    // 3: constant-time token verify against the stored hash.
    let stored = row.bootstrap_token_hash.ok_or(AppError::Forbidden)?;
    if !verify_token(submitted_token, &stored) {
        return Err(AppError::Forbidden);
    }

    // 4: belt-and-suspenders — refuse if an admin somehow already exists.
    let existing = sqlx::query!(r#"SELECT COUNT(*) AS "count!" FROM admins"#)
        .fetch_one(&mut *tx)
        .await?;
    if existing.count > 0 {
        return Err(AppError::Forbidden);
    }

    // 5: insert the admin (hard DB cap = admins_single_row_guard unique index).
    let inserted = sqlx::query!(
        r#"
        INSERT INTO admins (email, name, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        email,
        name,
        password_hash
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique_violation)?;

    // 6: conditional close — must flip exactly one row, else a concurrent winner
    // already initialized the console; abort so we never produce a 2nd admin.
    let flipped = sqlx::query!(
        r#"
        UPDATE console_settings
        SET initialized = true, bootstrap_token_hash = NULL
        WHERE id = true AND initialized = false
        "#
    )
    .execute(&mut *tx)
    .await?;
    if flipped.rows_affected() != 1 {
        return Err(AppError::Forbidden);
    }

    // 7: commit the all-or-nothing first-run transaction.
    tx.commit().await?;
    Ok(inserted.id)
}

/// Fetch an admin by (case-insensitive) email, if present. Used by `/login`.
pub async fn get_admin_by_email(pool: &PgPool, email: &str) -> Result<Option<Admin>, AppError> {
    let admin = sqlx::query_as!(
        Admin,
        r#"
        SELECT id, email::text AS "email!", name,
               password_hash, github_user_id,
               created_at, updated_at, last_login_at
        FROM admins
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;
    Ok(admin)
}

/// Fetch an admin by primary key, if present. Used by `GET /api/console/me`
/// to render the secret-free `AdminDto` for the authenticated session's admin.
pub async fn get_admin_by_id(pool: &PgPool, admin_id: Uuid) -> Result<Option<Admin>, AppError> {
    let admin = sqlx::query_as!(
        Admin,
        r#"
        SELECT id, email::text AS "email!", name,
               password_hash, github_user_id,
               created_at, updated_at, last_login_at
        FROM admins
        WHERE id = $1
        "#,
        admin_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(admin)
}

/// Fetch an admin by their linked GitHub user id, if present. The PRIMARY
/// GitHub-link lookup (CAUTH-04): a returning GitHub user is matched by the
/// numeric id persisted on first link, independent of email changes.
pub async fn find_admin_by_github_id(
    pool: &PgPool,
    github_user_id: i64,
) -> Result<Option<Admin>, AppError> {
    let admin = sqlx::query_as!(
        Admin,
        r#"
        SELECT id, email::text AS "email!", name,
               password_hash, github_user_id,
               created_at, updated_at, last_login_at
        FROM admins
        WHERE github_user_id = $1
        "#,
        github_user_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(admin)
}

/// Fetch an admin by (case-insensitive) email. Alias of `get_admin_by_email`
/// used by the GitHub callback's verified-primary-email fallback link
/// (CAUTH-04). Kept as a distinct name so the call-site intent is explicit.
pub async fn find_admin_by_email(pool: &PgPool, email: &str) -> Result<Option<Admin>, AppError> {
    get_admin_by_email(pool, email).await
}

/// Persist the GitHub user id on an existing admin (CAUTH-04 link-by-email-
/// then-persist). Idempotent: re-linking the same id is a no-op UPDATE. The
/// `github_user_id` column is UNIQUE, so linking an id already owned by another
/// admin surfaces a DB unique-violation (mapped to a generic 500 / denied at
/// the call site) rather than silently moving the link.
pub async fn link_github(
    pool: &PgPool,
    admin_id: Uuid,
    github_user_id: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE admins SET github_user_id = $1, updated_at = now() WHERE id = $2",
        github_user_id,
        admin_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a successful login timestamp for the admin.
pub async fn update_last_login(pool: &PgPool, admin_id: Uuid) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE admins SET last_login_at = now() WHERE id = $1",
        admin_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a session row. `expires_at` is computed as `now + absolute_secs` in
/// Rust and bound as a parameter (keeps the value explicit and testable). Only
/// the SHA-256 `token_hash` is persisted — never the raw token (CAUTH-05).
#[allow(clippy::too_many_arguments)]
pub async fn insert_session(
    pool: &PgPool,
    token_hash: &str,
    admin_id: Uuid,
    absolute_secs: i64,
    ip: Option<&str>,
    user_agent: Option<&str>,
    csrf_token: &str,
) -> Result<Uuid, AppError> {
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(absolute_secs);
    let row = sqlx::query!(
        r#"
        INSERT INTO sessions
            (token_hash, admin_id, expires_at, last_seen_at, ip, user_agent, csrf_token)
        VALUES ($1, $2, $3, now(), $4, $5, $6)
        RETURNING id
        "#,
        token_hash,
        admin_id,
        expires_at,
        ip,
        user_agent,
        csrf_token
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Fetch a session by its token hash, only if it is not past the absolute
/// `expires_at`. The idle-window check + `last_seen_at` slide happen in the
/// session layer. Returns `None` for a missing or absolutely-expired session.
pub async fn get_active_session(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Session>, AppError> {
    let session = sqlx::query_as!(
        Session,
        r#"
        SELECT id, token_hash, admin_id, created_at, expires_at,
               last_seen_at, ip, user_agent, csrf_token
        FROM sessions
        WHERE token_hash = $1 AND expires_at > now()
        "#,
        token_hash
    )
    .fetch_optional(pool)
    .await?;
    Ok(session)
}

/// Slide a session's `last_seen_at` to now (sliding idle expiry on a valid hit).
pub async fn touch_session(pool: &PgPool, token_hash: &str) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1",
        token_hash
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a single session by its token hash (logout).
pub async fn delete_session_by_hash(pool: &PgPool, token_hash: &str) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM sessions WHERE token_hash = $1", token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete all sessions for an admin (regenerate-on-auth: clear pre-auth /
/// stale sessions before minting a fresh one — OWASP).
pub async fn delete_sessions_for_admin(pool: &PgPool, admin_id: Uuid) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM sessions WHERE admin_id = $1", admin_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// WR-07: reap sessions past their absolute `expires_at`. Run periodically by
/// the background reaper task in `main.rs` to bound `sessions` growth (abandoned
/// sessions are never logged out, so without this the table grows without
/// bound). Idle-expired-but-not-absolutely-expired rows are left for the next
/// pass once they cross `expires_at`. Returns the number of rows deleted.
pub async fn delete_expired_sessions(pool: &PgPool) -> Result<u64, AppError> {
    let result = sqlx::query!("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
