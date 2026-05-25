//! Console-DB row models.
//!
//! CRITICAL (Pattern 6 / BACK-07 / threat T-02-01): NONE of these structs derive
//! `Serialize`. They carry secret-bearing columns (`password_hash`, `token_hash`,
//! `csrf_token`, `bootstrap_token_hash`). Because they are not `Serialize`, the
//! compiler makes `res.render(Json(admin))` impossible — secrets physically
//! cannot leak through a response body. Handlers must map to a dedicated,
//! secret-free response DTO (added in later plans).
//!
//! Timestamps use `time::OffsetDateTime` to match the sqlx `time` feature.

use time::OffsetDateTime;
use uuid::Uuid;

/// A console operator. `password_hash` is `None` for OAuth-only admins;
/// `github_user_id` is `None` until a GitHub identity is linked.
#[derive(Debug, sqlx::FromRow)]
pub struct Admin {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    /// Argon2id PHC string. SECRET — never serialized.
    pub password_hash: Option<String>,
    pub github_user_id: Option<i64>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

/// A DB-backed opaque session. Only the SHA-256 `token_hash` is stored; the raw
/// token lives solely in the client cookie. `csrf_token` is the per-session
/// double-submit value.
#[derive(Debug, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    /// SHA-256 hash of the opaque session token. SECRET — never serialized.
    pub token_hash: String,
    pub admin_id: Uuid,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// Per-session CSRF token. SECRET — never serialized.
    pub csrf_token: String,
}

/// Singleton first-run state row. `initialized` is the server-side flag that
/// guards `/setup` (CAUTH-01). `bootstrap_token_hash` is the hash of the
/// one-time setup token (CAUTH-02).
#[derive(Debug, sqlx::FromRow)]
pub struct ConsoleSettings {
    pub initialized: bool,
    /// Hash of the one-time bootstrap token. SECRET — never serialized.
    pub bootstrap_token_hash: Option<String>,
    pub created_at: OffsetDateTime,
}
