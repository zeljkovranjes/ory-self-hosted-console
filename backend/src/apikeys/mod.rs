//! Console API keys (PROJ-02).
//!
//! CRITICAL secret regime — the INVERSE of the webhook secret (11-01): a console
//! API key is ONE-WAY SHA-256 hashed at rest (`key_hash`), because the backend
//! only ever VERIFIES a presented key, never re-emits it. The raw key is shown to
//! the operator EXACTLY ONCE in the issue response and is unrecoverable
//! thereafter (T-11-11). This is NOT the recoverable webhook-secret pattern — do
//! not copy it here.
//!
//! Storage discipline (BACK-07 / db/models): [`ApiKeyRow`] carries `key_hash` and
//! therefore deliberately does NOT derive `Serialize`, so the compiler makes
//! rendering it into a response body impossible. Every list/detail response maps
//! to [`ApiKeyView`], which exposes only a non-secret masked display fragment
//! (`key_prefix` + dots) and a lifecycle `state` — never the hash, never the raw.

pub mod queries;
pub mod routes;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// A full `console_api_keys` row, INCLUDING the one-way `key_hash`.
///
/// Deliberately NOT `Serialize` (mirrors `db::models` / `WebhookRow` discipline):
/// because the hash column lives here, the type cannot be rendered into a
/// response body. Handlers map it to [`ApiKeyView`] for any GET/list; the hash is
/// read only by a future bearer-auth verify path (constant-time `verify_token_ct`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub name: String,
    /// One-way SHA-256 hex of the raw key. SECRET — never serialized.
    pub key_hash: String,
    pub key_prefix: String,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// The secret-free DTO returned by every GET/list. `masked` is `key_prefix` + a
/// fixed dot run — the raw key and the hash are NEVER present here (T-11-11).
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyView {
    pub id: Uuid,
    pub name: String,
    /// Non-secret display fragment, e.g. `ory_ab12cd34••••••••`.
    pub masked: String,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    /// Lifecycle: `"Active"` while `revoked_at IS NULL`, else `"Revoked"`.
    pub state: &'static str,
}

/// The fixed mask suffix appended after the non-secret prefix.
const MASK_SUFFIX: &str = "••••••••";

impl From<ApiKeyRow> for ApiKeyView {
    fn from(row: ApiKeyRow) -> Self {
        let state = if row.revoked_at.is_some() {
            "Revoked"
        } else {
            "Active"
        };
        ApiKeyView {
            id: row.id,
            name: row.name,
            masked: format!("{}{}", row.key_prefix, MASK_SUFFIX),
            created_by: row.created_by,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
            state,
        }
    }
}
