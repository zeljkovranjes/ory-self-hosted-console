//! Parameterized console-DB queries for `console_api_keys` (PROJ-02).
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation. The key
//! is ONE-WAY SHA-256 hashed at rest via [`crate::auth::password::sha256_hex`]
//! (T-11-11) — the INVERSE of the recoverable webhook secret. The raw key is
//! returned to the caller ONCE at issue and never stored.

use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::password::{sha256_hex, verify_token_ct};
use crate::auth::session::generate_token;
use crate::error::AppError;

use super::{ApiKeyRow, ApiKeyView};

/// Number of leading raw-key chars kept as the non-secret display prefix.
const PREFIX_LEN: usize = 8;

/// A fixed dummy SHA-256 hex used to flatten the verify timing profile when no
/// candidate row matches the presented prefix (WR-04). It is `sha256_hex("")`
/// (the empty-string digest) — a public constant, never a real key hash, so it
/// can never match a presented key. Running one constant-time compare against it
/// on the no-candidate path keeps the request-time cost of "unknown prefix"
/// indistinguishable from "known prefix, wrong key" (both perform >= 1
/// sha256+ct_eq), removing the prefix-existence timing oracle.
const DUMMY_HASH_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The freshly issued key: the RAW value (returned to the operator exactly once)
/// plus the persisted secret-free [`ApiKeyView`]. The raw is NOT stored anywhere.
pub struct IssuedKey {
    /// The raw API key — shown ONCE, never recoverable afterwards.
    pub raw: String,
    pub view: ApiKeyView,
}

/// Issue a new API key: mint a raw CSPRNG token, store ONLY `sha256_hex(raw)` as
/// `key_hash` plus a short non-secret `key_prefix`, and return the raw ONCE
/// alongside the masked view (T-11-11). The hash is one-way — the raw can never
/// be re-derived from the stored row.
pub async fn issue_api_key(
    pool: &PgPool,
    name: &str,
    created_by: Option<Uuid>,
) -> Result<IssuedKey, AppError> {
    let raw = generate_token();
    let key_hash = sha256_hex(&raw);
    // Non-secret display fragment: the first PREFIX_LEN chars of the raw. A
    // base64url token is ASCII, so char/byte boundaries coincide; clamp defensively.
    let key_prefix: String = raw.chars().take(PREFIX_LEN).collect();

    let row = sqlx::query_as!(
        ApiKeyRow,
        r#"
        INSERT INTO console_api_keys (name, key_hash, key_prefix, created_by)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, key_hash, key_prefix, created_by,
                  created_at, last_used_at, revoked_at
        "#,
        name,
        key_hash,
        key_prefix,
        created_by
    )
    .fetch_one(pool)
    .await?;

    Ok(IssuedKey {
        raw,
        view: row.into(),
    })
}

/// List all API keys as masked, secret-free views (newest first). Never returns
/// the raw key or the hash.
pub async fn list_api_keys(pool: &PgPool) -> Result<Vec<ApiKeyView>, AppError> {
    let rows = sqlx::query_as!(
        ApiKeyRow,
        r#"
        SELECT id, name, key_hash, key_prefix, created_by,
               created_at, last_used_at, revoked_at
        FROM console_api_keys
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Revoke an API key (idempotent): set `revoked_at = now()` if not already
/// revoked. Returns the updated masked view, or `None` if no such key exists.
pub async fn revoke_api_key(pool: &PgPool, id: Uuid) -> Result<Option<ApiKeyView>, AppError> {
    let row = sqlx::query_as!(
        ApiKeyRow,
        r#"
        UPDATE console_api_keys
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE id = $1
        RETURNING id, name, key_hash, key_prefix, created_by,
                  created_at, last_used_at, revoked_at
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Verify a presented raw key against the stored one-way hash, constant-time
/// (`verify_token_ct`). Returns the key id ONLY when the key matches AND is not
/// revoked, and stamps `last_used_at = now()` on a match (WR-04). Provided for a
/// future bearer-auth path; v1 routes stop at issue/list/revoke. Never logs the
/// presented value (BACK-07).
pub async fn verify_api_key(pool: &PgPool, presented: &str) -> Result<Option<Uuid>, AppError> {
    // Match by the non-secret prefix first to bound the candidate set, then
    // constant-time compare the full hash. (Even a single-candidate lookup goes
    // through verify_token_ct so the compare itself is timing-safe.)
    let prefix: String = presented.chars().take(PREFIX_LEN).collect();
    let candidates = sqlx::query!(
        r#"
        SELECT id, key_hash
        FROM console_api_keys
        WHERE key_prefix = $1 AND revoked_at IS NULL
        "#,
        prefix
    )
    .fetch_all(pool)
    .await?;

    // WR-04: scan EVERY candidate (no early return) so the per-candidate compare
    // count does not depend on which row matched, then flatten the no-candidate
    // path with one dummy compare so "unknown prefix" costs the same >= 1
    // sha256+ct_eq as "known prefix, wrong key" — removing the prefix-existence
    // timing oracle.
    let mut matched: Option<Uuid> = None;
    for c in &candidates {
        if verify_token_ct(presented, &c.key_hash) {
            matched = Some(c.id);
        }
    }
    if matched.is_none() {
        // Constant work on the no-match path; the result is intentionally discarded.
        let _ = verify_token_ct(presented, DUMMY_HASH_HEX);
        return Ok(None);
    }

    // WR-04: stamp last_used_at on a successful verify so the surfaced column is
    // live rather than permanently NULL.
    //
    // WR-03: this MUST be truly best-effort. The key has already verified
    // (constant-time, non-revoked) above — authentication has SUCCEEDED. A
    // transient failure of this benign telemetry UPDATE (pool exhaustion, a row
    // lock, a brief connectivity blip) must NOT propagate via `?`, because the
    // combined auth hoop maps any `Err(_)` to 401 — turning a valid operator key
    // into an authentication failure (a correctness/availability defect, and
    // asymmetric with the session path which has no secondary write). Log + ignore
    // the stamp error; the verified key still authenticates.
    let id = matched.expect("matched is Some on this branch");
    if let Err(e) = sqlx::query!(
        "UPDATE console_api_keys SET last_used_at = now() WHERE id = $1",
        id
    )
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "api-key verify: last_used_at stamp failed (auth still succeeds)");
    }
    Ok(Some(id))
}
