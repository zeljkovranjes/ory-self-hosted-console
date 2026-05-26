//! Integration tests for the PROJ-02 console API keys (one-way SHA-256
//! hash-at-rest, one-time reveal, masked list, revoke).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (incl. 0004 console_api_keys), then exercises the query layer directly. We
//! assert the security invariants WITHOUT the live stack:
//!   - issue returns the raw key once AND stores sha256_hex(raw) as key_hash AND
//!     the raw is NOT recoverable from the masked view;
//!   - list returns masked keys (prefix + dots), never the raw or the hash;
//!   - revoke sets revoked_at and flips state to "Revoked";
//!   - verify_api_key matches the raw constant-time and rejects after revoke.

mod common;

use ory_console_backend::apikeys::queries;
use ory_console_backend::auth::password::sha256_hex;
use sqlx::PgPool;

/// Read the stored key_hash for an issued key id (test-only introspection — the
/// production view never exposes it).
async fn stored_key_hash(pool: &PgPool, id: uuid::Uuid) -> String {
    let row = sqlx::query!("SELECT key_hash FROM console_api_keys WHERE id = $1", id)
        .fetch_one(pool)
        .await
        .expect("key row");
    row.key_hash
}

#[sqlx::test(migrations = "./migrations")]
async fn issue_stores_one_way_hash_and_reveals_raw_once(pool: PgPool) {
    let issued = queries::issue_api_key(&pool, "ci-key", None)
        .await
        .expect("issue key");

    // The raw is returned exactly once and is a non-empty CSPRNG token.
    assert!(!issued.raw.is_empty(), "raw key returned once");

    // The DB stores sha256_hex(raw) — one-way hash-at-rest (T-11-11), NOT the raw.
    let key_hash = stored_key_hash(&pool, issued.view.id).await;
    assert_eq!(key_hash, sha256_hex(&issued.raw), "key_hash == sha256_hex(raw)");
    assert_ne!(key_hash, issued.raw, "the raw key is never stored verbatim");

    // The masked view never contains the raw key or the hash.
    let view_json = serde_json::to_string(&issued.view).expect("serialize view");
    assert!(
        !view_json.contains(&issued.raw),
        "masked view must not contain the raw key: {view_json}"
    );
    assert!(
        !view_json.contains(&key_hash),
        "masked view must not contain the hash: {view_json}"
    );
    assert!(view_json.contains("masked"), "view exposes a masked fragment");
    assert_eq!(issued.view.state, "Active", "a fresh key is Active");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_masked_keys_without_raw_or_hash(pool: PgPool) {
    let issued = queries::issue_api_key(&pool, "list-key", None)
        .await
        .expect("issue key");
    let key_hash = stored_key_hash(&pool, issued.view.id).await;

    let list = queries::list_api_keys(&pool).await.expect("list keys");
    assert_eq!(list.len(), 1, "one key listed");
    let v = &list[0];
    // Masked = prefix + a dot run; the prefix is the first chars of the raw, but
    // the full raw is not recoverable from it.
    assert!(v.masked.contains('•'), "masked carries the dot fragment: {}", v.masked);
    assert_ne!(v.masked, issued.raw, "masked is not the raw key");

    let list_json = serde_json::to_string(&list).expect("serialize list");
    assert!(
        !list_json.contains(&issued.raw),
        "list must not leak the raw key: {list_json}"
    );
    assert!(
        !list_json.contains(&key_hash),
        "list must not leak the hash: {list_json}"
    );
    assert!(
        !list_json.contains("key_hash"),
        "list must not carry a key_hash field: {list_json}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_flips_state_and_blocks_verify(pool: PgPool) {
    let issued = queries::issue_api_key(&pool, "revoke-key", None)
        .await
        .expect("issue key");

    // Before revoke: the raw verifies (constant-time) to the key id.
    let matched = queries::verify_api_key(&pool, &issued.raw)
        .await
        .expect("verify");
    assert_eq!(matched, Some(issued.view.id), "raw verifies before revoke");

    // Revoke flips state.
    let revoked = queries::revoke_api_key(&pool, issued.view.id)
        .await
        .expect("revoke")
        .expect("key exists");
    assert_eq!(revoked.state, "Revoked", "state becomes Revoked");
    assert!(revoked.revoked_at.is_some(), "revoked_at is set");

    // After revoke: the same raw no longer verifies (revoked rows are excluded).
    let after = queries::verify_api_key(&pool, &issued.raw)
        .await
        .expect("verify after revoke");
    assert_eq!(after, None, "a revoked key must not verify");

    // A wrong key never matches.
    let wrong = queries::verify_api_key(&pool, "definitely-not-a-real-key")
        .await
        .expect("verify wrong");
    assert_eq!(wrong, None, "an unknown key does not match");

    // Revoking a non-existent key is a clean None (404 at the route).
    let missing = queries::revoke_api_key(&pool, uuid::Uuid::nil())
        .await
        .expect("revoke missing");
    assert!(missing.is_none(), "revoking an unknown id returns None");
}
