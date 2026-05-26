//! Organizations query-layer integration tests (Phase 14 SSO-05/06).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (including `0008_organizations`), then exercises the real query functions
//! against Postgres. These prove the DB-boundary behaviors the pure-fn
//! `domain::normalize_domain` unit tests cannot: that the UNIQUE index on the
//! normalized domain rejects a spoofed/IDNA/case duplicate (SSO-05), that the
//! domain->SSO lookup normalizes IDENTICALLY to the write path and resolves to
//! the org's linked connection (SSO-06), and that an unknown domain yields `None`
//! (the route renders a value-free 404 — no org-existence leak).
//!
//! Requires a live `DATABASE_URL` (the project's standard integration-test
//! posture; `cargo build --locked` is the offline production deliverable).

use ory_console_backend::error::AppError;
use ory_console_backend::organizations::{domain::normalize_domain, queries};
use sqlx::PgPool;

/// SSO-05: a second domain that NORMALIZES to the same key as an existing one is
/// rejected by the unique index (surfaced as `AppError::Conflict`). Here a second
/// org tries to claim `CORP.com` after the first stored normalized `corp.com`.
#[sqlx::test(migrations = "./migrations")]
async fn duplicate_normalized_domain_is_rejected(pool: PgPool) {
    let d1 = normalize_domain("corp.com").unwrap();
    queries::create_org(&pool, "Acme", &[d1], None)
        .await
        .expect("first org with corp.com");

    // A case variant normalizes to the SAME key -> the unique index rejects it.
    let dup = normalize_domain("CORP.com").unwrap();
    let err = queries::create_org(&pool, "Evil", &[dup], None)
        .await
        .expect_err("a colliding domain must be rejected");
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected a Conflict for the duplicate normalized domain, got {err:?}"
    );

    // The failed create rolled back: only the first org exists.
    let orgs = queries::list_orgs(&pool).await.unwrap();
    assert_eq!(orgs.len(), 1, "the colliding org must not have been created");
}

/// SSO-06: the domain->SSO lookup resolves an org's domain to its linked SSO
/// connection tenant, AND a spoofed/case/IDNA lookup variant normalizes to the
/// same key as the stored one (so it matches identically to the write path).
#[sqlx::test(migrations = "./migrations")]
async fn lookup_normalizes_identically_to_write(pool: PgPool) {
    let stored = normalize_domain("corp.com").unwrap();
    queries::create_org(&pool, "Acme", std::slice::from_ref(&stored), Some("org-acme"))
        .await
        .expect("create org");

    // A lookup using a sub-domain + uppercase + trailing dot must reduce to the
    // SAME registered-domain key and match.
    let probe = normalize_domain("MAIL.Corp.com.").unwrap();
    assert_eq!(probe, stored, "lookup normalization must equal write normalization");
    let found = queries::lookup_by_domain(&pool, &probe)
        .await
        .unwrap()
        .expect("the org is found via the normalized sub-domain");
    assert_eq!(found.domain, "corp.com");
    assert_eq!(found.sso_connection_tenant.as_deref(), Some("org-acme"));
}

/// SSO-06: an unknown domain yields `None` (the route renders a value-free 404 —
/// never a populated body, no org-existence leak). The classic spoof
/// `corp.com.attacker.com` is a DIFFERENT registered domain and must NOT match.
#[sqlx::test(migrations = "./migrations")]
async fn unknown_domain_returns_none(pool: PgPool) {
    let stored = normalize_domain("corp.com").unwrap();
    queries::create_org(&pool, "Acme", &[stored], None)
        .await
        .expect("create org");

    // A genuinely unknown (but structurally valid, registrable) domain.
    let none = normalize_domain("notanorg.com").unwrap();
    assert!(queries::lookup_by_domain(&pool, &none).await.unwrap().is_none());

    // The spoof reduces to attacker.com, NOT corp.com -> no match (SSO-05 boundary
    // enforced end-to-end through the DB lookup).
    let spoof = normalize_domain("corp.com.attacker.com").unwrap();
    assert_eq!(spoof, "attacker.com");
    assert!(
        queries::lookup_by_domain(&pool, &spoof).await.unwrap().is_none(),
        "corp.com.attacker.com must not resolve to corp.com's org"
    );
}

/// Create/list/get/delete round-trip: an org with multiple domains lists with its
/// domains aggregated; delete cascades the domains (the lookup then misses).
#[sqlx::test(migrations = "./migrations")]
async fn crud_roundtrip_with_cascade(pool: PgPool) {
    let d1 = normalize_domain("acme.com").unwrap();
    let d2 = normalize_domain("acme.co.uk").unwrap();
    let org = queries::create_org(&pool, "Acme", &[d1.clone(), d2.clone()], Some("org-acme"))
        .await
        .expect("create");
    assert_eq!(org.domains.len(), 2);

    let fetched = queries::get_org(&pool, org.id).await.unwrap().expect("get");
    assert_eq!(fetched.label, "Acme");
    assert!(fetched.domains.contains(&d1) && fetched.domains.contains(&d2));

    // Delete cascades the domains -> the lookup misses afterward.
    assert!(queries::delete_org(&pool, org.id).await.unwrap());
    assert!(queries::get_org(&pool, org.id).await.unwrap().is_none());
    assert!(queries::lookup_by_domain(&pool, &d1).await.unwrap().is_none());
    // Deleting a missing org returns false (the route -> 404).
    assert!(!queries::delete_org(&pool, org.id).await.unwrap());
}
