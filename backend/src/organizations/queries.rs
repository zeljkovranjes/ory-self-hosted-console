//! Parameterized console-DB queries for `organizations` / `organization_domains`.
//!
//! All SQL goes through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation (threat
//! T-14-08 / SQL injection). Org/domain rows carry NO secret, so the row types
//! map straight to [`OrgView`] / [`SsoLookupView`].
//!
//! The stored `organization_domains.domain` is ALWAYS the normalized key produced
//! by [`super::domain::normalize_domain`] — these query functions take the
//! already-normalized value (the route layer normalizes; the unique index is the
//! last-line collision defense).

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

use super::{OrgView, SsoLookupView};

/// A duplicate-domain collision (the unique index on the normalized domain
/// rejected the insert). The route maps this to a 409 Conflict.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.is_unique_violation())
}

/// Create an organization with its label, normalized domains, and an optional
/// linked SSO connection tenant, in a single transaction. `domains` MUST already
/// be normalized (the route normalizes each on write). A duplicate normalized
/// domain (against an existing org OR within this same request) trips the unique
/// index and surfaces as [`AppError::Conflict`] — the whole transaction rolls
/// back (no partial org).
pub async fn create_org(
    pool: &PgPool,
    label: &str,
    domains: &[String],
    sso_connection_tenant: Option<&str>,
) -> Result<OrgView, AppError> {
    let mut tx = pool.begin().await?;

    let org = sqlx::query!(
        r#"
        INSERT INTO organizations (label, sso_connection_tenant)
        VALUES ($1, $2)
        RETURNING id, label, sso_connection_tenant, created_at, updated_at
        "#,
        label,
        sso_connection_tenant,
    )
    .fetch_one(&mut *tx)
    .await?;

    for domain in domains {
        sqlx::query!(
            r#"INSERT INTO organization_domains (org_id, domain) VALUES ($1, $2)"#,
            org.id,
            domain,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("domain_taken".into())
            } else {
                AppError::from(e)
            }
        })?;
    }

    tx.commit().await?;

    Ok(OrgView {
        id: org.id,
        label: org.label,
        domains: domains.to_vec(),
        sso_connection_tenant: org.sso_connection_tenant,
        created_at: org.created_at,
        updated_at: org.updated_at,
    })
}

/// List all organizations (newest first), each with its domains aggregated. A
/// single query joins the domains and aggregates them into an array so there is
/// no N+1 fan-out.
pub async fn list_orgs(pool: &PgPool) -> Result<Vec<OrgView>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT o.id, o.label, o.sso_connection_tenant, o.created_at, o.updated_at,
               COALESCE(
                   ARRAY_AGG(d.domain ORDER BY d.domain) FILTER (WHERE d.domain IS NOT NULL),
                   '{}'
               ) AS "domains!: Vec<String>"
        FROM organizations o
        LEFT JOIN organization_domains d ON d.org_id = o.id
        GROUP BY o.id
        ORDER BY o.created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| OrgView {
            id: r.id,
            label: r.label,
            domains: r.domains,
            sso_connection_tenant: r.sso_connection_tenant,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

/// Fetch a single organization (with its domains) by id, if present.
pub async fn get_org(pool: &PgPool, id: Uuid) -> Result<Option<OrgView>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT o.id, o.label, o.sso_connection_tenant, o.created_at, o.updated_at,
               COALESCE(
                   ARRAY_AGG(d.domain ORDER BY d.domain) FILTER (WHERE d.domain IS NOT NULL),
                   '{}'
               ) AS "domains!: Vec<String>"
        FROM organizations o
        LEFT JOIN organization_domains d ON d.org_id = o.id
        WHERE o.id = $1
        GROUP BY o.id
        "#,
        id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| OrgView {
        id: r.id,
        label: r.label,
        domains: r.domains,
        sso_connection_tenant: r.sso_connection_tenant,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

/// Delete an organization (its domains cascade via the FK). Returns whether a row
/// was removed (false -> 404).
pub async fn delete_org(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
    let res = sqlx::query!(r#"DELETE FROM organizations WHERE id = $1"#, id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Resolve a NORMALIZED domain to its organization's linked SSO connection
/// (SSO-06). The caller MUST pass the value through
/// [`super::domain::normalize_domain`] first — the same normalization used on
/// write — so a spoofed/case/IDNA-variant lookup cannot bypass the match. Returns
/// `None` for an unknown domain (the route renders a value-free 404, no
/// org-existence leak).
pub async fn lookup_by_domain(
    pool: &PgPool,
    normalized_domain: &str,
) -> Result<Option<SsoLookupView>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT o.id AS org_id, d.domain, o.sso_connection_tenant
        FROM organization_domains d
        JOIN organizations o ON o.id = d.org_id
        WHERE d.domain = $1
        "#,
        normalized_domain,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| SsoLookupView {
        org_id: r.org_id,
        domain: r.domain,
        sso_connection_tenant: r.sso_connection_tenant,
    }))
}
