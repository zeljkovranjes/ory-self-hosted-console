//! Organizations CRUD + the login-time domain->SSO lookup (SSO-05/06/07).
//!
//! All handlers sit on the PROTECTED subtree behind
//! `FeatureFlagHoop::new("organizations")` (SSO-07 — 404 when the flag is OFF,
//! even with a valid session + CSRF token). The blanket response-phase audit hoop
//! already on that subtree auto-audits the state-changing create/delete
//! (actor-from-session, T-14-09) — there is NO second audit path here.
//!
//! Secret discipline: org/domain rows carry no secret, so the view types are
//! serialized directly. The ONLY spoofing-relevant invariant is that EVERY domain
//! is normalized through [`super::domain::normalize_domain`] on write AND in the
//! lookup — if those two ever diverged, a spoofed/IDNA-confusable domain could
//! match at lookup that could not have been stored. Both go through the one
//! function (SSO-05/06).

use salvo::prelude::*;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;

use super::{domain, queries};

/// Authoritative input bounds (the backend is the validation boundary; the
/// frontend Zod schema is advisory). A label longer than this, or more domains
/// than this, is rejected 422 before any DB write.
const MAX_LABEL_LEN: usize = 200;
const MAX_DOMAINS: usize = 100;

/// Obtain the console pool from the Depot, cloning BEFORE any await (the Depot
/// pattern — never hold a borrow across `.await`).
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// Parse the `{id}` path segment as a UUID (a malformed id -> 404, never a 500).
fn path_id(req: &mut Request) -> Result<Uuid, AppError> {
    req.param::<String>("id")
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or(AppError::NotFound)
}

#[derive(Debug, Deserialize)]
struct CreateOrgBody {
    label: String,
    /// Raw operator-entered domains — normalized server-side before storage.
    #[serde(default)]
    domains: Vec<String>,
    /// Optional linked SSO connection tenant (the Plan-01 (tenant, product)
    /// convention). May be set later via update; non-secret.
    #[serde(default)]
    sso_connection_tenant: Option<String>,
}

/// Normalize + de-duplicate a batch of operator-entered domains. Each goes through
/// the SSO-05 pipeline; a normalize failure is a value-free 422. Duplicates WITHIN
/// the request collapse (the unique index would reject them anyway, but we collapse
/// early for a clean create).
fn normalize_domains(raw: &[String]) -> Result<Vec<String>, AppError> {
    if raw.len() > MAX_DOMAINS {
        return Err(AppError::BadRequest(format!(
            "an organization may have at most {MAX_DOMAINS} domains"
        )));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for d in raw {
        let n = domain::normalize_domain(d)?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

/// `POST api/organizations` — create an org with a label, normalized verified
/// domains, and an optional linked SSO connection tenant. Audited (auto via the
/// subtree hoop). A duplicate normalized domain -> 409 (unique index).
#[handler]
pub async fn create_org(req: &mut Request, depot: &mut Depot) -> Result<Json<super::OrgView>, AppError> {
    let pool = pool(depot)?;
    let body: CreateOrgBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid organization body: {e}")))?;

    let label = body.label.trim();
    if label.is_empty() {
        return Err(AppError::BadRequest("Organization label is required.".into()));
    }
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(AppError::BadRequest(format!(
            "Organization label must be at most {MAX_LABEL_LEN} characters."
        )));
    }
    // SSO-05: normalize EVERY domain on write (identical to the lookup path).
    let domains = normalize_domains(&body.domains)?;

    let tenant = body
        .sso_connection_tenant
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());

    let org = queries::create_org(&pool, label, &domains, tenant).await?;
    Ok(Json(org))
}

/// `GET api/organizations` — list all orgs with their domains + linked connection
/// (csrf-exempt).
#[handler]
pub async fn list_orgs(depot: &mut Depot) -> Result<Json<Vec<super::OrgView>>, AppError> {
    let pool = pool(depot)?;
    let orgs = queries::list_orgs(&pool).await?;
    Ok(Json(orgs))
}

/// `GET api/organizations/{id}` — single org detail (csrf-exempt).
#[handler]
pub async fn get_org(req: &mut Request, depot: &mut Depot) -> Result<Json<super::OrgView>, AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    let org = queries::get_org(&pool, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(org))
}

/// `DELETE api/organizations/{id}` — delete an org (domains cascade). Audited.
#[handler]
pub async fn delete_org(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = pool(depot)?;
    let id = path_id(req)?;
    if queries::delete_org(&pool, id).await? {
        res.status_code(StatusCode::NO_CONTENT);
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// `GET api/sso/lookup?email=a@corp.com` (or `?domain=corp.com`) — resolve a
/// domain to its org's linked SSO connection (SSO-06). The domain is normalized
/// IDENTICALLY to the write path (SSO-05) before matching, so a spoofed/IDNA/case
/// variant cannot bypass the match. An unknown domain -> 404 (value-free, no
/// org-existence leak). Consumed by the Account Experience UI in Phase 15.
///
/// csrf-exempt (GET, read-only); inherits `auth_guard` (401) +
/// `FeatureFlagHoop::new("organizations")` (404 when OFF).
#[handler]
pub async fn sso_lookup(req: &mut Request, depot: &mut Depot) -> Result<Json<super::SsoLookupView>, AppError> {
    let pool = pool(depot)?;

    // Accept either ?email= (extract the host part) or ?domain= directly.
    let raw = if let Some(email) = req.query::<String>("email").filter(|s| !s.trim().is_empty()) {
        email
            .rsplit_once('@')
            .map(|(_, host)| host.to_string())
            .ok_or_else(|| AppError::BadRequest("email must contain a domain".into()))?
    } else if let Some(d) = req.query::<String>("domain").filter(|s| !s.trim().is_empty()) {
        d
    } else {
        return Err(AppError::BadRequest("email or domain query parameter is required".into()));
    };

    // SSO-05/06: normalize through the SAME function used on write.
    let normalized = domain::normalize_domain(&raw)?;
    let found = queries::lookup_by_domain(&pool, &normalized)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(found))
}

/// `GET api/sso/hint?email=a@corp.com` (or `?domain=corp.com`) — the NARROW,
/// UNAUTHENTICATED login-time domain->SSO HINT consumed by the Account Experience
/// login screen (AX-01 / SSO-06 surfacing, Phase 15).
///
/// WHY a SECOND endpoint instead of reusing [`sso_lookup`]: that handler sits on
/// the PROTECTED subtree (it requires a CONSOLE session via `auth_guard`). The AX
/// is an UNAUTHENTICATED end-user surface, so it CANNOT call the protected lookup
/// — and we must NOT loosen that lookup's auth (T-15-17 / EoP). This hint is the
/// minimal, end-user-safe alternative: it is mounted on the PUBLIC subtree but is
/// STILL gated by `FeatureFlagHoop::new("organizations")` (404 when the feature is
/// OFF), and it returns ONLY the linked SSO provider tenant ([`SsoHintView`]).
///
/// Information-disclosure discipline (T-15-16): the domain is normalized through
/// the SAME `domain::normalize_domain` used on write (SSO-05) so a spoofed/IDNA/
/// case variant cannot bypass the match. A domain that does NOT match an org, OR
/// matches an org with NO linked SSO connection, BOTH yield a value-free 404 — so
/// the response can never be used to enumerate which orgs/domains merely exist
/// (an unknown domain and a known-but-not-SSO domain are indistinguishable). The
/// caller (the AX) treats 404 as "no SSO route — proceed with normal password
/// login". csrf-exempt (GET, read-only); takes no console session.
#[handler]
pub async fn sso_hint(req: &mut Request, depot: &mut Depot) -> Result<Json<super::SsoHintView>, AppError> {
    let pool = pool(depot)?;

    // Accept either ?email= (extract the host part) or ?domain= directly.
    let raw = if let Some(email) = req.query::<String>("email").filter(|s| !s.trim().is_empty()) {
        email
            .rsplit_once('@')
            .map(|(_, host)| host.to_string())
            .ok_or_else(|| AppError::BadRequest("email must contain a domain".into()))?
    } else if let Some(d) = req.query::<String>("domain").filter(|s| !s.trim().is_empty()) {
        d
    } else {
        return Err(AppError::BadRequest("email or domain query parameter is required".into()));
    };

    // SSO-05/06: normalize through the SAME function used on write.
    let normalized = domain::normalize_domain(&raw)?;
    let found = queries::lookup_by_domain(&pool, &normalized)
        .await?
        .ok_or(AppError::NotFound)?;

    // A known domain with NO linked SSO connection is indistinguishable from an
    // unknown domain (both 404) — no "this org exists but is not SSO-enabled"
    // signal leaks (T-15-16). Only a real provider tenant produces a 200 hint.
    let provider = found.sso_connection_tenant.ok_or(AppError::NotFound)?;
    Ok(Json(super::SsoHintView { provider }))
}
