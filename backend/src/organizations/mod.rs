//! Organizations (domain -> SSO) — the console-owned data model for SAML
//! sign-in routing (Phase 14, SSO-05/06/07).
//!
//! Entirely in the backend's OWN `console` Postgres schema (migration `0008`),
//! like webhooks/api-keys — there is NO Ory primitive for organizations. An
//! Organization is an operator-managed `{ label, verified domains[], linked SSO
//! connection }`; its domains are the trust anchor that makes a SAML-asserted
//! email at that domain authoritative (the account-takeover defense from Plan 01
//! relies on this binding).
//!
//! Composed of:
//! - [`domain`] — spoofing-resistant domain normalization (SSO-05), applied
//!   IDENTICALLY on write and on the login-time lookup.
//! - [`queries`] — sqlx `query!`/`query_as!` CRUD + the domain->SSO lookup
//!   (compile-checked against the committed `.sqlx`).
//! - [`routes`] — audited CRUD handlers + the lookup handler, all gated by
//!   `FeatureFlagHoop::new("organizations")` (SSO-07).

pub mod domain;
pub mod queries;
pub mod routes;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// An organization with its verified domains and linked SSO connection tenant.
/// Carries no secret -> safe to `Serialize` directly to the operator UI.
#[derive(Debug, Clone, Serialize)]
pub struct OrgView {
    pub id: Uuid,
    pub label: String,
    /// The normalized registered-domain keys verified for this org (SSO-05).
    pub domains: Vec<String>,
    /// The linked Polis SSO connection `tenant` (the SSO-06 lookup result), or
    /// `None` until a connection is linked. `product` is the fixed
    /// `sso::POLIS_PRODUCT` ("ory-console") — not stored per-org.
    pub sso_connection_tenant: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The login-time domain->SSO lookup result (SSO-06). Returned by the
/// `GET api/sso/lookup` endpoint consumed by the Account Experience UI in Phase
/// 15. Carries only the org id + the linked SSO connection tenant (the
/// identifier AX needs to start the SSO flow). An unknown domain yields a 404 (no
/// org-existence leak), never a populated body with `null`.
#[derive(Debug, Clone, Serialize)]
pub struct SsoLookupView {
    /// The matched organization id.
    pub org_id: Uuid,
    /// The normalized domain that matched (the canonical key, echoed back).
    pub domain: String,
    /// The linked SSO connection tenant, or `None` if the org has no connection
    /// linked yet (the domain is known but not SSO-enabled).
    pub sso_connection_tenant: Option<String>,
}

/// The NARROW, UNAUTHENTICATED login-time domain->SSO HINT (SSO-06 surfacing,
/// Phase 15 / AX-01). Returned by the PUBLIC `GET /api/sso/hint` endpoint the
/// Account Experience login screen calls (browser -> AX server route -> backend).
///
/// Information-disclosure discipline (T-15-16): this carries ONLY the linked SSO
/// connection tenant (the `provider` the AX needs to route to). It deliberately
/// does NOT echo the org id or the matched domain — and the route 404s for a
/// domain that has NO linked connection — so the response can never be used to
/// enumerate which orgs/domains merely EXIST. The protected `SsoLookupView`
/// (console-authenticated) is the richer view; this hint is the unauthenticated
/// minimum.
#[derive(Debug, Clone, Serialize)]
pub struct SsoHintView {
    /// The KRATOS OIDC provider id to route the end-user to (the only field):
    /// `saml-<tenant>` (the stable `crate::sso::provider_id`), NOT the bare
    /// connection tenant. The AX `SsoRouting` affordance keys its
    /// `providerInitiateUrls` map on the login flow's `oidc` node value, which
    /// Kratos stamps as `saml-<tenant>` — so the hint must speak the same id for
    /// the "Continue with <provider> SSO" link to resolve end-to-end.
    pub provider: String,
}
