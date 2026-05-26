//! SAML Sign-In via Ory Polis (Phase 14 — the security crux of the milestone).
//!
//! The `sso` module wires two verified surfaces together with three load-bearing
//! security controls, each proven by a NEGATIVE test:
//!
//!   - [`polis_admin`] — a thin reqwest client over the verified Ory Polis
//!     connection admin API (`POST/GET/DELETE /api/v1/sso`, `Authorization:
//!     Api-Key`). The backend is the SOLE client of the Polis admin API (INFRA-05);
//!     the `POLIS_API_KEY` is a write-only secret, never logged/serialized.
//!   - [`metadata`] — the console-side MANDATORY IdP signing-certificate pre-flight
//!     (SSO-02): IdP metadata XML lacking a SIGNING `<X509Certificate>` is rejected
//!     (422) BEFORE any Polis call. An encryption-only cert must NOT pass. No
//!     skip-signature toggle is ever exposed.
//!   - [`mapper`] — the `email_verified`-default-false Kratos Jsonnet mapper
//!     generator (SSO-03, the account-takeover defense): the generated source drops
//!     the `email` trait whenever `email_verified` is absent/false — which for a
//!     Polis SAML bridge is ALWAYS (Polis emits no `email_verified`, verified). No
//!     operator toggle disables the guard.
//!   - [`routes`] — connection create/list/delete handlers (Task 2): SSRF-guarded
//!     `metadataUrl` (SSO-04), the CA pre-flight, the Polis POST, the Kratos
//!     `provider: generic` write via the AUTH-04 `providers[]` path, and the
//!     two-sided delete (Polis connection + Kratos provider entry — no dangling
//!     provider). All gated by `FeatureFlagHoop::new("saml")` (SSO-07).
//!
//! ## Tenant/product convention (single-tenant — RESEARCH Pattern 2 / A1)
//!
//! Polis multiplexes connections by `(tenant, product)`. This console fixes
//! `product = "ory-console"` and keys `tenant` to the connection's stable id (the
//! Organization id in Phase 15). The Kratos provider entry's stable id is
//! `saml-<tenant>` so a two-sided delete can find and remove exactly its entry.

pub mod mapper;
pub mod metadata;
pub mod polis_admin;
pub mod routes; // connection CRUD handlers (Task 2)

/// The fixed Polis `product` namespace for every console-managed SAML connection
/// (RESEARCH Pattern 2 / A1). Single-tenant: all connections share this product;
/// `tenant` is the per-connection discriminator.
pub const POLIS_PRODUCT: &str = "ory-console";

/// Build the stable Kratos `providers[]` entry id for a connection `tenant`.
/// Used at create (write the entry) and delete (find + remove the entry), so the
/// two sides can never drift (Pitfall 5). The id is `saml-<tenant>`.
pub fn provider_id(tenant: &str) -> String {
    format!("saml-{tenant}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_id_is_stable_and_tenant_scoped() {
        assert_eq!(provider_id("org-123"), "saml-org-123");
        // The same tenant always yields the same id (so delete finds create's entry).
        assert_eq!(provider_id("acme"), provider_id("acme"));
        // Different tenants never collide.
        assert_ne!(provider_id("a"), provider_id("b"));
    }
}
