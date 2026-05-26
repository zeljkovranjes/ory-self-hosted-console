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
//! - `queries` — sqlx `query!`/`query_as!` CRUD + the domain->SSO lookup (added
//!   in Task 2; compile-checked against the committed `.sqlx`).
//! - `routes` — audited CRUD handlers + the lookup handler (Task 2), all gated
//!   by `FeatureFlagHoop::new("organizations")` (SSO-07).

pub mod domain;
