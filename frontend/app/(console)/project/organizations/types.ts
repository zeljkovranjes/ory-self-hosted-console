// SSO-05/06 — shared types for the Organizations surface.
//
// Mirrors the 14-02 backend DTO (backend/src/organizations/mod.rs `OrgView`).
// Organizations carry NO secret, so the view is rendered directly. The linked
// SSO connection is the Plan-01 `tenant` (product is the fixed "ory-console",
// not stored per-org). Domains are the NORMALIZED registered-domain keys the
// backend stored (SSO-05) — the page echoes them back verbatim.

/** An organization with its verified domains + linked SSO connection tenant. */
export type Organization = {
  id: string;
  label: string;
  /** The normalized registered-domain keys verified for this org (SSO-05). */
  domains: string[];
  /** The linked Polis SSO connection tenant, or null if none is linked yet. */
  sso_connection_tenant: string | null;
  created_at: string;
  updated_at: string;
};

/** The shared TanStack Query key for the organizations list. */
export const ORGANIZATIONS_QUERY_KEY = "organizations";
