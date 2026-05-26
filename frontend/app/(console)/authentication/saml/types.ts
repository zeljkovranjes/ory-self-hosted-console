// SSO-02 — shared types for the SAML Sign-In connection surface.
//
// Mirrors the 14-01 backend DTOs (backend/src/sso/routes.rs):
//   - create response  → `CreateConnectionResponse` here.
//   - list item        → `SamlConnection` here (clientSecret STRIPPED on the
//     backend; the masked presence is `clientSecret_set`).
//
// The per-connection clientSecret is NEVER returned on list/detail (it lives,
// write-only, inside the Kratos provider entry). The frontend therefore renders
// ONLY the masked `clientSecret_set` badge echoed from the backend — it never
// hardcodes a sentinel literal of its own (T-14-11).

/** The IdP metadata facts Polis echoes back for a connection. */
export type IdpMetadata = {
  entityID?: string;
  thumbprint?: string;
  provider?: string;
  // Polis may include more fields (loginType, sso, etc.) — kept open.
  [key: string]: unknown;
};

/** A single SAML connection as returned by GET /api/sso/connections?tenant=.
 *  The clientSecret VALUE is never present — only the `clientSecret_set` badge. */
export type SamlConnection = {
  /** The Polis tenant — the stable connection id (operator-chosen on create). */
  tenant: string;
  /** The fixed Polis product ("ory-console"). */
  product?: string;
  /** Public OAuth2 client id minted by Polis (safe to display). */
  clientID?: string;
  /** Masked badge only — the raw clientSecret is never serialized to the UI. */
  clientSecret_set?: boolean;
  /** The IdP metadata facts (entityID / thumbprint / provider). */
  idpMetadata?: IdpMetadata;
  /** Optional human label (Polis `name`). */
  name?: string;
};

/** The create-connection response (14-01 `create_connection`). The clientSecret
 *  is NEVER returned — it is minted by Polis and stored write-only in Kratos; the
 *  response carries only the masked `clientSecret_set` badge. */
export type CreateConnectionResponse = {
  tenant: string;
  product?: string;
  provider_id?: string;
  clientID?: string;
  idpMetadata?: IdpMetadata;
  clientSecret_set?: boolean;
};

/** The list response wrapper (14-01 `list_connections`). */
export type ConnectionListResponse = {
  connections: SamlConnection[];
};

/** Browser-local registry of the connection tenants this console has created.
 *  The backend's list endpoint is per-tenant (GET ?tenant=<t>) — there is no
 *  "list all" route — so the page remembers which tenants to query. This is a
 *  pure UX convenience: it holds NO secret and never becomes an egress host. */
export const TENANT_REGISTRY_KEY = "ory-console:saml-tenants";

/** Read the locally-remembered set of connection tenants (best-effort). */
export function readTenantRegistry(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(TENANT_REGISTRY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((t): t is string => typeof t === "string")
      : [];
  } catch {
    return [];
  }
}

/** Add a tenant to the local registry (idempotent, best-effort). */
export function rememberTenant(tenant: string): void {
  if (typeof window === "undefined") return;
  const next = Array.from(new Set([...readTenantRegistry(), tenant]));
  try {
    window.localStorage.setItem(TENANT_REGISTRY_KEY, JSON.stringify(next));
  } catch {
    // localStorage may be unavailable (private mode); the list simply won't
    // remember across reloads — never fatal.
  }
}

/** Remove a tenant from the local registry (best-effort). */
export function forgetTenant(tenant: string): void {
  if (typeof window === "undefined") return;
  const next = readTenantRegistry().filter((t) => t !== tenant);
  try {
    window.localStorage.setItem(TENANT_REGISTRY_KEY, JSON.stringify(next));
  } catch {
    // ignore
  }
}

/** The shared TanStack Query key for the SAML connection list. */
export const SAML_CONNECTIONS_QUERY_KEY = "saml-connections";
