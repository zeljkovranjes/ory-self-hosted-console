// Shared OAuth2 client types + helpers for the OAUTH2-01 Clients pages.
//
// The backend (08-01) returns clients with the secret ALREADY stripped
// (`shape_client_value` removes `client_secret` + `registration_access_token`),
// so the frontend only ever sees a presence signal — never the value. The ONLY
// place a real secret is returned is the create/rotate response (the one-time
// reveal), surfaced via `client-secret-reveal.tsx` and never persisted.
//
// Field names mirror the crate `OAuth2Client` model (ory-hydra-client v26.2.0),
// which is generated from the same Hydra OpenAPI spec the `ory` CLI consumes —
// so this shape is CLI-interchangeable.

/** A Hydra OAuth2 client as returned by the backend (secret pre-stripped). */
export type OAuth2Client = {
  /** Immutable. Absent only in a create body where Hydra generates a UUID4. */
  client_id?: string;
  client_name?: string;
  /** Only present in a create/rotate RESPONSE (one-time). Never on GET/list. */
  client_secret?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  /** Space-separated scope string (RFC 6749 §3.3). */
  scope?: string;
  audience?: string[];
  token_endpoint_auth_method?: string;
  client_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  contacts?: string[];
  owner?: string;
  metadata?: unknown;
  created_at?: string;
  updated_at?: string;
};

/** The backend list-endpoint envelope: rows + the opaque Hydra offset cursor. */
export type ClientListResponse = {
  rows: OAuth2Client[];
  /** Opaque next-page cursor (Hydra offset page_token), or null on the last page. */
  next_token: string | null;
};

/** The token-endpoint auth methods Hydra supports (08-UI-SPEC §B select). */
export const TOKEN_ENDPOINT_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "none",
] as const;

/** Common OAuth2 grant types operators pick from (free-add still allowed). */
export const GRANT_TYPES = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
  "implicit",
] as const;

/** Whether this client has a secret set (write-only — backend strips the value,
 *  so we infer presence from the auth method: public `none` clients have none). */
export function clientHasSecret(c: Pick<OAuth2Client, "token_endpoint_auth_method">): boolean {
  return (c.token_endpoint_auth_method ?? "client_secret_basic") !== "none";
}

/** Best-effort display label for the list/detail header. */
export function clientLabel(c: Pick<OAuth2Client, "client_name" | "client_id">): string {
  if (c.client_name && c.client_name.length > 0) return c.client_name;
  return c.client_id ?? "(unnamed client)";
}
