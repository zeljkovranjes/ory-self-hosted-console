// Shared identity types + helpers for the IDENT-01/02 Users pages.
//
// The backend (Plan 01) returns identities with credential secrets ALREADY
// stripped (`shape_identity_value` removes credentials.*.config + identifiers),
// so the frontend only ever sees credential TYPE keys. We still defensively
// render ONLY the type keys (never the inner value) so a future backend
// regression cannot leak secret config to the operator (T-06-20).

/** A Kratos identity as returned by the backend (secrets pre-stripped). */
export type Identity = {
  id: string;
  schema_id: string;
  state: string;
  traits: Record<string, unknown>;
  metadata_public?: unknown;
  metadata_admin?: unknown;
  verifiable_addresses?: AddressRecord[];
  recovery_addresses?: AddressRecord[];
  /** Object keyed by credential TYPE (password/oidc/...); values are opaque. */
  credentials?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
};

export type AddressRecord = {
  value?: string;
  verified?: boolean;
  via?: string;
  status?: string;
};

/** The backend list-endpoint envelope: keyset cursor + forward-compat total. */
export type IdentityListResponse = {
  rows: Identity[];
  next_token: string | null;
  total: number;
};

/**
 * Best-effort human identifier for the list/detail header: prefer common login
 * traits (email/username), fall back to any string trait, then the id.
 */
export function identityIdentifier(identity: Pick<Identity, "traits" | "id">): string {
  const traits = identity.traits ?? {};
  const preferred = ["email", "username", "name", "phone_number", "phone"];
  for (const key of preferred) {
    const v = traits[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const v of Object.values(traits)) {
    if (typeof v === "string" && v.length > 0) return v;
  }
  return identity.id;
}

/** Credential TYPE names only (never the inner config) — for the detail chips. */
export function credentialTypeNames(identity: Pick<Identity, "credentials">): string[] {
  return Object.keys(identity.credentials ?? {});
}
