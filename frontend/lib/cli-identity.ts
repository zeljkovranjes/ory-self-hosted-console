// IDENT-04 — CLI bare-array interchange helpers (client-side UX layer).
//
// The bulk-import body the frontend POSTs is the SAME bare array that
// `ory import identities file.json` consumes (06-RESEARCH Pattern 4 / Pitfall 1).
// This module provides:
//   - parseImportArray: parse + shape-validate a pasted/uploaded bare array
//   - checkLimits:      mirror the backend's authoritative 1000/200 limits for
//                       fast UX feedback BEFORE the network call
//   - toExportArray:    map backend Identity objects -> the bare CLI shape, with
//                       all credential secrets stripped (T-06-32)
//   - SCHEMA_PRESETS:   starter draft-07 identity schemas for the editor dropdown
//
// SECURITY: these limits are UX only. The backend (Plan 01 `enforce_import_limits`)
// is the authoritative source of truth and re-rejects with 422 regardless of what
// the client allowed (T-06-30). All error messages here are value-free — the
// untrusted pasted payload is NEVER echoed back into a message (defense in depth).
//
// This file imports no network client and contains no Ory host/port/SDK literal
// (bundle-egress gate, T-06-33).

/** Backend authoritative limits, mirrored client-side for UX (Plan 01). */
export const HASHED_LIMIT = 1000;
export const CLEARTEXT_LIMIT = 200;

/**
 * One record in the bare CLI import array. Matches what `ory import identities`
 * consumes: a `schema_id`, a `traits` object, and optional `credentials`
 * (the only place a cleartext `password.config.password` may appear).
 */
export type CliIdentity = {
  schema_id: string;
  traits: Record<string, unknown>;
  credentials?: Record<string, unknown>;
  // Forward-compat: the CLI shape may carry additional optional fields
  // (metadata_public/admin, state, verifiable/recovery addresses). They pass
  // through untouched for import; they are not required by the shape check.
  [key: string]: unknown;
};

/** A backend Identity (secrets pre-stripped by the list/detail shaper). */
type BackendIdentity = {
  schema_id: string;
  traits?: Record<string, unknown>;
  [key: string]: unknown;
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Parse a pasted/uploaded bare-array JSON and assert the canonical CLI shape:
 * the top level MUST be an array, and every element MUST be an object carrying a
 * string `schema_id` and an object `traits`. Returns `{ records }` on success or
 * `{ error }` (value-free) on any malformed input.
 */
export function parseImportArray(
  text: string,
): { records: CliIdentity[] } | { error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: "Could not parse JSON. Paste a valid JSON array." };
  }

  if (!Array.isArray(parsed)) {
    return {
      error:
        "Expected a top-level JSON array of identity records (the `ory` CLI bare-array shape).",
    };
  }

  for (let i = 0; i < parsed.length; i++) {
    const rec = parsed[i];
    if (!isObject(rec)) {
      return { error: `Record at index ${i} is not an object.` };
    }
    if (typeof rec.schema_id !== "string" || rec.schema_id.length === 0) {
      return {
        error: `Record at index ${i} is missing a string "schema_id".`,
      };
    }
    if (!isObject(rec.traits)) {
      return { error: `Record at index ${i} is missing an object "traits".` };
    }
  }

  return { records: parsed as CliIdentity[] };
}

/** True when a record carries a non-empty cleartext `credentials.password.config.password`. */
function hasCleartextPassword(rec: CliIdentity): boolean {
  const creds = rec.credentials;
  if (!isObject(creds)) return false;
  const pw = creds.password;
  if (!isObject(pw)) return false;
  const config = pw.config;
  if (!isObject(config)) return false;
  const value = config.password;
  return typeof value === "string" && value.length > 0;
}

export type LimitCheck = { ok: boolean; violations: string[] };

/**
 * Mirror the backend's authoritative import limits for UX feedback:
 *   - an EMPTY array (zero records) is a violation — the backend
 *     `enforce_import_limits` rejects it with 422 ("import requires at least one
 *     identity"), so we flag it client-side (WR-04) to keep the Import button
 *     disabled and show a clear message instead of an opaque server 422;
 *   - more than {@link HASHED_LIMIT} (1000) records is ALWAYS a violation;
 *   - more than {@link CLEARTEXT_LIMIT} (200) records is a violation when ANY
 *     record carries a cleartext password.
 * Pure; the backend remains the source of truth.
 */
export function checkLimits(records: CliIdentity[]): LimitCheck {
  const violations: string[] = [];
  const count = records.length;

  // WR-04: mirror the backend's zero-record rejection so an empty `[]` payload
  // is caught client-side with a clear message (the button stays disabled).
  if (count === 0) {
    violations.push("Import requires at least one identity.");
  }

  if (count > HASHED_LIMIT) {
    violations.push(
      `${count} records exceeds the maximum of ${HASHED_LIMIT} per import.`,
    );
  }

  const anyCleartext = records.some(hasCleartextPassword);
  if (anyCleartext && count > CLEARTEXT_LIMIT) {
    violations.push(
      `${count} records with cleartext passwords exceeds the maximum of ${CLEARTEXT_LIMIT}. Pre-hash passwords or import in smaller batches.`,
    );
  }

  return { ok: violations.length === 0, violations };
}

/**
 * Map backend Identity objects to the bare CLI shape for export. Only
 * `schema_id` + `traits` are emitted — NO credentials/secret material is ever
 * exported (T-06-32). The result round-trips through `parseImportArray` and is
 * directly consumable by `ory import identities`.
 */
export function toExportArray(identities: BackendIdentity[]): CliIdentity[] {
  return identities.map((id) => ({
    schema_id: id.schema_id,
    traits: isObject(id.traits) ? id.traits : {},
  }));
}

/** A named starter identity schema for the editor preset dropdown. */
export type SchemaPreset = {
  /** Stable id (select value). */
  id: string;
  /** Human label. */
  name: string;
  /** The draft-07 schema as a pretty-printed JSON string. */
  schema: string;
};

function presetJson(traits: {
  properties: Record<string, unknown>;
  required: string[];
  credentialIdentifier?: string;
}): string {
  const traitProps = traits.properties;
  // When a credential identifier is named, wire it as a Kratos password-credential
  // identifier on that trait (mirrors the shipped Ory starter schemas).
  if (traits.credentialIdentifier) {
    const target = traitProps[traits.credentialIdentifier];
    if (isObject(target)) {
      target["ory.sh/kratos"] = {
        credentials: { password: { identifier: true } },
      };
    }
  }
  return JSON.stringify(
    {
      $id: "https://schemas.ory.sh/presets/identity.schema.json",
      $schema: "http://json-schema.org/draft-07/schema#",
      title: "Person",
      type: "object",
      properties: {
        traits: {
          type: "object",
          properties: traitProps,
          required: traits.required,
          additionalProperties: false,
        },
      },
    },
    null,
    2,
  );
}

/**
 * Three starter draft-07 identity schemas for the editor preset dropdown. Each
 * has an object `properties.traits` so it passes the Plan-02 backend validation
 * (`validate_identity_schema`).
 */
export const SCHEMA_PRESETS: SchemaPreset[] = [
  {
    id: "email-password",
    name: "Email + password (default)",
    schema: presetJson({
      properties: {
        email: {
          type: "string",
          format: "email",
          title: "E-Mail",
          maxLength: 320,
        },
      },
      required: ["email"],
      credentialIdentifier: "email",
    }),
  },
  {
    id: "email-name",
    name: "Email + name",
    schema: presetJson({
      properties: {
        email: {
          type: "string",
          format: "email",
          title: "E-Mail",
          maxLength: 320,
        },
        name: {
          type: "object",
          title: "Name",
          properties: {
            first: { type: "string", title: "First name" },
            last: { type: "string", title: "Last name" },
          },
        },
      },
      required: ["email"],
      credentialIdentifier: "email",
    }),
  },
  {
    id: "username",
    name: "Username",
    schema: presetJson({
      properties: {
        username: {
          type: "string",
          title: "Username",
          minLength: 3,
          maxLength: 64,
        },
      },
      required: ["username"],
      credentialIdentifier: "username",
    }),
  },
];
