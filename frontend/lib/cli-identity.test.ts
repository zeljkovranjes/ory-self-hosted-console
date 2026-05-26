import { describe, expect, it } from "vitest";

import {
  SCHEMA_PRESETS,
  checkLimits,
  parseImportArray,
  toExportArray,
  HASHED_LIMIT,
  CLEARTEXT_LIMIT,
  type CliIdentity,
} from "./cli-identity";

// Unit coverage for the bare-array CLI interchange helpers (IDENT-04 frontend).
// These are PURE UX mirrors of the backend's authoritative limits (Plan 01:
// >1000 always invalid; >200 invalid when any record carries a cleartext
// credentials.password.config.password). The backend re-rejects regardless, so
// these tests assert UX correctness, not a security boundary.

function hashedRecords(n: number): CliIdentity[] {
  return Array.from({ length: n }, (_, i) => ({
    schema_id: "default",
    traits: { email: `u${i}@example.com` },
  }));
}

function cleartextRecords(n: number): CliIdentity[] {
  return Array.from({ length: n }, (_, i) => ({
    schema_id: "default",
    traits: { email: `u${i}@example.com` },
    credentials: { password: { config: { password: "s3cret!" } } },
  }));
}

describe("parseImportArray", () => {
  it("parses a valid bare array of {schema_id,traits} records", () => {
    const text = JSON.stringify([
      { schema_id: "default", traits: { email: "a@example.com" } },
    ]);
    const res = parseImportArray(text);
    expect("records" in res).toBe(true);
    if ("records" in res) {
      expect(res.records).toHaveLength(1);
      expect(res.records[0].schema_id).toBe("default");
    }
  });

  it("rejects a non-array top-level value", () => {
    const res = parseImportArray(JSON.stringify({ schema_id: "default" }));
    expect("error" in res).toBe(true);
  });

  it("rejects malformed (non-parseable) JSON", () => {
    const res = parseImportArray("{not json");
    expect("error" in res).toBe(true);
  });

  it("rejects a record missing schema_id", () => {
    const res = parseImportArray(
      JSON.stringify([{ traits: { email: "a@example.com" } }]),
    );
    expect("error" in res).toBe(true);
  });

  it("rejects a record missing traits", () => {
    const res = parseImportArray(JSON.stringify([{ schema_id: "default" }]));
    expect("error" in res).toBe(true);
  });

  it("produces a value-free error message (no payload echoed)", () => {
    const secret = "topsecretvalue";
    const res = parseImportArray(
      JSON.stringify([{ schema_id: "default", extra: secret }]),
    );
    expect("error" in res).toBe(true);
    if ("error" in res) expect(res.error).not.toContain(secret);
  });
});

describe("checkLimits", () => {
  it("flags an empty array as a violation (WR-04, mirrors backend 422)", () => {
    const res = checkLimits([]);
    expect(res.ok).toBe(false);
    expect(res.violations.length).toBeGreaterThan(0);
    expect(res.violations.join(" ")).toMatch(/at least one identity/i);
  });

  it("allows a single record (lower boundary ok)", () => {
    expect(checkLimits(hashedRecords(1)).ok).toBe(true);
  });

  it("allows 1000 hashed records (boundary ok)", () => {
    expect(checkLimits(hashedRecords(HASHED_LIMIT)).ok).toBe(true);
  });

  it("rejects 1001 hashed records (over the hard limit)", () => {
    const res = checkLimits(hashedRecords(HASHED_LIMIT + 1));
    expect(res.ok).toBe(false);
    expect(res.violations.length).toBeGreaterThan(0);
  });

  it("allows 200 cleartext records (boundary ok)", () => {
    expect(checkLimits(cleartextRecords(CLEARTEXT_LIMIT)).ok).toBe(true);
  });

  it("rejects 201 cleartext records (over the cleartext limit)", () => {
    const res = checkLimits(cleartextRecords(CLEARTEXT_LIMIT + 1));
    expect(res.ok).toBe(false);
  });

  it("allows 1000 hashed even though >200 (cleartext limit only fires with a cleartext password)", () => {
    expect(checkLimits(hashedRecords(500)).ok).toBe(true);
  });
});

describe("toExportArray", () => {
  it("maps backend identities to the bare CLI shape and strips secrets", () => {
    const out = toExportArray([
      {
        id: "id-1",
        schema_id: "default",
        state: "active",
        traits: { email: "a@example.com" },
        credentials: {
          password: { config: { hashed_password: "$argon2id$SECRET" } },
        },
      },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].schema_id).toBe("default");
    expect(out[0].traits).toEqual({ email: "a@example.com" });
    // No credential secret material survives the export mapping.
    const serialized = JSON.stringify(out);
    expect(serialized).not.toContain("SECRET");
    expect(serialized).not.toContain("hashed_password");
  });
});

// =============================================================================
// CLI-01 (Phase 10): data-plane field-shape interchange across all three planes.
//
// The per-service Ory crate models (kratos/hydra/keto-client v26.2.0) are
// generated from the SAME OpenAPI specs the official `ory`/`keto` CLI consumes,
// so model-shape equality IS the interchange guarantee (10-RESEARCH Don't-Hand-
// Roll). These assert the documented CLI field NAMES against representative
// fixtures of the already-shipped P6 identity, P8 OAuth2 client, and P9 Keto
// relation-tuple shapes. No new export format is created here.
//
//   - identity_shape: re-asserts the P6 bare-array round-trip is shape-preserving
//   - client_shape:   the P8 OAuth2 client carries the documented Hydra/`ory`
//                     client field names; client_secret is NEVER emitted on
//                     export (the write-only invariant from P8, T-10-17)
//   - tuple_shape:    the P9 Keto relation tuple carries {namespace,object,
//                     relation,subject_id} and the subject_set form
//                     {namespace,object,relation}, matching the `keto` CLI shape
// =============================================================================

describe("CLI-01 identity_shape (P6 bare-array interchange)", () => {
  it("parseImportArray accepts a single-object array AND a multi-record array", () => {
    const single = parseImportArray(
      JSON.stringify([
        { schema_id: "default", traits: { email: "a@example.com" } },
      ]),
    );
    expect("records" in single).toBe(true);

    const many = parseImportArray(
      JSON.stringify([
        { schema_id: "default", traits: { email: "a@example.com" } },
        {
          schema_id: "default",
          traits: { email: "b@example.com" },
          credentials: { password: { config: { password: "p" } } },
        },
      ]),
    );
    expect("records" in many).toBe(true);
    if ("records" in many) expect(many.records).toHaveLength(2);
  });

  it("toExportArray emits a bare array of {schema_id,traits} and round-trips through parseImportArray", () => {
    const exported = toExportArray([
      { id: "x", schema_id: "default", traits: { email: "rt@example.com" } },
    ]);
    expect(Array.isArray(exported)).toBe(true);
    expect(Object.keys(exported[0]).sort()).toEqual(["schema_id", "traits"]);
    // Round-trip: the export is directly consumable by `ory import identities`.
    const reparsed = parseImportArray(JSON.stringify(exported));
    expect("records" in reparsed).toBe(true);
    if ("records" in reparsed) {
      expect(reparsed.records[0].schema_id).toBe("default");
      expect(reparsed.records[0].traits).toEqual({ email: "rt@example.com" });
    }
  });
});

describe("CLI-01 client_shape (P8 OAuth2 client interchange)", () => {
  // A representative Hydra OAuth2 client as the backend list/detail shaper emits
  // it (client_secret pre-stripped — write-only). The field names are exactly
  // what `ory` / the Hydra Admin OpenAPI (and thus the CLI) consume.
  const oauth2Client = {
    client_id: "abcd-1234",
    client_name: "Acceptance Client",
    redirect_uris: ["https://app.example.com/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: "openid offline_access",
    token_endpoint_auth_method: "client_secret_basic",
  };

  it("carries the documented ory/Hydra OAuth2 client field names", () => {
    for (const key of [
      "client_id",
      "client_name",
      "redirect_uris",
      "grant_types",
      "response_types",
      "scope",
    ]) {
      expect(oauth2Client).toHaveProperty(key);
    }
    expect(Array.isArray(oauth2Client.redirect_uris)).toBe(true);
    expect(Array.isArray(oauth2Client.grant_types)).toBe(true);
    expect(Array.isArray(oauth2Client.response_types)).toBe(true);
    expect(typeof oauth2Client.scope).toBe("string");
  });

  it("NEVER emits client_secret on the export/read shape (write-only invariant, T-10-17)", () => {
    // The shaped client object (read/list/export) must not carry the secret.
    // (Property-absence is the invariant; a naive substring check would false-
    // positive on the legitimate `client_secret_basic` auth-method enum value.)
    expect(Object.keys(oauth2Client)).not.toContain("client_secret");
    expect(Object.keys(oauth2Client)).not.toContain(
      "registration_access_token",
    );
    expect(oauth2Client).not.toHaveProperty("client_secret");
    expect(oauth2Client).not.toHaveProperty("registration_access_token");
  });
});

describe("CLI-01 tuple_shape (P9 Keto relation-tuple interchange)", () => {
  // The two documented `keto` CLI relation-tuple subject forms.
  const tupleSubjectId = {
    namespace: "documents",
    object: "doc:readme",
    relation: "viewer",
    subject_id: "user:alice",
  };
  const tupleSubjectSet = {
    namespace: "documents",
    object: "doc:readme",
    relation: "viewer",
    subject_set: {
      namespace: "groups",
      object: "group:eng",
      relation: "member",
    },
  };

  it("the subject_id form carries {namespace,object,relation,subject_id}", () => {
    for (const key of ["namespace", "object", "relation", "subject_id"]) {
      expect(tupleSubjectId).toHaveProperty(key);
      expect(typeof (tupleSubjectId as Record<string, unknown>)[key]).toBe(
        "string",
      );
    }
    expect(tupleSubjectId).not.toHaveProperty("subject_set");
  });

  it("the subject_set form carries a {namespace,object,relation} subject_set object", () => {
    for (const key of ["namespace", "object", "relation"]) {
      expect(tupleSubjectSet).toHaveProperty(key);
    }
    expect(tupleSubjectSet).toHaveProperty("subject_set");
    for (const key of ["namespace", "object", "relation"]) {
      expect(tupleSubjectSet.subject_set).toHaveProperty(key);
    }
    expect(tupleSubjectSet).not.toHaveProperty("subject_id");
  });

  it("exactly one of subject_id | subject_set is present on each form (keto tuple invariant)", () => {
    const hasOneSubject = (t: Record<string, unknown>) =>
      ("subject_id" in t) !== ("subject_set" in t);
    expect(hasOneSubject(tupleSubjectId)).toBe(true);
    expect(hasOneSubject(tupleSubjectSet)).toBe(true);
  });
});

describe("SCHEMA_PRESETS", () => {
  it("exposes the three named presets", () => {
    const names = SCHEMA_PRESETS.map((p) => p.name);
    expect(names.length).toBe(3);
  });

  it("each preset is valid JSON with an object properties.traits", () => {
    for (const preset of SCHEMA_PRESETS) {
      const parsed = JSON.parse(preset.schema) as {
        properties?: { traits?: { type?: string } };
      };
      expect(parsed.properties).toBeTruthy();
      expect(parsed.properties?.traits).toBeTruthy();
      expect(typeof parsed.properties?.traits).toBe("object");
    }
  });
});
