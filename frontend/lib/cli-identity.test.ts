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
