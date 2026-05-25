import { describe, expect, it } from "vitest";
import { z } from "zod";

import { buildTraitsForm } from "./identity-schema-form";

// Unit tests for the BOUNDED traits-schema -> RHF/Zod form descriptor generator
// (06-RESEARCH Pattern 6). We do NOT touch the network or any Ory host literal:
// the generator is a pure function over the active identity schema's
// `properties.traits.properties`. The fixture mirrors the shipped
// config/kratos/identity.schema.json (email+password default) plus extra trait
// types so we can assert the string/email/bool/enum/number mappings and the
// required-array -> non-optional Zod rule, with an exotic type falling back to a
// raw-JSON field rather than being dropped.

const emailSchemaFixture = {
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Person",
  type: "object",
  properties: {
    traits: {
      type: "object",
      properties: {
        email: {
          type: "string",
          format: "email",
          title: "E-Mail",
          minLength: 3,
        },
      },
      required: ["email"],
      additionalProperties: false,
    },
  },
} as const;

const richSchemaFixture = {
  type: "object",
  properties: {
    traits: {
      type: "object",
      properties: {
        email: { type: "string", format: "email", title: "E-Mail" },
        username: { type: "string", title: "Username" },
        newsletter: { type: "boolean", title: "Newsletter" },
        age: { type: "number", title: "Age" },
        plan: { type: "string", title: "Plan", enum: ["free", "pro"] },
        // An exotic/unsupported trait type must fall back, not crash/drop.
        address: { type: "array", title: "Addresses" },
      },
      required: ["email"],
    },
  },
} as const;

describe("buildTraitsForm (Pattern 6 — bounded traits generator)", () => {
  it("maps the shipped email trait to a required email input + email Zod", () => {
    const { fields, zodSchema } = buildTraitsForm(emailSchemaFixture);

    expect(fields).toHaveLength(1);
    const email = fields[0];
    expect(email).toMatchObject({
      name: "email",
      label: "E-Mail",
      input: "email",
      required: true,
    });

    // Zod mirrors the email + required rule.
    expect(zodSchema.safeParse({ email: "a@b.com" }).success).toBe(true);
    expect(zodSchema.safeParse({ email: "not-an-email" }).success).toBe(false);
    expect(zodSchema.safeParse({}).success).toBe(false); // required
  });

  it("uses the trait name as the label when no title is set", () => {
    const { fields } = buildTraitsForm({
      properties: { traits: { properties: { handle: { type: "string" } } } },
    });
    expect(fields[0]).toMatchObject({ name: "handle", label: "handle" });
  });

  it("maps boolean -> switch, number -> number, enum -> select with options", () => {
    const { fields } = buildTraitsForm(richSchemaFixture);
    const byName = Object.fromEntries(fields.map((f) => [f.name, f]));

    expect(byName.newsletter.input).toBe("switch");
    expect(byName.age.input).toBe("number");
    expect(byName.plan).toMatchObject({
      input: "select",
      options: ["free", "pro"],
    });
    expect(byName.username.input).toBe("text");
  });

  it("falls back to a raw-JSON field for an unsupported trait type (no drop)", () => {
    const { fields } = buildTraitsForm(richSchemaFixture);
    const address = fields.find((f) => f.name === "address");
    expect(address).toBeDefined();
    expect(address?.input).toBe("json");
  });

  it("marks only the schema's required[] traits as required in fields + Zod", () => {
    const { fields, zodSchema } = buildTraitsForm(richSchemaFixture);
    const byName = Object.fromEntries(fields.map((f) => [f.name, f]));
    expect(byName.email.required).toBe(true);
    expect(byName.username.required).toBe(false);

    // Optional fields can be omitted; required email cannot.
    expect(zodSchema.safeParse({ email: "a@b.com" }).success).toBe(true);
    expect(zodSchema.safeParse({ username: "bob" }).success).toBe(false);
  });

  it("returns an empty form for a schema with no traits (no crash)", () => {
    const { fields, zodSchema } = buildTraitsForm({});
    expect(fields).toEqual([]);
    expect(zodSchema.safeParse({}).success).toBe(true);
  });

  it("the produced zodSchema is a real Zod object (assignable to SettingsForm)", () => {
    const { zodSchema } = buildTraitsForm(emailSchemaFixture);
    expect(zodSchema).toBeInstanceOf(z.ZodType);
  });
});
