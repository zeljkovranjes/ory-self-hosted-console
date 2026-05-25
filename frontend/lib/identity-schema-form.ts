// IDENT-02 — bounded "active identity schema -> form" generator (06-RESEARCH
// Pattern 6 + Standard-Stack note: traits-only, NOT a full rjsf JSON-Schema
// engine).
//
// The create/edit identity form must reflect the ACTIVE identity schema. Rather
// than render an arbitrary JSON Schema, we read ONLY `properties.traits.properties`
// and map a BOUNDED set of trait shapes to typed form-field descriptors plus a
// matching Zod object schema:
//
//   string                -> text   (z.string())
//   string + format:email -> email  (z.string().email())
//   string + enum[]        -> select (z.enum(...))
//   boolean               -> switch (z.boolean())
//   number / integer       -> number (z.number())
//   anything else          -> json   (raw-JSON escape; z.string() parsed by the form)
//
// `properties.traits.required[]` drives both the `required` marker on each
// descriptor and the Zod non-optional rule. An unsupported/exotic trait type is
// NEVER silently dropped — it falls back to a single raw-JSON field so the
// operator can still edit it. This is pure + unit-tested; it imports no network
// client and contains no Ory host literal (egress gate).

import { z, type ZodType } from "zod";

/** The bounded set of input controls a trait can map to. */
export type TraitInput = "text" | "email" | "switch" | "select" | "number" | "json";

/** A single generated form-field descriptor for one trait. */
export type TraitField = {
  /** Trait key (the RHF field name). */
  name: string;
  /** Human label — the trait's `title`, falling back to its name. */
  label: string;
  /** Which control to render. */
  input: TraitInput;
  /** Enum options when `input === "select"`. */
  options?: string[];
  /** Whether the schema lists this trait in `required[]`. */
  required: boolean;
};

export type BuiltTraitsForm = {
  /** Ordered field descriptors (schema property order). */
  fields: TraitField[];
  /** Zod object schema mirroring the descriptors' rules. */
  zodSchema: ZodType<Record<string, unknown>>;
};

type JsonObject = Record<string, unknown>;

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read `properties.traits.properties` from an unknown schema, safely. */
function readTraitProps(schema: unknown): {
  props: JsonObject;
  required: Set<string>;
} {
  if (!isObject(schema)) return { props: {}, required: new Set() };
  const properties = isObject(schema.properties) ? schema.properties : {};
  const traits = isObject(properties.traits) ? properties.traits : {};
  const props = isObject(traits.properties) ? traits.properties : {};
  const required = new Set(
    Array.isArray(traits.required)
      ? traits.required.filter((r): r is string => typeof r === "string")
      : [],
  );
  return { props, required };
}

/** Classify a single trait sub-schema into a bounded {@link TraitInput}. */
function classify(def: JsonObject): { input: TraitInput; options?: string[] } {
  const type = def.type;
  if (Array.isArray(def.enum)) {
    const options = def.enum.filter((o): o is string => typeof o === "string");
    // Only treat as a select when every option is a string (bounded).
    if (options.length === def.enum.length && options.length > 0) {
      return { input: "select", options };
    }
    return { input: "json" };
  }
  if (type === "string") {
    return { input: def.format === "email" ? "email" : "text" };
  }
  if (type === "boolean") return { input: "switch" };
  if (type === "number" || type === "integer") return { input: "number" };
  // Exotic/unsupported (object, array, multi-type, missing) -> raw-JSON escape.
  return { input: "json" };
}

/** Build the Zod leaf for one descriptor, honoring required vs optional. */
function zodFor(field: TraitField): ZodType {
  let leaf: ZodType;
  switch (field.input) {
    case "email":
      leaf = z.string().email();
      break;
    case "switch":
      leaf = z.boolean();
      break;
    case "number":
      leaf = z.number();
      break;
    case "select":
      leaf =
        field.options && field.options.length > 0
          ? z.enum(field.options as [string, ...string[]])
          : z.string();
      break;
    case "json":
      // Raw-JSON escape: a string the form parses on submit.
      leaf = z.string();
      break;
    case "text":
    default:
      leaf = z.string().min(1);
      break;
  }
  return field.required ? leaf : leaf.optional();
}

/**
 * Turn the active identity schema's traits into typed RHF field descriptors and
 * a matching Zod object schema. Bounded + pure; an unsupported trait type falls
 * back to a raw-JSON field rather than being dropped.
 */
export function buildTraitsForm(schema: unknown): BuiltTraitsForm {
  const { props, required } = readTraitProps(schema);

  const fields: TraitField[] = Object.entries(props).map(([name, raw]) => {
    const def = isObject(raw) ? raw : {};
    const { input, options } = classify(def);
    const title = typeof def.title === "string" ? def.title : name;
    return {
      name,
      label: title,
      input,
      ...(options ? { options } : {}),
      required: required.has(name),
    };
  });

  const shape: Record<string, ZodType> = {};
  for (const field of fields) shape[field.name] = zodFor(field);

  return {
    fields,
    zodSchema: z.object(shape) as ZodType<Record<string, unknown>>,
  };
}
