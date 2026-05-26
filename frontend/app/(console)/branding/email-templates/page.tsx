"use client";

// BRAND-01 — Email Templates editor (10-UI-SPEC §C, 10-RESEARCH Pattern 4).
//
// Inline mechanism (RESOLVED: inline base64, NOT override-path): the editor edits
// the `courier.templates.*` body/subject keys as RAW text; the backend wraps each
// value as a `base64://<b64>` URI on PUT and decodes it back on GET (the round-trip
// is server-side and invisible here, 10-02 Task 1). The form keys ARE the section's
// allowlisted JSON-Pointers (the flat pointer-keyed PUT body, no transform) — a 1:1
// mirror of the backend `KRATOS_EMAIL_TEMPLATES` allowlist.
//
// On save Kratos restarts ONLY; the SettingsForm status banner + sonner toast are
// inherited. A template-type Tabs picker + a channel Select choose which body to
// edit (HTML body / plaintext body / subject); Monaco renders the body, a plain
// Input renders the subject.

import * as React from "react";
import { z } from "zod";

import { MonacoEditor } from "@/components/monaco-editor";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { ConfigSection } from "../../authentication/_lib/config-section";

// The six courier template types exposed in v1 (10-RESEARCH Open Q1: valid/email).
const TEMPLATE_TYPES = [
  { key: "recovery", label: "Recovery" },
  { key: "recovery_code", label: "Recovery (code)" },
  { key: "verification", label: "Verification" },
  { key: "verification_code", label: "Verification (code)" },
  { key: "registration_code", label: "Registration (code)" },
  { key: "login_code", label: "Login (code)" },
] as const;

type TemplateTypeKey = (typeof TEMPLATE_TYPES)[number]["key"];

// The editable channel/field within a template type.
const FIELDS = [
  { key: "body/html", label: "HTML body", lang: "html" as const },
  { key: "body/plaintext", label: "Plaintext body", lang: "plaintext" as const },
  { key: "subject", label: "Subject", lang: null },
] as const;

type FieldKey = (typeof FIELDS)[number]["key"];

/** The allowlisted JSON-Pointer for a (type, field) pair (mirrors the backend). */
function pointerFor(type: TemplateTypeKey, field: FieldKey): string {
  return `/courier/templates/${type}/valid/email/${field}`;
}

// Build the flat pointer-keyed schema + defaults over every (type, field) pair —
// exactly the backend `KRATOS_EMAIL_TEMPLATES` set. Every value is a string of
// RAW template text (the base64 round-trip is server-side).
const ALL_POINTERS: string[] = TEMPLATE_TYPES.flatMap((t) =>
  FIELDS.map((f) => pointerFor(t.key, f.key)),
);

const schema = z.object(
  Object.fromEntries(ALL_POINTERS.map((p) => [p, z.string()])),
) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = Object.fromEntries(
  ALL_POINTERS.map((p) => [p, ""]),
);

export default function EmailTemplatesPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Email Templates
        </h1>
        <p className="text-sm text-muted-foreground">
          Edit the courier email and SMS templates. On save the changes are
          written to the Kratos configuration and Kratos restarts.
        </p>
      </div>

      <ConfigSection
        section="email-templates"
        schema={schema}
        defaults={defaults}
        title="Email Templates"
        description="Edit each template's HTML body, plaintext body, and subject as raw text."
        saveLabel="Save templates"
      >
        {(form) => <TemplateEditor form={form} />}
      </ConfigSection>
    </div>
  );
}

// The body of the SettingsForm: a template-type Tabs picker + a channel Select,
// editing the currently-selected pointer. Bound to the RHF form via
// watch/setValue so the flat pointer-keyed value object is the PUT body.
function TemplateEditor({
  // The RHF form instance from ConfigSection/SettingsForm.
  form,
}: {
  form: {
    watch: (name: string) => unknown;
    setValue: (
      name: string,
      value: unknown,
      opts?: { shouldDirty?: boolean },
    ) => void;
  };
}) {
  const [type, setType] = React.useState<TemplateTypeKey>("recovery");
  const [fieldKey, setFieldKey] = React.useState<FieldKey>("body/html");

  const field = FIELDS.find((f) => f.key === fieldKey) ?? FIELDS[0];
  const pointer = pointerFor(type, fieldKey);
  const typeLabel =
    TEMPLATE_TYPES.find((t) => t.key === type)?.label ?? type;

  const raw = form.watch(pointer);
  const value = typeof raw === "string" ? raw : "";

  function commit(next: string) {
    form.setValue(pointer, next, { shouldDirty: true });
  }

  const ariaLabel = `${typeLabel} email — ${field.label}`;

  return (
    <div className="space-y-4">
      <Tabs value={type} onValueChange={(v) => setType(v as TemplateTypeKey)}>
        <TabsList className="flex-wrap">
          {TEMPLATE_TYPES.map((t) => (
            <TabsTrigger key={t.key} value={t.key}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      <div className="grid gap-2">
        <Label htmlFor="template-field">Field</Label>
        <Select value={fieldKey} onValueChange={(v) => setFieldKey(v as FieldKey)}>
          <SelectTrigger id="template-field" aria-label="Template field">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {FIELDS.map((f) => (
              <SelectItem key={f.key} value={f.key}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {field.lang ? (
        <MonacoEditor
          language={field.lang}
          value={value}
          onChange={commit}
          ariaLabel={ariaLabel}
        />
      ) : (
        <div className="grid gap-2">
          <Label htmlFor="template-subject">{ariaLabel}</Label>
          <Input
            id="template-subject"
            aria-label={ariaLabel}
            value={value}
            placeholder="Recover access to your account"
            onChange={(e) => commit(e.target.value)}
          />
        </div>
      )}
    </div>
  );
}
