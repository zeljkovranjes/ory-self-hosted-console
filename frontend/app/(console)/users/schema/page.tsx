"use client";

// IDENT-03 — the identity-schema editor page (/users/schema, UI-SPEC §4).
//
// Composes the Phase-5 MonacoEditor (json, with the draft-07 metaschema as the
// optional in-editor diagnostics hook) with a preset dropdown (SCHEMA_PRESETS)
// and the SettingsForm config-status banner visual contract. Save PUTs the whole
// schema to the dedicated Plan-02 route, which runs the transactional config
// engine (backup -> atomic JSON write -> Kratos restart -> health-poll/rollback)
// and returns `{status}`; the banner reflects that status. A 422 (invalid draft-07
// / missing properties.traits) surfaces the field errors inline; invalid JSON in
// the editor blocks the save BEFORE any network call. A standing warning notes
// that saving restarts Kratos.
//
// All egress is via lib/api.ts (`/backend`); no Ory host/SDK literal (T-06-33).

import * as React from "react";

import { api, ApiError, type FieldError } from "@/lib/api";
import { SCHEMA_PRESETS } from "@/lib/cli-identity";
import { MonacoEditor } from "@/components/monaco-editor";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";

// The status machine shared with SettingsForm (Phase-4 config status, the
// backend PUT response is authoritative). `validating` is a local-only step
// before the network call.
type Status = "idle" | "validating" | "restarting" | "healthy" | "failed";

type SchemaSaveResponse = { status?: Exclude<Status, "validating"> } | undefined;

// The JSON-Schema-of-JSON-Schema diagnostics hook (draft-07 metaschema, minimal):
// gives the operator in-editor squiggles without any network $ref fetch. Kept
// small + local — Monaco's enableSchemaRequest:false prevents remote resolution.
const DRAFT_07_META: object = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: ["object", "boolean"],
  properties: {
    type: {},
    properties: { type: "object" },
    required: { type: "array", items: { type: "string" } },
    title: { type: "string" },
  },
};

const BANNERS: Record<
  Exclude<Status, "idle" | "validating">,
  {
    role: "status" | "alert";
    variant: "default" | "destructive";
    icon: React.ReactNode;
    title: string;
    description: string;
  }
> = {
  restarting: {
    role: "status",
    variant: "default",
    icon: <Loader2Icon className="animate-spin" />,
    title: "Service restarting",
    description:
      "Applying the schema and waiting for Kratos to come back healthy.",
  },
  healthy: {
    role: "status",
    variant: "default",
    icon: <CheckCircle2Icon className="text-green-600 dark:text-green-500" />,
    title: "Configuration healthy",
    description: "Kratos restarted cleanly with the new identity schema.",
  },
  failed: {
    role: "alert",
    variant: "destructive",
    icon: <CircleAlertIcon />,
    title: "Save failed",
    description:
      "The schema could not be applied and was rolled back to last-known-good.",
  },
};

export default function SchemaEditorPage() {
  const [value, setValue] = React.useState<string>("");
  const [status, setStatus] = React.useState<Status>("idle");
  const [localError, setLocalError] = React.useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = React.useState<FieldError[]>([]);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [presetId, setPresetId] = React.useState<string>("");

  // Load the active schema on mount.
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const schema = await api<unknown>("/api/kratos/identity-schema");
        if (!cancelled) setValue(JSON.stringify(schema, null, 2));
      } catch {
        if (!cancelled)
          setLoadError("Could not load the active identity schema.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function onSelectPreset(id: string) {
    setPresetId(id);
    const preset = SCHEMA_PRESETS.find((p) => p.id === id);
    if (preset) {
      setValue(preset.schema);
      // Clearing prior errors keeps the editor state coherent after a swap.
      setLocalError(null);
      setFieldErrors([]);
      setStatus("idle");
    }
  }

  async function onSave() {
    setLocalError(null);
    setFieldErrors([]);

    // Block locally on malformed JSON BEFORE any network call.
    let parsed: unknown;
    try {
      parsed = JSON.parse(value);
    } catch {
      setLocalError("Editor content is not valid JSON. Fix it before saving.");
      setStatus("idle");
      return;
    }

    setStatus("restarting");
    try {
      const res = await api<SchemaSaveResponse>(
        "/api/kratos/identity-schema",
        { method: "PUT", body: JSON.stringify(parsed) },
      );
      setStatus(res?.status ?? "healthy");
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(e.fieldErrors);
        setStatus("idle");
        return;
      }
      setStatus("failed");
    }
  }

  const banner =
    status === "idle" || status === "validating" ? null : BANNERS[status];
  const isSaving = status === "restarting";

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Identity schema
        </h1>
        <p className="text-sm text-muted-foreground">
          Edit the active Kratos identity schema. Start from a preset or edit the
          current schema directly.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>Saving restarts Kratos</AlertTitle>
        <AlertDescription>
          Applying a new identity schema restarts the Kratos service. Existing
          sessions are unaffected, but the service is briefly unavailable while it
          comes back healthy.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>Schema editor</CardTitle>
          <CardDescription>
            JSON Schema (draft-07). The schema must define an object
            <code className="mx-1">properties.traits</code> for Kratos to accept
            it.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="schema-preset">Preset</Label>
            <select
              id="schema-preset"
              aria-label="Preset"
              value={presetId}
              onChange={(e) => onSelectPreset(e.target.value)}
              className="border-input bg-transparent h-9 w-fit rounded-md border px-3 py-2 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
            >
              <option value="">Choose a starter schema…</option>
              {SCHEMA_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          {loadError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Load failed</AlertTitle>
              <AlertDescription>{loadError}</AlertDescription>
            </Alert>
          ) : null}

          <MonacoEditor
            language="json"
            value={value}
            onChange={setValue}
            jsonSchema={DRAFT_07_META}
            ariaLabel="schema-editor"
            height={420}
          />

          {localError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Invalid JSON</AlertTitle>
              <AlertDescription>{localError}</AlertDescription>
            </Alert>
          ) : null}

          {fieldErrors.length > 0 ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Schema rejected</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-5">
                  {fieldErrors.map((fe, i) => (
                    <li key={`${fe.path}-${i}`}>
                      <code className="mr-1">{fe.path}</code>
                      {fe.message}
                    </li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}

          {banner ? (
            <Alert
              role={banner.role}
              variant={banner.variant}
              aria-live={banner.role === "alert" ? "assertive" : "polite"}
            >
              {banner.icon}
              <AlertTitle>
                {banner.title} ({status})
              </AlertTitle>
              <AlertDescription>{banner.description}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button type="button" onClick={onSave} disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2Icon className="animate-spin" />
                Saving…
              </>
            ) : (
              "Save schema"
            )}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
