"use client";

// AX-03 — Account Experience Localization editor (replaces the BRAND-04 stub).
//
// A real Monaco (JSON) editor over the console-owned `customTranslations`
// catalog. Loads via GET /api/account-experience/translations -> { translations }
// and saves via PUT /api/account-experience/translations (the JSON body IS the
// catalog) — BOTH through @/lib/api (the sole backend egress; no Ory/AX host
// literal). Gated by the `account_experience` FeatureGate: flag OFF renders the
// calm neutral disabled state (the backend route ALSO 404s — FLAG-01).
//
// Validation: advisory client-side `JSON.parse` blocks an obviously-malformed
// save early; the backend JSON-parse is authoritative and a 422 (malformed /
// non-object) is surfaced INLINE (never collapsed into a success — T-15-08). The
// catalog applies on the next AX restart (the AX re-reads translations.json at
// boot — A3).
//
// Email-template language variants are a SEPARATE, courier-side concern handled
// by the existing BRAND-01 editor; this page links to it. There is NO
// "Enterprise License" / "requires Ory" copy anywhere (FLAG-03 / SSO-07).

import * as React from "react";
import Link from "next/link";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { FeatureGate } from "@/components/feature-gate";
import { MonacoEditor } from "@/components/monaco-editor";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

type Status = "idle" | "saving" | "saved" | "failed";

type TranslationsLoadResponse = { translations?: unknown };

// Pretty-print a catalog object as the editor's initial JSON text.
function formatCatalog(value: unknown): string {
  if (value == null) return "{}";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}

function LocalizationEditor() {
  const [value, setValue] = React.useState<string>("{}");
  const [loaded, setLoaded] = React.useState<string>("{}");
  const [status, setStatus] = React.useState<Status>("idle");
  const [loadError, setLoadError] = React.useState<string | null>(null);
  // The inline error surfaced from either the advisory client parse OR a backend
  // 422 field error (verbatim) — never collapsed into a success (T-15-08).
  const [saveError, setSaveError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await api<TranslationsLoadResponse>(
          "/api/account-experience/translations",
        );
        if (!cancelled) {
          const text = formatCatalog(res?.translations ?? {});
          setValue(text);
          setLoaded(text);
        }
      } catch {
        if (!cancelled)
          setLoadError("Could not load the current translations catalog.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const isDirty = value !== loaded;

  function onEditorChange(next: string) {
    setValue(next);
    if (status === "saved" || status === "failed") setStatus("idle");
    setSaveError(null);
  }

  async function onSave() {
    if (!isDirty) return;
    setSaveError(null);

    // Advisory client-side validation (the backend is authoritative). Block an
    // obviously-malformed or non-object catalog before the round-trip.
    let parsed: unknown;
    try {
      parsed = JSON.parse(value);
    } catch {
      setStatus("failed");
      setSaveError(
        "The translations catalog is not valid JSON. Fix the syntax and try again.",
      );
      return;
    }
    if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
      setStatus("failed");
      setSaveError(
        "The translations catalog must be a JSON object (a locale → strings map).",
      );
      return;
    }

    setStatus("saving");
    try {
      // Send the catalog object as the JSON body (the body IS the catalog).
      await api("/api/account-experience/translations", {
        method: "PUT",
        body: JSON.stringify(parsed),
      });
      setStatus("saved");
      setLoaded(value);
    } catch (e) {
      setStatus("failed");
      if (e instanceof ApiError && e.status === 422) {
        // Surface the backend field error VERBATIM (never collapse to success).
        const first = e.fieldErrors[0]?.message;
        setSaveError(
          first ??
            "The translations catalog was rejected as invalid JSON by the server.",
        );
      } else {
        const suffix = e instanceof ApiError ? ` (${e.status})` : "";
        setSaveError(`The translations catalog could not be saved${suffix}.`);
      }
    }
  }

  const isSaving = status === "saving";

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Localization</h1>
        <p className="text-sm text-muted-foreground">
          Edit the Account Experience translation catalog. Saving applies after
          the Account Experience service restarts.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>Custom translations apply on restart</AlertTitle>
        <AlertDescription>
          The catalog is a JSON object keyed by locale (for example{" "}
          <code>en</code>), mapping message keys to your override strings. It is
          read by the Account Experience service when it next restarts. For the
          login, registration and recovery email wording, use the{" "}
          <Link
            href="/branding/email-templates"
            className="text-primary hover:underline"
          >
            Email Templates
          </Link>{" "}
          editor — those courier messages are localized separately.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>Translation catalog</CardTitle>
          <CardDescription>
            A JSON map of locale → message overrides for the Account Experience
            UI. Leave as an empty object to use the built-in translations.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-4">
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
            onChange={onEditorChange}
            ariaLabel="Account Experience translations catalog (JSON)"
            height={420}
          />

          {status === "saved" ? (
            <Alert role="status" aria-live="polite">
              <CheckCircle2Icon className="text-success" />
              <AlertTitle>Translations saved.</AlertTitle>
              <AlertDescription>
                The catalog was written. Restart the Account Experience service
                to apply it.
              </AlertDescription>
            </Alert>
          ) : null}

          {status === "failed" && saveError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Save failed</AlertTitle>
              <AlertDescription>{saveError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button
            type="button"
            onClick={() => void onSave()}
            disabled={!isDirty || isSaving}
          >
            {isSaving ? (
              <>
                <Loader2Icon className="animate-spin" />
                Saving…
              </>
            ) : (
              "Save translations"
            )}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

export default function LocalizationPage() {
  return (
    <FeatureGate flag="account_experience" title="Localization">
      <LocalizationEditor />
    </FeatureGate>
  );
}
