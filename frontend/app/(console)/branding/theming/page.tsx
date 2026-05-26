"use client";

// AX-02 — Account Experience Theming editor (replaces the BRAND-06 stub).
//
// A real Monaco (CSS) editor over the console-owned theme override. Loads via
// GET /api/account-experience/theme -> { source } and saves via
// PUT /api/account-experience/theme { source } — BOTH through @/lib/api (the
// sole backend egress; no Ory/AX host literal). Gated by the
// `account_experience` FeatureGate: flag OFF renders the calm neutral disabled
// state (the backend route ALSO 404s — FLAG-01), flag ON renders this body.
//
// The override is CSS custom properties (`--ui-*` / `--button-*`) the AX injects
// as a :root{} <style> AFTER the Elements theme styles. Saving applies on the
// next AX restart (the AX re-reads the file at boot — A3); there is NO live
// rebuild. There is NO "Enterprise License" / "requires Ory" copy anywhere
// (FLAG-03 / SSO-07 discipline; asserted by the no-license grep in the gate).

import * as React from "react";
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

type ThemeLoadResponse = { source?: string };

function ThemingEditor() {
  const [value, setValue] = React.useState<string>("");
  const [loaded, setLoaded] = React.useState<string>("");
  const [status, setStatus] = React.useState<Status>("idle");
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [saveError, setSaveError] = React.useState<string | null>(null);

  // Load the current override on mount.
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await api<ThemeLoadResponse>(
          "/api/account-experience/theme",
        );
        if (!cancelled) {
          const src = res?.source ?? "";
          setValue(src);
          setLoaded(src);
        }
      } catch {
        if (!cancelled)
          setLoadError("Could not load the current theme override.");
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
    setStatus("saving");
    setSaveError(null);
    try {
      await api("/api/account-experience/theme", {
        method: "PUT",
        body: JSON.stringify({ source: value }),
      });
      setStatus("saved");
      setLoaded(value);
    } catch (e) {
      setStatus("failed");
      const suffix = e instanceof ApiError ? ` (${e.status})` : "";
      setSaveError(`The theme override could not be saved${suffix}.`);
    }
  }

  const isSaving = status === "saving";

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Theming</h1>
        <p className="text-sm text-muted-foreground">
          Override the Account Experience theme with CSS custom properties.
          Saving applies after the Account Experience service restarts.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>Theme variables apply on restart</AlertTitle>
        <AlertDescription>
          Declare Account Experience CSS variables (for example{" "}
          <code>--ui-brand</code>,{" "}
          <code>--button-primary-background-default</code>) in a{" "}
          <code>:root</code> block. The override is read by the Account
          Experience service when it next restarts.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>Theme override</CardTitle>
          <CardDescription>
            CSS custom properties layered over the default Account Experience
            theme. Leave empty to use the stock theme.
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
            language="css"
            value={value}
            onChange={onEditorChange}
            ariaLabel="Account Experience theme override (CSS variables)"
            height={420}
          />

          {status === "saved" ? (
            <Alert role="status" aria-live="polite">
              <CheckCircle2Icon className="text-success" />
              <AlertTitle>Theme override saved.</AlertTitle>
              <AlertDescription>
                The override was written. Restart the Account Experience service
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
              "Save theme"
            )}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

export default function ThemingPage() {
  return (
    <FeatureGate flag="account_experience" title="Theming">
      <ThemingEditor />
    </FeatureGate>
  );
}
