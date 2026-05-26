"use client";

// OATH-01 — the Oathkeeper access-rules editor page (09-UI-SPEC §D).
//
// The same schema-editor shell as IDENT-03 / the Permission Model page, over
// the Oathkeeper rules file:
//   - MonacoEditor language="json", ariaLabel "Oathkeeper access rules".
//   - Load via GET /api/config/oathkeeper/rules (a JSON array).
//   - A local structural pre-check (valid JSON array) blocks Save BEFORE the
//     network call (mirrors the schema-editor JSON.parse guard).
//   - Save CTA "Save & restart" opens a confirm AlertDialog "Save access rules
//     and restart Oathkeeper?" -> PUT /api/config/oathkeeper/rules (the raw JSON
//     array) -> the {status} reflects in the SettingsForm-style status banner.
//   - Save disabled while !isDirty (or while the structural pre-check fails);
//     Discard resets to the last-loaded content.
//
// All egress via @/lib/api; no Ory host/port literal.

import * as React from "react";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";

import { api } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

type Status = "idle" | "restarting" | "healthy" | "failed";
type RulesSaveResponse = { status?: Exclude<Status, "idle"> } | undefined;

const BANNERS: Record<
  Exclude<Status, "idle">,
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
      "Applying the access rules and waiting for Oathkeeper to come back healthy.",
  },
  healthy: {
    role: "status",
    variant: "default",
    icon: <CheckCircle2Icon className="text-success" />,
    title: "Configuration healthy",
    description: "Oathkeeper restarted cleanly with the new access rules.",
  },
  failed: {
    role: "alert",
    variant: "destructive",
    icon: <CircleAlertIcon />,
    title: "Save failed",
    description:
      "The change could not be applied and was rolled back to last-known-good.",
  },
};

export default function AccessRulesPage() {
  const [value, setValue] = React.useState<string>("");
  const [loaded, setLoaded] = React.useState<string>("");
  const [status, setStatus] = React.useState<Status>("idle");
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [localError, setLocalError] = React.useState<string | null>(null);

  // Load the rules file on mount.
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await api<unknown>("/api/config/oathkeeper/rules");
        if (!cancelled) {
          const text = JSON.stringify(res ?? [], null, 2);
          setValue(text);
          setLoaded(text);
        }
      } catch {
        if (!cancelled)
          setLoadError("Could not load the Oathkeeper access rules.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const isDirty = value !== loaded;

  function onEditorChange(next: string) {
    setValue(next);
    setLocalError(null);
    if (status === "healthy" || status === "failed") setStatus("idle");
  }

  function onDiscard() {
    setValue(loaded);
    setLocalError(null);
    setStatus("idle");
  }

  // Structural pre-check: the rules file must be a JSON ARRAY. Returns the
  // parsed array, or null after setting a local error (blocks Save).
  function parseRulesArray(): unknown[] | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(value);
    } catch {
      setLocalError("Rules file is not valid JSON.");
      return null;
    }
    if (!Array.isArray(parsed)) {
      setLocalError("Rules file is not a valid JSON array.");
      return null;
    }
    return parsed;
  }

  async function onSave() {
    const parsed = parseRulesArray();
    if (parsed === null) {
      setStatus("idle");
      return;
    }
    setStatus("restarting");
    try {
      const res = await api<RulesSaveResponse>("/api/config/oathkeeper/rules", {
        method: "PUT",
        body: JSON.stringify(parsed),
      });
      setStatus(res?.status ?? "healthy");
      setLoaded(value);
    } catch {
      setStatus("failed");
    }
  }

  const banner = status === "idle" ? null : BANNERS[status];
  const isSaving = status === "restarting";

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Access Rules</h1>
        <p className="text-sm text-muted-foreground">
          Edit the Oathkeeper access-rules file. On save the rules are written and
          Oathkeeper restarts. The console authors and inspects rules; it does not
          proxy traffic.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>Saving restarts Oathkeeper</AlertTitle>
        <AlertDescription>
          Applying new access rules restarts the Oathkeeper service. Access
          decisions are briefly unavailable while it comes back healthy.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>Rules editor</CardTitle>
          <CardDescription>
            The Oathkeeper access rules, as a JSON array. The rules must be a
            valid JSON array before they can be saved.
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
            ariaLabel="Oathkeeper access rules"
            height={420}
          />

          {localError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Invalid rules file</AlertTitle>
              <AlertDescription>{localError}</AlertDescription>
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
          <Button
            type="button"
            variant="outline"
            onClick={onDiscard}
            disabled={!isDirty || isSaving}
          >
            Discard
          </Button>

          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button type="button" disabled={!isDirty || isSaving}>
                {isSaving ? (
                  <>
                    <Loader2Icon className="animate-spin" />
                    Saving…
                  </>
                ) : (
                  "Save & restart"
                )}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Save access rules and restart Oathkeeper?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  Oathkeeper will restart to load the new rules. Access decisions
                  will be briefly unavailable during the restart.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={isSaving}>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={(e) => {
                    e.preventDefault();
                    void onSave();
                  }}
                  disabled={isSaving}
                >
                  {isSaving ? "Saving…" : "Save & restart"}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardFooter>
      </Card>
    </div>
  );
}
