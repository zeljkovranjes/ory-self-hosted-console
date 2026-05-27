"use client";

// PERM-01 — the Permission Model (OPL) editor page (09-UI-SPEC §C).
//
// Copies the IDENT-03 schema-editor shell (Status machine + BANNERS map +
// on-mount load + gated onSave) with the OPL specifics:
//   - MonacoEditor language="plaintext" (OPL is TypeScript-like; the wrapper
//     documents plaintext for P9), ariaLabel "Permission model (…)".
//   - Load via GET /api/keto/permission-model -> { source }.
//   - The headline (PERM-01) pre-save validate: POST the editor text as
//     { source } to /api/keto/opl/validate. A clean result (errors null/empty)
//     shows a --success "valid" banner and ENABLES Save; errors show a
//     destructive banner listing each ParseError message (with line/column) and
//     KEEP Save disabled (T-9-fe-opl-gate — defence-in-depth over the backend).
//   - Save is gated on (dirty AND last-validation-clean). The Save CTA opens a
//     confirm AlertDialog "Save permission model and restart Keto?" -> PUT
//     /api/keto/permission-model { source } -> the {status} reflects in the
//     SettingsForm-style status banner (restarting -> healthy / failed).
//
// All egress via @/lib/api; no Ory host/port literal.

import * as React from "react";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";
import type { OnMount } from "@monaco-editor/react";

import { api, ApiError } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import {
  useLiveOplValidate,
  type OplEditorHandle,
} from "./use-live-opl-validate";
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

// The status machine shared with SettingsForm (the backend PUT response is
// authoritative). `restarting` is set locally while the PUT is in flight.
type Status = "idle" | "restarting" | "healthy" | "failed";

type ModelSaveResponse = { status?: Exclude<Status, "idle"> } | undefined;
type ModelLoadResponse = { source?: string };

// A SourcePosition + ParseError as returned by Keto's CheckOplSyntaxResult.
type SourcePosition = { line?: number; column?: number };
type ParseError = {
  message?: string;
  start?: SourcePosition;
  end?: SourcePosition;
};
type CheckOplSyntaxResult = { errors?: ParseError[] | null };

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
      "Applying the permission model and waiting for Keto to come back healthy.",
  },
  healthy: {
    role: "status",
    variant: "default",
    icon: <CheckCircle2Icon className="text-success" />,
    title: "Configuration healthy",
    description: "Keto restarted cleanly with the new permission model.",
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

function posLabel(p?: SourcePosition): string {
  if (!p || (p.line == null && p.column == null)) return "";
  const line = p.line ?? "?";
  const col = p.column ?? "?";
  return ` (line ${line}, column ${col})`;
}

export default function PermissionModelPage() {
  const [value, setValue] = React.useState<string>("");
  const [loaded, setLoaded] = React.useState<string>("");
  const [status, setStatus] = React.useState<Status>("idle");
  const [loadError, setLoadError] = React.useState<string | null>(null);

  // Validation state (the PERM-01 gate). `validation` is the last result;
  // `validatedSource` is the editor text that result corresponds to — Save is
  // only enabled while the editor STILL matches a clean validation.
  const [validation, setValidation] = React.useState<
    { ok: boolean; errors: ParseError[] } | null
  >(null);
  const [validatedSource, setValidatedSource] = React.useState<string | null>(
    null,
  );
  const [validating, setValidating] = React.useState(false);

  // PERM-04 live validation: the (editor, monaco) handle from MonacoEditor's
  // onMount (Plan 18-01) feeds the debounced live-validate hook, which paints
  // inline markers and reports a NON-BLOCKING `unavailable` state on a
  // transport/502 failure. This is ADDITIVE UX ONLY — it never touches the
  // pre-save Validate/Save gate below (T-18-07).
  const [editorHandle, setEditorHandle] =
    React.useState<OplEditorHandle | null>(null);

  const handleEditorMount = React.useCallback<OnMount>((editor, monaco) => {
    setEditorHandle({
      editor: { getModel: () => editor.getModel() },
      monaco: {
        editor: {
          setModelMarkers: (model, owner, markers) =>
            monaco.editor.setModelMarkers(
              model as Parameters<typeof monaco.editor.setModelMarkers>[0],
              owner,
              markers,
            ),
        },
        MarkerSeverity: { Error: monaco.MarkerSeverity.Error },
      },
    });
  }, []);

  // Load the active model on mount.
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await api<ModelLoadResponse>("/api/keto/permission-model");
        if (!cancelled) {
          const src = res?.source ?? "";
          setValue(src);
          setLoaded(src);
        }
      } catch {
        if (!cancelled)
          setLoadError("Could not load the active permission model.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const isDirty = value !== loaded;
  // Save is gated on (dirty AND the current editor text passed validation).
  const validationClean =
    validation?.ok === true && validatedSource === value;
  const canSave = isDirty && validationClean;

  // PERM-04: drive the live, as-you-type markers off the current editor text.
  // Disabled while the model failed to load (no point validating a blank shell).
  const { unavailable: liveUnavailable } = useLiveOplValidate({
    source: value,
    handle: editorHandle,
    enabled: !loadError,
  });

  function onEditorChange(next: string) {
    setValue(next);
    // Any edit invalidates a prior clean validation (re-validate before Save).
    if (status === "healthy" || status === "failed") setStatus("idle");
  }

  async function onValidate() {
    setValidating(true);
    try {
      const res = await api<CheckOplSyntaxResult>("/api/keto/opl/validate", {
        method: "POST",
        body: JSON.stringify({ source: value }),
      });
      const errors = res?.errors ?? [];
      const ok = errors.length === 0;
      setValidation({ ok, errors });
      setValidatedSource(value);
    } catch (e) {
      const statusSuffix = e instanceof ApiError ? ` (${e.status})` : "";
      setValidation({
        ok: false,
        errors: [{ message: `Validation request failed${statusSuffix}.` }],
      });
      setValidatedSource(value);
    } finally {
      setValidating(false);
    }
  }

  async function onSave() {
    if (!canSave) return;
    setStatus("restarting");
    try {
      const res = await api<ModelSaveResponse>("/api/keto/permission-model", {
        method: "PUT",
        body: JSON.stringify({ source: value }),
      });
      setStatus(res?.status ?? "healthy");
      // A successful save makes the editor the new last-loaded baseline.
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
        <h1 className="text-2xl font-semibold tracking-tight">
          Permission Model
        </h1>
        <p className="text-sm text-muted-foreground">
          Edit the Ory Permission Language model and namespaces. Changes are
          validated against Keto before they are saved, then Keto restarts.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>Saving restarts Keto</AlertTitle>
        <AlertDescription>
          Applying a new permission model restarts the Keto service. Permission
          checks are briefly unavailable while it comes back healthy. The model
          must pass Keto&apos;s syntax check before it can be saved.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>Model editor</CardTitle>
          <CardDescription>
            Ory Permission Language (OPL). Validate the model before saving — a
            model that fails the syntax check cannot be saved.
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
            language="ory-opl"
            value={value}
            onChange={onEditorChange}
            onMount={handleEditorMount}
            ariaLabel="Permission model (Ory Permission Language)"
            height={420}
          />

          {/* PERM-04 live-validation hint. A transport/502 failure of the live
              check degrades to this SUBTLE, NON-BLOCKING status line — NEVER a
              destructive "invalid" verdict and NEVER a Save gate (T-18-05). The
              inline red squiggles (when the live check DOES return errors) are
              painted directly on the editor model by useLiveOplValidate. */}
          {liveUnavailable ? (
            <p
              role="status"
              aria-live="polite"
              className="text-muted-foreground text-xs"
            >
              Live validation unavailable — the editor cannot reach the
              validator right now. Use the Validate button before saving.
            </p>
          ) : null}

          {/* Validation banner (PERM-01). */}
          {validation && validatedSource === value ? (
            validation.ok ? (
              <Alert role="status" aria-live="polite">
                <CheckCircle2Icon className="text-success" />
                <AlertTitle>Permission model is valid.</AlertTitle>
                <AlertDescription>
                  The model passed Keto&apos;s syntax check. You can save it now.
                </AlertDescription>
              </Alert>
            ) : (
              <Alert role="alert" variant="destructive">
                <CircleAlertIcon />
                <AlertTitle>Permission model has errors.</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-5">
                    {validation.errors.map((er, i) => (
                      <li key={i}>
                        {er.message ?? "Syntax error"}
                        {posLabel(er.start)}
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )
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
            onClick={onValidate}
            disabled={validating || isSaving}
          >
            {validating ? (
              <>
                <Loader2Icon className="animate-spin" />
                Validating…
              </>
            ) : (
              "Validate"
            )}
          </Button>

          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button type="button" disabled={!canSave || isSaving}>
                {isSaving ? (
                  <>
                    <Loader2Icon className="animate-spin" />
                    Saving…
                  </>
                ) : (
                  "Validate & save"
                )}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Save permission model and restart Keto?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  Keto will restart to load the new model. Permission checks will
                  be briefly unavailable during the restart. The model has
                  already passed Keto&apos;s syntax check.
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
