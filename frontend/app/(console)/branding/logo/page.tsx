"use client";

// BRAND-03 — the Console Logo upload page (10-UI-SPEC §E). CONSOLE branding
// only: the asset round-trips ONLY through the backend asset route
// (`/api/console/branding/logo`) — it is NEVER written to any Ory service.
//
// Flow: pick a file -> client-mirror type/size (the §Copywriting error copy) ->
// upload as multipart FormData (field name `logo`) through lib/api (CSRF
// attached) -> success toast + refresh preview + flip the state line. A
// "Reset to default" AlertDialog (shown only when custom) DELETEs the asset.
//
// The backend is AUTHORITATIVE: magic-byte + size + canonical-path validation
// live there. We surface any backend 4xx message verbatim — never silently drop.
// All egress via lib/api (`/backend`); no Ory host literal here.

import * as React from "react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
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
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { CircleAlertIcon } from "lucide-react";

// Client mirror of the backend cap (backend/src/branding/mod.rs MAX_LOGO_BYTES).
// The backend remains authoritative; this just gives instant feedback.
const MAX_LOGO_BYTES = 512 * 1024;
const ACCEPT = "image/png,image/svg+xml,image/x-icon,image/jpeg";
const ACCEPTED_TYPES = new Set([
  "image/png",
  "image/svg+xml",
  "image/x-icon",
  "image/vnd.microsoft.icon",
  "image/jpeg",
]);

type BrandingState = { logo: "custom" | "default"; kind?: string | null };

export default function ConsoleLogoPage() {
  const [state, setState] = React.useState<BrandingState | null>(null);
  const [previewUrl, setPreviewUrl] = React.useState<string>("");
  const [error, setError] = React.useState<string | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement | null>(null);

  // Cache-busting key so the <img> reloads after an upload/reset.
  const [bust, setBust] = React.useState(() => Date.now());

  const refreshState = React.useCallback(async () => {
    try {
      const s = await api<BrandingState>("/api/console/branding");
      setState(s);
    } catch {
      // Non-fatal: default to "default" if the state read fails.
      setState({ logo: "default" });
    }
  }, []);

  React.useEffect(() => {
    void refreshState();
  }, [refreshState]);

  const isCustom = state?.logo === "custom";
  // The served-asset URL (404 when unset -> the <img> onError falls back).
  const servedUrl = `/backend/api/console/branding/logo?v=${bust}`;

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    setError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    // Client mirror BEFORE upload (the backend is still authoritative).
    if (file.type && !ACCEPTED_TYPES.has(file.type)) {
      setError("Unsupported file type. Upload a PNG, SVG, ICO, or JPEG image.");
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setError(
        `File is too large. The maximum size is ${MAX_LOGO_BYTES / 1024} KB.`,
      );
      return;
    }

    // Local preview while uploading.
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(URL.createObjectURL(file));

    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("logo", file);
      await api("/api/console/branding/logo", { method: "POST", body: fd });
      toast.success("Console branding updated");
      setBust(Date.now());
      await refreshState();
    } catch (err) {
      // Surface the backend message verbatim — never silently drop.
      if (err instanceof ApiError && err.status === 422) {
        setError(
          err.fieldErrors.map((f) => f.message).join("; ") ||
            "The image was rejected by the server.",
        );
      } else if (err instanceof ApiError) {
        setError(`Upload failed (status ${err.status}).`);
      } else {
        setError("Upload failed due to an unexpected error.");
      }
    } finally {
      setUploading(false);
      // Allow re-selecting the same file.
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function onReset() {
    setResetting(true);
    setError(null);
    try {
      await api("/api/console/branding/logo", { method: "DELETE" });
      toast.success("Reset to the default logo");
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
        setPreviewUrl("");
      }
      setBust(Date.now());
      await refreshState();
    } catch (err) {
      const status = err instanceof ApiError ? ` (${err.status})` : "";
      toast.error(`Failed to reset the logo${status}`);
    } finally {
      setResetting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Console Logo</h1>
        <p className="text-sm text-muted-foreground">
          Upload a logo and favicon for this console&apos;s own interface. This
          is console branding only — it is never written to any Ory service.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Console logo</CardTitle>
          <CardDescription>
            Upload a PNG, SVG, ICO, or JPEG image (max {MAX_LOGO_BYTES / 1024}{" "}
            KB). The console shell falls back to the default logo when none is
            set.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-4">
          {/* Preview thumbnail on a muted backing so transparency shows. */}
          <div className="flex items-center gap-4">
            <div className="flex h-16 w-32 items-center justify-center rounded-md border bg-muted">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                key={bust}
                src={previewUrl || servedUrl}
                alt="Console logo preview"
                className="h-12 max-w-full object-contain"
                onError={(ev) => {
                  // No stored asset (404) and no local preview -> hide the
                  // broken-image glyph; the shell uses its bundled default.
                  (ev.currentTarget as HTMLImageElement).style.visibility =
                    "hidden";
                }}
              />
            </div>
            <p className="text-sm text-muted-foreground" aria-live="polite">
              {isCustom
                ? "Custom logo in use."
                : "Using the default Ory Console logo."}
            </p>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="logo-file">Logo image</Label>
            <input
              id="logo-file"
              ref={fileRef}
              type="file"
              accept={ACCEPT}
              aria-label="Upload logo"
              onChange={onFile}
              disabled={uploading}
              className="text-sm"
            />
          </div>

          {error ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Upload rejected</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              onClick={() => fileRef.current?.click()}
              disabled={uploading}
            >
              {uploading ? "Uploading…" : "Upload logo"}
            </Button>

            {isCustom ? (
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button type="button" variant="outline" disabled={resetting}>
                    Reset to default
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Reset to the default logo?</AlertDialogTitle>
                    <AlertDialogDescription>
                      The custom console logo and favicon are removed and the
                      default Ory Console branding is restored. You can upload a
                      new logo at any time.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel disabled={resetting}>
                      Cancel
                    </AlertDialogCancel>
                    <AlertDialogAction
                      onClick={(ev) => {
                        ev.preventDefault();
                        void onReset();
                      }}
                      disabled={resetting}
                      className="bg-destructive text-white hover:bg-destructive/90"
                    >
                      {resetting ? "Resetting…" : "Reset to default"}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
