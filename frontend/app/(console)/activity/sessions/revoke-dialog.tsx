"use client";

// ACT-01 — the destructive revoke-session confirm gate (10-UI-SPEC §A /
// Copywriting "Revoke this session?").
//
// Revoke is NEVER one-click: it is gated behind a shadcn AlertDialog (reusing
// the Phase-8 RevokeTokenDialog shell). On confirm it DELETEs the session via
// /api/kratos/sessions/{id} through lib/api.ts (which attaches X-CSRF-Token —
// T-10-revoke), then toasts and runs an optional onRevoked callback so the
// sessions table can invalidate/refresh. Revoke maps to the backend
// `disable_session` (single-session deactivate) — the session flips to Inactive
// on re-list, it does NOT delete the identity's other sessions.
//
// On an upstream failure (502 AppError::Upstream) we surface a destructive toast
// with the status — NEVER collapse a failure into a success (T-10-02).

import * as React from "react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
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

export type RevokeSessionDialogProps = {
  /** The session id to revoke (forwarded to the backend; never shown in copy). */
  sessionId: string;
  /**
   * A human label for context in the dialog (owning identity / device), shown in
   * place of the raw session id (10-UI-SPEC §Copywriting).
   */
  contextLabel?: string;
  /** The control that opens the dialog (e.g. the "Revoke" menu item / button). */
  trigger: React.ReactNode;
  /** Called after a successful revoke (e.g. invalidate the sessions query). */
  onRevoked?: () => void;
};

export function RevokeSessionDialog({
  sessionId,
  contextLabel,
  trigger,
  onRevoked,
}: RevokeSessionDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmRevoke() {
    setBusy(true);
    try {
      // X-CSRF-Token is attached automatically by lib/api for mutations.
      await api(`/api/kratos/sessions/${sessionId}`, { method: "DELETE" });
      toast.success("Session revoked");
      setOpen(false);
      onRevoked?.();
    } catch (e) {
      // Never collapse a 502 into success — surface the failure with its status.
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to revoke session${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke this session?</AlertDialogTitle>
          <AlertDialogDescription>
            The session is immediately invalidated and the user is signed out of
            this session. They will need to sign in again. This action cannot be
            undone.
            {contextLabel ? (
              <>
                {" "}
                Session for{" "}
                <span className="font-mono text-xs">{contextLabel}</span>.
              </>
            ) : null}
          </AlertDialogDescription>
        </AlertDialogHeader>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            // Prevent the default auto-close so the async revoke controls it.
            onClick={(e) => {
              e.preventDefault();
              void confirmRevoke();
            }}
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
          >
            {busy ? "Revoking…" : "Revoke session"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
