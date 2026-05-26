"use client";

// OAUTH2-02 — the destructive revoke-token confirm gate (08-UI-SPEC §D /
// Copywriting "Revoke this token?").
//
// Revoke is NEVER one-click: it is gated behind a shadcn AlertDialog (reusing
// the DeleteIdentityDialog shell). On confirm it POSTs the token to
// /api/hydra/oauth2/revoke through lib/api.ts (which attaches X-CSRF-Token —
// T-08-REVOKE-CSRF), then toasts and runs an optional onRevoked callback so the
// inspector can clear/refresh its result. The token value is never rendered in
// the dialog copy.

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

export type RevokeTokenDialogProps = {
  /** The token to revoke (forwarded to the backend; never shown in copy). */
  token: string;
  /** The control that opens the dialog (e.g. the "Revoke" button). */
  trigger: React.ReactNode;
  /** Called after a successful revoke (e.g. clear the introspection result). */
  onRevoked?: () => void;
};

export function RevokeTokenDialog({
  token,
  trigger,
  onRevoked,
}: RevokeTokenDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmRevoke() {
    setBusy(true);
    try {
      // X-CSRF-Token is attached automatically by lib/api for mutations.
      await api("/api/hydra/oauth2/revoke", {
        method: "POST",
        body: JSON.stringify({ token }),
      });
      toast.success("Token revoked");
      setOpen(false);
      onRevoked?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to revoke token${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke this token?</AlertDialogTitle>
          <AlertDialogDescription>
            The token is immediately invalidated and cannot be restored. The
            client must obtain a new token.
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
            {busy ? "Revoking…" : "Revoke"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
