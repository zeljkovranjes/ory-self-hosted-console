"use client";

// IDENT-02 — the destructive delete-confirm gate (UI-SPEC §States).
//
// Delete is NEVER one-click: it is gated behind a shadcn AlertDialog. On
// confirm it calls DELETE /api/kratos/identities/{id} through lib/api.ts (which
// attaches X-CSRF-Token, T-06-22), then invalidates the ["identities"] query so
// the list refetches, toasts, and runs an optional onDeleted callback (e.g. the
// detail page navigates back to /users).

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
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

export type DeleteIdentityDialogProps = {
  id: string;
  /** Human identifier shown in the confirm copy. */
  identifier: string;
  /** The control that opens the dialog (menu item / button). */
  trigger: React.ReactNode;
  /** Called after a successful delete (e.g. navigate away from the detail). */
  onDeleted?: () => void;
};

export function DeleteIdentityDialog({
  id,
  identifier,
  trigger,
  onDeleted,
}: DeleteIdentityDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/kratos/identities/${id}`, { method: "DELETE" });
      await queryClient.invalidateQueries({ queryKey: ["identities"] });
      toast.success(`Identity ${identifier} deleted`);
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete ${identifier}${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete identity?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently deletes <strong>{identifier}</strong> and all of its
            data. This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            // Prevent the default auto-close so the async delete controls it.
            onClick={(e) => {
              e.preventDefault();
              void confirmDelete();
            }}
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
          >
            {busy ? "Deleting…" : "Delete"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
