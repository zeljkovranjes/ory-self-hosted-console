"use client";

// EVT-01 — destructive event-sink confirmations (cloned from the Phase-11
// webhook-dialogs). Two AlertDialogs (never one-click; busy label; bg-destructive
// confirm):
//   - DeleteSinkDialog: DELETE /api/event-sinks/{id} → invalidate the list.
//   - RotateSecretDialog: POST /api/event-sinks/{id}/rotate-secret → the response
//     carries a NEW secret ONCE, handed to the one-time reveal block.
//
// All egress via @/lib/api (attaches X-CSRF-Token on mutations).

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

export const SINKS_QUERY_KEY = "event-sinks";

// --- Delete ------------------------------------------------------------------

export type DeleteSinkDialogProps = {
  sinkId: string;
  target: string;
  trigger: React.ReactNode;
  onDeleted?: () => void;
};

export function DeleteSinkDialog({
  sinkId,
  target,
  trigger,
  onDeleted,
}: DeleteSinkDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/event-sinks/${sinkId}`, { method: "DELETE" });
      await queryClient.invalidateQueries({ queryKey: [SINKS_QUERY_KEY] });
      toast.success("Sink deleted");
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete sink${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this event sink?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently deletes the sink and stops all future deliveries to{" "}
            <strong className="font-mono break-all">{target}</strong>. Past
            delivery records are retained until pruned. This action cannot be
            undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault();
              void confirmDelete();
            }}
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
          >
            {busy ? "Deleting…" : "Delete sink"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// --- Rotate secret -----------------------------------------------------------

export type RotateSecretDialogProps = {
  sinkId: string;
  trigger: React.ReactNode;
  /** Called with the NEW secret on success (surface it in the one-time reveal). */
  onRotated: (secret: string) => void;
};

export function RotateSecretDialog({
  sinkId,
  trigger,
  onRotated,
}: RotateSecretDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmRotate() {
    setBusy(true);
    try {
      // The backend mints the new secret and returns it ONCE in this response.
      const res = await api<{ secret?: string }>(
        `/api/event-sinks/${sinkId}/rotate-secret`,
        { method: "POST" },
      );
      await queryClient.invalidateQueries({ queryKey: [SINKS_QUERY_KEY] });
      setOpen(false);
      onRotated(res.secret ?? "");
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to rotate secret${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Rotate the signing secret?</AlertDialogTitle>
          <AlertDialogDescription>
            This generates a new secret and immediately invalidates the current
            one. Any receiver verifying the old signature will reject deliveries
            until updated. The new secret is shown only once.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault();
              void confirmRotate();
            }}
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
          >
            {busy ? "Rotating…" : "Rotate secret"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
