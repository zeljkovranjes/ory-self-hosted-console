"use client";

// SSO-05 — destructive organization confirmation (Phase 14 frontend).
//
// One AlertDialog reusing the Phase-11 DeleteWebhookDialog shell (never
// one-click; busy label; bg-destructive confirm): DELETE /api/organizations/{id}
// (UUID). The backend cascades the org's domains. On success we invalidate the
// list.
//
// All egress via @/lib/api (attaches X-CSRF-Token on the DELETE).

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
import { ORGANIZATIONS_QUERY_KEY } from "./types";

export type DeleteOrganizationDialogProps = {
  orgId: string;
  label: string;
  trigger: React.ReactNode;
  onDeleted?: () => void;
};

export function DeleteOrganizationDialog({
  orgId,
  label,
  trigger,
  onDeleted,
}: DeleteOrganizationDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/organizations/${encodeURIComponent(orgId)}`, {
        method: "DELETE",
      });
      await queryClient.invalidateQueries({
        queryKey: [ORGANIZATIONS_QUERY_KEY],
      });
      toast.success("Organization deleted");
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete organization${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this organization?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently deletes{" "}
            <strong className="break-all">{label}</strong> and releases all of
            its verified domains. Any linked SAML connection is left intact but is
            no longer associated with this organization. This action cannot be
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
            {busy ? "Deleting…" : "Delete organization"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
