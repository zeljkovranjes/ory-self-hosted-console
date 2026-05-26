"use client";

// SSO-02 — destructive SAML-connection confirmation (Phase 14 frontend).
//
// One AlertDialog reusing the Phase-11 DeleteWebhookDialog shell (never
// one-click; busy label; bg-destructive confirm): DELETE /api/sso/connections/{id}
// where {id} is the connection tenant. The backend delete is TWO-SIDED (it
// removes both the Polis connection and the Kratos provider entry), so a single
// confirm cleanly tears the whole thing down. On success we forget the tenant in
// the local registry and invalidate the list.
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
import { forgetTenant, SAML_CONNECTIONS_QUERY_KEY } from "./types";

export type DeleteConnectionDialogProps = {
  /** The connection tenant (the backend {id} path segment). */
  tenant: string;
  trigger: React.ReactNode;
  onDeleted?: () => void;
};

export function DeleteConnectionDialog({
  tenant,
  trigger,
  onDeleted,
}: DeleteConnectionDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/sso/connections/${encodeURIComponent(tenant)}`, {
        method: "DELETE",
      });
      forgetTenant(tenant);
      await queryClient.invalidateQueries({
        queryKey: [SAML_CONNECTIONS_QUERY_KEY],
      });
      toast.success("SAML connection deleted");
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete SAML connection${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this SAML connection?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently deletes the connection{" "}
            <strong className="font-mono break-all">{tenant}</strong> and removes
            its sign-in provider. Any organization linked to it can no longer use
            SAML sign-in until a new connection is created. This action cannot be
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
            {busy ? "Deleting…" : "Delete connection"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
