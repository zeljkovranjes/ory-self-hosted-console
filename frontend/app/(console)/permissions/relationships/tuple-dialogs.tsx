"use client";

// PERM-02 — the destructive delete-tuple confirmation (09-UI-SPEC Copywriting).
//
// Reuses the Phase-8 DeleteClientDialog shell verbatim (never one-click; busy
// label; bg-destructive confirm). DELETE /api/keto/relationships sends the FULL
// exact tuple (all filters) so exactly ONE row is removed — the backend delete
// is BY QUERY and an over-broad filter would match many tuples (T-9-fe-delete /
// Pitfall 2). The dialog names the exact tuple `{namespace}:{object}#{relation}
// @{subject}` so the operator confirms precisely what is removed.
//
// All egress via @/lib/api (attaches X-CSRF-Token on the DELETE). No Ory host.

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
import type { RelationTuple } from "./types";
import { subjectLabel } from "./types";

export type DeleteRelationshipDialogProps = {
  tuple: RelationTuple;
  trigger: React.ReactNode;
  onDeleted?: () => void;
};

/**
 * Build the exact-tuple DELETE query string from a full RelationTuple. Every
 * available filter is sent so the delete matches exactly one row (Pitfall 2).
 */
function deleteQuery(tuple: RelationTuple): string {
  const qp = new URLSearchParams();
  qp.set("namespace", tuple.namespace);
  qp.set("object", tuple.object);
  qp.set("relation", tuple.relation);
  if (tuple.subject_id) {
    qp.set("subject_id", tuple.subject_id);
  } else if (tuple.subject_set) {
    qp.set("subject_set_namespace", tuple.subject_set.namespace);
    qp.set("subject_set_object", tuple.subject_set.object);
    qp.set("subject_set_relation", tuple.subject_set.relation);
  }
  return qp.toString();
}

export function DeleteRelationshipDialog({
  tuple,
  trigger,
  onDeleted,
}: DeleteRelationshipDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  // namespace:object#relation@subject — the exact tuple identity.
  const tupleLabel = `${tuple.namespace}:${tuple.object}#${tuple.relation}@${subjectLabel(tuple)}`;

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/keto/relationships?${deleteQuery(tuple)}`, {
        method: "DELETE",
      });
      await queryClient.invalidateQueries({ queryKey: ["keto-relationships"] });
      toast.success("Relationship deleted");
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete relationship${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete relationship?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently removes the tuple{" "}
            <strong className="font-mono text-xs">{tupleLabel}</strong>. Any
            permission that depends on it will stop resolving for this subject.
            This action cannot be undone.
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
            {busy ? "Deleting…" : "Delete"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
