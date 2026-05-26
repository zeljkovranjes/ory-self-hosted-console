"use client";

// OAUTH2-01 — destructive client confirmations (08-UI-SPEC Copywriting / §C).
//
// Two AlertDialogs reusing the Phase-6 DeleteIdentityDialog shell (never
// one-click; busy label; bg-destructive confirm):
//   - DeleteClientDialog: DELETE /api/hydra/clients/{id} -> invalidate list.
//   - RotateSecretDialog: PUT /api/hydra/clients/{id} with an EXPLICIT new secret
//     (the only path that transmits a secret on update — the normal edit omits it,
//     #2869). On success it hands the new secret to the one-time reveal block.
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
import type { OAuth2Client } from "../_lib/oauth2-types";

// --- Delete ------------------------------------------------------------------

export type DeleteClientDialogProps = {
  clientId: string;
  trigger: React.ReactNode;
  onDeleted?: () => void;
};

export function DeleteClientDialog({
  clientId,
  trigger,
  onDeleted,
}: DeleteClientDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api(`/api/hydra/clients/${clientId}`, { method: "DELETE" });
      await queryClient.invalidateQueries({ queryKey: ["oauth2-clients"] });
      toast.success(`Client ${clientId} deleted`);
      setOpen(false);
      onDeleted?.();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to delete client${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete OAuth2 client?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently deletes <strong>{clientId}</strong> and revokes all
            of its tokens. Applications using it will stop working. This action
            cannot be undone.
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

// --- Rotate secret -----------------------------------------------------------

/** Generate a cryptographically-strong URL-safe secret for rotation. */
function generateSecret(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  // base64url without padding.
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type RotateSecretDialogProps = {
  /** The client whose secret to rotate (PUT carries its full non-secret shape). */
  client: OAuth2Client;
  trigger: React.ReactNode;
  /** Called with the NEW secret on success (surface it in the one-time reveal). */
  onRotated: (secret: string) => void;
};

export function RotateSecretDialog({
  client,
  trigger,
  onRotated,
}: RotateSecretDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const clientId = client.client_id ?? "";

  async function confirmRotate() {
    setBusy(true);
    try {
      const newSecret = generateSecret();
      // Send the full non-secret shape + the EXPLICIT new secret. The backend
      // PUTs it via set_o_auth2_client; an explicit (non-None) secret is the only
      // way a secret is transmitted on update (#2869).
      const body: OAuth2Client = {
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        scope: client.scope,
        audience: client.audience,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        client_uri: client.client_uri,
        logo_uri: client.logo_uri,
        policy_uri: client.policy_uri,
        tos_uri: client.tos_uri,
        contacts: client.contacts,
        client_secret: newSecret,
      };
      await api(`/api/hydra/clients/${clientId}`, {
        method: "PUT",
        body: JSON.stringify(body),
      });
      await queryClient.invalidateQueries({ queryKey: ["oauth2-clients"] });
      await queryClient.invalidateQueries({ queryKey: ["oauth2-client", clientId] });
      setOpen(false);
      onRotated(newSecret);
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
          <AlertDialogTitle>Rotate client secret?</AlertDialogTitle>
          <AlertDialogDescription>
            This generates a new secret and immediately invalidates the current
            one. Any application using the old secret will stop working until
            updated. The new secret is shown only once.
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
