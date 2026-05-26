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
//
// WR-05: Hydra's /oauth2/revoke is a PUBLIC-port endpoint that, per RFC 7009,
// requires the CLIENT to authenticate for a confidential-client token. Sending
// only `{token}` makes Hydra reject the revoke for `client_secret_basic`/
// `client_secret_post` tokens. So the dialog COLLECTS the client credentials:
// `client_id` is prefilled from the introspection result when available, and the
// operator supplies the `client_secret` (write-only — the console never has it).
// Both are forwarded to the backend, which relays them to Hydra. A public
// (`none`) client token needs no creds, so the secret field is optional.

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export type RevokeTokenDialogProps = {
  /** The token to revoke (forwarded to the backend; never shown in copy). */
  token: string;
  /**
   * The client_id this token belongs to, if known from introspection. Prefills
   * the (editable) client_id field so a confidential-client revoke can
   * authenticate (RFC 7009).
   */
  clientId?: string;
  /** The control that opens the dialog (e.g. the "Revoke" button). */
  trigger: React.ReactNode;
  /** Called after a successful revoke (e.g. clear the introspection result). */
  onRevoked?: () => void;
};

export function RevokeTokenDialog({
  token,
  clientId,
  trigger,
  onRevoked,
}: RevokeTokenDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [clientIdInput, setClientIdInput] = React.useState(clientId ?? "");
  const [clientSecret, setClientSecret] = React.useState("");

  // Re-seed the client_id when a new token (with a known client) is inspected.
  React.useEffect(() => {
    setClientIdInput(clientId ?? "");
    setClientSecret("");
  }, [clientId, token]);

  async function confirmRevoke() {
    setBusy(true);
    try {
      // RFC 7009: forward the client credentials so Hydra can authenticate the
      // revocation for a confidential-client token. Omit empty fields so a
      // public-client token (no creds) still works.
      const body: {
        token: string;
        client_id?: string;
        client_secret?: string;
      } = { token };
      const cid = clientIdInput.trim();
      const csecret = clientSecret;
      if (cid) body.client_id = cid;
      if (csecret) body.client_secret = csecret;

      // X-CSRF-Token is attached automatically by lib/api for mutations.
      await api("/api/hydra/oauth2/revoke", {
        method: "POST",
        body: JSON.stringify(body),
      });
      toast.success("Token revoked");
      setOpen(false);
      setClientSecret("");
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
            client must obtain a new token. For a confidential client, provide
            its credentials so Hydra can authenticate the revocation (RFC 7009).
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="space-y-3 py-2">
          <div className="grid gap-2">
            <Label htmlFor="revoke-client-id">Client ID</Label>
            <Input
              id="revoke-client-id"
              aria-label="Client ID for revocation"
              placeholder="Client ID that owns this token"
              value={clientIdInput}
              onChange={(e) => setClientIdInput(e.target.value)}
              className="font-mono text-xs"
              disabled={busy}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="revoke-client-secret">Client secret</Label>
            <Input
              id="revoke-client-secret"
              type="password"
              autoComplete="off"
              aria-label="Client secret for revocation"
              placeholder="Required for a confidential client (leave blank for public)"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              className="font-mono text-xs"
              disabled={busy}
            />
            <p className="text-muted-foreground text-xs">
              The console never stores client secrets. A public (auth method
              <code className="mx-1 font-mono">none</code>) client needs none.
            </p>
          </div>
        </div>

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
