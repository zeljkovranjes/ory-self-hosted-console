"use client";

// HOOK-02 — the one-time webhook signing-secret reveal (11-UI-SPEC §A / Copywriting).
//
// The backend mints a signing secret EXACTLY ONCE — on create and on an explicit
// rotate (11-01 routes return `secret` only in those two responses; GET/list are
// masked to a `secret_set` badge). This component is a near-verbatim copy of the
// Phase-8 ClientSecretReveal: it surfaces the secret once inside a Dialog gated by
// an explicit "I've stored the secret" acknowledgement — the dialog CANNOT be
// dismissed until the operator confirms they copied it. There is NO "show current
// secret" affordance anywhere else (the value is write-only — T-11-18).

import * as React from "react";
import { Check, Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export type WebhookSecretRevealProps = {
  /** The one-time secret to reveal, or null when there is nothing to show. */
  secret: string | null;
  /** The webhook name the secret belongs to (shown for context). */
  webhookName?: string;
  /** Called once the operator acknowledges and dismisses the dialog. */
  onDone: () => void;
};

export function WebhookSecretReveal({
  secret,
  webhookName,
  onDone,
}: WebhookSecretRevealProps) {
  const [acknowledged, setAcknowledged] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  // Reset the gate whenever a new secret is surfaced.
  React.useEffect(() => {
    setAcknowledged(false);
    setCopied(false);
  }, [secret]);

  if (!secret) return null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(secret!);
      setCopied(true);
    } catch {
      // Clipboard may be unavailable (insecure context); the value is selectable
      // in the code block as a fallback.
      setCopied(false);
    }
  }

  return (
    <Dialog
      open
      // Block dismissal until the operator has acknowledged. Radix calls
      // onOpenChange(false) on overlay/escape/close — swallow it unless ack'd.
      onOpenChange={(open) => {
        if (!open && acknowledged) onDone();
      }}
    >
      <DialogContent
        // Prevent escape/outside-click from closing before acknowledgement.
        onEscapeKeyDown={(e) => {
          if (!acknowledged) e.preventDefault();
        }}
        onPointerDownOutside={(e) => {
          if (!acknowledged) e.preventDefault();
        }}
        onInteractOutside={(e) => {
          if (!acknowledged) e.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle>Copy the signing secret now</DialogTitle>
          <DialogDescription>
            This is the only time the secret is shown. Store it securely — it
            cannot be retrieved again.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          {webhookName ? (
            <div className="grid gap-1">
              <span className="text-muted-foreground text-xs">Webhook</span>
              <code className="font-mono text-xs break-all">{webhookName}</code>
            </div>
          ) : null}

          <div className="rounded-md border p-4">
            <div className="flex items-start justify-between gap-2">
              <code
                className="font-mono text-sm break-all"
                aria-label="Webhook signing secret"
              >
                {secret}
              </code>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void copy()}
                aria-label="Copy signing secret"
              >
                {copied ? <Check /> : <Copy />}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="ack-webhook-secret"
              checked={acknowledged}
              onCheckedChange={(v) => setAcknowledged(v === true)}
              aria-label="I've stored the secret"
            />
            <Label htmlFor="ack-webhook-secret" className="text-sm font-normal">
              I&apos;ve stored the secret
            </Label>
          </div>
        </div>

        <DialogFooter>
          <Button type="button" disabled={!acknowledged} onClick={() => onDone()}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
