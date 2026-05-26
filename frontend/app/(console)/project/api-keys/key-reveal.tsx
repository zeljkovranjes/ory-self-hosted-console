"use client";

// PROJ-02 — the one-time API-key reveal (11-UI-SPEC §G / Copywriting :147).
//
// The backend issues a console API key and returns the RAW key EXACTLY ONCE on
// issue (the key is one-way SHA-256 hashed at rest and unrecoverable thereafter).
// This component surfaces it once inside a Dialog gated by an explicit "I've
// stored the key" acknowledgement: the dialog CANNOT be dismissed until the
// operator confirms they copied it. After dismiss only the masked form is ever
// shown — there is no reveal-again affordance anywhere (the key is write-only).
//
// Copied verbatim from the Phase-8 client-secret reveal, relabeled for API keys.

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

export type KeyRevealProps = {
  /** The one-time raw key to reveal, or null when there is nothing to show. */
  apiKey: string | null;
  /** The key name (shown for context). */
  name?: string;
  /** Called once the operator acknowledges and dismisses the dialog. */
  onDone: () => void;
};

export function KeyReveal({ apiKey, name, onDone }: KeyRevealProps) {
  const [acknowledged, setAcknowledged] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  // Reset the gate whenever a new key is surfaced.
  React.useEffect(() => {
    setAcknowledged(false);
    setCopied(false);
  }, [apiKey]);

  if (!apiKey) return null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(apiKey!);
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
          <DialogTitle>Copy your API key now</DialogTitle>
          <DialogDescription>
            This is the only time the full key is shown. Store it securely — it
            cannot be retrieved again. You can revoke it at any time.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          {name ? (
            <div className="grid gap-1">
              <span className="text-muted-foreground text-xs">Name</span>
              <code className="font-mono text-xs break-all">{name}</code>
            </div>
          ) : null}

          <div className="rounded-md border p-4">
            <div className="flex items-start justify-between gap-2">
              <code className="font-mono text-sm break-all" aria-label="API key">
                {apiKey}
              </code>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void copy()}
                aria-label="Copy API key"
              >
                {copied ? <Check /> : <Copy />}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="ack-key"
              checked={acknowledged}
              onCheckedChange={(v) => setAcknowledged(v === true)}
              aria-label="I've stored the key"
            />
            <Label htmlFor="ack-key" className="text-sm font-normal">
              I&apos;ve stored the key
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
