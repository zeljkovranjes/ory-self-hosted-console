"use client";

// PROJ-02 — Console API keys: issue / one-time reveal / masked list / revoke
// (11-UI-SPEC §G).
//
// A DataTable over GET /api/console/api-keys (the console_api_keys table — keys
// are one-way SHA-256 hashed at rest). The list shows the MASKED key only
// (prefix + dots). "Issue API key" opens a small Dialog for the name; on success
// the RAW key is surfaced EXACTLY ONCE via the ack-gated KeyReveal block and is
// never retrievable again. "Revoke" is gated behind an AlertDialog. All
// mutations go through @/lib/api (which attaches X-CSRF-Token).
//
// All egress via @/lib/api — no Ory host/port literal. (bundle-egress gate)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { KeyReveal } from "./key-reveal";

const QUERY_KEY = "console-api-keys";

// The masked ApiKeyView returned by GET /api/console/api-keys.
type ApiKeyView = {
  id: string;
  name: string;
  masked: string;
  created_by: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  state: string; // "Active" | "Revoked"
};

// The issue response = the masked view + a one-time `key`.
type IssueResponse = ApiKeyView & { key: string };

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function StateBadge({ state }: { state: string }) {
  return state === "Revoked" ? (
    <Badge variant="outline" className="text-muted-foreground">
      Revoked
    </Badge>
  ) : (
    <Badge variant="secondary">Active</Badge>
  );
}

// --- Revoke (AlertDialog) ----------------------------------------------------

function RevokeKeyDialog({
  apiKey,
  onRevoked,
}: {
  apiKey: ApiKeyView;
  onRevoked: () => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  async function confirmRevoke() {
    setBusy(true);
    try {
      await api(`/api/console/api-keys/${apiKey.id}/revoke`, {
        method: "POST",
      });
      toast.success(`API key "${apiKey.name}" revoked`);
      setOpen(false);
      onRevoked();
    } catch (e) {
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to revoke key${status}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button variant="ghost" size="sm" aria-label="Revoke API key">
          Revoke
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke this API key?</AlertDialogTitle>
          <AlertDialogDescription>
            The key is immediately invalidated and cannot be restored. Any
            integration using it will stop working. You can issue a new key at
            any time.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault();
              void confirmRevoke();
            }}
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
          >
            {busy ? "Revoking…" : "Revoke key"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// --- Issue (Dialog) ----------------------------------------------------------

function IssueKeyDialog({
  onIssued,
}: {
  onIssued: (key: string, name: string) => void;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function submit() {
    const trimmed = name.trim();
    if (!trimmed) {
      setError("A key name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api<IssueResponse>("/api/console/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: trimmed }),
      });
      await queryClient.invalidateQueries({ queryKey: [QUERY_KEY] });
      setOpen(false);
      setName("");
      onIssued(res.key, res.name);
    } catch (e) {
      if (e instanceof ApiError && e.fieldErrors.length) {
        setError(e.fieldErrors[0].message);
      } else {
        const status = e instanceof ApiError ? ` (${e.status})` : "";
        setError(`Failed to issue key${status}.`);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) {
          setName("");
          setError(null);
        }
      }}
    >
      <Button type="button" size="sm" onClick={() => setOpen(true)}>
        <Plus />
        Issue API key
      </Button>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Issue an API key</DialogTitle>
          <DialogDescription>
            Name this key so you can recognize it later. The full key is shown
            only once, immediately after it is issued.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="key-name">Name</Label>
          <Input
            id="key-name"
            value={name}
            placeholder="e.g. CI pipeline"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                void submit();
              }
            }}
          />
          {error ? (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => setOpen(false)}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button type="button" onClick={() => void submit()} disabled={busy}>
            {busy ? "Issuing…" : "Issue API key"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ApiKeysPage() {
  const queryClient = useQueryClient();
  // The one-time raw key surfaced after an issue.
  const [revealed, setRevealed] = React.useState<{
    key: string;
    name: string;
  } | null>(null);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEY] });
  }, [queryClient]);

  const columns = React.useMemo<ColumnDef<ApiKeyView>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Name",
        cell: ({ row }) => (
          <span className="font-medium">{row.original.name}</span>
        ),
      },
      {
        accessorKey: "masked",
        header: "Key",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.masked}</span>
        ),
      },
      {
        accessorKey: "created_at",
        header: "Created",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.created_at)}
          </span>
        ),
      },
      {
        accessorKey: "last_used_at",
        header: "Last used",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.last_used_at)}
          </span>
        ),
      },
      {
        id: "state",
        header: "State",
        cell: ({ row }) => <StateBadge state={row.original.state} />,
      },
    ],
    [],
  );

  const fetcher = React.useCallback(
    async (_args: FetchArgs): Promise<FetchResult<ApiKeyView>> => {
      const rows = await api<ApiKeyView[]>("/api/console/api-keys");
      return { rows, total: rows.length };
    },
    [],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">API Keys</h1>
        <p className="text-sm text-muted-foreground">
          Issue and revoke API keys for programmatic access to this console&apos;s
          own backend. These are console keys, not Ory credentials. A key is shown
          only once when issued.
        </p>
      </div>

      <p className="text-sm text-muted-foreground">
        Console keys for this backend, not Ory credentials.
      </p>

      <DataTable<ApiKeyView>
        columns={columns}
        fetcher={fetcher}
        queryKey={QUERY_KEY}
        caption="Console API keys"
        toolbar={
          <IssueKeyDialog
            onIssued={(key, name) => setRevealed({ key, name })}
          />
        }
        emptyCta={
          <IssueKeyDialog
            onIssued={(key, name) => setRevealed({ key, name })}
          />
        }
        rowActions={(row) =>
          row.state === "Revoked" ? null : (
            <div className="flex items-center justify-end">
              <RevokeKeyDialog apiKey={row} onRevoked={invalidate} />
            </div>
          )
        }
      />

      <KeyReveal
        apiKey={revealed?.key ?? null}
        name={revealed?.name}
        onDone={() => setRevealed(null)}
      />
    </div>
  );
}
