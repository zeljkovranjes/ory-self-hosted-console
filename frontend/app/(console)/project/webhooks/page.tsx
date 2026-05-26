"use client";

// HOOK-01/02 — the Webhooks list page (11-UI-SPEC §A).
//
// Composes the Phase-5 DataTable in server mode exactly like the Phase-8 OAuth2
// Clients page: a fetcher calls GET /api/webhooks through @/lib/api (the sole
// egress — no Ory/backend host literal). The backend route returns a plain array
// of secret-free WebhookViews, so the fetcher reports total = rows.length (server
// paging is a no-op until the list grows a cursor — same forward-compatible shape
// the other array-backed pages use).
//
// Columns: Name (font-medium), URL (mono, truncated + full title, click → edit),
// Events (Badge chips / +N count), Secret ("Set"/"Not set" Badge — NEVER the
// value), Enabled (Badge), Created. Kebab: View / Edit / Rotate secret / Delete
// (Rotate + Delete gated behind their AlertDialogs).
//
// Create/Edit are hosted in a Dialog on this page (the WebhookForm). The secret
// minted on create — and the new secret on rotate — surface ONCE in the
// ack-gated WebhookSecretReveal (T-11-18). The list itself renders no secret.

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus } from "lucide-react";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Webhook } from "./types";
import { WebhookForm } from "./webhook-form";
import { WebhookSecretReveal } from "./secret-reveal";
import {
  DeleteWebhookDialog,
  RotateSecretDialog,
  WEBHOOKS_QUERY_KEY,
} from "./webhook-dialogs";

const PAGE_SIZE = 20;

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function RowActions({
  webhook,
  onEdit,
  onRotated,
}: {
  webhook: Webhook;
  onEdit: (w: Webhook) => void;
  onRotated: (secret: string, name: string) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Webhook actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => onEdit(webhook)}>
          View
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onEdit(webhook)}>
          Edit
        </DropdownMenuItem>
        <RotateSecretDialog
          webhookId={webhook.id}
          onRotated={(secret) => onRotated(secret, webhook.name)}
          trigger={
            <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
              Rotate secret
            </DropdownMenuItem>
          }
        />
        <DropdownMenuSeparator />
        <DeleteWebhookDialog
          webhookId={webhook.id}
          url={webhook.url}
          trigger={
            <DropdownMenuItem
              variant="destructive"
              onSelect={(e) => e.preventDefault()}
            >
              Delete
            </DropdownMenuItem>
          }
        />
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export default function WebhooksPage() {
  const queryClient = useQueryClient();
  // The one-time secret to reveal (after create or rotate).
  const [revealed, setRevealed] = React.useState<{
    secret: string;
    name: string;
  } | null>(null);
  // The create/edit dialog state. `null` = closed; otherwise create or edit.
  const [editing, setEditing] = React.useState<
    { mode: "create" } | { mode: "edit"; webhook: Webhook } | null
  >(null);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: [WEBHOOKS_QUERY_KEY] });
  }, [queryClient]);

  const columns = React.useMemo<ColumnDef<Webhook>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Name",
        cell: ({ row }) => (
          <button
            type="button"
            className="font-medium text-primary hover:underline"
            onClick={() => setEditing({ mode: "edit", webhook: row.original })}
          >
            {row.original.name}
          </button>
        ),
      },
      {
        accessorKey: "url",
        header: "URL",
        cell: ({ row }) => {
          const url = row.original.url ?? "";
          return (
            <span className="font-mono text-xs" title={url}>
              {url.length > 32 ? `${url.slice(0, 32)}…` : url}
            </span>
          );
        },
      },
      {
        id: "events",
        header: "Events",
        cell: ({ row }) => {
          const evts = row.original.events ?? [];
          if (!evts.length)
            return <span className="text-muted-foreground">—</span>;
          const shown = evts.slice(0, 2);
          const extra = evts.length - shown.length;
          return (
            <div className="flex flex-wrap gap-1">
              {shown.map((e) => (
                <Badge key={e} variant="outline" className="font-mono text-xs">
                  {e}
                </Badge>
              ))}
              {extra > 0 ? (
                <Badge variant="secondary" className="text-xs">
                  +{extra}
                </Badge>
              ) : null}
            </div>
          );
        },
      },
      {
        id: "secret",
        header: "Secret",
        cell: ({ row }) =>
          // The secret VALUE is never rendered — only the masked presence badge.
          row.original.secret_set ? (
            <Badge variant="secondary">Set</Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">
              Not set
            </Badge>
          ),
      },
      {
        id: "enabled",
        header: "Enabled",
        cell: ({ row }) =>
          row.original.enabled ? (
            <Badge variant="secondary" className="text-[--success]">
              Enabled
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">
              Disabled
            </Badge>
          ),
      },
      {
        accessorKey: "created_at",
        header: "Created",
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {fmtTs(row.original.created_at)}
          </span>
        ),
      },
    ],
    [],
  );

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize, filters }: FetchArgs): Promise<
      FetchResult<Webhook>
    > => {
      // The backend list route returns a plain array (no cursor). Fetch all and
      // apply the search box client-side over name/url.
      const all = await api<Webhook[]>("/api/webhooks");
      let rows = all ?? [];

      const search = filters.find((f) => f.id === "name")?.value;
      if (typeof search === "string" && search) {
        const q = search.toLowerCase();
        rows = rows.filter(
          (w) =>
            w.name.toLowerCase().includes(q) ||
            w.url.toLowerCase().includes(q),
        );
      }

      const total = rows.length;
      const start = pageIndex * (pageSize || PAGE_SIZE);
      const page = rows.slice(start, start + (pageSize || PAGE_SIZE));
      return { rows: page, total };
    },
    [],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Webhooks</h1>
        <p className="text-sm text-muted-foreground">
          Outbound webhooks fired by the console on events. Each delivery is
          signed with the webhook&apos;s secret. This is the console&apos;s own
          dispatcher, not an Ory hook.
        </p>
      </div>

      <DataTable<Webhook>
        columns={columns}
        fetcher={fetcher}
        queryKey={WEBHOOKS_QUERY_KEY}
        searchColumn="name"
        searchPlaceholder="Search by name or URL…"
        initialPageSize={PAGE_SIZE}
        caption="Console webhooks"
        rowActions={(row) => (
          <RowActions
            webhook={row}
            onEdit={(w) => setEditing({ mode: "edit", webhook: w })}
            onRotated={(secret, name) => setRevealed({ secret, name })}
          />
        )}
        toolbar={
          <Button size="sm" onClick={() => setEditing({ mode: "create" })}>
            <Plus />
            Create webhook
          </Button>
        }
        emptyCta={
          <Button size="sm" onClick={() => setEditing({ mode: "create" })}>
            Create webhook
          </Button>
        }
      />

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {editing?.mode === "edit" ? "Edit webhook" : "Create webhook"}
            </DialogTitle>
          </DialogHeader>
          {editing?.mode === "edit" ? (
            <WebhookForm
              mode="edit"
              webhook={editing.webhook}
              onCancel={() => setEditing(null)}
              onUpdated={() => {
                setEditing(null);
                invalidate();
              }}
            />
          ) : editing?.mode === "create" ? (
            <WebhookForm
              mode="create"
              onCancel={() => setEditing(null)}
              onCreated={(secret, name) => {
                setEditing(null);
                invalidate();
                if (secret) setRevealed({ secret, name });
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>

      <WebhookSecretReveal
        secret={revealed?.secret ?? null}
        webhookName={revealed?.name}
        onDone={() => setRevealed(null)}
      />
    </div>
  );
}
