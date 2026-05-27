"use client";

// EVT-01/02/03 — the Event-streams console page (the real PROJ-03 surface, gated
// on the `event_streams` flag). Cloned from the Phase-11 Webhooks page: a sink
// DataTable + create/edit Dialog (kind webhook/nats/kafka, write-only creds, the
// one-time secret reveal on create/rotate) wrapped in <FeatureGate>. There is NO
// "Enterprise License" copy anywhere — the OFF state is the neutral FeatureGate
// empty-state.
//
// All egress via @/lib/api (the sole egress — no Ory/backend host literal). The
// list renders credentials ONLY as a Set/Not set badge (T-17-01), never the value.

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus } from "lucide-react";

import { FeatureGate } from "@/components/feature-gate";
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
import type { EventSink, SinkKind } from "./types";
import { SINK_KIND_LABELS } from "./types";
import { SinkForm } from "./sink-form";
import { SinkSecretReveal } from "./secret-reveal";
import {
  DeleteSinkDialog,
  RotateSecretDialog,
  SINKS_QUERY_KEY,
} from "./sink-dialogs";

const PAGE_SIZE = 20;

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function RowActions({
  sink,
  onEdit,
  onRotated,
}: {
  sink: EventSink;
  onEdit: (s: EventSink) => void;
  onRotated: (secret: string, name: string) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Sink actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => onEdit(sink)}>View</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onEdit(sink)}>Edit</DropdownMenuItem>
        <RotateSecretDialog
          sinkId={sink.id}
          onRotated={(secret) => onRotated(secret, sink.name)}
          trigger={
            <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
              Rotate secret
            </DropdownMenuItem>
          }
        />
        <DropdownMenuSeparator />
        <DeleteSinkDialog
          sinkId={sink.id}
          target={sink.target}
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

function EventStreamsBody() {
  const queryClient = useQueryClient();
  // The one-time secret to reveal (after create or rotate).
  const [revealed, setRevealed] = React.useState<{
    secret: string;
    name: string;
  } | null>(null);
  // The create/edit dialog state. `null` = closed; otherwise create or edit.
  const [editing, setEditing] = React.useState<
    { mode: "create" } | { mode: "edit"; sink: EventSink } | null
  >(null);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: [SINKS_QUERY_KEY] });
  }, [queryClient]);

  const columns = React.useMemo<ColumnDef<EventSink>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Name",
        cell: ({ row }) => (
          <button
            type="button"
            className="font-medium text-primary hover:underline"
            onClick={() => setEditing({ mode: "edit", sink: row.original })}
          >
            {row.original.name}
          </button>
        ),
      },
      {
        id: "kind",
        header: "Kind",
        cell: ({ row }) => (
          <Badge variant="outline">
            {SINK_KIND_LABELS[row.original.kind as SinkKind] ??
              row.original.kind}
          </Badge>
        ),
      },
      {
        accessorKey: "target",
        header: "Target",
        cell: ({ row }) => {
          const t = row.original.target ?? "";
          return (
            <span className="font-mono text-xs" title={t}>
              {t.length > 32 ? `${t.slice(0, 32)}…` : t}
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
      FetchResult<EventSink>
    > => {
      // The backend list route returns a plain array (no cursor). Fetch all and
      // apply the search box client-side over name/target.
      const all = await api<EventSink[]>("/api/event-sinks");
      let rows = all ?? [];

      const search = filters.find((f) => f.id === "name")?.value;
      if (typeof search === "string" && search) {
        const q = search.toLowerCase();
        rows = rows.filter(
          (s) =>
            s.name.toLowerCase().includes(q) ||
            s.target.toLowerCase().includes(q),
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
        <h1 className="text-2xl font-semibold tracking-tight">Event streams</h1>
        <p className="text-sm text-muted-foreground">
          Stream console events to external sinks — a signed webhook (the
          default), or a NATS / Kafka broker. Each delivery carries an
          idempotency id and is retried at-least-once. This is the console&apos;s
          own dispatcher, not an Ory hook.
        </p>
      </div>

      <div className="flex items-center justify-between">
        <a
          href="/project/event-streams/deliveries"
          className="text-sm text-primary hover:underline"
        >
          View delivery log →
        </a>
      </div>

      <DataTable<EventSink>
        columns={columns}
        fetcher={fetcher}
        queryKey={SINKS_QUERY_KEY}
        searchColumn="name"
        searchPlaceholder="Search by name or target…"
        initialPageSize={PAGE_SIZE}
        caption="Event sinks"
        rowActions={(row) => (
          <RowActions
            sink={row}
            onEdit={(s) => setEditing({ mode: "edit", sink: s })}
            onRotated={(secret, name) => setRevealed({ secret, name })}
          />
        )}
        toolbar={
          <Button size="sm" onClick={() => setEditing({ mode: "create" })}>
            <Plus />
            Create sink
          </Button>
        }
        emptyCta={
          <Button size="sm" onClick={() => setEditing({ mode: "create" })}>
            Create sink
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
              {editing?.mode === "edit" ? "Edit event sink" : "Create event sink"}
            </DialogTitle>
          </DialogHeader>
          {editing?.mode === "edit" ? (
            <SinkForm
              mode="edit"
              sink={editing.sink}
              onCancel={() => setEditing(null)}
              onUpdated={() => {
                setEditing(null);
                invalidate();
              }}
            />
          ) : editing?.mode === "create" ? (
            <SinkForm
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

      <SinkSecretReveal
        secret={revealed?.secret ?? null}
        sinkName={revealed?.name}
        onDone={() => setRevealed(null)}
      />
    </div>
  );
}

export default function EventStreamsPage() {
  return (
    <FeatureGate flag="event_streams" title="Event streams">
      <EventStreamsBody />
    </FeatureGate>
  );
}
