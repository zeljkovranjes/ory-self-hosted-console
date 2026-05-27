"use client";

// EVT-02 — the event-sink Delivery-log page (cloned from the Phase-11 webhook
// delivery log). Composes the Phase-5 DataTable in server mode against GET
// /api/event-sinks/deliveries (console Postgres, NOT Ory). A filter block (status
// Select + optional sink Select) builds a URLSearchParams and re-queries
// server-side. The backend route returns a plain array (capped at 200), so the
// fetcher reports total = rows.length.
//
// Detail (Dialog): the redacted request payload in a read-only Monaco json block
// (carrying the idempotency id, no raw PII — EVT-03), the target, the
// X-Console-Signature header name (webhook kind), last status/error, the
// per-attempt summary, and a redeliver action.
//
// Redeliver: POST /api/event-sinks/deliveries/{id}/redeliver via @/lib/api (CSRF
// attached). A redeliver to a now-SSRF-resolving target is rejected at delivery
// time and reflected as a failed/dead status on refetch — never a silent success.
//
// All egress via @/lib/api — no Ory host/port literal (bundle-egress gate).

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, Send } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { MonacoEditor } from "@/components/monaco-editor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { Delivery, EventSink } from "../types";
import { DELIVERY_STATUSES, SIGNATURE_HEADER } from "../types";

const PAGE_SIZE = 20;
const QUERY_KEY = "event-sink-deliveries";
const ALL = "all";

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

type Filters = {
  status: string;
  sinkId: string;
};

const EMPTY_FILTERS: Filters = { status: ALL, sinkId: ALL };

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case "delivered":
      return (
        <Badge variant="secondary" className="text-[--success]">
          Delivered
        </Badge>
      );
    case "failed":
      return (
        <Badge variant="secondary" className="text-destructive">
          Failed
        </Badge>
      );
    case "dead":
      return (
        <Badge variant="outline" className="text-destructive">
          Dead — max attempts reached
        </Badge>
      );
    case "delivering":
      return <Badge variant="secondary">Delivering</Badge>;
    case "pending":
    default:
      return <Badge variant="secondary">{status || "Pending"}</Badge>;
  }
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono text-xs break-all" : ""}>{value}</span>
    </div>
  );
}

function DeliveryDetailDialog({
  delivery,
  sink,
}: {
  delivery: Delivery;
  sink?: EventSink;
}) {
  const raw = React.useMemo(
    () => JSON.stringify(delivery.payload ?? {}, null, 2),
    [delivery.payload],
  );
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="View delivery details">
          <Eye />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Delivery details</DialogTitle>
        </DialogHeader>
        <div className="grid gap-2 text-sm">
          <DetailRow label="Event" value={delivery.event} mono />
          <DetailRow
            label="Status"
            value={<StatusBadge status={delivery.status} />}
          />
          <DetailRow
            label="Target"
            value={sink?.target ?? delivery.sink_id}
            mono
          />
          {sink?.kind === "webhook" || !sink ? (
            <DetailRow label="Signature header" value={SIGNATURE_HEADER} mono />
          ) : null}
          <DetailRow
            label="Attempt"
            value={`${delivery.attempt} / ${delivery.max_attempts}`}
            mono
          />
          <DetailRow
            label="Last status code"
            value={delivery.last_status_code ?? "—"}
            mono
          />
          <DetailRow
            label="Next attempt"
            value={fmtTs(delivery.next_attempt_at)}
            mono
          />
          <DetailRow label="Updated" value={fmtTs(delivery.updated_at)} mono />
        </div>

        <div className="space-y-2">
          <Label>Attempt history</Label>
          <div className="space-y-2">
            <div className="rounded-md border p-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs">
                  Attempt {delivery.attempt} / {delivery.max_attempts}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {delivery.last_status_code != null
                    ? `HTTP ${delivery.last_status_code}`
                    : "no response yet"}
                </span>
              </div>
              {delivery.last_error ? (
                <p className="mt-1 font-mono text-xs text-destructive break-all">
                  {delivery.last_error}
                </p>
              ) : null}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <Label>Request payload (redacted)</Label>
          <MonacoEditor
            language="json"
            value={raw}
            onChange={() => {}}
            readOnly
            height={320}
            ariaLabel="Delivery payload (read-only)"
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RedeliverButton({
  deliveryId,
  onDone,
}: {
  deliveryId: string;
  onDone: () => void;
}) {
  const [busy, setBusy] = React.useState(false);
  async function redeliver() {
    setBusy(true);
    try {
      await api(`/api/event-sinks/deliveries/${deliveryId}/redeliver`, {
        method: "POST",
      });
      toast.success("Delivery re-enqueued");
      onDone();
    } catch (e) {
      // A redeliver may be rejected (e.g. a now-SSRF-resolving target). Surface it
      // explicitly — never a silent success. The re-enqueued row reflects a
      // failed/dead status on the next refetch.
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      toast.error(`Failed to redeliver${status}`);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label="Redeliver"
      disabled={busy}
      onClick={() => void redeliver()}
    >
      <Send />
    </Button>
  );
}

export default function DeliveriesPage() {
  const queryClient = useQueryClient();
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);

  const filterKey = React.useMemo(() => JSON.stringify(applied), [applied]);

  // Sink options for the filter Select + name/target lookup in the table.
  const { data: sinks } = useQuery({
    queryKey: ["event-sinks-options"],
    queryFn: () => api<EventSink[]>("/api/event-sinks"),
  });
  const sinkById = React.useMemo(() => {
    const m = new Map<string, EventSink>();
    for (const s of sinks ?? []) m.set(s.id, s);
    return m;
  }, [sinks]);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({
      predicate: (q) =>
        Array.isArray(q.queryKey) &&
        typeof q.queryKey[0] === "string" &&
        (q.queryKey[0] as string).startsWith(QUERY_KEY),
    });
  }, [queryClient]);

  const columns = React.useMemo<ColumnDef<Delivery>[]>(
    () => [
      {
        id: "sink",
        header: "Sink",
        cell: ({ row }) => {
          const s = sinkById.get(row.original.sink_id);
          const label = s?.name ?? s?.target ?? row.original.sink_id;
          return (
            <a
              href="/project/event-streams"
              className="font-mono text-xs text-primary hover:underline"
              title={s?.target ?? row.original.sink_id}
            >
              {label}
            </a>
          );
        },
      },
      {
        accessorKey: "event",
        header: "Event",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.event}</span>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        id: "attempt",
        header: "Attempt",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.attempt} / {row.original.max_attempts}
          </span>
        ),
      },
      {
        accessorKey: "last_status_code",
        header: "Last status code",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.last_status_code ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "next_attempt_at",
        header: "Next attempt",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.next_attempt_at)}
          </span>
        ),
      },
    ],
    [sinkById],
  );

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize }: FetchArgs): Promise<
      FetchResult<Delivery>
    > => {
      const qp = new URLSearchParams();
      if (applied.status !== ALL) qp.set("status", applied.status);
      if (applied.sinkId !== ALL) qp.set("sink_id", applied.sinkId);

      const q = qp.toString();
      const all = await api<Delivery[]>(
        `/api/event-sinks/deliveries${q ? `?${q}` : ""}`,
      );
      const rows = all ?? [];
      const total = rows.length;
      const start = pageIndex * (pageSize || PAGE_SIZE);
      const page = rows.slice(start, start + (pageSize || PAGE_SIZE));
      return { rows: page, total };
    },
    [applied],
  );

  function applyFilters() {
    setApplied(draft);
  }

  function clearFilters() {
    setDraft(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Delivery log</h1>
        <p className="text-sm text-muted-foreground">
          Every event-sink delivery attempt — target, status, response code, and
          per-attempt history. Failed deliveries are retried with backoff
          (at-least-once); you can manually redeliver. The payload is PII-redacted
          and carries the event idempotency id.
        </p>
      </div>

      <div className="space-y-3 rounded-md border p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="filter-status">Status</Label>
            <Select
              value={draft.status}
              onValueChange={(v) => setDraft((d) => ({ ...d, status: v }))}
            >
              <SelectTrigger id="filter-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All</SelectItem>
                {DELIVERY_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-sink">Sink</Label>
            <Select
              value={draft.sinkId}
              onValueChange={(v) => setDraft((d) => ({ ...d, sinkId: v }))}
            >
              <SelectTrigger id="filter-sink">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All sinks</SelectItem>
                {(sinks ?? []).map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={clearFilters}>
            Clear
          </Button>
          <Button type="button" onClick={applyFilters}>
            Apply filters
          </Button>
        </div>
      </div>

      <DataTable<Delivery>
        key={filterKey}
        columns={columns}
        fetcher={fetcher}
        queryKey={`${QUERY_KEY}:${filterKey}`}
        initialPageSize={PAGE_SIZE}
        caption="Event-sink deliveries"
        rowActions={(row) => (
          <div className="flex items-center justify-end gap-1">
            <DeliveryDetailDialog
              delivery={row}
              sink={sinkById.get(row.sink_id)}
            />
            <RedeliverButton deliveryId={row.id} onDone={invalidate} />
          </div>
        )}
      />
    </div>
  );
}
