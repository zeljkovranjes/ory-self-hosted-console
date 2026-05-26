"use client";

// ACT-02 — the Courier Messages list page (10-UI-SPEC §B).
//
// Composes the Phase-5 DataTable in server mode with the SAME ref-backed
// cursor-map + +1-sentinel discipline as the Sessions / Relationships pages. The
// fetcher hits the Kratos courier wrapper through @/lib/api with page_size,
// optional page_token, a status filter, and a recipient filter.
//
// Columns: Recipient, Type, Status (Badge per the color map), Send count,
// Created. The detail is READ-ONLY ONLY (the courier is a delivery LOG): a Dialog
// with the message fields + the body in a read-only Monaco block. There is NO
// revoke / edit / delete affordance on this surface.
//
// All egress via @/lib/api — no Ory host/port literal. (bundle-egress gate)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { MonacoEditor } from "@/components/monaco-editor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

const PAGE_SIZE = 20;
const QUERY_KEY = "kratos-courier";

type CourierResponse = {
  rows: CourierMessage[];
  next_token: string | null;
  total: number;
};

type CourierMessage = {
  id: string;
  recipient?: string | null;
  subject?: string | null;
  body?: string | null;
  status?: string | null;
  type?: string | null;
  template_type?: string | null;
  send_count?: number | null;
  created_at?: string | null;
};

type StatusFilter = "all" | "queued" | "sent" | "processing" | "abandoned";

type Filters = {
  status: StatusFilter;
  recipient: string;
};

const EMPTY_FILTERS: Filters = { status: "all", recipient: "" };

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function StatusBadge({ status }: { status?: string | null }) {
  const s = (status ?? "").toLowerCase();
  if (s === "sent") {
    return (
      <Badge variant="secondary" className="text-[--success]">
        sent
      </Badge>
    );
  }
  if (s === "abandoned") {
    return (
      <Badge variant="secondary" className="text-destructive">
        abandoned
      </Badge>
    );
  }
  return <Badge variant="secondary">{s || "—"}</Badge>;
}

function CourierDetailDialog({ message }: { message: CourierMessage }) {
  const body = message.body ?? "";
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="View message details">
          <Eye />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Message details</DialogTitle>
        </DialogHeader>
        <div className="grid gap-2 text-sm">
          <DetailRow label="Recipient" value={message.recipient ?? "—"} mono />
          <DetailRow
            label="Type"
            value={message.type ?? message.template_type ?? "—"}
          />
          <DetailRow label="Status" value={message.status ?? "—"} />
          <DetailRow
            label="Send count"
            value={String(message.send_count ?? 0)}
          />
          <DetailRow label="Subject" value={message.subject ?? "—"} />
        </div>
        <div className="space-y-2">
          <Label>Message body</Label>
          <MonacoEditor
            language="plaintext"
            value={body}
            onChange={() => {}}
            readOnly
            height={280}
            ariaLabel="Courier message body (read-only)"
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono text-xs" : ""}>{value}</span>
    </div>
  );
}

export default function CourierPage() {
  const cursors = React.useRef<Map<number, string | null>>(
    new Map([[0, null]]),
  );
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);

  const filterKey = React.useMemo(() => JSON.stringify(applied), [applied]);

  const columns = React.useMemo<ColumnDef<CourierMessage>[]>(
    () => [
      {
        accessorKey: "recipient",
        header: "Recipient",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.recipient ?? "—"}
          </span>
        ),
      },
      {
        id: "type",
        header: "Type",
        cell: ({ row }) => (
          <span className="text-sm">
            {row.original.type ?? row.original.template_type ?? "—"}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        accessorKey: "send_count",
        header: "Send count",
        cell: ({ row }) => (
          <span className="text-sm">{row.original.send_count ?? 0}</span>
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
    ],
    [],
  );

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize }: FetchArgs): Promise<
      FetchResult<CourierMessage>
    > => {
      const token = cursors.current.get(pageIndex) ?? null;
      const qp = new URLSearchParams();
      qp.set("page_size", String(pageSize || PAGE_SIZE));
      if (token) qp.set("page_token", token);
      if (applied.status !== "all") qp.set("status", applied.status);
      if (applied.recipient) qp.set("recipient", applied.recipient.trim());

      const res = await api<CourierResponse>(
        `/api/kratos/courier/messages?${qp.toString()}`,
      );
      const rows = res.rows ?? [];

      const next = res.next_token?.trim() ? res.next_token : null;
      if (next) cursors.current.set(pageIndex + 1, next);

      const seen = pageIndex * (pageSize || PAGE_SIZE) + rows.length;
      const total = next ? seen + 1 : seen;
      return { rows, total };
    },
    [applied],
  );

  function applyFilters() {
    cursors.current = new Map([[0, null]]);
    setApplied(draft);
  }

  function clearFilters() {
    cursors.current = new Map([[0, null]]);
    setDraft(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Courier Messages
        </h1>
        <p className="text-sm text-muted-foreground">
          Browse the Kratos courier delivery log — email and SMS messages,
          filtered by status and recipient. This is a read-only record.
        </p>
      </div>

      <div className="space-y-3 rounded-md border p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="filter-status">Status</Label>
            <Select
              value={draft.status}
              onValueChange={(v) =>
                setDraft((d) => ({ ...d, status: v as StatusFilter }))
              }
            >
              <SelectTrigger id="filter-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="sent">Sent</SelectItem>
                <SelectItem value="processing">Processing</SelectItem>
                <SelectItem value="abandoned">Abandoned</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-recipient">Recipient</Label>
            <Input
              id="filter-recipient"
              className="font-mono text-xs"
              placeholder="e.g. user@example.com"
              value={draft.recipient}
              onChange={(e) =>
                setDraft((d) => ({ ...d, recipient: e.target.value }))
              }
            />
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

      <DataTable<CourierMessage>
        key={filterKey}
        columns={columns}
        fetcher={fetcher}
        queryKey={`${QUERY_KEY}:${filterKey}`}
        initialPageSize={PAGE_SIZE}
        caption="Kratos courier messages"
        rowActions={(row) => (
          <div className="flex items-center justify-end">
            <CourierDetailDialog message={row} />
          </div>
        )}
      />
    </div>
  );
}
