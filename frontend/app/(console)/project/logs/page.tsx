"use client";

// ACT-04 — the Logs & events (audit log) read-only view (11-UI-SPEC §C).
//
// Composes the Phase-5 DataTable in server mode against GET /api/console/audit
// (the append-only console_audit_log). READ-ONLY — there is NO create/edit/
// delete affordance anywhere on this surface. A filter block (actor / action /
// outcome / date range) re-queries server-side; each row opens a Dialog with the
// full record incl. the metadata jsonb in a read-only Monaco language="json"
// block.
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

const QUERY_KEY = "console-audit";

// The secret-free AuditView returned by GET /api/console/audit.
type AuditView = {
  id: string;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  method: string | null;
  path: string | null;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  metadata: unknown | null;
  created_at: string;
};

type OutcomeFilter = "all" | "success" | "failure";

type Filters = {
  actorId: string;
  action: string;
  outcome: OutcomeFilter;
  after: string; // datetime-local value
  before: string;
};

const EMPTY_FILTERS: Filters = {
  actorId: "",
  action: "",
  outcome: "all",
  after: "",
  before: "",
};

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// Convert a `datetime-local` value (no timezone) to an RFC3339 string the
// backend's `after`/`before` params parse, or null when empty/invalid.
function toRfc3339(local: string): string | null {
  if (!local) return null;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  const o = (outcome ?? "").toLowerCase();
  if (o === "success") {
    return (
      <Badge variant="secondary" className="text-[--success]">
        success
      </Badge>
    );
  }
  if (o === "failure" || o === "denied") {
    return (
      <Badge variant="secondary" className="text-destructive">
        {o}
      </Badge>
    );
  }
  return <Badge variant="secondary">{o || "—"}</Badge>;
}

function AuditDetailDialog({ row }: { row: AuditView }) {
  const metadata = React.useMemo(
    () => JSON.stringify(row.metadata ?? {}, null, 2),
    [row.metadata],
  );
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="View audit event">
          <Eye />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Audit event</DialogTitle>
        </DialogHeader>
        <div className="grid gap-2 text-sm">
          <DetailRow label="When" value={fmtTs(row.created_at)} mono />
          <DetailRow
            label="Actor"
            value={row.actor_email ?? row.actor_id ?? "—"}
            mono
          />
          <DetailRow label="Action" value={row.action} />
          <DetailRow label="Method" value={row.method ?? "—"} mono />
          <DetailRow label="Path" value={row.path ?? "—"} mono />
          <DetailRow
            label="Target"
            value={
              row.target_type || row.target_id
                ? `${row.target_type ?? ""} ${row.target_id ?? ""}`.trim()
                : "—"
            }
            mono
          />
          <DetailRow label="Outcome" value={row.outcome} />
        </div>
        <div className="space-y-2">
          <Label>Metadata</Label>
          <MonacoEditor
            language="json"
            value={metadata}
            onChange={() => {}}
            readOnly
            height={280}
            ariaLabel="Audit metadata (read-only)"
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
      <span className={mono ? "font-mono text-xs break-all" : ""}>{value}</span>
    </div>
  );
}

export default function LogsPage() {
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);

  const filterKey = React.useMemo(() => JSON.stringify(applied), [applied]);

  const columns = React.useMemo<ColumnDef<AuditView>[]>(
    () => [
      {
        accessorKey: "created_at",
        header: "When",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{fmtTs(row.original.created_at)}</span>
        ),
      },
      {
        id: "actor",
        header: "Actor",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.actor_email ?? row.original.actor_id ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "action",
        header: "Action",
        cell: ({ row }) => (
          <span className="text-sm">{row.original.action}</span>
        ),
      },
      {
        id: "target",
        header: "Target",
        cell: ({ row }) => {
          const t = row.original;
          const label =
            t.target_type || t.target_id
              ? `${t.target_type ?? ""} ${t.target_id ?? ""}`.trim()
              : "—";
          return <span className="font-mono text-xs">{label}</span>;
        },
      },
      {
        id: "outcome",
        header: "Outcome",
        cell: ({ row }) => <OutcomeBadge outcome={row.original.outcome} />,
      },
    ],
    [],
  );

  const fetcher = React.useCallback(
    async (_args: FetchArgs): Promise<FetchResult<AuditView>> => {
      const qp = new URLSearchParams();
      if (applied.actorId.trim()) qp.set("actor_id", applied.actorId.trim());
      if (applied.action.trim()) qp.set("action", applied.action.trim());
      if (applied.outcome !== "all") qp.set("outcome", applied.outcome);
      const after = toRfc3339(applied.after);
      const before = toRfc3339(applied.before);
      if (after) qp.set("after", after);
      if (before) qp.set("before", before);

      const q = qp.toString();
      const rows = await api<AuditView[]>(
        `/api/console/audit${q ? `?${q}` : ""}`,
      );
      return { rows, total: rows.length };
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
        <h1 className="text-2xl font-semibold tracking-tight">Logs &amp; events</h1>
        <p className="text-sm text-muted-foreground">
          An append-only audit log of console-initiated admin actions — who did
          what, when, and the outcome. This records console operations only.
        </p>
      </div>

      <div className="space-y-3 rounded-md border p-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="grid gap-2">
            <Label htmlFor="filter-actor">Actor (ID)</Label>
            <Input
              id="filter-actor"
              className="font-mono text-xs"
              placeholder="operator account ID"
              value={draft.actorId}
              onChange={(e) =>
                setDraft((d) => ({ ...d, actorId: e.target.value }))
              }
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-action">Action</Label>
            <Input
              id="filter-action"
              placeholder="e.g. DELETE /api/hydra/clients"
              value={draft.action}
              onChange={(e) =>
                setDraft((d) => ({ ...d, action: e.target.value }))
              }
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-outcome">Outcome</Label>
            <Select
              value={draft.outcome}
              onValueChange={(v) =>
                setDraft((d) => ({ ...d, outcome: v as OutcomeFilter }))
              }
            >
              <SelectTrigger id="filter-outcome">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="success">success</SelectItem>
                <SelectItem value="failure">failure</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-after">After</Label>
            <Input
              id="filter-after"
              type="datetime-local"
              value={draft.after}
              onChange={(e) =>
                setDraft((d) => ({ ...d, after: e.target.value }))
              }
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-before">Before</Label>
            <Input
              id="filter-before"
              type="datetime-local"
              value={draft.before}
              onChange={(e) =>
                setDraft((d) => ({ ...d, before: e.target.value }))
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

      <DataTable<AuditView>
        key={filterKey}
        columns={columns}
        fetcher={fetcher}
        queryKey={`${QUERY_KEY}:${filterKey}`}
        caption="Console audit log"
        rowActions={(row) => (
          <div className="flex items-center justify-end">
            <AuditDetailDialog row={row} />
          </div>
        )}
      />
    </div>
  );
}
