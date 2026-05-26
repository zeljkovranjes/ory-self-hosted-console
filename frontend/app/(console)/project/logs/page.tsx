"use client";

// ACT-04 + OBS-04 — the Logs & events surface.
//
// TWO distinct sources on one page, presented as tabs:
//   1. "Console audit" (ACT-04, unchanged): the append-only console_audit_log —
//      a READ-ONLY DataTable of console-initiated admin actions (who/what/when/
//      outcome) with a filter block + a Monaco metadata detail dialog. This is
//      NOT gated — it is always available, distinct from container logs.
//   2. "Container logs" (OBS-04): the Loki-backed search of the self-hosted
//      stack's container logs, gated by <FeatureGate flag="observability">. When
//      the flag is ON but the profile is DOWN, the backend returns the tolerant
//      `profile_not_running` state and we render <ProfileNotRunning /> — never a
//      raw error. The frontend sends only a CLOSED intent (+ allowlisted
//      service), never raw LogQL. Lines are PII-masked at ingestion (Alloy).
//
// All egress via @/lib/api — no Ory/Loki host literal. (bundle-egress gate)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";

import { api } from "@/lib/api";
import {
  isProfileNotRunning,
  lokiLines,
  useLogs,
  LOG_SERVICES,
  type LogFilters,
  type LogIntent,
  type LogService,
  type ObservabilityEnvelope,
} from "@/lib/observability";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { FeatureGate } from "@/components/feature-gate";
import { ProfileNotRunning } from "@/components/profile-not-running";
import { MonacoEditor } from "@/components/monaco-editor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

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

// Loki timestamps are nanosecond UNIX strings — convert to a locale string.
function fmtNanos(ns: string): string {
  const ms = Number(ns) / 1_000_000;
  if (!Number.isFinite(ms)) return ns;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? ns : d.toLocaleString();
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

// --- Console audit (ACT-04) --------------------------------------------------

function AuditLog() {
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
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        An append-only audit log of console-initiated admin actions — who did
        what, when, and the outcome. This records console operations only.
      </p>

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

// --- Container logs (OBS-04, Loki) ------------------------------------------

const LOG_INTENTS: { value: LogIntent; label: string }[] = [
  { value: "all", label: "All logs" },
  { value: "errors", label: "Errors only" },
  { value: "service", label: "By service" },
];

function ContainerLogs() {
  const [filters, setFilters] = React.useState<LogFilters>({ intent: "all" });
  const { data, isLoading, refetch } = useLogs(filters);
  const envelope = data as ObservabilityEnvelope | undefined;
  const lines = React.useMemo(() => lokiLines(envelope), [envelope]);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Container logs from the self-hosted stack, searched through Loki. Lines
        are PII-masked at ingestion.
      </p>

      <div className="flex flex-wrap items-end gap-4 rounded-md border p-4">
        <div className="grid gap-2">
          <Label htmlFor="log-intent">View</Label>
          <Select
            value={filters.intent}
            onValueChange={(v) =>
              setFilters((f) => ({
                intent: v as LogIntent,
                service: v === "service" ? (f.service ?? "backend") : undefined,
              }))
            }
          >
            <SelectTrigger id="log-intent" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {LOG_INTENTS.map((i) => (
                <SelectItem key={i.value} value={i.value}>
                  {i.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {filters.intent === "service" ? (
          <div className="grid gap-2">
            <Label htmlFor="log-service">Service</Label>
            <Select
              value={filters.service ?? "backend"}
              onValueChange={(v) =>
                setFilters((f) => ({ ...f, service: v as LogService }))
              }
            >
              <SelectTrigger id="log-service" className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOG_SERVICES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        ) : null}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      ) : isProfileNotRunning(envelope) ? (
        <ProfileNotRunning surface="logs" onRetry={() => void refetch()} />
      ) : lines.length === 0 ? (
        <div className="rounded-md border py-8 text-center text-sm text-muted-foreground">
          No log lines in the current window.
        </div>
      ) : (
        <ul className="divide-y rounded-md border font-mono text-xs">
          {lines.map((l, i) => (
            <li key={`${l.ts}-${i}`} className="flex gap-3 px-3 py-1.5">
              <span className="shrink-0 text-muted-foreground">
                {fmtNanos(l.ts)}
              </span>
              {l.labels.service ? (
                <Badge variant="secondary" className="shrink-0">
                  {l.labels.service}
                </Badge>
              ) : null}
              <span className="break-all">{l.line}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function LogsPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Logs &amp; events</h1>
        <p className="text-sm text-muted-foreground">
          The console audit trail plus the self-hosted stack&apos;s container
          logs.
        </p>
      </div>

      <Tabs defaultValue="audit">
        <TabsList>
          <TabsTrigger value="audit">Console audit</TabsTrigger>
          <TabsTrigger value="container">Container logs</TabsTrigger>
        </TabsList>
        <TabsContent value="audit">
          <AuditLog />
        </TabsContent>
        <TabsContent value="container">
          <FeatureGate flag="observability" title="Container logs">
            <ContainerLogs />
          </FeatureGate>
        </TabsContent>
      </Tabs>
    </div>
  );
}
