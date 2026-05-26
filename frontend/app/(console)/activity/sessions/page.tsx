"use client";

// ACT-01 — the Sessions list page (10-UI-SPEC §A).
//
// Composes the Phase-5 DataTable in server mode exactly like the Phase-9
// Relationships page: a ref-backed cursor map maps each forward pageIndex to the
// opaque page_token the backend returned for the previous page (a +1 sentinel
// while a next_token exists). The fetcher builds a URLSearchParams with
// page_size, optional page_token, and the active filter, hitting the Kratos
// sessions wrapper through @/lib/api.
//
// Columns: Identity (deep-link to /users/{id} when known), State (Active/Inactive
// Badge), AAL, Issued / Expires / Authenticated-at. Each row carries a "View"
// detail Dialog (read-only Monaco JSON) and a Revoke AlertDialog (disable_session).
//
// All egress via @/lib/api — no Ory host/port literal. (bundle-egress gate)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, Trash2 } from "lucide-react";

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
import { RevokeSessionDialog } from "./revoke-dialog";

const PAGE_SIZE = 20;
const QUERY_KEY = "kratos-sessions";

// The list envelope the backend list_sessions handler returns.
type SessionsResponse = {
  rows: Session[];
  next_token: string | null;
  total: number;
};

// A Kratos session (the fields the table/detail use). The full object is shown
// read-only in the detail Monaco view; only a subset is typed here.
type Session = {
  id: string;
  active?: boolean;
  authenticator_assurance_level?: string | null;
  issued_at?: string | null;
  expires_at?: string | null;
  authenticated_at?: string | null;
  identity?: { id?: string; traits?: Record<string, unknown> } | null;
};

type StateFilter = "active" | "inactive" | "all";

type Filters = {
  active: StateFilter;
  identityId: string;
};

const EMPTY_FILTERS: Filters = { active: "all", identityId: "" };

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// Best-effort human label for a session's owning identity.
function identityLabel(s: Session): string {
  const t = s.identity?.traits;
  if (t) {
    const email = typeof t.email === "string" ? t.email : undefined;
    const username = typeof t.username === "string" ? t.username : undefined;
    if (email) return email;
    if (username) return username;
  }
  return s.identity?.id ?? "—";
}

function IdentityCell({ session }: { session: Session }) {
  const id = session.identity?.id;
  const label = identityLabel(session);
  if (id) {
    return (
      <a
        href={`/users/${id}`}
        className="font-mono text-xs text-primary hover:underline"
      >
        {label}
      </a>
    );
  }
  return <span className="font-mono text-xs">{label}</span>;
}

function StateBadge({ active }: { active?: boolean }) {
  return active ? (
    <Badge variant="secondary" className="text-[--success]">
      Active
    </Badge>
  ) : (
    <Badge variant="outline" className="text-muted-foreground">
      Inactive
    </Badge>
  );
}

function SessionDetailDialog({ session }: { session: Session }) {
  const raw = React.useMemo(() => JSON.stringify(session, null, 2), [session]);
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="View session details">
          <Eye />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Session details</DialogTitle>
        </DialogHeader>
        <div className="grid gap-2 text-sm">
          <DetailRow label="Identity" value={identityLabel(session)} mono />
          <DetailRow
            label="State"
            value={session.active ? "Active" : "Inactive"}
          />
          <DetailRow
            label="AAL"
            value={session.authenticator_assurance_level ?? "—"}
            mono
          />
          <DetailRow label="Issued" value={fmtTs(session.issued_at)} mono />
          <DetailRow label="Expires" value={fmtTs(session.expires_at)} mono />
          <DetailRow
            label="Authenticated at"
            value={fmtTs(session.authenticated_at)}
            mono
          />
        </div>
        <div className="space-y-2">
          <Label>Raw session</Label>
          <MonacoEditor
            language="json"
            value={raw}
            onChange={() => {}}
            readOnly
            height={280}
            ariaLabel="Session (read-only)"
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

export default function SessionsPage() {
  const queryClient = useQueryClient();
  const cursors = React.useRef<Map<number, string | null>>(
    new Map([[0, null]]),
  );
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);

  const filterKey = React.useMemo(() => JSON.stringify(applied), [applied]);

  // Invalidate every page of the sessions table (prefix-match the wrapped key).
  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({
      predicate: (q) =>
        Array.isArray(q.queryKey) &&
        typeof q.queryKey[0] === "string" &&
        (q.queryKey[0] as string).startsWith(QUERY_KEY),
    });
  }, [queryClient]);

  const columns = React.useMemo<ColumnDef<Session>[]>(
    () => [
      {
        id: "identity",
        header: "Identity",
        cell: ({ row }) => <IdentityCell session={row.original} />,
      },
      {
        id: "state",
        header: "State",
        cell: ({ row }) => <StateBadge active={row.original.active} />,
      },
      {
        accessorKey: "authenticator_assurance_level",
        header: "AAL",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.authenticator_assurance_level ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "issued_at",
        header: "Issued",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.issued_at)}
          </span>
        ),
      },
      {
        accessorKey: "expires_at",
        header: "Expires",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.expires_at)}
          </span>
        ),
      },
      {
        accessorKey: "authenticated_at",
        header: "Authenticated",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {fmtTs(row.original.authenticated_at)}
          </span>
        ),
      },
    ],
    [],
  );

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize }: FetchArgs): Promise<
      FetchResult<Session>
    > => {
      const token = cursors.current.get(pageIndex) ?? null;
      const qp = new URLSearchParams();
      qp.set("page_size", String(pageSize || PAGE_SIZE));
      if (token) qp.set("page_token", token);
      if (applied.active !== "all") qp.set("active", applied.active);
      // The identity-ID field is an advisory client filter; the backend list
      // wrapper does not filter by identity, so we apply it client-side below.

      const res = await api<SessionsResponse>(
        `/api/kratos/sessions?${qp.toString()}`,
      );
      let rows = res.rows ?? [];
      if (applied.identityId) {
        const needle = applied.identityId.trim().toLowerCase();
        rows = rows.filter((s) =>
          (s.identity?.id ?? "").toLowerCase().includes(needle),
        );
      }

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
        <h1 className="text-2xl font-semibold tracking-tight">Sessions</h1>
        <p className="text-sm text-muted-foreground">
          View active and inactive Kratos sessions, inspect a session&apos;s
          details, and revoke a session to sign the user out.
        </p>
      </div>

      <div className="space-y-3 rounded-md border p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="filter-state">State</Label>
            <Select
              value={draft.active}
              onValueChange={(v) =>
                setDraft((d) => ({ ...d, active: v as StateFilter }))
              }
            >
              <SelectTrigger id="filter-state">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
                <SelectItem value="all">All</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="filter-identity">Identity ID</Label>
            <Input
              id="filter-identity"
              className="font-mono text-xs"
              placeholder="identity ID"
              value={draft.identityId}
              onChange={(e) =>
                setDraft((d) => ({ ...d, identityId: e.target.value }))
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

      <DataTable<Session>
        key={filterKey}
        columns={columns}
        fetcher={fetcher}
        queryKey={`${QUERY_KEY}:${filterKey}`}
        initialPageSize={PAGE_SIZE}
        caption="Kratos sessions"
        rowActions={(row) => (
          <div className="flex items-center justify-end gap-1">
            <SessionDetailDialog session={row} />
            <RevokeSessionDialog
              sessionId={row.id}
              contextLabel={identityLabel(row)}
              onRevoked={invalidate}
              trigger={
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Revoke session"
                >
                  <Trash2 className="text-destructive" />
                </Button>
              }
            />
          </div>
        )}
      />
    </div>
  );
}
