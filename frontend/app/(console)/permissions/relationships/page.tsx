"use client";

// PERM-02 / PERM-03 — the Relationships list page (09-UI-SPEC §A).
//
// Composes the Phase-5 DataTable in server mode exactly like the OAuth2 Clients
// page: a ref-backed cursor map maps each forward pageIndex to the opaque
// page_token Keto returned for the previous page, plus a +1 sentinel page while
// a next_page_token exists (Keto's token is empty-string on the last page). The
// fetcher builds a URLSearchParams with page_size, optional page_token, and the
// five server-side filters (namespace/object/relation/subject_id/subject_set).
//
// Columns: Namespace / Object / Relation / Subject (subject_id direct, or
// subject_set as ns:object#relation with a secondary Badge kind label), all
// font-mono text-xs. Create opens a dialog with the XOR-validated tuple form;
// each row carries a single named delete AlertDialog (exact-tuple DELETE).
//
// All egress via @/lib/api — no Ory host/port literal. (T-9-fe-egress)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus, Trash2 } from "lucide-react";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
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
  type RelationTuple,
  type RelationshipsResponse,
  subjectLabel,
} from "./types";
import { TupleForm } from "./tuple-form";
import { DeleteRelationshipDialog } from "./tuple-dialogs";

const PAGE_SIZE = 20;

// The five server-side filters (PERM-03). Empty values are omitted from the
// query so an empty filter set returns the unfiltered list.
type Filters = {
  namespace: string;
  object: string;
  relation: string;
  subject_id: string;
  subject_set: string;
};

const EMPTY_FILTERS: Filters = {
  namespace: "",
  object: "",
  relation: "",
  subject_id: "",
  subject_set: "",
};

const columns: ColumnDef<RelationTuple>[] = [
  {
    accessorKey: "namespace",
    header: "Namespace",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.namespace}</span>
    ),
  },
  {
    accessorKey: "object",
    header: "Object",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.object}</span>
    ),
  },
  {
    accessorKey: "relation",
    header: "Relation",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.relation}</span>
    ),
  },
  {
    id: "subject",
    header: "Subject",
    cell: ({ row }) => {
      const isSet = !row.original.subject_id && !!row.original.subject_set;
      return (
        <span className="flex items-center gap-2">
          <Badge variant="secondary">{isSet ? "set" : "id"}</Badge>
          <span className="font-mono text-xs">{subjectLabel(row.original)}</span>
        </span>
      );
    },
  },
];

function RowActions({ tuple }: { tuple: RelationTuple }) {
  return (
    <DeleteRelationshipDialog
      tuple={tuple}
      trigger={
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Delete relationship"
        >
          <Trash2 className="text-destructive" />
        </Button>
      }
    />
  );
}

export default function RelationshipsPage() {
  // Maps a forward pageIndex -> the opaque page_token to fetch it with. Page 0
  // uses no token; each fetched page records the token for the NEXT page.
  const cursors = React.useRef<Map<number, string | null>>(
    new Map([[0, null]]),
  );
  // Applied (committed) filters drive the query key; draft filters are the
  // editable input state until "Apply filters" commits them.
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);
  const [createOpen, setCreateOpen] = React.useState(false);

  // A stable key segment so changing filters re-keys the TanStack Query (and
  // resets the cursor map — a new filter set has its own token sequence).
  const filterKey = React.useMemo(() => JSON.stringify(applied), [applied]);

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize }: FetchArgs): Promise<
      FetchResult<RelationTuple>
    > => {
      const token = cursors.current.get(pageIndex) ?? null;
      const qp = new URLSearchParams();
      qp.set("page_size", String(pageSize || PAGE_SIZE));
      if (token) qp.set("page_token", token);
      if (applied.namespace) qp.set("namespace", applied.namespace);
      if (applied.object) qp.set("object", applied.object);
      if (applied.relation) qp.set("relation", applied.relation);
      if (applied.subject_id) qp.set("subject_id", applied.subject_id);
      // The subject-set filter accepts the ns:object#relation form and is split
      // into the three backend params; a malformed value simply matches nothing.
      if (applied.subject_set) {
        const m = applied.subject_set.match(/^([^:]+):(.+)#([^#]+)$/);
        if (m) {
          qp.set("subject_set_namespace", m[1]);
          qp.set("subject_set_object", m[2]);
          qp.set("subject_set_relation", m[3]);
        }
      }

      const res = await api<RelationshipsResponse>(
        `/api/keto/relationships?${qp.toString()}`,
      );
      const rows = res.relation_tuples ?? [];

      // Keto's next_page_token is empty-string on the last page; treat blank as
      // "no more pages".
      const next = res.next_page_token?.trim() ? res.next_page_token : null;
      if (next) cursors.current.set(pageIndex + 1, next);

      const seen = pageIndex * (pageSize || PAGE_SIZE) + rows.length;
      const total = next ? seen + 1 : seen;
      return { rows, total };
    },
    [applied],
  );

  function applyFilters() {
    // Reset the cursor map — a new filter set starts its own token sequence.
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
        <h1 className="text-2xl font-semibold tracking-tight">Relationships</h1>
        <p className="text-sm text-muted-foreground">
          Manage Keto relation tuples — create, search, and delete the
          relationships that back your permission model.
        </p>
      </div>

      {/* Server-side filter form (PERM-03). Layout mirrors the inspector grid. */}
      <div className="space-y-3 rounded-md border p-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <FilterField
            id="filter-namespace"
            label="Namespace"
            placeholder="e.g. documents"
            value={draft.namespace}
            onChange={(v) => setDraft((d) => ({ ...d, namespace: v }))}
          />
          <FilterField
            id="filter-object"
            label="Object"
            placeholder="e.g. doc:readme"
            value={draft.object}
            onChange={(v) => setDraft((d) => ({ ...d, object: v }))}
          />
          <FilterField
            id="filter-relation"
            label="Relation"
            placeholder="e.g. viewer"
            value={draft.relation}
            onChange={(v) => setDraft((d) => ({ ...d, relation: v }))}
          />
          <FilterField
            id="filter-subject-id"
            label="Subject ID"
            placeholder="e.g. user:alice"
            value={draft.subject_id}
            onChange={(v) => setDraft((d) => ({ ...d, subject_id: v }))}
          />
          <FilterField
            id="filter-subject-set"
            label="Subject set"
            placeholder="ns:object#relation"
            value={draft.subject_set}
            onChange={(v) => setDraft((d) => ({ ...d, subject_set: v }))}
          />
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

      <DataTable<RelationTuple>
        key={filterKey}
        columns={columns}
        fetcher={fetcher}
        queryKey={`keto-relationships:${filterKey}`}
        initialPageSize={PAGE_SIZE}
        caption="Keto relation tuples"
        rowActions={(row) => <RowActions tuple={row} />}
        toolbar={
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus />
                Create relationship
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Create relationship</DialogTitle>
              </DialogHeader>
              <TupleForm
                onCreated={() => setCreateOpen(false)}
                onCancel={() => setCreateOpen(false)}
              />
            </DialogContent>
          </Dialog>
        }
        emptyCta={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            Create relationship
          </Button>
        }
      />
    </div>
  );
}

function FilterField({
  id,
  label,
  placeholder,
  value,
  onChange,
}: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        className="font-mono text-xs"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
