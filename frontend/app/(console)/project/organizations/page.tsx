"use client";

// SSO-05/06/07 — the Organizations CRUD page (Phase 14 frontend).
//
// The Phase-12 FeatureGate shell is now the REAL feature body: gated on the
// "organizations" flag (OFF → the neutral disabled state rendered by FeatureGate;
// ON → the CRUD below). There is NO licensing/upsell copy anywhere (SSO-07) —
// the feature is simply on or off.
//
// Composes the Phase-5 DataTable: a fetcher calls GET /api/organizations through
// @/lib/api (the sole egress — no Ory host literal). The backend returns a plain
// array of OrgViews (label + normalized domains + linked SSO connection tenant).
//
// Create is hosted in a Dialog (the OrganizationForm). A domain-collision (409)
// or invalid-domain (422) is surfaced VERBATIM by the form, never collapsed into
// success (T-14-12). Delete is an AlertDialog. The login-time routing UI is
// Phase 15 — this page is org management only.

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus } from "lucide-react";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { FeatureGate } from "@/components/feature-gate";
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
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { type Organization, ORGANIZATIONS_QUERY_KEY } from "./types";
import { OrganizationForm } from "./organization-form";
import { DeleteOrganizationDialog } from "./organization-dialogs";

const PAGE_SIZE = 20;

function RowActions({ org }: { org: Organization }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Organization actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DeleteOrganizationDialog
          orgId={org.id}
          label={org.label}
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

const columns: ColumnDef<Organization>[] = [
  {
    accessorKey: "label",
    header: "Label",
    cell: ({ row }) => <span className="font-medium">{row.original.label}</span>,
  },
  {
    id: "domains",
    header: "Verified domains",
    cell: ({ row }) => {
      const domains = row.original.domains ?? [];
      if (!domains.length)
        return <span className="text-muted-foreground">—</span>;
      const shown = domains.slice(0, 3);
      const extra = domains.length - shown.length;
      return (
        <div className="flex flex-wrap gap-1">
          {shown.map((d) => (
            <Badge key={d} variant="outline" className="font-mono text-xs">
              {d}
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
    id: "connection",
    header: "Linked SSO connection",
    cell: ({ row }) =>
      row.original.sso_connection_tenant ? (
        <Badge variant="secondary" className="font-mono text-xs">
          {row.original.sso_connection_tenant}
        </Badge>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
  },
];

function OrganizationsBody() {
  const queryClient = useQueryClient();
  const [creating, setCreating] = React.useState(false);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: [ORGANIZATIONS_QUERY_KEY],
    });
  }, [queryClient]);

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize, filters }: FetchArgs): Promise<
      FetchResult<Organization>
    > => {
      const all = await api<Organization[]>("/api/organizations");
      let rows = all ?? [];

      const search = filters.find((f) => f.id === "label")?.value;
      if (typeof search === "string" && search) {
        const q = search.toLowerCase();
        rows = rows.filter(
          (o) =>
            o.label.toLowerCase().includes(q) ||
            (o.domains ?? []).some((d) => d.toLowerCase().includes(q)),
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
        <h1 className="text-2xl font-semibold tracking-tight">Organizations</h1>
        <p className="text-sm text-muted-foreground">
          Group users by their email domain and route an organization&apos;s
          sign-ins through a linked SAML connection. Each verified domain belongs
          to exactly one organization.
        </p>
      </div>

      <DataTable<Organization>
        columns={columns}
        fetcher={fetcher}
        queryKey={ORGANIZATIONS_QUERY_KEY}
        searchColumn="label"
        searchPlaceholder="Search by label or domain…"
        initialPageSize={PAGE_SIZE}
        caption="Organizations"
        rowActions={(row) => <RowActions org={row} />}
        toolbar={
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus />
            Create organization
          </Button>
        }
        emptyCta={
          <Button size="sm" onClick={() => setCreating(true)}>
            Create organization
          </Button>
        }
      />

      <Dialog
        open={creating}
        onOpenChange={(open) => {
          if (!open) setCreating(false);
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create organization</DialogTitle>
          </DialogHeader>
          <OrganizationForm
            onCancel={() => setCreating(false)}
            onCreated={() => {
              setCreating(false);
              invalidate();
            }}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function OrganizationsPage() {
  return (
    <FeatureGate flag="organizations" title="Organizations">
      <OrganizationsBody />
    </FeatureGate>
  );
}
