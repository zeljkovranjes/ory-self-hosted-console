"use client";

// SSO-02/03/04/07 — the SAML Sign-In connection CRUD page (Phase 14 frontend).
//
// The Phase-12 FeatureGate shell is now the REAL feature body: gated on the
// "saml" flag (OFF → the neutral disabled state rendered by FeatureGate; ON →
// the connection CRUD below). There is NO "requires Enterprise License" /
// "requires Ory" copy anywhere — the feature is simply on or off.
//
// Composes the Phase-5 DataTable: a fetcher calls GET /api/sso/connections?tenant=
// through @/lib/api (the sole egress — no Polis/Ory host literal). The backend
// list endpoint is per-tenant (there is no "list all" route — a connection's
// tenant IS its id), so the page aggregates over the tenants this console has
// created (a browser-local registry, see types.ts). Each list item has its
// clientSecret STRIPPED by the backend; the page renders ONLY the masked
// `clientSecret_set` badge echoed verbatim from the response (T-14-11).
//
// Create is hosted in a Dialog (the ConnectionForm). The clientSecret is
// write-only end-to-end — Polis mints it into the Kratos provider, the create
// response never returns it, so there is no reveal here. A 422 (CA-missing /
// SSRF reject) is surfaced VERBATIM by the form, never collapsed into success
// (T-14-12). Delete is a two-sided AlertDialog.

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus } from "lucide-react";

import { api, ApiError } from "@/lib/api";
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
import {
  type ConnectionListResponse,
  type SamlConnection,
  readTenantRegistry,
  rememberTenant,
  SAML_CONNECTIONS_QUERY_KEY,
} from "./types";
import { ConnectionForm } from "./connection-form";
import { DeleteConnectionDialog } from "./connection-dialogs";

const PAGE_SIZE = 20;

function RowActions({ connection }: { connection: SamlConnection }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Connection actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DeleteConnectionDialog
          tenant={connection.tenant}
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

const columns: ColumnDef<SamlConnection>[] = [
  {
    accessorKey: "tenant",
    header: "Connection",
    cell: ({ row }) => (
      <span className="font-medium">
        {row.original.name || row.original.tenant}
      </span>
    ),
  },
  {
    id: "entityID",
    header: "Entity ID",
    cell: ({ row }) => {
      const id = row.original.idpMetadata?.entityID ?? "";
      return id ? (
        <span className="font-mono text-xs" title={id}>
          {id.length > 40 ? `${id.slice(0, 40)}…` : id}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      );
    },
  },
  {
    id: "provider",
    header: "Provider",
    cell: ({ row }) => {
      const p = row.original.idpMetadata?.provider;
      return p ? (
        <Badge variant="outline" className="font-mono text-xs">
          {p}
        </Badge>
      ) : (
        <span className="text-muted-foreground">—</span>
      );
    },
  },
  {
    id: "thumbprint",
    header: "Cert thumbprint",
    cell: ({ row }) => {
      const t = row.original.idpMetadata?.thumbprint ?? "";
      return t ? (
        <span className="font-mono text-xs" title={t}>
          {t.length > 16 ? `${t.slice(0, 16)}…` : t}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      );
    },
  },
  {
    id: "secret",
    header: "Client secret",
    // The secret VALUE is never present — render ONLY the masked presence badge
    // echoed from the backend (clientSecret_set). Never a hardcoded sentinel.
    cell: ({ row }) =>
      row.original.clientSecret_set ? (
        <Badge variant="secondary">Set</Badge>
      ) : (
        <Badge variant="outline" className="text-muted-foreground">
          Not set
        </Badge>
      ),
  },
];

function SamlConnectionsBody() {
  const queryClient = useQueryClient();
  const [creating, setCreating] = React.useState(false);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: [SAML_CONNECTIONS_QUERY_KEY],
    });
  }, [queryClient]);

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize, filters }: FetchArgs): Promise<
      FetchResult<SamlConnection>
    > => {
      // The backend lists per-tenant only. Fan out over the locally-remembered
      // tenants and merge. A 404 for a tenant (e.g. deleted out-of-band) is
      // swallowed so the rest of the list still renders.
      const tenants = readTenantRegistry();
      const results = await Promise.all(
        tenants.map(async (tenant) => {
          try {
            const res = await api<ConnectionListResponse>(
              `/api/sso/connections?tenant=${encodeURIComponent(tenant)}`,
            );
            return (res.connections ?? []).map((c) => ({
              ...c,
              tenant: c.tenant || tenant,
            }));
          } catch (e) {
            if (e instanceof ApiError && e.status === 404) return [];
            throw e;
          }
        }),
      );
      let rows = results.flat();

      const search = filters.find((f) => f.id === "tenant")?.value;
      if (typeof search === "string" && search) {
        const q = search.toLowerCase();
        rows = rows.filter(
          (c) =>
            c.tenant.toLowerCase().includes(q) ||
            (c.name ?? "").toLowerCase().includes(q) ||
            (c.idpMetadata?.entityID ?? "").toLowerCase().includes(q),
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
        <h1 className="text-2xl font-semibold tracking-tight">SAML Sign-In</h1>
        <p className="text-sm text-muted-foreground">
          Connect external SAML identity providers. Upload the IdP metadata
          (which must include a signing certificate) and the console provisions a
          sign-in connection. Link a connection to an organization to route that
          organization&apos;s sign-ins through its IdP.
        </p>
      </div>

      <DataTable<SamlConnection>
        columns={columns}
        fetcher={fetcher}
        queryKey={SAML_CONNECTIONS_QUERY_KEY}
        searchColumn="tenant"
        searchPlaceholder="Search by connection, label, or entity ID…"
        initialPageSize={PAGE_SIZE}
        caption="SAML connections"
        rowActions={(row) => <RowActions connection={row} />}
        toolbar={
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus />
            Create connection
          </Button>
        }
        emptyCta={
          <Button size="sm" onClick={() => setCreating(true)}>
            Create connection
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
            <DialogTitle>Create SAML connection</DialogTitle>
          </DialogHeader>
          <ConnectionForm
            onCancel={() => setCreating(false)}
            onCreated={(created) => {
              setCreating(false);
              // Remember the tenant so the list can fetch it back.
              if (created.tenant) rememberTenant(created.tenant);
              invalidate();
            }}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function SamlSignInPage() {
  return (
    <FeatureGate flag="saml" title="SAML Sign-In">
      <SamlConnectionsBody />
    </FeatureGate>
  );
}
