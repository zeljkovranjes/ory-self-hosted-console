"use client";

// OAUTH2-01 — the OAuth2 Clients list page (08-UI-SPEC §A).
//
// Composes the Phase-5 DataTable with a fetcher that calls
// GET /api/hydra/clients?page_size=&page_token= through lib/api.ts (the sole
// egress — no Ory host literal). Columns: Client ID (mono, click->detail), Name,
// Secret badge (set/not set), Grant types, Created. Toolbar: search + Create
// client. Row kebab: View / Edit / Rotate secret / Delete (Rotate + Delete gated
// behind their AlertDialogs).
//
// Cursor paging (08-RESEARCH Pitfall 2): Hydra uses an offset-style page_token in
// a Link header, surfaced by the backend as an opaque `next_token`. We map each
// forward pageIndex to the token returned for the previous page (ref-backed
// cursor map) + a +1 sentinel page while a next_token exists — the SAME shape the
// Users page uses for the Kratos keyset cursor (the token semantics are opaque).

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus } from "lucide-react";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  type OAuth2Client,
  type ClientListResponse,
  clientAuthMethod,
  clientLabel,
} from "../_lib/oauth2-types";
import { ClientSecretReveal } from "./client-secret-reveal";
import { DeleteClientDialog, RotateSecretDialog } from "./client-dialogs";

const PAGE_SIZE = 20;

const columns: ColumnDef<OAuth2Client>[] = [
  {
    accessorKey: "client_id",
    header: "Client ID",
    cell: ({ row }) => {
      const id = row.original.client_id ?? "";
      return (
        <Link
          href={`/oauth2/clients/${id}`}
          className="font-mono text-xs text-primary hover:underline"
          title={id}
        >
          {id.slice(0, 8)}…
        </Link>
      );
    },
  },
  {
    id: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="font-medium">{clientLabel(row.original)}</span>
    ),
  },
  {
    // WR-02: show the OBSERVABLE auth method, not an inferred "secret set"
    // claim (the backend masks the secret value — presence is unobservable).
    id: "auth_method",
    header: "Auth method",
    cell: ({ row }) => (
      <Badge variant="secondary" className="font-mono">
        {clientAuthMethod(row.original)}
      </Badge>
    ),
  },
  {
    id: "grant_types",
    header: "Grant types",
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {(row.original.grant_types ?? []).join(", ") || "—"}
      </span>
    ),
  },
  {
    accessorKey: "created_at",
    header: "Created",
    cell: ({ row }) =>
      row.original.created_at ? (
        <span className="text-sm text-muted-foreground">
          {new Date(row.original.created_at).toLocaleString()}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
  },
];

function RowActions({
  client,
  onRotated,
}: {
  client: OAuth2Client;
  onRotated: (secret: string, clientId: string) => void;
}) {
  const router = useRouter();
  const id = client.client_id ?? "";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Client actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => router.push(`/oauth2/clients/${id}`)}>
          View
        </DropdownMenuItem>
        <DropdownMenuItem
          onSelect={() => router.push(`/oauth2/clients/${id}/edit`)}
        >
          Edit
        </DropdownMenuItem>
        <RotateSecretDialog
          client={client}
          onRotated={(secret) => onRotated(secret, id)}
          trigger={
            <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
              Rotate secret
            </DropdownMenuItem>
          }
        />
        <DropdownMenuSeparator />
        <DeleteClientDialog
          clientId={id}
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

export default function OAuth2ClientsPage() {
  const cursors = React.useRef<Map<number, string | null>>(
    new Map([[0, null]]),
  );
  // The one-time secret surfaced after an in-list rotate.
  const [revealed, setRevealed] = React.useState<{
    secret: string;
    clientId: string;
  } | null>(null);

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize, filters }: FetchArgs): Promise<
      FetchResult<OAuth2Client>
    > => {
      const token = cursors.current.get(pageIndex) ?? null;
      const qp = new URLSearchParams();
      qp.set("page_size", String(pageSize || PAGE_SIZE));
      if (token) qp.set("page_token", token);

      const res = await api<ClientListResponse>(
        `/api/hydra/clients?${qp.toString()}`,
      );

      // Client-side filter by name/id (Hydra's list filter is name/owner exact;
      // we keep the search box responsive over the current page).
      const search = filters.find((f) => f.id === "name")?.value;
      let rows = res.rows;
      if (typeof search === "string" && search) {
        const q = search.toLowerCase();
        rows = rows.filter(
          (c) =>
            (c.client_name ?? "").toLowerCase().includes(q) ||
            (c.client_id ?? "").toLowerCase().includes(q),
        );
      }

      if (res.next_token) {
        cursors.current.set(pageIndex + 1, res.next_token);
      }
      const seen = pageIndex * (pageSize || PAGE_SIZE) + res.rows.length;
      const total = res.next_token ? seen + 1 : seen;
      return { rows, total };
    },
    [],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">OAuth2 Clients</h1>
        <p className="text-sm text-muted-foreground">
          Manage Hydra OAuth2 / OIDC clients — create, rotate secrets, and delete
          clients.
        </p>
      </div>

      <DataTable<OAuth2Client>
        columns={columns}
        fetcher={fetcher}
        queryKey="oauth2-clients"
        searchColumn="name"
        searchPlaceholder="Search by name or client ID…"
        initialPageSize={PAGE_SIZE}
        caption="Hydra OAuth2 clients"
        rowActions={(row) => (
          <RowActions
            client={row}
            onRotated={(secret, clientId) => setRevealed({ secret, clientId })}
          />
        )}
        toolbar={
          <Button asChild size="sm">
            <Link href="/oauth2/clients/new">
              <Plus />
              Create client
            </Link>
          </Button>
        }
        emptyCta={
          <Button asChild size="sm">
            <Link href="/oauth2/clients/new">Create client</Link>
          </Button>
        }
      />

      <ClientSecretReveal
        secret={revealed?.secret ?? null}
        clientId={revealed?.clientId}
        onDone={() => setRevealed(null)}
      />
    </div>
  );
}
