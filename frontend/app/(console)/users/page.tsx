"use client";

// IDENT-01 — the Users list page (UI-SPEC §1).
//
// Composes the Phase-5 DataTable with a fetcher that calls
// GET /api/kratos/identities?page_size=&page_token= through lib/api.ts (the sole
// egress — no Ory host literal). Columns: ID (mono, click->detail), Identifier
// (from traits), State badge, Created. Toolbar: search by identifier + header
// actions (Create / Import / Edit schema). Row kebab: View / Edit / Delete
// (delete is gated behind the destructive AlertDialog).
//
// Cursor paging (06-RESEARCH Pitfall 3): Kratos uses a keyset Link-header cursor
// exposed by the backend as `next_token`. The DataTable lifts a zero-based
// pageIndex; we map each forward step to the token returned for the previous
// page (kept in a ref-backed cursor map) so Next/Prev work without a server
// offset. `total` is reported so the table can enable Next while a next_token
// exists (we report a +1 sentinel page when more data remains).

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ColumnDef } from "@tanstack/react-table";
import { MoreHorizontal, Plus, Upload, FileCode2 } from "lucide-react";

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
  type Identity,
  type IdentityListResponse,
  identityIdentifier,
} from "./identity-types";
import { DeleteIdentityDialog } from "./delete-identity-dialog";

const PAGE_SIZE = 20;

const columns: ColumnDef<Identity>[] = [
  {
    accessorKey: "id",
    header: "ID",
    cell: ({ row }) => (
      <Link
        href={`/users/${row.original.id}`}
        className="font-mono text-xs text-primary hover:underline"
        title={row.original.id}
      >
        {row.original.id.slice(0, 8)}…
      </Link>
    ),
  },
  {
    id: "identifier",
    header: "Identifier",
    cell: ({ row }) => (
      <span className="font-medium">{identityIdentifier(row.original)}</span>
    ),
  },
  {
    accessorKey: "state",
    header: "State",
    cell: ({ row }) => {
      const active = row.original.state === "active";
      return (
        <Badge variant={active ? "default" : "secondary"}>
          {row.original.state || "unknown"}
        </Badge>
      );
    },
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

function RowActions({ identity }: { identity: Identity }) {
  const router = useRouter();
  const identifier = identityIdentifier(identity);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Open actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => router.push(`/users/${identity.id}`)}>
          View
        </DropdownMenuItem>
        <DropdownMenuItem
          onSelect={() => router.push(`/users/${identity.id}/edit`)}
        >
          Edit
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DeleteIdentityDialog
          id={identity.id}
          identifier={identifier}
          trigger={
            <DropdownMenuItem
              variant="destructive"
              // Keep the menu's Radix select from closing the dialog trigger.
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

export default function UsersPage() {
  // Cursor map: pageIndex -> page_token used to fetch THAT page. Page 0 has no
  // token. We populate index+1 with the next_token the backend returns.
  const cursors = React.useRef<Map<number, string | null>>(
    new Map([[0, null]]),
  );

  const fetcher = React.useCallback(
    async ({ pageIndex, pageSize, filters }: FetchArgs): Promise<
      FetchResult<Identity>
    > => {
      const token = cursors.current.get(pageIndex) ?? null;
      const qp = new URLSearchParams();
      qp.set("page_size", String(pageSize || PAGE_SIZE));
      if (token) qp.set("page_token", token);
      const search = filters.find((f) => f.id === "identifier")?.value;
      if (typeof search === "string" && search) qp.set("credentials_identifier", search);

      const res = await api<IdentityListResponse>(
        `/api/kratos/identities?${qp.toString()}`,
      );

      // Remember the cursor for the next page so Next can advance.
      if (res.next_token) {
        cursors.current.set(pageIndex + 1, res.next_token);
      }
      // While a next_token exists there is at least one more page: report a +1
      // sentinel so the table keeps Next enabled; otherwise the known count.
      const seen = pageIndex * (pageSize || PAGE_SIZE) + res.rows.length;
      const total = res.next_token ? seen + 1 : seen;
      return { rows: res.rows, total };
    },
    [],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
        <p className="text-sm text-muted-foreground">
          Manage Kratos identities — create, edit, and delete users.
        </p>
      </div>

      <DataTable<Identity>
        columns={columns}
        fetcher={fetcher}
        queryKey="identities"
        searchColumn="identifier"
        searchPlaceholder="Search by identifier…"
        initialPageSize={PAGE_SIZE}
        caption="Kratos identities"
        rowActions={(row) => <RowActions identity={row} />}
        toolbar={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href="/users/schema">
                <FileCode2 />
                Edit schema
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link href="/users/import">
                <Upload />
                Import
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/users/new">
                <Plus />
                Create identity
              </Link>
            </Button>
          </>
        }
        emptyCta={
          <Button asChild size="sm">
            <Link href="/users/new">Create identity</Link>
          </Button>
        }
      />
    </div>
  );
}
