"use client";

// PROJ-04 — the Members (console-operator) list page (11-UI-SPEC §F).
//
// Lists the console OPERATOR accounts (the /setup local admin + any linked
// GitHub accounts) from GET /api/console/members through @/lib/api. These are
// CONSOLE accounts, not Ory identities — a persistent framing line makes that
// explicit and links to /users for end-user management. List-only v1 (the
// backend ships list-only): there is NO add/remove form — never a disabled
// phantom CRUD.
//
// All egress via @/lib/api — no Ory host/port literal. (bundle-egress gate)

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { api } from "@/lib/api";
import type { FetchArgs, FetchResult } from "@/lib/table-types";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";

const QUERY_KEY = "console-members";

// The secret-free MemberView returned by GET /api/console/members.
type MemberView = {
  id: string;
  email: string;
  name: string;
  account_type: string; // "Local admin" | "GitHub" | "Unknown"
  created_at: string;
  last_login_at: string | null;
};

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

const columns: ColumnDef<MemberView>[] = [
  {
    accessorKey: "email",
    header: "Email",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.email}</span>
    ),
  },
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="text-sm">{row.original.name || "—"}</span>
    ),
  },
  {
    id: "account_type",
    header: "Account type",
    cell: ({ row }) => (
      <Badge variant="secondary">{row.original.account_type}</Badge>
    ),
  },
  {
    accessorKey: "created_at",
    header: "Added",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{fmtTs(row.original.created_at)}</span>
    ),
  },
  {
    accessorKey: "last_login_at",
    header: "Last sign-in",
    cell: ({ row }) => (
      <span className="font-mono text-xs">
        {fmtTs(row.original.last_login_at)}
      </span>
    ),
  },
];

export default function MembersPage() {
  const fetcher = React.useCallback(
    async (_args: FetchArgs): Promise<FetchResult<MemberView>> => {
      const rows = await api<MemberView[]>("/api/console/members");
      return { rows, total: rows.length };
    },
    [],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Members</h1>
        <p className="text-sm text-muted-foreground">
          The console operator accounts that can sign in to this console. These
          are console accounts, not Ory identities — managing end users is done
          under Users.
        </p>
      </div>

      <p className="text-sm text-muted-foreground">
        Console accounts, not Ory identities. To manage end users, go to{" "}
        <a href="/users" className="text-primary hover:underline">
          Users
        </a>
        .
      </p>

      <DataTable<MemberView>
        columns={columns}
        fetcher={fetcher}
        queryKey={QUERY_KEY}
        caption="Console operator accounts"
      />
    </div>
  );
}
