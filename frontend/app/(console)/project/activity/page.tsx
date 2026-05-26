"use client";

// ACT-03 — the derived recent-activity stub (11-UI-SPEC §E).
//
// A thin, READ-ONLY v1 view, CLEARLY labeled "derived recent activity (v1)" in
// the description. Fetches GET /api/activity through @/lib/api — the backend
// folds recent Kratos sessions (authentications) + recent courier messages
// (sends) into one {source:"derived", version:"v1", items:[{kind, detail}]}
// envelope (NO new persistence). Each row renders an icon + a one-line who/what
// label + a font-mono timestamp; identity references deep-link to /users/{id}
// where feasible. There is NO phantom "coming soon" CRUD.
//
// All egress via @/lib/api — no Ory host/port literal. (bundle-egress gate)

import { useQuery } from "@tanstack/react-query";
import { LogIn, Send } from "lucide-react";

import { api } from "@/lib/api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

const QUERY_KEY = "project-activity";

type ActivityEntry = {
  kind: "authentication" | "courier" | string;
  detail: Record<string, unknown>;
};

type ActivityEnvelope = {
  source: string;
  version: string;
  items: ActivityEntry[];
};

function fmtTs(ts?: unknown): string {
  if (typeof ts !== "string" || !ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// Pull a best-effort identity label + id out of a derived session detail.
function sessionIdentity(detail: Record<string, unknown>): {
  label: string;
  id?: string;
} {
  const identity = detail.identity as
    | { id?: string; traits?: Record<string, unknown> }
    | undefined;
  const traits = identity?.traits;
  const email = typeof traits?.email === "string" ? traits.email : undefined;
  const username =
    typeof traits?.username === "string" ? traits.username : undefined;
  return { label: email ?? username ?? identity?.id ?? "an identity", id: identity?.id };
}

// One activity row: an icon, a one-line label, and a timestamp.
function ActivityRow({ entry }: { entry: ActivityEntry }) {
  const d = entry.detail;
  if (entry.kind === "authentication") {
    const { label, id } = sessionIdentity(d);
    const ts = d.authenticated_at ?? d.issued_at;
    return (
      <li className="flex items-center justify-between gap-3 rounded-md border p-3">
        <span className="flex min-w-0 items-center gap-2 text-sm">
          <LogIn className="size-4 shrink-0 text-muted-foreground" />
          <span className="truncate">
            Session for{" "}
            {id ? (
              <a
                href={`/users/${id}`}
                className="text-primary hover:underline"
              >
                {label}
              </a>
            ) : (
              <span className="font-medium">{label}</span>
            )}
          </span>
        </span>
        <span className="shrink-0 font-mono text-xs text-muted-foreground">
          {fmtTs(ts)}
        </span>
      </li>
    );
  }
  // courier
  const recipient =
    typeof d.recipient === "string" ? d.recipient : "a recipient";
  const type =
    typeof d.type === "string"
      ? d.type
      : typeof d.template_type === "string"
        ? d.template_type
        : "message";
  return (
    <li className="flex items-center justify-between gap-3 rounded-md border p-3">
      <span className="flex min-w-0 items-center gap-2 text-sm">
        <Send className="size-4 shrink-0 text-muted-foreground" />
        <span className="truncate">
          Courier {type} to <span className="font-mono text-xs">{recipient}</span>
        </span>
      </span>
      <span className="shrink-0 font-mono text-xs text-muted-foreground">
        {fmtTs(d.created_at)}
      </span>
    </li>
  );
}

export default function ActivityPage() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: [QUERY_KEY],
    queryFn: () => api<ActivityEnvelope>("/api/activity"),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Activity</h1>
        <p className="text-sm text-muted-foreground">
          A derived recent-activity view (v1) — recent sign-ins, sessions, and
          courier sends, aggregated from existing data. This is a thin stub; full
          metrics are not part of this milestone.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent activity</CardTitle>
        </CardHeader>
        <CardContent>
          {isError ? (
            <div className="space-y-3">
              <p className="text-sm text-destructive" role="alert">
                Failed to load recent activity.
              </p>
              <button
                type="button"
                className="text-sm text-primary hover:underline"
                onClick={() => void refetch()}
              >
                Retry
              </button>
            </div>
          ) : isLoading ? (
            <div className="space-y-2">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : items.length === 0 ? (
            <div className="space-y-1 py-6 text-center">
              <p className="text-sm font-medium">No recent activity</p>
              <p className="text-sm text-muted-foreground">
                There is no recent sign-in or courier activity to show yet.
              </p>
            </div>
          ) : (
            <ul className="space-y-2">
              {items.map((entry, i) => (
                <ActivityRow key={i} entry={entry} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
