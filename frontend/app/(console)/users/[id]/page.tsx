"use client";

// IDENT-01 — the identity detail route. Fetches GET /api/kratos/identities/{id}
// via lib/api.ts (the sole egress) and renders the read-only IdentityDetail
// cards. The backend already strips credential secrets; the view defensively
// renders only credential TYPE names regardless.

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { type Identity } from "../identity-types";
import { IdentityDetail } from "./identity-detail";

export default function IdentityDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const query = useQuery({
    queryKey: ["identities", id],
    queryFn: () => api<Identity>(`/api/kratos/identities/${id}`),
    enabled: Boolean(id),
  });

  if (query.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (query.isError || !query.data) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Failed to load identity</AlertTitle>
        <AlertDescription>
          The identity could not be loaded. It may have been deleted.
        </AlertDescription>
      </Alert>
    );
  }

  return <IdentityDetail identity={query.data} />;
}
