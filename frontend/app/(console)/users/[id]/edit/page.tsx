"use client";

// IDENT-02 — the edit-identity route. Loads the identity (GET
// /api/kratos/identities/{id}) then renders the schema-driven IdentityForm in
// edit mode, prefilled from the loaded identity (which carries the required
// `state` for the backend PUT).

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { type Identity } from "../../identity-types";
import { IdentityForm } from "../../identity-form";

export default function EditIdentityPage() {
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
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (query.isError || !query.data) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Failed to load identity</AlertTitle>
        <AlertDescription>
          The identity could not be loaded for editing.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Edit identity</h1>
        <p className="text-sm text-muted-foreground">
          Fields are generated from the active identity schema.
        </p>
      </div>
      <IdentityForm mode="edit" identity={query.data} />
    </div>
  );
}
