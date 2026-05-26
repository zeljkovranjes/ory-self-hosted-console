"use client";

// OAUTH2-01 — the edit-client route. Loads the client (GET
// /api/hydra/clients/{id}) then renders ClientForm in edit mode. The secret is
// never returned by GET (write-only); the form's secret field starts blank and a
// blank edit preserves the stored secret (#2869 — structural).

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { type OAuth2Client } from "../../../_lib/oauth2-types";
import { ClientForm } from "../../client-form";

export default function EditClientPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const query = useQuery({
    queryKey: ["oauth2-client", id],
    queryFn: () => api<OAuth2Client>(`/api/hydra/clients/${id}`),
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
        <AlertTitle>Failed to load client</AlertTitle>
        <AlertDescription>
          The client could not be loaded for editing.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Edit OAuth2 client
        </h1>
        <p className="text-sm text-muted-foreground">
          Update this client. The existing secret is preserved unless you
          explicitly rotate it.
        </p>
      </div>
      <ClientForm mode="edit" client={query.data} />
    </div>
  );
}
