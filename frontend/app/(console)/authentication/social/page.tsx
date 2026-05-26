"use client";

// AUTH-04 — Social Sign-In (OIDC) page (UI-SPEC §4). GETs the providers array
// (client_secret masked, mapper_url already decoded to Jsonnet source by the
// backend) and renders the list editor. The OIDC method enable flag rides along
// in the same flat object.

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";

import { OidcList, type OidcDefaults, type OidcProvider } from "./oidc-list";

const PROVIDERS_PTR = "/selfservice/methods/oidc/config/providers";
const ENABLED_PTR = "/selfservice/methods/oidc/enabled";

export default function SocialPage() {
  const query = useQuery({
    queryKey: ["config", "kratos", "oidc"],
    queryFn: () => api<Record<string, unknown>>("/api/config/kratos/oidc"),
  });

  if (query.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <Alert variant="destructive" role="alert">
        <AlertTitle>Failed to load configuration</AlertTitle>
        <AlertDescription>
          The OIDC provider configuration could not be loaded. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  const data = query.data ?? {};
  const defaults: OidcDefaults = {
    [PROVIDERS_PTR]: (data[PROVIDERS_PTR] as OidcProvider[]) ?? [],
    [ENABLED_PTR]: Boolean(data[ENABLED_PTR]),
  };

  return <OidcList defaultValues={defaults} />;
}
