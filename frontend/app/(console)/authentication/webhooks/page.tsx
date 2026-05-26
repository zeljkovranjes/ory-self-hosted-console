"use client";

// AUTH-11 / HOOK-04 — Actions & Webhooks page (UI-SPEC §10). GETs the webhooks
// flat object (keyed by each flow `hooks` array-root pointer; auth secrets
// masked, config.body decoded to Jsonnet source by the backend) and renders the
// combined list editor.

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";

import {
  WebhookList,
  WEBHOOK_POINTERS,
  type WebhookDefaults,
} from "./webhook-list";

export default function WebhooksPage() {
  const query = useQuery({
    queryKey: ["config", "kratos", "webhooks"],
    queryFn: () => api<Record<string, unknown>>("/api/config/kratos/webhooks"),
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
          The webhook configuration could not be loaded. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  const data = query.data ?? {};
  const defaults: WebhookDefaults = {};
  for (const p of WEBHOOK_POINTERS) {
    defaults[p] = Array.isArray(data[p]) ? (data[p] as unknown[]) : [];
  }

  return <WebhookList defaultValues={defaults} />;
}
