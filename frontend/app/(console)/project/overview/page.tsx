"use client";

// PROJ-01 — the Project Overview / service-health dashboard (11-UI-SPEC §D).
//
// Read-only. Fetches GET /api/overview through @/lib/api (the sole egress — no
// Ory host literal) and renders one status Card per Ory service in a responsive
// grid. Each card shows the service version + a health Badge carrying the WORD
// ("Healthy"/"Unhealthy"/"Unreachable") plus a lucide icon. An unreachable
// service STILL renders its card with helper copy — the dashboard never blanks
// out. A "Refresh" button triggers a TanStack Query refetch (a read-only
// re-poll, NOT a write). No filter, no write affordance.

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle, RefreshCw, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

// The per-service entry shape returned by GET /api/overview (backend
// ServiceOverview: name/version/health/reachable).
type ServiceOverview = {
  name: string;
  version: string | null;
  health: "Healthy" | "Unhealthy" | "Unreachable" | string;
  reachable: boolean;
};

const QUERY_KEY = "project-overview";

// Title-case a service name ("kratos" -> "Kratos") for the card title.
function displayName(name: string): string {
  return name.length ? name[0].toUpperCase() + name.slice(1) : name;
}

function HealthBadge({ health }: { health: string }) {
  if (health === "Healthy") {
    return (
      <Badge variant="secondary" className="gap-1 text-[--success]">
        <CheckCircle className="size-3.5" />
        Healthy
      </Badge>
    );
  }
  if (health === "Unreachable") {
    return (
      <Badge variant="outline" className="gap-1 text-destructive">
        <AlertTriangle className="size-3.5" />
        Unreachable
      </Badge>
    );
  }
  // "Unhealthy" (reachable but the health probe did not report ok) or any other
  // non-healthy state.
  return (
    <Badge variant="secondary" className="gap-1 text-destructive">
      <XCircle className="size-3.5" />
      {health || "Unhealthy"}
    </Badge>
  );
}

function ServiceCard({ service }: { service: ServiceOverview }) {
  const name = displayName(service.name);
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
        <CardTitle>{name}</CardTitle>
        <HealthBadge health={service.health} />
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Version</span>
          <span className="font-mono text-xs">{service.version ?? "—"}</span>
        </div>
        {service.reachable ? null : (
          <p className="text-sm text-muted-foreground">
            Could not reach {name}. Check that the service is running.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: [QUERY_KEY],
    queryFn: () => api<ServiceOverview[]>("/api/overview"),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            The health and version of each self-hosted Ory service in this stack.
            This is a read-only dashboard — refresh to re-check.
          </p>
        </div>
        <Button
          type="button"
          onClick={() => void refetch()}
          disabled={isFetching}
        >
          <RefreshCw className={isFetching ? "animate-spin" : undefined} />
          Refresh
        </Button>
      </div>

      {isError ? (
        <Card>
          <CardContent className="space-y-3 pt-6">
            <p className="text-sm text-destructive" role="alert">
              Failed to load the service overview.
            </p>
            <Button type="button" variant="outline" onClick={() => void refetch()}>
              Retry
            </Button>
          </CardContent>
        </Card>
      ) : isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[0, 1, 2, 3].map((i) => (
            <Card key={i}>
              <CardHeader className="space-y-0">
                <Skeleton className="h-5 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-4 w-32" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {(data ?? []).map((service) => (
            <ServiceCard key={service.name} service={service} />
          ))}
        </div>
      )}
    </div>
  );
}
