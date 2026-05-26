"use client";

// OBS-05 — the Grafana power-user surface.
//
// Grafana is reachable ONLY through the authenticated same-origin backend proxy
// (`/backend/api/console/grafana/...`): the backend injects X-WEBAUTH-USER from
// the session and forwards to the internal Grafana origin (plan 02). The client
// NEVER references the Grafana host directly — the only literal here is the
// same-origin `/backend` proxy PATH, which carries no host (bundle-egress gate
// stays green; no NEXT_PUBLIC_ Grafana URL anywhere).
//
// Surface choice (the lower-CSP-risk option per the plan facts): a LINK that
// opens the proxied Grafana in a new tab, NOT an iframe embed. A link avoids the
// CSP `frame-ancestors` / GF_SECURITY_ALLOW_EMBEDDING coupling entirely (no
// cross-frame surface to scope), while still giving the operator the full
// Grafana dashboards through the authed proxy.
//
// Two gating layers: <FeatureGate flag="observability"> (flag OFF -> disabled
// state, nav-hidden) + the runtime probe (flag ON but profile DOWN ->
// ProfileNotRunning, never a raw error). We probe via the metrics route's
// envelope so the page knows whether to show the link or the affordance.

import { ExternalLink } from "lucide-react";

import {
  isProfileNotRunning,
  useActivityMetrics,
  type ObservabilityEnvelope,
} from "@/lib/observability";
import { FeatureGate } from "@/components/feature-gate";
import { ProfileNotRunning } from "@/components/profile-not-running";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

// The same-origin authed proxy path (plan 02). NO host literal — the Next
// rewrite maps `/backend` to the internal backend, which proxies to Grafana.
const GRAFANA_PROXY_PATH = "/backend/api/console/grafana/";

function GrafanaSurface() {
  // Reuse the activity metrics probe as the runtime profile signal — if the
  // profile is down the same `profile_not_running` state comes back, and we show
  // the affordance instead of a dead link.
  const { data, isLoading, refetch } = useActivityMetrics("login-rate");
  const envelope = data as ObservabilityEnvelope | undefined;

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Grafana</h1>
        <p className="text-sm text-muted-foreground">
          Open the full Grafana dashboards for the observability stack. Access
          runs through the console&apos;s authenticated proxy — no separate
          Grafana login.
        </p>
      </div>

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : isProfileNotRunning(envelope) ? (
        <ProfileNotRunning surface="Grafana" onRetry={() => void refetch()} />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Grafana dashboards</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Grafana opens in a new tab through the authenticated proxy. Your
              console session is forwarded automatically.
            </p>
            <Button asChild>
              <a
                href={GRAFANA_PROXY_PATH}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink />
                Open Grafana
              </a>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function GrafanaPage() {
  return (
    <FeatureGate flag="observability" title="Grafana">
      <GrafanaSurface />
    </FeatureGate>
  );
}
