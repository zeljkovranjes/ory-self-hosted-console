"use client";

// FLAG-04 — the shared "observability profile not running" affordance.
//
// Rendered by the observability pages when the `observability` flag is ON (so
// FeatureGate already passed) but the runtime probe reports the profiled
// services are DOWN (the backend's tolerant `profile_not_running` 200 state).
// This is DISTINCT from the FeatureGate OFF state (flag OFF): here the feature
// is enabled, the operator just hasn't started the profile yet.
//
// HARD INVARIANT: zero fake/dead controls. The only interactive element is at
// most a single "Retry" (the page's own refetch) — never a placeholder input,
// switch, or a control that 502s. The copy carries the EXACT enable instruction
// (`docker compose --profile observability up`) so the operator knows precisely
// what to run. No raw upstream error / 502 is ever surfaced here.

import { InfoIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export type ProfileNotRunningProps = {
  /** The surface name (e.g. "metrics", "logs", "Grafana") for the copy. */
  surface?: string;
  /** Optional retry handler — wired to the page's TanStack Query refetch. */
  onRetry?: () => void;
};

/**
 * The calm enable-the-profile affordance for the flag-ON + profile-DOWN case.
 */
export function ProfileNotRunning({ surface, onRetry }: ProfileNotRunningProps) {
  const what = surface ? `${surface} ` : "";
  return (
    <Card>
      <CardContent className="space-y-4 pt-4">
        <Alert role="status" aria-live="polite">
          <InfoIcon />
          <AlertTitle>The observability profile is not running</AlertTitle>
          <AlertDescription className="space-y-3">
            <p>
              This {what}view needs the optional observability profile
              (Prometheus, Loki, and Grafana). It is enabled in the console but
              the services are not currently running.
            </p>
            <p>Start them, then restart the stack:</p>
            <pre className="w-full overflow-x-auto rounded-md border bg-muted px-3 py-2 font-mono text-xs text-foreground">
              docker compose --profile observability up
            </pre>
            {onRetry ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={onRetry}
              >
                Retry
              </Button>
            ) : null}
          </AlertDescription>
        </Alert>
      </CardContent>
    </Card>
  );
}
