"use client";

// OBS-03 — the real Prometheus-backed Activity dashboard (Phase-16).
//
// REPLACES the ACT-03 derived-stub body: instead of folding recent Kratos
// sessions + courier sends into a "derived (v1)" list, this renders metric
// panels backed by the plan-02 Prometheus route GET /api/console/metrics/activity
// (closed dashboard intents: login-rate, signup-rate, login-latency). The
// derived /api/activity stub is RETAINED unflagged by the backend as the OFF
// fallback — but this page IS the observability surface, so it is wrapped in
// <FeatureGate flag="observability">. When the flag is ON but the profile is
// DOWN, the backend returns a tolerant `profile_not_running` state and we render
// <ProfileNotRunning /> — never a raw error / 502.
//
// All egress via @/lib/api (useActivityMetrics) — no Prometheus host literal.
// (bundle-egress gate). No CDN chart lib: the panels are Card-based summaries
// computed from the returned series (counts/buckets only — no per-identity data).

import {
  activitySeries,
  isProfileNotRunning,
  useActivityMetrics,
  type ActivityIntent,
  type ObservabilityEnvelope,
  type PromSeries,
} from "@/lib/observability";
import { FeatureGate } from "@/components/feature-gate";
import { ProfileNotRunning } from "@/components/profile-not-running";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

type PanelSpec = {
  intent: ActivityIntent;
  title: string;
  description: string;
  /** How the latest value is rendered. */
  unit: "per-second" | "seconds";
};

const PANELS: PanelSpec[] = [
  {
    intent: "login-rate",
    title: "Login attempts / sec",
    description: "Console login attempts per second (5m rate), by result.",
    unit: "per-second",
  },
  {
    intent: "signup-rate",
    title: "Setup completions / sec",
    description: "Console setup completions per second (5m rate).",
    unit: "per-second",
  },
  {
    intent: "login-latency",
    title: "Request latency (p95)",
    description: "Backend HTTP request latency, 95th percentile (5m).",
    unit: "seconds",
  },
];

// The latest value across a Prometheus range series (the last sample). Returns a
// formatted string + an optional per-series label (e.g. result=success).
function latestSamples(
  series: PromSeries[],
  unit: PanelSpec["unit"],
): { label: string; value: string }[] {
  return series.map((s) => {
    const last = s.values.at(-1);
    const raw = last ? Number(last[1]) : NaN;
    const value = Number.isFinite(raw)
      ? unit === "seconds"
        ? `${(raw * 1000).toFixed(0)} ms`
        : raw.toFixed(3)
      : "—";
    // Prefer a meaningful metric label (e.g. `result`) for the row label.
    const label =
      s.metric.result ??
      s.metric.le ??
      Object.values(s.metric)[0] ??
      "value";
    return { label, value };
  });
}

function MetricPanel({ spec }: { spec: PanelSpec }) {
  const { data, isLoading, refetch } = useActivityMetrics(spec.intent);
  const envelope = data as ObservabilityEnvelope | undefined;

  return (
    <Card>
      <CardHeader className="space-y-1">
        <CardTitle className="text-base">{spec.title}</CardTitle>
        <p className="text-xs text-muted-foreground">{spec.description}</p>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-12 w-full" />
        ) : isProfileNotRunning(envelope) ? (
          <ProfileNotRunning surface="metrics" onRetry={() => void refetch()} />
        ) : (
          <MetricRows
            samples={latestSamples(activitySeries(envelope), spec.unit)}
          />
        )}
      </CardContent>
    </Card>
  );
}

function MetricRows({
  samples,
}: {
  samples: { label: string; value: string }[];
}) {
  if (samples.length === 0) {
    return (
      <p className="py-2 text-sm text-muted-foreground">
        No data points in the current window.
      </p>
    );
  }
  return (
    <ul className="space-y-2">
      {samples.map((s, i) => (
        <li
          key={`${s.label}-${i}`}
          className="flex items-center justify-between gap-3 text-sm"
        >
          <span className="truncate text-muted-foreground">{s.label}</span>
          <span className="font-mono tabular-nums">{s.value}</span>
        </li>
      ))}
    </ul>
  );
}

function ActivityDashboard() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Activity</h1>
        <p className="text-sm text-muted-foreground">
          Live metrics from the observability profile — sign-up/login rates and
          request latency, scraped from the backend&apos;s Prometheus exporter.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {PANELS.map((spec) => (
          <MetricPanel key={spec.intent} spec={spec} />
        ))}
      </div>
    </div>
  );
}

export default function ActivityPage() {
  return (
    <FeatureGate flag="observability" title="Activity">
      <ActivityDashboard />
    </FeatureGate>
  );
}
