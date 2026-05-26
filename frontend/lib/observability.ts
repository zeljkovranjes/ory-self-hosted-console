// OBS-03/04 — the observability data hooks (the frontend side of the Phase-16
// plan-02 backend routes).
//
// Every call routes through `api()` (lib/api.ts — the SOLE egress): so the
// X-CSRF-Token rules apply, and NO Prometheus/Loki/Grafana host literal ever
// enters the client bundle (the bundle-egress gate stays green). The backend
// returns a TOLERANT `profile_not_running` state as a 200-class structured
// payload (FLAG-04) — NOT a thrown error — so `api()` resolves normally and the
// pages branch on the payload via {@link isProfileNotRunning}.
//
// Two gating layers compose at the page level:
//   1. FeatureGate(observability) — flag OFF -> calm disabled state, nav-hidden.
//   2. the runtime probe (these hooks) — flag ON but profile DOWN -> the
//      ProfileNotRunning affordance (never a raw error / 502).

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

/**
 * The FLAG-04 health state every observability route carries. `"running"` means
 * the profiled services answered their readiness probe; `"profile_not_running"`
 * means the `observability` compose profile is up by flag but DOWN by runtime —
 * the page renders the enable-the-profile affordance, never a raw error.
 */
export type ProfileBackedState = "running" | "profile_not_running" | string;

/**
 * The shared envelope shape returned by both the Activity (Prometheus) and Logs
 * (Loki) routes. `result` is the raw upstream `data` object on success and
 * `null`/absent when the profile is down. We keep it generic JSON — the backend
 * passes the metric/log body through untouched (counts/buckets/log lines only).
 */
export type ObservabilityEnvelope = {
  /** `"prometheus"` (activity) or `"loki"` (logs). */
  source: string;
  /** The FLAG-04 health state. */
  state: ProfileBackedState;
  /** The selected dashboard/search intent, echoed back. */
  intent: string;
  /** The raw upstream `data` on success; `null`/absent when the profile is down. */
  result: unknown | null;
};

/** Detect the tolerant FLAG-04 down-state from a resolved (non-thrown) payload. */
export function isProfileNotRunning(
  data: Pick<ObservabilityEnvelope, "state"> | undefined,
): boolean {
  return data?.state === "profile_not_running";
}

// --- Activity (Prometheus) ---------------------------------------------------

/** The closed dashboard-intent set the backend accepts (T-16-09). */
export type ActivityIntent = "login-rate" | "signup-rate" | "login-latency";

/** One labelled Prometheus series from a `query_range` `data.result` entry. */
export type PromSeries = {
  metric: Record<string, string>;
  values: [number, string][];
};

const ACTIVITY_QUERY_KEY = "observability-activity";

/**
 * Fetch one Prometheus-backed Activity series (OBS-03) by closed INTENT. The
 * frontend never sends raw PromQL — only the intent + a numeric range/step the
 * backend validates and clamps.
 */
export function useActivityMetrics(intent: ActivityIntent) {
  return useQuery({
    queryKey: [ACTIVITY_QUERY_KEY, intent],
    queryFn: () =>
      api<ObservabilityEnvelope>(
        `/api/console/metrics/activity?intent=${encodeURIComponent(intent)}`,
      ),
  });
}

/**
 * Extract the `result` array from a Prometheus `query_range` envelope. The
 * upstream `data` is `{resultType, result:[{metric,values}]}`; we read the
 * series array tolerantly (empty array when the profile is down / no data).
 */
export function activitySeries(data: ObservabilityEnvelope | undefined): PromSeries[] {
  const result = (data?.result as { result?: unknown } | null)?.result;
  return Array.isArray(result) ? (result as PromSeries[]) : [];
}

// --- Logs (Loki) -------------------------------------------------------------

/** The closed log-search intent set the backend accepts (T-16-09). */
export type LogIntent = "all" | "errors" | "service";

/** The closed service allowlist for the `service` intent (mirrors the backend). */
export const LOG_SERVICES = [
  "kratos",
  "hydra",
  "keto",
  "oathkeeper",
  "backend",
  "frontend",
  "polis",
] as const;

export type LogService = (typeof LOG_SERVICES)[number];

/** The filter inputs the Logs search composes into the backend query params. */
export type LogFilters = {
  intent: LogIntent;
  /** Required only when `intent === "service"`; one of {@link LOG_SERVICES}. */
  service?: LogService;
};

/** One Loki log row, normalized from a stream's `values` ([ts_ns, line]). */
export type LokiLine = {
  /** Nanosecond UNIX timestamp string (Loki's native unit). */
  ts: string;
  /** The (already PII-masked at ingestion) log line. */
  line: string;
  /** The stream's labels (low-cardinality only; no identity/session IDs). */
  labels: Record<string, string>;
};

const LOGS_QUERY_KEY = "observability-logs";

/**
 * Fetch the Loki-backed log search (OBS-04) for the given filters. The frontend
 * sends a closed intent (+ an allowlisted service), never raw LogQL.
 */
export function useLogs(filters: LogFilters) {
  const qp = new URLSearchParams();
  qp.set("intent", filters.intent);
  if (filters.intent === "service" && filters.service) {
    qp.set("service", filters.service);
  }
  const key = qp.toString();
  return useQuery({
    queryKey: [LOGS_QUERY_KEY, key],
    queryFn: () => api<ObservabilityEnvelope>(`/api/console/logs?${key}`),
  });
}

/**
 * Flatten a Loki `query_range` envelope into a single chronological list of log
 * rows. The upstream `data` is `{resultType:"streams", result:[{stream,values}]}`
 * — we fold every stream's `values` into one list, newest first.
 */
export function lokiLines(data: ObservabilityEnvelope | undefined): LokiLine[] {
  const streams = (data?.result as { result?: unknown } | null)?.result;
  if (!Array.isArray(streams)) return [];
  const lines: LokiLine[] = [];
  for (const s of streams as {
    stream?: Record<string, string>;
    values?: [string, string][];
  }[]) {
    const labels = s.stream ?? {};
    for (const [ts, line] of s.values ?? []) {
      lines.push({ ts, line, labels });
    }
  }
  // Newest first (Loki returns backward-direction, but multiple streams must be
  // merged — sort by the numeric nanosecond timestamp descending).
  lines.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  return lines;
}
