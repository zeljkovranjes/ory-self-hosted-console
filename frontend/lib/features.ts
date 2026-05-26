// FLAG-02/03 — the single client-side source of truth for console feature flags.
//
// Reads GET /api/console/features (the Plan 01 backend contract) and toggles a
// flag via PUT /api/console/features/{key}. Both calls route through `api()` —
// the sole frontend egress (lib/api.ts) — so the X-CSRF-Token is auto-attached
// on the PUT and NO new host literal / NEXT_PUBLIC_ URL enters the bundle (the
// bundle-egress gate stays green). There is no independent flag derivation here:
// the sidebar nav-filter and FeatureGate are ADDITIVE cosmetics; the
// authoritative gate is the backend FeatureFlagHoop (Plan 01, T-12-08).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";

/** One flag's state as returned by GET /api/console/features. */
export type FeatureState = {
  enabled: boolean;
  label: string;
  /** Present (true) for flags whose feature also needs a runtime profile. */
  requires_runtime?: boolean;
};

/** The GET /api/console/features response shape (Plan 01 contract). */
export type FeaturesResponse = {
  features: Record<string, FeatureState>;
};

/** The shared TanStack Query key for the features set. */
export const FEATURES_QUERY_KEY = ["features"] as const;

/**
 * Read the full feature-flag set. The sidebar and FeatureGate consume `data`;
 * while `data` is undefined (pending) callers render the unfiltered/neutral
 * state to avoid a flash (no spinner).
 */
export function useFeatures() {
  return useQuery({
    queryKey: FEATURES_QUERY_KEY,
    queryFn: () => api<FeaturesResponse>("/api/console/features"),
  });
}

/**
 * Toggle a single flag. The PUT goes through `api()` (X-CSRF-Token auto-attached
 * on the mutating method); on settle we invalidate the features query so the
 * sidebar re-filters immediately. Callers do the optimistic UI + toast.
 */
export function useToggleFeature() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ key, enabled }: { key: string; enabled: boolean }) =>
      api(`/api/console/features/${key}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: FEATURES_QUERY_KEY }),
  });
}
