"use client";

// FLAG-02 — the Features management page (/project/features, UI-SPEC §1).
//
// A Switch-list over GET /api/console/features. Toggling a row fires
// PUT /api/console/features/{key} IMMEDIATELY (optimistic, NO Save button — this
// is NOT a dirty-gated SettingsForm). On success a sonner toast confirms; on
// error the optimistic state reverts and an error toast shows. The sidebar
// re-filters on settle (useToggleFeature invalidates the features query). All
// egress via @/lib/api — no Ory host/port literal (bundle-egress gate).

import * as React from "react";
import { toast } from "sonner";

import { useFeatures, useToggleFeature } from "@/lib/features";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";

// Per-key descriptions — plain tone, no marketing, no "Enterprise"/"licensed"
// language (UI-SPEC Copywriting). Keys mirror the backend FEATURE_META set.
const FLAG_DESCRIPTIONS: Record<string, string> = {
  saml: "Show the SAML sign-in configuration and add it to the navigation.",
  organizations:
    "Show the Organizations (B2B multi-tenancy) page and its navigation entry.",
  account_experience:
    "Show the account-experience pages — localization, custom domains, and theming.",
  observability:
    "Show the metrics and log dashboards backed by the observability profile.",
  event_streams:
    "Show the Event streams page for delivering events to an external sink.",
  opl_live_validation:
    "Validate the Ory Permission Language live in the permission-model editor.",
};

const RUNTIME_HINT = "Needs the observability profile running to be fully active.";

function safeId(key: string): string {
  return `feature-${key.replace(/[^a-zA-Z0-9]+/g, "-")}`;
}

function FlagRow({
  flagKey,
  label,
  enabled,
  requiresRuntime,
}: {
  flagKey: string;
  label: string;
  enabled: boolean;
  requiresRuntime?: boolean;
}) {
  const toggle = useToggleFeature();
  // Optimistic local state, reconciled when the query refetches on settle.
  const [optimistic, setOptimistic] = React.useState(enabled);
  React.useEffect(() => setOptimistic(enabled), [enabled]);

  const id = safeId(flagKey);
  const descId = `${id}-desc`;
  const description = FLAG_DESCRIPTIONS[flagKey] ?? "";

  function onCheckedChange(next: boolean) {
    setOptimistic(next); // optimistic flip
    toggle.mutate(
      { key: flagKey, enabled: next },
      {
        onSuccess: () =>
          toast.success(`${label} ${next ? "enabled" : "disabled"}`),
        onError: () => {
          setOptimistic(!next); // revert
          toast.error(`Couldn't update ${label}. Please try again.`);
        },
      },
    );
  }

  return (
    <div className="flex items-center justify-between gap-3">
      <div className="space-y-1">
        <Label htmlFor={id}>{label}</Label>
        {description ? (
          <p id={descId} className="text-sm text-muted-foreground">
            {description}
          </p>
        ) : null}
        {requiresRuntime && optimistic ? (
          <p
            role="note"
            aria-live="polite"
            className="text-xs text-muted-foreground"
          >
            {RUNTIME_HINT}
          </p>
        ) : null}
      </div>
      <Switch
        id={id}
        aria-label={label}
        aria-describedby={description ? descId : undefined}
        checked={optimistic}
        disabled={toggle.isPending}
        onCheckedChange={onCheckedChange}
      />
    </div>
  );
}

export default function FeaturesPage() {
  const { data, isPending } = useFeatures();
  const entries = data ? Object.entries(data.features) : [];

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Features</h1>
        <p className="text-sm text-muted-foreground">
          Turn console features on or off. Disabled features are hidden from the
          navigation and their pages until you enable them here.
        </p>
      </div>

      <Card>
        <CardContent className="space-y-4 pt-4">
          {isPending ? (
            // Loading: one skeleton row per expected flag (UI-SPEC Loading).
            <>
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <Skeleton className="h-4 w-40" />
                    <Skeleton className="h-3 w-64" />
                  </div>
                  <Skeleton className="h-5 w-9 rounded-full" />
                </div>
              ))}
            </>
          ) : entries.length === 0 ? (
            // Defensive empty state (the migration seeds the set — rarely hit).
            <div className="space-y-1">
              <h2 className="text-sm font-medium">No features to configure</h2>
              <p className="text-sm text-muted-foreground">
                There are no toggleable console features yet. New v2 features
                will appear here as they ship.
              </p>
            </div>
          ) : (
            entries.map(([key, state]) => (
              <FlagRow
                key={key}
                flagKey={key}
                label={state.label}
                enabled={state.enabled}
                requiresRuntime={state.requires_runtime}
              />
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
