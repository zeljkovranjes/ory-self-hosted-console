"use client";

// FLAG-03 — FeatureGate: the calm, neutral wrapper that REPLACES the retired
// license-gated page primitive.
//
// Reads its flag via useFeatures() (the single client-side source of truth):
//   - flag ON  → render `children` (the real feature body; thin placeholders
//                until Phases 14–17) with NO gate chrome.
//   - flag OFF → render a calm empty-state built ONLY from already-vendored
//                primitives (page shell + Card + informational Alert + a single
//                navigational Link to /project/features).
//   - pending  → render nothing (do NOT flash the disabled card; UI-SPEC §3).
//
// HARD INVARIANT (carried verbatim from the retired license-gate primitive):
// the OFF state
// renders ZERO form controls — no input/select/textarea/switch/checkbox/combobox/
// spinbutton/<form>/button[type=submit]. The ONLY interactive element is the
// navigational Link. The copy is NEUTRAL: "This feature is disabled" — never
// any license/Enterprise language and never an "unavailable in self-hosted"
// framing (T-12-11). This is additive cosmetics only; the authoritative gate is
// the backend FeatureFlagHoop (T-12-08).

import type { ReactNode } from "react";
import Link from "next/link";
import { InfoIcon } from "lucide-react";

import { useFeatures } from "@/lib/features";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Card, CardContent } from "@/components/ui/card";

export type FeatureGateProps = {
  /** The feature-flag key (e.g. "saml"). */
  flag: string;
  /** Page heading shown in both the ON and OFF states. */
  title: string;
  /** The real feature body, rendered only when the flag is ON. */
  children: ReactNode;
};

/**
 * Gate a feature page on a console feature flag. Renders `children` when the
 * flag is ON, a calm "feature disabled" empty-state when OFF, and nothing while
 * the flag query is pending.
 */
export function FeatureGate({ flag, title, children }: FeatureGateProps) {
  const { data } = useFeatures();
  const flags = data?.features;

  // Pending: render nothing rather than flash the disabled card (UI-SPEC §3).
  if (!flags) return null;

  if (flags[flag]?.enabled) return <>{children}</>;

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">
          This console feature is turned off.
        </p>
      </div>

      <Card>
        <CardContent className="space-y-4 pt-4">
          <Alert role="status" aria-live="polite">
            <InfoIcon />
            <AlertTitle>This feature is disabled</AlertTitle>
            <AlertDescription>
              Enable it under{" "}
              <Link
                href="/project/features"
                className="text-primary hover:underline"
              >
                Project → Features
              </Link>{" "}
              to use it.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
}
