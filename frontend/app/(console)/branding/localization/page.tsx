// AX — Localization (FLAG-03, gated on the "account_experience" flag). The real
// localization UI lands in Phase 15 (Account Experience). Until then this is a
// thin placeholder behind FeatureGate: OFF → neutral "feature disabled"; ON →
// "coming online".

import { FeatureGate } from "@/components/feature-gate";

export default function LocalizationPage() {
  return (
    <FeatureGate flag="account_experience" title="Localization">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            Localization
          </h1>
          <p className="text-sm text-muted-foreground">
            Localization for the account experience is coming online in this
            milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
