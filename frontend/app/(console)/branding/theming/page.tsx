// AX — Theming (FLAG-03, gated on the "account_experience" flag). The real
// account-experience theming UI lands in Phase 15. Until then this is a thin
// placeholder behind FeatureGate: OFF → neutral "feature disabled"; ON →
// "coming online".

import { FeatureGate } from "@/components/feature-gate";

export default function ThemingPage() {
  return (
    <FeatureGate flag="account_experience" title="Theming">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Theming</h1>
          <p className="text-sm text-muted-foreground">
            Theming for the account experience is coming online in this
            milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
