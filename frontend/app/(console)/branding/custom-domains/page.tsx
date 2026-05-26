// AX — Custom Domains (FLAG-03, gated on the "account_experience" flag). The
// real custom-domains UI lands in Phase 15 (Account Experience). Until then this
// is a thin placeholder behind FeatureGate: OFF → neutral "feature disabled";
// ON → "coming online".

import { FeatureGate } from "@/components/feature-gate";

export default function CustomDomainsPage() {
  return (
    <FeatureGate flag="account_experience" title="Custom Domains">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            Custom Domains
          </h1>
          <p className="text-sm text-muted-foreground">
            Custom domains for the account experience are coming online in this
            milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
