// SSO — Organizations (FLAG-03, gated on the "organizations" flag). The real
// B2B multi-tenancy UI lands in Phase 14. Until then this is a thin placeholder
// behind FeatureGate: OFF → neutral "feature disabled"; ON → "coming online".

import { FeatureGate } from "@/components/feature-gate";

export default function OrganizationsPage() {
  return (
    <FeatureGate flag="organizations" title="Organizations">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            Organizations
          </h1>
          <p className="text-sm text-muted-foreground">
            Organizations (B2B multi-tenancy) are coming online in this
            milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
