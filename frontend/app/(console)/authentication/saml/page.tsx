// SSO — SAML Sign-In (FLAG-03, gated on the "saml" flag). The real SAML
// configuration UI lands in Phase 14 (Ory Polis bridge). Until then this is a
// thin placeholder behind FeatureGate: when the flag is OFF the page shows the
// neutral "feature disabled" state; when ON it shows the "coming online" body.

import { FeatureGate } from "@/components/feature-gate";

export default function SamlSignInPage() {
  return (
    <FeatureGate flag="saml" title="SAML Sign-In">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            SAML Sign-In
          </h1>
          <p className="text-sm text-muted-foreground">
            SAML enterprise sign-in is coming online in this milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
