// AUTH-05 — SAML Sign-In (GATED). SAML enterprise sign-in is an Ory Enterprise /
// Network feature, not available in the self-hosted OSS stack (11-UI-SPEC §H).
// The CTA links to EXTERNAL Ory docs. This is a labeled explanation, never a
// dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function SamlSignInPage() {
  return (
    <GatedFeature
      title="SAML Sign-In"
      badgeLabel="Requires Ory Enterprise License"
      explanation="SAML enterprise sign-in is an Ory Enterprise / Network feature and is not available in the self-hosted OSS stack."
      recommendation="SAML sign-in requires Ory Enterprise. Read the documentation to learn how enterprise SSO is configured there."
      cta={{
        label: "Read about Ory Enterprise SAML",
        href: "https://www.ory.sh/docs/kratos/social-signin/saml",
        external: true,
      }}
    />
  );
}
