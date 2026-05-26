// ORG-01 — Organizations (GATED). B2B multi-tenancy is an Ory Enterprise /
// Network feature, not available in the self-hosted OSS stack (11-UI-SPEC §H).
// The CTA links to EXTERNAL Ory docs. This is a labeled explanation, never a
// dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function OrganizationsPage() {
  return (
    <GatedFeature
      title="Organizations"
      badgeLabel="Requires Ory Enterprise License / Network"
      explanation="Organizations (B2B multi-tenancy) are an Ory Enterprise / Network feature and are not available in the self-hosted OSS stack."
      recommendation="Organizations require Ory Enterprise or Ory Network. Read the documentation to learn how multi-tenancy works there."
      cta={{
        label: "Read about Ory Organizations",
        href: "https://www.ory.sh/docs/kratos/organizations",
        external: true,
      }}
    />
  );
}
