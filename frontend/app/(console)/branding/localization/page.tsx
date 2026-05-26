// BRAND-04 — Localization (GATED). Self-hosted Ory has no central localization
// API; localization is handled per message via the courier templates. The CTA
// links INTERNALLY to the Email Templates page (10-UI-SPEC §F). This is a
// labeled explanation, never a dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function LocalizationPage() {
  return (
    <GatedFeature
      title="Localization"
      badgeLabel="Not available in self-hosted Ory"
      explanation="Self-hosted Ory has no central localization API. Localization is handled per message through the courier email and SMS templates."
      recommendation="Localize your sign-up, recovery, and verification copy by editing the courier email and SMS templates directly."
      cta={{
        label: "Edit your email and SMS templates",
        href: "/branding/email-templates",
      }}
    />
  );
}
