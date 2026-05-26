// BRAND-06 — Theming / Account Experience (GATED). The self-hosted Account
// Experience is bring-your-own-UI; the console does not host an end-user theme.
// The CTA links INTERNALLY to the UI URLs page (10-UI-SPEC §F). This is a
// labeled explanation, never a dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function ThemingPage() {
  return (
    <GatedFeature
      title="Theming"
      badgeLabel="Not available in self-hosted Ory"
      explanation="The self-hosted Account Experience is bring-your-own-UI. The console does not host an end-user theme; you point the self-service flows at your own UI."
      recommendation="Build and host your own self-service UI, then point the Kratos self-service flows at it from the UI URLs page."
      cta={{
        label: "Configure your UI URLs",
        href: "/branding/ui-urls",
      }}
    />
  );
}
