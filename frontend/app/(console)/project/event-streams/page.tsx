// PROJ-03 — Event streams (GATED). Streaming events to an external sink is an
// Ory Network feature; self-hosted has derived Activity + outbound Webhooks
// instead (11-UI-SPEC §H). The CTA links INTERNALLY to the console's own webhook
// dispatcher. This is a labeled explanation, never a dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function EventStreamsPage() {
  return (
    <GatedFeature
      title="Event streams"
      badgeLabel="Limited in self-hosted"
      explanation="Streaming events to an external sink is an Ory Network feature. In self-hosted, derived activity is available under Activity, and outbound delivery is available via Webhooks."
      recommendation="To deliver events to an external endpoint in self-hosted, configure a webhook in the console's own dispatcher."
      cta={{
        label: "Set up a webhook",
        href: "/project/webhooks",
      }}
    />
  );
}
