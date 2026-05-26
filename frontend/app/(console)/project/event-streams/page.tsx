// EVT — Event streams (FLAG-03, gated on the "event_streams" flag). The real
// external-sink streaming UI lands in Phase 17. Until then this is a thin
// placeholder behind FeatureGate: OFF → neutral "feature disabled"; ON →
// "coming online".

import { FeatureGate } from "@/components/feature-gate";

export default function EventStreamsPage() {
  return (
    <FeatureGate flag="event_streams" title="Event streams">
      <div className="space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            Event streams
          </h1>
          <p className="text-sm text-muted-foreground">
            Streaming events to an external sink is coming online in this
            milestone.
          </p>
        </div>
      </div>
    </FeatureGate>
  );
}
