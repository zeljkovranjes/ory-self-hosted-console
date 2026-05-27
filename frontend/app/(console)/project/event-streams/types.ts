// EVT-01/02/03 — shared types for the Event-streams (sink) + Delivery-log surfaces.
//
// Mirrors the 17-01/02 backend DTOs (backend/src/events/mod.rs + routes.rs):
//   - EventSinkView      → `EventSink` here (credential-free; only `secret_set` /
//                          `sasl_username_set` badges — never a raw value).
//   - EventDeliveryView  → `Delivery` here (the redacted payload is safe to show).
// The raw signing secret is returned ONLY in the create/rotate responses (webhook
// kind), never in these list/detail shapes (T-17-01).

/** The pluggable sink kinds the backend registry dispatches. A `kind` outside this
 *  set is rejected at the boundary (422); the form only offers these. */
export const SINK_KINDS = ["webhook", "nats", "kafka"] as const;
export type SinkKind = (typeof SINK_KINDS)[number];

/** Human labels for each sink kind (the Badge + the kind <select>). */
export const SINK_KIND_LABELS: Record<SinkKind, string> = {
  webhook: "Webhook",
  nats: "NATS",
  kafka: "Kafka",
};

/** A credential-free event-sink view (backend `EventSinkView`). The secret /
 *  SASL credential values are NEVER present — only the `*_set` badges. */
export type EventSink = {
  id: string;
  name: string;
  /** webhook | nats | kafka. */
  kind: string;
  /** Webhook URL / NATS broker URL / Kafka brokers list. */
  target: string;
  /** NATS subject / Kafka topic. `null` for webhook sinks. */
  subject: string | null;
  events: string[];
  /** Masked badge only ("Set"/"Not set") — the raw secret is never serialized. */
  secret_set: boolean;
  /** Masked badge only — true when a SASL/NATS username is stored. */
  sasl_username_set: boolean;
  tls: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

/** A single sink delivery attempt (backend `EventDeliveryView`). The `payload` is
 *  the ALREADY-REDACTED OutboundEvent (no raw PII/secrets — EVT-03). */
export type Delivery = {
  id: string;
  sink_id: string;
  event: string;
  payload: unknown;
  status: string;
  attempt: number;
  max_attempts: number;
  next_attempt_at: string;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

/** The signature header the worker sets on every webhook-kind delivery (11-01
 *  hmac.rs, reused by the webhook sink). */
export const SIGNATURE_HEADER = "X-Console-Signature";

/** The curated event catalog the events multi-select offers. MUST stay in lockstep
 *  with the backend `events::routes::KNOWN_EVENTS` allowlist (an event outside the
 *  set is rejected 422). */
export const SINK_EVENTS: readonly string[] = [
  "identity.created",
  "identity.updated",
  "identity.deleted",
  "session.created",
  "session.revoked",
  "registration.completed",
  "login.completed",
  "recovery.completed",
  "verification.completed",
  "settings.completed",
] as const;

/** The delivery-status filter options (backend statuses + an "all" sentinel). */
export const DELIVERY_STATUSES: readonly string[] = [
  "pending",
  "delivering",
  "delivered",
  "failed",
  "dead",
] as const;
