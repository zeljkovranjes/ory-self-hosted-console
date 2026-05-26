// HOOK-01/02/03 — shared types for the Webhooks + Delivery-log surfaces.
//
// Mirrors the 11-01 backend DTOs (backend/src/webhooks/mod.rs):
//   - WebhookView  → `Webhook` here (secret-free; only `secret_set` badge).
//   - DeliveryView → `Delivery` here.
// The raw signing secret is returned ONLY in the create/rotate responses, never
// in these list/detail shapes (T-11-18).

/** A secret-free webhook view (backend `WebhookView`). The secret value is never
 *  present — only the `secret_set` badge. */
export type Webhook = {
  id: string;
  name: string;
  url: string;
  events: string[];
  /** Masked badge only ("Set"/"Not set") — the raw secret is never serialized. */
  secret_set: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

/** A single webhook delivery attempt (backend `DeliveryView`). */
export type Delivery = {
  id: string;
  webhook_id: string;
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

/** The signature header the worker sets on every delivery (11-01 hmac.rs). */
export const SIGNATURE_HEADER = "X-Console-Signature";

/** The curated event catalog the events multi-select offers. These mirror the
 *  Ory/Kratos identity- and session-lifecycle events most webhooks subscribe to;
 *  the backend stores `events` as a free-form string array, so this list is the
 *  console's recommended set, not an enforced enum. */
export const WEBHOOK_EVENTS: readonly string[] = [
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
