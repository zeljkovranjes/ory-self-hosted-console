-- 0009_event_streams.up.sql — Phase 17 EVT-01/02/03 event-stream sink schema.
--
-- Runs via `sqlx::migrate!()` on backend boot, after 0001..0008. Owned by the
-- Phase-1 `console` DB role. Idempotent-safe: `if not exists` everywhere. This
-- schema EXTENDS the Phase-11 webhook dispatcher (0003) — `event_deliveries` is a
-- near-verbatim clone of `webhook_deliveries` (same status state machine, backoff,
-- dead-letter, retention), keyed on `sink_id` instead of `webhook_id`.
--
-- Tables:
--   event_sinks       — operator-configured outbound event-stream sinks
--                        (kind webhook | nats | kafka) + per-sink audit cursor
--   event_deliveries  — the DURABLE delivery queue + delivery log (clone of 0003)
--
-- CRITICAL secret semantics (BACK-07 / mirrors webhooks.secret): `event_sinks.secret`
-- is RECOVERABLE plaintext — the delivery worker must read it to re-sign each
-- webhook delivery (HMAC-SHA256, reusing webhooks::hmac) / to authenticate to a
-- NATS broker (creds string / token / password) / to authenticate to Kafka (SASL
-- password). It is therefore NOT a one-way hash; the column is named `secret`,
-- never `secret_hash`. It is NEVER serialized back through any API: the Rust
-- `EventSinkRow` deliberately does NOT derive Serialize, and `EventSinkView`
-- exposes only `secret_set` / `sasl_username_set` masked badges (one-time reveal
-- on create/rotate). Do NOT conflate with the one-way SHA-256 API-key regime (0004).
--
-- CURSOR semantics (Pitfall 5 — replay-storm defense): `last_event_id` /
-- `last_event_cursor_at` are the per-sink cursor INTO console_audit_log (the event
-- source). `create_sink` initializes the cursor to now() so a NEW sink streams only
-- events AFTER it was created — it does NOT replay the entire audit history.

-- pgcrypto provides gen_random_uuid() (already created by 0001; idempotent here).
create extension if not exists pgcrypto;

-- event_sinks -----------------------------------------------------------------
-- `kind` is one of webhook | nats | kafka (a kind whose adapter feature is not
-- compiled in is rejected at the Rust boundary, never inserted blindly). `target`
-- is the webhook URL / NATS broker_url / Kafka brokers list. `subject` is the
-- NATS subject / Kafka topic (NULL for webhook). `events` is a Postgres text[] of
-- subscribed audit-action names (the allowlist). `secret` is the recoverable
-- credential (see header). `sasl_username` is the optional Kafka SASL / NATS user
-- (paired with `secret` as the password). `tls` requests TLS to the broker.
create table if not exists event_sinks (
    id                   uuid        primary key default gen_random_uuid(),
    name                 text        not null,
    kind                 text        not null,
    target               text        not null,
    subject              text        null,
    events               text[]      not null,
    secret               text        not null default '',
    sasl_username        text        null,
    tls                  boolean     not null default false,
    enabled              boolean     not null default true,
    -- Per-sink cursor into console_audit_log. Initialized to now() on create
    -- (stream-from-now) so a new sink never replays history (Pitfall 5).
    last_event_id        uuid        null,
    last_event_cursor_at timestamptz null,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now()
);

-- event_deliveries ------------------------------------------------------------
-- The durable queue AND the delivery log (EVT-02). A near-verbatim clone of
-- webhook_deliveries (0003), keyed on sink_id. Rows survive a backend restart; the
-- worker claims due rows with FOR UPDATE SKIP LOCKED, retries with exponential
-- backoff, and moves them to 'dead' at max_attempts.
--   status         pending -> delivering -> delivered | failed (retryable) | dead
--   attempt        delivery attempts made so far (0 on enqueue)
--   max_attempts   terminal-after count (default 8 ≈ hours of backoff)
--   next_attempt_at when the row next becomes claimable (now() on enqueue)
--   last_status_code / last_error  most-recent outcome for the log view
-- `payload` stores the ALREADY-REDACTED OutboundEvent (PII masked before enqueue,
-- EVT-03) so the durable queue + the delivery-log view never store raw PII.
create table if not exists event_deliveries (
    id              uuid        primary key default gen_random_uuid(),
    sink_id         uuid        not null references event_sinks (id) on delete cascade,
    event           text        not null,
    payload         jsonb       not null,
    status          text        not null default 'pending',
    attempt         int         not null default 0,
    max_attempts    int         not null default 8,
    next_attempt_at timestamptz not null default now(),
    last_status_code int        null,
    last_error      text        null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

-- Claim-supporting index: the worker's claim query filters on status and orders
-- by next_attempt_at (mirrors idx_webhook_deliveries_due on 0003).
create index if not exists idx_event_deliveries_due
    on event_deliveries (status, next_attempt_at);
