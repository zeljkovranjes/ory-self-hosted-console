-- 0003_webhooks.up.sql — Phase 11 HOOK-01/02/03 webhook dispatcher schema.
--
-- Runs via `sqlx::migrate!()` on backend boot, after 0001/0002. Owned by the
-- Phase-1 `console` DB role. Idempotent-safe: `if not exists` everywhere.
--
-- Tables:
--   webhooks            — operator-configured outbound webhook endpoints
--   webhook_deliveries  — the DURABLE delivery queue + delivery log (HOOK-01/03)
--
-- CRITICAL secret semantics (RESEARCH Pitfall 6 / Open Q1): `webhooks.secret` is
-- RECOVERABLE plaintext — the background worker must read it to HMAC-SHA256-sign
-- every delivery (HOOK-02). It is therefore NOT a one-way hash like
-- `admins.password_hash`; the column is named `secret`, never `secret_hash`. It
-- is NEVER serialized back through any API (WebhookView exposes only a
-- `secret_set` badge; create/rotate reveal the raw value exactly once). API keys
-- (migration 0004) use the OPPOSITE one-way SHA-256 regime — do NOT conflate.

-- pgcrypto provides gen_random_uuid() (already created by 0001; idempotent here).
create extension if not exists pgcrypto;

-- webhooks --------------------------------------------------------------------
-- `events` is a Postgres text[] of subscribed event names. `secret` is the
-- recoverable per-webhook HMAC signing key (see header). `enabled` gates whether
-- the worker delivers for this endpoint.
create table if not exists webhooks (
    id          uuid        primary key default gen_random_uuid(),
    name        text        not null,
    url         text        not null,
    events      text[]      not null,
    secret      text        not null,
    enabled     boolean     not null default true,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

-- webhook_deliveries ----------------------------------------------------------
-- The durable queue AND the delivery log (HOOK-01 + HOOK-03). Rows survive a
-- backend restart; the worker claims due rows with FOR UPDATE SKIP LOCKED,
-- retries with exponential backoff, and moves them to 'dead' at max_attempts.
--   status         pending -> delivering -> delivered | failed (retryable) | dead
--   attempt        delivery attempts made so far (0 on enqueue)
--   max_attempts   terminal-after count (default 8 ≈ hours of backoff)
--   next_attempt_at when the row next becomes claimable (now() on enqueue)
--   last_status_code / last_error  most-recent outcome for the log view
create table if not exists webhook_deliveries (
    id              uuid        primary key default gen_random_uuid(),
    webhook_id      uuid        not null references webhooks (id) on delete cascade,
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
-- by next_attempt_at (mirrors idx_sessions_expires_at on sessions).
create index if not exists idx_webhook_deliveries_due
    on webhook_deliveries (status, next_attempt_at);
