-- 0005_console_audit_log.up.sql — Phase 11 ACT-04 console audit log.
--
-- Consumed by the Wave-2 audit plan (11-03); landed here so all phase-11
-- migrations ship in one ordered batch. Idempotent-safe.
--
-- A response-phase audit hoop records every state-changing console action:
-- the actor (from the Depot session), the HTTP method/path, the affected
-- target, the outcome, and free-form jsonb metadata. Read-only via the log view.
create extension if not exists pgcrypto;

create table if not exists console_audit_log (
    id          uuid        primary key default gen_random_uuid(),
    actor_id    uuid        null,
    actor_email text        null,
    action      text        not null,
    method      text        null,
    path        text        null,
    target_type text        null,
    target_id   text        null,
    outcome     text        not null,
    metadata    jsonb       null,
    created_at  timestamptz not null default now()
);

-- Newest-first listing index for the log view.
create index if not exists idx_console_audit_log_created_at
    on console_audit_log (created_at);
