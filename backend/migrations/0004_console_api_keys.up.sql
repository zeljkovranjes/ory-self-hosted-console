-- 0004_console_api_keys.up.sql — Phase 11 PROJ-02 console API keys.
--
-- Consumed by the Wave-2 api-keys plan (11-04); landed here so all phase-11
-- migrations ship in one ordered batch. Idempotent-safe.
--
-- CRITICAL secret semantics: unlike webhook secrets (0003, recoverable), console
-- API keys are ONE-WAY SHA-256 hashed at rest (`key_hash`) — the backend only
-- ever VERIFIES a presented key, never re-emits it. The raw key is forwarded to
-- the operator exactly once at issue time and is unrecoverable thereafter.
-- `key_prefix` is a short non-secret display fragment (e.g. "ory_ab12…") for the
-- masked list view.
create extension if not exists pgcrypto;

create table if not exists console_api_keys (
    id          uuid        primary key default gen_random_uuid(),
    name        text        not null,
    key_hash    text        not null,
    key_prefix  text        not null,
    created_by  uuid        null,
    created_at  timestamptz not null default now(),
    last_used_at timestamptz null,
    revoked_at  timestamptz null
);
