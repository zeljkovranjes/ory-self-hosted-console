-- 0001_init.up.sql — Ory Self-Hosted Console v1 schema (BACK-03).
--
-- Runs via `sqlx::migrate!()` on backend boot, BEFORE the server binds. The
-- Phase-1 `console` DB role (CONNECT, CREATE; OWNER of the public schema) owns
-- everything created here. Idempotent-safe: `if not exists` everywhere so a
-- re-run (or a partially-applied state) does not error.
--
-- Tables:
--   admins           — console operators (local + optional GitHub-linked)
--   sessions         — DB-backed opaque sessions (only the token HASH at rest)
--   console_settings — singleton first-run state (initialized + bootstrap hash)
--   settings_history — stub for later phases (config-change audit); unused now

-- Extensions ------------------------------------------------------------------
-- citext: case-insensitive email uniqueness (admins.email).
-- pgcrypto: gen_random_uuid() for default UUID primary keys.
create extension if not exists citext;
create extension if not exists pgcrypto;

-- admins ----------------------------------------------------------------------
-- password_hash is NULL for OAuth-only admins; github_user_id is NULL until a
-- GitHub identity is linked. email is citext so uniqueness is case-insensitive.
create table if not exists admins (
    id              uuid        primary key default gen_random_uuid(),
    email           citext      unique not null,
    name            text        not null,
    password_hash   text        null,
    github_user_id  bigint      unique null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    last_login_at   timestamptz null
);

-- sessions --------------------------------------------------------------------
-- token_hash = SHA-256 of the opaque session token (the raw token only ever
-- lives in the client cookie). csrf_token is the per-session double-submit value.
create table if not exists sessions (
    id            uuid        primary key default gen_random_uuid(),
    token_hash    text        unique not null,
    admin_id      uuid        not null references admins (id) on delete cascade,
    created_at    timestamptz not null default now(),
    expires_at    timestamptz not null,
    last_seen_at  timestamptz not null default now(),
    ip            text        null,
    user_agent    text        null,
    csrf_token    text        not null
);

create index if not exists idx_sessions_admin_id   on sessions (admin_id);
create index if not exists idx_sessions_expires_at on sessions (expires_at);

-- console_settings ------------------------------------------------------------
-- Single-row table: the CHECK on the boolean PK (id = true) makes a second row
-- impossible. `initialized` is the server-side first-run flag; /setup 404s once
-- it is true. bootstrap_token_hash stores only the HASH of the one-time token.
create table if not exists console_settings (
    id                   boolean     primary key default true,
    initialized          boolean     not null default false,
    bootstrap_token_hash text        null,
    created_at           timestamptz not null default now(),
    constraint console_settings_single_row check (id)
);

-- settings_history ------------------------------------------------------------
-- Stub for later phases (YAML config-change audit, Phase 4/10/11). Defined now
-- so the schema is forward-compatible; no code writes to it this phase.
create table if not exists settings_history (
    id         uuid        primary key default gen_random_uuid(),
    service    text        not null,
    payload    jsonb       not null,
    created_at timestamptz not null default now()
);
