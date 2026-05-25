-- db/init/01-init.sql
--
-- Postgres first-boot initialization for the Ory Self-Hosted Console stack.
--
-- !! RUNS ONCE, ON FIRST BOOT ONLY !!
-- The official postgres image executes everything in /docker-entrypoint-initdb.d/
-- exactly once, and ONLY when the data directory is empty (a truly fresh volume).
-- Editing this file and re-running `docker compose up` against an EXISTING volume
-- does NOTHING. To re-apply, you must destroy the volume first:
--     docker compose down -v && docker compose up
-- (See Phase 1 RESEARCH Pitfall 2.)
--
-- Mounted via: ./db/init:/docker-entrypoint-initdb.d:ro
-- Connection:  runs as the super-user defined by POSTGRES_USER.
--
-- This script creates the five logical databases (INFRA-02) and, as a
-- production-grade hardening (RESEARCH Open Question 2 / Assumption A3),
-- one least-privilege role per DB-backed service database. Each role's
-- password is a placeholder here; Plan 04 wires the real values via env/.env
-- so no real secret is committed to git (threat T-01-leastpriv / T-01-secrets).
--
-- NOTE on the `oathkeeper` database (RESEARCH Assumption A4): Oathkeeper is
-- stateless by default (rules + JWKS come from files), so this DB is created
-- for forward-compatibility ONLY. NO oathkeeper-migrate container and NO DSN
-- are wired in this milestone.
--
-- NOTE on `console`: this is the Rust backend's own state database. Only the
-- database is created here; its schema/tables are owned by Phase 2's sqlx
-- migrations. Do NOT add any table DDL for the console database in this script.

-- ---------------------------------------------------------------------------
-- 1. Databases (exactly five — INFRA-02)
-- ---------------------------------------------------------------------------
CREATE DATABASE kratos;
CREATE DATABASE hydra;
CREATE DATABASE keto;
CREATE DATABASE oathkeeper;   -- forward-compat only; Oathkeeper is stateless in this milestone
CREATE DATABASE console;      -- Rust backend's own state (schema owned by Phase 2 sqlx migrations)

-- ---------------------------------------------------------------------------
-- 2. Per-database least-privilege roles (production-grade hardening — A3)
--
-- One scoped login role per service database instead of a single shared
-- super-user owning all data. Passwords are PLACEHOLDERS; Plan 04 must
-- override these from .env BEFORE first boot (the role passwords below are
-- only meaningful on the fresh-volume init run). Document in README that
-- production deployments MUST set strong, unique values via .env.
-- ---------------------------------------------------------------------------
CREATE ROLE kratos  WITH LOGIN PASSWORD 'changeme_kratos';
CREATE ROLE hydra   WITH LOGIN PASSWORD 'changeme_hydra';
CREATE ROLE keto    WITH LOGIN PASSWORD 'changeme_keto';
CREATE ROLE console WITH LOGIN PASSWORD 'changeme_console';
-- No role for the oathkeeper database: it is unused (stateless service, A4).

-- ---------------------------------------------------------------------------
-- 3. Grants — each role gets full privileges on ONLY its own database
-- ---------------------------------------------------------------------------
GRANT ALL PRIVILEGES ON DATABASE kratos  TO kratos;
GRANT ALL PRIVILEGES ON DATABASE hydra   TO hydra;
GRANT ALL PRIVILEGES ON DATABASE keto    TO keto;
GRANT ALL PRIVILEGES ON DATABASE console TO console;

-- ---------------------------------------------------------------------------
-- 4. Per-database `public` schema ownership (REQUIRED on Postgres 15+).
--
-- Since PostgreSQL 15, the `public` schema is owned by the bootstrap super-user
-- and non-owner roles no longer have CREATE on it by default — so an Ory migrate
-- run as the per-DB role fails with "permission denied for schema public"
-- (SQLSTATE 42501). Granting the service role OWNERSHIP of its own database's
-- `public` schema (scoped to that DB only) gives it full DDL rights there while
-- keeping least-privilege isolation between databases.
--
-- `ALTER SCHEMA ... OWNER TO` must run INSIDE the target database, so we switch
-- with the psql \connect meta-command (this file is executed by psql in the
-- official postgres entrypoint, which understands \connect).
-- ---------------------------------------------------------------------------
\connect kratos
ALTER SCHEMA public OWNER TO kratos;
GRANT ALL ON SCHEMA public TO kratos;

\connect hydra
ALTER SCHEMA public OWNER TO hydra;
GRANT ALL ON SCHEMA public TO hydra;

\connect keto
ALTER SCHEMA public OWNER TO keto;
GRANT ALL ON SCHEMA public TO keto;

\connect console
ALTER SCHEMA public OWNER TO console;
GRANT ALL ON SCHEMA public TO console;
