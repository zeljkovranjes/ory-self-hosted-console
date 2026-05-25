-- 0002_single_admin_guard.up.sql — CR-01 belt-and-suspenders single-admin cap.
--
-- The application enforces "exactly one admin during first-run bootstrap" inside
-- a single SERIALIZABLE-equivalent transaction (FOR UPDATE on the console_settings
-- singleton + a conditional flip of `initialized`). This migration adds a HARD DB
-- guard so that even a logic regression cannot create a second admin in v1: a
-- unique index on a constant expression permits at most ONE row in `admins`.
--
-- Phase 11 introduces multi-admin members and will DROP this index in its own
-- migration; until then the single-tenant invariant is enforced at the schema
-- level, not just in code.
--
-- Idempotent: `if not exists` so a re-run does not error.
create unique index if not exists admins_single_row_guard
    on admins ((true));
