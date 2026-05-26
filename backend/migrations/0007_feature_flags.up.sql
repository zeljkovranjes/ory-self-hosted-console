-- 0007_feature_flags.up.sql — Phase 12 FLAG-04 feature-toggle keystone.
--
-- The single console-owned source of truth for which v2 features are enabled.
-- A server-side hoop (`FeatureFlagHoop`) gates each feature's protected route
-- on this state (FLAG-01); the management routes read/toggle it (FLAG-02/04).
-- Idempotent-safe: `create table if not exists` + an `ON CONFLICT DO NOTHING`
-- seed so a re-run / partial-apply on an existing volume leaves the seed intact
-- (Pitfall 4).
--
-- The human label + `requires_runtime` marker are NOT columns (RESEARCH A3):
-- they live in a code-side `FEATURE_META` constant map in
-- `backend/src/features/mod.rs`, so adding a flag later is a code edit, not a
-- migration.
create table if not exists feature_flags (
    key        text        primary key,
    enabled    boolean     not null,
    updated_at timestamptz not null default now()
);

-- Seeded defaults (CONTEXT.md): external-setup features OFF, the in-place
-- enhancement (live OPL validation) ON. Idempotent — re-run / partial-apply safe.
insert into feature_flags (key, enabled) values
    ('saml', false),
    ('organizations', false),
    ('account_experience', false),
    ('observability', false),
    ('event_streams', false),
    ('opl_live_validation', true)
on conflict (key) do nothing;
