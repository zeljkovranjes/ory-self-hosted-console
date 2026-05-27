-- 0010_service_domain_flags.up.sql — CLI-builder SVC-SELECT / CASCADE.
--
-- Extends the 0007 feature-flag seed with the four SERVICE-DOMAIN keys that gate
-- the v1 Ory routes (Kratos identities/sessions/courier, Hydra OAuth2, Keto
-- permissions, Oathkeeper access-rules). Until now those v1 routes were
-- ALWAYS-ON with no flag; this seed makes them flag-gated so a service set `off`
-- (its CONSOLE_SERVICE_* env / compose svc-* profile dropped) can be
-- cascade-disabled SERVER-SIDE by the boot reconcile (route 404 + nav hidden).
--
-- Seeded `true`: services are ON by default per CONTEXT (the all-on default
-- posture). The env-driven `reconcile_service_flags` (called at boot) is what
-- flips a flag OFF when its service is `off`; the seed never starts disabled.
--
-- NOTE: `saml` (the Polis cascade target) is NOT seeded here — it already exists
-- in the 0007 seed (seeded false; turned on with the SAML feature).
--
-- Idempotent: `insert ... on conflict (key) do nothing`, so a re-run / partial-
-- apply on an existing volume leaves any operator-toggled state intact (Pitfall
-- 4). The human label + `requires_runtime` marker are NOT columns — they live in
-- the code-side `FEATURE_META` map in backend/src/features/mod.rs, kept in
-- LOCKSTEP with this seed (adding a flag later is a code + seed edit).
insert into feature_flags (key, enabled) values
    ('identities', true),
    ('oauth2', true),
    ('permissions', true),
    ('access_rules', true)
on conflict (key) do nothing;
