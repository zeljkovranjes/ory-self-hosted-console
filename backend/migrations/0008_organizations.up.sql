-- 0008_organizations.up.sql — Phase 14 SSO-05/06 Organizations data model.
--
-- Runs via `sqlx::migrate!()` on backend boot, after 0001..0007. Owned by the
-- Phase-1 `console` DB role. Idempotent-safe: `if not exists` everywhere.
--
-- Tables:
--   organizations        — operator-managed organizations (a label + the SSO
--                          connection it is linked to).
--   organization_domains — verified email domains owned by an organization. The
--                          stored `domain` is the NORMALIZED ASCII form
--                          (lowercase + IDNA/punycode + trailing-dot-stripped +
--                          registered-domain boundary — see
--                          `organizations::domain::normalize_domain`). The UNIQUE
--                          index is on that normalized value so a spoofed/IDNA-
--                          confusable/case-variant duplicate (CORP.com, corp.com.,
--                          Cyrillic homoglyph) collides on insert (SSO-05).
--
-- SSO connection link (SSO-06): an organization links to its SAML/SSO connection
-- by the Polis `tenant` discriminator. Plan 01 fixed the convention
-- `product = "ory-console"`, `tenant = <connection id>`, and the Kratos provider
-- id `saml-<tenant>`. We store the connection's `tenant` string on the
-- organization (`sso_connection_tenant`), so the domain->SSO lookup (SSO-06)
-- resolves an email's domain to the org and returns this tenant — the identifier
-- the Account Experience UI (Phase 15) uses to start the SSO flow. It is NULLABLE
-- (an org may exist before its connection is configured) and is NOT a foreign key
-- (the connection itself lives in the `polis` DB, encrypted — not in this DB).
--
-- NOTE: org/domain rows carry NO secret; every column here is non-secret and is
-- safe to serialize back to the operator UI. Audit of create/edit/delete is
-- handled by the blanket response-phase audit hoop on the protected subtree
-- (actor-from-session) — no audit columns are needed here.

-- pgcrypto provides gen_random_uuid() (already created by 0001; idempotent here).
create extension if not exists pgcrypto;

-- organizations ---------------------------------------------------------------
-- `label` is the operator-facing display name. `sso_connection_tenant` links the
-- org to its Polis SSO connection by the (tenant, product="ory-console")
-- convention from Plan 01 (NULL until a connection is linked).
create table if not exists organizations (
    id                    uuid        primary key default gen_random_uuid(),
    label                 text        not null,
    sso_connection_tenant text        null,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now()
);

-- organization_domains --------------------------------------------------------
-- `domain` is the NORMALIZED ASCII form (the application normalizes on write AND
-- on lookup — never store the raw operator input). Deleting an organization
-- cascades its domains.
create table if not exists organization_domains (
    id          uuid        primary key default gen_random_uuid(),
    org_id      uuid        not null references organizations (id) on delete cascade,
    domain      text        not null,
    created_at  timestamptz not null default now()
);

-- SSO-05 spoofing defense: the UNIQUE constraint is on the NORMALIZED domain, so
-- two inputs that normalize to the same key (CORP.com / corp.com. / a Cyrillic
-- homoglyph that punycodes to the same xn-- form) cannot both be stored — the
-- second insert fails the unique index and the route maps it to a 409/422.
create unique index if not exists idx_organization_domains_domain
    on organization_domains (domain);

-- Lookup-supporting index for resolving an org's domains by org_id (the org
-- detail/list join). The unique domain index above already serves the
-- domain->org lookup (SSO-06).
create index if not exists idx_organization_domains_org
    on organization_domains (org_id);
