# Ory Self-Hosted Console (`ory-ui`)

A self-hosted, single-tenant, drop-in replacement for the Ory Network Console,
delivered as a `docker compose` project. A single `docker compose up` brings up
the full stack — Postgres, Ory Kratos / Hydra / Keto / Oathkeeper, a hardened
restart broker, a Rust (Salvo) backend, and a Next.js admin frontend — with zero
manual plumbing. The operator experience mirrors pointing an SDK at Ory Network:
provide a single Ory API base URL + an admin credential and everything else
(database wiring, service config, migrations, internal URLs) is generated and
bootstrapped automatically.

> **Phase 1 status — infrastructure & security foundations.** This milestone
> delivers the orchestration and security substrate only. The backend and
> frontend are intentionally minimal *skeletons* (each exposes a `/health`
> endpoint to prove the compose graph and healthchecks). Real backend logic is
> Phase 2; the real frontend shell is Phase 5.

---

## Quick start

Prerequisites: Docker Engine + **Docker Compose v2.1.1+** (for `docker compose up -d --wait`).

```bash
# 1. Create your local env from the template and fill in the values.
cp .env.example .env
#    Edit .env: set ORY_BASE_URL + the admin credential (ADMIN_EMAIL / ADMIN_PASSWORD),
#    and strong values for POSTGRES_PASSWORD, the *_DB_PASSWORD roles, and
#    HYDRA_SECRETS_SYSTEM. The placeholders are fine for a local infra bring-up.

# 2. Bring the whole stack up on a fresh volume and wait for health.
docker compose up -d --wait

# 3. Backend and frontend are the only host-published services:
#    - frontend:  http://localhost:3000
#    - backend:   http://localhost:8080/health
```

The single operator-facing inputs (the **bootstrap contract**, INFRA-06) are the
Ory API base URL + the admin credential. Everything else in `.env` is supporting
plumbing with sensible dev defaults.

### Fresh-volume note (IMPORTANT)

The Postgres first-boot init script (`db/init/01-init.sql`) — which creates the
five logical databases and per-service roles — runs **only once, on an empty
data directory**. Editing it and re-running `docker compose up` against an
existing volume does nothing. To re-trigger DB initialization you must destroy
the volume first:

```bash
docker compose down -v && docker compose up -d --wait
```

The Hydra `HYDRA_SECRETS_SYSTEM` value is **immutable after the first
migration** — it encrypts OAuth2 data at rest and cannot be rotated. Set it once
to a strong, stable value before first boot and never change it.

---

## Console authentication (Phase 2)

Phase 2 turns the backend into the single authenticated API layer with its own
`console` database (admins, sessions, first-run state) and production-grade
console auth. Day-one operator flow:

### First run — the bootstrap setup token

On first boot, when no admin exists yet, the backend generates a one-time
high-entropy **setup token**, persists only its hash, and prints the raw token
to stdout exactly once. Read it from the backend logs:

```bash
docker compose logs backend | grep 'FIRST-RUN SETUP TOKEN'
# -> FIRST-RUN SETUP TOKEN: <token>
```

Complete first-run setup by POSTing the token plus your admin name/email/password
(password must be **at least 12 characters**) to `/setup`:

```bash
curl -X POST http://localhost:8080/setup \
  -H 'Content-Type: application/json' \
  --data '{"name":"You","email":"you@example.com","password":"a-strong-passphrase","token":"<token>"}'
```

Notes:
- The token is **regenerated on every uninitialized boot** — if you restart
  before completing setup, copy the newest line from the logs. A stale token is
  invalidated.
- Once the admin exists, `/setup` returns **404** (single-use; server-side
  `initialized` flag). `GET /api/console/state` reports `{"initialized":true}`.
- The token may also be supplied via an `X-Setup-Token` header instead of the
  body field.

### GitHub OAuth login (optional, link-to-existing-admin only)

GitHub OAuth is **off by default** and is mounted ONLY when both env vars are
present. To enable it:

1. Create a GitHub OAuth App (Settings → Developer settings → OAuth Apps). Set
   the **Authorization callback URL** to `http(s)://<your-host>/auth/github/callback`.
2. Set the env vars (e.g. in `.env`, then re-up the backend):

   ```bash
   GITHUB_OAUTH_CLIENT_ID=<your client id>
   GITHUB_OAUTH_CLIENT_SECRET=<your client secret>
   GITHUB_OAUTH_REDIRECT_URL=http://localhost:8080/auth/github/callback
   ```

3. `GET /api/console/state` now reports `github_oauth_enabled:true` and
   `GET /auth/github/login` 302-redirects to GitHub.

**Policy — no open self-registration.** On callback the console links the GitHub
identity to an **existing** admin: first by a previously-linked `github_user_id`,
then by the GitHub account's **verified primary email** matching an admin's
email. If no admin matches, the login is **denied (403)** — a GitHub login never
auto-creates an account. The OAuth `state` is verified constant-time against a
dedicated short-lived nonce cookie (CSRF defense), and all GitHub HTTP calls use
a redirect-disabled client (SSRF guard). The GitHub client secret and access
token are never logged or returned in any response.

### Why `SameSite=Lax` (not `Strict`)

The session cookie (`__Host-console_session`) is `SameSite=Lax`, not `Strict`.
The GitHub OAuth callback is a **top-level GET navigation** arriving from
github.com; `Lax` cookies are delivered on top-level GETs, so the session
survives the round-trip. `Strict` has historically been dropped on
cross-site-initiated redirects in some browser engines, which would intermittently
break login from external links. The OAuth `state` is carried in its OWN
short-lived cookie (never in the session cookie), so the session cookie's
SameSite mode does not affect CSRF protection of the OAuth flow.

### Dev escape hatch — `CONSOLE_INSECURE_COOKIES`

The hardened session cookie uses the `__Host-` prefix, which browsers honor only
over HTTPS (it requires the `Secure` attribute). Over plain-HTTP `localhost`,
a **browser** silently drops a `__Host-`/`Secure` cookie, causing a 401 loop
after an apparently successful login. For local browser dev, set:

```bash
CONSOLE_INSECURE_COOKIES=true
```

This drops the `__Host-` prefix and the `Secure` attribute (cookie name becomes
`console_session`) so the cookie survives plain HTTP. **Residual risk:** without
`Secure`, the cookie can be sent over a non-TLS connection — acceptable only on a
trusted local host. Production must keep this **unset** (hardened default) and
terminate TLS at the edge. (The acceptance harness intentionally runs with the
hardened default so it can assert the `__Host-` + `Secure` flags; `curl` receives
the `Set-Cookie` header verbatim because those attributes are browser-enforced,
not transport-enforced.)

### Pre-session origin allowlist (`CONSOLE_ALLOWED_ORIGINS`)

`POST /setup` and `/login` happen before a per-session CSRF token can exist, so
they are additionally guarded by an `Origin`/`Referer` allowlist (comma-separated
`CONSOLE_ALLOWED_ORIGINS`).

**Secure-by-default (IN-04).** The origin check is fully disabled ONLY under the
dev escape hatch — i.e. an empty allowlist *together with* `CONSOLE_INSECURE_COOKIES=1`.
In the production posture (`CONSOLE_INSECURE_COOKIES` unset), an empty allowlist
no longer means "allow any": any **present** cross-site `Origin` is rejected, and
you must set `CONSOLE_ALLOWED_ORIGINS` to your console origin(s) to permit a
browser origin. Requests that carry **no** `Origin` (API clients / server-side
`curl` / same-origin posts that omit it) are still allowed — browser cross-site
CSRF always carries an `Origin`, which is what this guard blocks. Set the
allowlist to your console origin(s) in production for full defense-in-depth.

### Rate-limit residual risk under Docker NAT (WR-01)

The pre-auth rate limiter on `/setup`, `/login`, `/auth/github/callback`, and
`/api/console/state` keys on the **direct connection IP** and deliberately does
**not** trust `X-Forwarded-For` (a forgeable header would let an attacker mint
unlimited buckets and defeat the limit). Under the shipped docker-compose
topology the backend often observes the Docker bridge **gateway IP** as the peer
for all externally originated traffic (published-port NAT / userland proxy), so
the per-IP limiter degrades to a **single global bucket**: it still throttles
total pre-auth request volume but does not isolate per-attacker, and unrelated
legitimate traffic shares the same quota. This is **documented and accepted** for
this milestone (`T-natratelimit`); the correct fix is a vetted reverse proxy that
sets a TRUSTED forwarded header, keyed off ONLY when the immediate peer is the
known proxy — revisit when such a proxy + XFF-trust policy is configured. Until
then the limiter is complemented by the one-time setup token and constant-time
credential checks.

### Verifying Phase 2

```bash
docker compose down -v && docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase2-acceptance.sh   # Git Bash on Windows
docker compose down -v
```

The harness exits `0` only when every criterion passes: the `/setup` token gate
and 404-after-init, the hardened login cookie flags, the 401 on an unauthenticated
protected route, the `/login` rate limit (429), the CSRF guard (403 without
`X-CSRF-Token`, 200 with it), secret-absence in every response body, and the
GitHub env-gating (404 + `github_oauth_enabled:false` when unconfigured).

---

## Service config editing (Phase 4)

Self-hosted Ory has **no live config API** — each service's settings live in a
mounted YAML file (`config/<svc>/...`) and take effect only on restart. Phase 4
adds the backend's transactional config-edit engine behind authenticated
`GET`/`PUT /api/config/<service>/<section>`: it loads the current YAML, applies
only the changes whose JSON-Pointer paths are on a code-defined per-section
**allowlist**, validates the FULL merged doc against the service's JSON Schema
*before* writing, atomically writes it, restarts **only the affected container**
via the scoped restart broker, polls `/health/ready`, and — if the service fails
to come back healthy — **rolls back to the last-known-good** `.bak` and restarts
again. Sensitive keys (`dsn`, `secrets.*`, `serve.admin`, TLS keys, the SMTP
connection URI) are rejected (403) regardless of schema validity; the engine
never writes the env-injected `dsn` to disk.

Verify the whole flow against the live stack:

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase4-acceptance.sh   # Git Bash on Windows
docker compose down -v
git checkout config/kratos/kratos.yml   # restore the file the live apply mutated
```

The gate exits `0` only when all four criteria pass: a valid
`/session/lifespan="24h"` edit applies (200) and restarts **only** `ory-kratos`
(the other three containers' `StartedAt` are unchanged) and Kratos comes back
healthy and a follow-up GET reflects the new value; an invalid value is rejected
`422` with no disk write; a sensitive/out-of-scope key is rejected `403` with no
disk write; and a health-breaking value triggers an auto-rollback to the
last-known-good with the service recovering.

### Caveats (read before editing config in production)

- **Windows / Docker Desktop bind-mount rename atomicity.** The engine writes
  via *temp-file-in-the-same-dir → fsync → atomic rename*, which is atomic on
  native Linux filesystems. On **Windows + Docker Desktop**, `config/` is a host
  bind mount surfaced through the WSL2/9P file-sharing layer, where the rename is
  **not guaranteed atomic** and an interrupted write could in theory leave a
  partial file. The backup-and-rollback path is the safety net (a failed health
  check restores the `.bak`), but for production we recommend placing `config/`
  on a **native-Linux / WSL2 path or a named Docker volume** rather than a
  Windows-host bind mount. (Run the verification harness and compose commands
  from a bash shell with `MSYS_NO_PATHCONV=1` on Git Bash — see the Windows notes
  below.)
- **YAML comments are not preserved across an edit.** The engine round-trips the
  file through a structured (serde) model, so it preserves keys and values but
  **drops comments** and applies a normalized key ordering on write. Keep any
  human-authored documentation for a config value out-of-band (e.g. in this repo
  / your runbook), not as inline comments in a console-editable file.
- **Restart-broker security posture (unchanged from Phase 1).** Config edits
  restart services only through the least-privilege `wollomatic/socket-proxy`
  broker (restart-only, four-container scope, `-allowfrom=backend`); the backend
  holds no Docker socket. The broker has no TLS and a restart is itself a limited
  DoS primitive — both documented and accepted residual risks (`T-notls-broker`,
  `T-restart-dos`) under "Security model & documented residual risks" above.

## Frontend console (Phase 5)

Phase 5 delivers the real Next.js admin console — the shell every later feature
page renders inside — and three reusable primitives (a TanStack DataTable, a
React-Hook-Form + Zod SettingsForm, and a Monaco editor wrapper). The frontend
is the **only** host-published UI; it talks to the Rust backend and **never** to
the Ory services directly.

### Running the console

The console comes up as part of the normal full-stack bring-up — it is the
`frontend` service:

```bash
cp .env.example .env          # fill in the values (see Quick start above)
docker compose up -d --wait   # waits for every service, including the frontend
```

Then open **http://localhost:3000** and complete the day-one flow:

1. **`/setup`** — first run only. Paste the one-time **bootstrap token** (read it
   from the backend logs, see below) and create the first operator account. On
   success you are routed to `/login` (setup does **not** auto-log-in).
2. **`/login`** — sign in with the operator email + password. (A "Sign in with
   GitHub" button appears only when GitHub OAuth is configured — see the Phase 2
   section.) On success you land on the authenticated console shell.
3. **The console shell** — a sidebar of sections (Users, Authentication, OAuth2,
   Permissions, Activity, Branding, Project) and a topbar with the account menu
   (logout + light/dark theme toggle). Feature pages for each section land in
   Phases 6–11; until then a section shows a labeled "Coming in a later phase"
   panel (the navigation is complete; no fake-working controls).

The console is **server-guarded**: the authenticated `(console)` layout performs
an authoritative server-side `GET /api/console/me` on every navigation and
redirects to `/login` whenever there is no valid session — so the shell is
unreachable unauthenticated (a 401 always lands you back on `/login`).

### The bootstrap token (same as Phase 2)

```bash
docker compose logs backend | grep 'FIRST-RUN SETUP TOKEN'
# -> FIRST-RUN SETUP TOKEN: <token>
```

It is regenerated on every uninitialized boot and is single-use; once an admin
exists, `/setup` redirects to `/login` and `GET /api/console/state` reports
`{"initialized":true}`.

### Same-origin `/backend` proxy + the FE-05 no-Ory-egress invariant

The browser bundle contains **no Ory hostname, no admin port, and no Ory SDK** —
a hard invariant (FE-05). The frontend's only backend reference is the literal
same-origin path `/backend/*`: the Next server rewrites those requests to the
internal backend (`BACKEND_INTERNAL_URL`, set to `http://backend:8080` on the
compose `frontend` service). `BACKEND_INTERNAL_URL` is read on the **server
only** — it is never a `NEXT_PUBLIC_` var and never reaches client JS. The
session cookie therefore stays first-party on the frontend origin (no CORS, no
cross-site cookie). This is enforced at build time by
`scripts/verify/bundle-egress.sh`, which greps the built output and fails on any
Ory host/port/SDK literal. See `frontend/.env.example` for the full `BACKEND_INTERNAL_URL` notes.

### Monaco loads from our own origin (no CDN)

The Monaco editor wrapper loads its engine and language workers from the
vendored, same-origin `public/monaco/vs` assets — **never** from jsDelivr/unpkg/
cdnjs. This keeps the console air-gap-friendly and removes a supply-chain egress.
The same `bundle-egress.sh` gate also fails on any CDN host in the built bundle.
See `frontend/MONACO.md` for the local-bundling strategy.

### Security posture — plain-HTTP cookie caveat

Over plain-HTTP `localhost` the hardened `__Host-`/`Secure` session cookie is
silently dropped by browsers, causing a 401 loop after an apparently successful
login. For a local **browser** bring-up set `CONSOLE_INSECURE_COOKIES=true` (the
cookie name becomes `console_session`, without `Secure`); the Phase-5 acceptance
gate exports this for the duration of its ephemeral run. **Production keeps it
unset** and terminates TLS at the edge — see "Dev escape hatch —
`CONSOLE_INSECURE_COOKIES`" and the pre-session origin allowlist notes under the
Phase 2 section, which describe the residual risk in full.

### Verifying Phase 5

A single live gate proves all four phase success criteria against the real stack
and tears it down cleanly afterward (a `trap` runs `docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 bash scripts/verify/phase5-acceptance.sh   # Git Bash on Windows
```

The script: (1) runs `bundle-egress.sh` (FE-05 + the Monaco no-CDN check); (2)
runs the three primitive component suites (FE-02/03/04); (3) builds + brings up
the full stack and waits for the frontend to be healthy; (4) parses the
bootstrap token from `docker compose logs backend` and drives the Playwright
`auth-flow` e2e — `/setup → /login → the authenticated shell`, then drops the
session and asserts the 401 → `/login` redirect (FE-01). It exits `0` only when
every gate passes. The frontend image build is heavy, so the bring-up allows a
generous timeout (override with `UP_TIMEOUT=<seconds>`); pass `KEEP_STACK=1` to
leave the stack up for debugging.

---

## User Management (Phase 6)

Phase 6 delivers the **Users** feature against live Kratos — the first full
vertical slice (typed Rust backend wrappers + Next.js pages) on top of the
Phase-5 shell and primitives. Everything goes through the backend; the frontend
never talks to Kratos directly.

### The Users pages

Open the console (http://localhost:3000) and pick **Users** in the sidebar:

- **List (`/users`)** — a TanStack DataTable of identities with **cursor
  pagination** (keyset, driven by the Kratos `Link` header), search by
  identifier, per-row actions (View / Edit / Delete), and header actions for
  Create / Import / Schema.
- **Detail (`/users/[id]`)** — a read-only view of one identity: traits,
  verifiable/recovery addresses, public + **admin-labeled** metadata, and the
  **credential TYPE names only** (e.g. `password`, `oidc`) — never any secret
  value.
- **Create / Edit (`/users/new`, `/users/[id]/edit`)** — a **schema-driven**
  form generated from the active identity schema's `properties.traits` (text /
  email / boolean / enum / number, with a raw-JSON fallback for exotic types),
  plus public/admin metadata Monaco editors (blank → key omitted). Edit
  **requires** a `state` (active/inactive). Backend `422` field errors surface
  inline.
- **Delete** — a destructive confirm dialog (`DELETE` + cache invalidation).
- **Schema editor (`/users/schema`)** — a Monaco JSON editor with draft-07
  presets; **saving rewrites the identity schema file and restarts Kratos** (see
  below).
- **Bulk import / export (`/users/import`)** — paste or upload a CLI-compatible
  **bare array** of identities; the page validates shape + limits before calling
  the backend, then shows a per-record result table. Export pages the whole list
  to a bare-array JSON download.

### CLI-compatible import/export (the `ory` CLI interchange)

The import/export format is the same **bare array of identity objects** that the
official `ory` CLI's `ory import identities <file>` consumes — each record is a
top-level `{ "schema_id": ..., "traits": { ... }, "credentials"?: { ... } }`
object, **not** wrapped in a `create` envelope. Internally the backend wraps each
record into Kratos' `batch_patch_identities` `{identities:[{create}]}` shape and
unwraps on export, so the console and the CLI can manage the same self-hosted
stack without a format conflict. Export emits only `schema_id` + `traits` (no
credential secrets).

**Import limits (authoritative, server-side).** A batch of **more than 1000**
records is always rejected; a batch of **more than 200** records is rejected when
**any** record carries a **cleartext** password (hashing 200+ passwords inline is
a DoS vector). The frontend mirrors these limits for fast UX feedback, but the
**backend is the source of truth** and re-rejects an over-limit batch with `422`
regardless of what the client allowed.

You can verify real CLI interchange manually (the acceptance gate proves the
shape structurally; the binary round-trip is operator-run):

```bash
# 1. Export from the console: Users -> Import/Export -> Export (a bare-array JSON).
# 2. Install the ory CLI: https://www.ory.sh/docs/guides/cli/installation
# 3. Round-trip it back through the CLI:
ory import identities exported.json    # must accept the file with no format error
```

### Identity-schema editor — restart & rollback

Self-hosted Kratos has **no live schema API**; the identity schema lives in a
mounted file (`config/kratos/identity.schema.json`) and takes effect only on
restart. Saving in the schema editor `PUT`s the whole document to a **dedicated**
backend route that: validates it as a **draft-07** schema **and** requires a
`properties.traits` object; on a valid schema, backs up the current file,
atomically writes the new one, **restarts only the `ory-kratos` container** via
the scoped restart broker, and polls health. If Kratos fails to come back
healthy, the engine **rolls back to the last-known-good** backup and restarts
again. An **invalid** schema is rejected `422` with **no disk write**. Because
this is a dedicated route (not the generic `{service}/{section}` config
allowlist), the editor can only ever touch the schema file — it cannot write an
arbitrary `kratos.yml` key.

### Security posture

- **Credential secrets are never exposed.** Every identity response is shaped to
  strip `credentials.*.config` (password hashes, recovery codes) and
  `credentials.*.identifiers`; only credential **type** names survive. The detail
  page renders type names only, never values.
- **Admin metadata is labeled.** `metadata_admin` is rendered distinctly from
  `metadata_public` so an operator never confuses internal data for
  user-visible data.
- **All routes are auth- and CSRF-gated.** The identity, import, and schema
  routes live on the protected subtree (`401` unauthenticated); every mutation
  (`POST`/`PUT`/`DELETE`) requires the per-session `X-CSRF-Token` (`403`
  without). The frontend's `lib/api.ts` attaches it automatically.
- **No config injection via the schema editor.** The schema PUT cannot write
  arbitrary `kratos.yml` keys — it targets only the fixed schema file, behind
  draft-07 + `properties.traits` validation.
- **Egress invariant holds (FE-05).** All identity/schema/import calls go through
  the same-origin `/backend` rewrite; no Ory host/port/SDK or CDN literal ships
  in the client bundle (`bundle-egress.sh`).

### Verifying Phase 6

Offline (no stack) — backend + frontend gates:

```bash
cd backend && SQLX_OFFLINE=true cargo build --locked && cargo test
cd frontend && npm run typecheck && npm run test
```

Live — a single fail-closed gate proves IDENT-01..04 end-to-end against the real
stack and tears it down cleanly afterward (a `trap` restores the identity schema
and runs `docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend frontend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase6-acceptance.sh   # Git Bash on Windows
# (the gate runs `docker compose down -v` itself on exit; pass KEEP_STACK=1 to keep it up)
bash scripts/verify/bundle-egress.sh   # FE-05 egress (also run inside the gate)
```

The gate exits `0` only when: the **CRUD round-trip** (create → list → get →
update → delete → `404`) holds with **no credential secret** in any detail body;
a small **bulk import** appears in the list and an over-limit batch is rejected
`422`; an exported record matches the **`ory` CLI bare-array shape** (top-level
`schema_id` + `traits`, no `create` wrapper); a **valid schema** edit writes the
file, restarts Kratos, and recovers healthy while an **invalid** schema is
rejected `422` with no disk write; and the **bundle-egress** gate stays clean.
Every negative assertion passes ONLY on the explicit refusal (a `2xx` where a
`4xx` is due is a hard fail). It also echoes the optional manual `ory` CLI
round-trip note above.

---

## Authentication Config (Phase 7)

Phase 7 adds ten Kratos **authentication-config** pages (methods, passwordless,
MFA/AAL, social OIDC, sessions, recovery, verification, SMTP, SMS, web_hooks),
each one a Kratos config **section** edited through the same Phase-4 transactional
engine (lock → allowlist-filter → merge into the full doc → validate against the
pinned v26.2.0 schema with the `dsn` overlay → atomic write + backup → restart
**only Kratos** → health-poll → rollback). Editable secrets are **write-only** in
the UI: the backend masks them on `GET` and merges-by-`id` on `PUT` so an untouched
secret is preserved (never clobbered with the mask sentinel).

### Caveats (read before configuring auth in production)

- **File-secret residual risk.** The editable secrets — the SMTP
  `connection_uri` (set only via the dedicated write-only `/api/kratos/smtp-connection`
  path), per-provider OIDC `client_secret` (and `apple_private_key`), and the SMS
  channel / web_hook `auth` credentials — are written into the mounted
  `config/kratos/kratos.yml` as **operator-managed file secrets**, consistent with
  the self-hosted "YAML + restart" model (self-hosted Ory has no live config API).
  They are masked on `GET` and never echoed/logged, but they live at rest in the
  config file on the host. Treat `config/kratos/kratos.yml` as a secret-bearing file
  (restrict filesystem permissions; keep it out of any image layer or VCS commit).
- **Inline Jsonnet only (`base64://`) — remote-fetch SSRF deferred.** The OIDC
  mapper, the SMS `request_config.body`, and the web_hook `config.body` are Jsonnet
  templates. In Phase 7 the console stores them **inline** as `base64://<b64(source)>`
  (the Monaco editor edits source; the backend encodes/decodes — no fetch). A remote
  `http(s)://` Jsonnet/web_hook URL would cause Kratos to **fetch it at runtime**, an
  SSRF/exfiltration surface; that remote-URL-fetch hardening (allowlist/guard) is an
  accepted-and-**deferred** posture, owned by the Phase-11 webhook dispatcher
  (HOOK-02). Phase 7 deliberately keeps the surface to inline `base64://`.
- **The hard denylist stays non-editable.** `dsn`, `secrets.*`, and `serve.admin`
  remain on the Phase-4 `SENSITIVE_PREFIXES` denylist — a `PUT` of any of them is
  refused `403` on **every** section path with no disk write (the denylist wins over
  any allowlist, and editing `secrets.cipher`/`secrets.cookie` would corrupt stored
  data). The SMTP `connection_uri` is likewise on the denylist for the generic
  section path (`403`) and is writable **only** through its dedicated, masked,
  write-only endpoint.

### Verifying Phase 7

Offline (no stack) — backend allowlist / secret-merge / SMTP-write-only tests:

```bash
cd backend && SQLX_OFFLINE=true cargo build --locked && cargo test --lib config_edit && cargo test --test auth_config -- --skip live
cd frontend && npm run typecheck && npm run test
```

Live — a single fail-closed gate proves a representative key per section group
end-to-end against the real stack and tears it down cleanly afterward (a `trap`
restores `config/kratos/kratos.yml` and runs `docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend frontend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase7-acceptance.sh   # Git Bash on Windows
# (the gate runs `docker compose down -v` itself on exit; pass KEEP_STACK=1 to keep it up)
```

The gate exits `0` only when, for each section group, a write **validates →
persists → restarts only Kratos** (Hydra/Keto/Oathkeeper `StartedAt` unchanged) →
recovers healthy → `GET` reflects the change with **secrets masked**; the OIDC and
SMTP secrets survive an **untouched-secret preserve** round-trip (a mask-echo `PUT`
does not clobber the stored value) while a retyped secret overwrites; an **invalid**
value (bad AAL enum / bad duration) is rejected `422` with **no disk write**; a
**sensitive** key (`/dsn`, `/secrets/*`, `/serve/admin`, or `connection_uri` via the
section path) and an out-of-scope **per-index** OIDC pointer are refused `403`;
unauthenticated / no-CSRF writes are refused `401` / `403`; and the
**bundle-egress** gate stays clean. Every negative assertion passes ONLY on the
explicit refusal (a `2xx` where a `4xx` is due is a hard fail).

### Verifying Phase 8 — OAuth2 / Hydra (`OAUTH2-01..08`)

A single fail-closed gate proves both Hydra planes end-to-end against the real
stack and tears it down cleanly afterward (a `trap` restores
`config/hydra/hydra.yml` and runs `docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend frontend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase8-acceptance.sh   # Git Bash on Windows
# (the gate runs `docker compose down -v` itself on exit; pass KEEP_STACK=1 to keep it up)
```

The gate exits `0` only when:

- **Data plane (`OAUTH2-01`).** An OAuth2 client is created (the one-time
  `client_secret` is captured from the create response), a `GET` masks both
  `client_secret` and `registration_access_token`, and the client is deleted
  (`204`).
- **`#2869` empirical secret-preserve (the headline correctness requirement).**
  The captured secret mints a `client_credentials` token, a **non-secret `PUT`**
  (a rename, secret omitted) is applied, and the **same original secret still
  mints a token afterward** — proving the stored secret survived the edit. This is
  proven by re-authenticating (not merely a `200` on the `PUT`); a regenerated /
  blanked secret would fail with `invalid_client` and **fail** the gate. Tokens are
  minted against Hydra's public `/oauth2/token` **from inside the `ory-hydra`
  container** because the Ory ports are host-internal (`INFRA-05`).
- **Data plane (`OAUTH2-02`).** The minted token introspects `active`, is
  **revoked** (the single CSRF-guarded state change), then introspects
  `inactive`; an unknown token introspects `active:false` (a `200`, not an error).
- **Config plane (`OAUTH2-03..08`).** A representative key per section
  (`general` issuer, `ttl` access-token, `strategies` access-token, `cookies`
  same-site) **validates → persists → restarts only Hydra** (Kratos/Keto/Oathkeeper
  `StartedAt` unchanged) → recovers healthy → `GET` reflects; the `oidc`
  `pairwise.salt` reports presence only (`{set:bool}`, never the value).
- **Negatives.** An invalid value (bad enum / bad duration) is rejected `422`
  with **no disk write**; a sensitive key (`/dsn`, `/secrets/system/*`,
  `/serve/admin/*`) is refused `403`; unauthenticated / no-CSRF writes on the new
  routes are refused `401` / `403`. Every negative passes ONLY on the explicit
  refusal.

**CLI-interchange method.** The gate asserts the created client JSON carries the
crate `OAuth2Client` field names the `ory` CLI consumes (`client_id`,
`grant_types`, `response_types`, `token_endpoint_auth_method`, …) — both are
generated from the same Hydra OpenAPI spec. If the `ory` CLI binary is present in
`PATH` the gate also round-trips the JSON through it; otherwise the field-shape
assertion is the interchange proof (the CLI is not a build dependency).

**`--dev` cross-reference.** Hydra runs with `--dev` (`T-08-DEV`) so the gate's
`http://localhost:4444/` issuer is accepted and tokens mint over plain HTTP on the
internal-only public port. See "Hydra boot mode — `--dev` residual risk" below for
the production-mode (https-issuer behind TLS) migration path.

---

## Permissions (Keto) & Access Rules (Oathkeeper) (Phase 9)

Phase 9 adds four operator surfaces for the permission system and the access proxy,
all routed through the Rust backend (the frontend never talks to Keto/Oathkeeper
directly — `FE-05`):

- **Relationships** (`PERM-02`/`PERM-03`) — a server-paged table of relation
  tuples with namespace / object / relation / subject filters, a create-tuple form,
  and an exact-tuple delete.
- **Check & Expand** (`PERM-03`) — enter a namespace / object / relation / subject
  and get an `allowed` / `denied` verdict, or expand a relation to its subject tree.
- **Permission Model** (`PERM-01`) — a Monaco editor for the Ory Permission
  Language (OPL) `namespaces.ts` model, with a pre-save syntax check.
- **Access Rules** (`OATH-01`) — a Monaco editor for the Oathkeeper `rules.json`
  access-rule array.

### The Keto three-port split (the correctness model)

Keto serves three **distinct** ports, and the backend routes every call to the
exact one — routing a write to the read port (or vice-versa) is a `404`/`405`:

| Port    | Purpose                       | Backend operations                         |
| ------- | ----------------------------- | ------------------------------------------ |
| `:4467` | **write**                     | create / delete relation tuples            |
| `:4466` | **read**                      | list / query / **check** / **expand**      |
| `:4469` | **OPL syntax**                | the Permission-Model pre-save syntax check |

These ports are **internal-only** (`INFRA-05`); the console reaches them only from
inside the compose network.

### Permission Model editor — pre-save OPL validate, then restart Keto ONLY

The Permission-Model editor runs a **pre-save syntax check against Keto `:4469`**
and writes `config/keto/namespaces.ts` **only on a clean parse** — an OPL with a
syntax error is rejected `422` with **no file write** (the byte-identical file is
the proof). On a clean parse it atomic-writes the raw OPL text and **restarts Keto
ONLY** (Kratos/Hydra/Oathkeeper `StartedAt` unchanged); if Keto fails to come back
healthy it **rolls back** to the last-known-good `.bak` and re-restarts. The file is
written as **raw TypeScript-like OPL text** — never YAML- or JSON-serialised.

### `permits`-function-name-as-relation (OPL permission checks)

For an **OPL-defined permission**, the check API is relation-agnostic: you pass the
**`permits`-function name** from the model (e.g. `view`) as the `relation` argument
to Check — there is no separate "permission-by-name" endpoint. This is the one
Keto behaviour with no code analog; it is **empirically confirmed live** by the
Phase-9 gate (define a model with a `permits` function, create the backing tuple,
then check with the function name as the relation → `allowed:true`).

### Access Rules editor — write `rules.json`, then restart Oathkeeper ONLY

The Access-Rules editor structurally pre-checks that the body is a **JSON array**
(a non-array is `422` with no write), writes `config/oathkeeper/rules.json`, and
**restarts Oathkeeper ONLY**. The post-restart `api_api` rule list (port `4456`)
is the authoritative confirmation that the new rules took effect.

> **Oathkeeper readiness finding (`A1`).** The restart health-poll uses
> **`/health/alive`, not `/health/ready`**, for Oathkeeper. Its `/health/ready`
> returns `503` for this stateless, from-file configuration ("its readiness
> reporter has no satisfiable dependency to report on"), so polling `/health/ready`
> would have **falsely rolled back every valid rules write**. The backend carries a
> per-service health-path override (`restart::Service::health_path`) so Oathkeeper
> alone polls `/health/alive`; the other services keep `/health/ready`.

### CLI interchange (`CLI-01`)

Relation tuples and access rules use the **same JSON shapes the `ory`/`keto` CLI
consumes** (both are generated from the same OpenAPI specs): a tuple carries
`namespace` / `object` / `relation` + `subject_id` | `subject_set`
(`namespace:object#relation@subject`); rules are a JSON array of rule objects. The
console and the CLI can therefore manage the same self-hosted stack without format
conflict.

### Verifying Phase 9 — Permissions / Access Rules (`PERM-01..03` / `OATH-01`)

A single fail-closed gate proves both Keto planes and the Oathkeeper rules plane
end-to-end against the real stack and tears it down cleanly afterward (a `trap`
restores `config/keto/namespaces.ts` + `config/oathkeeper/rules.json` and runs
`docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend frontend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase9-acceptance.sh   # Git Bash on Windows
# (the gate runs `docker compose down -v` itself on exit; pass KEEP_STACK=1 to keep it up)
```

The gate exits `0` only when:

- **`PERM-01`.** An invalid OPL is rejected `422` with `namespaces.ts` **byte-
  unchanged** (no write); a valid OPL **validates → persists → restarts only
  Keto** → recovers healthy → `GET` reflects the saved model.
- **`PERM-02`/`PERM-03`.** A relation tuple is **written** (`:4467`), **read back**
  (`:4466`, proving the port split), **checked** (`allowed:true`; an absent subject
  is a normal `200 {allowed:false}`, never a `502`-as-denied), **expanded** (the
  subject appears in the tree), and **deleted** by the exact filter set — with a
  sibling tuple confirmed **still present** afterward (an over-broad delete fails
  the gate).
- **`PERM-03` permits-as-relation.** A check passing the **`permits`-function
  name** as the relation returns `allowed:true` for the subject with the backing
  tuple (and `false` for one without) — the empirical confirmation on the live
  `oryd/keto:v26.2.0` image.
- **`OATH-01`.** A valid rules array **persists → restarts only Oathkeeper** →
  recovers healthy (via `/health/alive`) → the `api_api` rule list reflects the new
  rule; a non-array body is rejected `422` with `rules.json` **unchanged**.
- **Negatives.** Unauthenticated reads/writes are refused `401`; authenticated
  writes without `X-CSRF-Token` are refused `403` (create / delete / validate /
  model / rules); a sensitive key (`/dsn`) via the generic config route is refused
  `403` with **no disk write**; and the **bundle-egress** gate stays clean. Every
  negative passes ONLY on the explicit refusal.

---

## Activity, Branding & CLI Compatibility (Phase 10)

Phase 10 adds the Activity surfaces (Kratos **Sessions** + **Courier Messages**),
the Branding surfaces (**Email Templates**, **UI URLs**, a **Console Logo** upload,
and three labeled gated pages), and verifies **CLI data-plane interchange**
(`CLI-01`). It is overwhelmingly a *composition* phase reusing the Phase-3 typed
Kratos wrappers, the Phase-4 transactional config engine, and the Phase-5/8/9
frontend primitives.

### Caveats (read before relying on Phase-10 surfaces)

- **The Console Logo is CONSOLE branding only — it is NEVER written to any Ory
  service or config.** The upload (`POST /api/console/branding/logo`) stores the
  asset on the mounted console-data volume under a **server-defined canonical
  path** (the client filename never enters the path — no traversal), accepts a
  file only after a **magic-byte sniff of the actual bytes** (PNG/JPEG/ICO + an
  SVG text sniff — the spoofable `Content-Type` header is never the accept gate),
  caps the size before reading, and serves it back with a pinned content-type and
  `Content-Security-Policy: sandbox` so a stored SVG can never execute script as
  console-origin active content. It makes **no Ory call**.
- **Email templates use an inline `base64://` mechanism.** The Monaco editor edits
  **raw** template text; the backend base64-encodes it into the Kratos
  `courier.templates.*` URI value on save and base64-decodes on load, so the
  editor always shows raw text while `kratos.yml` stores a schema-valid
  `base64://…` URI. (The alternative `courier.template_override_path` directory
  mechanism is not used.)
- **The logout flow has NO `ui_url`.** The UI-URLs allowlist deliberately omits
  `/selfservice/flows/logout/ui_url` — that key does not exist in the Kratos
  v26.2.0 schema (`additionalProperties:false`), so including it fails validation
  and bricks the save. A PUT that includes it is refused `403` (not in the
  allowlist). If a logout redirect is ever wanted, use
  `/selfservice/flows/logout/after/default_browser_return_url` instead.
- **Session revoke is a single-session deactivate.** Revoking a session calls
  `disable_session(id)` (the session shows `active:false`, data retained), NEVER
  `delete_identity_sessions` (which would irrecoverably delete **every** session
  for the identity). Courier messages are **read-only** (a delivery log — no
  create/update/delete affordance).
- **`CLI-01` is data-plane only.** The console verifies that the identity
  import/export bare-array (`[{schema_id, traits, credentials?}]`), the OAuth2
  client JSON, and the Keto relation-tuple shapes are **interchangeable with the
  official `ory`/`keto` CLI field shapes**. Because the per-service Ory crate
  models are generated from the same OpenAPI specs the CLI consumes, **field-shape
  equality is the authoritative interchange guarantee** and runs with no external
  binary. A real `ory`/`keto` CLI binary, if present in the gate environment, is
  used for an OPTIONAL stronger round-trip — it is never required. The CLI's
  **config**-plane commands target Ory **Network** and are out of scope.

### Verifying Phase 10 — Activity / Branding / CLI (`ACT-01/02` / `BRAND-01..06` / `CLI-01`)

A single fail-closed gate proves the data plane, the Kratos-only config plane, the
console asset store, the gated pages, and the CLI interchange end-to-end against
the real stack and tears it down cleanly afterward (a `trap` restores
`config/kratos/kratos.yml` and runs `docker compose down -v`):

```bash
docker compose down -v
MSYS_NO_PATHCONV=1 docker compose build backend frontend
MSYS_NO_PATHCONV=1 docker compose up -d --wait
MSYS_NO_PATHCONV=1 bash scripts/verify/phase10-acceptance.sh   # Git Bash on Windows
# (the gate runs `docker compose down -v` itself on exit; pass KEEP_STACK=1 to keep it up)
```

The gate exits `0` only when:

- **`ACT-01`.** `GET /api/kratos/sessions?active=active|inactive` returns the
  `{rows, next_token, total}` envelope; a session (when one exists) is **revoked**
  via the single-session `disable_session` and re-appears on the inactive page.
- **`ACT-02`.** `GET /api/kratos/courier/messages?status=…&recipient=…` returns the
  filtered envelope; the courier surface is **read-only** (a write verb is
  `404/405`).
- **`BRAND-01`/`BRAND-02`.** A raw email-template edit and a UI-URL edit each
  **persist → restart only Kratos** (the other three Ory containers' `StartedAt`
  are unchanged) → recover healthy → `GET` reflects the change (the template GET
  returns **raw** text, never a `base64://` blob); a PUT including `logout/ui_url`
  is refused `403`.
- **`BRAND-03`.** A valid PNG **uploads** and is **served back** with an `image/*`
  content-type and `Content-Security-Policy: sandbox`; a content-type-spoofed
  non-image is **rejected** (`4xx`) and the previously-stored asset is **still
  served** (the reject wrote nothing).
- **`BRAND-04/05/06`.** Each gated page carries the **"Not available"** label and a
  CTA link and has **no CRUD form control** (anti-dead-CRUD).
- **`CLI-01`.** The frontend + backend **field-shape** suites are green
  (authoritative); an optional real CLI binary round-trip runs only when a binary
  is present.
- **Negatives.** Unauthenticated reads/writes are refused `401`; authenticated
  writes without `X-CSRF-Token` are refused `403` (revoke / config PUT / logo
  upload); a sensitive key (`/courier/smtp/connection_uri`) is refused `403` with
  **no disk write**; and the **bundle-egress** gate stays clean. Every negative
  passes ONLY on the explicit refusal.

---

## Webhooks, Console Features & Gated Pages (Phase 11)

Phase 11 adds the console's **own** webhook dispatcher (an outbound delivery
queue with HMAC signing and an SSRF guard — `HOOK-01/02/03`), plus the remaining
console-owned surfaces: an append-only **audit log** (`ACT-04`), a per-service
**Overview** of version + health (`PROJ-01`), a derived **Activity** feed
(`ACT-03`), one-way-hashed console **API keys** (`PROJ-02`), a **Members** list
(`PROJ-04`), and three labeled **gated pages** — Event streams (`PROJ-03`),
Organizations (`ORG-01`), and SAML Sign-In (`AUTH-05`).

### Caveats (read before relying on Phase-11 surfaces)

- **The webhook dispatcher is the console's OWN dispatcher — NOT an Ory hook.**
  Self-hosted Ory has no webhook/actions primitive, so the queue, signing, retry,
  and delivery log all live in the backend's own `console` Postgres schema
  (`webhooks` + `webhook_deliveries`). A boot-spawned worker claims due rows
  (`FOR UPDATE SKIP LOCKED`), delivers them, and records the outcome.
- **SSRF guard posture (the security headline, `HOOK-02`).** A webhook URL is
  operator input crossing the highest-risk outbound trust boundary. The guard
  **resolves the host and validates EVERY resolved IP** against a deny set
  (loopback / RFC1918 private incl. the docker bridge / link-local incl.
  `169.254.169.254` cloud metadata / ULA / CGNAT / benchmarking / IPv4-mapped-IPv6)
  at **webhook create** (fast `422`) **and again, authoritatively, at delivery
  time** (DNS-rebind defense). At delivery it **pins** the connection to the
  just-validated addresses (`resolve_to_addrs`, closing the TOCTOU window) and
  **following redirects is intentionally OFF** (`redirect(Policy::none())`) in v1 —
  a `3xx` to an internal `Location` is never followed; it is recorded as a non-2xx
  failure. A blocked target is an **explicit recorded failure**, never a silent
  no-op. (The std `is_global`/`is_shared`/`is_benchmarking` classifiers are
  nightly-only on the pinned stable Rust, so the guard is composed from stable
  classifiers + a couple of manual octet ranges — see the SSRF module header.)
- **The webhook signing secret is stored RECOVERABLE, the API key one-way hash.**
  The per-webhook HMAC secret must be readable by the worker to **re-sign every
  delivery**, so it is stored recoverably (column `secret`, never `secret_hash`).
  It is **write-only over the API**: it is revealed exactly **once** in the
  create/rotate response and never again — `GET`/list return only a `secret_set`
  badge. By contrast, console **API keys are one-way SHA-256 hashed at rest**
  (`PROJ-02`): the raw key is shown once on issue and is unrecoverable thereafter
  (list shows a masked `prefix••••`; revoke flips the state to `Revoked`).
- **Signature header.** Each delivery carries
  `X-Console-Signature: sha256=<hex>` — `HMAC-SHA256(secret, raw_request_body)`.
  A receiver verifies a delivery by recomputing the HMAC over the exact body bytes
  with its copy of the secret. The delivery id is stable across retries so a
  receiver can dedupe.
- **Retry / backoff / dead-letter and retention (chosen v1 defaults, `HOOK-01/03`).**
  A failed delivery retries with exponential backoff (**base 30 s × 2^attempt,
  capped at 1 h**) and becomes terminal **`dead` at `max_attempts` (default 8)**.
  Terminal rows (`delivered`/`dead`) are pruned after a **30-day** retention
  window by an hourly maintenance task (which also reaps rows stuck `delivering`
  past a crash). These are tunable defaults, not hard limits.
- **The audit log is append-only and console-only.** A response-phase hoop on the
  protected subtree records every state-changing console request (actor read from
  the **session**, never client input; method; path; outcome). There is a
  read-only list view and an age-based backend prune — and **deliberately no
  create/update/delete-by-id route**. It records **console** actions only, not Ory
  service events.
- **Members and API keys are CONSOLE accounts/keys, not Ory primitives.** Members
  lists the console operator accounts (mapped to a secret-free DTO — no
  `password_hash` ever leaves Postgres); API keys are credentials for **this
  backend**, not Ory credentials. To manage end users, use the Users pages.
- **SAML / Organizations / Event-streams are clearly-labeled gated pages.** They
  are static server components that render a labeled explanation + a CTA and make
  **no backend call** (Organizations + SAML link out to the Ory docs; Event
  streams links inward to the built-in Webhooks page). They are intentionally not
  CRUD stubs.
- **The acceptance echo receiver is test-only.** `docker-compose.yml` defines an
  `echo-receiver` sidecar **behind the `acceptance` compose profile** and **only
  on the internal network** (never host-published). A normal `docker compose up`
  does **not** start it; it exists solely as the delivery success target for the
  Phase-11 gate. That gate also sets a **double-gated, test-only**
  `WEBHOOK_ALLOW_PRIVATE_TARGETS` so the worker can reach the internal (RFC1918)
  echo — it is honored **only** together with `CONSOLE_INSECURE_COOKIES`, so it can
  never relax the SSRF guard in production, and the pin + redirects-off hardening
  applies regardless.

### Verifying Phase 11 — Webhooks / Console / Gated (`HOOK-01/02/03` / `ACT-03/04` / `PROJ-01..04` / `ORG-01` / `AUTH-05`)

A single fail-closed gate brings up the full stack **plus the internal echo
sidecar** (the `acceptance` profile), proves every requirement end-to-end, and
tears the stack down cleanly afterward (`docker compose --profile acceptance
down -v` on exit):

```bash
docker compose --profile acceptance down -v
MSYS_NO_PATHCONV=1 bash scripts/verify/phase11-acceptance.sh   # Git Bash on Windows
# (the gate does the full build -> up --wait -> drive -> down -v itself;
#  pass KEEP_STACK=1 to keep the stack up for debugging)
```

The gate exits `0` only when:

- **`HOOK-01/02/03` delivery + HMAC.** A webhook created against the internal echo
  receiver delivers successfully (`status=delivered`, `last_status_code=200`), and
  the gate **recomputes the HMAC-SHA256 over the exact stored payload bytes and
  confirms it matches** the `X-Console-Signature` the receiver actually recorded —
  a genuinely valid signature, not merely a present header.
- **`HOOK-02` SSRF (anti-false-green).** Creating a webhook at `169.254.169.254`,
  `127.0.0.1`, and an internal Ory admin `host:port` is each refused with an
  explicit **`422`**; a delivery whose target is rebound to a metadata address at
  delivery time is **blocked** — it never reaches `delivered`, the echo receiver
  records **no hit** for it, and a `last_error` reason is recorded (never a silent
  pass).
- **`HOOK-01` backoff → dead.** A delivery to a failing target records a failure,
  schedules a retry with `next_attempt_at` pushed into the future (exponential
  backoff), and reaches the terminal **`dead`** state at `max_attempts` (observed
  deterministically without waiting the full backoff).
- **`PROJ-02`.** An API key is **issued** (raw shown once), **masked** on the list
  (the raw never re-appears), and **revoked** (state → `Revoked`).
- **`ACT-04`.** The state-changing webhook create is recorded in the **audit log**
  with the authenticated admin as the actor and `outcome=success`.
- **`PROJ-01` / `ACT-03` / `PROJ-04`.** `GET /api/overview` reports a version +
  health for all four services; `GET /api/activity` returns a derived list
  envelope (v1); `GET /api/console/members` lists ≥1 operator with **no
  `password_hash`**.
- **`PROJ-03` / `ORG-01` / `AUTH-05`.** Each gated page carries labeled
  `GatedFeature` copy + a CTA and has **no CRUD form control and no backend call**.
- **Negatives.** Unauthenticated reads/writes are refused `401`; authenticated
  state changes without `X-CSRF-Token` are refused `403`; the webhook **secret is
  never present** in any `GET`/list response; and the **bundle-egress** gate stays
  clean. Every negative passes ONLY on the explicit refusal.

---

## Feature toggles (Phase 12)

Console v2 features are gated by **DB-backed feature flags**, the single
console-owned source of truth for which optional features are enabled. The flags
live in the `feature_flags` table (migration `0007`, in the backend's own
`console` Postgres schema) — one row per known feature: `key`, `enabled`,
`updated_at`.

### Seeded defaults

The migration seeds the known set idempotently (`ON CONFLICT DO NOTHING`, so a
re-run or partial-apply on an existing volume leaves operator toggles intact):

| Flag | Default | Notes |
|------|---------|-------|
| `saml` | **OFF** | External-setup feature (Phase 13/14) |
| `organizations` | **OFF** | External-setup feature (Phase 14) |
| `account_experience` | **OFF** | External-setup feature (Phase 15) |
| `observability` | **OFF** | `requires_runtime` — store-only this phase (see below) |
| `event_streams` | **OFF** | External-setup feature (Phase 17) |
| `opl_live_validation` | **ON** | The one in-place enhancement, on by default |

The human **label** and the `requires_runtime` marker are **not** columns — they
live in a code-side `FEATURE_META` constant map in `backend/src/features/mod.rs`,
so adding a flag later is a code + seed edit, not a schema migration.

### Management surface + API contract

The operator manages flags from the **`/project/features`** page — a Switch list
where each toggle fires immediately (optimistic, no Save button). It talks only
to the backend through `lib/api.ts` (same-origin, CSRF-echoed; no Ory egress).

- `GET /api/console/features` — returns the seeded set joined with metadata:
  `{ "features": { "<key>": { "enabled": bool, "label": string, "requires_runtime"?: true } } }`.
  Authenticated (`auth_guard` → `401` unauth); GET, so CSRF-exempt.
- `PUT /api/console/features/{key}` — body `{ "enabled": bool }`; toggles the flag,
  refreshes the in-process cache, and returns the new state. State-changing, so it
  requires `X-CSRF-Token` (`csrf_guard` → `403`) and is **auto-audited** by the
  response-phase audit hoop (actor read from the **session**, never client input).
  An **unknown key returns `404`** — the handler never creates an arbitrary row
  from caller input. These management routes are themselves **never** flag-gated
  (they manage the flags).

### Enforcement is SERVER-SIDE (the keystone)

Gating is **not** a hidden nav item. Each gated feature's protected route sits
behind a parameterized `FeatureFlagHoop` mounted **inside** the protected subtree,
**after** `auth_guard` and `csrf_guard`. When the flag is OFF the hoop returns
**`404`** (not `403`, so a disabled feature does not advertise its existence) and
short-circuits — so a flag-OFF route is unreachable **even with a valid session
cookie and a matching `X-CSRF-Token`**. The cache is **fail-closed**: any miss or
poisoned lock reads as disabled, and it is loaded at boot (after migrate, before
serve) so no gated route is ever reachable with an empty cache. The frontend
nav-hide + `FeatureGate` wrapper are additive cosmetics only; the authoritative
gate is always the backend hoop.

The previous **`GatedFeature` "requires Enterprise License"** pattern has been
**retired** (`FLAG-03`): the live acceptance gate asserts no `GatedFeature` /
`gated-feature` import remains anywhere in the frontend. Its former pages
(SAML, Organizations, Event streams, and the three branding pages) are now neutral
`FeatureGate` placeholders that real implementations land into in Phases 13–17.

### `requires_runtime` is store-only this phase

A flag marked `requires_runtime` (currently only `observability`) needs a runtime
component — a compose profile — to be running. **This phase only STORES that
marker**: turning such a flag ON persists the toggle and returns `2xx`, and it
**never `502`s** — there is no health-probe or proxy path here. Phase 16 wires the
profile health probe for `observability`; until then the marker is purely
informational (the `/project/features` page shows a hint when a runtime-dependent
flag is ON).

### Verifying Phase 12 — Feature toggles (`FLAG-01..04`)

A single fail-closed gate brings up the full stack, proves every requirement
end-to-end, **re-runs the three v1 invariants** (INFRA-05 / BACK-05 / BACK-01),
and tears the stack down cleanly afterward:

```bash
MSYS_NO_PATHCONV=1 bash scripts/verify/phase12-acceptance.sh   # Git Bash on Windows
# (the gate does the full build -> up --wait -> drive -> down -v itself;
#  pass KEEP_STACK=1 to keep the stack up for debugging)
```

The gate exits `0` only when:

- **`FLAG-01` (keystone).** With `saml` seeded OFF, a `POST /api/features/_probe`
  carrying a **valid session cookie AND a matching `X-CSRF-Token`** returns **`404`**
  (never `401`/`403`/`200`) — server-side enforcement past both guards. Flipping
  `saml` ON makes the same gated route serve `200`; restoring it OFF re-closes the
  gate (the toggle is live, not cached-open). `saml` is restored to its seeded
  default at the end.
- **`FLAG-02`.** `GET /api/console/features` returns all six seeded keys, each with
  `enabled` + a `label`; `observability` carries `requires_runtime:true`.
- **`FLAG-04`.** A `PUT` flips a flag and a re-GET reflects it; an **unknown key →
  `404`**; `observability=true` returns `2xx` and **never `502`**; the toggle is
  recorded in the **audit log** with the authenticated admin as the actor.
- **`FLAG-03`.** No `GatedFeature` / `gated-feature` import remains in the frontend.
- **v1 invariants.** No Ory Admin port is host-published (`INFRA-05`); restarts
  route only through the scoped socket-proxy and the backend holds no socket
  (`BACK-05`); the **bundle-egress** gate is clean (`BACK-01`).
- **Negatives.** Unauthenticated `GET` is refused `401`; an authenticated `PUT`
  without `X-CSRF-Token` is refused `403`. Every negative passes ONLY on the
  explicit refusal.

---

## Ory Polis — SAML bridge (Phase 13)

[Ory Polis](https://www.ory.sh/docs/polis) is the SAML→OAuth2/OIDC bridge that
lets the stack accept enterprise SAML identity providers and present them to
Kratos as a single OIDC provider. It runs as the `polis` compose service and is
managed entirely through the backend — the frontend never talks to it directly.

### Image pin — `boxyhq/jackson:26.2.0` (and the `ory/polis` 404 caveat)

Ory Polis **is** BoxyHQ Jackson, re-versioned into the Ory `v26.2.0` line. At the
time this was wired (2026-05-26) the **`ory/polis` Docker Hub repository returns
404** and `ghcr.io/ory/polis:v26.2.0` denied anonymous auth, so the service is
pinned to the registry-pullable, manifest-verified **`boxyhq/jackson:26.2.0`**
(no `:latest`, per `INFRA-04`). **Re-verify the canonical image at deploy time** —
if Ory later publishes `ory/polis` under the `v26.2.0` line, prefer it and keep
the tag in lockstep with the other Ory images.

### ENV-configured (NOT YAML) — a dedicated settings writer

Unlike Kratos/Hydra/Keto/Oathkeeper, **Polis has no mounted JSON-Schema'd YAML**;
it is configured purely through environment variables. The console therefore edits
it with a **dedicated `KEY=value` settings writer** (`/api/config/polis`, persisting
to `config/polis/settings.env`), **not** the Phase-4 `{service}/{section}` YAML
schema engine. Only a small, fixed allowlist of **non-secret** keys is editable
(`LOG_LEVEL`, `OPENID_REDIRECT_EXACT_MATCH`, telemetry toggles); a valid edit
restarts **only** the `polis` container and rolls back on a failed health probe.
The `/api/config/polis` route is gated behind the `saml` **feature flag** (seeded
OFF) — it server-side `404`s until an operator enables `saml`.

### Single public issuer — split-horizon (Pattern A)

Polis derives **every** OIDC discovery / OAuth endpoint from one base, `EXTERNAL_URL`.
That single public issuer URL **must be reachable identically by the browser AND by
Kratos server-side** (split-horizon, Pattern A) — set it to your public edge origin
(e.g. `https://sso.example.com`), reachable on both the user's browser and the
internal network. **The exact Kratos→issuer egress wiring (and the SAML provider
entry) lands in Phase 14**; Phase 13 ships the running, console-configurable bridge.

### Write-only, IMMUTABLE-after-first-boot secrets

`DB_ENCRYPTION_KEY` and `OPENID_RSA_PRIVATE_KEY` (with its matching public key) are
**deploy-time secrets the console can never mint, read back, or rotate** (`BACK-07`).
They are write-only: the settings writer **explicitly refuses** any PUT touching a
secret key (`403`), and a GET never reads them into a returnable value. They are
**IMMUTABLE after first boot** — rotating `DB_ENCRYPTION_KEY` strands every encrypted
connection row, and rotating the RSA private key invalidates every already-issued
token. Generate them once, set them in `.env`, and never change them:

```bash
# 32-byte base64 secrets:
openssl rand -base64 32   # -> POLIS_DB_ENCRYPTION_KEY  (immutable!)
openssl rand -base64 32   # -> POLIS_NEXTAUTH_SECRET
openssl rand -base64 32   # -> POLIS_API_KEY (or a strong token)
# RS256 keypair, base64-encoded onto single env lines (private key immutable!):
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out polis.key
openssl pkey -in polis.key -pubout -out polis.pub
base64 -w0 polis.key   # -> POLIS_OPENID_RSA_PRIVATE_KEY
base64 -w0 polis.pub   # -> POLIS_OPENID_RSA_PUBLIC_KEY
```

### Internal-only admin/OIDC port (`INFRA-05`)

Polis serves its admin **and** OIDC surface on port **`5225`, which is never
host-published** — there is no `ports:` entry on the `polis` service. The backend
is the **sole** admin client (it reaches `http://polis:5225` over the `internal`
network using `Authorization: Api-Key`); browsers reach the *issuer* only via your
operator edge proxy. The service is **dual-homed** (`internal` + `edge`): `internal`
so Kratos and the backend can reach it, `edge` so the public issuer is routable.

### Fresh-volume requirement (Pitfall 2)

The `polis` logical Postgres database + least-privilege role are created by
`db/init/01-init.sql` **only on a fresh-volume first boot**. If you add Polis to a
stack that already has a populated Postgres volume, the init script does **not**
re-run and Polis will fail to connect. Bring the new service up on a fresh volume:

```bash
docker compose down -v && docker compose up -d --wait
```

(This is the standard `db/init` first-boot caveat — see the Quick-start fresh-volume
note above.)

### Verifying Phase 13 — Ory Polis (`SSO-01`)

A single fail-closed gate brings up the full stack **incl. Polis on a fresh volume**,
proves `SSO-01` end to end, **re-runs the three v1 invariants** (INFRA-05 / BACK-05 /
BACK-01) with Polis present, and tears the stack down cleanly afterward:

```bash
MSYS_NO_PATHCONV=1 bash scripts/verify/phase13-acceptance.sh   # Git Bash on Windows
# (the gate does the full build -> up --wait -> drive -> down -v itself, and
#  GENERATES throwaway Polis secrets for its ephemeral run; pass KEEP_STACK=1 to
#  keep the stack up for debugging)
```

The gate exits `0` only when:

- **Polis healthy.** The `polis` container reaches Docker `healthy` on a fresh
  `docker compose up --wait`.
- **`INFRA-05`.** Port `5225` is **not host-published** (`docker inspect` shows no
  host binding AND a host connect to `:5225` is **refused**), while it remains
  reachable internally from the trusted backend container.
- **`BACK-05`.** The running restart-broker **allows** a scoped `polis` restart but
  **denies** list / stop / other-container restarts; the backend (and `polis`) hold
  **no** Docker socket.
- **Dual-homed.** `polis` is attached to **both** the `internal` and `edge` networks.
- **`saml` gate.** With a valid session + CSRF, `GET`/`PUT /api/config/polis` returns
  **`404`** while `saml` is OFF, and is **reachable** (`200`) once `saml` is flipped
  ON; a write-only **secret** key on `PUT` is refused **`403`**. `saml` is restored
  to its seeded default (OFF) at the end and the gate re-closes.
- **Polis-only restart.** A valid non-secret `PUT /api/config/polis` restarts **only**
  the `polis` container (every other container's `StartedAt` is unchanged) and the
  edit round-trips on a re-GET.
- **v1 invariants.** INFRA-05 (Ory admin ports), BACK-05 (broker scope), and BACK-01
  (bundle-egress: no Ory/Polis host/port/SDK in the built bundle) all re-run green.

Every negative passes ONLY on the explicit refusal (anti-false-green). The
cross-network issuer-reachability check is an **advisory echo** this phase (Phase 14
wires the Kratos egress).

---

## SAML Sign-In & Organizations (Phase 14)

Phase 14 turns the Phase-13 Polis bridge into two operator-facing features —
**SAML Sign-In** (connect an enterprise SAML IdP) and **Organizations**
(map verified email domains to an SSO connection). Both are **fully open-source,
no license or "Enterprise" tier required**: the pages carry zero upsell copy and
are gated only by the `saml` / `organizations` feature flags (seeded OFF).

Manage them under **Authentication → SAML Sign-In** and **Project → Organizations**.
The frontend talks only to the Rust backend (`lib/api.ts`); the backend is the
sole client of the Polis admin API — the browser never reaches Polis or Kratos.

### How SAML Sign-In works (the trust model)

A SAML connection wires an IdP into the stack as a single Kratos OIDC provider,
**via Polis**:

```
operator → console (SAML page) → backend → Polis /api/v1/sso  (connection minted)
                                          → Kratos providers[]  (generic OIDC entry)
end-user login → Kratos → Polis (OIDC) → SAML IdP → back to Kratos
```

The backend keys every connection by `(tenant, product)` where **`product` is the
fixed string `"ory-console"`** and **`tenant` is the connection's stable id** (the
Organization id from Phase 15 onward). The Kratos provider entry's id is
**`saml-<tenant>`**, so a delete can find and remove exactly its own entry.

Three security controls make a SAML connection safe; **each is enforced
console-side and cannot be toggled off**:

1. **Mandatory IdP signing certificate (SSO-02).** A SAML connection is only as
   trustworthy as the certificate Polis validates assertion signatures against.
   The console runs a **mandatory signing-cert pre-flight on the IdP metadata
   *before* any Polis call**: metadata with **no `<X509Certificate>` usable for
   signing** — including the subtle **encryption-only** case (a cert present only
   under `KeyDescriptor use="encryption"`) — is rejected **`422`** and **no Polis
   connection is created**. There is **no "skip signature validation" affordance**
   anywhere in the UI or API.

2. **`email_verified`-default-false mapper — the account-takeover defense
   (SSO-03).** Polis's OIDC id_token for a SAML bridge carries **no
   `email_verified` claim**. A naive Kratos mapper that maps `email`
   unconditionally would let an attacker who controls *any* connected SAML IdP
   assert `victim@corp.com` and have Kratos **auto-link** them to the victim's
   existing identity. The console therefore generates a Kratos Jsonnet mapper that
   begins with Ory's documented default-false overlay
   (`local claims = { email_verified: false } + std.extVar('claims')`) and emits
   the `email` trait **only** under a conditional gate
   (`[if 'email' in claims && claims.email_verified then 'email' else null]`).
   Because Polis never asserts `email_verified`, **the email trait is always
   dropped** — Kratos **cannot** auto-link by a SAML-asserted email. The mapper is
   stored base64-encoded in the provider's `mapper_url` and is **identical for
   every connection** (no per-connection knob can weaken it). The trust anchor that
   actually makes a SAML email usable is the **Organization domain binding** plus
   an explicit operator linking action — never the raw assertion.

3. **SSRF-guarded `metadataUrl` (SSO-04).** The preferred way to add a connection
   is to **upload the IdP metadata XML** (base64'd into `encodedRawMetadata` — no
   network fetch, no SSRF surface). If you instead supply a **metadata URL**, the
   **backend fetches that URL itself** through the same address-pinned,
   redirects-off client the webhook dispatcher uses — Polis is **never** handed the
   URL, so it is never the fetcher. The guard re-resolves the host, rejects the
   request if **any** resolved address is internal/private/link-local/
   cloud-metadata (`http://kratos:4434`, `http://169.254.169.254`, `127.0.0.1`, …)
   or carries **embedded credentials** (`user:pass@…`), then **pins the connection
   to exactly the just-validated addresses** so DNS cannot rebind between the check
   and the connect (TOCTOU/DNS-rebind defense), with **redirects disabled**
   (`Policy::none()`) so a 3xx to an internal target is never followed. The fetched
   XML is read under a size cap, runs through the **same signing-cert pre-flight**
   as uploaded XML, and is then sent to Polis as `encodedRawMetadata`. A blocked
   host or fetch failure is rejected with an explicit **422** keyed on the metadata
   URL field, surfaced verbatim in the form, naming the *category* — it never
   echoes the internal IP.

**Two-sided delete.** Deleting a connection removes **both** the Polis
`/api/v1/sso` connection **and** the matching Kratos `providers[]` entry
(`saml-<tenant>`), restarting only Kratos and preserving every other provider's
stored secret. The order is **Kratos-first**: the security-relevant provider entry
is removed (and Kratos confirmed healthy) **before** the Polis connection is
deleted, so a partial failure can never leave a `saml-<tenant>` provider pointing
at a deleted Polis connection. If the Kratos side fails, nothing was destroyed and
the operator can retry; the Polis delete is **idempotent** (an already-gone
connection is treated as success), so a retry after a half-finished delete
completes cleanly. Neither side is left dangling.

**Write-only `clientSecret` (BACK-07).** The OAuth2 `clientSecret` Polis mints is
written straight into the Kratos provider entry and is **never returned to the
frontend**: create surfaces only `clientID` + `idpMetadata`; list/detail strip
the secret and show a masked `clientSecret_set` badge. The `POLIS_API_KEY` is a
write-only secret sent only in the `Authorization: Api-Key` header — never logged,
never serialized.

#### Add a SAML connection

1. Enable the `saml` feature flag (**Settings → Features**, or
   `PUT /api/console/features/saml {"enabled":true}`).
2. **Authentication → SAML Sign-In → Add connection.** Upload the IdP metadata XML
   (preferred) or paste a metadata URL. Connections without a signing certificate,
   or whose metadata URL points at an internal/credentialed host, are rejected
   verbatim — fix the IdP export rather than looking for a bypass (there is none).
3. On success the connection appears in the list with its entity ID, certificate
   thumbprint, and a masked client-secret badge. A Kratos OIDC provider
   `saml-<tenant>` is written and Kratos is restarted automatically.

### How Organizations work (domain → SSO)

An **Organization** is console-owned state (a row in the console Postgres, not an
Ory primitive): a label, one or more **verified email domains**, and an optional
**linked SSO connection tenant**. At login time the Account Experience UI
(Phase 15) resolves a user's email domain to the org's linked connection via
`GET /api/sso/lookup?email=…` and routes them to the right IdP.

The single most important property is **domain normalization (SSO-05)**, applied
**identically on write and on lookup** so a spoofed variant can never match at
lookup that could not have been stored:

```
trim → strip a single trailing FQDN dot → lowercase → IDNA/punycode (TR-46,
url::Host::parse) → registered-domain (eTLD+1) boundary via the Public Suffix List
```

Consequences (all enforced by a **UNIQUE index on the normalized domain**, the
last-line `409` defense):

- **`CORP.com`, `corp.com.`** (uppercase, trailing dot) all **collapse to one key**
  → a second org with any variant is rejected **`409`**.
- An **IDNA-confusable** domain (e.g. a Cyrillic-homoglyph `cорp.com`) becomes a
  **distinct `xn--…` punycode label** — it is **never folded into** the ASCII
  `corp.com`, so it cannot silently hijack the real org's routing.
- **`corp.com.attacker.com`** reduces to the registered domain **`attacker.com`**
  — **distinct** from `corp.com`, so an attacker cannot register a sub-label of a
  victim's domain to capture its SSO routing.
- **Multi-label TLDs are correct.** The eTLD+1 boundary uses the embedded **Public
  Suffix List** (the `psl` crate, compiled in — no runtime fetch), so `co.uk` and
  friends reduce correctly (e.g. `mail.acme.co.uk` → `acme.co.uk`). The PSL is
  embedded at build time; refresh it by bumping the `psl` crate on an Ory upgrade.

A lookup for an **unknown** domain returns **`404`** (value-free — no
org-existence leak). Every org/domain create and delete is **audited** by the
response-phase audit hoop (actor-from-session).

#### Add an Organization

1. Enable the `organizations` feature flag.
2. **Project → Organizations → Add organization.** Enter a label, one or more
   email domains (any case / form — they are normalized for you), and optionally
   the **linked SSO connection tenant** (the SAML connection id from above).
3. A colliding domain is rejected **`409`** and an invalid/ambiguous domain
   **`4xx`**, both surfaced verbatim. Once linked, a login from that domain routes
   to the connection's SAML IdP (Phase-15 login UI).

### Residual risk (carried)

- **Per-tenant SAML list.** The Polis admin list endpoint is **per-`(tenant,
  product)`**, with no list-all route; the console SAML page aggregates over a
  **browser-local tenant registry** (localStorage, holds no secret). A connection
  created in a different browser profile won't appear until its tenant id is
  re-entered. Acceptable for single-operator self-hosting; revisit if a list-all
  Polis route becomes available.
- **Domain binding is the trust anchor, not the SAML assertion.** Because the
  mapper drops a SAML-asserted email, account linking relies on the operator
  having bound the correct domain to the correct connection. Bind domains
  carefully — a wrong domain→connection link routes that domain's logins to the
  wrong IdP (it cannot, however, take over an existing identity by email).

### Verifying Phase 14 — SAML Sign-In / Organizations (`SSO-02..07`)

A single fail-closed gate brings up the full stack **incl. Polis on a fresh
volume**, toggles `saml` + `organizations` **ON**, proves every `SSO-02..07`
control with anti-false-green negatives, **re-runs the v1 + Phase-13 invariants**
(INFRA-05 / BACK-05 / BACK-01 + bundle-egress) with the SAML/Orgs surface present,
and tears the stack down cleanly afterward:

```bash
MSYS_NO_PATHCONV=1 bash scripts/verify/phase14-acceptance.sh   # Git Bash on Windows
# (the gate does the full build -> up --wait -> drive -> down -v itself, and
#  GENERATES throwaway Polis secrets for its ephemeral run; pass KEEP_STACK=1 to
#  keep the stack up for debugging, SKIP_EGRESS=1 to skip the bundle build)
```

The gate exits `0` only when:

- **`SSO-07` flag-OFF 404.** With a valid session + CSRF, `GET`/`POST`
  `api/sso/connections` and `api/organizations` (and `api/sso/lookup`) all return
  **`404`** while their flag is OFF, become reachable once flipped ON, and re-close
  to `404` when restored — the flag gate beats both the auth and CSRF guards.
- **`SSO-02`.** A CA-less metadata POST → **`422`** (and **no** Polis connection is
  created); an encryption-only cert → **`422`**; a signing-cert connection is
  created, surfacing `clientID` + `idpMetadata` with **no** `clientSecret`.
- **`SSO-03`.** The stored Kratos mapper (decoded from `base64://`) carries
  `email_verified: false` **and** the conditional email gate **and no**
  unconditional `email` mapping — the account-takeover negative; the connection
  list carries **no** `clientSecret` value.
- **`SSO-04`.** A `metadataUrl` to `http://kratos:4434`, `169.254.169.254`, a
  credentialed URL, or loopback → explicit **422** SSRF reject (backend-fetch
  guard: re-resolve + address-pin + redirects-off) with **no** connection created;
  a URL whose fetched metadata lacks a signing cert is also rejected **422** (the
  signing-cert pre-flight runs on the URL path too).
- **`SSO-05`.** `corp.com.` collides with `CORP.com` → **`409`**; a
  Cyrillic-homoglyph is a distinct punycode label; `corp.com.attacker.com` is
  distinct → accepted; an audit row exists for `POST /api/organizations`.
- **`SSO-06`.** A known org domain lookup returns the linked connection tenant; an
  unknown domain → **`404`** (no leak).
- **Two-sided delete.** After delete the Polis connection is gone **and** the
  Kratos `providers[]` entry `saml-<tenant>` is removed (no dangling provider).
- **Config-write discipline.** A valid provider write restarts **only** Kratos;
  an invalid (CA-less) write leaves `kratos.yml` byte-identical (no disk change).
- **v1 invariants.** INFRA-05 (Ory + Polis admin ports refused from host),
  BACK-05 (broker scope, no backend/polis socket), BACK-01 (bundle-egress: no
  Ory/Polis host/port/SDK/CDN in the built bundle, no `enterprise license`/
  `requires ory` copy in `frontend/`) all re-run green.

Every negative passes ONLY on the explicit refusal (anti-false-green).

---

## Architecture (Phase 1)

Two Docker networks isolate the stack:

- **`internal`** (`internal: true` — no host route): Postgres, all four Ory
  services (admin **and** public APIs), the migrate one-shots, the curl health
  sidecars, and the restart broker. None of these publish a host port.
- **`edge`** (bridge): only the `backend` (8080) and `frontend` (3000) are
  published to the host. The backend is dual-homed (internal + edge) so it can
  reach the Ory services and the broker while remaining reachable from the host.

```
host ──> :3000 frontend         (edge only)
host ──> :8080 backend  ───┐     (edge + internal)
                           │
   internal (no host route)▼
     postgres ─ kratos ─ hydra ─ keto ─ oathkeeper
                  ▲
                  │ POST /v1.<ver>/containers/ory-<svc>/restart
            restart-broker ──> /var/run/docker.sock (mounted :ro, ONLY here)
```

Migration ordering: `postgres healthy → <svc>-migrate completes (exit 0) →
Ory <svc> starts`. Oathkeeper is stateless (no DB, no migrate container).

---

## Healthcheck strategy (and why the curl sidecars exist)

The Ory images are pinned to the **`-distroless`** variants
(`gcr.io/distroless/static-debian12:nonroot`) for a minimal attack surface.
Distroless images ship **no shell, no curl, no wget** — only the service binary.
A standard `HEALTHCHECK CMD curl .../health/ready` would therefore fail forever.

Per-service strategy:

- **Kratos** — uses its in-image `kratos remote status --endpoint
  http://127.0.0.1:4434` subcommand (the `kratos` binary is present in the
  distroless image and probes `/health/alive` + `/health/ready`). No shell or
  curl needed.
- **Hydra / Keto / Oathkeeper** — have **no equivalent `remote status`
  subcommand** (Hydra in particular ships no in-image health CLI), so each is
  built from a thin wrapper (`docker/ory-healthcheck/Dockerfile`) that vendors a
  single **statically-linked curl** binary into the pinned distroless base. The
  **service container itself** then carries an in-image `HEALTHCHECK` that curls
  its own admin `/health` endpoint over loopback: Hydra `/health/ready` (4445),
  Keto `/health/ready` (4469), and Oathkeeper `/health/alive` (4456). This makes
  `docker compose up -d --wait` gate on each service directly and lets the
  acceptance harness assert `healthy` on the service container itself — a truer
  compose-level health gate than a separate sidecar, with distroless hardening
  preserved (one static binary, still no shell / package manager, non-root).

  Oathkeeper uses `/health/alive` rather than `/health/ready` because, for this
  stateless empty-ruleset configuration, its `/health/ready` reporter returns
  503 with no satisfiable dependency to report on; `/health/alive` is the
  meaningful liveness signal. Real access rules arrive in Phase 9, at which point
  `/health/ready` can be revisited.

The **backend** image vendors a single static `curl` binary copied from
`ghcr.io/tarampampam/curl:8.11.1` (a `scratch` image whose `/bin/curl` is fully
statically linked, so it runs unmodified on glibc distroless — `curlimages/curl`
is dynamically linked against musl and cannot) into the distroless runtime so it
can self-healthcheck its own `/health` and act as the internal probe source for
the acceptance harness. This is the same static curl the Hydra/Keto/Oathkeeper
healthcheck wrapper (`docker/ory-healthcheck/Dockerfile`) vendors.

---

## Security model & documented residual risks

This is a security-foundations phase; the controls below are the deliverable.

- **Admin APIs never reach the host (INFRA-05).** No Ory admin port
  (4434/4445/4467/4469/4456) — and no public Ory port (4433/4444/4455) — is
  published. They live only on the `internal: true` network. The backend is the
  sole client over that internal network.
- **Restart broker as the sole socket holder (BACK-05).** `wollomatic/socket-proxy`
  is the **only** container mounting `/var/run/docker.sock` (read-only). It is
  default-deny: only a `POST /v1.<ver>/containers/(ory-kratos|ory-hydra|ory-keto|
  ory-oathkeeper)/restart` is allowed, and only from the `backend` container
  (`-allowfrom=backend`). The regex is auto-anchored (`^...$`). The **backend
  mounts no Docker socket** — it reaches the engine only through the broker.
- **Config tamper-resistance (INFRA-07).** `config/` is mounted **read-only**
  into every Ory container and **read-write** only into the backend (for the
  Phase 4 YAML-edit subsystem). A compromised Ory process cannot rewrite its own
  config.
- **Supply-chain pinning (INFRA-04).** All images are pinned to exact tags
  (`oryd/*:v26.2.0-distroless`, `postgres:17-alpine`,
  `wollomatic/socket-proxy:1.12.1`). The static curl vendored into the long-lived
  service images is `ghcr.io/tarampampam/curl:8.11.1`, pinned additionally by
  `@sha256:` digest in both `backend/Dockerfile` and
  `docker/ory-healthcheck/Dockerfile` (it injects a binary into every long-lived
  service, so its provenance is digest-pinned). No floating tags are used.
  `>= v26.2.0` fixes CVE-2026-33503/33504/33505. For stricter reproducibility you
  may additionally pin each remaining image to its `@sha256:` digest
  (`docker buildx imagetools inspect <image>` returns it).
- **Container hardening.** `restart-broker` runs `read_only: true` +
  `no-new-privileges:true`; the backend runs `no-new-privileges:true`; all
  runtime images are non-root. NOTE: the broker process runs in the root GROUP
  (`gid 0`, `user: "65534:0"`) ONLY to group-read the Docker socket, which is
  `root:root` mode `srw-rw----` on Docker Desktop/WSL2. This `gid` is
  HOST-SPECIFIC: on a host whose socket is owned by a `docker` group with a
  different gid, re-pin the broker `user:` gid to match that group.
- **Secrets handling.** Secrets come from `.env` / runtime env only, never baked
  into image layers or committed. `.gitignore` blocks `.env`; only `.env.example`
  (placeholders) is committed. The per-service DB password lives in exactly ONE
  authoritative place — the `*_DB_PASSWORD` in `.env`, injected as each service's
  `DSN` env var (the committed config YAMLs carry NO `dsn:` key). The Oathkeeper
  `id_token` signing JWKS is **generated at first boot** by the
  `oathkeeper-jwks-init` one-shot into the `oathkeeper-secrets` volume — **no
  private signing key is committed to the repo**. To rotate the JWKS, destroy the
  volume and re-up (`docker compose down -v && docker compose up -d --wait`); a
  fresh key is generated automatically. Only `config/oathkeeper/jwks.json.example`
  (an empty placeholder) is tracked in git.

### Hydra boot mode — `--dev` residual risk (Phase 8, `T-08-DEV`)

Ory Hydra runs with the `--dev` flag in `docker-compose.yml`
(`command: ["serve", "all", "--dev", …]`). This is a **deliberate, documented
decision**, not an oversight:

- **Why `--dev` stays.** Hydra v2.x removed the legacy `--dangerous-force-http`
  switch; `--dev` is now the only relaxed-security flag. Without it, Hydra
  **refuses to boot with a non-HTTPS `urls.self.issuer`**, and the shipped config
  uses `http://localhost:4444/` because Hydra's public/admin ports are served over
  plain HTTP on the **internal-only** Docker network. Running production-mode (no
  `--dev`) would require terminating TLS at a reverse proxy in front of Hydra's
  public port and switching the issuer to `https://…` — a reverse-proxy/TLS story
  that is larger than this phase and orthogonal to the console's job.
- **Why the residual risk is acceptable (INFRA-05).** Hydra's public (`4444`) and
  admin (`4445`) ports are **never published to the host** — they are reachable
  only from inside the `internal` Docker network (the Rust backend is the sole
  caller). `--dev` relaxes the HTTPS-issuer requirement and a few transport
  checks; it does **not** disable authentication, the OAuth2 security model, or
  the `secrets.system` encryption-at-rest. With no host-exposed port, the relaxed
  transport posture has no externally reachable surface.
- **What is NOT relaxed.** `SECRETS_SYSTEM` (→ `secrets.system`, immutable
  encryption-at-rest key) and the Postgres `DSN` remain env-injected and intact;
  both are on the console's hard config denylist and are never editable through
  the OAuth2 config pages.
- **Concrete instance — token revoke relays a client secret over plain HTTP**
  (`T-08-DEV`, WR-05). The Token & Flow Inspector's **Revoke** action targets
  Hydra's **public** `/oauth2/revoke` endpoint, which per RFC 7009 requires the
  client to authenticate for a confidential-client token. The operator-supplied
  `client_id`/`client_secret` therefore travel backend → Hydra public port in
  **plaintext** because the public port is served over plain HTTP under `--dev`.
  This is the **one** place the console relays a *client* credential (not an
  admin credential) to the public port. The residual risk is bounded by the same
  INFRA-05 guarantee: the public port is internal-only and never host-published,
  so the relay has no externally reachable surface. Going fully production-mode
  (TLS-terminated public port, below) closes this too.
- **To go fully production-mode.** Put a TLS-terminating reverse proxy in front of
  Hydra's public port, set `urls.self.issuer`/`urls.self.public` to the `https://`
  external URL (editable on the **General & Issuer** OAuth2 config page), and drop
  `--dev` from the Hydra `command` in `docker-compose.yml`. Keep `SECRETS_SYSTEM`
  and `DSN` env-injected exactly as they are today.

### Residual risks (accepted, documented per the production-grade mandate)

- **The restart broker has NO TLS / mTLS.** Confidentiality of the broker traffic
  relies entirely on the internal-only Docker network. Documented and accepted
  (`T-notls-broker`). If you expose the broker beyond a trusted internal network,
  add TLS or a mutual-auth layer.
- **Restart-as-DoS.** A container restart is itself a limited denial-of-service
  primitive for anything that can reach the broker. The blast radius is minimized
  by `-allowfrom=backend` and the restart-only, four-container scope. Documented
  and accepted (`T-restart-dos`).
- **Hydra runs in `--dev` relaxed-security mode** (`T-08-DEV`). Justified by
  INFRA-05 — Hydra's public/admin ports are never host-published, so the relaxed
  transport posture has no externally reachable surface. `secrets.system` and the
  Postgres DSN are preserved. See "Hydra boot mode" above for the production-mode
  migration path.

---

## Windows / Docker Desktop notes

The host for this project is Windows 11 + Docker Desktop. The restart broker
mounts the host Docker socket at `/var/run/docker.sock`. On Docker Desktop
(WSL2 backend) this path is provided by Docker Desktop's socket bridge and the
`/var/run/docker.sock:/var/run/docker.sock:ro` mount works as written. If you run
on native Windows containers or a non-default Docker context, verify the socket
path / endpoint on your target and adjust the mount accordingly (socket-proxy
also supports `-proxysocketendpoint` for alternate socket locations).

Run the verification harness and any compose commands from a bash shell
(Git Bash or WSL) so `docker compose`, `curl`, and `node` resolve as expected.
On **Git Bash**, prefix the harness with `MSYS_NO_PATHCONV=1` so MSYS does not
rewrite POSIX path arguments (e.g. `/etc/config`) into Windows paths:

```bash
MSYS_NO_PATHCONV=1 bash scripts/verify/phase1-acceptance.sh
```

Under WSL this is unnecessary.

---

## Verifying the stack

The full Phase 1 acceptance harness brings the stack up on a fresh volume and
asserts every success criterion (health, the five databases, migrate exit codes,
image pins, admin-port refusal from the host, the broker allow/deny scope, the
config ro/rw split, and that the backend holds no socket):

```bash
docker compose down -v && bash scripts/verify/phase1-acceptance.sh
```

It exits `0` only when every assertion passes. A quick syntactic check of the
compose file alone is `docker compose config -q`.

When you are done, leave a clean state:

```bash
docker compose down -v
```
