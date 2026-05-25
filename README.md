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

### Residual risks (accepted, documented per the production-grade mandate)

- **The restart broker has NO TLS / mTLS.** Confidentiality of the broker traffic
  relies entirely on the internal-only Docker network. Documented and accepted
  (`T-notls-broker`). If you expose the broker beyond a trusted internal network,
  add TLS or a mutual-auth layer.
- **Restart-as-DoS.** A container restart is itself a limited denial-of-service
  primitive for anything that can reach the broker. The blast radius is minimized
  by `-allowfrom=backend` and the restart-only, four-container scope. Documented
  and accepted (`T-restart-dos`).

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
