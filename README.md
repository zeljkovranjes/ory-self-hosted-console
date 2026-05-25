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
they are additionally guarded by an optional `Origin`/`Referer` allowlist
(comma-separated `CONSOLE_ALLOWED_ORIGINS`). An empty/unset list disables the
check (dev posture). Set it to your console origin(s) in production for
defense-in-depth against cross-site form posts.

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
