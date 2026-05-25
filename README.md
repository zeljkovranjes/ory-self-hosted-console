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
  subcommand**, so each gets a tiny **`curlimages/curl` healthcheck sidecar**
  that shares the service's network namespace (`network_mode: "service:<svc>"`)
  and curls the service's `/health/ready` admin endpoint over loopback (Hydra
  4445, Keto 4469, Oathkeeper 4456). `docker compose up -d --wait` gates on these
  sidecars' health, so a successful `--wait` genuinely proves all four Ory
  services are ready (chosen over a no-healthcheck approach for a true
  compose-level health gate, per the production-grade mandate).

The **backend** image vendors a single static `curl` binary copied from
`curlimages/curl` into the distroless runtime so it can self-healthcheck its own
`/health` and act as the internal probe source for the acceptance harness.

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
  `wollomatic/socket-proxy:1.12.1`, `curlimages/curl:8.11.1`); no floating tags.
  `>= v26.2.0` fixes CVE-2026-33503/33504/33505. For stricter reproducibility you
  may additionally pin each image to its `@sha256:` digest
  (`docker buildx imagetools inspect <image>` returns it).
- **Container hardening.** `restart-broker` runs `read_only: true` +
  `no-new-privileges:true`; the backend runs `no-new-privileges:true`; all
  runtime images are non-root.
- **Secrets handling.** Secrets come from `.env` / runtime env only, never baked
  into image layers or committed. `.gitignore` blocks `.env`; only `.env.example`
  (placeholders) is committed.

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
