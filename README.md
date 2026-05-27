# Ory Self-Hosted Console (`ory-ui`)

A **self-hosted, single-tenant, fully open-source** drop-in replacement for the Ory Network Console. One `docker compose up` brings up the entire stack — Postgres, Ory Kratos, Hydra, Keto, Oathkeeper, a Rust/Salvo backend (the single API layer), and a Next.js admin console — and a one-time `/setup` page gives you a production-grade console for managing identities, OAuth2 clients, permissions, SSO, and all service configuration against **your own** Ory services, with zero manual plumbing.

Everything is open source. There are **no licensed or gated features** — every surface that the hosted Ory Console gates behind an Enterprise license (SAML, Organizations, Account Experience, Branding, metrics) is implemented here as a real OSS feature.

![Ory Self-Hosted Console — feature toggles](docs/console-screenshot.png)

---

## What it is

- **Single API layer.** The browser never talks to Ory directly. The Rust/Salvo backend is the only thing that reaches the Ory Admin APIs (which stay on an internal-only Docker network and are never published to the host). The Next.js frontend talks only to the backend.
- **Config = mounted YAML + scoped restart.** Self-hosted Ory has no live config API, so configuration pages edit the mounted service config, validate it against each service's JSON Schema, write atomically, and restart **only** the affected service through a hardened, container-name-scoped socket-proxy broker — never a raw Docker socket.
- **Backend-owned state.** Console accounts, sessions, feature flags, webhook/event-sink configs + delivery logs, audit log, API keys, and SSO/Organizations data live in a dedicated `console` Postgres database with its own migrations.
- **Version-locked.** All Ory images are pinned to `v26.2.0-distroless` and the Rust per-service crates (`ory-kratos/hydra/keto/oathkeeper-client`) track the image tags in lockstep.

## Features

**Identity & access**
- Users & identities CRUD, identity-schema editor (JSON-Schema presets + Monaco), CLI-compatible bulk import
- OAuth2/OIDC client management (Hydra), token introspect/revoke, and all Hydra config sections
- Permissions: relation-tuple CRUD + check/expand, and an **Ory Permission Language editor with syntax highlighting and real-time validation** (Monaco + live Keto syntax-check)
- Oathkeeper access-rules editor

**Authentication & SSO (all OSS — no Enterprise license)**
- All Kratos auth config: methods, passwordless/passkeys, MFA, social OIDC, recovery, verification, sessions, SMTP, SMS
- **SAML Sign-In** via an embedded **Ory Polis** (Apache-2.0) SAML→OIDC bridge — IdP-connection CRUD with mandatory signing-cert enforcement, SSRF-guarded metadata, and an `email_verified`-gated identity mapper (no account-takeover)
- **Organizations** — email-domain → SSO-connection mapping with IDNA/public-suffix domain normalization
- **Account Experience UI** — a self-hosted end-user login/registration/recovery/verification/settings app (Ory Elements), with console editors for theming, localization, and custom domains

**Operations**
- **Feature toggles** — enable/disable any console feature; gated server-side (not just hidden in the nav)
- **Optional observability** — Prometheus + Grafana + Loki + Alloy as an opt-in compose profile (default off, internal-only), powering a real Activity metrics dashboard and a log search, with Grafana behind an authenticated backend proxy
- **Event streams** — forward console audit events to external sinks (HTTP webhook by default; NATS/Kafka behind build features) with idempotency, dead-letter, and PII redaction
- **Webhook dispatcher** — durable, retrying, HMAC-signed, SSRF-guarded
- Project overview/health, members, console API keys, audit log
- An **optional operator CLI** for first-run setup and day-2 operations

## Architecture

```
                 ┌─────────────── edge network ───────────────┐
   browser ──────▶ frontend (Next.js admin console :3000)      │
                 │ account-experience (Ory Elements UI :3001)  │
                 └───────────────┬─────────────────────────────┘
                                 │ (the only Ory client)
                 ┌───────────────▼──── internal network (no host ports) ────────┐
                 │ backend (Rust/Salvo :8080) ── console Postgres DB             │
                 │   ├─ Kratos / Hydra / Keto / Oathkeeper (admin APIs)          │
                 │   ├─ Ory Polis (SAML→OIDC bridge)                             │
                 │   ├─ restart-broker (socket-proxy; sole Docker-socket holder) │
                 │   └─ [observability profile] Prometheus/Grafana/Loki/Alloy    │
                 └───────────────────────────────────────────────────────────────┘
```

## Installation / Quickstart

**Prerequisites:** Docker + Docker Compose v2.

```bash
# 1. Provide the required secrets (DB passwords, etc.) — copy the example and fill it in
#    (or use the operator CLI bootstrap, below):
cp .env.example .env      # then edit .env

# 2. Bring up the full stack on a fresh volume:
docker compose up -d --wait

# 3. The backend prints a one-time bootstrap token to its logs on first boot:
docker compose logs backend | grep -i bootstrap

# 4. Open the console and complete first-run setup:
#    http://localhost:3000/setup   (paste the bootstrap token, create the local admin)
```

After `/setup`, log in at `http://localhost:3000`. GitHub OAuth login appears on the `/login` page when GitHub OAuth credentials are configured (env, or via the CLI).

**Optional observability stack** (default off):

```bash
docker compose --profile observability up -d --wait
```

Then enable the **Observability** feature toggle (Project → Features). Grafana is reachable only through the authenticated backend proxy — never published to the host.

## Configuration

- Service config (Kratos/Hydra/Keto/Oathkeeper/Polis) is edited **in the console** — it writes the mounted config, validates, and restarts only that service via the broker.
- Secrets (DB passwords, GitHub OAuth, SMTP/SMS, Polis keys) come from `.env` / secret files and are never logged or sent to the frontend.
- Ory CLI compatibility: identity schemas, OAuth2 client shapes, and Keto relation tuples interoperate with the official `ory` CLI.

### Email & SMS delivery (works out of the box)

Account recovery (password reset), address verification, and one-time-code sign-in are wired end-to-end with **dev catchers** so the stack works immediately with no external accounts:

- **Email → Mailpit.** Kratos's courier sends recovery/verification mail to a bundled [Mailpit](https://mailpit.axllent.org/) catcher. Read the captured messages (and their codes) at **http://localhost:8025**.
- **SMS → sms-sink.** Kratos POSTs one-time SMS login codes to a tiny bundled HTTP catcher. View captured texts at **http://localhost:8026**. (Sign-in by SMS uses the optional `phone` trait on the identity schema; email keeps password sign-in.)

**For production**, point Kratos at a real SMTP server and SMS gateway via the console's **Email/SMTP** and **SMS** pages (they rewrite the Kratos `courier` config and restart the service). The dev catchers are not encrypted and do not forward mail/SMS — don't rely on them in production.

## Operator CLI (optional)

The console works fully without the CLI (via `/setup` + env). The CLI is a convenience that smooths first-run setup and day-2 ops. It is a separate, lean binary run through Compose:

```bash
# First-run BOOTSTRAP — writes only gitignored .env / secret files; never echoes secrets,
# never accepts a secret as an argv flag (env var / --*-file / interactive prompt only):
docker compose run --rm cli oauth github set      # configure GitHub login OAuth (prompts for the secret)
docker compose run --rm cli admin create --via-setup --name "Admin" --email you@example.com

# ONLINE ops — authenticated to the backend HTTP API with a console API key
# (`Authorization: Api-Key`), driving the SAME validated routes; the CLI is never a second writer of config:
docker compose run --rm cli feature enable saml
docker compose run --rm cli feature list
docker compose run --rm cli observability on
docker compose run --rm cli sso add-saml --tenant <org> --metadata ./idp-metadata.xml
docker compose run --rm cli org add --label "Acme" --domain acme.com
```

## Security

Security hardening is a top priority:

- Ory **Admin ports are never published to the host** — only the backend reaches them, on an internal-only network.
- Service **restarts go only through a scoped socket-proxy** broker; the backend holds no Docker socket.
- Console auth: Argon2id passwords, DB-backed opaque sessions behind a `__Host-` cookie, CSRF protection, rate limiting, a one-time bootstrap token, optional GitHub OAuth.
- SAML: mandatory IdP signing-cert enforcement; the backend is the sole metadata fetcher behind an SSRF guard (DNS-rebind defended); the OIDC mapper is `email_verified`-default-false (no account-takeover).
- Feature flags are enforced **server-side** (a disabled feature's routes 404 even with a valid session).
- Outbound webhooks/event-sinks are SSRF-guarded with write-only credentials and PII-redacted payloads.
- The Account Experience UI uses a per-request nonce CSP and a session fully isolated from the admin console.

### Documented residual risks (single-tenant, operator-controlled deployment)

- The Account Experience service shares an internal network segment with Kratos, which co-listens its admin port on the same interface — the AX service has no admin URL/credentials and never calls it, and the admin port is not host-published; full network isolation would require an L7 public-only proxy in front of Kratos.
- The backend `/metrics` endpoint is unauthenticated (Prometheus pull model) and relies on its metrics port not being host-published.
- Hydra runs with `--dev` (carried from v1); documented and acceptable for self-hosted single-tenant.

See `.planning/v2-MILESTONE-AUDIT.md` for the full audit and tech-debt register.

## Development

- **Backend:** Rust (Cargo workspace: `console-core` shared DTOs + `backend` + `cli`), Salvo 0.93, sqlx 0.9 with committed offline metadata (`--locked` offline Docker builds).
- **Frontend:** Next.js 16 + React 19 + TypeScript, TanStack Table/Query, React Hook Form + Zod, shadcn/ui, Monaco (vendored same-origin — zero CDN egress). npm only.
- **Verification:** each feature area ships a live acceptance harness under `scripts/verify/phaseNN-acceptance.sh` that brings up the real stack and asserts behavior (including negative/security assertions). Optional Kafka support builds via `backend/Dockerfile.kafka`.

## License

Open source. No gated or license-restricted features.
