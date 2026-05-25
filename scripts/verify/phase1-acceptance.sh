#!/usr/bin/env bash
# scripts/verify/phase1-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 1 end-to-end fresh-volume acceptance harness.
#
# This is the single command the entire phase is validated against:
#   docker compose down -v && bash scripts/verify/phase1-acceptance.sh
# It brings the stack up from a fresh volume and asserts EVERY Phase 1 success
# criterion (see 01-VALIDATION.md "Per-Task Verification Map"):
#   INFRA-01 health, INFRA-02 5 DBs, INFRA-03 migrate exit 0, INFRA-04 image
#   pins, INFRA-05 admin-port-refused + internal reachable, INFRA-06 .env.example
#   contract, INFRA-07 config ro/rw split, BACK-05 broker scope + no socket.
#
# It exits non-zero if ANY assertion fails (see lib.sh failure counter).
#
# NOTE: Plan 04 builds docker-compose.yml to PASS this harness. Until then this
# script may fail at runtime (no compose graph), but it MUST parse (`bash -n`)
# and reference the exact container names / ports / paths Plan 04 will create.
#
# Host target: Windows 11 + Docker Desktop, run under bash (Git Bash / WSL).
# -----------------------------------------------------------------------------
set -euo pipefail

# Resolve our own directory so we can source lib.sh and locate repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# Repo root = two levels up from scripts/verify/. cd there so `docker compose`
# and static-file greps resolve against docker-compose.yml / .env.example.
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="docker-compose.yml"

# --- Exact container names Plan 04 will assign (used in broker paths) --------
# The broker allowlist regex is scoped to these four Ory container names.
KRATOS_CONTAINER="ory-kratos"
HYDRA_CONTAINER="ory-hydra"
KETO_CONTAINER="ory-keto"
OATHKEEPER_CONTAINER="ory-oathkeeper"

# --- Admin ports that MUST be refused from the host (INFRA-05) ---------------
# 4434 kratos-admin, 4445 hydra-admin, 4467 keto-write, 4469 keto-metadata,
# 4456 oathkeeper-api.
ADMIN_PORTS="4434 4445 4467 4469 4456"

# --- Logical databases that MUST exist on first boot (INFRA-02) --------------
DATABASES="kratos hydra keto oathkeeper console"

# --- Detect the Docker engine API version dynamically (research A2) ----------
# Do NOT hardcode v1.43. The broker regex (`v1\..{1,2}`) is version-tolerant,
# but the client must send the engine's actual ApiVersion or it 400s.
detect_api_version() {
  local ver=""
  ver="$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || true)"
  if [ -z "$ver" ]; then
    # Fallback: client API version, then a conservative default.
    ver="$(docker version --format '{{.Client.APIVersion}}' 2>/dev/null || true)"
  fi
  if [ -z "$ver" ]; then
    ver="1.43"
  fi
  printf 'v%s' "$ver"
}
API_VER="$(detect_api_version)"
echo "Using Docker engine API version path: ${API_VER}"

# --- Step 1: Fresh volume bring-up -------------------------------------------
# Pitfall 2: the postgres init script only runs on an empty data dir, so we
# MUST down -v first. Then up -d --wait blocks until healthchecks converge
# (Compose >= v2.1.1). Provide a poll-loop fallback if --wait is unsupported
# (research A5).
echo "==> Step 1: fresh-volume bring-up"
$DC down -v --remove-orphans || true

if $DC up -d --wait 2>/dev/null; then
  echo "    'up -d --wait' completed."
else
  echo "    'up -d --wait' unsupported or failed; falling back to poll loop."
  $DC up -d
  # Poll loop: wait until no service is still in 'starting'/'created', up to a
  # bounded number of attempts.
  attempts=0
  max_attempts=60   # ~5 min at 5s intervals
  while [ "$attempts" -lt "$max_attempts" ]; do
    starting="$($DC ps --all --format json 2>/dev/null \
      | node -e '
          let i = require("fs").readFileSync(0,"utf8").trim();
          if (!i) { process.stdout.write("0"); process.exit(0); }
          let rows = [];
          try { const p = JSON.parse(i); rows = Array.isArray(p)?p:[p]; }
          catch (e) {
            for (const l of i.split(/\r?\n/)) { const t=l.trim(); if(!t) continue;
              try { rows.push(JSON.parse(t)); } catch(_){} }
          }
          const pending = rows.filter(r => {
            const h = r.Health || ""; const s = r.State || "";
            if (h === "starting") return true;
            if (s === "created" || s === "restarting") return true;
            return false;
          }).length;
          process.stdout.write(String(pending));
        ' 2>/dev/null || echo 0)"
    if [ "${starting:-0}" = "0" ]; then
      echo "    poll loop: all services settled."
      break
    fi
    attempts=$((attempts + 1))
    sleep 5
  done
fi

# --- Step 2: INFRA-01 — every long-lived service healthy ---------------------
echo "==> Step 2 (INFRA-01): service health"
for svc in postgres kratos hydra keto oathkeeper restart-broker backend frontend; do
  assert_healthy "$svc"
done

# --- Step 3: INFRA-02 — all 5 databases exist --------------------------------
echo "==> Step 3 (INFRA-02): databases"
for db in $DATABASES; do
  assert_db_exists "$db"
done

# --- Step 4: INFRA-03 — migrate one-shots exited 0 ---------------------------
# kratos-migrate, hydra-migrate, keto-migrate. NO oathkeeper-migrate (stateless).
echo "==> Step 4 (INFRA-03): migration completion"
for m in kratos-migrate hydra-migrate keto-migrate; do
  assert_exited_zero "$m"
done

# --- Step 5: INFRA-04 — image pins -------------------------------------------
# Exactly 4 distroless v26.2.0 Ory pins; no :latest anywhere.
echo "==> Step 5 (INFRA-04): image pins"
assert_grep_count 'oryd/(kratos|hydra|keto|oathkeeper):v26\.2\.0-distroless' "$COMPOSE_FILE" 4
assert_not_grep ':latest' "$COMPOSE_FILE"

# --- Step 6: INFRA-05 — admin ports refused from host, reachable internally --
echo "==> Step 6 (INFRA-05): admin-port isolation"
for port in $ADMIN_PORTS; do
  assert_port_refused "$port"
done
# Positive: from the trusted backend container, the kratos admin API IS up.
assert_internal_reachable backend "http://kratos:4434/health/ready"

# --- Step 7: INFRA-07 — config ro into Ory, rw into backend ------------------
echo "==> Step 7 (INFRA-07): config mount ro/rw split"
# Ory side: kratos config mount must be read-only (RW == false).
assert_mount_rw kratos "/etc/config" false
# Backend side: config mount must be read-write (RW == true).
assert_mount_rw backend "/etc/config" true

# --- Step 8: BACK-05 — broker scope + backend holds no socket ----------------
echo "==> Step 8 (BACK-05): restart-broker scope"
# Allowlisted path (literal reference): POST /v1.<ver>/containers/ory-kratos/restart
# Allowed: scoped restart of an Ory container.
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart"
# Allowed WITH the standard graceful-stop timeout query string (CR-02). The real
# backend / `docker restart --time` path appends `?t=<seconds>`; the broker
# allowlist must accept it. This exercises the query-string branch of the regex.
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart?t=5"
# Denied: listing containers (GET), stopping (different verb-path), and
# restarting a non-Ory container (postgres) outside the allowlist.
assert_broker_denied GET  "/${API_VER}/containers/json"
assert_broker_denied POST "/${API_VER}/containers/${KRATOS_CONTAINER}/stop"
assert_broker_denied POST "/${API_VER}/containers/postgres/restart"
# Backend must not hold the docker socket at all.
assert_no_socket_mount backend

# --- Step 9: INFRA-06 — .env.example operator contract -----------------------
# Single Ory base URL + admin credential are documented; no per-service manual
# wiring required. Assert the canonical operator-input keys are present.
echo "==> Step 9 (INFRA-06): .env.example bootstrap contract"
assert_grep 'ORY_(BASE_URL|SDK_URL)|ORY_API' ".env.example"
assert_grep '(ADMIN_(EMAIL|PASSWORD|CREDENTIAL)|CONSOLE_ADMIN)' ".env.example"

# --- Finish ------------------------------------------------------------------
echo "==> Summary"
summary
exit $?
