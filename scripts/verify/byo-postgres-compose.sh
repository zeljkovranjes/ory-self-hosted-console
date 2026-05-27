#!/usr/bin/env bash
# scripts/verify/byo-postgres-compose.sh
# -----------------------------------------------------------------------------
# CLI-builder BYO-Postgres verification (IUX-BYO-PG-01 / -02).
#
# Asserts the four compose-level invariants of the bring-your-own Postgres change
# WITHOUT touching the running stack (pure `docker compose config` renders — no
# up/down, no data mutation):
#
#   (1) DEFAULT byte-identical: with NO POSTGRES_HOST/PORT/SSLMODE and svc-postgres
#       in COMPOSE_PROFILES, the 8 service DSNs render `@postgres:5432/<db>?sslmode=disable`
#       exactly (count == 8) and the `postgres` service IS present.
#   (2) INFRA-04 image-pin grep: each Ory `v26.2.0-distroless` tag literal still
#       appears EXACTLY 4 times in docker-compose.yml (the DSN change touches no
#       image line).
#   (3) BYO re-point: with POSTGRES_HOST=db.ext POSTGRES_PORT=6543 POSTGRES_SSLMODE=require
#       the 8 DSNs render `@db.ext:6543/<db>?sslmode=require` (count == 8).
#   (4) BYO drops the in-stack DB: with COMPOSE_PROFILES lacking svc-postgres,
#       `docker compose config --services` does NOT list `postgres`.
#
# All Ory service secrets are supplied as throwaway env values here so the
# `${VAR:?}` DSN interpolations render regardless of the operator's real `.env`.
# These are NOT real secrets and never touch the running stack.
# -----------------------------------------------------------------------------
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || { echo "FAIL: cannot cd to repo root"; exit 1; }

: "${DC:=docker compose}"

PASSES=0
FAILURES=0
_pass() { PASSES=$((PASSES + 1)); printf 'PASS: %s\n' "$*"; }
_fail() { FAILURES=$((FAILURES + 1)); printf 'FAIL: %s\n' "$*"; }

# Throwaway secret env so every ${VAR:?} DSN segment + the rest of the compose
# render resolves. NOT real credentials; render-only.
render_env() {
  env \
    POSTGRES_USER=ory \
    POSTGRES_PASSWORD=render \
    KRATOS_DB_PASSWORD=render \
    HYDRA_DB_PASSWORD=render \
    KETO_DB_PASSWORD=render \
    CONSOLE_DB_PASSWORD=render \
    POLIS_DB_PASSWORD=render \
    HYDRA_SECRETS_SYSTEM=render \
    POLIS_DB_ENCRYPTION_KEY=render \
    POLIS_API_KEY=render \
    POLIS_EXTERNAL_URL=http://localhost:5225 \
    POLIS_NEXTAUTH_SECRET=render \
    POLIS_OPENID_RSA_PRIVATE_KEY=render \
    POLIS_OPENID_RSA_PUBLIC_KEY=render \
    ADMIN_PASSWORD=renderrenderrender \
    SESSION_SECRET=renderrenderrender \
    "$@"
}

ALL_PROFILES="svc-postgres,svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis"

# --- (1) DEFAULT byte-identical render ---------------------------------------
DEFAULT_CFG="$(render_env COMPOSE_PROFILES="$ALL_PROFILES" $DC config 2>/dev/null)"
DEFAULT_DSNS="$(printf '%s\n' "$DEFAULT_CFG" | grep -Eo 'postgres://[a-z]+:[^@]*@postgres:5432/[a-z]+\?sslmode=disable' | sort)"
DEFAULT_COUNT="$(printf '%s\n' "$DEFAULT_DSNS" | grep -c 'postgres://')"
if [ "$DEFAULT_COUNT" -eq 8 ]; then
  _pass "(1) default render: 8 DSNs at @postgres:5432/<db>?sslmode=disable"
else
  _fail "(1) default render: expected 8 in-stack DSNs, got $DEFAULT_COUNT"
  printf '%s\n' "$DEFAULT_DSNS"
fi

# postgres service present in the default profile set.
DEFAULT_SVCS="$(render_env COMPOSE_PROFILES="$ALL_PROFILES" $DC config --services 2>/dev/null)"
if printf '%s\n' "$DEFAULT_SVCS" | grep -qx 'postgres'; then
  _pass "(1) postgres service present when svc-postgres profile active"
else
  _fail "(1) postgres service MISSING with svc-postgres active"
fi

# --- (2) INFRA-04 image-pin grep ---------------------------------------------
# Mirrors the canonical phase1-acceptance gate: the COMBINED Ory image-pin regex
# matches EXACTLY 4 lines (one per `*-image` YAML anchor definition; every service
# then references the anchor, so no literal tag is duplicated). The DSN-host
# parameterization touches no `image:` / anchor line, so this stays == 4. And
# `:latest` must appear nowhere.
INFRA04_N="$(grep -Ec 'oryd/(kratos|hydra|keto|oathkeeper):v26\.2\.0-distroless' docker-compose.yml)"
if [ "$INFRA04_N" -eq 4 ]; then
  _pass "(2) INFRA-04: 4 Ory v26.2.0-distroless image pins (combined grep == 4)"
else
  _fail "(2) INFRA-04: combined Ory image-pin grep == ${INFRA04_N} (expected 4)"
fi
# `:latest` must not appear on any actual image reference (anchor defs or
# `image:` lines). Comment lines that merely mention the policy are ignored.
if grep -E '(image:|&[a-z-]+-image)' docker-compose.yml | grep -q ':latest'; then
  _fail "(2) INFRA-04: ':latest' present on an image reference"
else
  _pass "(2) INFRA-04: no ':latest' on any image reference"
fi

# --- (3) BYO re-point render -------------------------------------------------
BYO_CFG="$(render_env COMPOSE_PROFILES="svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis" \
  POSTGRES_HOST=db.ext POSTGRES_PORT=6543 POSTGRES_SSLMODE=require \
  $DC config 2>/dev/null)"
BYO_DSNS="$(printf '%s\n' "$BYO_CFG" | grep -Eo 'postgres://[a-z]+:[^@]*@db\.ext:6543/[a-z]+\?sslmode=require' | sort)"
BYO_COUNT="$(printf '%s\n' "$BYO_DSNS" | grep -c 'postgres://')"
if [ "$BYO_COUNT" -eq 8 ]; then
  _pass "(3) BYO render: 8 DSNs re-pointed to @db.ext:6543/<db>?sslmode=require"
else
  _fail "(3) BYO render: expected 8 re-pointed DSNs, got $BYO_COUNT"
  printf '%s\n' "$BYO_DSNS"
fi

# --- (4) BYO drops in-stack postgres -----------------------------------------
BYO_SVCS="$(render_env COMPOSE_PROFILES="svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis" \
  POSTGRES_HOST=db.ext $DC config --services 2>/dev/null)"
if printf '%s\n' "$BYO_SVCS" | grep -qx 'postgres'; then
  _fail "(4) postgres service STILL listed when svc-postgres dropped"
else
  _pass "(4) postgres service omitted when svc-postgres profile dropped"
fi

# --- Summary -----------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
