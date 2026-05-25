#!/usr/bin/env bash
# scripts/verify/phase3-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 3 (backend-core-admin-api-wrappers) live-stack acceptance gate (BACK-02).
#
# Run against a FRESH-volume `docker compose up -d --wait` (Git Bash on Windows:
# prefix with MSYS_NO_PATHCONV=1 so the leading-slash URL paths are not mangled):
#   docker compose down -v && docker compose build backend && docker compose up -d --wait
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase3-acceptance.sh
#   docker compose down -v
#
# It proves the three BACK-02 success criteria + reinforces INFRA-05:
#   - Criterion 2 (INFRA-05): the five Ory admin ports are host-UNREACHABLE and
#     no admin port / admin-URL env name ships in the frontend source.
#   - Criterion 1: each of the three proof routes returns 200 + a well-formed
#     JSON body through an AUTHENTICATED backend route (anti-false-green: a 200
#     with an empty/non-JSON body FAILs). The unauth edge returns 401.
#   - Criterion 3: the reqwest fallback module is structurally isolated.
#
# SPLIT OF PROOF (pinned, no ambiguity):
#   - The seeded-NON-EMPTY Kratos read is proven by the GATED Rust live test
#       `ORY_LIVE_TESTS=1 cargo test -p ory-console-backend kratos_identities_live`
#     which seeds one identity (schema_id "default", traits {email}) via the
#     typed admin crate and asserts a NON-empty JSON array.
#   - THIS bash gate asserts only "authenticated route returns 200 + parseable
#     JSON" for all three routes. An EMPTY array is VALID for Hydra/Keto
#     (Pitfall 4), so the bash gate requires valid JSON of the right TYPE, not a
#     non-empty list, for Hydra/Keto. For Kratos the bash gate requires a JSON
#     array (the non-empty proof is the cargo live test's job).
#
# Every negative assertion PASSes ONLY on the exact expected outcome
# (anti-false-green, T-03): an exposed admin port, a frontend leak, or a
# 200-empty body all FAIL.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

# Repo root (this script lives in scripts/verify/).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Base URL for host-side HTTP assertions (overridable; default 8080).
: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"

echo "=== Phase 3 acceptance: Ory Admin API wrappers (BACK-02) ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"
echo "Repo root: ${REPO_ROOT}"

# =============================================================================
# Criterion 2 (no auth needed) — INFRA-05: admin URLs are backend-only.
# =============================================================================
echo
echo "--- [BACK-02 / INFRA-05] Ory admin ports refused from the host ---"
# Reuse the Phase-1 anti-false-green helper: PASS only on a connection-level
# refusal/timeout, never on a 2xx/4xx (a reachable admin port is a FAIL).
assert_port_refused 4434   # Kratos admin
assert_port_refused 4445   # Hydra admin
assert_port_refused 4466   # Keto read
assert_port_refused 4467   # Keto write
assert_port_refused 4456   # Oathkeeper api

echo
echo "--- [BACK-02 / INFRA-05] admin ports + admin-URL env names ABSENT from the frontend ---"
# The frontend only knows the BACKEND origin; it must never carry an Ory admin
# port number or an admin-URL env name. Grep the frontend SOURCE/BUILD excluding
# node_modules (third-party) — any hit FAILs (anti-false-green: PASS requires an
# explicit zero-hit grep, not absence of a file).
FRONTEND_DIR="${REPO_ROOT}/frontend"
ADMIN_LEAK_RE='4434|4445|4466|4467|4456|KRATOS_ADMIN|HYDRA_ADMIN|KETO_READ|KETO_WRITE|OATHKEEPER_API'
if [ ! -d "$FRONTEND_DIR" ]; then
  _fail "frontend dir not found at $FRONTEND_DIR (cannot run the INFRA-05 absence grep)"
else
  # Search app source + config + public, never node_modules / .next build cache.
  leak_hits="$(grep -rEn "$ADMIN_LEAK_RE" "$FRONTEND_DIR" \
      --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
      --include='*.mjs' --include='*.cjs' --include='*.json' --include='*.css' \
      --exclude-dir=node_modules --exclude-dir=.next 2>/dev/null || true)"
  if [ -z "$leak_hits" ]; then
    _pass "frontend carries NO Ory admin port / admin-URL env name (INFRA-05)"
  else
    _fail "frontend LEAKS an admin port/env name (INFRA-05 violation): ${leak_hits}"
  fi
fi

echo
echo "--- [BACK-02] admin URLs are backend-only in docker-compose.yml ---"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.yml"
# Present in the backend service env (the backend IS the sole admin client).
assert_grep 'KRATOS_ADMIN_URL' "$COMPOSE_FILE"
# Confirm the admin-URL env names appear ONLY in the backend service block, not
# the frontend block. Slice the compose file at the `frontend:` service key and
# assert the admin env names are absent from that tail.
frontend_block="$(awk '/^  frontend:/{f=1} f{print}' "$COMPOSE_FILE")"
if printf '%s' "$frontend_block" | grep -Eq 'KRATOS_ADMIN_URL|HYDRA_ADMIN_URL|KETO_READ_URL|KETO_WRITE_URL|OATHKEEPER_API_URL'; then
  _fail "frontend compose block carries an Ory admin-URL env name (must be backend-only)"
else
  _pass "Ory admin-URL env names are absent from the frontend compose block (backend-only)"
fi

# =============================================================================
# Criterion 1 — live authenticated data-path reads (need the stack up).
# =============================================================================
echo
echo "--- [BACK-02] backend healthy ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200

# --- Bootstrap the console (complete /setup) so we can obtain a session -------
# The backend prints `FIRST-RUN SETUP TOKEN: <token>` once on an uninitialized
# console (parsed from its logs, same as the Phase-2 gate). We complete /setup
# with it, then log in to get an authenticated session cookie.
echo
echo "--- [BACK-02] complete /setup + login to obtain an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase3-admin@example.com"
ADMIN_PW_TEST="phase3-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)

# The in-force session cookie name (hardened unless CONSOLE_INSECURE_COOKIES set).
: "${SESSION_COOKIE_NAME:=__Host-console_session}"

# Is the console already initialized? On a FRESH `down -v` run it is not (and the
# backend prints the bootstrap token once); on a re-run against a persisted
# volume an admin already exists and the one-time token is NOT re-logged. We use
# `GET /api/console/state` (public) to decide, so a missing token is only a
# failure when the console genuinely still needs setup.
state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
if printf '%s' "$state_now" | grep -q '"initialized":true'; then
  already_init=1
fi

# Complete setup (idempotent across re-runs: a 404 means an admin already exists,
# which is fine — we just log in below). Only attempt if we parsed a token.
if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase3 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
    "${BACKEND_BASE_URL}/setup" 2>/dev/null)"
  case "$setup_code" in
    201) _pass "completed /setup (admin created)";;
    404) _pass "/setup already completed on a prior run (404) — proceeding to login";;
    *)   _fail "/setup returned '$setup_code' (want 201 or 404-already-init)";;
  esac
elif [ "$already_init" = "1" ]; then
  # Re-run against a persisted volume: the one-time token is not re-logged, but
  # an admin already exists (state.initialized:true). Not a failure — proceed to
  # login. (For a clean first-run proof, run after `docker compose down -v`.)
  _pass "console already initialized (re-run; one-time token not re-logged) — proceeding to login"
else
  _fail "could not parse FIRST-RUN SETUP TOKEN from backend logs AND console is not initialized (cannot complete /setup)"
fi

# Log in and capture the raw session token (curl will not replay a Secure cookie
# over plain HTTP, so we parse it and send an explicit Cookie header — Phase-2
# pattern). If setup happened on a prior run with DIFFERENT creds, this login may
# fail; for a fresh `down -v` run the creds match the setup we just performed.
_login_session_token() {
  local email="$1" pw="$2" headers
  headers="$(curl -s -D - -o /dev/null --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"email\":\"${email}\",\"password\":\"${pw}\"}" \
    "${BACKEND_BASE_URL}/login" 2>/dev/null)"
  printf '%s' "$headers" \
    | grep -iE '^Set-Cookie:[[:space:]]*(__Host-)?console_session=' \
    | head -n1 \
    | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*(__Host-)?console_session=([^;]+).*/\2/' \
    | tr -d '\r'
}

SESSION_TOKEN="$(_login_session_token "$ADMIN_EMAIL_TEST" "$ADMIN_PW_TEST")"
if [ -z "$SESSION_TOKEN" ]; then
  _fail "could not obtain a session token from /login (authed reads cannot run)"
  COOKIE_HEADER=""
else
  _pass "obtained an authenticated session token from /login"
  COOKIE_HEADER="Cookie: ${SESSION_COOKIE_NAME}=${SESSION_TOKEN}"
fi

echo
echo "--- [BACK-02] unauthenticated wrapper read -> 401 (live edge, T-03-10) ---"
# Mirrors the integration test at the live edge: no cookie -> 401.
assert_status GET "${BACKEND_BASE_URL}/api/kratos/identities" 401
assert_status GET "${BACKEND_BASE_URL}/api/hydra/clients" 401
assert_status GET "${BACKEND_BASE_URL}/api/keto/relationships" 401

echo
echo "--- [BACK-02] authenticated live reads return 200 + JSON (anti-false-green) ---"
# Kratos: a JSON array (the seeded NON-EMPTY proof is the cargo live test's job;
# see SPLIT OF PROOF in the header). Hydra: a JSON array (empty is valid). Keto:
# an object carrying `relation_tuples` (empty list is valid). A 200 with an
# empty/non-JSON body FAILs via assert_json_ok.
if [ -n "$COOKIE_HEADER" ]; then
  REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${BACKEND_BASE_URL}/api/kratos/identities" array
  REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${BACKEND_BASE_URL}/api/hydra/clients" array
  REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${BACKEND_BASE_URL}/api/keto/relationships" has:relation_tuples
else
  _fail "skipping authed live reads — no session token (see /login failure above)"
fi

# =============================================================================
# Criterion 3 — reqwest fallback module isolation (structural, repo-relative).
# =============================================================================
echo
echo "--- [BACK-02] reqwest fallback module is structurally isolated ---"
ORY_DIR="${REPO_ROOT}/backend/src/ory"
# The fallback module is declared.
assert_grep 'pub mod fallback' "${ORY_DIR}/mod.rs"
# The fallback module does NOT import the Ory crates' generated `apis` modules
# (the 0.12/0.13 split is contained to one side; isolation invariant).
assert_not_grep '\bapis\b' "${ORY_DIR}/fallback.rs"
# The fallback uses the backend's own reqwest transport (0.13) + the shared
# AppError::Upstream envelope.
assert_grep 'reqwest' "${ORY_DIR}/fallback.rs"
assert_grep 'AppError::Upstream' "${ORY_DIR}/fallback.rs"
# The typed handlers never import the fallback module (the two paths never mix).
assert_not_grep 'fallback' "${ORY_DIR}/kratos.rs"
assert_not_grep 'fallback' "${ORY_DIR}/hydra.rs"
assert_not_grep 'fallback' "${ORY_DIR}/keto.rs"
assert_not_grep 'fallback' "${ORY_DIR}/oathkeeper.rs"

echo
summary
exit $?
