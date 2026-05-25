#!/usr/bin/env bash
# scripts/verify/phase2-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 2 (backend-core-console-auth-persistence) live-stack acceptance gate.
#
# Run against `docker compose up -d --wait` (Git Bash on Windows: prefix with
# MSYS_NO_PATHCONV=1 so the leading-slash URL paths are not mangled):
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase2-acceptance.sh
#
# This is the end-to-end gate for VALIDATION criteria (a)-(f). Plan 02-01
# implements only the steps provable now (health + DB schema present); the
# auth/cookie/csrf/rate-limit/github steps are TODO placeholders that Plans
# 02-02..04 fill in. Placeholders MUST NOT call _pass — an unimplemented check
# is not a passing check (anti-false-green, T-03).
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

# Base URL for host-side HTTP assertions (overridable; default 8080).
: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"

echo "=== Phase 2 acceptance: backend core, console auth & persistence ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"

# --- Implemented now (Plan 02-01): BACK-01 / BACK-03 -------------------------

echo
echo "--- [BACK-01] backend healthy + /health 200 ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200

echo
echo "--- [BACK-03] console DB exists + v1 tables present ---"
assert_db_exists console
# Assert each v1 table resolves via to_regclass (NULL/empty => table missing).
for tbl in admins sessions console_settings settings_history; do
  out="$($DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
        "SELECT to_regclass('public.${tbl}')" 2>/dev/null | tr -d '[:space:]')"
  if [ "$out" = "$tbl" ]; then
    _pass "table '$tbl' exists in console DB"
  else
    _fail "table '$tbl' missing in console DB (got '$out')"
  fi
done

# --- TODO: filled by Plans 02-02 / 02-03 / 02-04 -----------------------------
# These criteria are NOT yet implementable (the auth subsystem does not exist
# in Plan 02-01). They are listed so the gate's shape is complete; each is a
# no-op echo here and will become a real assertion in the named plan. None of
# them calls _pass — an unimplemented check must not green the gate.

echo
echo "--- [CAUTH-02] /setup requires one-time bootstrap token (a) ---"
echo "TODO: implemented in 02-02 — assert_status POST /setup (no token) -> 401/403"

echo
echo "--- [CAUTH-01] /setup returns 404 after init (a) ---"
echo "TODO: implemented in 02-02 — assert_route_absent ${BACKEND_BASE_URL}/setup (post-init)"

echo
echo "--- [CAUTH-05] login sets hardened __Host- cookie (b) ---"
echo "TODO: implemented in 02-02 — assert_set_cookie_flags ${BACKEND_BASE_URL}/login <creds>"

echo
echo "--- [CAUTH-06] unauthenticated protected route -> 401 JSON (c) ---"
echo "TODO: implemented in 02-03 — assert_status GET /api/console/me -> 401"

echo
echo "--- [CAUTH-05] /setup + /login rate-limited (d) ---"
echo "TODO: implemented in 02-02/03 — assert_rate_limited ${BACKEND_BASE_URL}/login <data> <n>"

echo
echo "--- [CAUTH-05] state-changing request without X-CSRF-Token -> 403 (d) ---"
echo "TODO: implemented in 02-03 — authenticated POST /logout sans header -> 403"

echo
echo "--- [BACK-07] no secret/hash in any response body (e) ---"
echo "TODO: implemented in 02-02/03 — assert_no_secret_in_body GET /api/console/state etc."

echo
echo "--- [CAUTH-04] GitHub endpoints only exist when env set (f) ---"
echo "TODO: implemented in 02-04 — env unset: assert_route_absent /auth/github/login; set: 302"

echo
summary
exit $?
