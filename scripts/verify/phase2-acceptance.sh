#!/usr/bin/env bash
# scripts/verify/phase2-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 2 (backend-core-console-auth-persistence) live-stack acceptance gate.
#
# Run against a FRESH-volume `docker compose up -d --wait` (Git Bash on Windows:
# prefix with MSYS_NO_PATHCONV=1 so the leading-slash URL paths are not mangled):
#   docker compose down -v && docker compose up -d --wait
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase2-acceptance.sh
#
# This is the end-to-end gate for VALIDATION criteria (a)-(f). Every negative
# assertion PASSes ONLY on the exact expected code (anti-false-green, T-03).
#
# IMPORTANT — cookie hardening: the acceptance run uses the DEFAULT hardened
# cookie posture (CONSOLE_INSECURE_COOKIES unset), so the backend emits a
# `__Host-console_session` cookie with Secure+HttpOnly+SameSite=Lax+Path=/.
# `curl` receives the Set-Cookie header verbatim regardless of HTTP-vs-HTTPS
# (the `__Host-`/Secure rules are BROWSER-enforced, not transport-enforced), so
# the cookie-flag assertion is meaningful over the plain-HTTP compose edge. A
# real browser would reject `__Host-` over plain HTTP — for browser dev set
# CONSOLE_INSECURE_COOKIES=true (Pitfall 6), documented in the README.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

# Base URL for host-side HTTP assertions (overridable; default 8080).
: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"

echo "=== Phase 2 acceptance: backend core, console auth & persistence ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"

# --- [BACK-01] backend healthy + /health 200 --------------------------------

echo
echo "--- [BACK-01] backend healthy + /health 200 ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200

echo
echo "--- [BACK-03] console DB exists + v1 tables present ---"
assert_db_exists console
for tbl in admins sessions console_settings settings_history; do
  out="$($DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
        "SELECT to_regclass('public.${tbl}')" 2>/dev/null | tr -d '[:space:]')"
  if [ "$out" = "$tbl" ]; then
    _pass "table '$tbl' exists in console DB"
  else
    _fail "table '$tbl' missing in console DB (got '$out')"
  fi
done

# --- Helper: read the per-session CSRF token from the console DB -------------
# The login/me DTOs are secret-free (they deliberately do NOT return the CSRF
# token), so the gate reads it from the session row to drive the CSRF (d) check.
# Looks up by the latest session for the given admin email.
_csrf_for_email() {
  local email="$1"
  $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
    "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
     WHERE a.email = '${email}' ORDER BY s.created_at DESC LIMIT 1" 2>/dev/null \
    | tr -d '[:space:]'
}

# --- Bootstrap token: read from backend stdout (CAUTH-02) --------------------
# `ensure_bootstrap_token` prints `FIRST-RUN SETUP TOKEN: <token>` once at boot
# on an uninitialized console. We parse it from the backend logs to drive the
# /setup token gate. (Documented manual step: an operator copies this same line.)
echo
echo "--- [CAUTH-02] bootstrap token present in backend logs ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"
if [ -n "$SETUP_TOKEN" ]; then
  _pass "bootstrap token parsed from backend logs"
else
  _fail "bootstrap token NOT found in backend logs (expected 'FIRST-RUN SETUP TOKEN: ...')"
fi

# Admin credentials used to complete /setup and exercise the auth flows.
ADMIN_EMAIL_TEST="acceptance-admin@example.com"
ADMIN_PW_TEST="phase2-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)

# --- (a) token gate: /setup requires the one-time bootstrap token ------------
echo
echo "--- [CAUTH-02] /setup token gate (a) ---"
# No token -> 403 (forbidden).
REQ_DATA="{\"name\":\"A\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\"}" \
  assert_status POST "${BACKEND_BASE_URL}/setup" 403
# Wrong token -> 403.
REQ_DATA="{\"name\":\"A\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"definitely-wrong\"}" \
  assert_status POST "${BACKEND_BASE_URL}/setup" 403
# Correct token -> 201 (creates the single admin).
REQ_DATA="{\"name\":\"Acceptance Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
  assert_status POST "${BACKEND_BASE_URL}/setup" 201

# --- (a') 404-after-init: /setup is single-use -------------------------------
echo
echo "--- [CAUTH-01] /setup 404 after init (a) ---"
# Now that an admin exists, /setup is guarded (require_uninitialized -> 404).
REQ_DATA="{\"name\":\"B\",\"email\":\"second@example.com\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
  assert_status POST "${BACKEND_BASE_URL}/setup" 404
# state now reports initialized:true.
state_body="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
if printf '%s' "$state_body" | grep -q '"initialized":true'; then
  _pass "GET /api/console/state reports initialized:true after setup"
else
  _fail "state did not report initialized:true: ${state_body}"
fi

# --- (b) login sets the hardened __Host- cookie ------------------------------
echo
echo "--- [CAUTH-05] login sets hardened __Host- cookie (b) ---"
assert_set_cookie_flags "${BACKEND_BASE_URL}/login" \
  "{\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\"}"

# --- (c) unauth protected route -> 401; public set reachable -----------------
echo
echo "--- [CAUTH-06] unauthenticated protected route -> 401 (c) ---"
assert_status GET "${BACKEND_BASE_URL}/api/console/me" 401
# Public set reachable without a cookie.
assert_status GET "${BACKEND_BASE_URL}/health" 200
assert_status GET "${BACKEND_BASE_URL}/api/console/state" 200
# /setup is now 404 (post-init) but still part of the public subtree (not 401);
# /login is reachable (a GET is not its method, but it must not be 401).

# --- (d) rate-limit on /login + CSRF on a protected state-changing route -----
echo
echo "--- [CAUTH-05] /login rate-limited (d) ---"
# >10 POST /login within a minute -> at least one 429.
assert_rate_limited "${BACKEND_BASE_URL}/login" \
  "{\"email\":\"nobody@example.com\",\"password\":\"a-very-long-password\"}" 15

echo
echo "--- [CAUTH-05] CSRF: authed POST /logout needs X-CSRF-Token (d) ---"
# Establish an authenticated session: capture the session cookie from /login.
COOKIE_JAR="$(mktemp)"
curl -s -c "$COOKIE_JAR" -o /dev/null --max-time 10 \
  -H 'Content-Type: application/json' \
  --data "{\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\"}" \
  "${BACKEND_BASE_URL}/login" 2>/dev/null
# Authenticated POST /logout WITHOUT X-CSRF-Token -> 403.
csrf_no_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -b "$COOKIE_JAR" -X POST "${BACKEND_BASE_URL}/logout" 2>/dev/null)"
if [ "$csrf_no_code" = "403" ]; then
  _pass "POST /logout without X-CSRF-Token: 403 (CSRF enforced)"
else
  _fail "POST /logout without X-CSRF-Token: got '$csrf_no_code' (want 403)"
fi
# WITH the matching X-CSRF-Token (read from the session row) -> 200.
CSRF_TOKEN="$(_csrf_for_email "$ADMIN_EMAIL_TEST")"
if [ -z "$CSRF_TOKEN" ]; then
  _fail "could not read csrf_token from session row for ${ADMIN_EMAIL_TEST}"
else
  csrf_ok_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -X POST "${BACKEND_BASE_URL}/logout" 2>/dev/null)"
  if [ "$csrf_ok_code" = "200" ]; then
    _pass "POST /logout with matching X-CSRF-Token: 200"
  else
    _fail "POST /logout with matching X-CSRF-Token: got '$csrf_ok_code' (want 200)"
  fi
fi
rm -f "$COOKIE_JAR"

# --- (e) no secret in any response body --------------------------------------
echo
echo "--- [BACK-07] no secret/hash in any response body (e) ---"
# /api/console/state (public).
assert_no_secret_in_body GET "${BACKEND_BASE_URL}/api/console/state"
# /login success body (secret-free admin DTO).
REQ_DATA="{\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\"}" \
  assert_no_secret_in_body POST "${BACKEND_BASE_URL}/login"
# /api/console/me (protected) — authenticate, then assert the body carries no secret.
ME_JAR="$(mktemp)"
curl -s -c "$ME_JAR" -o /dev/null --max-time 10 \
  -H 'Content-Type: application/json' \
  --data "{\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\"}" \
  "${BACKEND_BASE_URL}/login" 2>/dev/null
me_body="$(curl -s --max-time 10 -b "$ME_JAR" "${BACKEND_BASE_URL}/api/console/me" 2>/dev/null)"
if [ -z "$me_body" ]; then
  _fail "assert_no_secret_in_body GET /api/console/me: empty body (cannot confirm secret-absence)"
elif printf '%s' "$me_body" | grep -qiE 'password_hash|token_hash|bootstrap|client_secret|\$argon2|postgres://'; then
  _fail "assert_no_secret_in_body GET /api/console/me: SECRET marker found in response body"
else
  _pass "assert_no_secret_in_body GET /api/console/me: no secret markers present"
fi
rm -f "$ME_JAR"

# --- (f) GitHub endpoints exist ONLY when env set ----------------------------
echo
echo "--- [CAUTH-04] GitHub endpoints gated by env (f) ---"
# This compose run sets NO GITHUB_OAUTH_* env, so the routes must be absent and
# state must report github disabled.
assert_route_absent "${BACKEND_BASE_URL}/auth/github/login"
gh_state="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
if printf '%s' "$gh_state" | grep -q '"github_oauth_enabled":false'; then
  _pass "state reports github_oauth_enabled:false (GitHub unconfigured)"
else
  _fail "state did not report github_oauth_enabled:false: ${gh_state}"
fi
# Manual re-run (documented in README): with GITHUB_OAUTH_CLIENT_ID +
# GITHUB_OAUTH_CLIENT_SECRET set, GET /auth/github/login returns 302 to
# github.com/login/oauth/authorize and github_oauth_enabled:true. The real
# round-trip needs a browser + GitHub OAuth app (02-VALIDATION Manual-Only).

echo
summary
exit $?
