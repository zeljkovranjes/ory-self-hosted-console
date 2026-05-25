#!/usr/bin/env bash
# scripts/verify/phase5-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 5 (nextjs-shell-shared-components) live-stack acceptance gate.
# Proves all FOUR phase success criteria end-to-end against the REAL running
# stack and locks the FE-05 no-Ory-egress invariant:
#
#   FE-05  bundle-egress: the built frontend bundle contains NO Ory hostname /
#          admin port / Ory SDK string and NO Monaco CDN (jsDelivr/unpkg/cdnjs);
#          the browser's ONLY backend reference is the same-origin `/backend`
#          rewrite. (scripts/verify/bundle-egress.sh — build-time grep gate.)
#   FE-01  live auth journey: a real browser drives /setup -> /login -> the
#          server-guarded (console) shell against the REAL backend, and a
#          protected route without a session redirects to /login. The negative
#          (401 -> /login) assertion is anti-false-green: it passes ONLY on the
#          explicit redirect to /login (Playwright e2e/auth-flow.spec.ts).
#   FE-02/03/04  the three reusable primitives are tested: DataTable,
#          SettingsForm, and the Monaco wrapper (vitest component suites).
#   FE-04  Monaco loads from our OWN origin: the vendored public/monaco/vs AMD
#          distribution is present AND the built bundle references no CDN host
#          (folded into the bundle-egress gate per MONACO.md).
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script
# does the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless
# you ask it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase5-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still
#                    runs the bundle gate, the vitest suites, and the live e2e
#   SKIP_BUILD=1     passed through to bundle-egress.sh (reuse an existing .next)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
#
# Every negative assertion PASSes ONLY on the exact expected outcome
# (anti-false-green, lib.sh contract): an empty result, a missing redirect, or a
# reachable-when-it-should-be-guarded route all FAIL.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FRONTEND_DIR="${REPO_ROOT}/frontend"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${FRONTEND_BASE_URL:=http://localhost:${FRONTEND_PORT:-3000}}"
: "${UP_TIMEOUT:=1500}"

echo "=== Phase 5 acceptance: Next.js shell + shared primitives (FE-01..05) ==="
echo "Backend base URL:  ${BACKEND_BASE_URL}"
echo "Frontend base URL: ${FRONTEND_BASE_URL}"
echo "Repo root:         ${REPO_ROOT}"

# -----------------------------------------------------------------------------
# Teardown trap: ALWAYS `docker compose down -v` (unless KEEP_STACK=1) so the
# gate is idempotent and leaves no residue. The ephemeral first-boot stack holds
# the one-time bootstrap token only in logs; `down -v` discards it (T-05-25).
# -----------------------------------------------------------------------------
teardown() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "KEEP_STACK=1 — leaving the stack up (run 'docker compose down -v' to clean)."
    return 0
  fi
  echo
  echo "--- teardown: docker compose down -v ---"
  $DC down -v >/dev/null 2>&1 || true
}
trap teardown EXIT

# =============================================================================
# CRITERION FE-05 (part 1) — bundle egress + Monaco-no-CDN, BEFORE bringing the
# stack up. This builds the frontend and greps the built output; it is the
# cheapest hard gate and must hold regardless of the live stack.
# =============================================================================
echo
echo "--- [FE-05] bundle-egress: no Ory host/port/SDK + no Monaco CDN in the built bundle ---"
if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
  _pass "bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (FE-05/FE-04)"
else
  _fail "bundle-egress: FORBIDDEN Ory host/port/SDK or Monaco CDN reference in the built bundle"
fi

# FE-04 supporting check: the local Monaco AMD distribution is actually vendored
# (the loader points at /monaco/vs; if the assets are absent the editor would
# silently fall back to a CDN at runtime — defeating the air-gap requirement).
echo
echo "--- [FE-04] local Monaco assets vendored at public/monaco/vs (no runtime CDN) ---"
if [ -f "${FRONTEND_DIR}/public/monaco/vs/loader.js" ] \
   && [ -f "${FRONTEND_DIR}/public/monaco/vs/editor/editor.main.js" ]; then
  _pass "local Monaco AMD distribution present (public/monaco/vs/loader.js + editor.main.js)"
else
  _fail "local Monaco assets MISSING under public/monaco/vs (editor would fall back to a CDN)"
fi

# =============================================================================
# CRITERION FE-02/03/04 — the three reusable primitive component suites pass.
# Run them headless via vitest (jsdom). These gate the primitives independently
# of the live stack.
# =============================================================================
echo
echo "--- [FE-02/03/04] primitive component tests (DataTable, SettingsForm, Monaco) ---"
if ( cd "${FRONTEND_DIR}" && npx vitest run \
      components/data-table.test.tsx \
      components/settings-form.test.tsx \
      components/monaco-editor.test.tsx ); then
  _pass "primitive suites pass: data-table + settings-form + monaco-editor (FE-02/03/04)"
else
  _fail "one or more primitive component suites FAILED (FE-02/03/04)"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live FE-01 auth journey.
#
# The live e2e drives a real BROWSER over plain-HTTP localhost. A `__Host-`/
# `Secure` session cookie is silently dropped by browsers over http://, so we
# bring the backend up with CONSOLE_INSECURE_COOKIES=true for THIS ephemeral run
# (the session cookie becomes the dev name `console_session`). The frontend ↔
# backend traffic is same-origin via the /backend rewrite, so no cross-site
# Origin is presented; with insecure cookies + empty allowlist the pre-session
# origin check is the documented dev posture. Production keeps both UNSET.
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true
export CONSOLE_ALLOWED_ORIGINS="${FRONTEND_BASE_URL}"

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- bring up the full stack (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
  echo "    (frontend image build is heavy; this can take many minutes)"
  if ! $DC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary
    exit $?
  fi
  if $DC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "docker compose up -d --wait: all services healthy (incl. frontend)"
  else
    _fail "docker compose up -d --wait did NOT reach healthy within ${UP_TIMEOUT}s"
    echo "--- recent frontend logs ---"; $DC logs --tail 40 frontend 2>/dev/null || true
    echo "--- recent backend logs ---";  $DC logs --tail 40 backend  2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend + frontend healthy and serving.
echo
echo "--- [preflight] backend + frontend reachable ---"
assert_healthy backend
assert_healthy frontend
assert_status GET "${BACKEND_BASE_URL}/health" 200
# The frontend health route is served by the Next app itself.
assert_status GET "${FRONTEND_BASE_URL}/api/health" 200

# FE-05 (live): the SAME-ORIGIN /backend rewrite reaches the backend through the
# Next server (proving BACKEND_INTERNAL_URL is wired) — a browser-style call to
# the frontend origin's /backend/api/console/state must return the public state.
echo
echo "--- [FE-05 live] /backend rewrite reaches backend:8080 (same-origin egress) ---"
assert_json_ok GET "${FRONTEND_BASE_URL}/backend/api/console/state" "has:initialized"

# =============================================================================
# CRITERION FE-01 — the live auth journey via Playwright against the real stack.
# Parse the one-time FIRST-RUN SETUP TOKEN from the backend logs and hand it to
# the spec. The spec drives /setup -> /login -> shell, then drops the session
# and asserts the 401 -> /login redirect.
# =============================================================================
echo
echo "--- [FE-01] live auth journey: /setup -> /login -> shell + 401 -> /login ---"
BOOTSTRAP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -z "$BOOTSTRAP_TOKEN" ] && [ "$already_init" = "0" ]; then
  _fail "could not parse FIRST-RUN SETUP TOKEN from backend logs AND console is not initialized (cannot drive the setup leg)"
elif [ -z "$BOOTSTRAP_TOKEN" ] && [ "$already_init" = "1" ]; then
  _fail "console already initialized (re-run on a non-fresh volume) — run 'docker compose down -v' first so the one-time token is re-issued for the live setup leg"
else
  _pass "parsed the one-time FIRST-RUN SETUP TOKEN from backend logs"
  # Run the Playwright auth-flow spec against the live frontend origin.
  if ( cd "${FRONTEND_DIR}" \
        && BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
           E2E_BASE_URL="${FRONTEND_BASE_URL}" \
           npx playwright test e2e/auth-flow.spec.ts ); then
    _pass "live auth e2e PASSED: /setup -> /login -> (console) shell, and 401 -> /login (FE-01)"
  else
    _fail "live auth e2e FAILED (see Playwright output above) — the auth journey or the 401 redirect did not hold"
  fi
fi

# Anti-false-green backstop (independent of Playwright): a protected (console)
# route fetched with NO session cookie must REDIRECT to /login (the server
# layout's /me guard). curl follows redirects and we assert the FINAL URL is
# /login; a 200 that stayed on the protected path would FAIL.
echo
echo "--- [FE-01 negative] unauthenticated protected route -> /login redirect ---"
final_url="$(curl -s -o /dev/null -L --max-time 15 \
  -w '%{url_effective}' "${FRONTEND_BASE_URL}/users" 2>/dev/null)"
if printf '%s' "$final_url" | grep -qE '/login(\?|$)'; then
  _pass "unauthenticated /users redirected to login (final url: ${final_url})"
else
  _fail "unauthenticated /users did NOT land on /login (final url: '${final_url}' — guard not enforced)"
fi

echo
summary
exit $?
