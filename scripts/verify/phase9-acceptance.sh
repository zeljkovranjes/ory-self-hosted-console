#!/usr/bin/env bash
# scripts/verify/phase9-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 9 (permissions-keto-oathkeeper) live-stack acceptance gate. Proves the
# whole phase end-to-end against the REAL compose stack — PERM-01/02/03 + OATH-01
# — across both planes:
#
#   DATA PLANE (PERM-02/03), via /api/keto/*:
#     * create a relation tuple (write hits Keto :4467) and query it back (read
#       hits Keto :4466) — proving the three-port split is wired correctly
#       (T-9-port); a write routed to the read port would 404/405;
#     * query/search by namespace/object/relation/subject with server-side cursor
#       pagination (next_page_token);
#     * check returns allowed/denied (200 + {allowed}); an upstream 502 is NEVER
#       collapsed into "denied" (T-9-deny-vs-error);
#     * expand returns the subject tree (ExpandedPermissionTree);
#     * OPL-permission check: pass the permits-function name as the relation arg
#       and assert the expected allowed/denied (the empirical confirmation of the
#       permits-as-relation semantics — no code analog, must be live-asserted);
#     * delete the tuple by the FULL exact filter set (T-9-delete-broad) -> 204;
#     * CLI-interchange: assert the tuple JSON carries the crate Relationship
#       field shape the `ory`/`keto` CLI consumes (namespace/object/relation +
#       subject_id|subject_set).
#
#   CONFIG/FILE PLANE (PERM-01 / OATH-01) — owned by 09-02 / 09-03 / 09-04:
#     * OPL pre-save validate (:4469): invalid OPL -> populated errors + NO file
#       write; valid OPL -> clean result;
#     * Permission-Model save -> namespaces.ts written -> Keto restarts ONLY ->
#       healthy (StartedAt diff via assert_only_container_restarted); bad OPL or a
#       failed restart -> rollback to last-known-good;
#     * Access-Rules save -> rules.json written -> Oathkeeper restarts ONLY ->
#       healthy -> api_api::list_rules reflects the new rules;
#     * NEGATIVES: unauth -> 401; authed-no-CSRF -> 403 on writes (create/delete/
#       validate/model/rules); a sensitive Keto/Oathkeeper config key -> 403.
#
# Every negative assertion PASSes ONLY on the EXACT expected refusal (anti-false-
# green, lib.sh T-03/T-04 contract): a 2xx where a 4xx is due, an empty body, a
# missing refusal, or an over-broad delete that removed more than the named tuple
# all FAIL — a SKIP is never a silent pass. The restart scope is asserted via the
# container StartedAt diff (assert_only_container_restarted).
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script does
# the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless you ask
# it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase9-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
#
# STATUS: Wave-0 SCAFFOLD. The lifecycle + auth + helper wiring below is the live
# harness cloned from phase8-acceptance.sh; the phase-9-specific assertion BODY is
# a clearly-marked `# TODO(09-04): fill assertions` placeholder. Plan 09-04 owns
# the full gate. The scaffold MUST stay `bash -n` clean and source lib.sh.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The live config FILES this phase edits (bind-mounted RW into backend, RO into
# the Ory services). The backend writes here on a save; the host sees the same
# path. We back them up at start and restore on exit so the gate is idempotent.
KETO_NAMESPACES="${REPO_ROOT}/config/keto/namespaces.ts"
OATHKEEPER_RULES="${REPO_ROOT}/config/oathkeeper/rules.json"

: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

# The compose SERVICE name (for `docker compose exec`), distinct from the
# container_name used by `docker inspect`/`compose ps` matching.
: "${KETO_SVC:=keto}"
: "${OATHKEEPER_SVC:=oathkeeper}"

echo "=== Phase 9 acceptance: Permissions (Keto) & Oathkeeper (PERM-01..03 / OATH-01) ==="
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Keto namespaces:    ${KETO_NAMESPACES}"
echo "Oathkeeper rules:   ${OATHKEEPER_RULES}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL config files and restore them on exit (every
# positive config write mutates them in place + restarts a service). Then
# `docker compose down -v` unless KEEP_STACK=1.
# -----------------------------------------------------------------------------
ORIG_KETO_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KETO_NAMESPACES}.orig.$$")"
ORIG_OATH_SNAPSHOT="$(mktemp 2>/dev/null || echo "${OATHKEEPER_RULES}.orig.$$")"
cp "$KETO_NAMESPACES" "$ORIG_KETO_SNAPSHOT" 2>/dev/null || true
cp "$OATHKEEPER_RULES" "$ORIG_OATH_SNAPSHOT" 2>/dev/null || true

teardown() {
  # Restore the original config files (idempotent gate).
  if [ -f "$ORIG_KETO_SNAPSHOT" ]; then
    cp "$ORIG_KETO_SNAPSHOT" "$KETO_NAMESPACES" 2>/dev/null || true
    rm -f "$ORIG_KETO_SNAPSHOT" 2>/dev/null || true
  fi
  if [ -f "$ORIG_OATH_SNAPSHOT" ]; then
    cp "$ORIG_OATH_SNAPSHOT" "$OATHKEEPER_RULES" 2>/dev/null || true
    rm -f "$ORIG_OATH_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${KETO_NAMESPACES}.bak" "${OATHKEEPER_RULES}.bak" 2>/dev/null || true
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
# CRITERION (FE-05) FIRST — bundle egress. The cheapest hard gate; it builds the
# frontend and greps the built output, and must hold regardless of the live
# stack. (Run before bring-up so a leaked literal fails fast.)
# =============================================================================
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [FE-05] bundle-egress: no Ory host/port/SDK + no CDN in the built bundle ---"
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (FE-05)"
  else
    _fail "bundle-egress: FORBIDDEN Ory host/port/SDK or CDN reference in the built bundle"
  fi
else
  echo
  echo "--- [FE-05] bundle-egress SKIPPED (SKIP_EGRESS=1) — live-only run ---"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live assertions. Insecure
# cookies for THIS ephemeral run so curl can replay the session cookie over the
# plain-HTTP compose edge (mirrors the phase4..8 gates).
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- bring up the full stack (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
  echo "    (the frontend image build is heavy; this can take many minutes)"
  if ! $DC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary
    exit $?
  fi
  if $DC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "docker compose up -d --wait: all services healthy"
  else
    _fail "docker compose up -d --wait did NOT reach healthy within ${UP_TIMEOUT}s"
    echo "--- recent backend logs ---"; $DC logs --tail 40 backend 2>/dev/null || true
    echo "--- recent keto logs ---";    $DC logs --tail 40 "$KETO_CTR" 2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend + Keto + Oathkeeper healthy and serving.
echo
echo "--- [preflight] backend + ory services healthy ---"
assert_healthy backend
assert_healthy "$KETO_CTR"
assert_healthy "$OATHKEEPER_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KETO_NAMESPACES" ]; then
  _pass "live keto namespaces present: $KETO_NAMESPACES"
else
  _fail "live keto namespaces MISSING: $KETO_NAMESPACES (cannot run PERM-01)"
fi
if [ -f "$OATHKEEPER_RULES" ]; then
  _pass "live oathkeeper rules present: $OATHKEEPER_RULES"
else
  _fail "live oathkeeper rules MISSING: $OATHKEEPER_RULES (cannot run OATH-01)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-8
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token (read from the console
# DB session row) on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase9-admin@example.com"
ADMIN_PW_TEST="phase9-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"   # insecure-cookie run => dev name

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase9 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
    "${BACKEND_BASE_URL}/setup" 2>/dev/null)"
  case "$setup_code" in
    201) _pass "completed /setup (admin created)";;
    404) _pass "/setup already completed on a prior run (404) — proceeding to login";;
    *)   _fail "/setup returned '$setup_code' (want 201 or 404-already-init)";;
  esac
elif [ "$already_init" = "1" ]; then
  _pass "console already initialized (re-run; one-time token not re-logged) — proceeding to login"
else
  _fail "could not parse FIRST-RUN SETUP TOKEN from backend logs AND console is not initialized"
fi

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

_csrf_for_email() {
  local email="$1"
  $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
    "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
     WHERE a.email = '${email}' ORDER BY s.created_at DESC LIMIT 1" 2>/dev/null \
    | tr -d '[:space:]'
}

SESSION_TOKEN="$(_login_session_token "$ADMIN_EMAIL_TEST" "$ADMIN_PW_TEST")"
if [ -z "$SESSION_TOKEN" ]; then
  _fail "could not obtain a session token from /login (live criteria cannot run)"
  COOKIE_HEADER=""
  CSRF_TOKEN=""
else
  _pass "obtained an authenticated session token from /login"
  COOKIE_HEADER="Cookie: ${SESSION_COOKIE_NAME}=${SESSION_TOKEN}"
  CSRF_TOKEN="$(_csrf_for_email "$ADMIN_EMAIL_TEST")"
  if [ -n "$CSRF_TOKEN" ]; then
    _pass "obtained the per-session CSRF token (from the console session row)"
  else
    _fail "could not read csrf_token from the session row (mutations would 403)"
  fi
fi

# Guard: without an authenticated session the live criteria cannot run.
if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo
  _fail "no authenticated session/CSRF — skipping the live Phase-9 criteria"
  summary
  exit $?
fi

# The Phase-9 endpoint surface (filled by 09-04).
RELATIONSHIPS_URL="${BACKEND_BASE_URL}/api/keto/relationships"
CHECK_URL="${BACKEND_BASE_URL}/api/keto/check"
EXPAND_URL="${BACKEND_BASE_URL}/api/keto/expand"
OPL_VALIDATE_URL="${BACKEND_BASE_URL}/api/keto/opl/validate"

# =============================================================================
# TODO(09-04): fill assertions
# -----------------------------------------------------------------------------
# Plan 09-04 owns the full Phase-9 assertion body. Implement here, all PASSing
# ONLY on the EXACT expected outcome (anti-false-green):
#
#   PERM-02/03 (DATA PLANE, via $RELATIONSHIPS_URL / $CHECK_URL / $EXPAND_URL):
#     1. create a tuple (POST, write :4467) with CSRF -> 200/201 + the created
#        Relationship JSON; assert the crate field shape (namespace/object/
#        relation + subject_id|subject_set) for CLI-interchange.
#     2. query it back (GET, read :4466) filtered by namespace/object/relation
#        -> the created tuple appears; assert next_page_token cursor behavior.
#     3. check (GET, read :4466) the subject -> {allowed:true}; a known-absent
#        subject -> {allowed:false} (a 502 must NOT collapse to denied).
#     4. OPL-permission check: pass the permits-function name as `relation`
#        -> expected allowed/denied (empirical permits-as-relation confirmation).
#     5. expand (GET) the relation -> ExpandedPermissionTree with the subject.
#     6. delete (DELETE, write :4467) by the FULL exact filter set with CSRF
#        -> 204; re-query -> the tuple is gone AND no sibling tuple was removed
#        (T-9-delete-broad: an over-broad delete FAILS the gate).
#
#   PERM-01 (CONFIG/FILE PLANE, via $OPL_VALIDATE_URL + the 09-02 model route):
#     7. invalid OPL -> validate returns populated errors + NO file write.
#     8. valid OPL -> validate clean; model save -> namespaces.ts written ->
#        assert_only_container_restarted "$KETO_CTR" (Keto ONLY) -> healthy.
#     9. a save that fails health -> rollback to the .bak (last-known-good).
#
#   OATH-01 (CONFIG/FILE PLANE, via the 09-03 rules route):
#    10. rules save -> rules.json written -> assert_only_container_restarted
#        "$OATHKEEPER_CTR" (Oathkeeper ONLY) -> healthy -> list_rules reflects.
#        (VERIFY Oathkeeper /health/ready semantics after a rules-only restart —
#         09-RESEARCH Pitfall 5 / Open Q1.)
#
#   NEGATIVES (security):
#    11. unauth (no cookie) -> 401 on a protected Keto route.
#    12. authed-no-CSRF -> 403 on each write (create/delete/validate/model/rules).
#    13. a sensitive Keto/Oathkeeper config key via the {service}/{section}
#        allowlist -> 403 + NO disk write.
#
# Use the lib.sh helpers: assert_status, assert_only_container_restarted, _pass,
# _fail. Replay "$COOKIE_HEADER" + "X-CSRF-Token: $CSRF_TOKEN" on every mutation.
# =============================================================================
echo
echo "--- [TODO 09-04] Phase-9 live assertions not yet implemented (Wave-0 scaffold) ---"

echo
summary
exit $?
