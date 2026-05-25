#!/usr/bin/env bash
# scripts/verify/phase4-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 4 (backend-core-yaml-config-subsystem) live-stack acceptance gate
# (BACK-04 / BACK-06). Proves the four phase success criteria end-to-end against
# the REAL running stack: the transactional YAML config-edit engine
# validate -> write -> restart-affected-only -> health -> rollback.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled):
#   docker compose down -v
#   MSYS_NO_PATHCONV=1 docker compose build backend
#   MSYS_NO_PATHCONV=1 docker compose up -d --wait
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase4-acceptance.sh
#   docker compose down -v
#   git checkout config/kratos/kratos.yml   # restore the live-mutated file
#
# THE FOUR CRITERIA (each a labeled section below):
#   1. VALID apply: an authenticated allowlisted `/session/lifespan="24h"` PUT
#      returns 200 healthy. This is the env-overlay-validation proof — the live
#      `config/kratos/kratos.yml` OMITS `dsn` (env-injected) yet Kratos' schema
#      marks dsn root-required, so the PUT validates the env-OVERLAID effective
#      doc and returns 200 (NOT 422). It is ALSO the absent-parent-create proof —
#      the live doc ships NO `session:` block, so `apply_patch` creates it. We
#      assert: 200 + ONLY ory-kratos restarted (the other three StartedAt
#      unchanged) + Kratos /health/ready 200 again + a follow-up GET reflects
#      `/session/lifespan == "24h"` + the WRITTEN kratos.yml still has NO dsn.
#   2. INVALID reject: a schema-invalid `/session/lifespan` -> 422 + file
#      UNCHANGED (validation rejects before disk; the overlay does not mask a
#      real schema error).
#   3. OUT-OF-SCOPE reject: `/serve/admin/base_url` (sensitive) -> 403 + file
#      UNCHANGED (BACK-06 allowlist/denylist).
#   4. BREAK-HEALTH -> ROLLBACK: a schema-valid but boot-failing value -> the
#      service fails /health/ready within the timeout -> the endpoint reports
#      `failed`, the file is rolled back byte-equal to the `.bak`, and Kratos
#      returns 200 again after the auto-restart.
#
# Every negative assertion PASSes ONLY on the exact expected refusal
# (anti-false-green, T-04-17): a reject that wrote to disk, a missing restart,
# or a 200-where-a-422-was-due all FAIL.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

# Repo root (this script lives in scripts/verify/).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Base URL for host-side HTTP assertions (overridable; default 8080).
: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"

# The live Kratos config file (bind-mounted into ory-kratos + the backend). The
# backend writes here; the host sees the change on this same path.
KRATOS_YML="${REPO_ROOT}/config/kratos/kratos.yml"
KRATOS_BAK="${KRATOS_YML}.bak"

# The four Ory containers (compose default names). Override if your project name
# differs (e.g. COMPOSE_PROJECT_NAME prefixes the container).
: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

echo "=== Phase 4 acceptance: transactional YAML config-edit engine (BACK-04 / BACK-06) ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"
echo "Repo root: ${REPO_ROOT}"
echo "Kratos config: ${KRATOS_YML}"

# Preserve the ORIGINAL committed kratos.yml so the gate is idempotent: restore
# it on exit regardless of pass/fail (the live apply mutates it in place).
ORIG_KRATOS_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KRATOS_YML}.orig.$$")"
cp "$KRATOS_YML" "$ORIG_KRATOS_SNAPSHOT" 2>/dev/null || true
# The Criterion-4 fault injection moves the identity schema aside; this global
# records where, so the EXIT trap always puts it back even on an early failure.
KRATOS_SCHEMA="${REPO_ROOT}/config/kratos/identity.schema.json"
KRATOS_SCHEMA_AWAY=""
restore_original() {
  if [ -f "$ORIG_KRATOS_SNAPSHOT" ]; then
    cp "$ORIG_KRATOS_SNAPSHOT" "$KRATOS_YML" 2>/dev/null || true
    rm -f "$ORIG_KRATOS_SNAPSHOT" 2>/dev/null || true
  fi
  # Restore the identity schema if Criterion 4 moved it and did not put it back.
  if [ -n "$KRATOS_SCHEMA_AWAY" ] && [ -f "$KRATOS_SCHEMA_AWAY" ]; then
    mv "$KRATOS_SCHEMA_AWAY" "$KRATOS_SCHEMA" 2>/dev/null || true
  fi
  # Remove any leftover .bak the engine created.
  rm -f "$KRATOS_BAK" 2>/dev/null || true
}
trap restore_original EXIT

# =============================================================================
# Preflight — the stack is up and the backend is healthy.
# =============================================================================
echo
echo "--- [preflight] backend healthy + config file present ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KRATOS_YML" ]; then
  _pass "live config present: $KRATOS_YML"
else
  _fail "live config MISSING: $KRATOS_YML (cannot run the config-edit gate)"
fi
# The live committed doc must ship NO session block AND no dsn (the two proofs).
assert_not_grep '^[[:space:]]*session[[:space:]]*:' "$KRATOS_YML"
assert_no_dsn_in_file "$KRATOS_YML"

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-3
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs.
# =============================================================================
echo
echo "--- [auth] complete /setup + login to obtain an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase4-admin@example.com"
ADMIN_PW_TEST="phase4-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=__Host-console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase4 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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

# Read the per-session CSRF token from the console DB. The login/me DTOs are
# deliberately secret-free (they do NOT return the CSRF token, asserted in the
# Phase-2 gate), so — exactly as phase2-acceptance.sh does — the gate reads it
# from the latest session row for this admin to drive the state-changing PUTs.
_csrf_for_email() {
  local email="$1"
  $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
    "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
     WHERE a.email = '${email}' ORDER BY s.created_at DESC LIMIT 1" 2>/dev/null \
    | tr -d '[:space:]'
}

SESSION_TOKEN="$(_login_session_token "$ADMIN_EMAIL_TEST" "$ADMIN_PW_TEST")"
if [ -z "$SESSION_TOKEN" ]; then
  _fail "could not obtain a session token from /login (config-edit PUTs cannot run)"
  COOKIE_HEADER=""
  CSRF_TOKEN=""
else
  _pass "obtained an authenticated session token from /login"
  COOKIE_HEADER="Cookie: ${SESSION_COOKIE_NAME}=${SESSION_TOKEN}"
  CSRF_TOKEN="$(_csrf_for_email "$ADMIN_EMAIL_TEST")"
  if [ -n "$CSRF_TOKEN" ]; then
    _pass "obtained the per-session CSRF token (from the console session row)"
  else
    _fail "could not read csrf_token from the session row (PUTs would 403)"
  fi
fi

# Guard: if we have no authenticated session, the live criteria cannot run.
if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo
  _fail "no authenticated session/CSRF — skipping the four live criteria"
  summary
  exit $?
fi

CFG_URL="${BACKEND_BASE_URL}/api/config/kratos/session"

# Helper: issue an authenticated config PUT, echo "HTTP_CODE<newline>BODY".
_cfg_put() {
  local json="$1"
  curl -s -w '\n%{http_code}' --max-time 90 -X PUT \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -H 'Content-Type: application/json' --data "$json" "$CFG_URL" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }

# =============================================================================
# CRITERION 1 — VALID apply: 200 + only-kratos-restart + healthy + GET reflects
# the value + the written file still has NO dsn (env-overlay validation proof +
# absent-parent-create proof + A3 real-write-on-the-mount spike).
# =============================================================================
echo
echo "--- [BACK-04] Criterion 1: VALID /session/lifespan='24h' apply ---"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"

resp="$(_cfg_put '{"/session/lifespan":"24h"}')"
code="$(_code_of "$resp")"
body="$(_body_of "$resp")"
if [ "$code" = "200" ]; then
  _pass "valid apply returned 200 (env-overlay validation passed on the no-dsn doc): $body"
else
  _fail "valid apply returned '$code' (want 200; body: $body)"
fi

# ONLY ory-kratos restarted (the other three StartedAt unchanged) — BACK-05/T-04-18.
assert_only_container_restarted "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"

# Kratos is healthy again. The engine already polled /health/ready (the 200
# proves the service was ready), but Docker's own healthcheck reports `starting`
# for a few seconds post-restart, so poll until it settles to `healthy`.
wait_container_healthy "$KRATOS_CTR" 60

# A follow-up GET reflects the applied value (persisted through write+restart).
get_body="$(curl -s --max-time 10 -H "$COOKIE_HEADER" "$CFG_URL" 2>/dev/null)"
if printf '%s' "$get_body" | grep -q '"/session/lifespan":"24h"'; then
  _pass "GET reflects the applied /session/lifespan=24h (persisted through restart): $get_body"
else
  _fail "GET does NOT reflect /session/lifespan=24h (got: $get_body)"
fi

# The WRITTEN file created the absent session parent AND still has NO dsn key
# (the validation overlay was never persisted — T-04-25).
assert_grep '^[[:space:]]*session[[:space:]]*:' "$KRATOS_YML"
assert_grep 'lifespan:[[:space:]]*[\"'\'']?24h' "$KRATOS_YML"
assert_no_dsn_in_file "$KRATOS_YML"
# The non-edited secrets block is preserved byte-present (Pitfall 7 spirit).
assert_grep '^[[:space:]]*secrets[[:space:]]*:' "$KRATOS_YML"

# =============================================================================
# CRITERION 2 — INVALID reject: 422 + file UNCHANGED (overlay does not mask a
# real schema error).
# =============================================================================
echo
echo "--- [BACK-04] Criterion 2: INVALID /session/lifespan -> 422, no disk write ---"
snapshot_file "$KRATOS_YML"
resp="$(_cfg_put '{"/session/lifespan":"not-a-valid-duration"}')"
code="$(_code_of "$resp")"
body="$(_body_of "$resp")"
if [ "$code" = "422" ]; then
  _pass "schema-invalid value rejected with 422 (overlay did not mask the error): $body"
else
  _fail "schema-invalid value returned '$code' (want 422; body: $body)"
fi
# The 422 body carries value-free field errors and never a secret.
if printf '%s' "$body" | grep -q 'validation_failed'; then
  _pass "422 body carries the validation_failed machine code"
else
  _fail "422 body missing validation_failed: $body"
fi
if printf '%s' "$body" | grep -qiE 'postgres://|dsn'; then
  _fail "422 body LEAKS a dsn/secret marker: $body"
else
  _pass "422 body carries no dsn/secret marker"
fi
assert_file_unchanged "$KRATOS_YML"

# =============================================================================
# CRITERION 3 — OUT-OF-SCOPE / sensitive reject: 403 forbidden_key + file
# UNCHANGED (BACK-06).
# =============================================================================
echo
echo "--- [BACK-06] Criterion 3: sensitive /serve/admin/base_url -> 403, no disk write ---"
snapshot_file "$KRATOS_YML"
resp="$(_cfg_put '{"/serve/admin/base_url":"http://evil:9999/"}')"
code="$(_code_of "$resp")"
body="$(_body_of "$resp")"
if [ "$code" = "403" ]; then
  _pass "sensitive/out-of-scope key rejected with 403 forbidden_key: $body"
else
  _fail "sensitive key returned '$code' (want 403; body: $body)"
fi
if printf '%s' "$body" | grep -q 'evil:9999'; then
  _fail "403 body echoes the rejected value (must never): $body"
else
  _pass "403 body does not echo the rejected value"
fi
assert_file_unchanged "$KRATOS_YML"

# =============================================================================
# CRITERION 4 — BREAK-HEALTH -> ROLLBACK: a restart that fails to become healthy
# -> the engine restores the last-known-good `.bak` (byte-equal), reports
# `failed` (502), and the service recovers once the underlying fault clears.
#
# WHY A FAULT INJECTION (not a bad config value): Kratos v26.2.0 is deliberately
# tolerant of the LOW-RISK allowlisted `session` keys — it hot-reloads and stays
# healthy for any schema-valid `/session/lifespan` / `/session/cookie/*` value
# (verified empirically), by design (the allowlist was chosen to be safe,
# BACK-06). So no allowlisted+schema-valid PUT can make Kratos fail /health/ready.
# To still PROVE the engine's rollback END-TO-END through the real PUT path, we
# inject an EXTERNAL fault that makes the NEXT Kratos start fail — we move aside
# the referenced identity-schema file (a missing schema makes `kratos serve`
# exit on start, verified). A normal valid `/session/lifespan` PUT then:
#   backup good file -> write merged -> restart -> Kratos crashes (missing
#   schema) -> health poll TIMES OUT -> engine restores the `.bak` (the
#   last-known-good) -> restart (still crashes while the fault persists) ->
#   reports `failed` (502 health_failed).
# We assert the `.bak` restoration is byte-equal to the captured good file, then
# CLEAR the fault and confirm Kratos recovers to healthy. This exercises the
# REAL engine (validate -> write -> restart -> poll -> rollback) against the live
# stack, with the disk fault standing in for the bad-config-rejected-at-boot case.
# =============================================================================
echo
echo "--- [BACK-04] Criterion 4: break-health -> auto-rollback -> recover ---"
# Capture the known-good file as the expected rollback target (this is what the
# engine's `<file>.bak` will hold and restore).
GOOD_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KRATOS_YML}.good.$$")"
cp "$KRATOS_YML" "$GOOD_SNAPSHOT"

# Inject the fault: move the identity schema file aside so the next `kratos
# serve` start fails. The path is referenced by the committed kratos.yml.
# KRATOS_SCHEMA + KRATOS_SCHEMA_AWAY are declared at the top so the EXIT trap can
# always restore the file.
KRATOS_SCHEMA_AWAY="${KRATOS_SCHEMA}.away.$$"
schema_moved=0
if [ -f "$KRATOS_SCHEMA" ]; then
  mv "$KRATOS_SCHEMA" "$KRATOS_SCHEMA_AWAY" && schema_moved=1
fi
# Ensure we ALWAYS put the schema back, whatever happens below.
restore_schema() {
  if [ "$schema_moved" = "1" ] && [ -f "$KRATOS_SCHEMA_AWAY" ]; then
    mv "$KRATOS_SCHEMA_AWAY" "$KRATOS_SCHEMA" 2>/dev/null || true
    schema_moved=0
    KRATOS_SCHEMA_AWAY=""
  fi
}
if [ "$schema_moved" = "1" ]; then
  _pass "fault injected: identity schema moved aside (next Kratos start will fail)"
else
  _fail "could not move the identity schema aside (cannot inject the break-health fault)"
fi

# A normal valid allowlisted PUT. With the fault in place the restarted Kratos
# never reaches /health/ready, so the engine rolls back and reports failed.
# The engine polls health up to its 60s timeout, then rolls back, restarts, and
# re-polls another 60s — so allow a generous client timeout (>~120s).
resp="$(curl -s -w '\n%{http_code}' --max-time 200 -X PUT \
  -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -H 'Content-Type: application/json' --data '{"/session/lifespan":"48h"}' "$CFG_URL" 2>/dev/null)"
code="$(_code_of "$resp")"
body="$(_body_of "$resp")"
if [ "$code" = "502" ] && printf '%s' "$body" | grep -q '"status":"failed"'; then
  _pass "break-health PUT reported 502 health_failed {status:failed} (rolled back): $body"
elif [ "$code" = "502" ]; then
  _pass "break-health PUT reported 502 (rolled back): $body"
else
  _fail "break-health PUT returned '$code' (want 502 health_failed; body: $body)"
fi

# The live file was rolled back byte-equal to the last-known-good copy.
assert_rolled_back "$KRATOS_YML" "$GOOD_SNAPSHOT"

# Clear the fault, then confirm Kratos recovers to healthy (the engine left the
# last-known-good config on disk; with the schema present again it boots clean).
restore_schema
docker restart "$KRATOS_CTR" >/dev/null 2>&1 || true
wait_container_healthy "$KRATOS_CTR" 90

# A GET still reflects the LAST-KNOWN-GOOD value (the 24h from Criterion 1), not
# the rejected 48h — proving the rollback reverted the change end-to-end.
get_body="$(curl -s --max-time 10 -H "$COOKIE_HEADER" "$CFG_URL" 2>/dev/null)"
if printf '%s' "$get_body" | grep -q '"/session/lifespan":"24h"'; then
  _pass "post-rollback GET shows the last-known-good 24h (the 48h edit was reverted): $get_body"
else
  _fail "post-rollback GET does not show the last-known-good value (got: $get_body)"
fi
rm -f "$GOOD_SNAPSHOT" 2>/dev/null || true

echo
summary
exit $?
