#!/usr/bin/env bash
# scripts/verify/phase18-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 18 (opl-editor-upgrade-independent-track) live acceptance gate. Proves
# PERM-04 — "add real time validating in the ui" — end-to-end with anti-false-
# green discipline (lib.sh T-03/T-04 contract: a negative PASSes only on the
# EXACT expected refusal; a SKIP is never a silent pass):
#
#   (1) COLORING REGISTERED IN THE BUILT BUNDLE (Plan 18-01):
#       the built frontend client output contains the custom `ory-opl` language
#       id AND the Monarch token provider wiring (`setMonarchTokensProvider`) —
#       i.e. the coloring actually shipped — AND no new CDN host leaked (the
#       bundle-egress gate is invoked and required GREEN: same-origin /monaco/vs
#       only, zero jsDelivr/unpkg/cdnjs).
#
#   (2) LIVE-VALIDATE MARKER SOURCE DATA (Plan 18-02 hook input):
#       drive the EXISTING `POST /api/keto/opl/validate` through the backend
#       passthrough — INVALID OPL returns a populated `errors[]` carrying a
#       start/end line+column (the exact data the live hook maps to inline
#       Monaco markers); VALID OPL returns a clean (empty-errors) result. Keto
#       :4469 stays internal-only behind the backend (BACK-01/INFRA-05).
#
#   (3) 502 / TRANSPORT -> "UNAVAILABLE", NOT "INVALID" (T-18-05, Pitfall 13):
#       UNIT-AUTHORITATIVE. The live stack returns a 422-class body for bad OPL,
#       never a 502, so the transport-failure branch cannot be driven live. The
#       frontend unit suite (`use-live-opl-validate` + `permissions/model`)
#       encodes 502/transport -> unavailable=true + ZERO error markers (never
#       "invalid") and the pre-save gate independence; we RUN it here and require
#       it GREEN. (Cited explicitly per the plan.)
#
#   (4) PRE-SAVE AUTHORITATIVE GATE UNCHANGED — the Phase-9 OPL regression:
#       invalid OPL via the model PUT -> 422 AND namespaces.ts UNCHANGED (no
#       write); valid OPL via the model PUT -> namespaces.ts written -> Keto
#       restarts ONLY (assert_only_container_restarted) -> healthy. This is the
#       PERM-01 gate the live hook must NOT alter.
#
#   (5) BUNDLE-EGRESS GREEN (FE-05): invoked and required PASS (re-asserted
#       alongside (1); zero Ory host/port/SDK + zero CDN in the built bundle).
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script
# does the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless
# you ask it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase18-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress + ory-opl built-bundle gate
#   SKIP_UNIT=1      skip the frontend unit suite (criterion 3 is then NOT proven)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500)
#
# bash -n clean; sources lib.sh; follows the phase9-acceptance harness contract.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FRONTEND_DIR="${FRONTEND_DIR:-${REPO_ROOT}/frontend}"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

KETO_NAMESPACES="${REPO_ROOT}/config/keto/namespaces.ts"

: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

echo "=== Phase 18 acceptance: live OPL validation in the UI (PERM-04) ==="
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Frontend dir:       ${FRONTEND_DIR}"
echo "Keto namespaces:    ${KETO_NAMESPACES}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL Keto namespaces and restore on exit (the
# valid-OPL model PUT mutates it in place + restarts Keto). Then `docker compose
# down -v` unless KEEP_STACK=1.
# -----------------------------------------------------------------------------
ORIG_KETO_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KETO_NAMESPACES}.orig.$$")"
cp "$KETO_NAMESPACES" "$ORIG_KETO_SNAPSHOT" 2>/dev/null || true

teardown() {
  if [ -f "$ORIG_KETO_SNAPSHOT" ]; then
    cp "$ORIG_KETO_SNAPSHOT" "$KETO_NAMESPACES" 2>/dev/null || true
    rm -f "$ORIG_KETO_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${KETO_NAMESPACES}.bak" 2>/dev/null || true
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
# CRITERION 1 + 5 (cheapest hard gate, runs first, builds the frontend):
#   - bundle-egress.sh GREEN (no Ory host/port/SDK + no CDN), AND
#   - the built client bundle ships the ory-opl coloring (the `ory-opl` language
#     id + the Monarch `setMonarchTokensProvider` wiring).
# Both assert on built OUTPUT (what ships to browsers), not source.
# =============================================================================
STATIC_DIR="${FRONTEND_DIR}/.next/static"
STANDALONE_NEXT="${FRONTEND_DIR}/.next/standalone/.next"

if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [FE-05] bundle-egress: no Ory host/port/SDK + no CDN in the built bundle ---"
  # bundle-egress.sh builds the frontend (unless SKIP_BUILD=1) and greps output.
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (FE-05)"
  else
    _fail "bundle-egress: FORBIDDEN Ory host/port/SDK or CDN reference in the built bundle"
  fi

  echo
  echo "--- [PERM-04/18-01] ory-opl coloring registered in the BUILT bundle ---"
  if [ ! -d "$STATIC_DIR" ]; then
    _fail "built output ${STATIC_DIR} not found — cannot assert the ory-opl coloring shipped"
  else
    SEARCH_ROOTS=("$STATIC_DIR")
    [ -d "$STANDALONE_NEXT" ] && SEARCH_ROOTS+=("$STANDALONE_NEXT")
    # The custom language id is a string literal -> survives minification verbatim.
    if grep -rIlF "ory-opl" "${SEARCH_ROOTS[@]}" >/dev/null 2>&1; then
      _pass "[PERM-04] built bundle contains the 'ory-opl' language id (coloring shipped)"
    else
      _fail "[PERM-04] built bundle is MISSING the 'ory-opl' language id (coloring did NOT ship)"
    fi
    # The Monarch token-provider call is a Monaco API property name -> preserved
    # in minified output (property access, not a renamed local). Its presence
    # proves the grammar is actually WIRED, not merely a dangling string.
    if grep -rIlF "setMonarchTokensProvider" "${SEARCH_ROOTS[@]}" >/dev/null 2>&1; then
      _pass "[PERM-04] built bundle wires the Monarch token provider (setMonarchTokensProvider)"
    else
      _fail "[PERM-04] built bundle is MISSING setMonarchTokensProvider (coloring not wired)"
    fi
  fi
else
  echo
  echo "--- [FE-05] bundle-egress + ory-opl built-bundle check SKIPPED (SKIP_EGRESS=1) ---"
fi

# =============================================================================
# CRITERION 3 (UNIT-AUTHORITATIVE): 502/transport -> unavailable, NOT invalid.
# The live stack returns a 422-class body for bad OPL (never a 502), so the
# transport-failure branch of the live hook cannot be driven against the real
# engine. The frontend unit suite encodes it (use-live-opl-validate: 502/
# transport -> unavailable=true + ZERO error markers; permissions/model: the
# muted hint is shown and the destructive "invalid" banner is NOT, and the
# pre-save gate is independent of the live result). Run it and require GREEN.
# =============================================================================
if [ "${SKIP_UNIT:-0}" != "1" ]; then
  echo
  echo "--- [PERM-04/T-18-05] frontend unit suite: 502/transport -> unavailable-not-invalid (unit-authoritative) ---"
  if ( cd "$FRONTEND_DIR" && npm test -- use-live-opl-validate "permissions/model" ); then
    _pass "[PERM-04] unit suite GREEN: 502/transport -> unavailable (never invalid); pre-save gate independent"
  else
    _fail "[PERM-04] unit suite FAILED: the 502->unavailable-not-invalid / gate-independence contract is broken"
  fi
else
  echo
  echo "--- [PERM-04] unit suite SKIPPED (SKIP_UNIT=1) — criterion 3 NOT proven this run ---"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live assertions (criteria
# 2 + 4). Insecure cookies for THIS ephemeral run so curl can replay the session
# cookie over the plain-HTTP compose edge (mirrors the phase4..9 gates).
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- bring up the full stack (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
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

# Preflight: backend + Keto healthy and serving.
echo
echo "--- [preflight] backend + keto healthy ---"
assert_healthy backend
assert_healthy "$KETO_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KETO_NAMESPACES" ]; then
  _pass "live keto namespaces present: $KETO_NAMESPACES"
else
  _fail "live keto namespaces MISSING: $KETO_NAMESPACES (cannot run the PERM-01 regression)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-9
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase18-admin@example.com"
ADMIN_PW_TEST="phase18-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase18 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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

if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo
  _fail "no authenticated session/CSRF — skipping the live Phase-18 criteria"
  summary
  exit $?
fi

OPL_VALIDATE_URL="${BACKEND_BASE_URL}/api/keto/opl/validate"
MODEL_URL="${BACKEND_BASE_URL}/api/keto/permission-model"

# --- HTTP helpers (cloned from the phase9 gate) ------------------------------
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 200 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }
_json_field() {
  printf '%s' "$1" | EXPR="$2" node -e '
    const expr = process.env.EXPR;
    let input = require("fs").readFileSync(0, "utf8");
    let data; try { data = JSON.parse(input); } catch (e) { process.exit(0); }
    let out;
    try { out = (function(){ return eval(expr); })(); } catch (e) { process.exit(0); }
    if (out === undefined || out === null) process.exit(0);
    process.stdout.write(typeof out === "string" ? out : JSON.stringify(out));
  ' 2>/dev/null
}

TEST_NS="phase18_acceptance"

echo
echo "============================================================"
echo " CRITERION 2 — live-validate marker SOURCE DATA via /api/keto/opl/validate"
echo "============================================================"

# A VALID OPL model (the live hook's clean-result path).
OPL_VALID_SRC="$(NS="$TEST_NS" node -e '
  const ns = process.env.NS;
  const src =
    "import { Namespace, Context } from \"@ory/keto-namespace-types\"\n\n" +
    "class " + ns + " implements Namespace {\n" +
    "  related: {\n" +
    "    viewers: SubjectSet<" + ns + ", \"viewers\">[]\n" +
    "  }\n\n" +
    "  permits = {\n" +
    "    view: (ctx: Context): boolean =>\n" +
    "      this.related.viewers.includes(ctx.subject),\n" +
    "  }\n" +
    "}\n";
  process.stdout.write(JSON.stringify({ source: src }));
')"
INVALID_OPL='{"source":"class Broken implements Namespace { this is not valid typescript @@@ }"}'

echo
echo "--- [PERM-04] invalid OPL -> 200 + populated errors[] carrying start/end line+column (the marker source data) ---"
val_inv="$(_auth_mut POST "$OPL_VALIDATE_URL" "$INVALID_OPL")"
val_inv_code="$(_code_of "$val_inv")"; val_inv_body="$(_body_of "$val_inv")"
INV_ERRS="$(_json_field "$val_inv_body" '(data.errors && data.errors.length) ? data.errors.length : 0')"
if [ "$val_inv_code" = "200" ] && [ -n "$INV_ERRS" ] && [ "$INV_ERRS" != "0" ]; then
  _pass "[PERM-04] POST /opl/validate (invalid) -> 200 with populated errors ($INV_ERRS)"
else
  _fail "[PERM-04] POST /opl/validate (invalid) -> code='$val_inv_code' errors='$INV_ERRS' (want 200 + errors; body: $val_inv_body)"
fi
# The marker mapping REQUIRES a start position line (the line the squiggle lands
# on). Assert at least one error carries a numeric start line — tolerating Keto
# v26.2.0's CAPITAL `Line` key (verified live: the backend passes the :4469 body
# through verbatim as {"start":{"Line":N,"column":M}}). The live hook reads both
# casings; this assertion mirrors that so it can't false-fail on the real shape
# nor false-pass on a position-less body (anti-false-green).
HAS_POS="$(_json_field "$val_inv_body" '
  (function(){
    const es = (data.errors)||[];
    const lineOf = p => p && (typeof p.Line === "number" ? p.Line
                          : (typeof p.line === "number" ? p.line : undefined));
    return es.some(e => e && e.start && typeof lineOf(e.start) === "number")
      ? "YES" : "NO";
  })()')"
if [ "$HAS_POS" = "YES" ]; then
  _pass "[PERM-04] at least one error carries a numeric start line (Keto 'Line'/'line') — the live marker source data"
else
  _fail "[PERM-04] errors[] carry NO start line position -> the live hook would have no marker location (body: $val_inv_body)"
fi

echo
echo "--- [PERM-04] valid OPL -> 200 + clean (empty errors) result (the live hook clears markers) ---"
val_ok="$(_auth_mut POST "$OPL_VALIDATE_URL" "$OPL_VALID_SRC")"
val_ok_code="$(_code_of "$val_ok")"; val_ok_body="$(_body_of "$val_ok")"
OK_ERRS="$(_json_field "$val_ok_body" '(data.errors && data.errors.length) ? data.errors.length : 0')"
if [ "$val_ok_code" = "200" ] && { [ -z "$OK_ERRS" ] || [ "$OK_ERRS" = "0" ]; }; then
  _pass "[PERM-04] POST /opl/validate (valid) -> 200 with NO errors (clean parse)"
else
  _fail "[PERM-04] POST /opl/validate (valid) -> code='$val_ok_code' errors='$OK_ERRS' (want 200 + clean; body: $val_ok_body)"
fi

# Keto :4469 stays internal-only (the live check only goes through the backend
# passthrough). T-18-08 / INFRA-05: the validate admin port is NOT host-exposed.
echo
echo "--- [T-18-08/INFRA-05] Keto validate admin port (:4469) is NOT reachable from the host ---"
assert_port_refused 4469

echo
echo "============================================================"
echo " CRITERION 4 — PRE-SAVE GATE UNCHANGED (Phase-9 OPL regression)"
echo "============================================================"

echo
echo "--- [PERM-01] invalid OPL via model PUT -> 422 AND namespaces.ts UNCHANGED (no write) ---"
snapshot_file "$KETO_NAMESPACES"
model_inv="$(_auth_mut PUT "$MODEL_URL" "$INVALID_OPL")"
model_inv_code="$(_code_of "$model_inv")"; model_inv_body="$(_body_of "$model_inv")"
if [ "$model_inv_code" = "422" ]; then
  _pass "[PERM-01] PUT /permission-model (invalid OPL) -> 422 (rejected pre-save)"
else
  _fail "[PERM-01] PUT /permission-model (invalid OPL) -> '$model_inv_code' (want 422; body: $model_inv_body)"
fi
assert_file_unchanged "$KETO_NAMESPACES"

echo
echo "--- [PERM-01] valid OPL via model PUT -> healthy, restart Keto ONLY, namespaces.ts written ---"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
model_ok="$(_auth_mut PUT "$MODEL_URL" "$OPL_VALID_SRC")"
model_ok_code="$(_code_of "$model_ok")"; model_ok_body="$(_body_of "$model_ok")"
if [ "$model_ok_code" = "200" ] && printf '%s' "$model_ok_body" | grep -q '"status":"healthy"'; then
  _pass "[PERM-01] PUT /permission-model (valid OPL) -> 200 {status:healthy} (written + Keto healthy)"
else
  _fail "[PERM-01] PUT /permission-model (valid OPL) -> '$model_ok_code' (want 200 {status:healthy}; body: $model_ok_body)"
fi
# RESTART SCOPE: ONLY Keto restarted (Kratos/Hydra/Oathkeeper StartedAt UNCHANGED).
assert_only_container_restarted "$KETO_CTR" "$KRATOS_CTR" "$HYDRA_CTR" "$OATHKEEPER_CTR"
wait_container_healthy "$KETO_CTR" 90
# Disk proof: the written namespaces.ts carries our namespace.
assert_grep "class[[:space:]]+${TEST_NS}" "$KETO_NAMESPACES"

echo
summary
exit $?
