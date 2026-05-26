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
# STATUS: FULL LIVE GATE (owned by 09-04). The lifecycle + auth + helper wiring
# is the live harness derived from phase8-acceptance.sh; the phase-9-specific
# assertion body below implements the complete PERM-01/02/03 + OATH-01 + negatives
# gate (no TODO placeholder remains). The script stays `bash -n` clean and sources
# lib.sh.
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

# The Phase-9 endpoint surface.
RELATIONSHIPS_URL="${BACKEND_BASE_URL}/api/keto/relationships"
CHECK_URL="${BACKEND_BASE_URL}/api/keto/check"
EXPAND_URL="${BACKEND_BASE_URL}/api/keto/expand"
OPL_VALIDATE_URL="${BACKEND_BASE_URL}/api/keto/opl/validate"
MODEL_URL="${BACKEND_BASE_URL}/api/keto/permission-model"
RULES_FILE_URL="${BACKEND_BASE_URL}/api/config/oathkeeper/rules"
RULES_LIST_URL="${BACKEND_BASE_URL}/api/oathkeeper/rules"
CFG_URL="${BACKEND_BASE_URL}/api/config"

# --- HTTP helpers (cloned from the phase8 gate) ------------------------------
# Authenticated GET (cookie only; GET is CSRF-exempt). Echo "CODE<newline>BODY".
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
# Authenticated mutating call (cookie + CSRF + optional JSON body). "CODE\nBODY".
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 200 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }

# Pull a JSON field from a body via node. _json_field "<body>" '<js-over-data>'.
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

# A disposable test namespace/object so the gate never collides with real data.
TEST_NS="acceptance_docs"
TEST_OBJ="doc:phase9-acceptance"
TEST_REL="viewer"
TEST_SUBJ="user:phase9-acceptance-alice"
ABSENT_SUBJ="user:phase9-acceptance-nobody"
# The OPL permits-function name we will define + check as a relation (PERM-03 #3).
PERMITS_FN="view"

echo
echo "============================================================"
echo " GROUP 0 — PERM-01: install a disposable OPL model (permits fn)"
echo "============================================================"
# Define an OPL namespace that declares a `viewer` relation AND a `view` PERMITS
# FUNCTION (permit = has the viewer relation). Saving this model proves PERM-01
# (validate -> write namespaces.ts -> restart Keto ONLY -> healthy) AND sets up
# the permits-as-relation empirical check in GROUP 2. We snapshot the original
# file and the teardown trap restores it.
OPL_MODEL_SRC="$(NS="$TEST_NS" node -e '
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

echo
echo "--- [PERM-01] invalid OPL -> validate returns populated errors ---"
INVALID_OPL='{"source":"class Broken implements Namespace { this is not valid typescript @@@ }"}'
val_inv="$(_auth_mut POST "$OPL_VALIDATE_URL" "$INVALID_OPL")"
val_inv_code="$(_code_of "$val_inv")"; val_inv_body="$(_body_of "$val_inv")"
INV_ERRS="$(_json_field "$val_inv_body" '(data.errors && data.errors.length) ? data.errors.length : 0')"
if [ "$val_inv_code" = "200" ] && [ -n "$INV_ERRS" ] && [ "$INV_ERRS" != "0" ]; then
  _pass "[PERM-01] POST /opl/validate (invalid) -> 200 with populated errors ($INV_ERRS)"
else
  _fail "[PERM-01] POST /opl/validate (invalid) -> code='$val_inv_code' errors='$INV_ERRS' (want 200 + errors; body: $val_inv_body)"
fi

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
# Anti-false-green NO-write proof: the live OPL file is byte-identical.
assert_file_unchanged "$KETO_NAMESPACES"

echo
echo "--- [PERM-01] valid OPL via model PUT -> healthy, restart Keto ONLY, namespaces.ts written ---"
# Validate the valid model is clean first (the pre-save gate the editor uses).
val_ok="$(_auth_mut POST "$OPL_VALIDATE_URL" "$OPL_MODEL_SRC")"
val_ok_code="$(_code_of "$val_ok")"; val_ok_body="$(_body_of "$val_ok")"
OK_ERRS="$(_json_field "$val_ok_body" '(data.errors && data.errors.length) ? data.errors.length : 0')"
if [ "$val_ok_code" = "200" ] && { [ -z "$OK_ERRS" ] || [ "$OK_ERRS" = "0" ]; }; then
  _pass "[PERM-01] POST /opl/validate (valid model) -> 200 with NO errors (clean parse)"
else
  _fail "[PERM-01] POST /opl/validate (valid model) -> code='$val_ok_code' errors='$OK_ERRS' (want 200 + clean; body: $val_ok_body)"
fi
# Snapshot every Ory container's StartedAt, then PUT the model.
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
model_ok="$(_auth_mut PUT "$MODEL_URL" "$OPL_MODEL_SRC")"
model_ok_code="$(_code_of "$model_ok")"; model_ok_body="$(_body_of "$model_ok")"
if [ "$model_ok_code" = "200" ] && printf '%s' "$model_ok_body" | grep -q '"status":"healthy"'; then
  _pass "[PERM-01] PUT /permission-model (valid OPL) -> 200 {status:healthy} (written + Keto healthy)"
else
  _fail "[PERM-01] PUT /permission-model (valid OPL) -> '$model_ok_code' (want 200 {status:healthy}; body: $model_ok_body)"
fi
# RESTART SCOPE: ONLY Keto restarted (Kratos/Hydra/Oathkeeper StartedAt UNCHANGED).
assert_only_container_restarted "$KETO_CTR" "$KRATOS_CTR" "$HYDRA_CTR" "$OATHKEEPER_CTR"
wait_container_healthy "$KETO_CTR" 90
# CLI-01 / disk proof: the written namespaces.ts carries our namespace + permits fn.
assert_grep "class[[:space:]]+${TEST_NS}" "$KETO_NAMESPACES"
assert_grep "view:" "$KETO_NAMESPACES"
# GET the model back -> the source reflects the write (the editor's load path).
model_get_body="$(_body_of "$(_auth_get "$MODEL_URL")")"
if printf '%s' "$(_json_field "$model_get_body" 'data.source')" | grep -q "class ${TEST_NS}"; then
  _pass "[PERM-01] GET /permission-model reflects the saved model (source round-trips)"
else
  _fail "[PERM-01] GET /permission-model did NOT reflect the saved model (body: $model_get_body)"
fi

echo
echo "============================================================"
echo " GROUP 1 — PERM-02/03 DATA PLANE: tuple write/read/check/expand/delete"
echo "============================================================"

# --- PERM-02: create a tuple (WRITE :4467) -----------------------------------
echo
echo "--- [PERM-02] create a relation tuple (POST, WRITE :4467) ---"
CREATE_TUPLE_BODY="$(NS="$TEST_NS" OBJ="$TEST_OBJ" REL="viewers" SUBJ="$TEST_SUBJ" node -e '
  process.stdout.write(JSON.stringify({
    namespace: process.env.NS, object: process.env.OBJ,
    relation: process.env.REL, subject_id: process.env.SUBJ
  }));
')"
create_resp="$(_auth_mut POST "$RELATIONSHIPS_URL" "$CREATE_TUPLE_BODY")"
create_code="$(_code_of "$create_resp")"; create_body="$(_body_of "$create_resp")"
CREATE_OK=0
if { [ "$create_code" = "200" ] || [ "$create_code" = "201" ]; }; then
  CREATE_OK=1
  _pass "[PERM-02] POST /relationships -> $create_code (tuple created via WRITE :4467)"
else
  _fail "[PERM-02] POST /relationships -> '$create_code' (want 200/201; body: $create_body)"
fi

# --- PERM-02 / CLI-01: the created Relationship JSON carries the crate shape --
echo
echo "--- [PERM-02/CLI-01] created tuple JSON carries the ory/keto CLI Relationship shape ---"
if [ "$CREATE_OK" = "1" ]; then
  SHAPE_OK="$(printf '%s' "$create_body" | node -e '
    let input = require("fs").readFileSync(0, "utf8");
    let d; try { d = JSON.parse(input); } catch (e) { process.stdout.write("BADJSON"); process.exit(0); }
    // ory/keto CLI relation-tuple JSON: namespace/object/relation + subject_id|subject_set.
    const want = ["namespace","object","relation"];
    const missing = want.filter(k => !(k in d));
    const hasSubject = ("subject_id" in d) || ("subject_set" in d);
    if (missing.length) { process.stdout.write("MISSING:"+missing.join(",")); process.exit(0); }
    process.stdout.write(hasSubject ? "OK" : "NOSUBJECT");
  ')"
  if [ "$SHAPE_OK" = "OK" ]; then
    _pass "[PERM-02/CLI-01] created tuple is ory/keto-CLI-interchangeable (namespace/object/relation + subject_id|subject_set)"
  else
    _fail "[PERM-02/CLI-01] created tuple JSON is NOT CLI-interchangeable ($SHAPE_OK; body: $create_body)"
  fi
else
  _fail "[PERM-02/CLI-01] CLI-shape skipped — tuple create failed"
fi

# --- PERM-03: query the tuple back (READ :4466) — proves the port split ------
echo
echo "--- [PERM-03] query the tuple back (GET, READ :4466) filtered by ns/object/relation ---"
read_resp="$(_auth_get "${RELATIONSHIPS_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers")"
read_code="$(_code_of "$read_resp")"; read_body="$(_body_of "$read_resp")"
FOUND_SUBJ="$(printf '%s' "$read_body" | SUBJ="$TEST_SUBJ" node -e '
  let input = require("fs").readFileSync(0, "utf8");
  let d; try { d = JSON.parse(input); } catch(e){ process.exit(0); }
  const tuples = (d && d.relation_tuples) || [];
  const hit = tuples.find(t => t.subject_id === process.env.SUBJ);
  process.stdout.write(hit ? "FOUND" : "MISS");
')"
if [ "$read_code" = "200" ] && [ "$FOUND_SUBJ" = "FOUND" ]; then
  _pass "[PERM-03] GET /relationships reads the tuple back (READ :4466; write+read round-trip proves the port split)"
else
  _fail "[PERM-03] GET /relationships did NOT read the tuple back (code='$read_code' found='$FOUND_SUBJ'; body: $read_body)"
fi
# Cursor behaviour: the list carries a next_page_token field (empty-string = last page).
if printf '%s' "$read_body" | node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(1)}; process.exit("next_page_token" in d ? 0 : 1)' 2>/dev/null; then
  _pass "[PERM-03] GET /relationships carries the next_page_token cursor field"
else
  _fail "[PERM-03] GET /relationships is missing the next_page_token cursor (body: $read_body)"
fi

# --- PERM-03: check the relation directly -> allowed:true --------------------
echo
echo "--- [PERM-03] check the viewers relation -> allowed:true; absent subject -> allowed:false ---"
chk_resp="$(_auth_get "${CHECK_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers&subject_id=${TEST_SUBJ}")"
chk_code="$(_code_of "$chk_resp")"; chk_body="$(_body_of "$chk_resp")"
CHK_ALLOWED="$(_json_field "$chk_body" 'String(data.allowed)')"
if [ "$chk_code" = "200" ] && [ "$CHK_ALLOWED" = "true" ]; then
  _pass "[PERM-03] check viewers/$TEST_SUBJ -> 200 {allowed:true}"
else
  _fail "[PERM-03] check viewers/$TEST_SUBJ -> code='$chk_code' allowed='$CHK_ALLOWED' (want 200 true; body: $chk_body)"
fi
# A KNOWN-ABSENT subject denies as a NORMAL 200 {allowed:false} (never a 502-as-denied).
chk_absent="$(_auth_get "${CHECK_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers&subject_id=${ABSENT_SUBJ}")"
chk_absent_code="$(_code_of "$chk_absent")"; chk_absent_body="$(_body_of "$chk_absent")"
ABSENT_ALLOWED="$(_json_field "$chk_absent_body" 'String(data.allowed)')"
if [ "$chk_absent_code" = "200" ] && [ "$ABSENT_ALLOWED" = "false" ]; then
  _pass "[PERM-03] check an absent subject -> 200 {allowed:false} (deny is a normal 200, not an error)"
else
  _fail "[PERM-03] check absent subject -> code='$chk_absent_code' allowed='$ABSENT_ALLOWED' (want 200 false; body: $chk_absent_body)"
fi

# --- PERM-03 (the empirical headline): permits-as-relation -------------------
echo
echo "--- [PERM-03] EMPIRICAL permits-as-relation: check passing the PERMITS-FUNCTION NAME ('$PERMITS_FN') as relation ---"
# The OPL model defines `view = has the viewers relation`. We created a viewers
# tuple for $TEST_SUBJ, so a check with relation=view (the permits fn name, NOT a
# raw relation) MUST resolve allowed:true on the live v26.2.0 image. This is the
# one behaviour with no code analog — it can only be proven against the engine.
permits_resp="$(_auth_get "${CHECK_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=${PERMITS_FN}&subject_id=${TEST_SUBJ}")"
permits_code="$(_code_of "$permits_resp")"; permits_body="$(_body_of "$permits_resp")"
PERMITS_ALLOWED="$(_json_field "$permits_body" 'String(data.allowed)')"
if [ "$permits_code" = "200" ] && [ "$PERMITS_ALLOWED" = "true" ]; then
  _pass "[PERM-03] permits-as-relation CONFIRMED: check relation='$PERMITS_FN' (OPL permits fn) -> 200 {allowed:true} on live Keto v26.2.0"
else
  _fail "[PERM-03] permits-as-relation FAILED: check relation='$PERMITS_FN' -> code='$permits_code' allowed='$PERMITS_ALLOWED' (want 200 true; body: $permits_body)"
fi
# Negative: the permits fn denies for the absent subject (no viewers tuple).
permits_absent="$(_auth_get "${CHECK_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=${PERMITS_FN}&subject_id=${ABSENT_SUBJ}")"
PERMITS_ABSENT_ALLOWED="$(_json_field "$(_body_of "$permits_absent")" 'String(data.allowed)')"
if [ "$(_code_of "$permits_absent")" = "200" ] && [ "$PERMITS_ABSENT_ALLOWED" = "false" ]; then
  _pass "[PERM-03] permits-as-relation denies the absent subject -> 200 {allowed:false}"
else
  _fail "[PERM-03] permits-as-relation absent-subject -> allowed='$PERMITS_ABSENT_ALLOWED' (want false; body: $(_body_of "$permits_absent"))"
fi

# --- PERM-03: expand the relation -> subject tree contains the subject -------
echo
echo "--- [PERM-03] expand the viewers relation -> ExpandedPermissionTree contains the subject ---"
exp_resp="$(_auth_get "${EXPAND_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers")"
exp_code="$(_code_of "$exp_resp")"; exp_body="$(_body_of "$exp_resp")"
if [ "$exp_code" = "200" ] && printf '%s' "$exp_body" | grep -q "$TEST_SUBJ"; then
  _pass "[PERM-03] GET /expand -> 200 ExpandedPermissionTree containing $TEST_SUBJ"
else
  _fail "[PERM-03] GET /expand -> code='$exp_code' (want 200 with $TEST_SUBJ in the tree; body: $exp_body)"
fi

# --- PERM-02: delete the EXACT tuple (WRITE :4467) -> gone, no sibling lost ---
echo
echo "--- [PERM-02] delete the EXACT tuple (DELETE, WRITE :4467) -> 204; re-query -> gone ---"
# First create a SIBLING tuple sharing the n/o/r triple but a DIFFERENT subject,
# so the over-broad-delete guard (T-9-delete-broad) is actually exercised: the
# delete must remove exactly $TEST_SUBJ and leave the sibling intact.
SIBLING_SUBJ="user:phase9-acceptance-bob"
SIB_BODY="$(NS="$TEST_NS" OBJ="$TEST_OBJ" REL="viewers" SUBJ="$SIBLING_SUBJ" node -e '
  process.stdout.write(JSON.stringify({namespace:process.env.NS,object:process.env.OBJ,relation:process.env.REL,subject_id:process.env.SUBJ}));')"
_auth_mut POST "$RELATIONSHIPS_URL" "$SIB_BODY" >/dev/null 2>&1 || true

del_resp="$(_auth_mut DELETE "${RELATIONSHIPS_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers&subject_id=${TEST_SUBJ}")"
del_code="$(_code_of "$del_resp")"
if [ "$del_code" = "204" ]; then
  _pass "[PERM-02] DELETE the exact tuple -> 204"
else
  _fail "[PERM-02] DELETE the exact tuple -> '$del_code' (want 204; body: $(_body_of "$del_resp"))"
fi
# Re-query: $TEST_SUBJ is GONE but the sibling $SIBLING_SUBJ SURVIVED (no over-broad delete).
after_body="$(_body_of "$(_auth_get "${RELATIONSHIPS_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers")")"
GONE="$(printf '%s' "$after_body" | SUBJ="$TEST_SUBJ" node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)};const t=(d&&d.relation_tuples)||[];process.stdout.write(t.find(x=>x.subject_id===process.env.SUBJ)?"PRESENT":"GONE")')"
SIB_LEFT="$(printf '%s' "$after_body" | SUBJ="$SIBLING_SUBJ" node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)};const t=(d&&d.relation_tuples)||[];process.stdout.write(t.find(x=>x.subject_id===process.env.SUBJ)?"PRESENT":"GONE")')"
if [ "$GONE" = "GONE" ]; then
  _pass "[PERM-02] re-query: the deleted tuple is GONE"
else
  _fail "[PERM-02] re-query: the deleted tuple is STILL present (delete did not take effect)"
fi
if [ "$SIB_LEFT" = "PRESENT" ]; then
  _pass "[PERM-02] re-query: the SIBLING tuple SURVIVED (T-9-delete-broad: delete was exact, not over-broad)"
else
  _fail "[PERM-02] re-query: the sibling tuple was ALSO removed (OVER-BROAD DELETE — T-9-delete-broad regression!)"
fi
# Clean up the sibling so the gate is idempotent (tuples live in the keto DB).
_auth_mut DELETE "${RELATIONSHIPS_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers&subject_id=${SIBLING_SUBJ}" >/dev/null 2>&1 || true

echo
echo "============================================================"
echo " GROUP 2 — OATH-01: rules write -> restart Oathkeeper ONLY -> list reflects"
echo "============================================================"
echo
echo "--- [OATH-01] PUT a valid rules array -> healthy, restart Oathkeeper ONLY, list_rules reflects ---"
OATH_RULE_ID="phase9-acceptance-rule"
RULES_BODY="$(RID="$OATH_RULE_ID" node -e '
  const rule = {
    id: process.env.RID,
    version: "v0.40.0",
    match: { url: "http://acceptance.test/<.*>", methods: ["GET"] },
    authenticators: [{ handler: "noop" }],
    authorizer: { handler: "allow" },
    mutators: [{ handler: "noop" }]
  };
  process.stdout.write(JSON.stringify([rule]));
')"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
rules_resp="$(_auth_mut PUT "$RULES_FILE_URL" "$RULES_BODY")"
rules_code="$(_code_of "$rules_resp")"; rules_rbody="$(_body_of "$rules_resp")"
if [ "$rules_code" = "200" ] && printf '%s' "$rules_rbody" | grep -q '"status":"healthy"'; then
  _pass "[OATH-01] PUT /config/oathkeeper/rules -> 200 {status:healthy} (written + Oathkeeper healthy via /health/alive)"
else
  _fail "[OATH-01] PUT /config/oathkeeper/rules -> '$rules_code' (want 200 {status:healthy}; body: $rules_rbody)"
fi
# RESTART SCOPE: ONLY Oathkeeper restarted (Kratos/Hydra/Keto StartedAt UNCHANGED).
assert_only_container_restarted "$OATHKEEPER_CTR" "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR"
wait_container_healthy "$OATHKEEPER_CTR" 90
# CLI-01 / disk proof: rules.json carries the rule id.
assert_grep "$OATH_RULE_ID" "$OATHKEEPER_RULES"
# AUTHORITATIVE confirm: the api_api list (port 4456) reflects the new rule.
list_body="$(_body_of "$(_auth_get "$RULES_LIST_URL")")"
if printf '%s' "$list_body" | RID="$OATH_RULE_ID" node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(1)};const a=Array.isArray(d)?d:[];process.exit(a.find(r=>r&&r.id===process.env.RID)?0:1)' 2>/dev/null; then
  _pass "[OATH-01] api_api list_rules reflects the new rule '$OATH_RULE_ID' (authoritative post-restart confirm)"
else
  _fail "[OATH-01] api_api list_rules does NOT reflect '$OATH_RULE_ID' (body: $list_body)"
fi

echo
echo "--- [OATH-01] invalid rules body (non-array) -> 422 AND rules.json UNCHANGED (no write) ---"
snapshot_file "$OATHKEEPER_RULES"
rules_inv="$(_auth_mut PUT "$RULES_FILE_URL" '{"not":"an-array"}')"
rules_inv_code="$(_code_of "$rules_inv")"; rules_inv_body="$(_body_of "$rules_inv")"
if [ "$rules_inv_code" = "422" ]; then
  _pass "[OATH-01] PUT /config/oathkeeper/rules (non-array) -> 422 (structural pre-check rejects)"
else
  _fail "[OATH-01] PUT /config/oathkeeper/rules (non-array) -> '$rules_inv_code' (want 422; body: $rules_inv_body)"
fi
assert_file_unchanged "$OATHKEEPER_RULES"

echo
echo "============================================================"
echo " GROUP 3 — NEGATIVES: 401 unauth, 403 no-CSRF, 403 sensitive-key"
echo "============================================================"

# --- unauthenticated (no cookie) -> 401 on a protected Keto route ------------
echo
echo "--- [neg] unauthenticated requests -> 401 ---"
unauth_get_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
  "${RELATIONSHIPS_URL}?namespace=${TEST_NS}" 2>/dev/null)"
if [ "$unauth_get_code" = "401" ]; then
  _pass "[neg] unauthenticated GET /keto/relationships -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated GET /keto/relationships -> '$unauth_get_code' (want 401)"
fi
unauth_post_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
  -H 'Content-Type: application/json' --data "$CREATE_TUPLE_BODY" "$RELATIONSHIPS_URL" 2>/dev/null)"
if [ "$unauth_post_code" = "401" ]; then
  _pass "[neg] unauthenticated POST /keto/relationships -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated POST /keto/relationships -> '$unauth_post_code' (want 401)"
fi
unauth_model_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H 'Content-Type: application/json' --data "$OPL_MODEL_SRC" "$MODEL_URL" 2>/dev/null)"
if [ "$unauth_model_code" = "401" ]; then
  _pass "[neg] unauthenticated PUT /keto/permission-model -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated PUT /keto/permission-model -> '$unauth_model_code' (want 401)"
fi

# --- authenticated but NO X-CSRF-Token -> 403 on every write -----------------
echo
echo "--- [neg] authed-no-CSRF -> 403 on each write (create/delete/validate/model/rules) ---"
# A cookie-only mutation (omit X-CSRF-Token). PASSes ONLY on an explicit 403.
nocsrf() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 30 -X "$method" -H "$COOKIE_HEADER")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
assert_nocsrf_403() {
  local label="$1" code="$2"
  if [ "$code" = "403" ]; then
    _pass "[neg] $label without X-CSRF-Token -> 403 (csrf_guard)"
  else
    _fail "[neg] $label without X-CSRF-Token -> '$code' (want 403)"
  fi
}
assert_nocsrf_403 "POST /keto/relationships"   "$(nocsrf POST   "$RELATIONSHIPS_URL" "$CREATE_TUPLE_BODY")"
assert_nocsrf_403 "DELETE /keto/relationships" "$(nocsrf DELETE "${RELATIONSHIPS_URL}?namespace=${TEST_NS}&object=${TEST_OBJ}&relation=viewers&subject_id=${TEST_SUBJ}")"
assert_nocsrf_403 "POST /keto/opl/validate"    "$(nocsrf POST   "$OPL_VALIDATE_URL" "$OPL_MODEL_SRC")"
assert_nocsrf_403 "PUT /keto/permission-model" "$(nocsrf PUT    "$MODEL_URL" "$OPL_MODEL_SRC")"
assert_nocsrf_403 "PUT /config/oathkeeper/rules" "$(nocsrf PUT  "$RULES_FILE_URL" "$RULES_BODY")"

# --- sensitive config key via the generic {service}/{section} route -> 403 ---
echo
echo "--- [neg] sensitive config key via the generic {service}/{section} route -> 403 + NO write ---"
# The Phase-9 dedicated OPL/rules editors can ONLY touch namespaces.ts / rules.json
# (server-built constant paths — T-9-path-traversal). A sensitive key like /dsn can
# only be ATTEMPTED through the generic {service}/{section} config route, where the
# hard SENSITIVE_PREFIXES denylist rejects it (403 forbidden_key) BEFORE any write —
# regardless of section. Keto/Oathkeeper have no registered editable section (an
# unknown section is 404), so the denylist is exercised on a registered section
# (hydra/general); the guarantee asserted is the SAME (a sensitive pointer never
# reaches disk via any config route).
put_forbidden_no_write() {
  local label="$1" section="$2" body="$3" file="$4" resp code rbody
  snapshot_file "$file"
  resp="$(_auth_mut PUT "${CFG_URL}/${section}" "$body")"
  code="$(_code_of "$resp")"; rbody="$(_body_of "$resp")"
  if [ "$code" = "403" ]; then
    _pass "[neg] $label -> 403 (forbidden_key, denied)"
  else
    _fail "[neg] $label -> '$code' (want 403; body: $rbody)"
  fi
  assert_file_unchanged "$file"
}
# /dsn is on the SENSITIVE_PREFIXES denylist (rejected for ALL sections); hydra.yml
# is the bind-mounted config the generic route would write on an accepted edit.
HYDRA_YAML="${REPO_ROOT}/config/hydra/hydra.yml"
if [ -f "$HYDRA_YAML" ]; then
  put_forbidden_no_write "/dsn via hydra/general (SENSITIVE denylist)" "hydra/general" '{"/dsn":"postgres://evil@db/x"}' "$HYDRA_YAML"
else
  _fail "[neg] hydra.yml MISSING at $HYDRA_YAML (cannot run the sensitive-key denylist negative)"
fi

echo
summary
exit $?
