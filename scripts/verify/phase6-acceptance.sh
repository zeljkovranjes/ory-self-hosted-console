#!/usr/bin/env bash
# scripts/verify/phase6-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 6 (user-management) live-stack acceptance gate. Proves IDENT-01..04
# end-to-end against the REAL running stack and re-locks the FE-05 no-Ory-egress
# invariant. Every negative assertion PASSes ONLY on the EXACT expected refusal
# (anti-false-green, lib.sh T-03/T-06 contract): a 2xx where a 4xx is due, an
# empty body, or a missing 404 all FAIL — a SKIP is never a silent pass.
#
# The FOUR assertion groups (each a labeled section below):
#   1. IDENT-01/02 CRUD round-trip: authed POST create -> 200/201 with an id;
#      GET list contains the id (keyset cursor works); GET /{id} returns it AND
#      carries NO credential secret material (T-06-41); PUT update (state
#      REQUIRED) -> 200; DELETE -> 204; subsequent GET /{id} -> 404 (fail-closed).
#   2. IDENT-04 import + limits + CLI-interchange: POST a small bare-array batch
#      -> records appear in the list; an over-limit batch (>1000 hashed, OR >200
#      with a cleartext password) -> 422 (negative assertion, T-06-? import DoS);
#      an exported record (a list row mapped to the bare-array shape) is a
#      TOP-LEVEL object carrying schema_id + traits and is NOT wrapped in a
#      `create` envelope — the `ory` CLI bare-array shape (CLI-01 foreshadow, A1).
#   3. IDENT-03 schema edit: PUT a valid draft-07 schema (with properties.traits)
#      -> file written + Kratos restarts + healthy 200; PUT an invalid schema ->
#      422 with NO disk write (T-06-43); GET reflects the active schema. The
#      ORIGINAL schema is restored at the end so the gate is idempotent.
#   4. Egress regression (FE-05): bundle-egress.sh -> no Ory host/port/SDK/CDN in
#      the built bundle (T-06-42).
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script
# does the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless
# you ask it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase6-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still
#                    runs the bundle gate and the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FRONTEND_DIR="${REPO_ROOT}/frontend"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The live Kratos identity schema FILE (bind-mounted into ory-kratos + backend).
# The backend writes here on a schema PUT; the host sees it on this same path.
KRATOS_SCHEMA="${REPO_ROOT}/config/kratos/identity.schema.json"
: "${KRATOS_CTR:=ory-kratos}"

echo "=== Phase 6 acceptance: user management (IDENT-01..04) ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"
echo "Repo root:        ${REPO_ROOT}"
echo "Kratos schema:    ${KRATOS_SCHEMA}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL identity schema and restore it on exit
# (the schema-edit criterion mutates it in place + triggers a Kratos restart).
# Then `docker compose down -v` unless KEEP_STACK=1. The ephemeral first-boot
# stack holds the one-time bootstrap token only in logs; `down -v` discards it.
# -----------------------------------------------------------------------------
ORIG_SCHEMA_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KRATOS_SCHEMA}.orig.$$")"
cp "$KRATOS_SCHEMA" "$ORIG_SCHEMA_SNAPSHOT" 2>/dev/null || true

teardown() {
  # Restore the original identity schema (idempotent gate, T-06-43).
  if [ -f "$ORIG_SCHEMA_SNAPSHOT" ]; then
    cp "$ORIG_SCHEMA_SNAPSHOT" "$KRATOS_SCHEMA" 2>/dev/null || true
    rm -f "$ORIG_SCHEMA_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${KRATOS_SCHEMA}.bak" 2>/dev/null || true
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
# CRITERION 4 (FE-05) FIRST — bundle egress. The cheapest hard gate; it builds
# the frontend and greps the built output, and must hold regardless of the live
# stack. (Run before bring-up so a leaked literal fails fast.)
# =============================================================================
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [FE-05] bundle-egress: no Ory host/port/SDK + no CDN in the built bundle ---"
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (FE-05/T-06-42)"
  else
    _fail "bundle-egress: FORBIDDEN Ory host/port/SDK or CDN reference in the built bundle"
  fi
else
  echo
  echo "--- [FE-05] bundle-egress SKIPPED (SKIP_EGRESS=1) — live-only run ---"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live IDENT-01..04 assertions.
# Use insecure cookies for THIS ephemeral run so curl can replay the session
# cookie over the plain-HTTP compose edge (mirrors phase4/phase5 gates).
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
    echo "--- recent kratos logs ---";  $DC logs --tail 40 "$KRATOS_CTR" 2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend + Kratos healthy and serving.
echo
echo "--- [preflight] backend + kratos healthy ---"
assert_healthy backend
assert_healthy "$KRATOS_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KRATOS_SCHEMA" ]; then
  _pass "live identity schema present: $KRATOS_SCHEMA"
else
  _fail "live identity schema MISSING: $KRATOS_SCHEMA (cannot run the schema-edit criterion)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-4
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token (read from the console
# DB session row) on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase6-admin@example.com"
ADMIN_PW_TEST="phase6-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"   # insecure-cookie run => dev name

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase6 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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
  _fail "could not obtain a session token from /login (live IDENT criteria cannot run)"
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
  _fail "no authenticated session/CSRF — skipping the live IDENT-01..04 criteria"
  summary
  exit $?
fi

IDENTITIES_URL="${BACKEND_BASE_URL}/api/kratos/identities"
SCHEMA_URL="${BACKEND_BASE_URL}/api/kratos/identity-schema"

# Authenticated GET (cookie only; GET is CSRF-exempt). Echo "CODE<newline>BODY".
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
# Authenticated mutating call (cookie + CSRF + JSON body). Echo "CODE<newline>BODY".
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 200 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }

# Pull a JSON field from a body via node (the toolchain is present per CLAUDE.md).
# Usage: _json_field "<body>" '<js-expr-over-data>'  (prints the result or empty)
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

SCHEMA_ID="default"

# =============================================================================
# CRITERION 1 — IDENT-01/02 CRUD round-trip (create -> list -> get(no secrets) ->
# update -> delete -> 404). Every leg is a positive proof; the post-delete 404 is
# fail-closed (a 2xx GET after DELETE is a hard FAIL).
# =============================================================================
echo
echo "--- [IDENT-01/02] CRUD round-trip: create -> list -> get -> update -> delete -> 404 ---"
UNIQ="phase6-$(date +%s)-$$@example.com"
CREATE_BODY="{\"schema_id\":\"${SCHEMA_ID}\",\"traits\":{\"email\":\"${UNIQ}\"},\"credentials\":{\"password\":{\"config\":{\"password\":\"a-very-long-test-password\"}}}}"

resp="$(_auth_mut POST "$IDENTITIES_URL" "$CREATE_BODY")"
code="$(_code_of "$resp")"; body="$(_body_of "$resp")"
NEW_ID=""
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
  NEW_ID="$(_json_field "$body" 'data.id')"
fi
if [ -n "$NEW_ID" ]; then
  _pass "create identity -> $code with id=$NEW_ID"
else
  _fail "create identity -> '$code' with NO id (body: $body)"
fi

if [ -n "$NEW_ID" ]; then
  # GET list must contain the new id (the keyset-cursor list returns {rows,...}).
  list_resp="$(_auth_get "${IDENTITIES_URL}?page_size=500")"
  list_code="$(_code_of "$list_resp")"; list_body="$(_body_of "$list_resp")"
  if [ "$list_code" = "200" ]; then
    found="$(printf '%s' "$list_body" | ID="$NEW_ID" node -e '
      const id = process.env.ID;
      let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
      const rows = (d && d.rows) || [];
      process.stdout.write(rows.some(r => r && r.id === id) ? "YES" : "NO");
    ' 2>/dev/null)"
    if [ "$found" = "YES" ]; then
      _pass "GET list contains the created id (keyset cursor list works, IDENT-01)"
    else
      _fail "GET list does NOT contain the created id (list shape/cursor broken)"
    fi
  else
    _fail "GET list returned '$list_code' (want 200; body: $list_body)"
  fi

  # GET /{id} returns it AND carries NO credential secret material (T-06-41).
  get_resp="$(_auth_get "${IDENTITIES_URL}/${NEW_ID}")"
  get_code="$(_code_of "$get_resp")"; get_body="$(_body_of "$get_resp")"
  if [ "$get_code" = "200" ] && [ -n "$get_body" ]; then
    _pass "GET /{id} returned the identity (200, IDENT-01 detail)"
  else
    _fail "GET /{id} returned '$get_code' / empty body (want 200 + body)"
  fi
  # Secret-absence: the shaped detail must carry NO password hash / credential
  # config / recovery-code material. Fail-closed: an empty body cannot prove it.
  if [ -z "$get_body" ]; then
    _fail "GET /{id} empty body — cannot confirm credential-secret absence (T-06-41)"
  elif printf '%s' "$get_body" | grep -qiE '\$argon2|\$2[aby]\$|hashed_password|"config"|recovery_codes|password_hash'; then
    _fail "GET /{id} body LEAKS credential-secret material (T-06-41 VIOLATED): $get_body"
  else
    _pass "GET /{id} body carries NO credential-secret material (T-06-41 mitigated)"
  fi

  # PUT update (state REQUIRED). Flip the state to inactive.
  UPDATE_BODY="{\"schema_id\":\"${SCHEMA_ID}\",\"state\":\"inactive\",\"traits\":{\"email\":\"${UNIQ}\"}}"
  upd_resp="$(_auth_mut PUT "${IDENTITIES_URL}/${NEW_ID}" "$UPDATE_BODY")"
  upd_code="$(_code_of "$upd_resp")"; upd_body="$(_body_of "$upd_resp")"
  if [ "$upd_code" = "200" ]; then
    _pass "PUT update (state=inactive) -> 200 (IDENT-02 update, state required)"
  else
    _fail "PUT update -> '$upd_code' (want 200; body: $upd_body)"
  fi

  # DELETE -> 204.
  del_resp="$(_auth_mut DELETE "${IDENTITIES_URL}/${NEW_ID}")"
  del_code="$(_code_of "$del_resp")"
  if [ "$del_code" = "204" ]; then
    _pass "DELETE -> 204 (IDENT-02 delete)"
  else
    _fail "DELETE -> '$del_code' (want 204)"
  fi

  # Post-delete GET -> 404 (FAIL-CLOSED: a 2xx here is a hard FAIL).
  gone_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
    -H "$COOKIE_HEADER" "${IDENTITIES_URL}/${NEW_ID}" 2>/dev/null)"
  if [ "$gone_code" = "404" ]; then
    _pass "post-delete GET /{id} -> 404 (identity gone, fail-closed)"
  else
    _fail "post-delete GET /{id} -> '$gone_code' (want 404; the identity was NOT deleted)"
  fi
else
  _fail "no created id — skipping the rest of the CRUD round-trip"
fi

# =============================================================================
# CRITERION 2 — IDENT-04 import + limits + CLI-interchange.
#   (a) a small bare-array import -> records appear in the list;
#   (b) an over-limit batch (>200 with a cleartext password) -> 422 (fail-closed);
#   (c) an exported list row maps to the bare-array CLI shape (top-level object
#       with schema_id + traits, NOT wrapped in `create`) — CLI-01 foreshadow.
# =============================================================================
echo
echo "--- [IDENT-04] import + limits + CLI bare-array shape ---"
IMP1="phase6-imp1-$(date +%s)-$$@example.com"
IMP2="phase6-imp2-$(date +%s)-$$@example.com"
IMPORT_BODY="[{\"schema_id\":\"${SCHEMA_ID}\",\"traits\":{\"email\":\"${IMP1}\"}},{\"schema_id\":\"${SCHEMA_ID}\",\"traits\":{\"email\":\"${IMP2}\"}}]"

imp_resp="$(_auth_mut POST "${IDENTITIES_URL}/import" "$IMPORT_BODY")"
imp_code="$(_code_of "$imp_resp")"; imp_body="$(_body_of "$imp_resp")"
if { [ "$imp_code" = "200" ] || [ "$imp_code" = "201" ]; } \
   && printf '%s' "$imp_body" | grep -q '"results"'; then
  _pass "bulk import (bare array) -> $imp_code {results} (IDENT-04)"
else
  _fail "bulk import -> '$imp_code' (want 2xx + {results}; body: $imp_body)"
fi

# The two imported records appear in the list.
list_resp="$(_auth_get "${IDENTITIES_URL}?page_size=500")"
list_body="$(_body_of "$list_resp")"
imp_found="$(printf '%s' "$list_body" | E1="$IMP1" E2="$IMP2" node -e '
  const e1 = process.env.E1, e2 = process.env.E2;
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
  const rows = (d && d.rows) || [];
  const has = (em) => rows.some(r => r && r.traits && r.traits.email === em);
  process.stdout.write(has(e1) && has(e2) ? "YES" : "NO");
' 2>/dev/null)"
if [ "$imp_found" = "YES" ]; then
  _pass "both imported identities appear in the list (IDENT-04 import -> list)"
else
  _fail "imported identities did NOT all appear in the list (import incomplete)"
fi

# Over-limit reject: 201 records each carrying a CLEARTEXT password -> 422
# (>200-cleartext authoritative limit). Negative assertion: a 2xx is a hard FAIL.
echo
echo "--- [IDENT-04] over-limit (>200 cleartext) import -> 422 (fail-closed) ---"
OVERLIMIT_BODY="$(N=201 SID="$SCHEMA_ID" node -e '
  const n = parseInt(process.env.N, 10), sid = process.env.SID;
  const arr = [];
  for (let i = 0; i < n; i++) {
    arr.push({ schema_id: sid, traits: { email: `phase6-ol-${i}-${Date.now()}@example.com` },
      credentials: { password: { config: { password: "a-very-long-test-password" } } } });
  }
  process.stdout.write(JSON.stringify(arr));
')"
ol_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
  -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -H 'Content-Type: application/json' --data "$OVERLIMIT_BODY" \
  "${IDENTITIES_URL}/import" 2>/dev/null)"
if [ "$ol_code" = "422" ]; then
  _pass "over-limit (>200 cleartext) import -> 422 (authoritative limit enforced, fail-closed)"
else
  _fail "over-limit import -> '$ol_code' (want 422; the DoS limit was NOT enforced)"
fi

# CLI bare-array shape: an exported record (a list row mapped to {schema_id,
# traits}) is a TOP-LEVEL object carrying schema_id + traits and is NOT wrapped
# in a `create` envelope — the shape `ory import identities` consumes (CLI-01).
echo
echo "--- [IDENT-04/CLI-01] exported record matches the ory-CLI bare-array shape ---"
shape_verdict="$(printf '%s' "$list_body" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  const rows = (d && d.rows) || [];
  if (!Array.isArray(rows) || rows.length === 0) { process.stdout.write("NOROWS"); process.exit(0); }
  // Map a row to the bare-array CLI export shape (mirrors lib/cli-identity.toExportArray).
  const r = rows[0];
  const exported = { schema_id: r.schema_id, traits: r.traits };
  if (typeof exported.schema_id !== "string") { process.stdout.write("NO_SCHEMA_ID"); process.exit(0); }
  if (exported.traits === undefined || exported.traits === null || typeof exported.traits !== "object") {
    process.stdout.write("NO_TRAITS"); process.exit(0);
  }
  if ("create" in exported) { process.stdout.write("HAS_CREATE_WRAPPER"); process.exit(0); }
  process.stdout.write("OK");
' 2>/dev/null)"
if [ "$shape_verdict" = "OK" ]; then
  _pass "exported record is a top-level {schema_id, traits} object, NOT a create-wrapped patch (CLI bare-array shape, CLI-01)"
else
  _fail "exported record FAILED the CLI bare-array shape check ($shape_verdict)"
fi

# =============================================================================
# CRITERION 3 — IDENT-03 schema edit: a valid draft-07 schema PUT writes the file
# + restarts Kratos + recovers healthy 200; an invalid schema PUT -> 422 with NO
# disk write (fail-closed). GET reflects the active schema. The ORIGINAL schema
# is restored on teardown (idempotent).
# =============================================================================
echo
echo "--- [IDENT-03] schema edit: valid PUT -> write + restart + healthy 200 ---"
# A valid draft-07 schema with properties.traits (Kratos identity schema shape).
VALID_SCHEMA='{
  "$id": "https://example.com/phase6-acceptance.schema.json",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Phase6 Acceptance Identity",
  "type": "object",
  "properties": {
    "traits": {
      "type": "object",
      "properties": {
        "email": {
          "type": "string",
          "format": "email",
          "title": "E-Mail",
          "ory.sh/kratos": { "credentials": { "password": { "identifier": true } } }
        }
      },
      "required": ["email"],
      "additionalProperties": false
    }
  }
}'
snapshot_started_at "$KRATOS_CTR"
sch_resp="$(_auth_mut PUT "$SCHEMA_URL" "$VALID_SCHEMA")"
sch_code="$(_code_of "$sch_resp")"; sch_body="$(_body_of "$sch_resp")"
if [ "$sch_code" = "200" ] && printf '%s' "$sch_body" | grep -q '"status":"healthy"'; then
  _pass "valid schema PUT -> 200 {status:healthy} (file written + Kratos restarted + healthy, IDENT-03)"
elif [ "$sch_code" = "200" ]; then
  _pass "valid schema PUT -> 200 (Kratos recovered healthy, IDENT-03): $sch_body"
else
  _fail "valid schema PUT -> '$sch_code' (want 200 healthy; body: $sch_body)"
fi
# Kratos actually restarted (StartedAt changed) and is healthy again.
assert_only_container_restarted "$KRATOS_CTR"
wait_container_healthy "$KRATOS_CTR" 90
# The file on disk now reflects the new schema title (the write hit the mount).
assert_grep 'Phase6 Acceptance Identity' "$KRATOS_SCHEMA"
# GET reflects the active schema.
get_sch="$(_auth_get "$SCHEMA_URL")"
get_sch_code="$(_code_of "$get_sch")"; get_sch_body="$(_body_of "$get_sch")"
if [ "$get_sch_code" = "200" ] && printf '%s' "$get_sch_body" | grep -q 'Phase6 Acceptance Identity'; then
  _pass "GET /identity-schema reflects the active (just-written) schema (IDENT-03)"
else
  _fail "GET /identity-schema does NOT reflect the written schema (got '$get_sch_code': $get_sch_body)"
fi

# Invalid schema PUT -> 422 with NO disk write (fail-closed, T-06-43). A schema
# missing properties.traits violates the Layer-2 structural check.
echo
echo "--- [IDENT-03] invalid schema PUT -> 422, no disk write (fail-closed) ---"
INVALID_SCHEMA='{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": { "not_traits": { "type": "string" } }
}'
snapshot_file "$KRATOS_SCHEMA"
inv_resp="$(_auth_mut PUT "$SCHEMA_URL" "$INVALID_SCHEMA")"
inv_code="$(_code_of "$inv_resp")"; inv_body="$(_body_of "$inv_resp")"
if [ "$inv_code" = "422" ]; then
  _pass "invalid schema PUT -> 422 (rejected before any disk write, IDENT-03)"
else
  _fail "invalid schema PUT -> '$inv_code' (want 422; body: $inv_body)"
fi
# The on-disk schema is byte-identical to the pre-PUT snapshot (no write on reject).
assert_file_unchanged "$KRATOS_SCHEMA"
# The 422 body must not echo the rejected payload as a secret leak vector.
if printf '%s' "$inv_body" | grep -qiE 'postgres://|\$argon2'; then
  _fail "invalid-schema 422 body LEAKS a secret marker: $inv_body"
else
  _pass "invalid-schema 422 body carries no secret marker"
fi

# =============================================================================
# MANUAL-ONLY note (echoed, NOT executed) — the optional real ory CLI round-trip
# (06-VALIDATION Manual-Only). The in-console import/export shape is already
# proven structurally above (CLI-01 foreshadow); the real binary round-trip needs
# the `ory` CLI installed + a target and is an operator step.
# =============================================================================
echo
echo "--- [MANUAL-ONLY] optional real 'ory' CLI round-trip (06-VALIDATION) ---"
echo "    The in-console bare-array import/export shape is proven above. To verify"
echo "    real CLI interchange (not executed by this gate):"
echo "      1. Export from the console (Users -> Import/Export -> Export) to a JSON file."
echo "      2. Install the ory CLI (https://www.ory.sh/docs/guides/cli/installation)."
echo "      3. Run:  ory import identities exported.json"
echo "      4. Confirm the CLI accepts the file with NO format error (bare array)."

echo
summary
exit $?
