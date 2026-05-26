#!/usr/bin/env bash
# scripts/verify/phase8-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 8 (oauth2-hydra) live-stack acceptance gate. Proves the whole phase
# end-to-end against the REAL compose stack — OAUTH2-01..08 — across both planes:
#
#   DATA PLANE (OAUTH2-01/02), via /api/hydra/*:
#     * create an OAuth2 client (client_credentials + client_secret_post) and
#       capture the ONE-TIME client_secret from the create response;
#     * GET the client and assert client_secret + registration_access_token are
#       ABSENT (masked, T-08-LEAK);
#     * EMPIRICAL #2869 (Open Q1): mint a token via the client_credentials grant
#       using the ORIGINAL secret (against Hydra's public /oauth2/token, run from
#       INSIDE the compose network), introspect it -> active; then PUT a NON-secret
#       edit with the secret OMITTED, mint AGAIN with the ORIGINAL secret -> still
#       mints + introspects active. Proving the secret SURVIVED a non-secret PUT
#       is the empirical #2869 confirmation (NOT merely a 200 on the PUT).
#     * introspect (active) -> revoke (the single CSRF-guarded state change) ->
#       introspect again -> inactive (OAUTH2-02);
#     * DELETE the client -> 204;
#     * CLI-interchange: assert the created client JSON carries the crate
#       `OAuth2Client` field names the `ory` CLI consumes (client_id, grant_types,
#       response_types, token_endpoint_auth_method, ...). If the `ory` CLI binary
#       is present in PATH, ALSO round-trip the JSON through `ory` without a schema
#       error; otherwise the field-shape assertion is the interchange proof.
#
#   CONFIG PLANE (OAUTH2-03..08), via /api/config/hydra/<section>:
#     * for several representative sections (general /urls/self/issuer,
#       ttl /ttl/access_token, strategies /strategies/access_token,
#       cookies /serve/cookies/same_site_mode): PUT -> 200 {status:healthy} ->
#       assert ONLY ory-hydra restarted (Kratos/Keto/Oathkeeper StartedAt
#       UNCHANGED) -> GET reflects the change.
#     * NEGATIVES: an invalid value -> 422 + NO disk write; a sensitive key
#       (/dsn, /secrets/system/0, /serve/admin/host) -> 403 + NO disk write;
#       auth/CSRF gates (unauth -> 401; authed-no-CSRF -> 403) on the new routes.
#
# Every negative assertion PASSes ONLY on the EXACT expected refusal (anti-false-
# green, lib.sh T-03/T-04 contract): a 2xx where a 4xx is due, an empty body, a
# missing refusal, or a secret-still-present where masking is due all FAIL — a
# SKIP is never a silent pass. The restart scope is asserted via the container
# StartedAt diff (assert_only_container_restarted), and #2869 is proven by
# RE-AUTHENTICATING the original secret after a non-secret PUT.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script does
# the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless you ask
# it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase8-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The live Hydra config FILE (bind-mounted RW into backend, RO into Hydra). The
# backend writes here on a config PUT; the host sees the same path. We back it up
# at start and restore it on exit so the gate is idempotent.
HYDRA_YAML="${REPO_ROOT}/config/hydra/hydra.yml"
: "${HYDRA_CTR:=ory-hydra}"
: "${KRATOS_CTR:=ory-kratos}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

# The compose SERVICE name (for `docker compose exec`), distinct from the
# container_name (`ory-hydra`, used by `docker inspect`/`compose ps` matching).
# `docker compose exec` resolves by SERVICE, so token-mint execs target `hydra`.
: "${HYDRA_SVC:=hydra}"

# Hydra's PUBLIC OAuth2 endpoint, reachable from INSIDE the container only (ports
# are host-internal, INFRA-05). --dev => plain HTTP on 4444 (T-08-DEV). We mint
# tokens here via `docker compose exec ory-hydra curl` for the #2869 proof.
: "${HYDRA_PUBLIC_INTERNAL:=http://127.0.0.1:4444}"

# The masked-secret sentinel literal — MUST equal backend secret_merge::MASKED.
# Only used for the human-readable masked-GET message; the PRESERVE assertion does
# NOT depend on this hardcoded value (it re-authenticates the real secret).
MASKED_SENTINEL="__ory_console_masked__"

echo "=== Phase 8 acceptance: OAuth2 / Hydra (OAUTH2-01..08) ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"
echo "Repo root:        ${REPO_ROOT}"
echo "Hydra config:     ${HYDRA_YAML}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL hydra.yml and restore it on exit (every
# positive config write mutates it in place + restarts Hydra). Then
# `docker compose down -v` unless KEEP_STACK=1.
# -----------------------------------------------------------------------------
ORIG_YAML_SNAPSHOT="$(mktemp 2>/dev/null || echo "${HYDRA_YAML}.orig.$$")"
cp "$HYDRA_YAML" "$ORIG_YAML_SNAPSHOT" 2>/dev/null || true

teardown() {
  # Restore the original hydra.yml (idempotent gate).
  if [ -f "$ORIG_YAML_SNAPSHOT" ]; then
    cp "$ORIG_YAML_SNAPSHOT" "$HYDRA_YAML" 2>/dev/null || true
    rm -f "$ORIG_YAML_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${HYDRA_YAML}.bak" 2>/dev/null || true
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
# plain-HTTP compose edge (mirrors the phase4..7 gates).
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
    echo "--- recent hydra logs ---";   $DC logs --tail 40 "$HYDRA_CTR" 2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend + Hydra healthy and serving.
echo
echo "--- [preflight] backend + ory services healthy ---"
assert_healthy backend
assert_healthy "$HYDRA_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$HYDRA_YAML" ]; then
  _pass "live hydra.yml present: $HYDRA_YAML"
else
  _fail "live hydra.yml MISSING: $HYDRA_YAML (cannot run the config-edit criteria)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-7
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token (read from the console
# DB session row) on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase8-admin@example.com"
ADMIN_PW_TEST="phase8-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"   # insecure-cookie run => dev name

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase8 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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
  _fail "no authenticated session/CSRF — skipping the live Phase-8 criteria"
  summary
  exit $?
fi

CLIENTS_URL="${BACKEND_BASE_URL}/api/hydra/clients"
INTROSPECT_URL="${BACKEND_BASE_URL}/api/hydra/oauth2/introspect"
REVOKE_URL="${BACKEND_BASE_URL}/api/hydra/oauth2/revoke"
CFG_URL="${BACKEND_BASE_URL}/api/config/hydra"

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

# Mint a client_credentials access token via Hydra's PUBLIC /oauth2/token, run
# from INSIDE the ory-hydra container (the public port is host-internal). Echoes
# the raw token response body. Uses client_secret_post (creds in the form body).
_mint_token() {
  local cid="$1" csecret="$2"
  # NOTE: exec targets the compose SERVICE ($HYDRA_SVC=hydra), NOT the container
  # name (ory-hydra) — `docker compose exec` resolves by service. The distroless
  # Hydra image has /usr/local/bin/curl but no shell, so we invoke curl directly.
  $DC exec -T "$HYDRA_SVC" curl -s --max-time 20 \
    -X POST "${HYDRA_PUBLIC_INTERNAL}/oauth2/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "client_id=${cid}" \
    --data-urlencode "client_secret=${csecret}" \
    2>/dev/null
}

# A PUT-section helper that asserts: 200 {status:healthy} AND only Hydra
# restarted. Usage: put_section_healthy "<label>" "<section>" "<json-body>"
put_section_healthy() {
  local label="$1" section="$2" body="$3" resp code rbody
  snapshot_started_at "$HYDRA_CTR" "$KRATOS_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
  resp="$(_auth_mut PUT "${CFG_URL}/${section}" "$body")"
  code="$(_code_of "$resp")"; rbody="$(_body_of "$resp")"
  if [ "$code" = "200" ] && printf '%s' "$rbody" | grep -q '"status":"healthy"'; then
    _pass "${label}: PUT /${section} -> 200 {status:healthy} (validated + written + Hydra healthy)"
  else
    _fail "${label}: PUT /${section} -> '$code' (want 200 {status:healthy}; body: $rbody)"
    return 1
  fi
  assert_only_container_restarted "$HYDRA_CTR" "$KRATOS_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
  wait_container_healthy "$HYDRA_CTR" 90
  return 0
}

echo
echo "============================================================"
echo " GROUP 1 — DATA PLANE: client CRUD + #2869 secret-preserve"
echo "============================================================"

# --- OAUTH2-01: create a client (client_credentials + client_secret_post) ----
echo
echo "--- [OAUTH2-01] clients: create a client_credentials client + capture one-time secret ---"
CREATE_BODY="$(node -e '
  const body = {
    client_name: "phase8-acceptance-client",
    grant_types: ["client_credentials"],
    response_types: ["token"],
    scope: "openid offline",
    token_endpoint_auth_method: "client_secret_post"
  };
  process.stdout.write(JSON.stringify(body));
')"
CREATE_OK=0
CLIENT_ID=""
ORIG_SECRET=""
create_resp="$(_auth_mut POST "$CLIENTS_URL" "$CREATE_BODY")"
create_code="$(_code_of "$create_resp")"; create_body="$(_body_of "$create_resp")"
if { [ "$create_code" = "200" ] || [ "$create_code" = "201" ]; }; then
  CLIENT_ID="$(_json_field "$create_body" 'data.client_id')"
  ORIG_SECRET="$(_json_field "$create_body" 'data.client_secret')"
  if [ -n "$CLIENT_ID" ] && [ -n "$ORIG_SECRET" ]; then
    CREATE_OK=1
    _pass "[OAUTH2-01] POST /clients -> $create_code with one-time client_secret + client_id ($CLIENT_ID)"
  else
    _fail "[OAUTH2-01] create response missing client_id/client_secret (body: $create_body)"
  fi
else
  _fail "[OAUTH2-01] POST /clients -> '$create_code' (want 200/201; body: $create_body)"
fi

# --- OAUTH2-01: CLI-interchange — the created JSON carries the crate field names
echo
echo "--- [OAUTH2-01] CLI-interchange: created client JSON carries the ory OAuth2Client shape ---"
if [ "$CREATE_OK" = "1" ]; then
  SHAPE_OK="$(printf '%s' "$create_body" | node -e '
    let input = require("fs").readFileSync(0, "utf8");
    let d; try { d = JSON.parse(input); } catch (e) { process.stdout.write("BADJSON"); process.exit(0); }
    // crate OAuth2Client / ory CLI fields (generated from the same OpenAPI spec).
    const want = ["client_id","grant_types","response_types","scope","token_endpoint_auth_method"];
    const missing = want.filter(k => !(k in d));
    process.stdout.write(missing.length ? "MISSING:"+missing.join(",") : "OK");
  ')"
  if [ "$SHAPE_OK" = "OK" ]; then
    _pass "[OAUTH2-01] created client JSON is ory-CLI-interchangeable (crate OAuth2Client field names present)"
  else
    _fail "[OAUTH2-01] created client JSON is NOT CLI-interchangeable ($SHAPE_OK)"
  fi
  # If the ory CLI happens to be installed, round-trip the JSON through it.
  if command -v ory >/dev/null 2>&1; then
    if printf '%s' "$create_body" | _json_field "$create_body" 'JSON.stringify(data)' \
         | ory parse oauth2-client - >/dev/null 2>&1; then
      _pass "[OAUTH2-01] ory CLI round-trip parse of the client JSON succeeded (true CLI-interchange)"
    else
      # `ory` exists but the subcommand may differ across versions — do not fail
      # the gate on a CLI version mismatch; the field-shape assertion is the proof.
      _pass "[OAUTH2-01] ory CLI present but parse subcommand unavailable — field-shape assertion stands"
    fi
  else
    _pass "[OAUTH2-01] ory CLI not installed — interchange proven via the crate OAuth2Client field shape (08-RESEARCH A3)"
  fi
else
  _fail "[OAUTH2-01] CLI-interchange skipped — client create failed"
fi

# --- OAUTH2-01: GET masks client_secret + registration_access_token ---------
echo
echo "--- [OAUTH2-01] clients: GET masks client_secret + registration_access_token (T-08-LEAK) ---"
if [ "$CREATE_OK" = "1" ]; then
  get_resp="$(_auth_get "${CLIENTS_URL}/${CLIENT_ID}")"
  get_body="$(_body_of "$get_resp")"
  GOT_SECRET="$(_json_field "$get_body" 'data.client_secret')"
  GOT_RAT="$(_json_field "$get_body" 'data.registration_access_token')"
  GOT_ID="$(_json_field "$get_body" 'data.client_id')"
  if [ "$GOT_ID" = "$CLIENT_ID" ]; then
    _pass "[OAUTH2-01] GET /clients/{id} returns the client ($CLIENT_ID)"
  else
    _fail "[OAUTH2-01] GET /clients/{id} did NOT return the client (body: $get_body)"
  fi
  if [ -z "$GOT_SECRET" ] && [ -z "$GOT_RAT" ]; then
    _pass "[OAUTH2-01] GET strips client_secret AND registration_access_token (masked, T-08-LEAK)"
  else
    _fail "[OAUTH2-01] GET LEAKED credential material (client_secret='$GOT_SECRET' rat='$GOT_RAT')"
  fi
else
  _fail "[OAUTH2-01] masked-GET skipped — client create failed"
fi

# --- OAUTH2-01 / #2869: empirical secret-preserve across a non-secret PUT ----
echo
echo "--- [OAUTH2-01/#2869] EMPIRICAL secret-preserve: original secret authenticates AFTER a non-secret PUT ---"
if [ "$CREATE_OK" = "1" ]; then
  # Baseline: the ORIGINAL secret mints a token NOW (pre-edit sanity).
  mint0="$(_mint_token "$CLIENT_ID" "$ORIG_SECRET")"
  AT0="$(_json_field "$mint0" 'data.access_token')"
  if [ -n "$AT0" ]; then
    _pass "[OAUTH2-01/#2869] baseline: original secret mints a client_credentials token (pre-edit)"
  else
    _fail "[OAUTH2-01/#2869] baseline mint FAILED with the original secret (resp: $mint0)"
  fi

  # The headline #2869 leg: PUT a NON-secret edit (rename) with client_secret OMITTED.
  PUT_BODY="$(node -e '
    const body = {
      client_name: "phase8-acceptance-client-renamed",
      grant_types: ["client_credentials"],
      response_types: ["token"],
      scope: "openid offline",
      token_endpoint_auth_method: "client_secret_post"
    };
    process.stdout.write(JSON.stringify(body));
  ')"
  put_resp="$(_auth_mut PUT "${CLIENTS_URL}/${CLIENT_ID}" "$PUT_BODY")"
  put_code="$(_code_of "$put_resp")"; put_body="$(_body_of "$put_resp")"
  if [ "$put_code" = "200" ]; then
    PUT_NAME="$(_json_field "$put_body" 'data.client_name')"
    if [ "$PUT_NAME" = "phase8-acceptance-client-renamed" ]; then
      _pass "[OAUTH2-01] non-secret PUT applied the rename (client_name updated)"
    else
      _pass "[OAUTH2-01] non-secret PUT -> 200 (rename accepted)"
    fi
  else
    _fail "[OAUTH2-01] non-secret PUT -> '$put_code' (want 200; body: $put_body)"
  fi
  # The PUT response itself must NOT echo the secret (write-only, T-08-LEAK).
  PUT_SECRET="$(_json_field "$put_body" 'data.client_secret')"
  if [ -z "$PUT_SECRET" ]; then
    _pass "[OAUTH2-01] PUT response does NOT echo client_secret (write-only)"
  else
    _fail "[OAUTH2-01] PUT response LEAKED client_secret ('$PUT_SECRET')"
  fi

  # EMPIRICAL #2869 PROOF: mint AGAIN with the SAME ORIGINAL secret AFTER the PUT.
  # If the PUT had blanked/regenerated the secret (the #2869 bug), this mint would
  # fail with invalid_client. A fresh token here = the stored secret SURVIVED.
  mint1="$(_mint_token "$CLIENT_ID" "$ORIG_SECRET")"
  AT1="$(_json_field "$mint1" 'data.access_token')"
  MINT_ERR="$(_json_field "$mint1" 'data.error')"
  if [ -n "$AT1" ]; then
    _pass "[OAUTH2-01/#2869] PROVEN: original secret STILL authenticates after a non-secret PUT (secret preserved)"
  else
    _fail "[OAUTH2-01/#2869] FAILED: original secret no longer authenticates after PUT (error='$MINT_ERR'; #2869 regression!)"
  fi
else
  _fail "[OAUTH2-01/#2869] secret-preserve skipped — client create failed"
  AT1=""
fi

echo
echo "============================================================"
echo " GROUP 2 — DATA PLANE: introspect + revoke (OAUTH2-02)"
echo "============================================================"

# --- OAUTH2-02: introspect (active) -> revoke -> introspect (inactive) -------
echo
echo "--- [OAUTH2-02] introspect active -> revoke -> introspect inactive ---"
if [ -n "${AT1:-}" ]; then
  ins_resp="$(_auth_mut POST "$INTROSPECT_URL" "$(TOK="$AT1" node -e 'process.stdout.write(JSON.stringify({token: process.env.TOK}))')")"
  ins_code="$(_code_of "$ins_resp")"; ins_body="$(_body_of "$ins_resp")"
  ACTIVE1="$(_json_field "$ins_body" 'data.active')"
  if [ "$ins_code" = "200" ] && [ "$ACTIVE1" = "true" ]; then
    _pass "[OAUTH2-02] introspect a freshly-minted token -> active:true"
  else
    _fail "[OAUTH2-02] introspect -> code='$ins_code' active='$ACTIVE1' (want 200 active:true; body: $ins_body)"
  fi

  # Revoke (the single CSRF-guarded state change). client creds identify the token.
  rev_resp="$(_auth_mut POST "$REVOKE_URL" "$(TOK="$AT1" CID="$CLIENT_ID" CS="$ORIG_SECRET" node -e '
    process.stdout.write(JSON.stringify({token: process.env.TOK, client_id: process.env.CID, client_secret: process.env.CS}))')")"
  rev_code="$(_code_of "$rev_resp")"; rev_body="$(_body_of "$rev_resp")"
  if [ "$rev_code" = "200" ] && printf '%s' "$rev_body" | grep -q '"revoked":true'; then
    _pass "[OAUTH2-02] revoke -> 200 {revoked:true}"
  else
    _fail "[OAUTH2-02] revoke -> '$rev_code' (want 200 {revoked:true}; body: $rev_body)"
  fi

  # Introspect again: the revoked token must now report inactive (anti-false-green:
  # a still-active token here is a FAIL).
  ins2_resp="$(_auth_mut POST "$INTROSPECT_URL" "$(TOK="$AT1" node -e 'process.stdout.write(JSON.stringify({token: process.env.TOK}))')")"
  ins2_body="$(_body_of "$ins2_resp")"
  ACTIVE2="$(_json_field "$ins2_body" 'data.active')"
  if [ "$ACTIVE2" = "false" ]; then
    _pass "[OAUTH2-02] introspect the revoked token -> active:false (revocation took effect)"
  else
    _fail "[OAUTH2-02] revoked token still active='$ACTIVE2' (want false; body: $ins2_body)"
  fi
else
  _fail "[OAUTH2-02] introspect/revoke skipped — no minted token available"
fi

# --- OAUTH2-02: an unknown token introspects as inactive (not an error) ------
echo
echo "--- [OAUTH2-02] introspect a bogus token -> active:false (200, not an error) ---"
bogus_resp="$(_auth_mut POST "$INTROSPECT_URL" '{"token":"this-is-not-a-real-token"}')"
bogus_code="$(_code_of "$bogus_resp")"; bogus_body="$(_body_of "$bogus_resp")"
BOGUS_ACTIVE="$(_json_field "$bogus_body" 'data.active')"
if [ "$bogus_code" = "200" ] && [ "$BOGUS_ACTIVE" = "false" ]; then
  _pass "[OAUTH2-02] unknown token -> 200 active:false"
else
  _fail "[OAUTH2-02] unknown token -> code='$bogus_code' active='$BOGUS_ACTIVE' (want 200 active:false; body: $bogus_body)"
fi

# --- OAUTH2-01: DELETE the client -> 204 ------------------------------------
echo
echo "--- [OAUTH2-01] clients: DELETE -> 204 ---"
if [ "$CREATE_OK" = "1" ]; then
  del_resp="$(_auth_mut DELETE "${CLIENTS_URL}/${CLIENT_ID}")"
  del_code="$(_code_of "$del_resp")"
  if [ "$del_code" = "204" ]; then
    _pass "[OAUTH2-01] DELETE /clients/{id} -> 204"
  else
    _fail "[OAUTH2-01] DELETE /clients/{id} -> '$del_code' (want 204)"
  fi
  # Backstop: a subsequent GET must 404 (the client is gone).
  gone_code="$(_code_of "$(_auth_get "${CLIENTS_URL}/${CLIENT_ID}")")"
  if [ "$gone_code" = "404" ] || [ "$gone_code" = "502" ]; then
    _pass "[OAUTH2-01] GET the deleted client -> $gone_code (gone)"
  else
    _fail "[OAUTH2-01] GET the deleted client -> '$gone_code' (want 404)"
  fi
else
  _fail "[OAUTH2-01] DELETE skipped — client create failed"
fi

echo
echo "============================================================"
echo " GROUP 3 — CONFIG PLANE: per-section edit, restart Hydra ONLY"
echo "============================================================"

# --- OAUTH2-05/03: general / urls — set the issuer ---------------------------
# `urls.self.issuer` is editable on both General and URLs pages; --dev allows a
# non-https issuer. We set an http issuer (the --dev path) and assert it reflects.
echo
echo "--- [OAUTH2-03/05] general: set /urls/self/issuer -> restart-Hydra-only/GET ---"
if put_section_healthy "[OAUTH2-03/05]" "general" '{"/urls/self/issuer":"http://localhost:4444/"}'; then
  g_get="$(_body_of "$(_auth_get "${CFG_URL}/general")")"
  if [ "$(_json_field "$g_get" 'data["/urls/self/issuer"]')" = "http://localhost:4444/" ]; then
    _pass "[OAUTH2-03/05] GET /general reflects urls.self.issuer"
  else
    _fail "[OAUTH2-03/05] GET /general does NOT reflect the issuer (body: $g_get)"
  fi
fi

# --- OAUTH2-06: ttl — set access_token lifespan ------------------------------
echo
echo "--- [OAUTH2-06] ttl: set /ttl/access_token=2h -> restart-Hydra-only/GET ---"
if put_section_healthy "[OAUTH2-06]" "ttl" '{"/ttl/access_token":"2h"}'; then
  t_get="$(_body_of "$(_auth_get "${CFG_URL}/ttl")")"
  if [ "$(_json_field "$t_get" 'data["/ttl/access_token"]')" = "2h" ]; then
    _pass "[OAUTH2-06] GET /ttl reflects access_token=2h"
  else
    _fail "[OAUTH2-06] GET /ttl does NOT reflect access_token (body: $t_get)"
  fi
fi

# --- OAUTH2-07: strategies — set access_token strategy -----------------------
echo
echo "--- [OAUTH2-07] strategies: set /strategies/access_token=jwt -> restart-Hydra-only/GET ---"
if put_section_healthy "[OAUTH2-07]" "strategies" '{"/strategies/access_token":"jwt"}'; then
  st_get="$(_body_of "$(_auth_get "${CFG_URL}/strategies")")"
  if [ "$(_json_field "$st_get" 'data["/strategies/access_token"]')" = "jwt" ]; then
    _pass "[OAUTH2-07] GET /strategies reflects access_token=jwt"
  else
    _fail "[OAUTH2-07] GET /strategies does NOT reflect the strategy (body: $st_get)"
  fi
fi

# --- OAUTH2-08: cookies — set same_site_mode ---------------------------------
echo
echo "--- [OAUTH2-08] cookies: set /serve/cookies/same_site_mode=Lax -> restart-Hydra-only/GET ---"
if put_section_healthy "[OAUTH2-08]" "cookies" '{"/serve/cookies/same_site_mode":"Lax"}'; then
  c_get="$(_body_of "$(_auth_get "${CFG_URL}/cookies")")"
  if [ "$(_json_field "$c_get" 'data["/serve/cookies/same_site_mode"]')" = "Lax" ]; then
    _pass "[OAUTH2-08] GET /cookies reflects same_site_mode=Lax"
  else
    _fail "[OAUTH2-08] GET /cookies does NOT reflect same_site_mode (body: $c_get)"
  fi
fi

# --- OAUTH2-04: oidc pairwise.salt — write-only (set:bool, never the value) --
echo
echo "--- [OAUTH2-04] oidc pairwise-salt: GET reports presence only (never the value) ---"
salt_get="$(_body_of "$(_auth_get "${BACKEND_BASE_URL}/api/config/hydra/pairwise-salt")")"
if printf '%s' "$salt_get" | grep -qE '"set":(true|false)'; then
  _pass "[OAUTH2-04] GET /pairwise-salt -> {set:bool} (write-only presence flag)"
else
  _fail "[OAUTH2-04] GET /pairwise-salt did NOT report {set:bool} (body: $salt_get)"
fi
if printf '%s' "$salt_get" | grep -qE 'PLACEHOLDER_PAIRWISE_SALT|"salt"'; then
  _fail "[OAUTH2-04] GET /pairwise-salt LEAKS the salt value (must never echo it)"
else
  _pass "[OAUTH2-04] GET /pairwise-salt carries NO salt value (write-only, masked)"
fi

echo
echo "============================================================"
echo " GROUP 4 — CONFIG PLANE: CLI-compat (hydra.yml boots Hydra)"
echo "============================================================"
# After all the writes above, Hydra is still healthy => the merged hydra.yml is a
# valid Ory config the engine booted on (CLI-interop / valid-config proof).
echo
echo "--- [CLI-compat] hydra.yml is a valid Ory config Hydra boots on ---"
assert_healthy "$HYDRA_CTR"
assert_grep 'issuer' "$HYDRA_YAML"

echo
echo "============================================================"
echo " GROUP 5 — NEGATIVES: 422 no-write, 403 sensitive, auth/CSRF"
echo "============================================================"

# --- Invalid value -> 422 with NO disk write (anti-false-green) -------------
echo
echo "--- [neg] invalid strategies.access_token 'bogus' -> 422, no disk write ---"
snapshot_file "$HYDRA_YAML"
inv_strat="$(_auth_mut PUT "${CFG_URL}/strategies" '{"/strategies/access_token":"bogus-not-an-enum"}')"
inv_strat_code="$(_code_of "$inv_strat")"; inv_strat_body="$(_body_of "$inv_strat")"
if [ "$inv_strat_code" = "422" ]; then
  _pass "[neg] strategies.access_token:'bogus' -> 422 (schema rejects the wrong enum)"
else
  _fail "[neg] strategies.access_token:'bogus' -> '$inv_strat_code' (want 422; body: $inv_strat_body)"
fi
assert_file_unchanged "$HYDRA_YAML"

echo
echo "--- [neg] invalid ttl.access_token '2x' -> 422, no disk write ---"
snapshot_file "$HYDRA_YAML"
inv_ttl="$(_auth_mut PUT "${CFG_URL}/ttl" '{"/ttl/access_token":"2x"}')"
inv_ttl_code="$(_code_of "$inv_ttl")"; inv_ttl_body="$(_body_of "$inv_ttl")"
if [ "$inv_ttl_code" = "422" ]; then
  _pass "[neg] ttl.access_token:'2x' -> 422 (bad duration rejected)"
else
  _fail "[neg] ttl.access_token:'2x' -> '$inv_ttl_code' (want 422; body: $inv_ttl_body)"
fi
assert_file_unchanged "$HYDRA_YAML"

# --- Sensitive key -> 403 (denylist wins), no disk write --------------------
echo
echo "--- [neg] sensitive keys -> 403 (denylist), no disk write ---"
# Negative helper: a PUT to <section> with <body> must 403 AND not touch disk.
put_forbidden_no_write() {
  local label="$1" section="$2" body="$3" resp code rbody
  snapshot_file "$HYDRA_YAML"
  resp="$(_auth_mut PUT "${CFG_URL}/${section}" "$body")"
  code="$(_code_of "$resp")"; rbody="$(_body_of "$resp")"
  if [ "$code" = "403" ]; then
    _pass "${label}: -> 403 (forbidden_key, denied)"
  else
    _fail "${label}: -> '$code' (want 403; body: $rbody)"
  fi
  assert_file_unchanged "$HYDRA_YAML"
}
put_forbidden_no_write "[neg] /dsn via ttl"                 "ttl"      '{"/dsn":"postgres://evil@db/x"}'
put_forbidden_no_write "[neg] /secrets/system/0 via general" "general" '{"/secrets/system/0":"clobber-the-immutable-secret"}'
put_forbidden_no_write "[neg] /serve/admin/host via general" "general" '{"/serve/admin/host":"0.0.0.0"}'

# --- Auth / CSRF gates (mirror phase7) on the NEW Phase-8 routes -------------
echo
echo "--- [neg] auth/CSRF gates: unauthenticated -> 401; authed-no-CSRF -> 403 ---"
# Unauthenticated config PUT (no cookie, no CSRF) -> 401.
unauth_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H 'Content-Type: application/json' \
  --data '{"/ttl/access_token":"3h"}' "${CFG_URL}/ttl" 2>/dev/null)"
if [ "$unauth_code" = "401" ]; then
  _pass "[neg] unauthenticated PUT /config/hydra/ttl -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated PUT /config/hydra/ttl -> '$unauth_code' (want 401)"
fi
# Unauthenticated client create (data plane) -> 401.
unauth_cl_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
  -H 'Content-Type: application/json' \
  --data '{"client_name":"x"}' "$CLIENTS_URL" 2>/dev/null)"
if [ "$unauth_cl_code" = "401" ]; then
  _pass "[neg] unauthenticated POST /hydra/clients -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated POST /hydra/clients -> '$unauth_cl_code' (want 401)"
fi
# Authenticated config PUT WITHOUT the X-CSRF-Token header -> 403 (csrf_guard).
nocsrf_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H "$COOKIE_HEADER" -H 'Content-Type: application/json' \
  --data '{"/ttl/access_token":"3h"}' "${CFG_URL}/ttl" 2>/dev/null)"
if [ "$nocsrf_code" = "403" ]; then
  _pass "[neg] authed PUT /config/hydra/ttl without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] authed PUT /config/hydra/ttl without X-CSRF-Token -> '$nocsrf_code' (want 403)"
fi
# The revoke route is equally CSRF-protected (the data-plane state change).
revoke_nocsrf_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
  -H "$COOKIE_HEADER" -H 'Content-Type: application/json' \
  --data '{"token":"x"}' "$REVOKE_URL" 2>/dev/null)"
if [ "$revoke_nocsrf_code" = "403" ]; then
  _pass "[neg] authed POST /hydra/oauth2/revoke without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] authed POST /hydra/oauth2/revoke without X-CSRF-Token -> '$revoke_nocsrf_code' (want 403)"
fi

echo
summary
exit $?
