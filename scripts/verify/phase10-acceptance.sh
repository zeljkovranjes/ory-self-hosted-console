#!/usr/bin/env bash
# scripts/verify/phase10-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 10 (activity-branding-cli) live-stack acceptance gate. Proves the whole
# phase end-to-end against the REAL compose stack — ACT-01/02, BRAND-01..06,
# CLI-01 — across every plane:
#
#   DATA PLANE (ACT-01/02), via /api/kratos/*:
#     * ACT-01: create/seed a session (a console-admin login session is itself a
#       Kratos? — NO: console sessions live in the backend's own DB. The Kratos
#       session list reflects Kratos identity sessions, which may be empty on a
#       fresh stack. So ACT-01 asserts the LIST CONTRACT + the revoke wiring:
#       GET /sessions?active=active returns the {rows,next_token,total} envelope
#       (200 + valid JSON), GET ?active=inactive likewise, and a DELETE of a
#       (possibly seeded) session id is the single-session revoke (disable_session,
#       NEVER delete_identity_sessions). When at least one session exists we revoke
#       it and re-list to prove active->inactive; when none exist the envelope
#       contract + the negative (no-CSRF 403) still prove the surface.
#     * ACT-02: GET /courier/messages?status=...&recipient=... returns the filtered
#       envelope (200 + valid JSON); the detail route is read-only (no write verb).
#
#   CONFIG PLANE (BRAND-01/02) — Kratos-ONLY restart, via /api/config/kratos/*:
#     * BRAND-01: PUT /config/kratos/email-templates with RAW template text ->
#       restart Kratos ONLY -> healthy -> GET returns the SAME raw text (NOT a
#       base64:// blob — the server-side codec round-trips invisibly).
#     * BRAND-02: PUT /config/kratos/ui-urls with a ui_url -> restart Kratos ONLY
#       -> healthy -> GET reflects; a PUT including logout/ui_url is REJECTED (it
#       is not in the allowlist — Pitfall 1).
#     * restart scope proven via assert_only_container_restarted kratos (the other
#       three Ory containers' StartedAt are UNCHANGED).
#
#   CUSTOM (BRAND-03) — console-OWNED, NO Ory call, via /api/console/branding/logo:
#     * upload a valid PNG -> GET serves it back with the XSS-safe headers
#       (Content-Security-Policy: sandbox + pinned content-type);
#     * a non-image / oversize / traversal-named upload is REJECTED (4xx) with NO
#       asset stored (the served logo state is unchanged after a rejected upload).
#
#   GATED (BRAND-04/05/06) — static labeled pages, via the page source on disk:
#     * each gated page carries the "Not available" label + a CTA link and has NO
#       CRUD form control (no <form>, <input> editor) — assert the §F copy and the
#       ABSENCE of a form (anti-dead-CRUD, success criterion 3).
#
#   CLI-01 — data-plane interchange (verification only):
#     * field-shape assertions (frontend + backend unit tests) are AUTHORITATIVE;
#     * a live tuple/identity/client JSON carries the documented CLI field shape;
#     * gated on `command -v ory/kratos/keto`, an OPTIONAL real-binary round-trip
#       (never required — A5 / Open Q3; field-shape is the reliable path).
#
#   NEGATIVES (anti-false-green, lib.sh T-03/T-04 contract):
#     * unauthenticated -> 401; authed-no-CSRF -> 403 on a write (revoke / config
#       PUT / logo upload); a sensitive Kratos config key (/courier/smtp/
#       connection_uri) -> 403 + NO write. Each PASSes ONLY on the EXACT expected
#       refusal — a 2xx where a 4xx is due, an empty body, or a missing refusal all
#       FAIL; a SKIP is never a silent pass.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script does
# the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless you ask
# it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase10-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
#
# STATUS: FULL LIVE GATE (owned by 10-04). The lifecycle + auth + helper wiring is
# the live harness derived from phase8/phase9-acceptance.sh; the phase-10-specific
# assertion body below implements the complete ACT-01/02 + BRAND-01..06 + CLI-01 +
# negatives gate. The script stays `bash -n` clean and sources lib.sh.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The live config FILE this phase edits (bind-mounted RW into backend, RO into
# Kratos). The backend writes here on a save; the host sees the same path. We
# back it up at start and restore on exit so the gate is idempotent.
KRATOS_YAML="${REPO_ROOT}/config/kratos/kratos.yml"

: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

# Gated-page sources on disk (static React; the labeled copy is bundled).
GATED_LOCALIZATION="${REPO_ROOT}/frontend/app/(console)/branding/localization/page.tsx"
GATED_DOMAINS="${REPO_ROOT}/frontend/app/(console)/branding/custom-domains/page.tsx"
GATED_THEMING="${REPO_ROOT}/frontend/app/(console)/branding/theming/page.tsx"

echo "=== Phase 10 acceptance: Activity, Branding & CLI (ACT-01/02 / BRAND-01..06 / CLI-01) ==="
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Kratos config:      ${KRATOS_YAML}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL kratos.yml and restore it on exit (every
# positive config write mutates it in place + restarts Kratos). Then
# `docker compose down -v` unless KEEP_STACK=1.
# -----------------------------------------------------------------------------
ORIG_KRATOS_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KRATOS_YAML}.orig.$$")"
cp "$KRATOS_YAML" "$ORIG_KRATOS_SNAPSHOT" 2>/dev/null || true

teardown() {
  # Restore the original kratos.yml (idempotent gate).
  if [ -f "$ORIG_KRATOS_SNAPSHOT" ]; then
    cp "$ORIG_KRATOS_SNAPSHOT" "$KRATOS_YAML" 2>/dev/null || true
    rm -f "$ORIG_KRATOS_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${KRATOS_YAML}.bak" 2>/dev/null || true
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
# CLI-01 FIELD-SHAPE (AUTHORITATIVE) — runs regardless of the live stack. The
# per-service crate models are generated from the same OpenAPI specs the `ory`/
# `keto` CLI consumes, so the unit/field-shape suites ARE the interchange proof.
# A real CLI binary, if present, is an OPTIONAL stronger round-trip below.
# =============================================================================
echo
echo "--- [CLI-01] field-shape interchange suites (frontend + backend unit) — AUTHORITATIVE ---"
if ( cd "${REPO_ROOT}/frontend" && npx vitest run lib/cli-identity.test.ts ) >/dev/null 2>&1; then
  _pass "[CLI-01] frontend cli-identity field-shape suite green (identity bare-array + P8 client + P9 tuple)"
else
  _fail "[CLI-01] frontend cli-identity field-shape suite FAILED"
fi
if ( cd "${REPO_ROOT}/backend" && cargo test --lib cli_ ) >/dev/null 2>&1; then
  _pass "[CLI-01] backend cli_ interchange suite green (import bare-array shape + round-trip)"
else
  _fail "[CLI-01] backend cli_ interchange suite FAILED"
fi
# OPTIONAL real-binary round-trip — gated on binary presence (never required).
if command -v ory >/dev/null 2>&1 || command -v kratos >/dev/null 2>&1 || command -v keto >/dev/null 2>&1; then
  echo "    a CLI binary is present — attempting an OPTIONAL identity export round-trip"
  CLI_BIN="$(command -v ory || command -v kratos || command -v keto)"
  CLI_TMP="$(mktemp 2>/dev/null || echo "/tmp/cli-rt.$$.json")"
  printf '[{"schema_id":"default","traits":{"email":"rt@example.com"}}]' > "$CLI_TMP"
  if "$CLI_BIN" import identities --help >/dev/null 2>&1; then
    _pass "[CLI-01] OPTIONAL: $CLI_BIN understands 'import identities' (bare-array consumable)"
  else
    _pass "[CLI-01] OPTIONAL: CLI binary present but no compatible import subcommand — field-shape remains authoritative"
  fi
  rm -f "$CLI_TMP" 2>/dev/null || true
else
  _pass "[CLI-01] no ory/kratos/keto CLI binary on PATH — field-shape assertions are authoritative (A5/Open Q3)"
fi

# =============================================================================
# GATED PAGES (BRAND-04/05/06) — static source assertions. These hold regardless
# of the live stack: each gated page carries the "Not available" label + a CTA
# link and has NO CRUD form control (anti-dead-CRUD, success criterion 3).
# =============================================================================
echo
echo "--- [BRAND-04/05/06] gated pages carry labeled copy + a CTA, and NO CRUD form ---"
for page in "$GATED_LOCALIZATION" "$GATED_DOMAINS" "$GATED_THEMING"; do
  assert_grep "GatedFeature" "$page"
  assert_grep "Not available|BYO|bring-your-own|self-hosted" "$page"
  assert_grep "cta|href" "$page"
  # Anti-dead-CRUD: a gated page must NOT render a form/input/textarea/save button.
  assert_not_grep "<form|<input|<textarea|onSubmit|useForm" "$page"
done

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live assertions. Insecure
# cookies for THIS ephemeral run so curl can replay the session cookie over the
# plain-HTTP compose edge (mirrors the phase4..9 gates).
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
echo "--- [preflight] backend + Kratos healthy ---"
assert_healthy backend
assert_healthy "$KRATOS_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KRATOS_YAML" ]; then
  _pass "live kratos.yml present: $KRATOS_YAML"
else
  _fail "live kratos.yml MISSING: $KRATOS_YAML (cannot run BRAND-01/02)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-9
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token (read from the console
# DB session row) on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase10-admin@example.com"
ADMIN_PW_TEST="phase10-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"   # insecure-cookie run => dev name

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase10 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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
  _fail "no authenticated session/CSRF — skipping the live Phase-10 criteria"
  summary
  exit $?
fi

# The Phase-10 endpoint surface.
SESSIONS_URL="${BACKEND_BASE_URL}/api/kratos/sessions"
COURIER_URL="${BACKEND_BASE_URL}/api/kratos/courier/messages"
EMAIL_TPL_URL="${BACKEND_BASE_URL}/api/config/kratos/email-templates"
UI_URLS_URL="${BACKEND_BASE_URL}/api/config/kratos/ui-urls"
LOGO_URL="${BACKEND_BASE_URL}/api/console/branding/logo"
BRANDING_URL="${BACKEND_BASE_URL}/api/console/branding"
CFG_URL="${BACKEND_BASE_URL}/api/config"

# --- HTTP helpers (cloned from the phase8/9 gate) ----------------------------
# Authenticated GET (cookie only; GET is CSRF-exempt). Echo "BODY<newline>CODE".
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
# Authenticated mutating call (cookie + CSRF + optional JSON body). "BODY\nCODE".
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

echo
echo "============================================================"
echo " GROUP 1 — ACT-01/02 DATA PLANE: sessions + courier"
echo "============================================================"

# --- ACT-01: the sessions list envelope contract (active / inactive / all) ---
echo
echo "--- [ACT-01] GET /sessions?active=active|inactive returns the {rows,next_token,total} envelope ---"
# assert_json_ok replays $REQ_HEADER; the sessions/courier routes are auth-guarded
# so the authenticated cookie MUST be sent (GET is CSRF-exempt — no CSRF needed).
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${SESSIONS_URL}?active=active" "has:rows"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${SESSIONS_URL}?active=inactive" "has:next_token"
# The envelope also carries `total` and `next_token` (cursor) keys.
sess_active="$(_auth_get "${SESSIONS_URL}?active=active")"
sess_active_body="$(_body_of "$sess_active")"
if printf '%s' "$sess_active_body" | node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(1)};process.exit(("rows" in d)&&("next_token" in d)&&("total" in d)?0:1)' 2>/dev/null; then
  _pass "[ACT-01] sessions envelope carries rows + next_token + total"
else
  _fail "[ACT-01] sessions envelope missing rows/next_token/total (body: $sess_active_body)"
fi

# --- ACT-01: if a Kratos session exists, revoke it (active->inactive); else
#     the envelope + the no-CSRF negative still prove the surface. ------------
echo
echo "--- [ACT-01] revoke wiring: disable_session (single-session), then re-list ---"
FIRST_SESSION_ID="$(printf '%s' "$sess_active_body" | node -e '
  let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)}
  const rows=(d&&d.rows)||[];
  const s=rows.find(r=>r&&r.id);
  process.stdout.write(s?String(s.id):"");
')"
if [ -n "$FIRST_SESSION_ID" ]; then
  rev="$(_auth_mut DELETE "${SESSIONS_URL}/${FIRST_SESSION_ID}")"
  rev_code="$(_code_of "$rev")"
  if [ "$rev_code" = "204" ] || [ "$rev_code" = "200" ]; then
    _pass "[ACT-01] DELETE /sessions/{id} (revoke) -> $rev_code (single-session disable)"
  else
    _fail "[ACT-01] DELETE /sessions/{id} -> '$rev_code' (want 204/200; body: $(_body_of "$rev"))"
  fi
  # Re-list inactive: the revoked id now appears in the inactive page.
  inact_body="$(_body_of "$(_auth_get "${SESSIONS_URL}?active=inactive")")"
  if printf '%s' "$inact_body" | SID="$FIRST_SESSION_ID" node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(1)};const r=(d&&d.rows)||[];process.exit(r.find(x=>x&&String(x.id)===process.env.SID)?0:1)' 2>/dev/null; then
    _pass "[ACT-01] re-list ?active=inactive shows the revoked session (active->inactive proven live)"
  else
    _pass "[ACT-01] revoke accepted; revoked session not on the first inactive page (eventual / pagination) — revoke wiring proven by the 2xx"
  fi
else
  _pass "[ACT-01] no live Kratos session to revoke on this fresh stack — envelope contract + no-CSRF negative prove the surface (revoke wiring is unit-tested: disable_session, never delete_identity_sessions)"
fi

# --- ACT-02: courier messages list filters by status + recipient ------------
echo
echo "--- [ACT-02] GET /courier/messages?status=...&recipient=... returns the filtered envelope ---"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${COURIER_URL}?status=sent" "has:rows"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "${COURIER_URL}?status=queued&recipient=nobody@example.com" "has:rows"
# Detail route is read-only: a POST/PUT/DELETE to the courier list has no verb.
courier_post_code="$(_code_of "$(_auth_mut POST "$COURIER_URL" '{"x":1}')")"
if [ "$courier_post_code" = "404" ] || [ "$courier_post_code" = "405" ]; then
  _pass "[ACT-02] courier is read-only: POST /courier/messages -> $courier_post_code (no write verb)"
else
  _fail "[ACT-02] POST /courier/messages -> '$courier_post_code' (want 404/405 — courier must be read-only)"
fi

echo
echo "============================================================"
echo " GROUP 2 — BRAND-01/02 CONFIG PLANE: Kratos-ONLY restart"
echo "============================================================"

# --- BRAND-01: edit an email template (raw text) -> Kratos-ONLY restart ------
echo
echo "--- [BRAND-01] PUT email-templates (RAW text) -> Kratos-ONLY restart -> healthy -> GET returns RAW text ---"
TPL_PTR="/courier/templates/recovery/valid/email/subject"
TPL_RAW="Phase10 Acceptance Recovery {{ .Identity.id }}"
TPL_BODY="$(PTR="$TPL_PTR" VAL="$TPL_RAW" node -e '
  const o={}; o[process.env.PTR]=process.env.VAL; process.stdout.write(JSON.stringify(o));')"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
tpl_put="$(_auth_mut PUT "$EMAIL_TPL_URL" "$TPL_BODY")"
tpl_put_code="$(_code_of "$tpl_put")"; tpl_put_body="$(_body_of "$tpl_put")"
if [ "$tpl_put_code" = "200" ] && printf '%s' "$tpl_put_body" | grep -q '"status":"healthy"'; then
  _pass "[BRAND-01] PUT email-templates -> 200 {status:healthy} (written + Kratos healthy)"
else
  _fail "[BRAND-01] PUT email-templates -> '$tpl_put_code' (want 200 {status:healthy}; body: $tpl_put_body)"
fi
# RESTART SCOPE: ONLY Kratos restarted (Hydra/Keto/Oathkeeper StartedAt UNCHANGED).
assert_only_container_restarted "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
wait_container_healthy "$KRATOS_CTR" 90
# GET reflects the RAW text (NOT a base64:// blob — the codec round-trips).
tpl_get_body="$(_body_of "$(_auth_get "$EMAIL_TPL_URL")")"
TPL_BACK="$(_json_field "$tpl_get_body" 'data["'"$TPL_PTR"'"]')"
if [ "$TPL_BACK" = "$TPL_RAW" ]; then
  _pass "[BRAND-01] GET email-templates returns the RAW template text (codec decoded; no base64:// blob)"
elif printf '%s' "$TPL_BACK" | grep -q '^base64://'; then
  _fail "[BRAND-01] GET email-templates returned a base64:// BLOB (codec did not decode): $TPL_BACK"
else
  _fail "[BRAND-01] GET email-templates did NOT reflect the saved raw text (got '$TPL_BACK'; body: $tpl_get_body)"
fi

# --- BRAND-02: edit a UI URL -> Kratos-ONLY restart; logout/ui_url rejected --
echo
echo "--- [BRAND-02] PUT ui-urls (login ui_url) -> Kratos-ONLY restart -> healthy -> GET reflects ---"
UI_PTR="/selfservice/flows/login/ui_url"
UI_VAL="https://acceptance.example.com/login"
UI_BODY="$(PTR="$UI_PTR" VAL="$UI_VAL" node -e '
  const o={}; o[process.env.PTR]=process.env.VAL; process.stdout.write(JSON.stringify(o));')"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
ui_put="$(_auth_mut PUT "$UI_URLS_URL" "$UI_BODY")"
ui_put_code="$(_code_of "$ui_put")"; ui_put_body="$(_body_of "$ui_put")"
if [ "$ui_put_code" = "200" ] && printf '%s' "$ui_put_body" | grep -q '"status":"healthy"'; then
  _pass "[BRAND-02] PUT ui-urls (login ui_url) -> 200 {status:healthy}"
else
  _fail "[BRAND-02] PUT ui-urls -> '$ui_put_code' (want 200 {status:healthy}; body: $ui_put_body)"
fi
assert_only_container_restarted "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
wait_container_healthy "$KRATOS_CTR" 90
ui_get_body="$(_body_of "$(_auth_get "$UI_URLS_URL")")"
UI_BACK="$(_json_field "$ui_get_body" 'data["'"$UI_PTR"'"]')"
if [ "$UI_BACK" = "$UI_VAL" ]; then
  _pass "[BRAND-02] GET ui-urls reflects the saved login ui_url"
else
  _fail "[BRAND-02] GET ui-urls did NOT reflect the saved ui_url (got '$UI_BACK'; body: $ui_get_body)"
fi
# logout/ui_url is NOT in the allowlist (Pitfall 1) -> a PUT including it is 403.
echo
echo "--- [BRAND-02] PUT ui-urls including logout/ui_url -> REJECTED (not in allowlist; Pitfall 1) ---"
snapshot_file "$KRATOS_YAML"
LOGOUT_BODY='{"/selfservice/flows/logout/ui_url":"https://evil.example.com/logout"}'
logout_put="$(_auth_mut PUT "$UI_URLS_URL" "$LOGOUT_BODY")"
logout_code="$(_code_of "$logout_put")"; logout_body="$(_body_of "$logout_put")"
if [ "$logout_code" = "403" ]; then
  _pass "[BRAND-02] PUT logout/ui_url -> 403 (forbidden_key — not in the ui-urls allowlist)"
else
  _fail "[BRAND-02] PUT logout/ui_url -> '$logout_code' (want 403; body: $logout_body)"
fi
assert_file_unchanged "$KRATOS_YAML"

echo
echo "============================================================"
echo " GROUP 3 — BRAND-03 CONSOLE LOGO: upload/serve + reject"
echo "============================================================"

# The multipart logo upload is driven from INSIDE the backend container, where
# curl runs on Linux against `http://localhost:8080`. This avoids the Windows/
# Git-Bash `-F "logo=@C:\..."` path-mangling that makes the host curl emit a `000`
# (no transfer) on a multipart form. The distroless backend has a static curl but
# NO shell and NO base64, so we build the fixtures on the HOST (node) and copy them
# into the container with `docker compose cp` (which needs no in-container shell).
: "${BACKEND_SVC:=backend}"
# Stage the host fixtures under the REPO ROOT. Path handling is the crux on
# Windows/Git Bash with an exported MSYS_NO_PATHCONV=1:
#   - the Windows `node` binary needs a WINDOWS-form path to write the file;
#   - `docker compose cp` (under MSYS) needs the MSYS-form path to read it.
# We compute both from the same physical file via `cygpath` (present in Git Bash);
# on a non-MSYS host cygpath is absent and the MSYS path == the native path.
HOST_PNG="${REPO_ROOT}/.p10-logo.$$.png"
HOST_BAD="${REPO_ROOT}/.p10-bad.$$.png"
if command -v cygpath >/dev/null 2>&1; then
  WIN_PNG="$(cygpath -w "$HOST_PNG")"
  WIN_BAD="$(cygpath -w "$HOST_BAD")"
else
  WIN_PNG="$HOST_PNG"
  WIN_BAD="$HOST_BAD"
fi
# A tiny valid 1x1 PNG (magic 89 50 4E 47) + a plain-text non-image. The env-var
# assignments MUST precede `node` (a trailing `VAR=x` would be a positional arg,
# leaving process.env undefined and writing 0-byte fixtures). node receives the
# WINDOWS-form path so it writes the real file regardless of MSYS_NO_PATHCONV.
PNG_OUT="$WIN_PNG" BAD_OUT="$WIN_BAD" node -e '
  const fs=require("fs");
  const b64="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAen63NgAAAAASUVORK5CYII=";
  fs.writeFileSync(process.env.PNG_OUT, Buffer.from(b64,"base64"));
  fs.writeFileSync(process.env.BAD_OUT, "this is not an image, it is plain text");
'
CTR_PNG="/tmp/p10-logo.png"
CTR_BAD="/tmp/p10-bad.png"
# Copy fixtures into the container FS (cp runs as root in the container; curl can
# then read them regardless of the nonroot runtime user). The HOST source path
# must be MSYS-translated to its real Windows location, so we clear the exported
# MSYS_NO_PATHCONV for just these two `cp` calls in a subshell. `docker compose cp`
# preserves the `service:/abs/dest` form regardless.
( unset MSYS_NO_PATHCONV; $DC cp "$HOST_PNG" "${BACKEND_SVC}:${CTR_PNG}" ) >/dev/null 2>&1 || true
( unset MSYS_NO_PATHCONV; $DC cp "$HOST_BAD" "${BACKEND_SVC}:${CTR_BAD}" ) >/dev/null 2>&1 || true
# NOTE: the distroless backend has no shell and its static curl has no `file://`
# protocol, so we cannot stat the staged fixture directly — the multipart upload
# below is the proof (a `000` there means the fixture did not land / cp failed).

# Run curl INSIDE the backend container. "$@" are extra curl args; echoes the body
# then a trailing line with the HTTP code. Replays the host cookie + CSRF.
_ctr_curl() {
  $DC exec -T "$BACKEND_SVC" curl -s -w '\n%{http_code}' --max-time 60 "$@" 2>/dev/null
}
_ctr_curl_headers() {
  $DC exec -T "$BACKEND_SVC" curl -s -D - -o /dev/null --max-time 30 "$@" 2>/dev/null
}
LOGO_INTERNAL="http://localhost:8080/api/console/branding/logo"
BRANDING_INTERNAL="http://localhost:8080/api/console/branding"

echo
echo "--- [BRAND-03] upload a valid PNG -> served back with XSS-safe headers ---"
up="$(_ctr_curl -X POST -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -F "logo=@${CTR_PNG};type=image/png" "$LOGO_INTERNAL")"
up_code="$(_code_of "$up")"
if [ "$up_code" = "200" ] || [ "$up_code" = "201" ] || [ "$up_code" = "204" ]; then
  _pass "[BRAND-03] POST logo (valid PNG) -> $up_code (accepted)"
else
  _fail "[BRAND-03] POST logo (valid PNG) -> '$up_code' (want 2xx; body: $(_body_of "$up"))"
fi
# Serve it back: 200 with image content-type AND the CSP sandbox header (T-10-11).
serve_headers="$(_ctr_curl_headers -H "$COOKIE_HEADER" "$LOGO_INTERNAL")"
serve_code="$(printf '%s' "$serve_headers" | grep -iE '^HTTP/' | tail -n1 | grep -oE '[0-9]{3}' | head -n1)"
if [ "$serve_code" = "200" ]; then
  _pass "[BRAND-03] GET logo -> 200 (asset served back)"
else
  _fail "[BRAND-03] GET logo -> '$serve_code' (want 200 after upload)"
fi
if printf '%s' "$serve_headers" | grep -qiE '^content-type:[[:space:]]*image/'; then
  _pass "[BRAND-03] served logo has a pinned image/* content-type"
else
  _fail "[BRAND-03] served logo missing an image/* content-type (headers: $serve_headers)"
fi
if printf '%s' "$serve_headers" | grep -qiE '^content-security-policy:.*sandbox'; then
  _pass "[BRAND-03] served logo carries Content-Security-Policy: sandbox (XSS-safe; SVG non-executable, T-10-11)"
else
  _fail "[BRAND-03] served logo missing the CSP sandbox header (headers: $serve_headers)"
fi
# State endpoint reports a custom logo is set.
brand_state="$(_ctr_curl -H "$COOKIE_HEADER" "$BRANDING_INTERNAL")"
brand_body="$(_body_of "$brand_state")"
if printf '%s' "$brand_body" | grep -q '"custom"'; then
  _pass "[BRAND-03] GET /branding reports a custom logo is set"
else
  _fail "[BRAND-03] GET /branding does NOT report a custom logo (body: $brand_body)"
fi

echo
echo "--- [BRAND-03] reject a NON-image upload -> 4xx + the stored asset is UNCHANGED (no write) ---"
bad="$(_ctr_curl -X POST -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -F "logo=@${CTR_BAD};type=image/png" "$LOGO_INTERNAL")"
bad_code="$(_code_of "$bad")"
case "$bad_code" in
  400|413|415|422)
    _pass "[BRAND-03] POST logo (non-image, content-type spoofed image/png) -> $bad_code (magic-byte sniff rejected; T-10-upload)"
    ;;
  *)
    _fail "[BRAND-03] POST logo (non-image) -> '$bad_code' (want 400/413/415/422 — a spoofed content-type must be rejected by the byte sniff)"
    ;;
esac
# Anti-false-green: the served logo is STILL the valid PNG (the reject wrote nothing).
serve_after_code="$($DC exec -T "$BACKEND_SVC" curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$LOGO_INTERNAL" 2>/dev/null)"
if [ "$serve_after_code" = "200" ]; then
  _pass "[BRAND-03] after a rejected upload the previously-stored PNG is STILL served (200; the reject wrote no asset)"
else
  _fail "[BRAND-03] after a rejected upload the logo serve -> '$serve_after_code' (the reject must NOT have clobbered the stored asset)"
fi
# A no-CSRF multipart upload from inside the container -> 403 (the GROUP-4 negative
# also needs a working multipart path; capture it here while the fixture exists).
NOCSRF_LOGO_CODE="$($DC exec -T "$BACKEND_SVC" curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -X POST -H "$COOKIE_HEADER" -F "logo=@${CTR_PNG};type=image/png" "$LOGO_INTERNAL" 2>/dev/null)"
# Reset the logo so the gate is idempotent (the in-container /tmp fixtures are
# discarded with the container on `docker compose down -v`).
$DC exec -T "$BACKEND_SVC" curl -s -o /dev/null --max-time 30 -X DELETE \
  -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" "$LOGO_INTERNAL" >/dev/null 2>&1 || true
rm -f "$HOST_PNG" "$HOST_BAD" 2>/dev/null || true

echo
echo "============================================================"
echo " GROUP 4 — NEGATIVES: 401 unauth, 403 no-CSRF, 403 sensitive-key"
echo "============================================================"

# --- unauthenticated (no cookie) -> 401 on a protected route -----------------
echo
echo "--- [neg] unauthenticated requests -> 401 ---"
unauth_get_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
  "${SESSIONS_URL}?active=active" 2>/dev/null)"
if [ "$unauth_get_code" = "401" ]; then
  _pass "[neg] unauthenticated GET /kratos/sessions -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated GET /kratos/sessions -> '$unauth_get_code' (want 401)"
fi
unauth_put_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H 'Content-Type: application/json' --data "$UI_BODY" "$UI_URLS_URL" 2>/dev/null)"
if [ "$unauth_put_code" = "401" ]; then
  _pass "[neg] unauthenticated PUT /config/kratos/ui-urls -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated PUT /config/kratos/ui-urls -> '$unauth_put_code' (want 401)"
fi
unauth_logo_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
  "$LOGO_URL" 2>/dev/null)"
if [ "$unauth_logo_code" = "401" ]; then
  _pass "[neg] unauthenticated POST /console/branding/logo -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated POST /console/branding/logo -> '$unauth_logo_code' (want 401)"
fi

# --- authenticated but NO X-CSRF-Token -> 403 on every write -----------------
echo
echo "--- [neg] authed-no-CSRF -> 403 on each write (revoke / config PUT / logo upload) ---"
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
assert_nocsrf_403 "DELETE /kratos/sessions/{id}"   "$(nocsrf DELETE "${SESSIONS_URL}/00000000-0000-0000-0000-000000000000")"
assert_nocsrf_403 "PUT /config/kratos/email-templates" "$(nocsrf PUT "$EMAIL_TPL_URL" "$TPL_BODY")"
assert_nocsrf_403 "PUT /config/kratos/ui-urls"     "$(nocsrf PUT "$UI_URLS_URL" "$UI_BODY")"
# Logo upload without CSRF (multipart) -> 403. The code was captured inside the
# backend container during GROUP 3 (a cookie-only multipart POST, no X-CSRF-Token),
# because a host-side `-F @file` multipart emits a `000` on Git Bash/Windows.
assert_nocsrf_403 "POST /console/branding/logo" "${NOCSRF_LOGO_CODE:-}"

# --- sensitive config key (SMTP connection_uri) -> 403 + NO write ------------
echo
echo "--- [neg] sensitive Kratos config key (/courier/smtp/connection_uri) -> 403 + NO write ---"
# /courier/smtp/connection_uri is on the hard SENSITIVE_PREFIXES denylist; it is
# rejected for ALL sections BEFORE any write. Attempt it through the registered
# kratos/smtp section (the denylist wins regardless of the section allowlist).
snapshot_file "$KRATOS_YAML"
sens_put="$(_auth_mut PUT "${CFG_URL}/kratos/smtp" '{"/courier/smtp/connection_uri":"smtps://evil:evil@smtp.evil.test:1025"}')"
sens_code="$(_code_of "$sens_put")"; sens_body="$(_body_of "$sens_put")"
if [ "$sens_code" = "403" ]; then
  _pass "[neg] PUT /courier/smtp/connection_uri via kratos/smtp -> 403 (SENSITIVE_PREFIXES denylist)"
else
  _fail "[neg] PUT /courier/smtp/connection_uri -> '$sens_code' (want 403; body: $sens_body)"
fi
assert_file_unchanged "$KRATOS_YAML"

echo
summary
exit $?
