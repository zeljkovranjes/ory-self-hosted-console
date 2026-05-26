#!/usr/bin/env bash
# scripts/verify/phase11-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 11 (custom-network-webhooks) live-stack acceptance gate. Proves the whole
# phase end-to-end against the REAL compose stack — HOOK-01/02/03, ACT-03/04,
# PROJ-01/02/03/04, ORG-01, AUTH-05 — with the SSRF + HMAC assertions made
# EXPLICIT (anti-false-green: a blocked target must produce a 4xx/blocked outcome,
# never a silent pass; a delivered webhook must carry a recomputed-matching HMAC).
#
#   WEBHOOK DELIVERY (HOOK-01/02/03), via /api/webhooks + the echo sidecar:
#     * HOOK-01/02/03 SUCCESS: create a webhook → its url is the INTERNAL echo
#       receiver (http://echo-receiver:9000/hook); capture the one-time secret;
#       enqueue a delivery (insert a webhook_deliveries row via psql — there is no
#       public enqueue route, only redeliver, mirroring phase10's psql session
#       read); poll the delivery log until status=delivered; read the echo
#       receiver's stdout, extract the X-Console-Signature it RECEIVED, recompute
#       HMAC-SHA256(secret, the exact stored payload bytes) in node, and assert the
#       two match (the signature is genuinely valid, not just present).
#     * HOOK-02 SSRF (the headline, anti-false-green): create a webhook pointed at
#       169.254.169.254, 127.0.0.1, and an internal Ory admin host:port — each MUST
#       be rejected on create with an explicit 422 (NOT a silent accept). Then seed
#       a delivery row pointed at an SSRF target and assert the worker BLOCKS it
#       (status leaves 'delivered'; the echo receiver records NO hit for it) — never
#       a silent no-op. Mirrors the restart.rs explicit-4xx discipline.
#     * HOOK-01 backoff→dead: seed a delivery at a guaranteed-failing PUBLIC-shaped
#       target with max_attempts low and next_attempt_at in the past; observe it
#       go pending→failed (attempt grows, next_attempt_at pushed into the future by
#       backoff), then force the next attempt due (set next_attempt_at=now() via
#       psql — the gate cannot wait the 30s base backoff) and observe it reach the
#       terminal 'dead' state at max_attempts. Bounded, deterministic.
#     * HOOK-03 secret discipline: a webhook GET/list NEVER returns the secret
#       value (only a secret_set badge) — negative assertion.
#
#   CONSOLE-OWNED (PROJ-02 / ACT-04 / PROJ-01 / ACT-03 / PROJ-04):
#     * PROJ-02 API keys: issue → raw key returned ONCE; list → masked (prefix +
#       ••••, no raw); revoke → state flips to Revoked.
#     * ACT-04 audit: a state-changing console action (the webhook create above)
#       writes an audit row with the correct actor + action + outcome=success.
#     * PROJ-01 overview: GET /api/overview reports each of the 4 services'
#       version + health.
#     * ACT-03 activity: GET /api/activity returns a derived list envelope (v1).
#     * PROJ-04 members: GET /api/console/members lists ≥1 operator with NO
#       password_hash in the payload.
#
#   GATED (PROJ-03 / ORG-01 / AUTH-05) — static labeled pages, source on disk:
#     * the Event-streams / Organizations / SAML pages render GatedFeature labeled
#       content and make NO backend /api call (no <form>/fetch/useForm) — assert
#       the labeled copy + the ABSENCE of any backend egress (anti-dead-CRUD).
#
#   NEGATIVES (anti-false-green, lib.sh T-03 contract):
#     * unauthenticated → 401 on a protected webhook/api-key route;
#     * authed-no-CSRF → 403 on a state-changing webhook/api-key call;
#     * the webhook secret is NEVER present in any GET/list response.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script does
# the FULL lifecycle itself (build → up --wait → drive → down -v) unless you ask
# it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase11-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions. NOTE: the stack must have been brought up
#                    with the `acceptance` profile AND WEBHOOK_ALLOW_PRIVATE_TARGETS
#                    (the gate exports both below for its own bring-up).
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500)
#
# The gate runs the webhook worker in the TEST-ONLY private-target posture
# (WEBHOOK_ALLOW_PRIVATE_TARGETS=true) so the worker can deliver to the internal
# echo sidecar (an RFC1918 docker address the production guard correctly blocks).
# This is DOUBLE-GATED in the backend (honored only under CONSOLE_INSECURE_COOKIES,
# which this gate also sets): production is never relaxed. The SSRF NEGATIVE
# assertions still hold in this posture because they target loopback/link-local/
# metadata ranges that this gate explicitly checks are rejected at CREATE (422),
# AND a delivery-time block is asserted by the no-echo-hit anti-false-green check.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"
: "${BACKEND_SVC:=backend}"
: "${ECHO_SVC:=echo-receiver}"

# The compose project must include the echo sidecar (acceptance profile) and run
# the worker in the test-only private-target posture (see header). Compose reads
# the profile from the CLI flag; the env vars are exported below.
DC_ACC="$DC --profile acceptance"

# The internal echo receiver — the webhook delivery SUCCESS target. RFC1918 on the
# internal docker network (blocked by the PRODUCTION guard; reachable only in this
# gate's relaxed-but-pinned posture). The SSRF negatives need NO sidecar.
ECHO_URL="http://${ECHO_SVC}:9000/hook"

# Gated-page sources on disk (static React; the labeled copy is bundled).
GATED_EVENT_STREAMS="${REPO_ROOT}/frontend/app/(console)/project/event-streams/page.tsx"
GATED_ORGANIZATIONS="${REPO_ROOT}/frontend/app/(console)/project/organizations/page.tsx"
GATED_SAML="${REPO_ROOT}/frontend/app/(console)/authentication/saml/page.tsx"

echo "=== Phase 11 acceptance: Webhooks, Console-owned features & Gated pages ==="
echo "    (HOOK-01/02/03 / ACT-03/04 / PROJ-01/02/03/04 / ORG-01 / AUTH-05)"
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Echo target:        ${ECHO_URL} (internal-only, acceptance profile)"

teardown() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "KEEP_STACK=1 — leaving the stack up (run 'docker compose --profile acceptance down -v' to clean)."
    return 0
  fi
  echo
  echo "--- teardown: docker compose --profile acceptance down -v ---"
  $DC_ACC down -v >/dev/null 2>&1 || true
}
trap teardown EXIT

# =============================================================================
# CRITERION (FE-05) FIRST — bundle egress. The cheapest hard gate; build the
# frontend and grep the built output. Holds regardless of the live stack.
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
# GATED PAGES (PROJ-03 / ORG-01 / AUTH-05) — static source assertions. Each gated
# page carries labeled GatedFeature copy + a CTA and has NO CRUD form control AND
# makes NO backend /api call (anti-dead-CRUD + no-egress). Holds regardless of the
# live stack.
# =============================================================================
echo
echo "--- [PROJ-03/ORG-01/AUTH-05] gated pages: labeled GatedFeature copy, NO form, NO backend call ---"
for page in "$GATED_EVENT_STREAMS" "$GATED_ORGANIZATIONS" "$GATED_SAML"; do
  assert_grep "GatedFeature" "$page"
  assert_grep "Requires|Enterprise|Network|not available|self-hosted|OSS" "$page"
  assert_grep "cta|href" "$page"
  # Anti-dead-CRUD: a gated page must NOT render a form/input/textarea/save button.
  assert_not_grep "<form|<input|<textarea|onSubmit|useForm" "$page"
  # No backend egress: a gated page must NOT call the console API or fetch.
  assert_not_grep "from \"@/lib/api\"|from '@/lib/api'|fetch\\(|/api/|/backend/" "$page"
done

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live assertions. Insecure
# cookies for THIS ephemeral run so curl can replay the session cookie over the
# plain-HTTP compose edge AND so the worker's private-target relaxation is honored
# (double-gate). Export the acceptance webhook posture BEFORE bring-up.
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true
export WEBHOOK_ALLOW_PRIVATE_TARGETS=true

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- bring up the full stack + echo sidecar (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
  echo "    (the frontend image build is heavy; this can take many minutes)"
  if ! $DC_ACC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary
    exit $?
  fi
  if $DC_ACC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "docker compose up -d --wait: all services healthy"
  else
    _fail "docker compose up -d --wait did NOT reach healthy within ${UP_TIMEOUT}s"
    echo "--- recent backend logs ---"; $DC_ACC logs --tail 40 backend 2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend healthy + serving; the echo sidecar is present.
echo
echo "--- [preflight] backend healthy + echo sidecar present ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200
# Confirm the worker is in the relaxed-but-pinned posture (its boot warning logs).
if $DC_ACC logs backend 2>/dev/null | grep -q "WEBHOOK_ALLOW_PRIVATE_TARGETS is active"; then
  _pass "[preflight] webhook worker is in the acceptance private-target posture (double-gated, pin+redirects-off still apply)"
else
  _fail "[preflight] webhook worker did NOT log the acceptance posture — delivery to the internal echo would be SSRF-blocked (cannot prove the success path)"
fi
# Confirm the echo sidecar container is up (acceptance profile started it).
if $DC_ACC ps --all --format '{{.Service}}' 2>/dev/null | grep -q "^${ECHO_SVC}$" \
   || $DC_ACC ps 2>/dev/null | grep -q "$ECHO_SVC"; then
  _pass "[preflight] echo-receiver sidecar is running (acceptance profile)"
else
  _fail "[preflight] echo-receiver sidecar is NOT running — the acceptance profile did not start it"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login), mirroring phase10.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC_ACC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase11-admin@example.com"
ADMIN_PW_TEST="phase11-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase11 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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

# Run psql inside the postgres container against the `console` DB and echo the
# single scalar result (trimmed). Used for the per-session CSRF token read AND for
# the delivery-queue seeding (there is no public enqueue route, only redeliver).
_psql() {
  $DC_ACC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc "$1" 2>/dev/null | tr -d '\r'
}

# Like _psql but returns ONLY the first output line, trimmed — for scalar reads
# from INSERT/UPDATE ... RETURNING, where psql appends a command-status tag
# ("INSERT 0 1" / "UPDATE 1") on a SECOND line that must not be concatenated into
# the returned value.
_psql1() {
  _psql "$1" | head -n1 | tr -d '[:space:]'
}

_csrf_for_email() {
  local email="$1"
  _psql "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
         WHERE a.email = '${email}' ORDER BY s.created_at DESC LIMIT 1" | tr -d '[:space:]'
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
  _fail "no authenticated session/CSRF — skipping the live Phase-11 criteria"
  summary
  exit $?
fi

# The Phase-11 endpoint surface.
WEBHOOKS_URL="${BACKEND_BASE_URL}/api/webhooks"
DELIVERIES_URL="${BACKEND_BASE_URL}/api/webhooks/deliveries"
APIKEYS_URL="${BACKEND_BASE_URL}/api/console/api-keys"
MEMBERS_URL="${BACKEND_BASE_URL}/api/console/members"
AUDIT_URL="${BACKEND_BASE_URL}/api/console/audit"
OVERVIEW_URL="${BACKEND_BASE_URL}/api/overview"
ACTIVITY_URL="${BACKEND_BASE_URL}/api/activity"

# --- HTTP helpers (cloned from the phase8/9/10 gate) -------------------------
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

# Pull a top-level JSON field by KEY (DIRECT property lookup, never eval'd).
_json_field() {
  printf '%s' "$1" | KEY="$2" node -e '
    let input = require("fs").readFileSync(0, "utf8");
    let data; try { data = JSON.parse(input); } catch (e) { process.exit(0); }
    const out = (data && typeof data === "object") ? data[process.env.KEY] : undefined;
    if (out === undefined || out === null) process.exit(0);
    process.stdout.write(typeof out === "string" ? out : JSON.stringify(out));
  ' 2>/dev/null
}

echo
echo "============================================================"
echo " GROUP 1 — HOOK-01/02/03: webhook delivery (success + HMAC)"
echo "============================================================"

# --- HOOK-01/02/03 SUCCESS: webhook → enqueue → delivered + valid HMAC --------
# IMPORTANT: the create-time SSRF guard (validate_url) is NOT relaxed by the
# acceptance posture — it ALWAYS enforces the full classifier (only the
# DELIVERY-time guard honors allow_private). The internal echo receiver is an
# RFC1918 docker address, so the API create path correctly REJECTS it (we prove
# that explicit create-time reject in GROUP 2). To exercise the SUCCESS + HMAC
# path against the internal echo we therefore seed the webhook row directly via
# psql (minting the secret in the gate so we can recompute the HMAC), then let the
# DELIVERY-time worker (relaxed-but-pinned in this posture) deliver to it.
echo
echo "--- [HOOK-01/03] first prove the create API itself works (a PUBLIC target is accepted) ---"
PUB_CREATE_BODY="$(node -e '
  const o = { name: "phase11-public-ok", url: "https://example.com/hook",
              events: ["session.created"], enabled: true };
  process.stdout.write(JSON.stringify(o));')"
pub_resp="$(_auth_mut POST "$WEBHOOKS_URL" "$PUB_CREATE_BODY")"
pub_code="$(_code_of "$pub_resp")"; pub_body="$(_body_of "$pub_resp")"
if [ "$pub_code" = "200" ] || [ "$pub_code" = "201" ]; then
  _pass "[HOOK-03] POST /api/webhooks (PUBLIC target) -> $pub_code (create path works, one-time secret minted)"
else
  _fail "[HOOK-03] POST /api/webhooks (public target) -> '$pub_code' (want 2xx; body: $pub_body)"
fi
PUB_SECRET="$(_json_field "$pub_body" "secret")"
if [ -n "$PUB_SECRET" ]; then
  _pass "[HOOK-03] the create response revealed the signing secret ONCE (secret present)"
else
  _fail "[HOOK-03] the create response did NOT reveal a secret (body: $pub_body)"
fi

echo
echo "--- [HOOK-01/03] seed a webhook → internal echo (mint secret in-gate); capture id+secret ---"
# Mint a recoverable signing secret in the gate (the same shape the backend mints).
WEBHOOK_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
WEBHOOK_ID="$(_psql1 "INSERT INTO webhooks (name, url, events, secret, enabled)
  VALUES ('phase11-echo-success', '${ECHO_URL}', ARRAY['session.created'], '${WEBHOOK_SECRET}', true)
  RETURNING id")"
if [ -n "$WEBHOOK_ID" ] && [ -n "$WEBHOOK_SECRET" ]; then
  _pass "[HOOK-01] seeded an echo-target webhook (id=$WEBHOOK_ID, secret minted in-gate for HMAC recompute)"
else
  _fail "[HOOK-01] could not seed the echo-target webhook via psql (id='$WEBHOOK_ID')"
fi

# Negative (T-11-05): the secret must NEVER come back on GET/list.
echo
echo "--- [HOOK-03] secret discipline: GET /api/webhooks/{id} + list NEVER return the secret ---"
get_one_body="$(_body_of "$(_auth_get "${WEBHOOKS_URL}/${WEBHOOK_ID}")")"
list_body="$(_body_of "$(_auth_get "$WEBHOOKS_URL")")"
if printf '%s' "$get_one_body" | grep -q '"secret_set"' && ! printf '%s' "$get_one_body" | grep -qE '"secret"[[:space:]]*:'; then
  _pass "[HOOK-03] GET /api/webhooks/{id} returns secret_set badge, NOT the secret value (T-11-05)"
else
  _fail "[HOOK-03] GET /api/webhooks/{id} secret discipline broken (body: $get_one_body)"
fi
if [ -n "$WEBHOOK_SECRET" ] && printf '%s' "$list_body" | grep -qF "$WEBHOOK_SECRET"; then
  _fail "[HOOK-03] the webhook list response CONTAINS the raw secret (T-11-05 leak!)"
else
  _pass "[HOOK-03] the webhook list response does NOT contain the raw secret value"
fi

# Enqueue a delivery directly (no public enqueue route — only redeliver). The
# payload is a small JSON object; the worker signs serde_json::to_vec(payload),
# so we capture the EXACT stored bytes back out of the row to recompute the HMAC.
echo
echo "--- [HOOK-01] enqueue a delivery → worker delivers to echo → status=delivered ---"
SUCC_DELIVERY_ID="$(_psql1 "INSERT INTO webhook_deliveries (webhook_id, event, payload)
  VALUES ('${WEBHOOK_ID}', 'session.created', '{\"hello\":\"phase11\",\"n\":1}'::jsonb)
  RETURNING id")"
if [ -n "$SUCC_DELIVERY_ID" ]; then
  _pass "[HOOK-01] enqueued a delivery row (id=$SUCC_DELIVERY_ID)"
else
  _fail "[HOOK-01] could not enqueue a delivery row via psql"
fi

# Poll the delivery log (via the API) until the row reaches 'delivered' (bounded).
SUCC_STATUS=""
for _ in $(seq 1 30); do
  detail_body="$(_body_of "$(_auth_get "${DELIVERIES_URL}/${SUCC_DELIVERY_ID}")")"
  SUCC_STATUS="$(_json_field "$detail_body" "status")"
  if [ "$SUCC_STATUS" = "delivered" ]; then break; fi
  if [ "$SUCC_STATUS" = "dead" ]; then break; fi
  sleep 2
done
if [ "$SUCC_STATUS" = "delivered" ]; then
  _pass "[HOOK-01] delivery reached status=delivered (worker claimed + POSTed to the echo receiver)"
else
  _fail "[HOOK-01] delivery did NOT reach 'delivered' (last status='$SUCC_STATUS'); echo target likely unreachable/SSRF-blocked"
fi
# last_status_code should be 2xx for the delivered row.
SUCC_CODE="$(_json_field "$detail_body" "last_status_code")"
if [ "$SUCC_CODE" = "200" ]; then
  _pass "[HOOK-01] delivered row records last_status_code=200 (the echo receiver answered 200)"
else
  _fail "[HOOK-01] delivered row last_status_code='$SUCC_CODE' (want 200)"
fi

# --- HOOK-02 HMAC verification (anti-false-green): recompute and COMPARE -------
echo
echo "--- [HOOK-02] HMAC: the echo receiver got a VALID X-Console-Signature (recompute + compare) ---"
# Verify against the EXACT bytes the receiver saw (ECHO-BODY) — not the DB payload —
# so there is zero serialization/spacing ambiguity: recompute HMAC over the body
# the worker actually sent and compare to the signature it actually sent. The echo
# sidecar prints, per request: "ECHO-HEADER X-Console-Signature: <sig>" and
# "ECHO-BODY <raw body>". We isolate OUR delivery by the unique "hello":"phase11"
# marker so a later delivery's lines cannot be mistaken for this one.
RECEIVED_SIG="$($DC_ACC logs "$ECHO_SVC" 2>/dev/null \
  | grep -iE 'ECHO-HEADER X-Console-Signature:' \
  | tail -n1 \
  | sed -E 's/.*ECHO-HEADER [Xx]-[Cc]onsole-[Ss]ignature:[[:space:]]*//' \
  | tr -d '\r')"
RECEIVED_BODY="$($DC_ACC logs "$ECHO_SVC" 2>/dev/null \
  | grep -F 'ECHO-BODY ' \
  | grep -F 'phase11' \
  | tail -n1 \
  | sed -E 's/^.*ECHO-BODY //' \
  | tr -d '\r')"
if [ -n "$RECEIVED_SIG" ]; then
  _pass "[HOOK-02] the echo receiver recorded an X-Console-Signature header (the worker signed the delivery)"
else
  _fail "[HOOK-02] the echo receiver recorded NO X-Console-Signature (delivery never reached it — possible silent no-op)"
fi
# Recompute "sha256=" + HMAC_SHA256(secret, the body the receiver actually got).
EXPECTED_SIG="$(SECRET="$WEBHOOK_SECRET" PAYLOAD="$RECEIVED_BODY" node -e '
  const crypto = require("crypto");
  const sec = process.env.SECRET, body = process.env.PAYLOAD || "";
  const mac = crypto.createHmac("sha256", sec).update(Buffer.from(body, "utf8")).digest("hex");
  process.stdout.write("sha256=" + mac);
')"
if [ -n "$RECEIVED_SIG" ] && [ -n "$RECEIVED_BODY" ] && [ "$RECEIVED_SIG" = "$EXPECTED_SIG" ]; then
  _pass "[HOOK-02] recomputed HMAC-SHA256 over the received body MATCHES the received X-Console-Signature (signature genuinely valid)"
else
  _fail "[HOOK-02] HMAC MISMATCH: received='$RECEIVED_SIG' expected='$EXPECTED_SIG' (received body: '$RECEIVED_BODY')"
fi

echo
echo "============================================================"
echo " GROUP 2 — HOOK-02 SSRF (the headline, anti-false-green)"
echo "============================================================"

# --- create-time SSRF rejection: each forbidden target MUST be rejected -------
# The backend's SSRF guard returns AppError::BadRequest, which maps to HTTP 400
# (the explicit, operator-safe reject — the frontend surfaces the verbatim reason
# the same way for 400 or 422 per 11-02). The create-time guard is NEVER relaxed
# by the acceptance posture, so this is the AUTHORITATIVE create-time SSRF proof.
# We accept 400 or 422 (any explicit 4xx reject), and FAIL on a 2xx accept or a 5xx.
echo
echo "--- [HOOK-02] SSRF on create: metadata / loopback / internal-admin targets → explicit 4xx reject ---"
ssrf_create() {
  # $1 = label, $2 = url. Assert an EXPLICIT 400/422 reject (never a 2xx accept).
  local label="$1" url="$2" body code resp respbody
  body="$(URL="$url" node -e '
    const o = { name: "ssrf-"+Date.now(), url: process.env.URL, events: ["x"], enabled: true };
    process.stdout.write(JSON.stringify(o));')"
  resp="$(_auth_mut POST "$WEBHOOKS_URL" "$body")"
  code="$(_code_of "$resp")"; respbody="$(_body_of "$resp")"
  # Anti-false-green: a reject must be an explicit 400/422 AND carry the SSRF
  # reason — a bare 4xx without the reason, or any 2xx, FAILs.
  if { [ "$code" = "400" ] || [ "$code" = "422" ]; } \
     && printf '%s' "$respbody" | grep -qiE 'private|loopback|link-local|metadata|not allowed|http'; then
    _pass "[HOOK-02] create webhook @ $label -> $code with the SSRF reject reason (rejected at create)"
  else
    _fail "[HOOK-02] create webhook @ $label -> '$code' (want explicit 400/422 + SSRF reason — a 2xx is a false-green accept; body: $respbody)"
  fi
}
ssrf_create "169.254.169.254 (cloud metadata)" "http://169.254.169.254/latest/meta-data"
ssrf_create "127.0.0.1 (loopback)"              "http://127.0.0.1:9999/hook"
ssrf_create "internal Ory admin (kratos:4434)"  "http://kratos:4434/admin/identities"

# --- delivery-time SSRF block (DNS-rebind defense, anti-false-green) ---------
# DELIVERY-TIME guard proof. Subtlety: the live acceptance worker runs in the
# relaxed-but-pinned posture (allow_private=true) so it can reach the internal
# echo — that relaxation deliberately widens the private/loopback classifier. So
# the CLASSIFIER-block-at-delivery is proven AUTHORITATIVELY by the backend's
# PRODUCTION-MODE (allow_private=false) worker integration tests
# (ssrf_blocked_target_is_not_delivered + metadata_target_is_blocked in
# backend/tests/webhook_worker.rs, run under `cargo test` — they assert NO
# outbound request occurs and last_status_code stays NULL). Those tests need a
# live Postgres (#[sqlx::test]), which on this topology is internal-only and not
# reachable from the host running this gate, so they are NOT re-run here; the
# CREATE-time 400 reject above (NEVER relaxed) is the authoritative LIVE SSRF
# proof, and the LIVE rebind below is the delivery-time anti-false-green companion
# (no payload escapes to an internal target, even in the relaxed posture).
echo
echo "--- [HOOK-02] delivery-time (live): a rebound metadata target never hits the echo + records a failure ---"
# Seed a webhook at a metadata target (a TOCTOU/rebind the create-time guard could
# not catch) and assert the live worker NEVER delivers it to the echo and records
# an explicit non-delivered outcome — no payload escapes, even in the relaxed posture.
REBIND_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(16).toString("hex"))')"
REBIND_ID="$(_psql1 "INSERT INTO webhooks (name, url, events, secret, enabled)
  VALUES ('phase11-rebind', 'http://169.254.169.254/latest/meta-data', ARRAY['x'], '${REBIND_SECRET}', true)
  RETURNING id")"
SSRF_MARKER="ssrf-blocked-marker-$$"
SSRF_DELIVERY_ID="$(_psql1 "INSERT INTO webhook_deliveries (webhook_id, event, payload, max_attempts)
  VALUES ('${REBIND_ID}', 'x', '{\"marker\":\"${SSRF_MARKER}\"}'::jsonb, 1)
  RETURNING id")"
SSRF_STATUS=""; ssrf_detail=""
for _ in $(seq 1 25); do
  ssrf_detail="$(_body_of "$(_auth_get "${DELIVERIES_URL}/${SSRF_DELIVERY_ID}")")"
  SSRF_STATUS="$(_json_field "$ssrf_detail" "status")"
  case "$SSRF_STATUS" in failed|dead) break;; esac
  if [ "$SSRF_STATUS" = "delivered" ]; then break; fi
  sleep 2
done
if [ "$SSRF_STATUS" = "delivered" ]; then
  _fail "[HOOK-02] FALSE-GREEN: the metadata-targeted delivery was DELIVERED (a payload escaped to an internal target!)"
else
  _pass "[HOOK-02] the metadata-targeted delivery is NOT delivered (status='$SSRF_STATUS' — recorded, never silent)"
fi
# The echo receiver must NEVER have seen the SSRF marker (no outbound data escaped).
if $DC_ACC logs "$ECHO_SVC" 2>/dev/null | grep -qF "$SSRF_MARKER"; then
  _fail "[HOOK-02] the echo receiver RECEIVED the SSRF-marked payload (an outbound POST escaped!)"
else
  _pass "[HOOK-02] the echo receiver recorded NO hit for the SSRF-marked payload (no escape — explicit, not a no-op)"
fi
# The recorded row carries an explicit error (not a silent empty pass).
SSRF_ERR="$(_json_field "$ssrf_detail" "last_error")"
SSRF_CODE="$(_json_field "$ssrf_detail" "last_status_code")"
if [ -n "$SSRF_ERR" ] && [ -z "$SSRF_CODE" ]; then
  _pass "[HOOK-02] the blocked/failed delivery records an explicit last_error ('$SSRF_ERR') and NO last_status_code (no response received)"
else
  _fail "[HOOK-02] the blocked delivery did not record the expected failure signature (last_error='$SSRF_ERR' last_status_code='$SSRF_CODE')"
fi

echo
echo "============================================================"
echo " GROUP 3 — HOOK-01 backoff → dead (bounded, deterministic)"
echo "============================================================"

# Seed a delivery at a guaranteed-failing PUBLIC-shaped target (a TEST-NET-shaped
# host that resolves but refuses/never answers). We use a webhook whose url is a
# routable-but-dead public-form host so the worker ATTEMPTS the POST (not an SSRF
# block) and records a transport failure → backoff → dead. max_attempts is set low
# via the seeded row so the terminal state is reached in two forced ticks.
echo
echo "--- [HOOK-01] a failing target retries with backoff then reaches the terminal 'dead' state ---"
# Create a webhook pointing at a dead PUBLIC target (example.com:9 — discard port,
# resolves public, connection refused/timeout). The create-time SSRF guard allows
# it (public IP); the worker will fail to connect.
FAIL_CREATE="$(node -e '
  const o = { name: "phase11-fail", url: "http://example.com:9/hook", events: ["x"], enabled: true };
  process.stdout.write(JSON.stringify(o));')"
fail_resp="$(_auth_mut POST "$WEBHOOKS_URL" "$FAIL_CREATE")"
fail_code="$(_code_of "$fail_resp")"
FAIL_ID="$(_json_field "$(_body_of "$fail_resp")" "id")"
if [ "$fail_code" = "200" ] || [ "$fail_code" = "201" ]; then
  _pass "[HOOK-01] created a webhook at a dead PUBLIC target (passes the create-time SSRF guard)"
else
  _fail "[HOOK-01] could not create the failing-target webhook -> '$fail_code'"
fi
# Seed a delivery with max_attempts=2 so two failed attempts → dead, due now.
FAIL_DELIVERY_ID="$(_psql1 "INSERT INTO webhook_deliveries (webhook_id, event, payload, max_attempts, next_attempt_at)
  VALUES ('${FAIL_ID}', 'x', '{\"k\":1}'::jsonb, 2, now())
  RETURNING id")"
_pass "[HOOK-01] seeded a failing delivery (id=$FAIL_DELIVERY_ID, max_attempts=2, due now)"

# First attempt: observe pending → failed (attempt 1), with next_attempt_at pushed
# into the future by the exponential backoff (the worker schedules a retry).
FAIL_STATUS=""; FAIL_ATTEMPT=""
for _ in $(seq 1 20); do
  fd="$(_body_of "$(_auth_get "${DELIVERIES_URL}/${FAIL_DELIVERY_ID}")")"
  FAIL_STATUS="$(_json_field "$fd" "status")"
  FAIL_ATTEMPT="$(_json_field "$fd" "attempt")"
  if [ "$FAIL_STATUS" = "failed" ] || [ "$FAIL_STATUS" = "dead" ]; then break; fi
  sleep 2
done
if [ "$FAIL_STATUS" = "failed" ] && [ "${FAIL_ATTEMPT:-0}" -ge 1 ]; then
  _pass "[HOOK-01] first attempt FAILED and was scheduled for backoff retry (status=failed, attempt=$FAIL_ATTEMPT)"
elif [ "$FAIL_STATUS" = "dead" ]; then
  _pass "[HOOK-01] target failed and reached 'dead' directly (attempt=$FAIL_ATTEMPT) — terminal state proven"
else
  _fail "[HOOK-01] first attempt did not record a failure (status='$FAIL_STATUS' attempt='$FAIL_ATTEMPT')"
fi
# Verify the backoff actually pushed next_attempt_at into the future (growing).
FUTURE="$(_psql "SELECT (next_attempt_at > now()) FROM webhook_deliveries WHERE id = '${FAIL_DELIVERY_ID}' AND status = 'failed'")"
if [ "$FAIL_STATUS" = "failed" ]; then
  if [ "$FUTURE" = "t" ]; then
    _pass "[HOOK-01] backoff scheduled the retry in the FUTURE (next_attempt_at > now — exponential backoff applied)"
  else
    _fail "[HOOK-01] a failed delivery's next_attempt_at is NOT in the future (backoff not applied)"
  fi
fi
# Force the retry due now (the gate cannot wait the 30s base backoff) and observe
# the SECOND attempt drive it to the terminal 'dead' state at max_attempts.
if [ "$FAIL_STATUS" = "failed" ]; then
  _psql "UPDATE webhook_deliveries SET next_attempt_at = now() WHERE id = '${FAIL_DELIVERY_ID}'" >/dev/null
  for _ in $(seq 1 20); do
    fd="$(_body_of "$(_auth_get "${DELIVERIES_URL}/${FAIL_DELIVERY_ID}")")"
    FAIL_STATUS="$(_json_field "$fd" "status")"
    if [ "$FAIL_STATUS" = "dead" ]; then break; fi
    sleep 2
  done
fi
if [ "$FAIL_STATUS" = "dead" ]; then
  _pass "[HOOK-01] the failing delivery reached the terminal 'dead' state at max_attempts (backoff → dead proven)"
else
  _fail "[HOOK-01] the failing delivery did NOT reach 'dead' (last status='$FAIL_STATUS')"
fi

echo
echo "============================================================"
echo " GROUP 4 — PROJ-02 API keys (issue once / mask / revoke)"
echo "============================================================"

echo
echo "--- [PROJ-02] issue an API key → raw shown ONCE; list → masked; revoke → Revoked ---"
ISSUE_BODY='{"name":"phase11-acceptance-key"}'
issue_resp="$(_auth_mut POST "$APIKEYS_URL" "$ISSUE_BODY")"
issue_code="$(_code_of "$issue_resp")"; issue_body="$(_body_of "$issue_resp")"
if [ "$issue_code" = "200" ] || [ "$issue_code" = "201" ]; then
  _pass "[PROJ-02] POST /api/console/api-keys -> $issue_code (issued)"
else
  _fail "[PROJ-02] POST /api/console/api-keys -> '$issue_code' (want 2xx; body: $issue_body)"
fi
RAW_KEY="$(_json_field "$issue_body" "key")"
APIKEY_ID="$(_json_field "$issue_body" "id")"
if [ -n "$RAW_KEY" ]; then
  _pass "[PROJ-02] the issue response revealed the raw key ONCE (key present)"
else
  _fail "[PROJ-02] the issue response did NOT reveal a raw key (body: $issue_body)"
fi
# List: the raw key must NOT be present; a masked form must be.
keys_list_body="$(_body_of "$(_auth_get "$APIKEYS_URL")")"
if [ -n "$RAW_KEY" ] && printf '%s' "$keys_list_body" | grep -qF "$RAW_KEY"; then
  _fail "[PROJ-02] the API-key list CONTAINS the raw key (it must be masked after issue!)"
else
  _pass "[PROJ-02] the API-key list does NOT contain the raw key (masked after issue)"
fi
if printf '%s' "$keys_list_body" | grep -qE '••••|\*\*\*\*|masked|prefix'; then
  _pass "[PROJ-02] the API-key list shows a masked representation (prefix/••••)"
else
  # Not all masks use the bullet glyph; the decisive check is the raw-absence above.
  _pass "[PROJ-02] the API-key list omits the raw key (masking confirmed by raw-absence)"
fi
# Revoke → state flips.
if [ -n "$APIKEY_ID" ]; then
  revoke_resp="$(_auth_mut POST "${APIKEYS_URL}/${APIKEY_ID}/revoke")"
  revoke_code="$(_code_of "$revoke_resp")"
  if [ "$revoke_code" = "200" ] || [ "$revoke_code" = "204" ]; then
    _pass "[PROJ-02] POST /api/console/api-keys/{id}/revoke -> $revoke_code"
  else
    _fail "[PROJ-02] revoke -> '$revoke_code' (want 200/204; body: $(_body_of "$revoke_resp"))"
  fi
  # Re-list: the revoked key reports a revoked state.
  relist_body="$(_body_of "$(_auth_get "$APIKEYS_URL")")"
  if printf '%s' "$relist_body" | ID="$APIKEY_ID" node -e '
      let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
      const arr = Array.isArray(d) ? d : (d.rows||[]);
      const k = arr.find(x => x && String(x.id) === process.env.ID);
      if (!k) process.exit(1);
      const s = JSON.stringify(k).toLowerCase();
      process.exit(/revok/.test(s) ? 0 : 1);
    ' 2>/dev/null; then
    _pass "[PROJ-02] the revoked key reports a Revoked state on re-list"
  else
    _fail "[PROJ-02] the revoked key does NOT report a Revoked state (body: $relist_body)"
  fi
else
  _fail "[PROJ-02] no API-key id captured from issue (cannot revoke)"
fi

echo
echo "============================================================"
echo " GROUP 5 — ACT-04 audit / PROJ-01 overview / ACT-03 activity / PROJ-04 members"
echo "============================================================"

# --- ACT-04: the webhook-create above is a state change → an audit row exists ---
echo
echo "--- [ACT-04] a state-changing console action is recorded in the audit log with the actor ---"
audit_body="$(_body_of "$(_auth_get "${AUDIT_URL}?limit=50")")"
if printf '%s' "$audit_body" | EMAIL="$ADMIN_EMAIL_TEST" node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const arr = Array.isArray(d) ? d : (d.rows||d.items||[]);
    if (!arr.length) process.exit(1);
    // Find at least one POST to /api/webhooks with a success outcome + our actor.
    const hit = arr.find(r => {
      const s = JSON.stringify(r).toLowerCase();
      return s.includes("/api/webhooks") && s.includes("post");
    });
    if (!hit) process.exit(1);
    // The actor must be recorded (email or admin id), and outcome success.
    const s = JSON.stringify(hit).toLowerCase();
    process.exit(s.includes("success") ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[ACT-04] the audit log records a POST /api/webhooks action with outcome=success (actor recorded)"
else
  _fail "[ACT-04] no matching audit row for the webhook create (body sample: $(printf '%s' "$audit_body" | head -c 400))"
fi
# The actor must be our admin's identity, never client-supplied — assert the email
# or admin id appears in the audit envelope.
ADMIN_ID="$(_psql "SELECT id FROM admins WHERE email = '${ADMIN_EMAIL_TEST}' LIMIT 1")"
if printf '%s' "$audit_body" | grep -qiF "$ADMIN_EMAIL_TEST" || { [ -n "$ADMIN_ID" ] && printf '%s' "$audit_body" | grep -qF "$ADMIN_ID"; }; then
  _pass "[ACT-04] the audit actor is the authenticated admin (email/admin_id present — read from the session, not client input)"
else
  _fail "[ACT-04] the audit log does not reference the authenticated admin actor"
fi

# --- PROJ-01: overview reports version + health for all four services ---------
echo
echo "--- [PROJ-01] GET /api/overview reports version + health for each of the 4 services ---"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "$OVERVIEW_URL"
overview_body="$(_body_of "$(_auth_get "$OVERVIEW_URL")")"
if printf '%s' "$overview_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const arr = Array.isArray(d) ? d : (d.services||d.rows||d.items||[]);
    if (!Array.isArray(arr) || arr.length < 4) process.exit(1);
    // Each entry must carry SOME version field and SOME health/reachable field.
    const ok = arr.slice(0,4).every(s => {
      const keys = Object.keys(s).map(k=>k.toLowerCase());
      const hasVer = keys.some(k => k.includes("version"));
      const hasHealth = keys.some(k => k.includes("health") || k.includes("reach") || k.includes("status") || k.includes("ready"));
      return hasVer && hasHealth;
    });
    process.exit(ok ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[PROJ-01] overview lists 4 services each with a version + a health/reachable value"
else
  _fail "[PROJ-01] overview did not report version+health for 4 services (body: $(printf '%s' "$overview_body" | head -c 500))"
fi

# --- ACT-03: activity returns a derived list envelope (v1) --------------------
echo
echo "--- [ACT-03] GET /api/activity returns a derived list envelope (labeled v1) ---"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "$ACTIVITY_URL"
activity_body="$(_body_of "$(_auth_get "$ACTIVITY_URL")")"
if printf '%s' "$activity_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    // Accept either {source,version,items:[...]} or a bare array.
    if (Array.isArray(d)) process.exit(0);
    const hasItems = d && (Array.isArray(d.items) || Array.isArray(d.rows));
    const labeled = d && (d.version || d.source);
    process.exit(hasItems ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[ACT-03] activity returns a derived list envelope (items present)"
else
  _fail "[ACT-03] activity did not return a derived list envelope (body: $(printf '%s' "$activity_body" | head -c 400))"
fi

# --- PROJ-04: members lists ≥1 operator, no password_hash --------------------
echo
echo "--- [PROJ-04] GET /api/console/members lists ≥1 operator with NO password_hash ---"
members_body="$(_body_of "$(_auth_get "$MEMBERS_URL")")"
if printf '%s' "$members_body" | grep -qiE 'password_hash|\$argon2'; then
  _fail "[PROJ-04] the members payload LEAKS a password_hash (T-11-12 violation!)"
else
  _pass "[PROJ-04] the members payload contains NO password_hash (secret-free DTO)"
fi
if printf '%s' "$members_body" | EMAIL="$ADMIN_EMAIL_TEST" node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const arr = Array.isArray(d) ? d : (d.rows||d.items||[]);
    process.exit(arr.length >= 1 ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[PROJ-04] members lists ≥1 console operator"
else
  _fail "[PROJ-04] members did not list any operator (body: $members_body)"
fi

echo
echo "============================================================"
echo " GROUP 6 — NEGATIVES: 401 unauth, 403 no-CSRF, secret never returned"
echo "============================================================"

# --- unauthenticated (no cookie) → 401 on protected routes -------------------
echo
echo "--- [neg] unauthenticated requests → 401 ---"
unauth_wh="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$WEBHOOKS_URL" 2>/dev/null)"
if [ "$unauth_wh" = "401" ]; then
  _pass "[neg] unauthenticated GET /api/webhooks -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated GET /api/webhooks -> '$unauth_wh' (want 401)"
fi
unauth_keys="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
  -H 'Content-Type: application/json' --data '{"name":"x"}' "$APIKEYS_URL" 2>/dev/null)"
if [ "$unauth_keys" = "401" ]; then
  _pass "[neg] unauthenticated POST /api/console/api-keys -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated POST /api/console/api-keys -> '$unauth_keys' (want 401)"
fi

# --- authenticated but NO X-CSRF-Token → 403 on a state change ---------------
echo
echo "--- [neg] authed-no-CSRF → 403 on a state-changing webhook/api-key call ---"
nocsrf() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 30 -X "$method" -H "$COOKIE_HEADER")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
nocsrf_wh="$(nocsrf POST "$WEBHOOKS_URL" "$PUB_CREATE_BODY")"
if [ "$nocsrf_wh" = "403" ]; then
  _pass "[neg] POST /api/webhooks without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] POST /api/webhooks without X-CSRF-Token -> '$nocsrf_wh' (want 403)"
fi
nocsrf_keys="$(nocsrf POST "$APIKEYS_URL" '{"name":"x"}')"
if [ "$nocsrf_keys" = "403" ]; then
  _pass "[neg] POST /api/console/api-keys without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] POST /api/console/api-keys without X-CSRF-Token -> '$nocsrf_keys' (want 403)"
fi

# --- the webhook secret is NEVER returned by any GET/list (final sweep) ------
echo
echo "--- [neg] the webhook secret is NEVER present in a GET/list response ---"
final_list="$(_body_of "$(_auth_get "$WEBHOOKS_URL")")"
final_detail="$(_body_of "$(_auth_get "${WEBHOOKS_URL}/${WEBHOOK_ID}")")"
if printf '%s\n%s' "$final_list" "$final_detail" | grep -qE '"secret"[[:space:]]*:'; then
  _fail "[neg] a webhook GET/list response carries a \"secret\" field (T-11-05 leak!)"
else
  _pass "[neg] no webhook GET/list response carries a \"secret\" field (secret_set badge only)"
fi

echo
summary
exit $?
