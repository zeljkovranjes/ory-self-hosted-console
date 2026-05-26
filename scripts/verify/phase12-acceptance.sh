#!/usr/bin/env bash
# scripts/verify/phase12-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 12 (feature-toggle-system-keystone) live-stack acceptance gate. Proves the
# whole phase end-to-end against the REAL compose stack — FLAG-01/02/03/04 — AND
# re-runs the three v1-invariant regressions (INFRA-05, BACK-05, BACK-01) so the
# new feature module + routes are shown NOT to have regressed them. Every negative
# assertion is EXPLICIT (anti-false-green, lib.sh T-03 contract): a flag-OFF route
# must produce a 404 — never a silent pass, a 401/403 by accident, or a 200.
#
#   FLAG-01 (the keystone, the most important): with `saml` seeded OFF, a request
#     to the gated probe `/api/features/_probe` carrying a VALID session cookie AND
#     a matching X-CSRF-Token (a POST — past BOTH the auth and csrf guards) returns
#     404, NOT 401/403/200. That proves SERVER-SIDE enforcement past both guards —
#     a flag-OFF feature is unreachable even by a fully-authenticated operator.
#     Then PUT `saml`=true and assert the probe GET now returns 200 (flag-ON
#     serves). `saml` is restored to false at the end (the seeded default).
#
#   FLAG-02: GET /api/console/features (authenticated) returns the six seeded keys,
#     each with `enabled` + `label`; `observability` carries `requires_runtime:true`.
#
#   FLAG-04: PUT /api/console/features/{key} with a valid session+CSRF flips a flag
#     and a re-GET reflects it; PUT to an UNKNOWN key returns 404; PUT
#     observability=true returns 2xx and NEVER 502 (requires_runtime is store-only
#     this phase — Phase 16 owns the health probe). The toggle is recorded in the
#     audit log with the authenticated admin as the actor (actor-from-session,
#     never client input).
#
#   FLAG-03: the grep gate `! grep -rn "GatedFeature\|gated-feature" frontend/`
#     passes — no import of the retired license-gate primitive remains.
#
#   v1-INVARIANT REGRESSION (phase success criteria — deep_work_rules):
#     INFRA-05 — no Ory Admin port is host-published (admin ports refused from host,
#                reachable only internally from the trusted backend container).
#     BACK-05  — restarts route ONLY through the container-name-scoped socket-proxy
#                allowlist; the backend holds NO Docker socket.
#     BACK-01  — invoke scripts/verify/bundle-egress.sh: no Ory URL/SDK/new egress
#                host (and no CDN) in the built frontend bundle.
#
# Run against a bring-up (Git Bash on Windows: prefix compose with MSYS_NO_PATHCONV=1
# so leading-slash URL paths are not mangled). This script does the FULL lifecycle
# itself (build -> up -d --wait -> drive -> down -v) unless told to reuse a stack:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase12-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions. The stack must have been brought up with
#                    CONSOLE_INSECURE_COOKIES=true (so curl can replay the session
#                    cookie over the plain-HTTP compose edge).
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500)
#
# Phase 12 needs NO echo sidecar and NO acceptance profile (the keystone probe is a
# self-contained 200 behind the gate; it touches no Ory service and no outbound
# target). The standard `docker compose up` graph is sufficient.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# --- Exact container names + admin ports for the v1-invariant re-run ---------
KRATOS_CONTAINER="ory-kratos"
HYDRA_CONTAINER="ory-hydra"
KETO_CONTAINER="ory-keto"
OATHKEEPER_CONTAINER="ory-oathkeeper"
# Admin ports that MUST be refused from the host (INFRA-05): 4434 kratos-admin,
# 4445 hydra-admin, 4467 keto-write, 4469 keto-metadata, 4456 oathkeeper-api.
ADMIN_PORTS="4434 4445 4467 4469 4456"

# Detect the Docker engine API version dynamically (the broker regex is
# version-tolerant but the client must send the engine's actual ApiVersion).
detect_api_version() {
  local ver=""
  ver="$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="$(docker version --format '{{.Client.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="1.43"
  printf 'v%s' "$ver"
}
API_VER="$(detect_api_version)"

echo "=== Phase 12 acceptance: Feature-Toggle System (keystone) ==="
echo "    (FLAG-01/02/03/04 + v1-invariant regression INFRA-05 / BACK-05 / BACK-01)"
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Docker API version: ${API_VER}"

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
# CRITERION FLAG-03 FIRST — the cheapest hard gate. No GatedFeature/gated-feature
# import may remain anywhere in the frontend source (the retired license-gate
# primitive). A static-source grep that holds regardless of the live stack.
# =============================================================================
echo
echo "--- [FLAG-03] no GatedFeature/gated-feature import remains in frontend/ ---"
FLAG03_HITS="$(grep -rn "GatedFeature\|gated-feature" "${REPO_ROOT}/frontend" \
  --include=*.tsx --include=*.ts 2>/dev/null || true)"
if [ -z "$FLAG03_HITS" ]; then
  _pass "[FLAG-03] grep gate clean: no GatedFeature/gated-feature reference in frontend/ (retired)"
else
  _fail "[FLAG-03] GatedFeature/gated-feature STILL referenced in frontend/ (must be retired):"
  printf '%s\n' "$FLAG03_HITS"
fi

# =============================================================================
# CRITERION BACK-01 — bundle egress. Build the frontend and grep the built
# output for any Ory host/port/SDK/CDN leak. Holds regardless of the live stack.
# =============================================================================
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [BACK-01] bundle-egress: no Ory host/port/SDK + no CDN in the built bundle ---"
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "[BACK-01] bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free"
  else
    _fail "[BACK-01] bundle-egress: FORBIDDEN Ory host/port/SDK or CDN reference in the built bundle"
  fi
else
  echo
  echo "--- [BACK-01] bundle-egress SKIPPED (SKIP_EGRESS=1) — live-only run ---"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) for the live assertions. Insecure
# cookies for THIS ephemeral run so curl can replay the session cookie over the
# plain-HTTP compose edge (a `__Host-`/`Secure` cookie is dropped over http).
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true

# WR-01: the FLAG-01 keystone probe (`/api/features/_probe`) is now compiled OUT
# of the production backend image — it ships ONLY when the backend is built with
# the `test-probe` cargo feature. Export TEST_PROBE=1 so the ephemeral acceptance
# image built below DOES expose the probe (the compose `TEST_PROBE` build-arg
# threads it into `cargo build --features test-probe`). Without this the keystone
# assertions below would (correctly) see a 404 for a non-existent route rather
# than the flag-gate 404, so this export is what keeps FLAG-01 anchorable on the
# live stack while a normal `docker compose up` ships no probe.
export TEST_PROBE=1

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- fresh-volume reset (down -v) so /setup runs and mints a one-time token ---"
  # Pitfall (phase1): the backend's `console` DB persists in a volume across runs.
  # If a prior stack left an INITIALIZED console, /setup is closed (404) and no
  # FIRST-RUN SETUP TOKEN is logged — and a freshly-named gate admin can never be
  # created, so /login fails. Always start from a fresh volume so /setup mints the
  # token and creates this run's admin (mirrors phase1-acceptance.sh).
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
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
    summary
    exit $?
  fi
fi

# Preflight: backend healthy + serving.
echo
echo "--- [preflight] backend healthy + serving ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200

# =============================================================================
# Authenticate a console session (complete /setup + login), mirroring phase11.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase12-admin@example.com"
ADMIN_PW_TEST="phase12-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase12 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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

# Run psql inside the postgres container against the `console` DB; echo the single
# trimmed scalar. Used for the per-session CSRF token read and the actor id lookup.
_psql() {
  $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc "$1" 2>/dev/null | tr -d '\r'
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
  _fail "no authenticated session/CSRF — skipping the live Phase-12 criteria"
  summary
  exit $?
fi

# --- The Phase-12 endpoint surface + HTTP helpers ----------------------------
FEATURES_URL="${BACKEND_BASE_URL}/api/console/features"
PROBE_URL="${BACKEND_BASE_URL}/api/features/_probe"
AUDIT_URL="${BACKEND_BASE_URL}/api/console/audit"

# GET with the session cookie; echoes "<body>\n<code>".
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
# A mutating verb WITH the session cookie + matching CSRF token.
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 60 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
# A mutating verb WITH the session cookie but NO CSRF token (negative).
_auth_mut_nocsrf() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 30 -X "$method" -H "$COOKIE_HEADER")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
# Split the "<body>\n<code>" envelope. Accept the value as $1 OR via stdin (a
# pipe), so both `_code_of "$resp"` and `... | _code_of` work under `set -u`.
_code_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | tail -n1; }
_body_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | sed '$d'; }

echo
echo "============================================================"
echo " FLAG-01 — the KEYSTONE: a flag-OFF route 404s past a VALID"
echo "           session + matching CSRF (server-side enforcement)"
echo "============================================================"

# `saml` is seeded OFF. The probe sits INSIDE the protected subtree (after the
# audit/auth/csrf hoops) behind FeatureFlagHoop::new("saml"). A request that has
# ALREADY passed auth_guard (valid session) and csrf_guard (matching CSRF) must
# STILL 404 — that ordering IS the FLAG-01 guarantee. We use POST so the request
# is past BOTH guards (a csrf-guarded state change), not merely a csrf-exempt GET.
echo
echo "--- [FLAG-01] POST /api/features/_probe with VALID session + matching CSRF, saml OFF -> 404 ---"
# First confirm saml is OFF (the seeded default) before the keystone assertion.
features_resp="$(_auth_get "$FEATURES_URL")"
features_body="$(_body_of "$features_resp")"
SAML_ENABLED="$(printf '%s' "$features_body" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
  const f = d && d.features && d.features.saml;
  process.stdout.write(f ? String(!!f.enabled) : "missing");' 2>/dev/null)"
if [ "$SAML_ENABLED" = "true" ]; then
  # Defensive: a prior interrupted run may have left saml ON. Restore OFF first.
  echo "    (saml was ON from a prior run; restoring OFF before the keystone assertion)"
  _auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":false}' >/dev/null
fi

# THE KEYSTONE assertion (anti-false-green): an explicit 404, NOT 401/403/200.
keystone_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -H 'Content-Type: application/json' --data '{}' "$PROBE_URL" 2>/dev/null)"
case "$keystone_code" in
  404) _pass "[FLAG-01] flag-OFF probe POST (valid session + matching CSRF) -> 404 — server-side gate beats BOTH guards (the keystone)";;
  401) _fail "[FLAG-01] probe -> 401 (auth guard fired — the session/cookie was not accepted; the keystone proof is INVALID, not a flag gate)";;
  403) _fail "[FLAG-01] probe -> 403 (csrf guard fired — the CSRF token was not accepted; the keystone proof is INVALID, not a flag gate)";;
  200) _fail "[FLAG-01] probe -> 200 with saml OFF — THE GATE LEAKED (a disabled feature served past both guards: the keystone hole is OPEN)";;
  *)   _fail "[FLAG-01] probe -> '$keystone_code' (want an explicit 404 with saml OFF)";;
esac

# Now flip saml ON and assert the SAME probe (GET, csrf-exempt) serves 200.
echo
echo "--- [FLAG-01] PUT saml=true, then GET /api/features/_probe -> 200 (flag-ON serves) ---"
on_resp="$(_auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":true}')"
on_code="$(_code_of "$on_resp")"
if [ "$on_code" = "200" ] || [ "$on_code" = "201" ]; then
  _pass "[FLAG-01] PUT /api/console/features/saml {enabled:true} -> $on_code (flag flipped ON)"
else
  _fail "[FLAG-01] PUT saml=true -> '$on_code' (want 2xx; body: $(_body_of "$on_resp"))"
fi
probe_on_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -H "$COOKIE_HEADER" "$PROBE_URL" 2>/dev/null)"
if [ "$probe_on_code" = "200" ]; then
  _pass "[FLAG-01] GET /api/features/_probe with saml ON -> 200 (the SAME gated route now serves — ON/OFF pair proven)"
else
  _fail "[FLAG-01] GET probe with saml ON -> '$probe_on_code' (want 200 — flag-ON must serve)"
fi

# Restore saml to its seeded default (OFF) so re-runs and downstream phases see a
# clean baseline. (Done before the FLAG-02 read so the seeded-set check is clean.)
echo
echo "--- [FLAG-01] restore saml=false (the seeded default) ---"
restore_resp="$(_auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":false}')"
restore_code="$(_code_of "$restore_resp")"
if [ "$restore_code" = "200" ] || [ "$restore_code" = "201" ]; then
  _pass "[FLAG-01] PUT /api/console/features/saml {enabled:false} -> $restore_code (restored to seeded default)"
else
  _fail "[FLAG-01] could not restore saml=false -> '$restore_code' (re-runs may start dirty)"
fi
# Confirm the gate is closed again: the probe POST 404s once more.
reclose_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
  -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -H 'Content-Type: application/json' --data '{}' "$PROBE_URL" 2>/dev/null)"
if [ "$reclose_code" = "404" ]; then
  _pass "[FLAG-01] after restoring saml OFF the probe POST 404s again (the gate re-closed — toggle is live, not cached-open)"
else
  _fail "[FLAG-01] after restoring saml OFF the probe POST -> '$reclose_code' (want 404 — the toggle must re-close the gate)"
fi

echo
echo "============================================================"
echo " FLAG-02 — GET /api/console/features returns the seeded set"
echo "============================================================"

echo
echo "--- [FLAG-02] GET /api/console/features (authenticated) returns 200 + the six seeded keys ---"
REQ_HEADER="$COOKIE_HEADER" assert_json_ok GET "$FEATURES_URL" "has:features"
features_resp="$(_auth_get "$FEATURES_URL")"
features_body="$(_body_of "$features_resp")"
if printf '%s' "$features_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const f = d && d.features;
    if (!f || typeof f !== "object") process.exit(1);
    const want = ["saml","organizations","account_experience","observability","event_streams","opl_live_validation"];
    // Every seeded key must be present, each carrying enabled (bool) + a non-empty label.
    for (const k of want) {
      const e = f[k];
      if (!e) process.exit(1);
      if (typeof e.enabled !== "boolean") process.exit(1);
      if (typeof e.label !== "string" || e.label.length === 0) process.exit(1);
    }
    process.exit(0);
  ' 2>/dev/null; then
  _pass "[FLAG-02] all six seeded keys present, each with enabled (bool) + a non-empty label"
else
  _fail "[FLAG-02] GET /api/console/features did not return the full seeded set with enabled+label (body: $(printf '%s' "$features_body" | head -c 600))"
fi
# observability must carry requires_runtime:true (the only runtime-dependent flag).
if printf '%s' "$features_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const o = d && d.features && d.features.observability;
    process.exit(o && o.requires_runtime === true ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[FLAG-02] observability carries requires_runtime:true (the runtime-dependent flag marker)"
else
  _fail "[FLAG-02] observability did NOT carry requires_runtime:true (body: $(printf '%s' "$features_body" | head -c 600))"
fi

echo
echo "============================================================"
echo " FLAG-04 — PUT toggles + audited; unknown -> 404; requires_runtime never 502"
echo "============================================================"

# Toggle a non-keystone flag both ways and confirm a re-GET reflects it. We use
# `organizations` (seeded OFF) so we never disturb saml's restored baseline.
echo
echo "--- [FLAG-04] PUT /api/console/features/organizations flips the flag; re-GET reflects it ---"
put_on="$(_auth_mut PUT "${FEATURES_URL}/organizations" '{"enabled":true}')"
put_on_code="$(_code_of "$put_on")"
if [ "$put_on_code" = "200" ] || [ "$put_on_code" = "201" ]; then
  _pass "[FLAG-04] PUT organizations {enabled:true} -> $put_on_code"
else
  _fail "[FLAG-04] PUT organizations=true -> '$put_on_code' (want 2xx; body: $(_body_of "$put_on"))"
fi
reget_body="$(_body_of "$(_auth_get "$FEATURES_URL")")"
if printf '%s' "$reget_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const o = d && d.features && d.features.organizations;
    process.exit(o && o.enabled === true ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[FLAG-04] a re-GET reflects organizations.enabled=true (the toggle persisted + the cache refreshed)"
else
  _fail "[FLAG-04] the re-GET did NOT reflect organizations.enabled=true (body: $(printf '%s' "$reget_body" | head -c 400))"
fi
# Restore organizations OFF (the seeded default) and confirm the re-GET reflects it.
put_off="$(_auth_mut PUT "${FEATURES_URL}/organizations" '{"enabled":false}')"
put_off_code="$(_code_of "$put_off")"
reget2_body="$(_body_of "$(_auth_get "$FEATURES_URL")")"
if { [ "$put_off_code" = "200" ] || [ "$put_off_code" = "201" ]; } \
   && printf '%s' "$reget2_body" | node -e '
      let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
      const o = d && d.features && d.features.organizations;
      process.exit(o && o.enabled === false ? 0 : 1);' 2>/dev/null; then
  _pass "[FLAG-04] PUT organizations {enabled:false} -> $put_off_code and a re-GET reflects OFF (toggle both ways, restored to seeded default)"
else
  _fail "[FLAG-04] could not restore organizations OFF (code='$put_off_code'; body: $(printf '%s' "$reget2_body" | head -c 400))"
fi

# Unknown key -> 404 (never an INSERT from caller input, T-12-06).
echo
echo "--- [FLAG-04] PUT to an UNKNOWN feature key -> 404 (no arbitrary rows from input) ---"
unknown_code="$(_code_of "$(_auth_mut PUT "${FEATURES_URL}/this_is_not_a_real_flag" '{"enabled":true}')")"
if [ "$unknown_code" = "404" ]; then
  _pass "[FLAG-04] PUT /api/console/features/this_is_not_a_real_flag -> 404 (unknown key rejected, never created)"
else
  _fail "[FLAG-04] PUT unknown key -> '$unknown_code' (want an explicit 404)"
fi

# requires_runtime ON must NEVER 502 this phase (store-only; Phase 16 owns the probe).
echo
echo "--- [FLAG-04] PUT observability=true returns 2xx and NEVER 502 (requires_runtime store-only) ---"
obs_on="$(_auth_mut PUT "${FEATURES_URL}/observability" '{"enabled":true}')"
obs_on_code="$(_code_of "$obs_on")"
case "$obs_on_code" in
  200|201) _pass "[FLAG-04] PUT observability {enabled:true} -> $obs_on_code (store-only; no runtime probe, no 502)";;
  502)     _fail "[FLAG-04] PUT observability=true -> 502 — a requires_runtime flag MUST NOT 502 this phase (store-only; Phase 16 owns the probe)";;
  *)       _fail "[FLAG-04] PUT observability=true -> '$obs_on_code' (want 2xx, never 502; body: $(_body_of "$obs_on"))";;
esac
# Restore observability OFF (the seeded default).
obs_off_code="$(_code_of "$(_auth_mut PUT "${FEATURES_URL}/observability" '{"enabled":false}')")"
if [ "$obs_off_code" = "200" ] || [ "$obs_off_code" = "201" ]; then
  _pass "[FLAG-04] restored observability=false ($obs_off_code) to the seeded default"
else
  _fail "[FLAG-04] could not restore observability=false -> '$obs_off_code'"
fi

# The toggle(s) above are state changes → an audit row with our actor + success.
echo
echo "--- [FLAG-04] the toggle is recorded in the audit log with the authenticated admin actor ---"
audit_body="$(_body_of "$(_auth_get "${AUDIT_URL}?limit=50")")"
if printf '%s' "$audit_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const arr = Array.isArray(d) ? d : (d.rows||d.items||[]);
    if (!arr.length) process.exit(1);
    // At least one PUT to /api/console/features/<key> with a success outcome.
    const hit = arr.find(r => {
      const s = JSON.stringify(r).toLowerCase();
      return s.includes("/api/console/features/") && s.includes("put");
    });
    if (!hit) process.exit(1);
    process.exit(JSON.stringify(hit).toLowerCase().includes("success") ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[FLAG-04] the audit log records a PUT /api/console/features/{key} action with outcome=success"
else
  _fail "[FLAG-04] no matching audit row for the feature toggle (sample: $(printf '%s' "$audit_body" | head -c 400))"
fi
# The actor must be OUR admin (read from the session, never client input).
ADMIN_ID="$(_psql "SELECT id FROM admins WHERE email = '${ADMIN_EMAIL_TEST}' LIMIT 1")"
if printf '%s' "$audit_body" | grep -qiF "$ADMIN_EMAIL_TEST" \
   || { [ -n "$ADMIN_ID" ] && printf '%s' "$audit_body" | grep -qF "$ADMIN_ID"; }; then
  _pass "[FLAG-04] the audit actor is the authenticated admin (email/admin_id present — read from the session)"
else
  _fail "[FLAG-04] the audit log does not reference the authenticated admin actor"
fi

echo
echo "============================================================"
echo " NEGATIVES — anti-false-green guard proofs on the toggle PUT"
echo "============================================================"

echo
echo "--- [neg] unauthenticated GET /api/console/features -> 401 ---"
unauth_get="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$FEATURES_URL" 2>/dev/null)"
if [ "$unauth_get" = "401" ]; then
  _pass "[neg] unauthenticated GET /api/console/features -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated GET /api/console/features -> '$unauth_get' (want 401)"
fi
echo
echo "--- [neg] authed PUT WITHOUT X-CSRF-Token -> 403 ---"
nocsrf_put="$(_auth_mut_nocsrf PUT "${FEATURES_URL}/organizations" '{"enabled":true}')"
if [ "$nocsrf_put" = "403" ]; then
  _pass "[neg] authed PUT /api/console/features/organizations without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] authed PUT without X-CSRF-Token -> '$nocsrf_put' (want 403)"
fi

echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — INFRA-05 admin-port isolation"
echo "============================================================"

echo
echo "--- [INFRA-05] no Ory Admin port is host-published (refused from host; reachable internally) ---"
for port in $ADMIN_PORTS; do
  assert_port_refused "$port"
done
# Positive: from the trusted backend container the kratos admin API IS up.
assert_internal_reachable backend "http://kratos:4434/health/ready"

echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — BACK-05 restart-broker scope"
echo "============================================================"

echo
echo "--- [BACK-05] restarts route ONLY through the scoped socket-proxy; backend holds NO socket ---"
# Allowed: scoped restart of an Ory container (+ the graceful-stop ?t= query).
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart"
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart?t=5"
# Denied (explicit default-deny): listing, stopping, restarting a non-Ory container.
assert_broker_denied GET  "/${API_VER}/containers/json"
assert_broker_denied POST "/${API_VER}/containers/${KRATOS_CONTAINER}/stop"
assert_broker_denied POST "/${API_VER}/containers/postgres/restart"
# The backend must not hold the docker socket at all.
assert_no_socket_mount backend

echo
summary
exit $?
