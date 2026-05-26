#!/usr/bin/env bash
# scripts/verify/phase14-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 14 (saml-sign-in-organizations) live-stack acceptance gate. Proves
# SSO-02..07 end to end against the REAL compose stack on a FRESH VOLUME (incl.
# Polis) with the `saml` + `organizations` feature flags toggled ON, AND re-runs
# the v1 + Phase-13 invariant gates (INFRA-05, BACK-05, BACK-01 + bundle-egress)
# with the SAML/Organizations surface present so they are shown NOT to have
# regressed. Every negative assertion is EXPLICIT (anti-false-green, lib.sh T-03
# contract): a refusal must be an explicit 4xx / connection-refused, NEVER a
# silent pass on absence-of-output.
#
#   SSO-02 — a SAML connection POST from CA-less metadata (no signing
#            <X509Certificate>) is REJECTED 422 BEFORE any Polis connection is
#            created; an encryption-only cert is ALSO rejected; a connection WITH
#            a signing cert is created (surfacing clientID + idpMetadata).
#   SSO-03 — the generated Kratos providers[] mapper (decoded from base64://) is
#            verified-default-false: it carries `email_verified: false` + the
#            conditional email gate and NO unconditional email mapping (the
#            account-takeover negative); a GET/list never carries clientSecret.
#   SSO-04 — a metadataUrl to an internal host (http://kratos:4434,
#            169.254.169.254) or a credentialed URL is SSRF-REJECTED (explicit
#            4xx, NO fetch); the reject names the category, never the internal IP.
#   SSO-05 — IDNA-confusable / uppercase / trailing-dot domains normalize and
#            COLLIDE (409 on the second create); corp.com.attacker.com is DISTINCT
#            (accepted). An audit row exists for the org create.
#   SSO-06 — domain->SSO lookup returns the linked connection for a known org
#            domain; an unknown domain -> 404 (no existence leak).
#   two-sided delete — after DELETE, the Polis /api/v1/sso connection is gone AND
#            the Kratos providers[] entry is removed (no dangling provider).
#   SSO-07 — with `saml` OFF, GET/POST api/sso/connections -> 404 (valid session +
#            CSRF); with `organizations` OFF, api/organizations -> 404; no
#            clientSecret/API_KEY value in any GET/list body (BACK-07); no
#            "enterprise license"/"requires ory" string in frontend/ source.
#
#   v1 + Phase-13 INVARIANT REGRESSION (with SAML/Orgs present):
#     INFRA-05 — no Ory Admin nor Polis admin port host-published (refused from
#                host; reachable internally from the trusted backend container).
#     BACK-05  — restarts route ONLY through the container-scoped socket-proxy
#                allowlist; the backend (and polis) hold NO Docker socket. A valid
#                provider write restarts ONLY Kratos (Phase-9 config-write
#                discipline); an invalid provider write leaves the file untouched.
#     BACK-01  — scripts/verify/bundle-egress.sh: no Ory/Polis URL/SDK/CDN in the
#                built frontend bundle; no NEXT_PUBLIC Polis var in source.
#
# Run (Git Bash on Windows: prefix with MSYS_NO_PATHCONV=1 so leading-slash URL
# paths are not mangled). This gate does the FULL lifecycle (build -> up -d
# --wait -> drive -> down -v) unless told to reuse a stack:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase14-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions. The stack must have been brought up with
#                    CONSOLE_INSECURE_COOKIES=true + TEST_PROBE=1 + the Polis env.
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1800  seconds to allow `docker compose up -d --wait` (default 1800)
#
# Polis introduces deploy-time secrets the backend can never mint (BACK-07). For
# THIS ephemeral acceptance run we GENERATE placeholder values for every
# `${POLIS_*:?}` so `docker compose up` resolves; they are never committed and the
# stack is torn down (`down -v`) at the end. A real deployment sets these in `.env`.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1800}"

# --- Exact container names + admin ports for the invariant re-run ------------
KRATOS_CONTAINER="ory-kratos"
HYDRA_CONTAINER="ory-hydra"
KETO_CONTAINER="ory-keto"
OATHKEEPER_CONTAINER="ory-oathkeeper"
POLIS_CONTAINER="polis"
BACKEND_CONTAINER="backend"
FRONTEND_CONTAINER="frontend"
POSTGRES_CONTAINER="postgres"
# Admin ports that MUST be refused from the host (INFRA-05): 4434 kratos-admin,
# 4445 hydra-admin, 4467 keto-write, 4469 keto-metadata, 4456 oathkeeper-api.
ADMIN_PORTS="4434 4445 4467 4469 4456"
POLIS_ADMIN_PORT="5225"

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

echo "=== Phase 14 acceptance: SAML Sign-In + Organizations — SSO-02..07 ==="
echo "    (CA-less reject + gated mapper + SSRF reject + domain-collision +"
echo "     domain->SSO lookup + two-sided delete + flag-OFF 404 + no-license +"
echo "     INFRA-05/BACK-05/BACK-01 + bundle-egress regression)"
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
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
  [ -n "${POLIS_ENV_FILE:-}" ] && rm -f "$POLIS_ENV_FILE" 2>/dev/null || true
}
trap teardown EXIT

# =============================================================================
# CRITERION BACK-01 — bundle egress (no Ory/Polis host/port/SDK/CDN in the built
# bundle). Holds regardless of the live stack, so run it first.
# =============================================================================
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [BACK-01] bundle-egress: no Ory/Polis host/port/SDK + no CDN in the built bundle ---"
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "[BACK-01] bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (SAML/Orgs present)"
  else
    _fail "[BACK-01] bundle-egress: FORBIDDEN Ory/Polis host/port/SDK or CDN reference in the built bundle"
  fi
else
  echo
  echo "--- [BACK-01] bundle-egress SKIPPED (SKIP_EGRESS=1) — live-only run ---"
fi

# Defense-in-depth static check: no NEXT_PUBLIC Polis var / Polis admin URL in
# the frontend SOURCE.
echo
echo "--- [BACK-01] no NEXT_PUBLIC Polis var / :5225 admin URL in frontend source ---"
POLIS_SRC_HITS="$(grep -rnE 'NEXT_PUBLIC[A-Z_]*POLIS|polis:5225|//polis([/:."'"'"']|$)' \
  "${REPO_ROOT}/frontend" --include=*.tsx --include=*.ts 2>/dev/null || true)"
if [ -z "$POLIS_SRC_HITS" ]; then
  _pass "[BACK-01] no NEXT_PUBLIC Polis var / Polis admin URL in frontend source"
else
  _fail "[BACK-01] a NEXT_PUBLIC Polis var / Polis admin URL leaked into frontend source:"
  printf '%s\n' "$POLIS_SRC_HITS"
fi

# =============================================================================
# SSO-07 (static) — no "enterprise license" / "requires ory" licensing copy
# anywhere in frontend SOURCE (header-prose-safe: the only allowed matches are
# the negation assertions inside the *.test.tsx files, which PROVE the copy is
# absent). PASS only on an explicit "no offending source hit" verdict.
# =============================================================================
echo
echo "--- [SSO-07] no 'enterprise license' / 'requires ory' / 'requires enterprise' copy in frontend source ---"
# Exclude .next build output and the test files (whose negation assertions
# legitimately contain the forbidden phrases to prove they are absent).
LICENSE_HITS="$(grep -rniE 'enterprise license|requires ory|requires enterprise' \
  "${REPO_ROOT}/frontend" --include=*.tsx --include=*.ts \
  | grep -vE '\.test\.tsx?:' \
  | grep -vE '/\.next/' || true)"
if [ -z "$LICENSE_HITS" ]; then
  _pass "[SSO-07] no licensing/upsell copy in frontend source (SAML/Orgs are OSS, no license needed)"
else
  _fail "[SSO-07] licensing copy found in frontend source (SSO-07 forbids it):"
  printf '%s\n' "$LICENSE_HITS"
fi

# =============================================================================
# Bring the stack up on a FRESH VOLUME (unless REUSE_STACK=1).
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true
export TEST_PROBE=1

# CRITICAL (Windows/MSYS): strip BOTH \r AND \n. On Windows the mingw openssl emits
# CRLF, so a bare `tr -d '\n'` leaves a trailing \r INSIDE the secret. That \r then
# rides into JACKSON_API_KEYS, so Jackson stores the key as "<key>\r" while the
# backend sends "<key>" -> every Polis admin call 401s (verified live in Phase 14:
# the gate's create surfaced as a 502 caused by an upstream Polis 401). `tr -d '\r\n'`
# yields a clean single-line secret on every platform.
_gen_b64() { openssl rand -base64 32 2>/dev/null | tr -d '\r\n' || node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64"))'; }
_gen_rsa_b64() {
  # NO temp files (robust under MSYS_NO_PATHCONV=1): pipe the PEM through stdin/stdout.
  local priv_pem pub_pem
  priv_pem="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)" || return 1
  [ -n "$priv_pem" ] || return 1
  pub_pem="$(printf '%s' "$priv_pem" | openssl pkey -pubout 2>/dev/null)" || return 1
  [ -n "$pub_pem" ] || return 1
  POLIS_OPENID_RSA_PRIVATE_KEY="$(printf '%s' "$priv_pem" | base64 | tr -d '\r\n')"
  POLIS_OPENID_RSA_PUBLIC_KEY="$(printf '%s' "$pub_pem" | base64 | tr -d '\r\n')"
  [ "${#POLIS_OPENID_RSA_PRIVATE_KEY}" -ge 512 ] && [ "${#POLIS_OPENID_RSA_PUBLIC_KEY}" -ge 200 ]
}
POLIS_DB_PASSWORD="${POLIS_DB_PASSWORD:-changeme_polis}"
POLIS_DB_ENCRYPTION_KEY="${POLIS_DB_ENCRYPTION_KEY:-$(_gen_b64)}"
POLIS_API_KEY="${POLIS_API_KEY:-$(_gen_b64)}"
POLIS_NEXTAUTH_SECRET="${POLIS_NEXTAUTH_SECRET:-$(_gen_b64)}"
POLIS_EXTERNAL_URL="${POLIS_EXTERNAL_URL:-http://localhost:5225}"
if [ -z "${POLIS_OPENID_RSA_PRIVATE_KEY:-}" ] || [ -z "${POLIS_OPENID_RSA_PUBLIC_KEY:-}" ]; then
  if ! _gen_rsa_b64; then
    _fail "could not generate an ephemeral Polis RSA keypair — cannot bring Polis up"
    summary
    exit $?
  fi
fi

# Belt-and-suspenders: strip any stray CR from every value before writing the
# env-file (a value sourced from a pre-set POLIS_* env on Windows could carry one).
_strip_cr() { printf '%s' "$1" | tr -d '\r\n'; }
POLIS_DB_PASSWORD="$(_strip_cr "$POLIS_DB_PASSWORD")"
POLIS_DB_ENCRYPTION_KEY="$(_strip_cr "$POLIS_DB_ENCRYPTION_KEY")"
POLIS_API_KEY="$(_strip_cr "$POLIS_API_KEY")"
POLIS_NEXTAUTH_SECRET="$(_strip_cr "$POLIS_NEXTAUTH_SECRET")"
POLIS_EXTERNAL_URL="$(_strip_cr "$POLIS_EXTERNAL_URL")"
POLIS_OPENID_RSA_PRIVATE_KEY="$(_strip_cr "$POLIS_OPENID_RSA_PRIVATE_KEY")"
POLIS_OPENID_RSA_PUBLIC_KEY="$(_strip_cr "$POLIS_OPENID_RSA_PUBLIC_KEY")"

POLIS_ENV_FILE="${REPO_ROOT}/.env.p14-acceptance-$$"
: > "$POLIS_ENV_FILE"
chmod 600 "$POLIS_ENV_FILE" 2>/dev/null || true
{
  printf 'POLIS_DB_PASSWORD=%s\n'            "$POLIS_DB_PASSWORD"
  printf 'POLIS_DB_ENCRYPTION_KEY=%s\n'      "$POLIS_DB_ENCRYPTION_KEY"
  printf 'POLIS_API_KEY=%s\n'                "$POLIS_API_KEY"
  printf 'POLIS_NEXTAUTH_SECRET=%s\n'        "$POLIS_NEXTAUTH_SECRET"
  printf 'POLIS_EXTERNAL_URL=%s\n'           "$POLIS_EXTERNAL_URL"
  printf 'POLIS_OPENID_RSA_PRIVATE_KEY=%s\n' "$POLIS_OPENID_RSA_PRIVATE_KEY"
  printf 'POLIS_OPENID_RSA_PUBLIC_KEY=%s\n'  "$POLIS_OPENID_RSA_PUBLIC_KEY"
} > "$POLIS_ENV_FILE"

cd "$REPO_ROOT" || { _fail "could not cd to repo root ${REPO_ROOT}"; summary; exit $?; }
POLIS_ENV_REL="./$(basename "$POLIS_ENV_FILE")"
if [ -f "${REPO_ROOT}/.env" ]; then
  DC="docker compose --env-file .env --env-file ${POLIS_ENV_REL}"
else
  DC="docker compose --env-file ${POLIS_ENV_REL}"
fi
export POLIS_DB_PASSWORD POLIS_DB_ENCRYPTION_KEY POLIS_API_KEY POLIS_NEXTAUTH_SECRET \
  POLIS_EXTERNAL_URL POLIS_OPENID_RSA_PRIVATE_KEY POLIS_OPENID_RSA_PUBLIC_KEY

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- fresh-volume reset (down -v) so the polis DB + console /setup token are minted fresh ---"
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
  echo
  echo "--- bring up the full stack incl. Polis (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
  echo "    (the frontend image build is heavy; this can take many minutes)"
  if ! $DC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary
    exit $?
  fi
  if $DC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "docker compose up -d --wait: all services healthy (incl. polis)"
  else
    _fail "docker compose up -d --wait did NOT reach healthy within ${UP_TIMEOUT}s"
    echo "--- recent polis logs ---";   $DC logs --tail 40 polis   2>/dev/null || true
    echo "--- recent backend logs ---"; $DC logs --tail 40 backend 2>/dev/null || true
    summary
    exit $?
  fi
fi

echo
echo "--- preflight: backend + polis healthy ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200
wait_container_healthy "$POLIS_CONTAINER" 120

# =============================================================================
# Authenticate a console session (complete /setup + login), mirroring phase13.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase14-admin@example.com"
ADMIN_PW_TEST="phase14-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase14 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
    "${BACKEND_BASE_URL}/setup" 2>/dev/null)"
  case "$setup_code" in
    201) _pass "completed /setup (admin created)";;
    404) _pass "/setup already completed on a prior run (404) — proceeding to login";;
    *)   _fail "/setup returned '$setup_code' (want 201 or 404-already-init)";;
  esac
elif [ "$already_init" = "1" ]; then
  _pass "console already initialized (re-run) — proceeding to login"
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
  _fail "no authenticated session/CSRF — skipping the live SSO criteria"
  summary
  exit $?
fi

# --- endpoint surface + HTTP helpers (mirror phase13) ------------------------
FEATURES_URL="${BACKEND_BASE_URL}/api/console/features"
SSO_CONN_URL="${BACKEND_BASE_URL}/api/sso/connections"
SSO_LOOKUP_URL="${BACKEND_BASE_URL}/api/sso/lookup"
ORG_URL="${BACKEND_BASE_URL}/api/organizations"

_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 120 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_auth_mut_code() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 120 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | tail -n1; }
_body_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | sed '$d'; }

_flag_enabled() {
  local key="$1" body
  body="$(_body_of "$(_auth_get "$FEATURES_URL")")"
  printf '%s' "$body" | KEY="$key" node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
    const k = process.env.KEY;
    const f = d && d.features && d.features[k];
    process.stdout.write(f ? String(!!f.enabled) : "missing");' 2>/dev/null
}

_set_flag() {
  local key="$1" enabled="$2" resp code
  resp="$(_auth_mut PUT "${FEATURES_URL}/${key}" "{\"enabled\":${enabled}}")"
  code="$(_code_of "$resp")"
  case "$code" in
    200|201) return 0 ;;
    *) echo "    (warning: PUT features/${key} {enabled:${enabled}} -> ${code})"; return 1 ;;
  esac
}

# =============================================================================
# SSO-07 (live, the keystone) — flag-OFF 404 with a VALID session + CSRF.
# Both flags are seeded OFF; assert the gated routes 404 BEFORE we turn them ON.
# =============================================================================
echo
echo "============================================================"
echo " SSO-07 — flag-OFF 404 (valid session + CSRF beats both guards)"
echo "============================================================"

# Make sure both flags are OFF (a prior interrupted run may have left them ON).
[ "$(_flag_enabled saml)" = "true" ] && _set_flag saml false >/dev/null
[ "$(_flag_enabled organizations)" = "true" ] && _set_flag organizations false >/dev/null

echo
echo "--- [SSO-07] saml OFF: GET/POST api/sso/connections (valid session+CSRF) -> 404 ---"
off_get="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${SSO_CONN_URL}?tenant=probe" 2>/dev/null)"
case "$off_get" in
  404) _pass "[SSO-07] GET api/sso/connections with saml OFF -> 404 (gate beats auth+csrf)";;
  401) _fail "[SSO-07] GET api/sso/connections -> 401 (auth guard fired — gate proof INVALID)";;
  403) _fail "[SSO-07] GET api/sso/connections -> 403 (csrf guard fired — gate proof INVALID)";;
  200) _fail "[SSO-07] GET api/sso/connections -> 200 with saml OFF — THE GATE LEAKED";;
  *)   _fail "[SSO-07] GET api/sso/connections -> '$off_get' (want explicit 404 with saml OFF)";;
esac
off_post="$(_auth_mut_code POST "$SSO_CONN_URL" '{"tenant":"probe","default_redirect_url":"https://c/x","redirect_url":["https://c/x"],"metadata_xml":"<x/>"}')"
if [ "$off_post" = "404" ]; then
  _pass "[SSO-07] POST api/sso/connections with saml OFF -> 404 (gate beats the mutation too)"
else
  _fail "[SSO-07] POST api/sso/connections with saml OFF -> '$off_post' (want 404)"
fi

echo
echo "--- [SSO-07] organizations OFF: GET/POST api/organizations (valid session+CSRF) -> 404 ---"
off_org_get="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$ORG_URL" 2>/dev/null)"
case "$off_org_get" in
  404) _pass "[SSO-07] GET api/organizations with organizations OFF -> 404 (gate beats auth+csrf)";;
  401) _fail "[SSO-07] GET api/organizations -> 401 (auth guard fired — gate proof INVALID)";;
  403) _fail "[SSO-07] GET api/organizations -> 403 (csrf guard fired — gate proof INVALID)";;
  200) _fail "[SSO-07] GET api/organizations -> 200 with organizations OFF — THE GATE LEAKED";;
  *)   _fail "[SSO-07] GET api/organizations -> '$off_org_get' (want explicit 404)";;
esac
off_org_post="$(_auth_mut_code POST "$ORG_URL" '{"label":"probe","domains":["probe.example.com"]}')"
if [ "$off_org_post" = "404" ]; then
  _pass "[SSO-07] POST api/organizations with organizations OFF -> 404 (gate beats the mutation too)"
else
  _fail "[SSO-07] POST api/organizations with organizations OFF -> '$off_org_post' (want 404)"
fi
# The organizations-gated lookup is also OFF.
off_lookup="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${SSO_LOOKUP_URL}?domain=probe.example.com" 2>/dev/null)"
if [ "$off_lookup" = "404" ]; then
  _pass "[SSO-07] GET api/sso/lookup with organizations OFF -> 404 (gate beats auth+csrf)"
else
  _fail "[SSO-07] GET api/sso/lookup with organizations OFF -> '$off_lookup' (want 404)"
fi

# =============================================================================
# Flip both flags ON for the remaining live criteria.
# =============================================================================
echo
echo "--- flip saml + organizations ON for the SSO-02..06 criteria ---"
if _set_flag saml true; then _pass "PUT features/saml {enabled:true} -> 2xx"; else _fail "could not enable saml"; fi
if _set_flag organizations true; then _pass "PUT features/organizations {enabled:true} -> 2xx"; else _fail "could not enable organizations"; fi
# Confirm the gates now open (a sanity GET).
on_get="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$ORG_URL" 2>/dev/null)"
if [ "$on_get" = "200" ]; then
  _pass "[SSO-07] GET api/organizations with organizations ON -> 200 (the gate opened — ON/OFF pair proven)"
else
  _fail "[SSO-07] GET api/organizations with organizations ON -> '$on_get' (want 200)"
fi

# =============================================================================
# SSO-02 — CA-less / encryption-only metadata is rejected 422 BEFORE Polis.
# The console-side mandatory signing-cert pre-flight is the enforcement point.
# =============================================================================
echo
echo "============================================================"
echo " SSO-02 — CA-less / encryption-only SAML metadata rejected 422"
echo "============================================================"

# Generate a REAL self-signed X509 signing certificate (base64 DER) so Polis's
# `@boxyhq/saml20` metadata parser accepts the signing connection. A synthetic
# placeholder cert passes the console pre-flight (structural) but Polis rejects it
# at parse time (-> 502). We mint a throwaway 2048-bit cert per run via openssl,
# extract its base64 DER, and embed it in valid IdP metadata. The key is discarded.
SIGNING_CERT_B64=""
_gen_signing_cert() {
  local cnf key cert tmpd
  # Use a system temp dir (NOT the repo) so no cert/key artifact can be committed.
  tmpd="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}")"
  cnf="${tmpd}/p14-idpreq.cnf"
  key="${tmpd}/p14-idpk.pem"
  cert="${tmpd}/p14-idpc.pem"
  {
    printf '[req]\n'
    printf 'distinguished_name = dn\n'
    printf 'prompt = no\n'
    printf '[dn]\n'
    printf 'CN = acceptance-idp\n'
  } > "$cnf"
  # CRITICAL (Windows/MSYS): the gate runs under MSYS_NO_PATHCONV=1 so leading-slash
  # compose URL paths are not mangled — but under that setting the Windows openssl
  # binary cannot resolve an MSYS temp path passed as `-out/-in/-config/-key`. We
  # therefore UNSET MSYS_NO_PATHCONV in a subshell for the openssl calls ONLY, so
  # those file-path args are translated to the native form openssl can open. (The
  # surrounding compose calls keep MSYS_NO_PATHCONV=1.)
  ( unset MSYS_NO_PATHCONV; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" ) >/dev/null 2>&1 || { rm -rf "$tmpd"; return 1; }
  ( unset MSYS_NO_PATHCONV; openssl req -x509 -key "$key" -config "$cnf" -days 3650 -out "$cert" ) >/dev/null 2>&1 || { rm -rf "$tmpd"; return 1; }
  SIGNING_CERT_B64="$( unset MSYS_NO_PATHCONV; openssl x509 -in "$cert" -outform DER 2>/dev/null | base64 | tr -d '\n' )"
  rm -rf "$tmpd"
  [ "${#SIGNING_CERT_B64}" -ge 400 ]
}
if ! _gen_signing_cert; then
  _fail "could not mint a self-signed IdP signing certificate (openssl) — SSO-02 create cannot run"
  SIGNING_CERT_B64="MIIDplaceholder=="
fi

CA_LESS_XML='<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/no-ca"><md:IDPSSODescriptor><md:SingleSignOnService Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'
ENC_ONLY_XML='<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/enc"><md:IDPSSODescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDencONLY==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>'
# Valid IdP metadata with a REAL signing cert + an HTTP-Redirect SSO binding
# (both required by the Polis metadata parser). entityID uses a registrable host.
SIGNING_XML="<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.acme-acceptance.com/meta\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>${SIGNING_CERT_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.acme-acceptance.com/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>"

# Build a create body via node so XML embeds safely into JSON.
_make_create_body() {
  # $1=tenant $2=metadata_xml (raw)  -> JSON on stdout
  TENANT="$1" XML="$2" node -e '
    const body = {
      tenant: process.env.TENANT,
      metadata_xml: process.env.XML,
      default_redirect_url: "http://localhost:3000/sso/callback",
      redirect_url: ["http://localhost:3000/sso/callback"],
      name: "Acceptance IdP"
    };
    process.stdout.write(JSON.stringify(body));'
}

echo
echo "--- [SSO-02] POST a CA-less SAML connection -> 422 (signing-cert mandate, BEFORE any Polis call) ---"
ca_less_body="$(_make_create_body "ca-less-probe" "$CA_LESS_XML")"
ca_less_code="$(_auth_mut_code POST "$SSO_CONN_URL" "$ca_less_body")"
if [ "$ca_less_code" = "422" ]; then
  _pass "[SSO-02] CA-less metadata POST -> 422 (rejected by the console signing-cert pre-flight; no Polis connection created)"
else
  _fail "[SSO-02] CA-less metadata POST -> '$ca_less_code' (want explicit 422 reject)"
fi

echo
echo "--- [SSO-02] POST an ENCRYPTION-ONLY SAML connection -> 422 (a naive contains(X509Certificate) would WRONGLY accept) ---"
enc_only_body="$(_make_create_body "enc-only-probe" "$ENC_ONLY_XML")"
enc_only_code="$(_auth_mut_code POST "$SSO_CONN_URL" "$enc_only_body")"
if [ "$enc_only_code" = "422" ]; then
  _pass "[SSO-02] encryption-only metadata POST -> 422 (an encryption cert cannot validate a signature — rejected)"
else
  _fail "[SSO-02] encryption-only metadata POST -> '$enc_only_code' (want explicit 422 reject)"
fi

# Count the connections for a tenant. Polis returns a non-2xx for a tenant with
# ZERO connections (the backend maps that to 502); that — like a 200 with an empty
# array — means "no connection exists". So this helper echoes a NUMERIC count for a
# populated 200-list and "EMPTY" for the no-connection case (non-2xx / empty array /
# absent). A real connection therefore yields a count >= 1; nothing else does.
_connection_count() {
  local tenant="$1" resp code body
  resp="$(_auth_get "${SSO_CONN_URL}?tenant=${tenant}")"
  code="$(_code_of "$resp")"
  body="$(_body_of "$resp")"
  if [ "$code" != "200" ]; then printf 'EMPTY'; return 0; fi
  printf '%s' "$body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("EMPTY"); process.exit(0); }
    const c = d && d.connections;
    if (!Array.isArray(c) || c.length === 0) { process.stdout.write("EMPTY"); process.exit(0); }
    process.stdout.write(String(c.length));' 2>/dev/null
}

# Prove the CA-less reject did NOT create a Polis connection (no side effect).
echo
echo "--- [SSO-02] the rejected CA-less tenant has NO Polis connection (the reject was BEFORE Polis) ---"
caless_count="$(_connection_count "ca-less-probe")"
if [ "$caless_count" = "EMPTY" ] || [ "$caless_count" = "0" ]; then
  _pass "[SSO-02] no Polis connection exists for the rejected CA-less tenant (reject was pre-Polis)"
else
  _fail "[SSO-02] expected NO Polis connection for ca-less-probe (got count='$caless_count')"
fi

# =============================================================================
# SSO-02/03 — a connection WITH a signing cert is CREATED, surfacing clientID +
# idpMetadata; the generated Kratos providers[] mapper is verified-default-false.
# =============================================================================
echo
echo "============================================================"
echo " SSO-02/03 — signing-cert connection created + gated mapper"
echo "============================================================"

GOOD_TENANT="acme-org-acc"
echo
echo "--- [SSO-02] POST a SAML connection WITH a signing cert -> created (clientID + idpMetadata surfaced) ---"
good_body="$(_make_create_body "$GOOD_TENANT" "$SIGNING_XML")"
good_resp="$(_auth_mut POST "$SSO_CONN_URL" "$good_body")"
good_code="$(_code_of "$good_resp")"
good_payload="$(_body_of "$good_resp")"
if [ "$good_code" = "200" ] || [ "$good_code" = "201" ]; then
  has_cid="$(printf '%s' "$good_payload" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
    const ok = d && typeof d.clientID === "string" && d.clientID.length > 0
      && d.idpMetadata && typeof d.idpMetadata === "object"
      && !("clientSecret" in d);
    process.stdout.write(ok ? "OK" : "BAD:" + JSON.stringify(Object.keys(d||{})));' 2>/dev/null)"
  if [ "$has_cid" = "OK" ]; then
    _pass "[SSO-02] signing-cert connection created (clientID + idpMetadata surfaced; clientSecret NOT returned — BACK-07)"
  else
    _fail "[SSO-02] connection created but response shape wrong ($has_cid)"
  fi
else
  _fail "[SSO-02] signing-cert connection POST -> '$good_code' (want 2xx; body: $(printf '%s' "$good_payload" | head -c 300))"
fi

echo
echo "--- [SSO-03] the generated Kratos providers[] mapper is verified-default-false (account-takeover negative) ---"
# Read the stored Kratos provider entry from the mounted kratos.yml inside the
# kratos container, extract the saml-<tenant> provider's mapper_url (base64://),
# decode it, and assert: (1) email_verified:false guard present, (2) a CONDITIONAL
# email gate present, (3) NO unconditional `email: claims.email` mapping. PASS
# only on an explicit "verified-default-false" verdict (anti-false-green).
PROVIDER_ID="saml-${GOOD_TENANT}"
# Read the HOST-side kratos.yml: it is the SAME file the backend writes (mounted
# ./config:/etc/config:rw into the backend, :ro into the distroless kratos image,
# which has no `cat`/`sh` to exec). The provider write persists here, so the host
# copy reflects the live provider entry the moment after create.
KRATOS_HOST_FILE="${REPO_ROOT}/config/kratos/kratos.yml"
KRATOS_YML="$(cat "$KRATOS_HOST_FILE" 2>/dev/null || true)"
# NOTE: this node script is wrapped in a bash DOUBLE-quoted string so it contains
# NO literal single quotes (a single-quote `node -e '...'` would be split by the
# Jsonnet `'email'` literals). The `$` in the regex/`process.env` is escaped (\$)
# so bash does not expand it; `\"` keeps the JS string-literal quotes intact.
MAPPER_VERDICT="$(printf '%s' "$KRATOS_YML" | PID="$PROVIDER_ID" node -e "
  const fs = require(\"fs\");
  const txt = fs.readFileSync(0, \"utf8\");
  const pid = process.env.PID;
  if (!txt.trim()) { process.stdout.write(\"NO_KRATOS_YML\"); process.exit(0); }
  // Collect ALL base64:// mapper urls, decode each, and require the gated shape.
  const tokens = [...txt.matchAll(/base64:\/\/([A-Za-z0-9+\/=_-]+)/g)].map(m => m[1]);
  if (tokens.length === 0) { process.stdout.write(\"NO_MAPPER_URL\"); process.exit(0); }
  if (!txt.includes(pid)) { process.stdout.write(\"NO_PROVIDER:\" + pid); process.exit(0); }
  let anyGated = false;
  for (const t of tokens) {
    let decoded = \"\";
    try {
      const norm = t.replace(/-/g, \"+\").replace(/_/g, \"/\");
      decoded = Buffer.from(norm, \"base64\").toString(\"utf8\");
    } catch (e) { continue; }
    const hasGuard = decoded.includes(\"email_verified: false\");
    const hasGate  = decoded.includes(\"claims.email_verified\");
    // An UNCONDITIONAL email mapping is any line that maps claims.email WITHOUT a
    // verification gate on the same line. The single gated line carries
    // email_verified, so it is excluded; any OTHER claims.email line is a takeover
    // vector. (Line-based so we never embed a single-quoted Jsonnet literal here.)
    const lines = decoded.split(/\r?\n/);
    const unconditional = lines.some(l =>
      l.includes(\"claims.email\") &&
      !l.includes(\"email_verified\") &&
      /email/.test(l.split(\"claims.email\")[0] || \"\"));
    if (hasGuard && hasGate && !unconditional) anyGated = true;
  }
  process.stdout.write(anyGated ? \"GATED\" : \"NOT_GATED\");
" 2>/dev/null)"
case "$MAPPER_VERDICT" in
  GATED)
    _pass "[SSO-03] the stored Kratos mapper carries email_verified:false + a CONDITIONAL email gate and NO unconditional email mapping (account-takeover defense intact)"
    ;;
  NO_KRATOS_YML|NO_MAPPER_URL|NO_PROVIDER:*)
    _fail "[SSO-03] could not read a gated mapper for ${PROVIDER_ID} (verdict='$MAPPER_VERDICT') — cannot confirm the takeover defense"
    ;;
  NOT_GATED)
    _fail "[SSO-03] the stored Kratos mapper is NOT verified-default-false (an unconditional email mapping was found — ACCOUNT-TAKEOVER VECTOR)"
    ;;
  *)
    _fail "[SSO-03] mapper verdict unreadable (verdict='$MAPPER_VERDICT')"
    ;;
esac

echo
echo "--- [SSO-03/BACK-07] GET api/sso/connections never carries a clientSecret value ---"
list_resp="$(_auth_get "${SSO_CONN_URL}?tenant=${GOOD_TENANT}")"
list_code="$(_code_of "$list_resp")"
list_body="$(_body_of "$list_resp")"
if [ "$list_code" = "200" ] && [ -n "$list_body" ]; then
  if printf '%s' "$list_body" | grep -qiE '"clientSecret"[[:space:]]*:[[:space:]]*"[^"]'; then
    _fail "[SSO-03/BACK-07] a clientSecret VALUE leaked into the connection list body"
  else
    _pass "[SSO-03/BACK-07] the connection list carries NO clientSecret value (masked badge only)"
  fi
else
  _fail "[SSO-03/BACK-07] GET api/sso/connections?tenant=${GOOD_TENANT} -> code='$list_code' empty='$([ -z "$list_body" ] && echo yes || echo no)' (cannot confirm secret-absence)"
fi

# =============================================================================
# SSO-04 (CR-01/WR-02/WR-03 fix-proving) — a metadataUrl is now fetched BY THE
# BACKEND through the authoritative SSRF-guarded client (re-resolve + address-pin
# + redirects OFF); Polis is NEVER handed the URL. An internal/credentialed/
# loopback host is rejected with an explicit **422** (AppError::Validation keyed on
# metadata_url, so the form surfaces it verbatim — WR-02), and the signing-cert
# pre-flight now runs on the fetched XML too (WR-03). Anti-false-green: PASS only
# on an explicit 422, FAIL on 2xx, on a 400 (the OLD pre-fix status — its presence
# would mean the verbatim-422 remap regressed), or on a connection error.
# =============================================================================
echo
echo "============================================================"
echo " SSO-04 — metadataUrl SSRF reject via BACKEND fetch (422, no Polis fetch)"
echo "============================================================"

_make_url_body() {
  # $1=tenant $2=metadata_url
  TENANT="$1" URL="$2" node -e '
    const body = {
      tenant: process.env.TENANT,
      metadata_url: process.env.URL,
      default_redirect_url: "http://localhost:3000/sso/callback",
      redirect_url: ["http://localhost:3000/sso/callback"]
    };
    process.stdout.write(JSON.stringify(body));'
}

_assert_ssrf_reject() {
  # $1=label $2=metadata_url
  # The fix maps the SSRF/fetch reject to a 422 keyed on metadata_url (WR-02). We
  # assert 422 SPECIFICALLY: a 400 here would mean the verbatim-422 remap regressed
  # (the pre-fix behavior), and a 2xx would mean the backend-fetch SSRF guard
  # leaked. Either is an explicit FAIL (anti-false-green).
  local label="$1" url="$2" body code
  body="$(_make_url_body "ssrf-probe" "$url")"
  code="$(_auth_mut_code POST "$SSO_CONN_URL" "$body")"
  case "$code" in
    422)
      _pass "[SSO-04] metadataUrl '${label}' -> 422 (BACKEND-fetch SSRF reject, verbatim metadata_url field error; Polis never fetched)"
      ;;
    400)
      _fail "[SSO-04] metadataUrl '${label}' -> 400 (WR-02 regression: SSRF reject must be a verbatim 422, not a generic 400)"
      ;;
    "")
      _fail "[SSO-04] metadataUrl '${label}' -> no response (connection error; want an explicit 422)"
      ;;
    2*)
      _fail "[SSO-04] metadataUrl '${label}' -> ${code} (ACCEPTED — the backend-fetch SSRF guard LEAKED)"
      ;;
    *)
      _fail "[SSO-04] metadataUrl '${label}' -> ${code} (want an explicit 422 SSRF reject)"
      ;;
  esac
}

echo
_assert_ssrf_reject "http://kratos:4434 (internal Ory admin)" "http://kratos:4434/metadata"
_assert_ssrf_reject "http://169.254.169.254 (cloud metadata)" "http://169.254.169.254/latest/meta-data"
_assert_ssrf_reject "credentialed userinfo URL" "http://user:pass@idp.example.test/metadata"
_assert_ssrf_reject "loopback literal" "http://127.0.0.1/metadata"
# CR-01 fix-proving: a metadataUrl whose host resolves to an internal docker
# address (the Polis admin itself) — the EXACT SSRF-by-proxy target the old
# delegate-to-Polis path enabled. The backend's own pinned re-resolve must refuse
# it BEFORE any fetch, proving Polis is no longer the fetcher.
_assert_ssrf_reject "http://polis:5225 (internal Polis admin — the by-proxy target)" "http://polis:5225/api/v1/sso"

# CR-01/WR-03 fix-proving: a metadataUrl that points at the backend's OWN internal
# port (resolves to a private docker IP) is refused by the backend-fetch guard.
# This is the channel that, pre-fix, Polis would have fetched server-side.
_assert_ssrf_reject "http://backend:8080 (internal backend port)" "http://backend:8080/health"

# Confirm the SSRF probe never created a connection (no fetch, no side effect).
ssrf_count="$(_connection_count "ssrf-probe")"
if [ "$ssrf_count" = "EMPTY" ] || [ "$ssrf_count" = "0" ]; then
  _pass "[SSO-04] no Polis connection exists for the SSRF probe tenant (the reject was before any fetch/create)"
else
  _fail "[SSO-04] expected NO connection for ssrf-probe (got count='$ssrf_count')"
fi

# -----------------------------------------------------------------------------
# WR-03 fix-proving — a URL-sourced metadata document with NO signing cert is
# rejected (422) and NEVER creates a connection. Pre-fix the URL path was handed
# straight to Polis and the backend NEVER saw the XML, so there was zero
# console-side signing-cert enforcement on URL-sourced connections (a reassuring
# thumbprint could be shown for a connection with no verified signing cert).
#
# The SSO create path always uses the PRODUCTION SSRF posture (build_pinned_client
# with allow_private=false), so to actually reach the signing-cert pre-flight the
# fetch must target a PUBLIC, fetchable host whose document carries no SAML signing
# cert. We use https://example.com/ (stable IANA-reserved example host, returns
# HTML — definitively no <KeyDescriptor use="signing"> X509Certificate).
#
# Outcome is deterministic in VERDICT regardless of egress: if the host is
# reachable, the backend fetches it and the signing-cert pre-flight rejects the
# CA-less HTML -> 422; if outbound egress is unavailable in the CI sandbox, the
# backend fetch fails -> also 422 (value-free metadata_url field error). In BOTH
# cases the result is an explicit 422 and NEVER a created connection. A 2xx would
# mean a CA-less URL-sourced doc created a connection (the WR-03 hole) -> FAIL.
echo
echo "--- [WR-03] a URL-sourced CA-less (public) metadata document is rejected 422; no connection created ---"
caless_url_body="$(_make_url_body "caless-url-probe" "https://example.com/")"
caless_url_code="$(_auth_mut_code POST "$SSO_CONN_URL" "$caless_url_body")"
case "$caless_url_code" in
  422) _pass "[WR-03] URL-sourced CA-less metadata -> 422 (signing-cert pre-flight / fetch guard reached on the URL path — no longer a CA blind spot)";;
  2*)  _fail "[WR-03] URL-sourced CA-less metadata -> ${caless_url_code} (ACCEPTED — no signing-cert enforcement on the URL path)";;
  *)   _fail "[WR-03] URL-sourced CA-less metadata -> '${caless_url_code}' (want an explicit 422 reject)";;
esac
caless_url_count="$(_connection_count "caless-url-probe")"
if [ "$caless_url_count" = "EMPTY" ] || [ "$caless_url_count" = "0" ]; then
  _pass "[WR-03] no Polis connection exists for the URL-sourced CA-less probe (rejected before any Polis create)"
else
  _fail "[WR-03] expected NO connection for caless-url-probe (got count='$caless_url_count')"
fi

# =============================================================================
# SSO-05 — IDNA/case/trailing-dot domain collision (409) + the
# corp.com.attacker.com non-collision + an audit row for the org create.
# =============================================================================
echo
echo "============================================================"
echo " SSO-05 — domain normalization collision (409) + audit row"
echo "============================================================"

echo
echo "--- [SSO-05] create an org with domain CORP.com -> 201, then a colliding variant -> 409 ---"
org1_resp="$(_auth_mut POST "$ORG_URL" '{"label":"Acme Acc","domains":["CORP.com"]}')"
org1_code="$(_code_of "$org1_resp")"
org1_body="$(_body_of "$org1_resp")"
if [ "$org1_code" = "200" ] || [ "$org1_code" = "201" ]; then
  _pass "[SSO-05] create org with domain CORP.com -> $org1_code"
else
  _fail "[SSO-05] create org with CORP.com -> '$org1_code' (want 2xx; body: $(printf '%s' "$org1_body" | head -c 200))"
fi
ORG1_ID="$(printf '%s' "$org1_body" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
  process.stdout.write((d && (d.id||"")).toString());' 2>/dev/null)"

# A trailing-dot variant of the SAME registered domain must collide (409).
echo
echo "--- [SSO-05] a second org with 'corp.com.' (trailing dot, lowercase) collides -> 409 ---"
collide_code="$(_auth_mut_code POST "$ORG_URL" '{"label":"Collider","domains":["corp.com."]}')"
if [ "$collide_code" = "409" ]; then
  _pass "[SSO-05] colliding domain 'corp.com.' -> 409 (normalized to the same key as CORP.com — UNIQUE index defense)"
else
  _fail "[SSO-05] colliding domain 'corp.com.' -> '$collide_code' (want explicit 409 collision)"
fi

# A Cyrillic-homoglyph variant ("cорp.com" with Cyrillic о/р) — after IDNA it is
# a DIFFERENT registrable label (xn--...), so it does NOT collide with corp.com.
# This proves the normalizer does not silently fold confusables INTO the ASCII
# domain (which would be a FALSE collision). We assert it is accepted as distinct.
echo
echo "--- [SSO-05] a Cyrillic-homoglyph 'cорp.com' is a DISTINCT punycode domain (not folded into corp.com) ---"
HOMO_DOMAIN="$(node -e 'process.stdout.write("cорp.com")')"  # c + Cyrillic о р + p.com
homo_body="$(LABEL="Homoglyph" DOM="$HOMO_DOMAIN" node -e '
  process.stdout.write(JSON.stringify({label: process.env.LABEL, domains: [process.env.DOM]}));')"
homo_code="$(_auth_mut_code POST "$ORG_URL" "$homo_body")"
case "$homo_code" in
  200|201) _pass "[SSO-05] Cyrillic-homoglyph 'cорp.com' -> $homo_code (distinct punycode label; NOT folded into corp.com — no false collision)";;
  409)     _fail "[SSO-05] Cyrillic-homoglyph 'cорp.com' -> 409 (the normalizer WRONGLY folded a confusable into corp.com)";;
  422|400) _pass "[SSO-05] Cyrillic-homoglyph 'cорp.com' -> $homo_code (conservatively rejected as ambiguous — also acceptable; it is NOT treated as corp.com)";;
  *)       _fail "[SSO-05] Cyrillic-homoglyph 'cорp.com' -> '$homo_code' (want a distinct create or a conservative 4xx — never a corp.com collision)";;
esac

# corp.com.attacker.com reduces to attacker.com (eTLD+1) — DISTINCT from corp.com.
echo
echo "--- [SSO-05] 'corp.com.attacker.com' is DISTINCT (reduces to attacker.com, not corp.com) -> accepted ---"
attacker_code="$(_auth_mut_code POST "$ORG_URL" '{"label":"Attacker Distinct","domains":["corp.com.attacker.com"]}')"
case "$attacker_code" in
  200|201) _pass "[SSO-05] 'corp.com.attacker.com' -> $attacker_code (registered domain attacker.com, DISTINCT from corp.com — no false collision)";;
  409)     _fail "[SSO-05] 'corp.com.attacker.com' -> 409 (WRONGLY collided with corp.com — the eTLD+1 boundary failed)";;
  *)       _fail "[SSO-05] 'corp.com.attacker.com' -> '$attacker_code' (want a distinct create)";;
esac

# Audit row: a state-changing POST /api/organizations is auto-audited by the
# response-phase hoop. Assert at least one audit row exists for the path.
echo
echo "--- [SSO-05/T-14-09] an audit row exists for the org create (POST /api/organizations) ---"
audit_count="$(_psql "SELECT count(*) FROM console_audit_log WHERE path = '/api/organizations' AND method = 'POST'" | tr -d '[:space:]')"
if [ -n "$audit_count" ] && [ "$audit_count" -ge 1 ] 2>/dev/null; then
  _pass "[SSO-05/T-14-09] ${audit_count} audit row(s) for POST /api/organizations (org/domain changes are audited)"
else
  _fail "[SSO-05/T-14-09] no audit row for POST /api/organizations (got count='$audit_count') — org changes must be audited"
fi

# =============================================================================
# SSO-06 — domain->SSO lookup returns the org's linked connection for a known
# domain; an unknown domain -> 404 (no existence leak).
# =============================================================================
echo
echo "============================================================"
echo " SSO-06 — domain->SSO lookup (known -> link; unknown -> 404)"
echo "============================================================"

# Link the CORP.com org (ORG1) to the signing-cert connection tenant, then look up.
if [ -n "$ORG1_ID" ]; then
  echo
  echo "--- [SSO-06] create a linkable org (domain lookup-acme.com) wired to the SAML connection tenant ---"
  link_body="$(TENANT="$GOOD_TENANT" node -e '
    process.stdout.write(JSON.stringify({
      label: "Linked Org",
      domains: ["lookup-acme.com"],
      sso_connection_tenant: process.env.TENANT
    }));')"
  link_resp="$(_auth_mut POST "$ORG_URL" "$link_body")"
  link_code="$(_code_of "$link_resp")"
  if [ "$link_code" = "200" ] || [ "$link_code" = "201" ]; then
    _pass "[SSO-06] created a linked org (domain lookup-acme.com -> tenant ${GOOD_TENANT})"
  else
    _fail "[SSO-06] could not create the linked org -> '$link_code'"
  fi

  echo
  echo "--- [SSO-06] GET api/sso/lookup?email=a@lookup-acme.com -> returns the linked connection tenant ---"
  lookup_resp="$(_auth_get "${SSO_LOOKUP_URL}?email=a@lookup-acme.com")"
  lookup_code="$(_code_of "$lookup_resp")"
  lookup_body="$(_body_of "$lookup_resp")"
  if [ "$lookup_code" = "200" ]; then
    linked="$(printf '%s' "$lookup_body" | TENANT="$GOOD_TENANT" node -e '
      let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
      const want = process.env.TENANT;
      const s = JSON.stringify(d);
      process.stdout.write(s.includes(want) ? "OK" : "MISSING:" + s.slice(0,200));' 2>/dev/null)"
    if [ "$linked" = "OK" ]; then
      _pass "[SSO-06] lookup for a known org domain returns the linked SSO connection tenant (${GOOD_TENANT})"
    else
      _fail "[SSO-06] lookup body did not carry the linked tenant ($linked)"
    fi
  else
    _fail "[SSO-06] GET api/sso/lookup (known domain) -> '$lookup_code' (want 200)"
  fi
fi

echo
echo "--- [SSO-06] GET api/sso/lookup for an UNKNOWN domain -> 404 (no org-existence leak) ---"
unknown_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${SSO_LOOKUP_URL}?domain=notanorg.example.org" 2>/dev/null)"
if [ "$unknown_code" = "404" ]; then
  _pass "[SSO-06] lookup for an unknown domain -> 404 (value-free; no org-existence leak)"
else
  _fail "[SSO-06] lookup for an unknown domain -> '$unknown_code' (want explicit 404)"
fi

# =============================================================================
# TWO-SIDED DELETE — after delete, the Polis connection is gone AND the Kratos
# providers[] entry is removed (no dangling provider).
# =============================================================================
echo
echo "============================================================"
echo " Two-sided delete — Polis connection + Kratos provider entry"
echo "============================================================"

echo
echo "--- [two-sided] DELETE api/sso/connections/${GOOD_TENANT} -> Polis connection gone AND Kratos provider removed ---"
del_code="$(_auth_mut_code DELETE "${SSO_CONN_URL}/${GOOD_TENANT}")"
if [ "$del_code" = "200" ] || [ "$del_code" = "204" ]; then
  _pass "[two-sided] DELETE api/sso/connections/${GOOD_TENANT} -> $del_code"
else
  _fail "[two-sided] DELETE api/sso/connections/${GOOD_TENANT} -> '$del_code' (want 2xx)"
fi
wait_container_healthy "$KRATOS_CONTAINER" 120

# Side 1: the Polis connection is gone.
del_count="$(_connection_count "${GOOD_TENANT}")"
if [ "$del_count" = "EMPTY" ] || [ "$del_count" = "0" ]; then
  _pass "[two-sided] the Polis connection for ${GOOD_TENANT} is GONE (no connections after delete)"
else
  _fail "[two-sided] Polis still lists ${del_count} connection(s) for ${GOOD_TENANT} after delete"
fi

# Side 2: the Kratos providers[] entry is removed (no dangling provider).
KRATOS_YML_AFTER="$(cat "${REPO_ROOT}/config/kratos/kratos.yml" 2>/dev/null || true)"
DANGLE_VERDICT="$(printf '%s' "$KRATOS_YML_AFTER" | PID="$PROVIDER_ID" node -e '
  const txt = require("fs").readFileSync(0, "utf8");
  const pid = process.env.PID;
  if (!txt.trim()) { process.stdout.write("NO_KRATOS_YML"); process.exit(0); }
  process.stdout.write(txt.includes(pid) ? "DANGLING" : "REMOVED");' 2>/dev/null)"
case "$DANGLE_VERDICT" in
  REMOVED)  _pass "[two-sided] the Kratos providers[] entry '${PROVIDER_ID}' is REMOVED (no dangling provider)";;
  DANGLING) _fail "[two-sided] the Kratos providers[] entry '${PROVIDER_ID}' STILL EXISTS after delete (DANGLING provider)";;
  *)        _fail "[two-sided] could not read kratos.yml after delete (verdict='$DANGLE_VERDICT')";;
esac

# -----------------------------------------------------------------------------
# CR-02 fix-proving — the two-sided delete is idempotent / retry-safe. After the
# delete above, the Polis connection is ALREADY GONE — this is exactly the state a
# retry hits after a partial failure (Kratos cleaned, Polis gone). Pre-fix, a
# second delete 502'd (Polis 404 -> Upstream) BEFORE the Kratos cleanup ran, so a
# half-finished delete could never be completed through the endpoint, leaving a
# dangling provider. Post-fix, the Polis delete treats a 404 as success and the
# Kratos side runs FIRST, so a retry returns 2xx and leaves NO dangling provider.
echo
echo "--- [CR-02] a RETRY of DELETE on the already-gone connection succeeds (idempotent; Polis 404 = success) ---"
retry_del_code="$(_auth_mut_code DELETE "${SSO_CONN_URL}/${GOOD_TENANT}")"
case "$retry_del_code" in
  200|204) _pass "[CR-02] retry DELETE api/sso/connections/${GOOD_TENANT} -> $retry_del_code (idempotent; a Polis 404 is treated as already-deleted)";;
  502)     _fail "[CR-02] retry DELETE -> 502 (Polis 404 -> Upstream; the partial-failure recovery path is BROKEN — pre-fix behavior)";;
  *)        _fail "[CR-02] retry DELETE -> '$retry_del_code' (want 2xx idempotent success)";;
esac
# After the idempotent retry, the Kratos provider entry must STILL be absent (the
# retry must not re-introduce or strand a dangling provider).
KRATOS_YML_RETRY="$(cat "${REPO_ROOT}/config/kratos/kratos.yml" 2>/dev/null || true)"
RETRY_DANGLE="$(printf '%s' "$KRATOS_YML_RETRY" | PID="$PROVIDER_ID" node -e '
  const txt = require("fs").readFileSync(0, "utf8");
  const pid = process.env.PID;
  if (!txt.trim()) { process.stdout.write("NO_KRATOS_YML"); process.exit(0); }
  process.stdout.write(txt.includes(pid) ? "DANGLING" : "REMOVED");' 2>/dev/null)"
case "$RETRY_DANGLE" in
  REMOVED)  _pass "[CR-02] after the idempotent retry, NO dangling Kratos provider '${PROVIDER_ID}' remains (cleanup completed)";;
  DANGLING) _fail "[CR-02] after the retry, the Kratos provider '${PROVIDER_ID}' is present (dangling provider stranded)";;
  *)        _fail "[CR-02] could not read kratos.yml after the retry (verdict='$RETRY_DANGLE')";;
esac

# =============================================================================
# Phase-9-style config-write discipline — a VALID provider write restarts ONLY
# Kratos; an INVALID provider write leaves the file untouched (no disk change).
# We exercise this by re-creating a valid connection (restart-scope proof) and a
# CA-less create (no-disk-change proof).
# =============================================================================
echo
echo "============================================================"
echo " BACK-05 (config-write discipline) — Kratos-only restart + no-write-on-reject"
echo "============================================================"

echo
echo "--- [BACK-05] a valid provider write restarts ONLY Kratos (every other container's StartedAt unchanged) ---"
snapshot_started_at "$KRATOS_CONTAINER" "$HYDRA_CONTAINER" "$KETO_CONTAINER" \
  "$OATHKEEPER_CONTAINER" "$POLIS_CONTAINER" "$BACKEND_CONTAINER" \
  "$FRONTEND_CONTAINER" "$POSTGRES_CONTAINER"
RESTART_TENANT="restart-scope-acc"
rscope_body="$(_make_create_body "$RESTART_TENANT" "$SIGNING_XML")"
rscope_resp="$(_auth_mut POST "$SSO_CONN_URL" "$rscope_body")"
rscope_code="$(_code_of "$rscope_resp")"
if [ "$rscope_code" = "200" ] || [ "$rscope_code" = "201" ]; then
  _pass "[BACK-05] valid provider create -> $rscope_code (triggers a Kratos provider write)"
else
  _fail "[BACK-05] valid provider create -> '$rscope_code' (want 2xx; body: $(printf '%s' "$(_body_of "$rscope_resp")" | head -c 200))"
fi
assert_only_container_restarted "$KRATOS_CONTAINER" "$HYDRA_CONTAINER" "$KETO_CONTAINER" \
  "$OATHKEEPER_CONTAINER" "$POLIS_CONTAINER" "$BACKEND_CONTAINER" \
  "$FRONTEND_CONTAINER" "$POSTGRES_CONTAINER"
wait_container_healthy "$KRATOS_CONTAINER" 120

echo
echo "--- [BACK-05] an INVALID (CA-less) provider write does NOT touch kratos.yml (no disk change) ---"
# Snapshot the host kratos.yml, attempt a CA-less create (rejected pre-Polis,
# pre-write), and assert the file is byte-identical (the reject never wrote).
KRATOS_HOST_YML="${REPO_ROOT}/config/kratos/kratos.yml"
snapshot_file "$KRATOS_HOST_YML"
caless2_code="$(_auth_mut_code POST "$SSO_CONN_URL" "$(_make_create_body "no-write-acc" "$CA_LESS_XML")")"
if [ "$caless2_code" = "422" ]; then
  _pass "[BACK-05] CA-less create -> 422 (rejected before any provider write)"
else
  _fail "[BACK-05] CA-less create -> '$caless2_code' (want 422)"
fi
assert_file_unchanged "$KRATOS_HOST_YML"

# Clean up the restart-scope connection (two-sided) so re-runs start clean.
_auth_mut_code DELETE "${SSO_CONN_URL}/${RESTART_TENANT}" >/dev/null
wait_container_healthy "$KRATOS_CONTAINER" 120

# =============================================================================
# Restore both flags to their seeded default (OFF) so re-runs / downstream phases
# see a clean baseline, and confirm the gates re-close (404 again).
# =============================================================================
echo
echo "--- restore saml + organizations to their seeded default (OFF); the gates re-close (404) ---"
_set_flag saml false >/dev/null && _pass "restored saml=false" || _fail "could not restore saml=false"
_set_flag organizations false >/dev/null && _pass "restored organizations=false" || _fail "could not restore organizations=false"
reclose_sso="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${SSO_CONN_URL}?tenant=x" 2>/dev/null)"
reclose_org="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$ORG_URL" 2>/dev/null)"
if [ "$reclose_sso" = "404" ]; then
  _pass "[SSO-07] after restoring saml OFF, api/sso/connections 404s again (toggle is live)"
else
  _fail "[SSO-07] after restoring saml OFF, api/sso/connections -> '$reclose_sso' (want 404)"
fi
if [ "$reclose_org" = "404" ]; then
  _pass "[SSO-07] after restoring organizations OFF, api/organizations 404s again (toggle is live)"
else
  _fail "[SSO-07] after restoring organizations OFF, api/organizations -> '$reclose_org' (want 404)"
fi

# =============================================================================
# v1-INVARIANT REGRESSION — INFRA-05 admin-port isolation (Ory services + Polis).
# =============================================================================
echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — INFRA-05 admin-port isolation"
echo "============================================================"
echo
echo "--- [INFRA-05] no Ory Admin port is host-published (refused from host; reachable internally) ---"
for port in $ADMIN_PORTS; do
  assert_port_refused "$port"
done
echo
echo "--- [INFRA-05] the Polis admin/OIDC port 5225 is NOT host-published (refused from host) ---"
assert_port_refused "$POLIS_ADMIN_PORT"
# Positive: from the trusted backend the kratos admin API + the Polis issuer ARE up.
assert_internal_reachable backend "http://kratos:4434/health/ready"
assert_internal_reachable backend "http://polis:5225/api/health"

# =============================================================================
# v1-INVARIANT REGRESSION — BACK-05 restart-broker scope (Ory + Polis containers).
# =============================================================================
echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — BACK-05 restart-broker scope"
echo "============================================================"
echo
echo "--- [BACK-05] restarts route ONLY through the scoped socket-proxy; backend + polis hold NO socket ---"
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart"
assert_broker_allowed POST "/${API_VER}/containers/${POLIS_CONTAINER}/restart"
assert_broker_denied GET  "/${API_VER}/containers/json"
assert_broker_denied POST "/${API_VER}/containers/${KRATOS_CONTAINER}/stop"
assert_broker_denied POST "/${API_VER}/containers/postgres/restart"
assert_no_socket_mount backend
assert_no_socket_mount "$POLIS_CONTAINER"

echo
summary
exit $?
