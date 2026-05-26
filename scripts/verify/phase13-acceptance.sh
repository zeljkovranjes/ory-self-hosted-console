#!/usr/bin/env bash
# scripts/verify/phase13-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 13 (ory-polis-saml-bridge-service) live-stack acceptance gate. Proves
# SSO-01 end to end against the REAL compose stack on a FRESH VOLUME, AND re-runs
# the three v1-invariant regressions (INFRA-05, BACK-05, BACK-01) with the new
# `polis` service present so the SAML bridge is shown NOT to have regressed them.
# Every negative assertion is EXPLICIT (anti-false-green, lib.sh T-03 contract):
# a refusal must be an explicit 404 / connection-refused / 403, NEVER a silent
# pass on absence-of-output.
#
#   SSO-01 (healthy)   — the `polis` container reaches Docker `healthy` on a fresh
#                        `docker compose up --wait` (boxyhq/jackson:26.2.0, ENV-
#                        configured, self-migrating). FAIL if absent/unhealthy.
#   SSO-01 (INFRA-05)  — admin/OIDC port 5225 is NOT host-published: docker inspect
#                        shows no host binding for 5225 AND a host connect to :5225
#                        is REFUSED (negative; PASS only on connection refusal).
#   SSO-01 (BACK-05)   — the running restart-broker allowlist permits a SCOPED
#                        `polis` restart but DENIES list/stop/other-container; the
#                        backend container holds NO /var/run/docker.sock.
#   SSO-01 (dual-homed)— polis is attached to BOTH the `internal` and `edge`
#                        networks (Kratos+backend reach internal; browser reaches
#                        the issuer via edge — split-horizon Pattern A).
#   SSO-01 (saml gate) — with a VALID session + CSRF, GET /api/config/polis 404s
#                        while `saml` is OFF (the seeded default), then PUT-toggles
#                        `saml` ON and the SAME route is reachable (200); a valid
#                        non-secret PUT returns {status:healthy}.
#   SSO-01 (Polis-only restart) — a valid non-secret PUT /api/config/polis restarts
#                        ONLY the `polis` container (its StartedAt changes; every
#                        other container's StartedAt is UNCHANGED — phase9/10 proof).
#
#   v1-INVARIANT REGRESSION (phase success criteria, with Polis present):
#     INFRA-05 — no Ory Admin port host-published (refused from host; reachable
#                internally from the trusted backend container).
#     BACK-05  — restarts route ONLY through the container-scoped socket-proxy
#                allowlist; the backend holds NO Docker socket.
#     BACK-01  — scripts/verify/bundle-egress.sh: no Ory/Polis URL/SDK/new egress
#                host (and no CDN) in the built frontend bundle.
#
# ADVISORY (NOT a gate this phase): the cross-network issuer-reachability check
# (curl ${POLIS_EXTERNAL_URL}/.well-known/openid-configuration from host AND from
# a Kratos-network container, issuer matching) is echoed but never FAILs the gate
# — Phase 14 wires the Kratos egress + provider entry (RESEARCH Manual-Only).
#
# Run (Git Bash on Windows: prefix compose with MSYS_NO_PATHCONV=1 so leading-slash
# URL paths are not mangled). This script does the FULL lifecycle itself
# (build -> up -d --wait -> drive -> down -v) unless told to reuse a stack:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase13-acceptance.sh
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

# --- Exact container names + admin ports for the v1-invariant re-run ---------
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
# Polis admin/OIDC port — MUST also be refused from the host (SSO-01 / INFRA-05).
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

echo "=== Phase 13 acceptance: Ory Polis (SAML bridge) — SSO-01 ==="
echo "    (Polis healthy + 5225 internal-only + broker scope + dual-homed +"
echo "     saml-gate 404/200 + Polis-only restart + INFRA-05/BACK-05/BACK-01 regression)"
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
}
trap teardown EXIT

# =============================================================================
# CRITERION BACK-01 — bundle egress. Build the frontend and grep the built
# output for any Ory/Polis host/port/SDK/CDN leak. Holds regardless of the live
# stack, so run it first (the cheapest hard gate next to a static grep).
# =============================================================================
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  echo
  echo "--- [BACK-01] bundle-egress: no Ory/Polis host/port/SDK + no CDN in the built bundle ---"
  if bash "${REPO_ROOT}/scripts/verify/bundle-egress.sh"; then
    _pass "[BACK-01] bundle-egress: built frontend bundle is Ory-egress-clean and CDN-free (Polis present)"
  else
    _fail "[BACK-01] bundle-egress: FORBIDDEN Ory/Polis host/port/SDK or CDN reference in the built bundle"
  fi
else
  echo
  echo "--- [BACK-01] bundle-egress SKIPPED (SKIP_EGRESS=1) — live-only run ---"
fi

# Defense-in-depth static check: no NEXT_PUBLIC Polis var / Polis admin URL is
# wired into the frontend SOURCE (the bundle grep above is the authoritative hard
# gate; this catches a leak before it even builds). PASS only on explicit absence.
echo
echo "--- [BACK-01] no NEXT_PUBLIC Polis var / :5225 admin URL in frontend source ---"
POLIS_SRC_HITS="$(grep -rnE 'NEXT_PUBLIC[A-Z_]*POLIS|polis:5225|//polis([/:."'"'"']|$)' \
  "${REPO_ROOT}/frontend" --include=*.tsx --include=*.ts 2>/dev/null || true)"
if [ -z "$POLIS_SRC_HITS" ]; then
  _pass "[BACK-01] no NEXT_PUBLIC Polis var / Polis admin URL in frontend source (browser reaches Polis only via the backend)"
else
  _fail "[BACK-01] a NEXT_PUBLIC Polis var / Polis admin URL leaked into frontend source:"
  printf '%s\n' "$POLIS_SRC_HITS"
fi

# =============================================================================
# Bring the stack up on a FRESH VOLUME (unless REUSE_STACK=1) for the live
# assertions. SSO-01 mandates a fresh `docker compose up`: the new `polis`
# logical DB + role is only created by db/init on a fresh-volume boot, and the
# console DB must be fresh so /setup mints a one-time token (mirrors phase12).
# =============================================================================
# Insecure cookies for THIS ephemeral run so curl can replay the session cookie
# over the plain-HTTP compose edge (a `__Host-`/`Secure` cookie is dropped over http).
export CONSOLE_INSECURE_COOKIES=true
# The flag gate is anchored on the REAL saml-gated route /api/config/polis (a real
# saml-gated backend route as of 13-02), so the FLAG-01 test-probe is NOT needed.
# We still export TEST_PROBE=1 to match the prior gate's acceptance image posture
# (harmless: it only adds the unused probe route to the ephemeral image).
export TEST_PROBE=1

# --- Generate ephemeral Polis secrets so every `${POLIS_*:?}` resolves --------
# These are throwaway, generated per-run, never written to .env, never committed
# (BACK-07: the backend can never mint these — but THIS acceptance harness MUST
# provide them so the `${VAR:?}` interpolation does not abort the compose up).
_gen_b64() { openssl rand -base64 32 2>/dev/null | tr -d '\n' || node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64"))'; }
_gen_rsa_b64() {
  # A base64-encoded RSA-2048 PKCS#8 private key (Polis OPENID_RSA_PRIVATE_KEY) and
  # its public key. Base64 the PEM so the single-line env value carries no newlines.
  local tmpk tmppub
  tmpk="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/polis_rsa_$$")"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmpk" >/dev/null 2>&1 || return 1
  tmppub="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/polis_rsa_pub_$$")"
  openssl pkey -in "$tmpk" -pubout -out "$tmppub" >/dev/null 2>&1 || return 1
  POLIS_OPENID_RSA_PRIVATE_KEY="$(base64 < "$tmpk" | tr -d '\n')"
  POLIS_OPENID_RSA_PUBLIC_KEY="$(base64 < "$tmppub" | tr -d '\n')"
  rm -f "$tmpk" "$tmppub" 2>/dev/null || true
}
export POLIS_DB_PASSWORD="${POLIS_DB_PASSWORD:-acceptance_polis_pw}"
export POLIS_DB_ENCRYPTION_KEY="${POLIS_DB_ENCRYPTION_KEY:-$(_gen_b64)}"
export POLIS_API_KEY="${POLIS_API_KEY:-$(_gen_b64)}"
export POLIS_NEXTAUTH_SECRET="${POLIS_NEXTAUTH_SECRET:-$(_gen_b64)}"
# Single public issuer. For a localhost acceptance run there is no public edge, so
# point it at the host-published frontend origin (any reachable URL satisfies the
# `${VAR:?}` contract; the live issuer-reachability check is ADVISORY this phase).
export POLIS_EXTERNAL_URL="${POLIS_EXTERNAL_URL:-http://localhost:5225}"
if [ -z "${POLIS_OPENID_RSA_PRIVATE_KEY:-}" ] || [ -z "${POLIS_OPENID_RSA_PUBLIC_KEY:-}" ]; then
  if ! _gen_rsa_b64; then
    _fail "could not generate an ephemeral Polis RSA keypair (openssl unavailable) — cannot bring Polis up"
    summary
    exit $?
  fi
fi
export POLIS_OPENID_RSA_PRIVATE_KEY POLIS_OPENID_RSA_PUBLIC_KEY
# The other services' `${VAR:?}` contracts (ADMIN_PASSWORD / *_DB_PASSWORD) are
# satisfied by the operator .env that the prior phase gates already require.

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- fresh-volume reset (down -v) so the polis DB + console /setup token are minted fresh ---"
  # SSO-01 / Pitfall 2: the `polis` logical DB + role are created by db/init ONLY
  # on a fresh-volume boot; an existing volume would skip it and Polis would fail
  # to connect. And the console DB must be fresh so /setup mints a one-time token.
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

# =============================================================================
# SSO-01 (1) — Polis is HEALTHY on the fresh-volume bring-up.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (1) — Polis reaches healthy on a fresh volume"
echo "============================================================"
echo
echo "--- [SSO-01] preflight: backend healthy + the polis container healthy ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200
# The polis container must report Docker `healthy` (the node-fetch /api/health
# probe). A bare assert_healthy can race the post-boot `starting` window; poll.
wait_container_healthy "$POLIS_CONTAINER" 120

# =============================================================================
# SSO-01 (2) — INFRA-05: the Polis admin/OIDC port 5225 is NOT host-published.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (2) — INFRA-05: Polis admin/OIDC port 5225 internal-only"
echo "============================================================"
echo
echo "--- [SSO-01/INFRA-05] docker inspect polis: no host binding for 5225 ---"
# NEGATIVE structural assertion: the published-ports map must carry NO host
# binding for 5225/tcp. PASS only on an explicit "no host port" verdict — never on
# a parse miss (anti-false-green).
POLIS_5225_BINDING="$(docker inspect "$POLIS_CONTAINER" 2>/dev/null | PORT="${POLIS_ADMIN_PORT}/tcp" node -e '
  let input = require("fs").readFileSync(0, "utf8").trim();
  if (!input) { process.stdout.write("INSPECT_EMPTY"); process.exit(0); }
  let arr; try { arr = JSON.parse(input); } catch (e) { process.stdout.write("BADJSON"); process.exit(0); }
  const c = Array.isArray(arr) ? arr[0] : arr;
  const ports = (c && c.NetworkSettings && c.NetworkSettings.Ports) || {};
  const key = process.env.PORT;
  const binding = ports[key];
  // Docker represents a published port as a non-null array of {HostIp,HostPort};
  // an unpublished exposed port is null (or the key is absent entirely).
  if (binding == null) { process.stdout.write("UNPUBLISHED"); process.exit(0); }
  if (Array.isArray(binding) && binding.length === 0) { process.stdout.write("UNPUBLISHED"); process.exit(0); }
  process.stdout.write("PUBLISHED:" + JSON.stringify(binding));
' 2>/dev/null)"
case "$POLIS_5225_BINDING" in
  UNPUBLISHED)
    _pass "[SSO-01/INFRA-05] polis 5225/tcp has NO host binding (internal-only per the compose NO-ports rule)"
    ;;
  PUBLISHED:*)
    _fail "[SSO-01/INFRA-05] polis 5225/tcp IS host-published: ${POLIS_5225_BINDING#PUBLISHED:} (admin/OIDC port exposed!)"
    ;;
  *)
    _fail "[SSO-01/INFRA-05] could not read polis port bindings (verdict='$POLIS_5225_BINDING') — cannot confirm 5225 is internal-only"
    ;;
esac
echo
echo "--- [SSO-01/INFRA-05] a host connect to :5225 is REFUSED (negative; PASS only on refusal) ---"
assert_port_refused "$POLIS_ADMIN_PORT"
# Positive counterpart: the issuer/admin IS reachable internally from the trusted
# backend container (proves the port is up on the internal network, just not on the host).
echo
echo "--- [SSO-01/INFRA-05] the Polis issuer IS reachable internally from the backend container ---"
assert_internal_reachable "$BACKEND_CONTAINER" "http://polis:5225/api/health"

# =============================================================================
# SSO-01 (3) — BACK-05: the broker permits a SCOPED polis restart, denies the
# rest; the backend holds NO docker socket.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (3) — BACK-05: broker allowlist includes polis ONLY"
echo "============================================================"
echo
echo "--- [SSO-01/BACK-05] broker ALLOWS a scoped polis restart (+ graceful ?t=) ---"
assert_broker_allowed POST "/${API_VER}/containers/${POLIS_CONTAINER}/restart"
assert_broker_allowed POST "/${API_VER}/containers/${POLIS_CONTAINER}/restart?t=5"
echo
echo "--- [SSO-01/BACK-05] broker DENIES list / stop polis / other-container restart (explicit deny) ---"
assert_broker_denied GET  "/${API_VER}/containers/json"
assert_broker_denied POST "/${API_VER}/containers/${POLIS_CONTAINER}/stop"
assert_broker_denied POST "/${API_VER}/containers/postgres/restart"
echo
echo "--- [SSO-01/BACK-05] the backend container holds NO /var/run/docker.sock ---"
assert_no_socket_mount "$BACKEND_CONTAINER"
# The polis container itself must also never hold the socket (only the broker may).
assert_no_socket_mount "$POLIS_CONTAINER"

# =============================================================================
# SSO-01 (4) — dual-homed: polis is on BOTH `internal` and `edge`.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (4) — Polis dual-homed on internal + edge"
echo "============================================================"
echo
echo "--- [SSO-01] docker inspect polis: attached to BOTH the internal AND edge networks ---"
# The compose project prefixes network names (e.g. ory-ui_internal); match on a
# suffix so the assertion is project-name-tolerant. PASS only when BOTH are present.
POLIS_NETS="$(docker inspect "$POLIS_CONTAINER" 2>/dev/null | node -e '
  let input = require("fs").readFileSync(0, "utf8").trim();
  if (!input) { process.stdout.write("INSPECT_EMPTY"); process.exit(0); }
  let arr; try { arr = JSON.parse(input); } catch (e) { process.stdout.write("BADJSON"); process.exit(0); }
  const c = Array.isArray(arr) ? arr[0] : arr;
  const nets = (c && c.NetworkSettings && c.NetworkSettings.Networks) || {};
  const names = Object.keys(nets);
  const hasInternal = names.some(n => n === "internal" || n.endsWith("_internal"));
  const hasEdge     = names.some(n => n === "edge"     || n.endsWith("_edge"));
  process.stdout.write((hasInternal ? "I" : "-") + (hasEdge ? "E" : "-") + ":" + names.join(","));
' 2>/dev/null)"
case "$POLIS_NETS" in
  IE:*)
    _pass "[SSO-01] polis is dual-homed on BOTH internal AND edge (${POLIS_NETS#IE:})"
    ;;
  INSPECT_EMPTY|BADJSON|"")
    _fail "[SSO-01] could not read polis networks (verdict='$POLIS_NETS') — cannot confirm dual-homed"
    ;;
  *)
    _fail "[SSO-01] polis is NOT dual-homed: verdict='${POLIS_NETS%%:*}' nets='${POLIS_NETS#*:}' (want both internal+edge)"
    ;;
esac

# =============================================================================
# Authenticate a console session (complete /setup + login), mirroring phase12.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase13-admin@example.com"
ADMIN_PW_TEST="phase13-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase13 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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
# trimmed scalar. Used for the per-session CSRF token read.
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
  _fail "no authenticated session/CSRF — skipping the live Polis criteria"
  summary
  exit $?
fi

# --- endpoint surface + HTTP helpers (mirror phase12) ------------------------
FEATURES_URL="${BACKEND_BASE_URL}/api/console/features"
POLIS_URL="${BACKEND_BASE_URL}/api/config/polis"

_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 90 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | tail -n1; }
_body_of() { if [ "$#" -ge 1 ]; then printf '%s' "$1"; else cat; fi | sed '$d'; }

# Ensure `saml` is OFF (the seeded default) before the keystone 404 assertion — a
# prior interrupted run may have left it ON.
_saml_enabled() {
  local body
  body="$(_body_of "$(_auth_get "$FEATURES_URL")")"
  printf '%s' "$body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
    const f = d && d.features && d.features.saml;
    process.stdout.write(f ? String(!!f.enabled) : "missing");' 2>/dev/null
}

# =============================================================================
# SSO-01 (5) — the saml-flag gate: OFF -> 404, ON -> reachable, valid PUT healthy.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (5) — /api/config/polis saml-gated: OFF 404 / ON 200"
echo "============================================================"

if [ "$(_saml_enabled)" = "true" ]; then
  echo "    (saml was ON from a prior run; restoring OFF before the keystone assertion)"
  _auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":false}' >/dev/null
fi

echo
echo "--- [SSO-01] saml OFF: GET /api/config/polis with VALID session+CSRF -> 404 (server-side gate) ---"
# THE KEYSTONE (anti-false-green): an explicit 404, NOT 401/403/200. The route is
# mounted behind FeatureFlagHoop::new("saml") AFTER auth+csrf, so a request that
# already passed BOTH guards STILL 404s while saml is OFF.
off_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -H "$COOKIE_HEADER" "$POLIS_URL" 2>/dev/null)"
case "$off_code" in
  404) _pass "[SSO-01] GET /api/config/polis (valid session+CSRF) with saml OFF -> 404 — saml gate beats both guards";;
  401) _fail "[SSO-01] GET /api/config/polis -> 401 (auth guard fired — the session was not accepted; the gate proof is INVALID)";;
  403) _fail "[SSO-01] GET /api/config/polis -> 403 (csrf guard fired — the gate proof is INVALID, not a flag gate)";;
  200) _fail "[SSO-01] GET /api/config/polis -> 200 with saml OFF — THE GATE LEAKED (a disabled feature served)";;
  *)   _fail "[SSO-01] GET /api/config/polis -> '$off_code' (want an explicit 404 with saml OFF)";;
esac
# A PUT to the gated route must ALSO 404 while OFF (past auth+csrf, the gate wins).
off_put_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -H 'Content-Type: application/json' --data '{"LOG_LEVEL":"info"}' "$POLIS_URL" 2>/dev/null)"
if [ "$off_put_code" = "404" ]; then
  _pass "[SSO-01] PUT /api/config/polis (valid session+CSRF) with saml OFF -> 404 (the gate beats the mutation too)"
else
  _fail "[SSO-01] PUT /api/config/polis with saml OFF -> '$off_put_code' (want 404)"
fi

echo
echo "--- [SSO-01] PUT saml=true, then GET /api/config/polis -> 200 (flag-ON makes the route reachable) ---"
on_resp="$(_auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":true}')"
on_code="$(_code_of "$on_resp")"
if [ "$on_code" = "200" ] || [ "$on_code" = "201" ]; then
  _pass "[SSO-01] PUT /api/console/features/saml {enabled:true} -> $on_code (flag flipped ON)"
else
  _fail "[SSO-01] PUT saml=true -> '$on_code' (want 2xx; body: $(_body_of "$on_resp"))"
fi
on_get_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$POLIS_URL" 2>/dev/null)"
if [ "$on_get_code" = "200" ]; then
  _pass "[SSO-01] GET /api/config/polis with saml ON -> 200 (the SAME gated route now serves — ON/OFF pair proven)"
else
  _fail "[SSO-01] GET /api/config/polis with saml ON -> '$on_get_code' (want 200 — flag-ON must serve)"
fi

# A valid NON-SECRET PUT must return {status:healthy} (filter passes, atomic write,
# Polis-only restart, /api/health poll). This is the input for the restart-scope
# proof below, so we capture container StartedAt FIRST.
echo
echo "--- [SSO-01] negative: a write-only SECRET key on PUT -> 403 (never written) ---"
secret_put_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -H 'Content-Type: application/json' --data '{"DB_ENCRYPTION_KEY":"attacker-supplied"}' "$POLIS_URL" 2>/dev/null)"
if [ "$secret_put_code" = "403" ]; then
  _pass "[SSO-01] PUT /api/config/polis {DB_ENCRYPTION_KEY:...} -> 403 (write-only secret refused, never written — T-13-07)"
else
  _fail "[SSO-01] PUT a write-only secret -> '$secret_put_code' (want an explicit 403)"
fi

# =============================================================================
# SSO-01 (6) — a valid Polis config edit restarts ONLY the polis container.
# =============================================================================
echo
echo "============================================================"
echo " SSO-01 (6) — a Polis config edit restarts ONLY polis"
echo "============================================================"
echo
echo "--- [SSO-01] snapshot every container StartedAt, PUT a valid non-secret edit, assert ONLY polis restarted ---"
snapshot_started_at "$POLIS_CONTAINER" "$KRATOS_CONTAINER" "$HYDRA_CONTAINER" \
  "$KETO_CONTAINER" "$OATHKEEPER_CONTAINER" "$BACKEND_CONTAINER" \
  "$FRONTEND_CONTAINER" "$POSTGRES_CONTAINER"
# A safe, allowlisted, non-secret edit (LOG_LEVEL=debug). Returns {status:healthy}.
edit_resp="$(_auth_mut PUT "$POLIS_URL" '{"LOG_LEVEL":"debug"}')"
edit_code="$(_code_of "$edit_resp")"; edit_body="$(_body_of "$edit_resp")"
if [ "$edit_code" = "200" ] && printf '%s' "$edit_body" | grep -q '"status":"healthy"'; then
  _pass "[SSO-01] PUT /api/config/polis {LOG_LEVEL:debug} -> 200 {status:healthy} (filter -> write -> restart -> /api/health OK)"
else
  _fail "[SSO-01] PUT /api/config/polis {LOG_LEVEL:debug} -> '$edit_code' (want 200 {status:healthy}; body: $edit_body)"
fi
# RESTART SCOPE: ONLY polis restarted; all other containers' StartedAt UNCHANGED.
assert_only_container_restarted "$POLIS_CONTAINER" "$KRATOS_CONTAINER" "$HYDRA_CONTAINER" \
  "$KETO_CONTAINER" "$OATHKEEPER_CONTAINER" "$BACKEND_CONTAINER" \
  "$FRONTEND_CONTAINER" "$POSTGRES_CONTAINER"
wait_container_healthy "$POLIS_CONTAINER" 120
# The edit round-trips on a re-GET (the writer persisted it to settings.env).
reget_body="$(_body_of "$(_auth_get "$POLIS_URL")")"
if printf '%s' "$reget_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    process.exit(d && d.LOG_LEVEL === "debug" ? 0 : 1);' 2>/dev/null; then
  _pass "[SSO-01] a re-GET /api/config/polis reflects LOG_LEVEL=debug (the edit persisted to settings.env)"
else
  _fail "[SSO-01] the re-GET did NOT reflect LOG_LEVEL=debug (body: $(printf '%s' "$reget_body" | head -c 300))"
fi

# Restore saml to its seeded default (OFF) so re-runs / downstream phases see a
# clean baseline, and confirm the gate re-closes (404 again).
echo
echo "--- [SSO-01] restore saml=false (the seeded default); the polis route re-closes (404) ---"
restore_resp="$(_auth_mut PUT "${FEATURES_URL}/saml" '{"enabled":false}')"
restore_code="$(_code_of "$restore_resp")"
if [ "$restore_code" = "200" ] || [ "$restore_code" = "201" ]; then
  _pass "[SSO-01] PUT /api/console/features/saml {enabled:false} -> $restore_code (restored to seeded default)"
else
  _fail "[SSO-01] could not restore saml=false -> '$restore_code' (re-runs may start dirty)"
fi
reclose_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$POLIS_URL" 2>/dev/null)"
if [ "$reclose_code" = "404" ]; then
  _pass "[SSO-01] after restoring saml OFF, GET /api/config/polis 404s again (the gate re-closed — toggle is live)"
else
  _fail "[SSO-01] after restoring saml OFF, GET /api/config/polis -> '$reclose_code' (want 404 — the toggle must re-close the gate)"
fi

# =============================================================================
# v1-INVARIANT REGRESSION — INFRA-05 admin-port isolation (Ory services).
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
# Positive: from the trusted backend container the kratos admin API IS up.
assert_internal_reachable backend "http://kratos:4434/health/ready"

# =============================================================================
# v1-INVARIANT REGRESSION — BACK-05 restart-broker scope (Ory containers).
# =============================================================================
echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — BACK-05 restart-broker scope"
echo "============================================================"
echo
echo "--- [BACK-05] restarts route ONLY through the scoped socket-proxy; backend holds NO socket ---"
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart"
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart?t=5"
assert_broker_denied GET  "/${API_VER}/containers/json"
assert_broker_denied POST "/${API_VER}/containers/${KRATOS_CONTAINER}/stop"
assert_broker_denied POST "/${API_VER}/containers/postgres/restart"
assert_no_socket_mount backend

# =============================================================================
# ADVISORY (NOT a gate) — cross-network issuer reachability (Phase 14 wires it).
# =============================================================================
echo
echo "============================================================"
echo " ADVISORY — cross-network issuer reachability (Phase 14)"
echo "============================================================"
echo "    The single public issuer (${POLIS_EXTERNAL_URL}) must eventually be reachable"
echo "    IDENTICALLY by the browser AND by Kratos server-side (split-horizon Pattern A)."
echo "    Phase 14 wires the Kratos egress + provider entry; this is an ADVISORY echo,"
echo "    NOT a gate this phase (RESEARCH Manual-Only Verifications)."
ADV_DISCOVERY="$($DC exec -T "$BACKEND_CONTAINER" curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  "http://polis:5225/.well-known/openid-configuration" 2>/dev/null || true)"
echo "    [advisory] internal GET http://polis:5225/.well-known/openid-configuration -> '${ADV_DISCOVERY:-<no response>}' (informational only)"

echo
summary
exit $?
