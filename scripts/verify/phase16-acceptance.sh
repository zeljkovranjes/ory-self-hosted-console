#!/usr/bin/env bash
# scripts/verify/phase16-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 16 (observability-profile-opt-in) live-stack acceptance gate — FINAL.
#
# Plan 16-04 FINALIZES this gate: the OBS-01 / OBS-02 assertions from 16-01 are
# kept, and the OBS-03 / OBS-04 / OBS-05 + FLAG-04 handshake assertions are now
# WIRED (no longer stubbed), plus the BACK-01 bundle-egress + Phase-13/14/15
# invariant regression. Every negative assertion is EXPLICIT (anti-false-green,
# lib.sh T-03 contract): a host curl to an observability port must be REFUSED (a
# refusal is the pass, a 200 is a fail); a flag-OFF observability route must 404;
# a flag-ON + profile-DOWN route must be profile_not_running, NEVER a raw 502.
#
#   OBS-01 (base, no profile): a plain `docker compose up -d --wait` (no profile)
#     starts the EXACT base service set; prometheus/grafana/loki/alloy are ABSENT
#     from `docker compose ps`. Explicit FAIL if any of the four is running.
#
#   OBS-01 (profile up): `docker compose --profile observability up -d --wait`
#     starts all four; NO NEW host-published port appears (the published-port set
#     equals the base run's); a HOST curl to the grafana/prometheus/loki ports is
#     REFUSED (anti-false-green: refusal passes, a 200 fails — INFRA-05).
#
#   OBS-02: from inside the internal network, `prometheus:9090/api/v1/targets`
#     reports all FIVE jobs `up`; `backend:8080/metrics` returns 200 text/plain
#     with NO per-identity label (grep). A1/A6 result is PRINTED for the SUMMARY.
#
#   v1-INVARIANT REGRESSION (extended with the profiled services):
#     INFRA-05 — no Ory admin port AND no observability port is host-published.
#     BACK-05  — the backend AND Alloy hold NO Docker socket (broker is sole holder).
#
#   STUBBED for later plans (printed as TODO, not asserted here):
#     OBS-03 Activity-from-Prometheus, OBS-04 Loki PII-masked search,
#     OBS-05 Grafana authed-proxy-only + no default creds, FLAG-04 flag-ON +
#     profile-DOWN -> profile_not_running (never 502).
#
# Run (Git Bash on Windows: prefix with MSYS_NO_PATHCONV=1 so leading-slash URL
# paths are not mangled). The script does the FULL lifecycle unless told to reuse:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase16-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up with the observability profile
#   SKIP_EGRESS=1    skip the (slow) frontend bundle-egress build assertion (BACK-01)
#   UP_TIMEOUT=1500  seconds for `docker compose up -d --wait` (default 1500)
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The four observability services + their internal-only ports (MUST be refused
# from the host — INFRA-05). Prometheus 9090, Loki 3100. NOTE: Grafana's internal
# container port is 3000, but it is NEVER host-published — and host :3000 is owned
# by the FRONTEND (a legitimate host-published service). So we do NOT host-curl
# :3000 here (it would hit the frontend, a false FAIL); the "no Grafana host port"
# guarantee is proven instead by the BASE_PORTS == PROFILE_PORTS diff below (the
# profile adds no new host-published port) + the internal-only Grafana proxy.
OBS_SERVICES="prometheus grafana loki alloy"
OBS_PORTS="9090 3100"
# The five Prometheus scrape jobs that must all report `up` (OBS-02).
SCRAPE_JOBS="kratos hydra keto oathkeeper backend"

detect_api_version() {
  local ver=""
  ver="$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="$(docker version --format '{{.Client.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="1.43"
  printf 'v%s' "$ver"
}
API_VER="$(detect_api_version)"

echo "=== Phase 16 acceptance: Observability Profile (opt-in) — FINAL ==="
echo "    (OBS-01/02/03/04/05 + FLAG-04 handshake + BACK-01/Phase-13/14/15 regression)"
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Docker API version: ${API_VER}"

teardown() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "KEEP_STACK=1 — leaving the stack up (run 'docker compose --profile observability down -v' to clean)."
    return 0
  fi
  echo
  echo "--- teardown: docker compose --profile observability down -v (stack down; ports 3000+3001 freed) ---"
  $DC --profile observability down -v --remove-orphans >/dev/null 2>&1 || true
  [ -n "${OBS04_EMITTER:-}" ] && docker rm -f "$OBS04_EMITTER" >/dev/null 2>&1 || true
  [ -n "${POLIS_ENV_FILE:-}" ] && rm -f "$POLIS_ENV_FILE" 2>/dev/null || true
}
trap teardown EXIT

# =============================================================================
# Ephemeral Polis-secret generation (mirror phase15). The base compose has
# `${POLIS_*:?}` guards (the Polis service + the backend env block) that abort
# `docker compose up` interpolation even for the base stack — so we GENERATE
# throwaway placeholders so the bring-up resolves. They are never committed; the
# stack is torn down (down -v) at the end. Polis itself is NOT started (it is not
# in the base service set we bring up here), but the guards must still resolve.
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true

_gen_b64() { openssl rand -base64 32 2>/dev/null | tr -d '\r\n' || node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64"))'; }
_gen_rsa_b64() {
  local priv_pem pub_pem
  priv_pem="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)" || return 1
  [ -n "$priv_pem" ] || return 1
  pub_pem="$(printf '%s' "$priv_pem" | openssl pkey -pubout 2>/dev/null)" || return 1
  [ -n "$pub_pem" ] || return 1
  POLIS_OPENID_RSA_PRIVATE_KEY="$(printf '%s' "$priv_pem" | base64 | tr -d '\r\n')"
  POLIS_OPENID_RSA_PUBLIC_KEY="$(printf '%s' "$pub_pem" | base64 | tr -d '\r\n')"
  [ "${#POLIS_OPENID_RSA_PRIVATE_KEY}" -ge 512 ] && [ "${#POLIS_OPENID_RSA_PUBLIC_KEY}" -ge 200 ]
}
_strip_cr() { printf '%s' "$1" | tr -d '\r\n'; }
POLIS_DB_PASSWORD="$(_strip_cr "${POLIS_DB_PASSWORD:-changeme_polis}")"
POLIS_DB_ENCRYPTION_KEY="$(_strip_cr "${POLIS_DB_ENCRYPTION_KEY:-$(_gen_b64)}")"
POLIS_API_KEY="$(_strip_cr "${POLIS_API_KEY:-$(_gen_b64)}")"
POLIS_NEXTAUTH_SECRET="$(_strip_cr "${POLIS_NEXTAUTH_SECRET:-$(_gen_b64)}")"
POLIS_EXTERNAL_URL="$(_strip_cr "${POLIS_EXTERNAL_URL:-http://localhost:5225}")"
if [ -z "${POLIS_OPENID_RSA_PRIVATE_KEY:-}" ] || [ -z "${POLIS_OPENID_RSA_PUBLIC_KEY:-}" ]; then
  if ! _gen_rsa_b64; then
    _fail "could not generate an ephemeral Polis RSA keypair — cannot bring the stack up"
    summary; exit $?
  fi
fi
POLIS_OPENID_RSA_PRIVATE_KEY="$(_strip_cr "$POLIS_OPENID_RSA_PRIVATE_KEY")"
POLIS_OPENID_RSA_PUBLIC_KEY="$(_strip_cr "$POLIS_OPENID_RSA_PUBLIC_KEY")"

POLIS_ENV_FILE="${REPO_ROOT}/.env.p16-acceptance-$$"
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

# --- helper: print the set of host-published ports across ALL running services -
# Uses `docker compose ps --format json` and extracts PublishedPort entries.
_published_host_ports() {
  $DC ps --format json 2>/dev/null | node -e '
    let input = require("fs").readFileSync(0,"utf8").trim();
    if (!input) process.exit(0);
    let rows=[];
    try { const p=JSON.parse(input); rows=Array.isArray(p)?p:[p]; }
    catch(e){ for(const l of input.split(/\r?\n/)){const t=l.trim(); if(!t)continue; try{rows.push(JSON.parse(t));}catch(_){}}}
    const ports=new Set();
    for(const r of rows){
      const pub=r.Publishers||r.Ports||[];
      if(Array.isArray(pub)){
        for(const p of pub){ const hp=p.PublishedPort||p.published||0; if(hp) ports.add(String(hp)); }
      }
    }
    process.stdout.write([...ports].sort().join(" "));
  ' 2>/dev/null
}

# --- helper: assert a service is ABSENT from `docker compose ps` (running set) -
assert_service_absent() {
  local svc="$1" triple
  triple="$(_ps_status_for "$svc")"
  if [ -z "$triple" ]; then
    _pass "assert_service_absent $svc: not running (correct for a no-profile up)"
    return 0
  fi
  _fail "assert_service_absent $svc: IS running ('$triple') — a plain up must NOT start it"
  return 1
}

# =============================================================================
# PHASE A — OBS-01 base path: plain `up` (NO profile) must NOT start the four.
# =============================================================================
if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- fresh-volume reset (down -v) ---"
  $DC --profile observability down -v --remove-orphans >/dev/null 2>&1 || true

  echo
  echo "============================================================"
  echo " OBS-01 (base) — plain \`docker compose up\` does NOT start"
  echo "                 prometheus/grafana/loki/alloy"
  echo "============================================================"
  echo "--- bring up the BASE stack (NO --profile observability) ---"
  echo "    (building backend + frontend; the Next image build can take several minutes)"
  if ! $DC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary; exit $?
  fi
  if $DC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "[OBS-01] base \`docker compose up -d --wait\`: healthy"
  else
    _fail "[OBS-01] base up did NOT reach healthy within ${UP_TIMEOUT}s"
    $DC logs --tail 30 backend 2>/dev/null || true
    summary; exit $?
  fi
fi

# The four observability services must be ABSENT on a plain up (the keystone of
# OBS-01: opt-in, default off).
echo
echo "--- [OBS-01] the four observability services are ABSENT on a plain up ---"
for svc in $OBS_SERVICES; do
  assert_service_absent "$svc"
done

# Capture the BASE published-port set so the profile-up diff can prove NO NEW port.
BASE_PORTS="$(_published_host_ports)"
echo "    base published host ports: [${BASE_PORTS}]"

# =============================================================================
# PHASE B — OBS-01 profile path: bring the profile up; assert NO NEW host port.
# =============================================================================
echo
echo "============================================================"
echo " OBS-01 (profile) — \`--profile observability up\` adds the"
echo "          four services with NO new host-published port"
echo "============================================================"
if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo "--- bring up the observability profile ---"
  if $DC --profile observability up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "[OBS-01] \`--profile observability up -d --wait\`: all four healthy/started"
  else
    _fail "[OBS-01] profile up did NOT reach healthy within ${UP_TIMEOUT}s"
    for s in $OBS_SERVICES; do echo "--- $s logs ---"; docker logs "$s" 2>&1 | tail -15 || true; done
    summary; exit $?
  fi
fi

# The four must now be present.
echo
echo "--- [OBS-01] the four observability services ARE running under the profile ---"
for svc in $OBS_SERVICES; do
  triple="$(_ps_status_for "$svc")"
  if [ -n "$triple" ]; then
    _pass "[OBS-01] $svc is running under the observability profile"
  else
    _fail "[OBS-01] $svc is NOT running with --profile observability"
  fi
done

# No NEW host-published port (INFRA-05): the profile-up port set equals the base.
echo
echo "--- [OBS-01] NO new host-published port appears with the profile (INFRA-05) ---"
PROFILE_PORTS="$(_published_host_ports)"
echo "    profile published host ports: [${PROFILE_PORTS}]"
if [ "$BASE_PORTS" = "$PROFILE_PORTS" ]; then
  _pass "[OBS-01] published host-port set UNCHANGED by the profile (no new host port)"
else
  _fail "[OBS-01] published host-port set CHANGED ('$BASE_PORTS' -> '$PROFILE_PORTS') — a profiled service published a host port (INFRA-05 violation)"
fi

# Anti-false-green: a HOST curl to each observability port must be REFUSED.
echo
echo "--- [OBS-01] host curl to grafana/prometheus/loki ports is REFUSED (INFRA-05) ---"
for port in $OBS_PORTS; do
  assert_port_refused "$port"
done

# =============================================================================
# PHASE C — OBS-02: Prometheus scrapes the five jobs; backend /metrics is clean.
# =============================================================================
echo
echo "============================================================"
echo " OBS-02 — Prometheus scrapes the four Ory admin metrics +"
echo "          backend /metrics (internal); /metrics is label-safe"
echo "============================================================"

# A1/A6 LIVE CHECK — curl each metrics endpoint from inside the network and PRINT
# the result so the SUMMARY can record A1/A6 resolved.
echo
echo "--- [A1/A6] live metrics-endpoint auth probe (from the backend container) ---"
_obs_metric_probe() {
  local name="$1" url="$2" code
  code="$($DC exec -T backend curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$url" 2>/dev/null)"
  echo "    A1/A6 ${name}: HTTP ${code}  (${url})"
  case "$code" in
    200) _pass "[OBS-02] ${name} metrics reachable internally, unauthenticated (200) — A1: no credential needed";;
    401|403) _fail "[OBS-02] ${name} metrics returned ${code} — A1: this job needs a bearer/credential in prometheus.yml";;
    *) _fail "[OBS-02] ${name} metrics returned '${code}' (want 200 internal)";;
  esac
}
_obs_metric_probe kratos     "http://kratos:4434/metrics/prometheus"
_obs_metric_probe hydra      "http://hydra:4445/admin/metrics/prometheus"   # A6: /admin prefix
_obs_metric_probe keto       "http://keto:4468/metrics/prometheus"
_obs_metric_probe oathkeeper "http://oathkeeper:9000/metrics/prometheus"
_obs_metric_probe backend    "http://backend:8080/metrics"

# All five Prometheus scrape jobs must report `up`.
echo
echo "--- [OBS-02] Prometheus reports all five scrape jobs \`up\` ---"
# Poll Prometheus across several scrape intervals: a freshly-started target shows
# health='unknown' until the first scrape completes. Loop until all five are up or
# the budget elapses (anti-false-green: we still assert each below).
_targets_all_up() {
  local json="$1" job h missing=0
  for job in $SCRAPE_JOBS; do
    h="$(printf '%s' "$json" | JOB="$job" node -e '
      const job=process.env.JOB;
      let d=""; try{d=require("fs").readFileSync(0,"utf8");}catch(e){process.exit(0);}
      let j; try{j=JSON.parse(d);}catch(e){process.exit(0);}
      const ts=(j.data&&j.data.activeTargets)||[];
      const t=ts.find(x=>x.labels&&x.labels.job===job);
      process.stdout.write(t?t.health:"absent");' 2>/dev/null)"
    [ "$h" = "up" ] || missing=1
  done
  return $missing
}
TARGETS_JSON=""
for _try in $(seq 1 24); do
  TARGETS_JSON="$($DC exec -T backend curl -s --max-time 10 'http://prometheus:9090/api/v1/targets?state=active' 2>/dev/null)"
  if _targets_all_up "$TARGETS_JSON"; then break; fi
  sleep 5
done
for job in $SCRAPE_JOBS; do
  up="$(printf '%s' "$TARGETS_JSON" | JOB="$job" node -e '
    const job=process.env.JOB;
    let d=""; try{d=require("fs").readFileSync(0,"utf8");}catch(e){process.exit(0);}
    let j; try{j=JSON.parse(d);}catch(e){process.exit(0);}
    const ts=(j.data&&j.data.activeTargets)||[];
    const t=ts.find(x=>x.labels&&x.labels.job===job);
    process.stdout.write(t?t.health:"absent");
  ' 2>/dev/null)"
  if [ "$up" = "up" ]; then
    _pass "[OBS-02] Prometheus scrape job '$job' is up"
  else
    _fail "[OBS-02] Prometheus scrape job '$job' health='$up' (want 'up')"
  fi
done

# backend /metrics: 200 text/plain, NO per-identity label (grep) — internal-only.
echo
echo "--- [OBS-02] backend /metrics is 200 text/plain with NO per-identity label ---"
METRICS_BODY="$($DC exec -T backend curl -s --max-time 8 http://backend:8080/metrics 2>/dev/null)"
if [ -z "$METRICS_BODY" ]; then
  _fail "[OBS-02] backend /metrics returned an EMPTY body (cannot confirm label-safety)"
else
  if printf '%s' "$METRICS_BODY" | grep -q 'console_'; then
    _pass "[OBS-02] backend /metrics renders a console-owned counter family"
  else
    _fail "[OBS-02] backend /metrics has no console_* counter family"
  fi
  # The no-per-identity-label assertion (T-16-04): NONE of the forbidden keys.
  if printf '%s' "$METRICS_BODY" | grep -Eq '(email=|identity_id=|session_id=|subject=|_id=)'; then
    _fail "[OBS-02] backend /metrics carries a FORBIDDEN per-identity label key (T-16-04 violation):"
    printf '%s\n' "$METRICS_BODY" | grep -Eo '(email=|identity_id=|session_id=|subject=|_id=)' | sort -u
  else
    _pass "[OBS-02] backend /metrics carries NO per-identity label key (counts/buckets only — T-16-04)"
  fi
fi

# =============================================================================
# AUTH BOOTSTRAP — an authenticated console session + CSRF for the flag PUTs and
# the observability routes (mirrors phase15's /setup + /login + per-session CSRF
# pattern; CONSOLE_INSECURE_COOKIES posture for the host-side cookie name).
# =============================================================================
echo
echo "============================================================"
echo " AUTH BOOTSTRAP — console session + CSRF (for the flag PUTs)"
echo "============================================================"

: "${SESSION_COOKIE_NAME:=console_session}"
ADMIN_EMAIL_TEST="phase16-admin@example.com"
ADMIN_PW_TEST="phase16-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)

echo
echo "--- [auth] complete /setup + login for an authenticated console session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"
state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1
if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase16 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
    "${BACKEND_BASE_URL}/setup" 2>/dev/null)"
  case "$setup_code" in
    201) _pass "[auth] completed /setup (admin created)";;
    404) _pass "[auth] /setup already completed on a prior run (404) — proceeding to login";;
    *)   _fail "[auth] /setup returned '$setup_code' (want 201 or 404-already-init)";;
  esac
elif [ "$already_init" = "1" ]; then
  _pass "[auth] console already initialized (re-run) — proceeding to login"
else
  _fail "[auth] could not parse FIRST-RUN SETUP TOKEN from backend logs AND console is not initialized"
fi

: "${POSTGRES_USER:=ory}"
_psql() { $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc "$1" 2>/dev/null | tr -d '\r'; }
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
  _psql "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
         WHERE a.email = '$1' ORDER BY s.created_at DESC LIMIT 1" | tr -d '[:space:]'
}

SESSION_TOKEN="$(_login_session_token "$ADMIN_EMAIL_TEST" "$ADMIN_PW_TEST")"
if [ -z "$SESSION_TOKEN" ]; then
  _fail "[auth] could not obtain a console session token from /login (OBS-03/04/05 + FLAG-04 cannot run)"
  COOKIE_HEADER=""; CSRF_TOKEN=""
else
  _pass "[auth] obtained an authenticated console session token from /login"
  COOKIE_HEADER="Cookie: ${SESSION_COOKIE_NAME}=${SESSION_TOKEN}"
  CSRF_TOKEN="$(_csrf_for_email "$ADMIN_EMAIL_TEST")"
  [ -n "$CSRF_TOKEN" ] && _pass "[auth] obtained the per-session CSRF token" \
    || _fail "[auth] could not read csrf_token from the session row (mutations would 403)"
fi

FEATURES_URL="${BACKEND_BASE_URL}/api/console/features"
ACTIVITY_URL="${BACKEND_BASE_URL}/api/console/metrics/activity"
LOGS_URL="${BACKEND_BASE_URL}/api/console/logs"
GRAFANA_PROXY_URL="${BACKEND_BASE_URL}/api/console/grafana/api/health"

_auth_get_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null; }
_auth_get_body() { curl -s --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null; }
_auth_mut_code() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 60 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_set_flag() {
  local key="$1" enabled="$2"
  _auth_mut_code PUT "${FEATURES_URL}/${key}" "{\"enabled\":${enabled}}" >/dev/null 2>&1 || true
}

if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo; _fail "no authenticated session/CSRF — skipping the live OBS-03/04/05 + FLAG-04 criteria"
else

# =============================================================================
# FLAG-04 (handshake, part 1: profile UP + flag ON) + OBS-03 — the Activity route
# returns Prometheus-DERIVED series, NOT the retired ACT-03 derived stub.
# The profile is UP here (Phase B brought it up).
# =============================================================================
echo
echo "============================================================"
echo " OBS-03 — Activity route returns Prometheus-derived series"
echo "          (flag ON + profile UP; not the ACT-03 derived stub)"
echo "============================================================"
_set_flag observability true

# Wait for the backend readiness PROBE to see the profile as running. The probe
# GETs Prometheus /-/ready + Loki /ready + Grafana /api/health; a freshly-started
# profile takes a few seconds before all three are ready (Loki/Grafana lag the
# `up --wait` health gate). Poll the live route until state=running or timeout.
echo
echo "--- [OBS-03] wait for the backend probe to see the profile as running ---"
PROFILE_READY=0
for _try in $(seq 1 30); do
  _ps="$(_auth_get_body "${ACTIVITY_URL}?intent=login-rate" | node -e '
    let d; try{d=JSON.parse(require("fs").readFileSync(0,"utf8"));}catch(e){process.exit(0);}
    process.stdout.write((d&&d.state)?d.state:"");' 2>/dev/null)"
  if [ "$_ps" = "running" ]; then PROFILE_READY=1; break; fi
  sleep 4
done
if [ "$PROFILE_READY" = "1" ]; then
  _pass "[OBS-03] the backend probe reports the profile running (Prometheus+Loki+Grafana ready)"
else
  _fail "[OBS-03] the backend probe never saw the profile running within the wait window (last state='${_ps}')"
fi

echo
echo "--- [OBS-03] GET /api/console/metrics/activity (flag ON, profile UP) -> 200 + source=prometheus, state=running ---"
ACT_BODY="$(_auth_get_body "${ACTIVITY_URL}?intent=login-rate")"
ACT_VERDICT="$(printf '%s' "$ACT_BODY" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  if (!d || typeof d !== "object") { process.stdout.write("NOTOBJ"); process.exit(0); }
  // Anti-false-green: the LIVE Prometheus surface MUST report source=prometheus
  // (never the retired "derived" stub) AND, profile-up, state=running with a
  // metric-backed result body (resultType + result array from Prometheus).
  if (d.source === "derived") { process.stdout.write("DERIVEDSTUB"); process.exit(0); }
  if (d.source !== "prometheus") { process.stdout.write("WRONGSOURCE:" + d.source); process.exit(0); }
  if (d.state !== "running") { process.stdout.write("NOTRUNNING:" + d.state); process.exit(0); }
  const r = d.result;
  if (!r || typeof r !== "object" || !("resultType" in r)) { process.stdout.write("NORESULT"); process.exit(0); }
  process.stdout.write("OK:" + r.resultType);
' 2>/dev/null)"
case "$ACT_VERDICT" in
  OK:*)        _pass "[OBS-03] Activity route is Prometheus-derived (source=prometheus, state=running, ${ACT_VERDICT#OK:} matrix/vector) — NOT the derived stub" ;;
  DERIVEDSTUB) _fail "[OBS-03] Activity route still returns the retired ACT-03 'derived' stub (OBS-03 not live)" ;;
  NORESULT)    _fail "[OBS-03] Activity route 200 but carries no Prometheus result body (cannot confirm metric-backed series)" ;;
  *)           _fail "[OBS-03] Activity route verdict='${ACT_VERDICT}' (want a prometheus/running result; body head: $(printf '%s' "$ACT_BODY" | head -c 200))" ;;
esac

# Anti-injection (T-16-09): an unknown intent is rejected 422 BEFORE any upstream
# call (the route never passes a raw operator query to Prometheus).
echo
echo "--- [OBS-03] an unknown Activity intent is rejected 422 (no raw PromQL passthrough — T-16-09) ---"
UNK_INTENT_CODE="$(_auth_get_code "${ACTIVITY_URL}?intent=up%7Bjob%3D%22kratos%22%7D")"
if [ "$UNK_INTENT_CODE" = "422" ] || [ "$UNK_INTENT_CODE" = "400" ]; then
  _pass "[OBS-03] unknown Activity intent -> ${UNK_INTENT_CODE} (closed-intent allowlist; no raw PromQL passthrough)"
else
  _fail "[OBS-03] unknown Activity intent -> ${UNK_INTENT_CODE} (want 422/400 reject)"
fi

# =============================================================================
# OBS-04 — push a log line with a KNOWN email marker through a container Alloy
# tails; query Loki through the backend /api/console/logs and assert the email is
# REDACTED + the label set is LOW-CARDINALITY (no per-identity label). EXPLICIT
# fail if the raw email appears.
# =============================================================================
echo
echo "============================================================"
echo " OBS-04 — Loki PII mask + low-cardinality labels"
echo "============================================================"

OBS04_EMAIL="obs04-pii-$$@example.com"
OBS04_MARKER="P16PIIMARKER$$"
OBS04_EMITTER="p16-pii-emitter-$$"
echo
echo "--- [OBS-04] emit a log line carrying ${OBS04_EMAIL} on a container's MAIN stdout (Alloy file-tails it) ---"
# Alloy file-tails EVERY container's json-file log under job="docker" — but ONLY
# the container's MAIN process stdout/stderr lands in /var/lib/docker/containers/
# <id>/<id>-json.log (a `docker exec ... echo` does NOT). So we spawn a SHORT-LIVED
# emitter container whose MAIN command echoes the marker+email to stdout. Its
# json-file log persists (no --rm) for Alloy to tail; we remove it at the end.
# Reuse the already-present postgres image (no pull). It shares the same Docker
# engine + json-file driver, so Alloy's glob picks it up.
docker rm -f "$OBS04_EMITTER" >/dev/null 2>&1 || true
# WR-04: emit THREE distinct marker lines so the gate can drive ALL the closed
# log intents the UI exposes (not just intent=all), turning WR-01/WR-02-style
# dead-path regressions into hard FAILs (anti-false-green):
#   (1) an info line carrying the PII email   -> intent=all (masking) + the
#                                                 intent=errors NEGATIVE (must be
#                                                 EXCLUDED, it is level=info).
#   (2) a line naming the `backend` service   -> intent=service&service=backend
#                                                 (WR-01: the by-service line filter
#                                                 must return it).
#   (3) an explicit level=error line          -> intent=errors (must be INCLUDED).
docker run -d --name "$OBS04_EMITTER" postgres:17-alpine \
  /bin/sh -c "for i in 1 2 3 4 5; do \
    echo \"${OBS04_MARKER} login attempt for ${OBS04_EMAIL} level=info\"; \
    echo \"${OBS04_MARKER} backend service heartbeat ok\"; \
    echo \"${OBS04_MARKER} backend level=error simulated failure for gate\"; \
    sleep 2; \
  done" \
  >/dev/null 2>&1 || true

# Confirm the emitter is actually running before we wait for its line (otherwise a
# missing line is an emitter problem, surfaced — not a silent NOTYET).
if [ -n "$(docker ps -q -f "name=${OBS04_EMITTER}" 2>/dev/null)" ] \
   || [ -n "$(docker ps -aq -f "name=${OBS04_EMITTER}" 2>/dev/null)" ]; then
  echo "    (emitter ${OBS04_EMITTER} started; waiting for Alloy to tail + ship the line to Loki…)"
else
  echo "    (WARNING: emitter container did not start — the OBS-04 line may be absent)"
fi
OBS04_HIT=""
OBS04_RAW_EMAIL=0
for _try in $(seq 1 20); do
  sleep 4
  LOGS_BODY="$(_auth_get_body "${LOGS_URL}?intent=all&range=600&limit=1000")"
  # Find our marker line and inspect whether the email is masked within it.
  OBS04_VERDICT="$(printf '%s' "$LOGS_BODY" | MARKER="$OBS04_MARKER" EMAIL="$OBS04_EMAIL" node -e '
    const marker=process.env.MARKER, email=process.env.EMAIL;
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
    const result = d && d.result;
    const streams = (result && result.result) || [];
    let found=false, rawEmail=false, masked=false;
    for (const s of streams) {
      for (const v of (s.values||[])) {
        const line = v[1] || "";
        if (line.indexOf(marker) === -1) continue;
        found=true;
        if (line.indexOf(email) !== -1) rawEmail=true;
        if (/REDACTED/.test(line)) masked=true;
      }
    }
    if (!found) { process.stdout.write("NOTYET"); process.exit(0); }
    if (rawEmail) { process.stdout.write("RAWEMAIL"); process.exit(0); }
    process.stdout.write(masked ? "MASKED" : "FOUND-NOEMAIL");
  ' 2>/dev/null)"
  if [ "$OBS04_VERDICT" = "MASKED" ] || [ "$OBS04_VERDICT" = "FOUND-NOEMAIL" ]; then
    OBS04_HIT="$OBS04_VERDICT"; break
  elif [ "$OBS04_VERDICT" = "RAWEMAIL" ]; then
    OBS04_HIT="RAWEMAIL"; OBS04_RAW_EMAIL=1; break
  fi
done

echo
echo "--- [OBS-04] the marker line is in Loki with the email REDACTED (raw email NEVER stored) ---"
case "$OBS04_HIT" in
  MASKED)        _pass "[OBS-04] the marker line is in Loki with the email masked (***REDACTED***) — PII scrubbed at ingestion (T-16-05)" ;;
  FOUND-NOEMAIL) _pass "[OBS-04] the marker line is in Loki and carries NO raw email (scrubbed at ingestion — T-16-05)" ;;
  RAWEMAIL)      _fail "[OBS-04] the RAW email ${OBS04_EMAIL} appears in the Loki line — PII mask FAILED (T-16-05 violation)" ;;
  *)             _fail "[OBS-04] the marker line never reached Loki within the wait window (last verdict='${OBS04_VERDICT}') — cannot confirm masking (anti-false-green)" ;;
esac

# Remove the throwaway emitter container (its log dir is cleaned with it).
docker rm -f "$OBS04_EMITTER" >/dev/null 2>&1 || true

# Low-cardinality labels: query the Loki label-names through the backend network
# and assert NO per-identity label key (email/identity_id/session_id/subject) is a
# stream label. Alloy applies only static low-card labels (job, stream).
echo
echo "--- [OBS-04] Loki stream labels are LOW-CARDINALITY (no per-identity label) ---"
LOKI_LABELS="$($DC exec -T backend curl -s --max-time 10 'http://loki:3100/loki/api/v1/labels' 2>/dev/null)"
LABELS_VERDICT="$(printf '%s' "$LOKI_LABELS" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  const labels = (d && d.data) || [];
  if (!Array.isArray(labels)) { process.stdout.write("NOLABELS"); process.exit(0); }
  const forbidden = labels.filter(l => /email|identity_id|session_id|subject|user_id|_id$/.test(l));
  process.stdout.write(forbidden.length ? ("HIGH:" + forbidden.join(",")) : ("LOW:" + labels.join(",")));
' 2>/dev/null)"
case "$LABELS_VERDICT" in
  LOW:*)  _pass "[OBS-04] Loki labels are low-cardinality (no per-identity label): ${LABELS_VERDICT#LOW:}" ;;
  HIGH:*) _fail "[OBS-04] Loki carries a FORBIDDEN per-identity stream label (high-cardinality / PII): ${LABELS_VERDICT#HIGH:}" ;;
  NOLABELS) _fail "[OBS-04] Loki returned no label list (cannot confirm low-cardinality — anti-false-green)" ;;
  *)      _fail "[OBS-04] could not read Loki labels (verdict='${LABELS_VERDICT}')" ;;
esac

# =============================================================================
# WR-04 — drive the CLOSED log intents the UI actually exposes (service, errors),
# not just intent=all. Before this, the gate only queried intent=all so the dead
# `{service=...}` selector (WR-01) and the errors line filter were never exercised
# — the green was hollow. Now a WR-01-style regression (by-service returns nothing)
# is a hard FAIL. The emitter (above) emitted the lines into Loki; they persist
# there independent of the now-removed emitter container.
#
# (a) intent=service&service=backend MUST return the marker line that names the
#     `backend` service (WR-01: the by-service line filter returns real data).
echo
echo "--- [WR-04/OBS-04] intent=service&service=backend returns the service-named marker line (WR-01 regression guard) ---"
OBS04_SVC_HIT=""
for _try in $(seq 1 12); do
  SVC_BODY="$(_auth_get_body "${LOGS_URL}?intent=service&service=backend&range=600&limit=1000")"
  OBS04_SVC_VERDICT="$(printf '%s' "$SVC_BODY" | MARKER="$OBS04_MARKER" node -e '
    const marker=process.env.MARKER;
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
    if (d && d.state && d.state !== "running") { process.stdout.write("STATE:"+d.state); process.exit(0); }
    const streams=((d&&d.result&&d.result.result))||[];
    let found=false;
    for (const s of streams) for (const v of (s.values||[])) {
      const line=v[1]||"";
      if (line.indexOf(marker)!==-1 && /backend/.test(line)) found=true;
    }
    process.stdout.write(found ? "HIT" : "NOTYET");
  ' 2>/dev/null)"
  if [ "$OBS04_SVC_VERDICT" = "HIT" ]; then OBS04_SVC_HIT="HIT"; break; fi
  sleep 4
done
if [ "$OBS04_SVC_HIT" = "HIT" ]; then
  _pass "[WR-04/OBS-04] intent=service&service=backend returned the backend-named marker line (by-service filter is LIVE — WR-01 fixed)"
else
  _fail "[WR-04/OBS-04] intent=service&service=backend returned NO backend-named marker line (last verdict='${OBS04_SVC_VERDICT}') — the by-service log path is DEAD (WR-01 regression)"
fi

# (b) intent=errors MUST INCLUDE the level=error marker line AND EXCLUDE the
#     level=info marker line (the cheap negative the gate can prove).
echo
echo "--- [WR-04/OBS-04] intent=errors includes the level=error line and EXCLUDES the level=info line ---"
ERR_BODY="$(_auth_get_body "${LOGS_URL}?intent=errors&range=600&limit=1000")"
OBS04_ERR_VERDICT="$(printf '%s' "$ERR_BODY" | MARKER="$OBS04_MARKER" node -e '
  const marker=process.env.MARKER;
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  if (d && d.state && d.state !== "running") { process.stdout.write("STATE:"+d.state); process.exit(0); }
  const streams=((d&&d.result&&d.result.result))||[];
  let sawError=false, sawInfo=false;
  for (const s of streams) for (const v of (s.values||[])) {
    const line=v[1]||"";
    if (line.indexOf(marker)===-1) continue;
    if (/level=error/.test(line)) sawError=true;
    if (/level=info/.test(line))  sawInfo=true;
  }
  if (sawInfo) { process.stdout.write("LEAKEDINFO"); process.exit(0); }
  process.stdout.write(sawError ? "OK" : "NOERROR");
' 2>/dev/null)"
case "$OBS04_ERR_VERDICT" in
  OK)         _pass "[WR-04/OBS-04] intent=errors includes the level=error marker line and excludes the level=info one (errors line filter is LIVE + correct)" ;;
  LEAKEDINFO) _fail "[WR-04/OBS-04] intent=errors returned a level=info marker line — the errors line filter is too broad (false-green)" ;;
  NOERROR)    _fail "[WR-04/OBS-04] intent=errors returned NO level=error marker line — the errors intent path is dead/broken" ;;
  STATE:*)    _fail "[WR-04/OBS-04] intent=errors profile state='${OBS04_ERR_VERDICT#STATE:}' (want running)" ;;
  *)          _fail "[WR-04/OBS-04] intent=errors verdict='${OBS04_ERR_VERDICT}' (cannot confirm the errors path)" ;;
esac

# (c) WR-02: the login-latency Activity panel must return a metric-backed series
#     (the http_request_duration_seconds histogram now exists + the latency_hoop
#     records it on every request, so the p95 query resolves). Drive a few backend
#     requests first to populate at least one bucket, then assert a result body.
echo
echo "--- [WR-04/OBS-03] login-latency Activity intent returns a metric-backed series (WR-02 regression guard) ---"
# Generate traffic so the histogram has buckets (any backend request is timed by
# the root latency_hoop). A handful of cheap state probes is enough.
for _ping in 1 2 3 4 5 6 7 8; do curl -s -o /dev/null --max-time 5 "${BACKEND_BASE_URL}/api/console/state" >/dev/null 2>&1 || true; done
OBS_LAT_HIT=""
for _try in $(seq 1 12); do
  LAT_BODY="$(_auth_get_body "${ACTIVITY_URL}?intent=login-latency")"
  OBS_LAT_VERDICT="$(printf '%s' "$LAT_BODY" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
    if (d && d.source && d.source !== "prometheus") { process.stdout.write("SRC:"+d.source); process.exit(0); }
    if (d && d.state && d.state !== "running") { process.stdout.write("STATE:"+d.state); process.exit(0); }
    const r=d&&d.result;
    if (!r || !("resultType" in r)) { process.stdout.write("NORESULT"); process.exit(0); }
    const arr=r.result;
    // A populated p95 query yields at least one series with a numeric value (not
    // NaN/empty). An EMPTY result array means the histogram is not being emitted
    // (the WR-02 dead-panel regression).
    let hasVal=false;
    if (Array.isArray(arr)) for (const s of arr) {
      const vals = s.values || (s.value ? [s.value] : []);
      for (const pair of vals) {
        const n = Number(pair && pair[1]);
        if (Number.isFinite(n)) hasVal=true;
      }
    }
    process.stdout.write(hasVal ? "HASDATA" : "EMPTY");
  ' 2>/dev/null)"
  if [ "$OBS_LAT_VERDICT" = "HASDATA" ]; then OBS_LAT_HIT="HASDATA"; break; fi
  # keep generating a little traffic between polls so a fresh rate window fills
  for _ping in 1 2 3 4; do curl -s -o /dev/null --max-time 5 "${BACKEND_BASE_URL}/api/console/state" >/dev/null 2>&1 || true; done
  sleep 5
done
if [ "$OBS_LAT_HIT" = "HASDATA" ]; then
  _pass "[WR-04/OBS-03] login-latency returned a metric-backed p95 value (http_request_duration_seconds histogram is LIVE — WR-02 fixed)"
else
  _fail "[WR-04/OBS-03] login-latency returned no metric-backed value (last verdict='${OBS_LAT_VERDICT}') — the latency histogram is not emitted (WR-02 regression)"
fi

# =============================================================================
# OBS-05 — Grafana: host curl refused (already proven in Phase B), internal
# admin/admin login FAILS, the backend authed-proxy reaches Grafana WITH the flag
# ON, and the proxy route 404s with the flag OFF (FeatureFlagHoop).
# =============================================================================
echo
echo "============================================================"
echo " OBS-05 — Grafana authed-proxy-only + no default admin/admin"
echo "============================================================"

echo
echo "--- [OBS-05] internal Grafana login with admin/admin FAILS (no default creds — T-16-03) ---"
# From inside the network, POST the Grafana login form with admin/admin. A 200 +
# a grafana_session cookie would mean the default creds work (FAIL). Grafana's
# login form is disabled (GF_AUTH_DISABLE_LOGIN_FORM) + the admin password is the
# secret file, so admin/admin must be rejected (401) or the form route gone (404).
# Capture BOTH the status AND whether a grafana_session cookie was granted. A 200
# WITH a session cookie is the only true "default creds work" failure; Grafana with
# the login form disabled (GF_AUTH_DISABLE_LOGIN_FORM) refuses with a 4xx OR a 3xx
# redirect to /login — neither grants a session. The anti-false-green proof is the
# ABSENCE of a session cookie on a non-error response.
ADMIN_ADMIN_HDRS="$($DC exec -T backend curl -s -D - -o /dev/null --max-time 10 \
  -X POST -H 'Content-Type: application/json' \
  --data '{"user":"admin","password":"admin"}' \
  'http://grafana:3000/login' 2>/dev/null)"
ADMIN_ADMIN_CODE="$(printf '%s' "$ADMIN_ADMIN_HDRS" | grep -iE '^HTTP/' | tail -n1 | awk '{print $2}')"
ADMIN_ADMIN_SESSION="$(printf '%s' "$ADMIN_ADMIN_HDRS" | grep -iE '^Set-Cookie:[[:space:]]*grafana_session=' | head -n1)"
if [ -n "$ADMIN_ADMIN_SESSION" ]; then
  _fail "[OBS-05] Grafana admin/admin login GRANTED a grafana_session cookie — DEFAULT CREDENTIALS ACTIVE (T-16-03 violation)"
else
  case "$ADMIN_ADMIN_CODE" in
    401|403|404|405|301|302|303) _pass "[OBS-05] Grafana admin/admin login REFUSED (${ADMIN_ADMIN_CODE}, no session granted) — no default creds (T-16-03)" ;;
    200)                         _fail "[OBS-05] Grafana admin/admin login returned 200 (no session cookie, but a 200 on /login POST is suspicious — investigate)" ;;
    *)                           _fail "[OBS-05] Grafana admin/admin login -> '${ADMIN_ADMIN_CODE}' (no session granted; unexpected status)" ;;
  esac
fi

echo
echo "--- [OBS-05] the backend authed Grafana proxy reaches Grafana WITH the flag ON (200) ---"
GRAFANA_PROXY_CODE="$(_auth_get_code "$GRAFANA_PROXY_URL")"
if [ "$GRAFANA_PROXY_CODE" = "200" ]; then
  _pass "[OBS-05] backend /api/console/grafana/api/health -> 200 (authed proxy reaches Grafana via X-WEBAUTH-USER)"
else
  _fail "[OBS-05] backend Grafana proxy -> ${GRAFANA_PROXY_CODE} (want 200 with the flag ON + profile up)"
fi

echo
echo "--- [OBS-05] the Grafana proxy route 404s with the observability flag OFF (FeatureFlagHoop) ---"
_set_flag observability false
GRAFANA_OFF_CODE="$(_auth_get_code "$GRAFANA_PROXY_URL")"
if [ "$GRAFANA_OFF_CODE" = "404" ]; then
  _pass "[OBS-05/FLAG] Grafana proxy with flag OFF -> 404 (gate beats a valid session+CSRF)"
elif [ "$GRAFANA_OFF_CODE" = "403" ]; then
  _fail "[OBS-05/FLAG] Grafana proxy with flag OFF -> 403 (csrf guard fired — gate proof INVALID)"
else
  _fail "[OBS-05/FLAG] Grafana proxy with flag OFF -> ${GRAFANA_OFF_CODE} (want 404)"
fi
# Also confirm the Activity + Logs routes 404 with the flag OFF (FLAG-01 / T-16-12).
echo
echo "--- [OBS-05/FLAG] Activity + Logs routes also 404 with the flag OFF ---"
for u in "${ACTIVITY_URL}?intent=login-rate" "${LOGS_URL}?intent=all"; do
  oc="$(_auth_get_code "$u")"
  if [ "$oc" = "404" ]; then
    _pass "[FLAG] $(printf '%s' "$u" | sed -E 's#.*/api/console/##;s/\?.*//') with flag OFF -> 404 (observability gate)"
  else
    _fail "[FLAG] $(printf '%s' "$u" | sed -E 's#.*/api/console/##;s/\?.*//') with flag OFF -> ${oc} (want 404)"
  fi
done

# =============================================================================
# FLAG-04 (handshake, part 2: flag ON + profile DOWN -> profile_not_running, NOT
# a raw 502). Bring the observability profile DOWN (keep the base stack up), set
# observability=ON, and assert /api/console/metrics/activity returns the tolerant
# profile_not_running 200 — NEVER a 502/500.
# =============================================================================
echo
echo "============================================================"
echo " FLAG-04 — flag ON + profile DOWN -> profile_not_running (never 502)"
echo "============================================================"
echo
echo "--- [FLAG-04] stop the observability profile services (keep the base stack up) ---"
$DC --profile observability stop prometheus loki grafana alloy >/dev/null 2>&1 || true
# Give the readiness probe a moment to see them gone.
sleep 3
_set_flag observability true

echo
echo "--- [FLAG-04] GET /api/console/metrics/activity (flag ON + profile DOWN) -> profile_not_running, NOT 502/500 ---"
FLAG04_RAW="$(curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${ACTIVITY_URL}?intent=login-rate" 2>/dev/null)"
FLAG04_CODE="$(printf '%s' "$FLAG04_RAW" | tail -n1)"
FLAG04_BODY="$(printf '%s' "$FLAG04_RAW" | sed '$d')"
FLAG04_STATE="$(printf '%s' "$FLAG04_BODY" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  process.stdout.write((d && d.state) ? d.state : "NOSTATE");
' 2>/dev/null)"
if [ "$FLAG04_CODE" = "502" ] || [ "$FLAG04_CODE" = "500" ]; then
  _fail "[FLAG-04] Activity with profile DOWN returned ${FLAG04_CODE} — a RAW upstream error leaked (FLAG-04 violation; must be profile_not_running)"
elif [ "$FLAG04_CODE" = "200" ] && [ "$FLAG04_STATE" = "profile_not_running" ]; then
  _pass "[FLAG-04] Activity with profile DOWN -> 200 + state=profile_not_running (tolerant handshake; never a 502)"
else
  _fail "[FLAG-04] Activity with profile DOWN -> code=${FLAG04_CODE} state=${FLAG04_STATE} (want 200 + profile_not_running)"
fi
# Logs route obeys the same tolerant contract.
echo
echo "--- [FLAG-04] GET /api/console/logs (flag ON + profile DOWN) -> profile_not_running, NOT 502/500 ---"
LOGS04_RAW="$(curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "${LOGS_URL}?intent=all" 2>/dev/null)"
LOGS04_CODE="$(printf '%s' "$LOGS04_RAW" | tail -n1)"
LOGS04_BODY="$(printf '%s' "$LOGS04_RAW" | sed '$d')"
LOGS04_STATE="$(printf '%s' "$LOGS04_BODY" | node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.stdout.write("BADJSON"); process.exit(0); }
  process.stdout.write((d && d.state) ? d.state : "NOSTATE");
' 2>/dev/null)"
if [ "$LOGS04_CODE" = "502" ] || [ "$LOGS04_CODE" = "500" ]; then
  _fail "[FLAG-04] Logs with profile DOWN returned ${LOGS04_CODE} — a RAW upstream error leaked (FLAG-04 violation)"
elif [ "$LOGS04_CODE" = "200" ] && [ "$LOGS04_STATE" = "profile_not_running" ]; then
  _pass "[FLAG-04] Logs with profile DOWN -> 200 + state=profile_not_running (tolerant handshake; never a 502)"
else
  _fail "[FLAG-04] Logs with profile DOWN -> code=${LOGS04_CODE} state=${LOGS04_STATE} (want 200 + profile_not_running)"
fi

# Reset the flag OFF (seeded default) so a re-run starts clean (best-effort).
_set_flag observability false

fi  # end: authenticated session/CSRF available

# =============================================================================
# v1 + Phase-13/14/15 INVARIANT REGRESSION SWEEP (Plan 04 — finalization).
#
# The base stack is up (the observability profile is now STOPPED again). Re-prove
# the load-bearing v1 + Phase-13/14/15 security invariants still hold now that the
# observability profile + backend observability routes exist. Asserted INLINE
# against the live stack (re-invoking each phaseN gate would tear down + rebuild
# its own fresh volume and collide with this one).
# =============================================================================
echo
echo "============================================================"
echo " v1 + Phase-13/14/15 INVARIANT REGRESSION (INFRA-05/BACK-05/BACK-01)"
echo "============================================================"

# --- INFRA-05: Ory admin ports + observability ports refused from the host -----
echo
echo "--- [INFRA-05 regression] Ory admin ports REFUSED from the host (4434/4445/4467/4469/4456) ---"
for port in 4434 4445 4467 4469 4456; do
  assert_port_refused "$port"
done
# The four observability ports are ALSO never host-published (re-assert).
echo
echo "--- [INFRA-05 regression] observability ports REFUSED from the host (grafana/prometheus/loki) ---"
for port in $OBS_PORTS; do
  assert_port_refused "$port"
done
# Polis admin/OIDC :5225 is NEVER host-published (Phase-13 INFRA-05).
echo
echo "--- [INFRA-05 regression] Polis admin/OIDC :5225 is NOT host-published ---"
assert_port_refused 5225
# Positive: the TRUSTED backend container reaches the Kratos admin API internally.
assert_internal_reachable backend "http://kratos:4434/health/ready"

# --- BACK-05: restart-broker default-deny scope + no socket on backend/Alloy ----
echo
echo "--- [BACK-05 regression] restart-broker default-deny scope (Ory restart allowed; list/stop/non-Ory denied) ---"
assert_broker_allowed POST "/${API_VER}/containers/ory-kratos/restart"
assert_broker_denied  GET  "/${API_VER}/containers/json"
assert_broker_denied  POST "/${API_VER}/containers/ory-kratos/stop"
assert_broker_denied  POST "/${API_VER}/containers/postgres/restart"
# The backend must NOT hold the docker socket — only the broker may. Alloy is the
# Phase-16 addition: it file-tails the json-file log dir and is NEVER routed
# through the broker, so it too must hold NO docker socket (16-01 decision).
echo
echo "--- [BACK-05 regression] neither the backend NOR Alloy holds the Docker socket (broker is sole holder) ---"
assert_no_socket_mount backend
# Alloy is STOPPED at this point (FLAG-04 stopped the profile). assert_no_socket_mount
# uses `docker compose ps -q` (running only), so it cannot inspect a stopped Alloy.
# If a stopped container record still exists, inspect it directly; otherwise assert
# against the compose config that the alloy service declares no docker.sock bind.
ALLOY_CID="$($DC ps -aq alloy 2>/dev/null | head -n1)"
if [ -n "$ALLOY_CID" ]; then
  if docker inspect "$ALLOY_CID" 2>/dev/null | node -e '
      let a; try{a=JSON.parse(require("fs").readFileSync(0,"utf8"));}catch(e){process.exit(1);}
      const c=Array.isArray(a)?a[0]:a; const m=(c&&c.Mounts)||[];
      const hit=m.some(x=>(x.Source&&x.Source.includes("docker.sock"))||(x.Destination&&x.Destination.includes("docker.sock")));
      process.exit(hit?1:0);' 2>/dev/null; then
    _pass "[BACK-05] alloy (stopped container ${ALLOY_CID}) holds no docker.sock mount (broker stays sole socket holder)"
  else
    _fail "[BACK-05] alloy container has a docker.sock mount (forbidden)"
  fi
else
  # Alloy container removed (profile down + down -v on a prior run); assert against
  # the compose config that the alloy service block carries no docker.sock bind.
  ALLOY_SOCK="$(awk '
    /^  alloy:/{f=1; next}
    f && /^  [a-zA-Z]/ {f=0}
    f && /docker\.sock/ {print}' "${REPO_ROOT}/docker-compose.yml" 2>/dev/null)"
  if [ -z "$ALLOY_SOCK" ]; then
    _pass "[BACK-05] alloy service declares NO docker.sock mount in docker-compose.yml (file-tail only — broker stays sole socket holder)"
  else
    _fail "[BACK-05] alloy service declares a docker.sock mount: $ALLOY_SOCK"
  fi
fi

# --- BACK-01: the FRONTEND container has NO direct route to any Ory admin port --
echo
echo "--- [BACK-01 regression] the FRONTEND container has NO direct route to Ory admin ports ---"
_frontend_can_reach() {
  local url="$1"
  $DC exec -T frontend node -e "
    fetch(process.argv[1], { signal: AbortSignal.timeout(4000) })
      .then(() => { process.stdout.write('OK'); })
      .catch(() => { process.stdout.write('REFUSED'); });
  " "$url" 2>/dev/null
}
for target in "http://kratos:4434/admin/identities" "http://hydra:4445/admin/clients" \
              "http://keto:4467/relation-tuples" "http://oathkeeper:4456/rules"; do
  fv="$(_frontend_can_reach "$target")"
  if [ "$fv" = "REFUSED" ]; then
    _pass "[BACK-01] frontend CANNOT reach ${target} (no direct frontend->Ory route)"
  else
    _fail "[BACK-01] frontend REACHED ${target} (verdict='$fv') — a direct frontend->Ory path exists!"
  fi
done

# --- BACK-01: the console CLIENT bundle carries NO observability host literal ---
# The Activity/Logs/Grafana surfaces egress ONLY through the same-origin /backend
# proxy; the Prometheus/Loki/Grafana internal hosts must never reach the bundle.
echo
echo "--- [BACK-01 regression] the console bundle carries no Prometheus/Loki/Grafana host literal ---"
if [ "${SKIP_EGRESS:-0}" != "1" ]; then
  FE_DIR="${REPO_ROOT}/frontend"
  FE_STATIC="${FE_DIR}/.next/static"
  if [ ! -d "$FE_STATIC" ]; then
    echo "    (no prior .next build — building the frontend once for the egress scan)"
    ( cd "$FE_DIR" && npm run build ) >/dev/null 2>&1 || true
  fi
  if [ -d "$FE_STATIC" ]; then
    OBS_FORBIDDEN='(//|@)(prometheus|loki|grafana)([/:."'"'"']|$)|(prometheus|loki|grafana):(9090|3100|3000)([^0-9]|$)'
    OBS_HITS="$(grep -rIEli "$OBS_FORBIDDEN" "$FE_STATIC" 2>/dev/null || true)"
    if [ -z "$OBS_HITS" ]; then
      _pass "[BACK-01] the console CLIENT bundle carries no Prometheus/Loki/Grafana host literal (egress via /backend only — T-16-14)"
    else
      _fail "[BACK-01] an observability host literal leaked into the console CLIENT bundle:"
      printf '%s\n' "$OBS_HITS"
    fi
  else
    _fail "[BACK-01] frontend .next/static not found after build — cannot assert egress (anti-false-green)"
  fi
else
  echo "    (SKIP_EGRESS=1 — skipping the console bundle-egress build)"
fi

# --- Phase-13/14/15: the flag-gated routes are not anonymously reachable -------
echo
echo "--- [Phase-13/14/15 regression] saml/organizations/observability protected routes are not anonymously reachable ---"
for purl in "${BACKEND_BASE_URL}/api/config/polis" "${BACKEND_BASE_URL}/api/sso/connections" \
            "${BACKEND_BASE_URL}/api/organizations" "${BACKEND_BASE_URL}/api/console/metrics/activity"; do
  pc="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$purl" 2>/dev/null)"
  if [ "$pc" = "401" ] || [ "$pc" = "404" ]; then
    _pass "[Phase-13/14/15] GET ${purl##*/api/} unauthenticated -> ${pc} (gated/guarded, not anonymously served)"
  else
    _fail "[Phase-13/14/15] GET ${purl##*/api/} unauthenticated -> ${pc} (want 401/404 — a guard regressed)"
  fi
done

echo
summary
exit $?
