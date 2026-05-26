#!/usr/bin/env bash
# scripts/verify/phase16-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 16 (observability-profile-opt-in) live-stack acceptance gate — SCAFFOLD.
#
# Plan 16-01 delivers this scaffold with the OBS-01 / OBS-02 assertions WIRED and
# the OBS-03 / OBS-04 / OBS-05 + FLAG-04 handshake assertions STUBBED as
# `TODO(16-02/16-04)` so the later plans fill them. Every negative assertion is
# EXPLICIT (anti-false-green, lib.sh T-03 contract): a host curl to an
# observability port must be REFUSED (a refusal is the pass, a 200 is a fail).
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
#   UP_TIMEOUT=1500  seconds for `docker compose up -d --wait` (default 1500)
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The four observability services + their internal-only ports (MUST be refused
# from the host — INFRA-05). Grafana 3000, Prometheus 9090, Loki 3100.
OBS_SERVICES="prometheus grafana loki alloy"
OBS_PORTS="3000 9090 3100"
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

echo "=== Phase 16 acceptance: Observability Profile (opt-in) — SCAFFOLD ==="
echo "    (OBS-01/OBS-02 wired; OBS-03/04/05 + FLAG-04 handshake stubbed for 16-02/16-04)"
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Docker API version: ${API_VER}"

teardown() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "KEEP_STACK=1 — leaving the stack up (run 'docker compose --profile observability down -v' to clean)."
    return 0
  fi
  echo
  echo "--- teardown: docker compose --profile observability down -v ---"
  $DC --profile observability down -v >/dev/null 2>&1 || true
}
trap teardown EXIT

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
  if ! $DC build backend >/dev/null 2>&1; then
    _fail "docker compose build backend FAILED"
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
# Give Prometheus a couple scrape intervals to mark targets up.
sleep 5
TARGETS_JSON="$($DC exec -T backend curl -s --max-time 10 'http://prometheus:9090/api/v1/targets?state=active' 2>/dev/null)"
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
# v1-INVARIANT REGRESSION (extended with the profiled services).
# =============================================================================
echo
echo "============================================================"
echo " v1-INVARIANT REGRESSION — INFRA-05 / BACK-05 (+ Alloy)"
echo "============================================================"
echo
echo "--- [BACK-05] neither the backend NOR Alloy holds the Docker socket ---"
assert_no_socket_mount backend
assert_no_socket_mount alloy

# =============================================================================
# STUBS — OBS-03 / OBS-04 / OBS-05 / FLAG-04 handshake (filled by 16-02/16-04).
# =============================================================================
echo
echo "============================================================"
echo " STUBS for later plans (printed, NOT asserted in 16-01)"
echo "============================================================"
echo "TODO(16-02/16-04) OBS-03: Activity route returns Prometheus-derived series (not the ACT-03 derived stub)."
echo "TODO(16-02/16-04) OBS-04: push a log line with an email through a container; Loki query returns ***REDACTED***, low-cardinality labels only."
echo "TODO(16-02/16-04) OBS-05: host curl to grafana refused; internal admin/admin login fails; backend authed-proxy reaches Grafana; flag-OFF -> 404."
echo "TODO(16-02/16-04) FLAG-04: flag observability=ON + profile NOT up -> /api/console/activity returns structured profile_not_running (NEVER 502/500)."
echo "TODO(16-04) BACK-01 bundle-egress + Phase 13/14/15 regression re-run."

echo
summary
exit $?
