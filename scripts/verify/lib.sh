#!/usr/bin/env bash
# scripts/verify/lib.sh
# -----------------------------------------------------------------------------
# Shared assert helpers for the Phase 1 (infrastructure-security-foundations)
# verification harness. Every Phase 1 success criterion maps to one of these
# helpers (see 01-VALIDATION.md "Per-Task Verification Map").
#
# Usage: a sourcing script does `source "$(dirname "$0")/lib.sh"`, calls the
# assert_* helpers, then calls `summary` at the end and exits with its status.
#
# Each helper prints a single PASS/FAIL line and, on failure, increments the
# global ASSERT_FAILURES counter so the sourcing script can exit non-zero on
# ANY failed assertion (threat T-03-false-green: negative assertions PASS only
# on the explicit failure/403 outcome, never on absence of output).
#
# Helpers parse `docker compose ... --format json` with `node` (Node toolchain
# is confirmed present per CLAUDE.md) and fall back to `jq` if node is absent.
# No secrets are echoed; POSTGRES_USER is read from env with a sensible default.
# -----------------------------------------------------------------------------

# --- Global counters ---------------------------------------------------------
: "${ASSERT_PASSES:=0}"
: "${ASSERT_FAILURES:=0}"

# --- Config (overridable via env) --------------------------------------------
: "${POSTGRES_USER:=ory}"
# Docker compose binary (allow override for `docker-compose` v1 shims / tests).
: "${DC:=docker compose}"

# --- Output helpers ----------------------------------------------------------
_pass() {
  ASSERT_PASSES=$((ASSERT_PASSES + 1))
  printf 'PASS: %s\n' "$*"
}

_fail() {
  ASSERT_FAILURES=$((ASSERT_FAILURES + 1))
  printf 'FAIL: %s\n' "$*"
}

# --- JSON helper -------------------------------------------------------------
# _json_eval <node-expression-over-stdin-parsed-as-`data`>
# Reads JSON from stdin, parses it, and evaluates a JS expression where the
# parsed value is bound to `data`. Prefers node; falls back to jq when given a
# jq-compatible filter via _json_eval_jq. We standardize on node here.
_have_node() { command -v node >/dev/null 2>&1; }
_have_jq()   { command -v jq   >/dev/null 2>&1; }

# Parse `docker compose ps --format json` (which emits either a JSON array or
# one JSON object per line depending on Compose version) and print, for a given
# service, a `health|state|exitcode` triple. Empty if the service is absent.
_ps_status_for() {
  # $1 = service name
  local svc="$1"
  local raw
  raw="$($DC ps --all --format json 2>/dev/null)" || return 1
  if _have_node; then
    printf '%s' "$raw" | SVC="$svc" node -e '
      const svc = process.env.SVC;
      let input = require("fs").readFileSync(0, "utf8").trim();
      if (!input) process.exit(0);
      let rows = [];
      // Compose may emit a single JSON array, or newline-delimited objects.
      try {
        const parsed = JSON.parse(input);
        rows = Array.isArray(parsed) ? parsed : [parsed];
      } catch (e) {
        for (const line of input.split(/\r?\n/)) {
          const t = line.trim();
          if (!t) continue;
          try { rows.push(JSON.parse(t)); } catch (_) { /* skip */ }
        }
      }
      const r = rows.find(x =>
        x && (x.Service === svc || x.Name === svc || x.Names === svc));
      if (!r) process.exit(0);
      const health = r.Health || "";
      const state = r.State || "";
      const exitCode = (r.ExitCode === undefined || r.ExitCode === null) ? "" : r.ExitCode;
      process.stdout.write(`${health}|${state}|${exitCode}`);
    '
  elif _have_jq; then
    # jq fallback: handle array or stream of objects via --slurp + flatten.
    printf '%s' "$raw" | jq -rs --arg svc "$svc" '
      (if (.[0]|type) == "array" then .[0] else . end)
      | map(select(.Service == $svc or .Name == $svc or .Names == $svc))
      | .[0] // {}
      | "\(.Health // "")|\(.State // "")|\(.ExitCode // "")"
    '
  else
    echo "ERROR: neither node nor jq available to parse JSON" >&2
    return 2
  fi
}

# --- assert_healthy <service> ------------------------------------------------
# PASS when the service Health == "healthy". For one-shot migrate containers
# that have no healthcheck, PASS when State == exited AND ExitCode == 0.
assert_healthy() {
  local svc="$1"
  local triple health state exitcode
  triple="$(_ps_status_for "$svc")"
  if [ -z "$triple" ]; then
    _fail "assert_healthy $svc: service not found in 'docker compose ps'"
    return 1
  fi
  health="${triple%%|*}"
  state="$(printf '%s' "$triple" | cut -d'|' -f2)"
  exitcode="${triple##*|}"
  if [ "$health" = "healthy" ]; then
    _pass "assert_healthy $svc: healthy"
    return 0
  fi
  # One-shot migrate container path: no healthcheck, must have exited cleanly.
  if [ "$state" = "exited" ] && [ "$exitcode" = "0" ]; then
    _pass "assert_healthy $svc: exited 0 (one-shot)"
    return 0
  fi
  _fail "assert_healthy $svc: health='$health' state='$state' exit='$exitcode'"
  return 1
}

# --- assert_exited_zero <service> -------------------------------------------
# Strict one-shot assertion: State == exited && ExitCode == 0 (migrate gates).
assert_exited_zero() {
  local svc="$1"
  local triple state exitcode
  triple="$(_ps_status_for "$svc")"
  if [ -z "$triple" ]; then
    _fail "assert_exited_zero $svc: service not found"
    return 1
  fi
  state="$(printf '%s' "$triple" | cut -d'|' -f2)"
  exitcode="${triple##*|}"
  if [ "$state" = "exited" ] && [ "$exitcode" = "0" ]; then
    _pass "assert_exited_zero $svc: exited 0"
    return 0
  fi
  _fail "assert_exited_zero $svc: state='$state' exit='$exitcode' (want exited/0)"
  return 1
}

# --- assert_db_exists <db> ---------------------------------------------------
# PASS when SELECT 1 FROM pg_database WHERE datname='<db>' returns 1.
assert_db_exists() {
  local db="$1"
  local out
  out="$($DC exec -T postgres psql -U "$POSTGRES_USER" -tAc \
        "SELECT 1 FROM pg_database WHERE datname='${db}'" 2>/dev/null | tr -d '[:space:]')"
  if [ "$out" = "1" ]; then
    _pass "assert_db_exists $db: present"
    return 0
  fi
  _fail "assert_db_exists $db: not found (got '$out')"
  return 1
}

# --- assert_port_refused <port> ----------------------------------------------
# Negative security assertion (INFRA-05). From the HOST, the admin port MUST
# NOT be reachable. PASS only when the curl FAILS (connection refused / no
# route / timeout). A 200/anything-reachable is a FAIL. PASS is never granted
# merely because output is empty — curl's non-zero exit is the explicit signal.
assert_port_refused() {
  local port="$1"
  if curl --max-time 3 -sf "http://localhost:${port}/" >/dev/null 2>&1; then
    _fail "assert_port_refused $port: host could REACH localhost:$port (admin port exposed!)"
    return 1
  fi
  _pass "assert_port_refused $port: refused/unreachable from host"
  return 0
}

# --- assert_internal_reachable <fromsvc> <url> -------------------------------
# Positive assertion (INFRA-05): the admin API IS reachable on the internal
# network from a trusted container. PASS when curl -sf returns success (HTTP 2xx).
assert_internal_reachable() {
  local fromsvc="$1" url="$2"
  if $DC exec -T "$fromsvc" curl -sf "$url" >/dev/null 2>&1; then
    _pass "assert_internal_reachable $fromsvc -> $url: 200"
    return 0
  fi
  _fail "assert_internal_reachable $fromsvc -> $url: not reachable internally"
  return 1
}

# --- _broker_status <method> <path> ------------------------------------------
# Issue an HTTP <method> from the backend container against the restart-broker
# and echo the numeric HTTP status code.
_broker_status() {
  local method="$1" path="$2"
  $DC exec -T backend curl -s -o /dev/null -w "%{http_code}" \
    -X"$method" "http://restart-broker:2375${path}" 2>/dev/null
}

# --- assert_broker_allowed <method> <path> -----------------------------------
# PASS when the broker returns a 2xx (allowed scoped restart). 204/200/201 ok.
assert_broker_allowed() {
  local method="$1" path="$2" code
  code="$(_broker_status "$method" "$path")"
  case "$code" in
    2??) _pass "assert_broker_allowed $method $path: $code"; return 0 ;;
    *)   _fail "assert_broker_allowed $method $path: got '$code' (want 2xx)"; return 1 ;;
  esac
}

# --- assert_broker_denied <method> <path> ------------------------------------
# Negative security assertion (BACK-05). PASS ONLY on an explicit 403 (the
# proxy's default-deny verdict). Any 2xx (the call went through) is a FAIL.
# A connection error returns empty code -> FAIL (we will not green on absence).
assert_broker_denied() {
  local method="$1" path="$2" code
  code="$(_broker_status "$method" "$path")"
  if [ "$code" = "403" ]; then
    _pass "assert_broker_denied $method $path: 403 (denied)"
    return 0
  fi
  _fail "assert_broker_denied $method $path: got '$code' (want 403 default-deny)"
  return 1
}

# --- assert_no_socket_mount <service> ----------------------------------------
# Negative security assertion (BACK-05). PASS when the container has NO
# /var/run/docker.sock in its Mounts (only the broker may hold the socket).
assert_no_socket_mount() {
  local svc="$1" cid mounts
  cid="$($DC ps -q "$svc" 2>/dev/null | head -n1)"
  if [ -z "$cid" ]; then
    _fail "assert_no_socket_mount $svc: container not found"
    return 1
  fi
  # Inspect the Mounts array's Source + Destination for the docker socket.
  if _have_node; then
    mounts="$(docker inspect "$cid" 2>/dev/null | node -e '
      let input = require("fs").readFileSync(0, "utf8").trim();
      if (!input) process.exit(0);
      let arr;
      try { arr = JSON.parse(input); } catch (e) { process.exit(0); }
      const c = Array.isArray(arr) ? arr[0] : arr;
      const m = (c && c.Mounts) || [];
      const hit = m.some(x =>
        (x.Source && x.Source.includes("docker.sock")) ||
        (x.Destination && x.Destination.includes("docker.sock")));
      process.stdout.write(hit ? "SOCKET" : "CLEAN");
    ')"
  elif _have_jq; then
    mounts="$(docker inspect "$cid" 2>/dev/null | jq -r '
      .[0].Mounts // []
      | if any(.Source // "" | contains("docker.sock"))
           or any(.Destination // "" | contains("docker.sock"))
        then "SOCKET" else "CLEAN" end')"
  else
    _fail "assert_no_socket_mount $svc: no node/jq to parse docker inspect"
    return 2
  fi
  if [ "$mounts" = "CLEAN" ]; then
    _pass "assert_no_socket_mount $svc: no docker.sock mounted"
    return 0
  fi
  _fail "assert_no_socket_mount $svc: docker.sock IS mounted (forbidden)"
  return 1
}

# --- assert_mount_rw <service> <dest-substring> <expected: true|false> -------
# Inspect a container's bind mount whose Destination contains <dest-substring>
# and assert its RW flag matches <expected> (INFRA-07 ro/rw split).
assert_mount_rw() {
  local svc="$1" dest="$2" expected="$3" cid actual
  cid="$($DC ps -q "$svc" 2>/dev/null | head -n1)"
  if [ -z "$cid" ]; then
    _fail "assert_mount_rw $svc ($dest): container not found"
    return 1
  fi
  if _have_node; then
    actual="$(docker inspect "$cid" 2>/dev/null | DEST="$dest" node -e '
      const dest = process.env.DEST;
      let input = require("fs").readFileSync(0, "utf8").trim();
      if (!input) process.exit(0);
      let arr;
      try { arr = JSON.parse(input); } catch (e) { process.exit(0); }
      const c = Array.isArray(arr) ? arr[0] : arr;
      const m = (c && c.Mounts) || [];
      const hit = m.find(x => x.Destination && x.Destination.includes(dest));
      if (!hit) process.exit(0);
      process.stdout.write(String(hit.RW === true));
    ')"
  elif _have_jq; then
    actual="$(docker inspect "$cid" 2>/dev/null | jq -r --arg dest "$dest" '
      .[0].Mounts // []
      | map(select(.Destination // "" | contains($dest)))
      | .[0] // empty
      | (.RW // false) | tostring')"
  else
    _fail "assert_mount_rw $svc ($dest): no node/jq to parse docker inspect"
    return 2
  fi
  if [ -z "$actual" ]; then
    _fail "assert_mount_rw $svc ($dest): no matching mount found"
    return 1
  fi
  if [ "$actual" = "$expected" ]; then
    _pass "assert_mount_rw $svc ($dest): RW=$actual (expected $expected)"
    return 0
  fi
  _fail "assert_mount_rw $svc ($dest): RW=$actual (expected $expected)"
  return 1
}

# --- assert_grep <pattern> <file> --------------------------------------------
# Static-file assertion. PASS when the extended-regex pattern is present.
assert_grep() {
  local pattern="$1" file="$2"
  if [ ! -f "$file" ]; then
    _fail "assert_grep '$pattern' $file: file does not exist"
    return 1
  fi
  if grep -Eq "$pattern" "$file"; then
    _pass "assert_grep '$pattern' $file: found"
    return 0
  fi
  _fail "assert_grep '$pattern' $file: NOT found"
  return 1
}

# --- assert_not_grep <pattern> <file> ----------------------------------------
# Static-file negative assertion. PASS when the pattern is ABSENT.
assert_not_grep() {
  local pattern="$1" file="$2"
  if [ ! -f "$file" ]; then
    _fail "assert_not_grep '$pattern' $file: file does not exist"
    return 1
  fi
  if grep -Eq "$pattern" "$file"; then
    _fail "assert_not_grep '$pattern' $file: pattern PRESENT (must be absent)"
    return 1
  fi
  _pass "assert_not_grep '$pattern' $file: absent"
  return 0
}

# --- assert_grep_count <pattern> <file> <expected-count> ---------------------
# Static-file assertion with an exact match count (e.g. exactly 4 image pins).
# Counts matching lines, ignoring comment-only lines (leading # or whitespace#).
assert_grep_count() {
  local pattern="$1" file="$2" expected="$3" actual
  if [ ! -f "$file" ]; then
    _fail "assert_grep_count '$pattern' $file: file does not exist"
    return 1
  fi
  # Strip full-line comments before counting so a commented pin can't inflate it.
  actual="$(grep -Ev '^[[:space:]]*#' "$file" | grep -Ec "$pattern")"
  if [ "$actual" = "$expected" ]; then
    _pass "assert_grep_count '$pattern' $file: $actual (expected $expected)"
    return 0
  fi
  _fail "assert_grep_count '$pattern' $file: $actual (expected $expected)"
  return 1
}

# --- summary -----------------------------------------------------------------
# Print totals and set the conventional exit code. The sourcing script should
# call `summary; exit $?` (or `exit $(summary >/dev/null; echo $?)`).
summary() {
  printf -- '----------------------------------------\n'
  printf 'PASS: %d   FAIL: %d\n' "$ASSERT_PASSES" "$ASSERT_FAILURES"
  if [ "$ASSERT_FAILURES" -gt 0 ]; then
    printf 'RESULT: FAILED (%d assertion(s) failed)\n' "$ASSERT_FAILURES"
    return 1
  fi
  printf 'RESULT: PASSED\n'
  return 0
}
