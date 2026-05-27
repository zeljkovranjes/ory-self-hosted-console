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
# is confirmed present per the project guide) and fall back to `jq` if node is absent.
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
# Negative security assertion (INFRA-05). From the HOST, the admin port MUST be
# unreachable at the CONNECTION level. We must distinguish a true connection
# failure (refused / no route / timeout) from a reachable port that merely
# returns a non-2xx HTTP status (CR-03): an exposed admin port whose `/` returns
# 404 would, under `curl -f`, exit non-zero and FALSE-GREEN this gate. So we DROP
# `-f` and inspect curl's exit code:
#   7  = connection refused / could not connect   -> PASS (genuinely unreachable)
#   28 = operation timed out                       -> PASS (no host route)
#   6  = could not resolve host                    -> PASS (no route)
#   0 (or any HTTP status received, e.g. 404/200)  -> FAIL (TCP connect SUCCEEDED
#                                                     => the admin port IS exposed)
# Any successful TCP connect — regardless of HTTP status — is a FAIL. PASS is
# never granted merely because output is empty; it requires an explicit
# connection-level failure exit code (threat T-03-false-green).
assert_port_refused() {
  local port="$1" rc
  # `|| true` so a non-zero curl exit does not trip the caller's `set -e`; we
  # capture the real exit code from PIPESTATUS-free direct invocation below.
  curl --max-time 3 -s -o /dev/null "http://localhost:${port}/" >/dev/null 2>&1 && rc=0 || rc=$?
  case "$rc" in
    7|28|6)
      _pass "assert_port_refused $port: refused/unreachable from host (curl rc=$rc)"
      return 0
      ;;
    *)
      _fail "assert_port_refused $port: host REACHED localhost:$port (curl rc=$rc — admin port exposed!)"
      return 1
      ;;
  esac
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
# Negative security assertion (BACK-05). PASS ONLY on an EXPLICIT default-deny
# verdict from the proxy. wollomatic/socket-proxy distinguishes two deny codes:
#   - 403 Forbidden          -> path/source not in the allowlist
#   - 405 Method Not Allowed -> the HTTP method has no allow rule at all
# Both are explicit rejections by the default-deny proxy (the request never
# reaches the Docker socket). We accept either. Any 2xx (the call went THROUGH)
# is a FAIL, and an empty code (connection error) is a FAIL — we never green on
# absence of output (threat T-03-false-green).
assert_broker_denied() {
  local method="$1" path="$2" code
  code="$(_broker_status "$method" "$path")"
  case "$code" in
    403|405)
      _pass "assert_broker_denied $method $path: $code (denied)"
      return 0
      ;;
    *)
      _fail "assert_broker_denied $method $path: got '$code' (want explicit deny 403/405)"
      return 1
      ;;
  esac
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

# =============================================================================
# Phase 2 auth assert helpers (live-stack HTTP).
#
# Base URL is overridable; defaults to the host-published backend port.
# Every NEGATIVE helper obeys the anti-false-green contract (T-03): it PASSes
# only on the EXPLICIT expected code/condition and FAILs on empty output or any
# unexpected (often 2xx) result — never green merely because output is empty.
# =============================================================================
: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"

# --- assert_status <method> <url> <expected_code> ----------------------------
# Issue <method> <url> and PASS only when the HTTP status EXACTLY equals
# <expected_code>. Optional request body via $REQ_DATA (sent as JSON) and extra
# header via $REQ_HEADER. An empty/unreadable code (connection error) FAILs.
assert_status() {
  local method="$1" url="$2" expected="$3" code
  local -a curlargs=(-s -o /dev/null -w '%{http_code}' --max-time 10 -X "$method")
  if [ -n "${REQ_DATA:-}" ]; then
    curlargs+=(-H 'Content-Type: application/json' --data "$REQ_DATA")
  fi
  if [ -n "${REQ_HEADER:-}" ]; then
    curlargs+=(-H "$REQ_HEADER")
  fi
  code="$(curl "${curlargs[@]}" "$url" 2>/dev/null)"
  if [ -z "$code" ]; then
    _fail "assert_status $method $url: no response (connection error; want $expected)"
    return 1
  fi
  if [ "$code" = "$expected" ]; then
    _pass "assert_status $method $url: $code (expected $expected)"
    return 0
  fi
  _fail "assert_status $method $url: got '$code' (expected $expected)"
  return 1
}

# --- assert_route_absent <url> -----------------------------------------------
# Negative assertion: a route that must NOT exist (e.g. /auth/github/login when
# OAuth is unconfigured, or /setup after init). PASS ONLY on an explicit 404.
# Any 2xx/3xx (route present) or empty code (connection error) FAILs.
assert_route_absent() {
  local url="$1" code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null)"
  if [ -z "$code" ]; then
    _fail "assert_route_absent $url: no response (connection error; want 404)"
    return 1
  fi
  if [ "$code" = "404" ]; then
    _pass "assert_route_absent $url: 404 (absent)"
    return 0
  fi
  _fail "assert_route_absent $url: got '$code' (route PRESENT; want 404)"
  return 1
}

# --- assert_set_cookie_flags <url> <data> ------------------------------------
# POST <data> (JSON) to <url> and inspect the response headers. PASS ONLY when a
# `Set-Cookie: __Host-console_session=...` line is present AND carries HttpOnly,
# Secure, SameSite=Lax, and Path=/. Missing header or any missing flag FAILs
# (never green on empty headers).
assert_set_cookie_flags() {
  local url="$1" data="$2" headers line
  headers="$(curl -s -D - -o /dev/null --max-time 10 \
      -H 'Content-Type: application/json' --data "$data" "$url" 2>/dev/null)"
  if [ -z "$headers" ]; then
    _fail "assert_set_cookie_flags $url: no response headers (connection error)"
    return 1
  fi
  # Extract the session Set-Cookie line (case-insensitive header name).
  line="$(printf '%s' "$headers" | grep -iE '^Set-Cookie:[[:space:]]*__Host-console_session=' | head -n1)"
  if [ -z "$line" ]; then
    _fail "assert_set_cookie_flags $url: no '__Host-console_session' Set-Cookie present"
    return 1
  fi
  local missing=""
  printf '%s' "$line" | grep -qi 'HttpOnly'      || missing="$missing HttpOnly"
  printf '%s' "$line" | grep -qi 'Secure'        || missing="$missing Secure"
  printf '%s' "$line" | grep -qi 'SameSite=Lax'  || missing="$missing SameSite=Lax"
  printf '%s' "$line" | grep -qi 'Path=/'        || missing="$missing Path=/"
  if [ -n "$missing" ]; then
    _fail "assert_set_cookie_flags $url: cookie missing flag(s):$missing"
    return 1
  fi
  _pass "assert_set_cookie_flags $url: __Host-console_session HttpOnly+Secure+SameSite=Lax+Path=/"
  return 0
}

# --- assert_no_secret_in_body <method> <url> ---------------------------------
# Fetch the response body and PASS ONLY when it is non-empty AND contains NONE
# of the secret markers (password_hash, token_hash, bootstrap, client_secret,
# $argon2, postgres:// DSN). An EMPTY body FAILs (anti-false-green: we never
# green on absence of output). Optional $REQ_DATA / $REQ_HEADER as in assert_status.
assert_no_secret_in_body() {
  local method="$1" url="$2" body
  local -a curlargs=(-s --max-time 10 -X "$method")
  if [ -n "${REQ_DATA:-}" ]; then
    curlargs+=(-H 'Content-Type: application/json' --data "$REQ_DATA")
  fi
  if [ -n "${REQ_HEADER:-}" ]; then
    curlargs+=(-H "$REQ_HEADER")
  fi
  body="$(curl "${curlargs[@]}" "$url" 2>/dev/null)"
  if [ -z "$body" ]; then
    _fail "assert_no_secret_in_body $method $url: empty body (cannot confirm secret-absence)"
    return 1
  fi
  if printf '%s' "$body" | grep -qiE 'password_hash|token_hash|bootstrap|client_secret|\$argon2|postgres://'; then
    _fail "assert_no_secret_in_body $method $url: SECRET marker found in response body"
    return 1
  fi
  _pass "assert_no_secret_in_body $method $url: no secret markers present"
  return 0
}

# --- assert_rate_limited <url> <data> <count> --------------------------------
# Fire <count> POSTs of <data> at <url>; PASS ONLY if AT LEAST one response is
# 429 (rate limit tripped). Zero 429s (or all-empty responses) FAILs — we never
# green on absence of a 429.
assert_rate_limited() {
  local url="$1" data="$2" count="$3" i code saw_429=0 saw_any=0
  for i in $(seq 1 "$count"); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -H 'Content-Type: application/json' --data "$data" "$url" 2>/dev/null)"
    [ -n "$code" ] && saw_any=1
    if [ "$code" = "429" ]; then
      saw_429=1
    fi
  done
  if [ "$saw_any" = "0" ]; then
    _fail "assert_rate_limited $url: no responses at all over $count requests (connection error)"
    return 1
  fi
  if [ "$saw_429" = "1" ]; then
    _pass "assert_rate_limited $url: at least one 429 over $count requests"
    return 0
  fi
  _fail "assert_rate_limited $url: no 429 over $count requests (rate limit NOT enforced)"
  return 1
}

# --- assert_json_ok <method> <url> [shape] -----------------------------------
# Positive data-path assertion (Phase 3 BACK-02, anti-false-green T-03): issue
# <method> <url> capturing BOTH the HTTP status and the body in one request, and
# PASS ONLY when ALL of:
#   - the HTTP status is exactly 200, AND
#   - the body is NON-empty, AND
#   - the body PARSES as JSON (via node, jq fallback), AND
#   - the optional <shape> holds: "array" (top-level JSON array),
#     "nonempty-array" (a JSON array with >=1 element), or "has:<key>" (a JSON
#     object carrying <key>). Omit <shape> to require only valid JSON.
# A 200 with an empty/non-JSON body, or a 200 that fails the shape, FAILs — a
# reachable-but-empty endpoint can never false-green this gate.
# Optional request body via $REQ_DATA and extra header via $REQ_HEADER (e.g. the
# authenticated `Cookie:` header), mirroring assert_status.
assert_json_ok() {
  local method="$1" url="$2" shape="${3:-}" body code
  local -a curlargs=(-s -w '\n%{http_code}' --max-time 10 -X "$method")
  if [ -n "${REQ_DATA:-}" ]; then
    curlargs+=(-H 'Content-Type: application/json' --data "$REQ_DATA")
  fi
  if [ -n "${REQ_HEADER:-}" ]; then
    curlargs+=(-H "$REQ_HEADER")
  fi
  # Append the status on its own trailing line, then split it back off.
  local raw
  raw="$(curl "${curlargs[@]}" "$url" 2>/dev/null)"
  code="$(printf '%s' "$raw" | tail -n1)"
  body="$(printf '%s' "$raw" | sed '$d')"

  if [ -z "$code" ]; then
    _fail "assert_json_ok $method $url: no response (connection error; want 200+JSON)"
    return 1
  fi
  if [ "$code" != "200" ]; then
    _fail "assert_json_ok $method $url: status '$code' (want 200)"
    return 1
  fi
  if [ -z "$body" ]; then
    _fail "assert_json_ok $method $url: 200 but EMPTY body (anti-false-green: empty is not proof)"
    return 1
  fi

  # Validate JSON (and the optional shape) via node; fall back to jq.
  local verdict
  if _have_node; then
    verdict="$(printf '%s' "$body" | SHAPE="$shape" node -e '
      const shape = process.env.SHAPE || "";
      let input = require("fs").readFileSync(0, "utf8");
      let data;
      try { data = JSON.parse(input); } catch (e) { process.stdout.write("BADJSON"); process.exit(0); }
      if (shape === "array" && !Array.isArray(data)) { process.stdout.write("NOTARRAY"); process.exit(0); }
      if (shape === "nonempty-array") {
        if (!Array.isArray(data)) { process.stdout.write("NOTARRAY"); process.exit(0); }
        if (data.length === 0) { process.stdout.write("EMPTYARRAY"); process.exit(0); }
      }
      if (shape.startsWith("has:")) {
        const key = shape.slice(4);
        if (data === null || typeof data !== "object" || Array.isArray(data) || !(key in data)) {
          process.stdout.write("MISSINGKEY"); process.exit(0);
        }
      }
      process.stdout.write("OK");
    ')"
  elif _have_jq; then
    # jq fallback: validate JSON, then the shape.
    if ! printf '%s' "$body" | jq -e . >/dev/null 2>&1; then
      verdict="BADJSON"
    elif [ "$shape" = "array" ] && ! printf '%s' "$body" | jq -e 'type=="array"' >/dev/null 2>&1; then
      verdict="NOTARRAY"
    elif [ "$shape" = "nonempty-array" ] && ! printf '%s' "$body" | jq -e 'type=="array" and length>0' >/dev/null 2>&1; then
      verdict="EMPTYARRAY"
    elif [ "${shape#has:}" != "$shape" ] && ! printf '%s' "$body" | jq -e --arg k "${shape#has:}" 'type=="object" and has($k)' >/dev/null 2>&1; then
      verdict="MISSINGKEY"
    else
      verdict="OK"
    fi
  else
    _fail "assert_json_ok $method $url: no node/jq to parse JSON"
    return 2
  fi

  if [ "$verdict" = "OK" ]; then
    _pass "assert_json_ok $method $url: 200 + valid JSON${shape:+ ($shape)}"
    return 0
  fi
  _fail "assert_json_ok $method $url: 200 but body failed JSON/shape check ($verdict, shape='${shape:-any}')"
  return 1
}

# =============================================================================
# Phase 4 config-edit assert helpers (live-stack restart-scope / rollback /
# overlay-not-persisted). Every NEGATIVE/idempotence helper obeys the
# anti-false-green contract (T-04-17): PASS only on the explicit expected
# condition, never merely because output is empty.
# =============================================================================

# --- _started_at <container> -------------------------------------------------
# Echo a container's `.State.StartedAt` (an RFC3339 timestamp that changes on
# every (re)start). Empty if the container is absent. Used to prove that ONLY
# the affected service restarted (BACK-05/INFRA-05, T-04-18).
_started_at() {
  docker inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null || true
}

# --- snapshot_started_at <svc...> / assert_only_container_restarted ----------
# Capture each container's `.State.StartedAt` into a `BEFORE_<name>` var, then
# after the action assert ONLY the named service restarted (its StartedAt
# CHANGED) and every "other" service is UNCHANGED. An empty timestamp (container
# vanished) FAILs — we never green on absence (T-04-18).
#
# Caller pattern:
#   snapshot_started_at ory-kratos ory-hydra ory-keto ory-oathkeeper
#   <do the PUT that restarts ory-kratos>
#   assert_only_container_restarted ory-kratos ory-hydra ory-keto ory-oathkeeper
_bk_var() { printf 'BEFORE_%s' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"; }

snapshot_started_at() {
  local svc var val
  for svc in "$@"; do
    var="$(_bk_var "$svc")"
    val="$(_started_at "$svc")"
    eval "$var=\$val"
  done
}

assert_only_container_restarted() {
  local restarted="$1"; shift
  local ok=1
  local before_var before after
  before_var="$(_bk_var "$restarted")"
  eval "before=\${$before_var:-}"
  after="$(_started_at "$restarted")"
  if [ -z "$before" ] || [ -z "$after" ]; then
    _fail "assert_only_container_restarted: '$restarted' StartedAt missing (before='$before' after='$after')"
    return 1
  fi
  if [ "$before" = "$after" ]; then
    _fail "assert_only_container_restarted: '$restarted' did NOT restart (StartedAt unchanged: $after)"
    ok=0
  fi
  local other ob_var ob oa
  for other in "$@"; do
    ob_var="$(_bk_var "$other")"
    eval "ob=\${$ob_var:-}"
    oa="$(_started_at "$other")"
    if [ -z "$ob" ] || [ -z "$oa" ]; then
      _fail "assert_only_container_restarted: '$other' StartedAt missing (before='$ob' after='$oa')"
      ok=0
      continue
    fi
    if [ "$ob" != "$oa" ]; then
      _fail "assert_only_container_restarted: '$other' ALSO restarted (StartedAt changed: $ob -> $oa)"
      ok=0
    fi
  done
  if [ "$ok" = "1" ]; then
    _pass "assert_only_container_restarted: ONLY '$restarted' restarted; $* unchanged"
    return 0
  fi
  return 1
}

# --- wait_container_healthy <container> [timeout_s] --------------------------
# Poll a container's Docker `.State.Health.Status` until it is `healthy` or the
# timeout elapses. After a broker restart Docker reports `starting` for a few
# seconds before the healthcheck flips to `healthy`; a bare assert_healthy can
# race that window. PASS when it reaches `healthy`; FAIL (with the last observed
# status) on timeout — never green on absence.
wait_container_healthy() {
  local ctr="$1" timeout="${2:-60}" waited=0 status=""
  while [ "$waited" -lt "$timeout" ]; do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo '')"
    if [ "$status" = "healthy" ]; then
      _pass "wait_container_healthy $ctr: healthy after ${waited}s"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  _fail "wait_container_healthy $ctr: NOT healthy within ${timeout}s (last status='$status')"
  return 1
}

# --- _file_digest <path> -----------------------------------------------------
# sha256 of a file's bytes (empty if absent). Prefers sha256sum, then openssl,
# then node (always present per the project guide).
_file_digest() {
  local path="$1"
  if [ ! -f "$path" ]; then printf ''; return 0; fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$path" | sed 's/.*= //'
  elif _have_node; then
    PATH_ARG="$path" node -e '
      const fs=require("fs"),c=require("crypto");
      const p=process.env.PATH_ARG;
      process.stdout.write(c.createHash("sha256").update(fs.readFileSync(p)).digest("hex"));'
  else
    printf ''
  fi
}

# --- snapshot_file <path> / assert_file_unchanged <path> ---------------------
# Capture a file's sha256 (snapshot_file), perform the action, then assert the
# file still exists AND is byte-identical (assert_file_unchanged). A missing
# file or a changed digest FAILs (T-04-17: a reject must not touch disk).
_file_var() { printf 'BEFORE_FILE_%s' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"; }

snapshot_file() {
  local path="$1" var val
  var="$(_file_var "$path")"
  val="$(_file_digest "$path")"
  eval "$var=\$val"
}

assert_file_unchanged() {
  local path="$1" var before after
  var="$(_file_var "$path")"
  eval "before=\${$var:-}"
  after="$(_file_digest "$path")"
  if [ -z "$before" ]; then
    _fail "assert_file_unchanged $path: no snapshot taken (call snapshot_file first)"
    return 1
  fi
  if [ -z "$after" ]; then
    _fail "assert_file_unchanged $path: file missing after action (cannot confirm no-write)"
    return 1
  fi
  if [ "$before" = "$after" ]; then
    _pass "assert_file_unchanged $path: byte-identical (no disk write)"
    return 0
  fi
  _fail "assert_file_unchanged $path: file CHANGED (a reject wrote to disk!)"
  return 1
}

# --- assert_rolled_back <path> <backup> --------------------------------------
# After a health-breaking edit the engine restores the last-known-good `.bak`.
# PASS only when <path> + <backup> both exist AND their sha256 digests match
# (the live file is byte-equal to the backup -> rolled back). Any mismatch or a
# missing file FAILs (T-04-19).
assert_rolled_back() {
  local path="$1" backup="$2" dpath dbak
  dpath="$(_file_digest "$path")"
  dbak="$(_file_digest "$backup")"
  if [ -z "$dpath" ]; then
    _fail "assert_rolled_back $path: live file missing (cannot confirm rollback)"
    return 1
  fi
  if [ -z "$dbak" ]; then
    _fail "assert_rolled_back: backup '$backup' missing (cannot confirm rollback)"
    return 1
  fi
  if [ "$dpath" = "$dbak" ]; then
    _pass "assert_rolled_back $path: restored byte-equal to last-known-good ($backup)"
    return 0
  fi
  _fail "assert_rolled_back $path: live file does NOT match the backup (not rolled back)"
  return 1
}

# --- assert_no_dsn_in_file <path> --------------------------------------------
# Prove the env-overlay validation was VALIDATION-ONLY and never persisted: the
# written YAML must contain NO top-level `dsn:` key (T-04-25). PASS only when the
# file exists AND no uncommented top-level `dsn:` line is present.
assert_no_dsn_in_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    _fail "assert_no_dsn_in_file $path: file does not exist"
    return 1
  fi
  if grep -Ev '^[[:space:]]*#' "$path" | grep -Eq '^dsn[[:space:]]*:'; then
    _fail "assert_no_dsn_in_file $path: a top-level 'dsn:' key IS present (overlay leaked to disk!)"
    return 1
  fi
  _pass "assert_no_dsn_in_file $path: no top-level dsn key (overlay never persisted)"
  return 0
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
