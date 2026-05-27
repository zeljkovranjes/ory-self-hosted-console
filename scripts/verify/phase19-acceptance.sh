#!/usr/bin/env bash
# scripts/verify/phase19-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 19 (operator-cli-optional-final) live acceptance gate. The FINAL gate of
# the final phase: proves CLI-02..06 end-to-end against the REAL compose stack
# with anti-false-green discipline (lib.sh T-03 contract: a negative/security
# assertion PASSes ONLY on the EXPLICIT expected refusal — 401/403/404/non-zero
# exit / gitignore-match — NEVER on absence of output).
#
#   OPTIONALITY (CLI-02 / T-19-16): the full feature set + a representative prior
#     acceptance gate (phase12 — the feature-toggle keystone) pass with NO `cli`
#     service started. The base stack reaches healthy with no `cli` dependency;
#     the `cli` service is profiled (`--profile cli`) so a plain `up` never starts
#     it; no base-stack `depends_on` references it.
#
#   API-KEY AUTH end-to-end (CLI-02 / T-19-17): issue a console API key (session +
#     CSRF), then with ONLY `Authorization: Api-Key <raw>` (no cookie, no CSRF):
#       (a) protected GET /api/console/features -> 200
#       (b) protected PUT feature toggle  -> 200 AND the flag flips (csrf-exempt)
#       (c) revoke the key, repeat the PUT -> 401
#       (d) a syntactically-plausible unknown key -> 401
#       (e) the audit log shows a row for the api-key PUT (audited).
#     SESSION-UNCHANGED: a valid SESSION PUT with NO X-CSRF-Token -> 403.
#
#   NEVER A SECOND WRITER (CLI-02/03 / T-19-18): `docker compose run --rm cli
#     feature enable/disable <key>` (CONSOLE_API_KEY set) flips the flag, read back
#     via GET /api/console/features — proving the CLI drove the BACKEND ROUTE (no
#     direct DB/YAML write). Static: `cargo tree -p ory-console-cli` (default) shows
#     no sqlx.
#
#   NO ARGV SECRET (CLI-04/06 / T-19-19): the cli help over every subcommand
#     exposes NO value-taking secret flag (re-run of the Plan-03 clap-introspection
#     test, the authoritative check) — explicit pass only.
#
#   BOOTSTRAP GITIGNORED (CLI-04/06 / T-19-19): `docker compose run` (repo root
#     bind-mounted) `cli oauth github set` writes a temp `.env`; assert both
#     GITHUB_OAUTH_* keys present AND `git check-ignore` returns the path AND the
#     secret value is NOT echoed in the command output.
#
#   PRIOR INVARIANTS: INFRA-05 (no admin / cli host port published), BACK-05
#     (restart-broker allowlist unchanged; backend holds no socket), BACK-01
#     (bundle-egress green). A Phase-13..18 representative regression rides along
#     in the phase12 re-run + the invariant checks WITH the cli image present.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script does
# the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless told to
# reuse a stack:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase19-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still runs
#                    the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   SKIP_CARGO=1     skip the `cargo tree`/`cargo test` static checks (no toolchain)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500)
#
# bash -n clean; sources lib.sh; follows the phase12/phase14 harness contract.
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

KRATOS_CONTAINER="ory-kratos"
HYDRA_CONTAINER="ory-hydra"
KETO_CONTAINER="ory-keto"
OATHKEEPER_CONTAINER="ory-oathkeeper"
# Admin ports that MUST be refused from the host (INFRA-05).
ADMIN_PORTS="4434 4445 4467 4469 4456"

detect_api_version() {
  local ver=""
  ver="$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="$(docker version --format '{{.Client.APIVersion}}' 2>/dev/null || true)"
  [ -z "$ver" ] && ver="1.43"
  printf 'v%s' "$ver"
}
API_VER="$(detect_api_version)"

echo "=== Phase 19 acceptance: Operator CLI (OPTIONAL) + api-key auth (CLI-02..06) ==="
echo "    optionality + api-key auth + never-2nd-writer + no-argv-secret + bootstrap-gitignored"
echo "    + INFRA-05 / BACK-05 / BACK-01 + Phase-12 (feature-toggle) regression with the cli present"
echo "Backend base URL:   ${BACKEND_BASE_URL}"
echo "Repo root:          ${REPO_ROOT}"
echo "Docker API version: ${API_VER}"

# -----------------------------------------------------------------------------
# Polis env overlay (mirrors phase14): the base stack needs the POLIS_* secrets.
# Generate ephemeral values into a throwaway env-file combined with .env. The
# whole stack (incl. the bootstrap .env the cli writes) is torn down at the end.
# -----------------------------------------------------------------------------
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

POLIS_ENV_FILE="${REPO_ROOT}/.env.p19-acceptance-$$"
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

# Temp file the cli bootstrap test writes (a gitignored .env under the repo root).
BOOTSTRAP_ENV_REL=".env.cli-bootstrap-$$"
BOOTSTRAP_ENV_ABS="${REPO_ROOT}/${BOOTSTRAP_ENV_REL}"

teardown() {
  # Bring the stack down BEFORE removing the ephemeral env-file: $DC references it
  # via `--env-file`, so deleting it first would make `down` unable to resolve the
  # project and silently leave the stack up (the temp files are gitignored either
  # way, but the stack must actually come down).
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "KEEP_STACK=1 — leaving the stack up (run '$DC --profile cli down -v' to clean)."
  else
    echo
    echo "--- teardown: docker compose down -v (incl. the cli profile) ---"
    $DC --profile cli down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$POLIS_ENV_FILE" 2>/dev/null || true
  rm -f "$BOOTSTRAP_ENV_ABS" 2>/dev/null || true
}
trap teardown EXIT

# =============================================================================
# [BACK-01] bundle-egress (cheapest hard gate; holds regardless of the stack).
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
# STATIC: the cli is structurally OPTIONAL + no-second-writer (no live stack).
# =============================================================================
echo
echo "============================================================"
echo " STATIC — optionality wiring + no-second-writer (no stack)"
echo "============================================================"

echo
echo "--- [CLI-02] the cli service is profiled (absent from a plain 'up'); no base depends_on references it ---"
# Default config: cli MUST be absent (profiled). Anti-false-green: an explicit
# absence from the SERVICE LIST, not an empty grep over the file.
DEFAULT_SVCS="$($DC config --services 2>/dev/null)"
if printf '%s\n' "$DEFAULT_SVCS" | grep -qx cli; then
  _fail "[CLI-02] 'cli' appears in the DEFAULT compose service list (it must be profiled, not auto-started)"
else
  _pass "[CLI-02] 'cli' is absent from the default compose services (profiled — a plain 'up' never starts it)"
fi
# Under --profile cli it MUST exist (proves it is a real, runnable service).
PROFILE_SVCS="$($DC --profile cli config --services 2>/dev/null)"
if printf '%s\n' "$PROFILE_SVCS" | grep -qx cli; then
  _pass "[CLI-02] 'cli' exists under --profile cli (a runnable one-shot service)"
else
  _fail "[CLI-02] 'cli' missing even under --profile cli (the optional service is not wired)"
fi
# No base-stack service may depend_on cli (optionality). Scan every service's
# depends_on in the rendered config for a 'cli' dependency.
CLI_DEPENDED="$($DC --profile cli config --format json 2>/dev/null | node -e '
  let s=""; try { s=require("fs").readFileSync(0,"utf8"); } catch(e){ process.exit(0); }
  let d; try { d=JSON.parse(s); } catch(e){ process.exit(0); }
  const svcs=(d&&d.services)||{};
  const hits=[];
  for (const [name,def] of Object.entries(svcs)) {
    if (name==="cli") continue;
    const dep=def&&def.depends_on;
    if (!dep) continue;
    const keys=Array.isArray(dep)?dep:Object.keys(dep);
    if (keys.includes("cli")) hits.push(name);
  }
  process.stdout.write(hits.join(","));
' 2>/dev/null)"
if [ -z "$CLI_DEPENDED" ]; then
  _pass "[CLI-02] NO base-stack service depends_on 'cli' (the stack comes up without it — optionality)"
else
  _fail "[CLI-02] base-stack service(s) depend_on 'cli': $CLI_DEPENDED (breaks optionality)"
fi
# No host port on the cli service (INFRA-05 / T-19-15).
CLI_PORTS="$($DC --profile cli config --format json 2>/dev/null | node -e '
  let s=""; try { s=require("fs").readFileSync(0,"utf8"); } catch(e){ process.exit(0); }
  let d; try { d=JSON.parse(s); } catch(e){ process.exit(0); }
  const c=(d&&d.services&&d.services.cli)||{};
  const p=c.ports||[];
  process.stdout.write(String(p.length));
' 2>/dev/null)"
if [ "$CLI_PORTS" = "0" ]; then
  _pass "[INFRA-05/T-19-15] the cli service publishes NO host port (internal-only)"
else
  _fail "[INFRA-05/T-19-15] the cli service publishes $CLI_PORTS host port(s) (must be none)"
fi

if [ "${SKIP_CARGO:-0}" != "1" ] && command -v cargo >/dev/null 2>&1; then
  echo
  echo "--- [CLI-02/03/T-19-18] cargo tree -p ory-console-cli (default) shows NO sqlx (no second writer) ---"
  if cargo tree -p ory-console-cli -i sqlx >/dev/null 2>&1; then
    _fail "[T-19-18] sqlx IS present in the DEFAULT cli graph (the default build must carry no DB writer)"
  else
    _pass "[T-19-18] sqlx is ABSENT from the default cli dependency graph (online = HTTP-only, never a 2nd writer)"
  fi

  echo
  echo "--- [CLI-04/06/T-19-19] no-argv-secret: re-run the Plan-03 clap-introspection test (authoritative) ---"
  if cargo test -p ory-console-cli --locked no_subcommand_accepts_a_value_taking_secret_flag >/dev/null 2>&1; then
    _pass "[T-19-19] no cli subcommand exposes a value-taking secret flag (env/--*-file/prompt only)"
  else
    _fail "[T-19-19] the no-argv-secret clap-introspection test FAILED (a secret-bearing argv flag may exist)"
  fi
else
  echo
  echo "--- [CLI-02/03/04/06] cargo static checks SKIPPED (SKIP_CARGO=1 or no cargo) — STATIC no-sqlx/no-argv not proven this run ---"
fi

# =============================================================================
# Bring the stack up (unless REUSE_STACK=1) — WITHOUT the cli profile, proving
# the full stack reaches healthy with NO cli started (optionality, live).
# Insecure cookies for THIS ephemeral run so curl can replay the session cookie
# over the plain-HTTP compose edge. TEST_PROBE=1 so the phase12 keystone anchors.
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true
export TEST_PROBE=1

if [ "${REUSE_STACK:-0}" != "1" ]; then
  echo
  echo "--- fresh-volume reset (down -v) so /setup mints a one-time token ---"
  $DC --profile cli down -v --remove-orphans >/dev/null 2>&1 || true
  echo
  echo "--- [CLI-02] bring up the FULL stack WITHOUT the cli profile (build + up -d --wait, timeout ${UP_TIMEOUT}s) ---"
  echo "    (the frontend image build is heavy; this can take many minutes)"
  if ! $DC build backend frontend; then
    _fail "docker compose build (backend + frontend) FAILED"
    summary; exit $?
  fi
  # Pre-build the cli IMAGE (so `run` is fast later) but do NOT start it.
  if ! $DC --profile cli build cli; then
    _fail "docker compose build cli FAILED (the cli image must build)"
    summary; exit $?
  fi
  if $DC up -d --wait --wait-timeout "${UP_TIMEOUT}"; then
    _pass "[CLI-02] docker compose up -d --wait (NO cli profile): the whole stack reached healthy WITHOUT the cli"
  else
    _fail "docker compose up -d --wait did NOT reach healthy within ${UP_TIMEOUT}s"
    echo "--- recent backend logs ---"; $DC logs --tail 40 backend 2>/dev/null || true
    summary; exit $?
  fi
fi

# Confirm the cli container is NOT running (optionality, live).
echo
echo "--- [CLI-02] the cli service is NOT running after a plain 'up' (optionality, live) ---"
CLI_RUNNING="$($DC ps --services 2>/dev/null | grep -x cli || true)"
if [ -z "$CLI_RUNNING" ]; then
  _pass "[CLI-02] no 'cli' container is running after 'up' (the stack is fully functional without it)"
else
  _fail "[CLI-02] a 'cli' container IS running after a plain 'up' (it must be a one-shot, not auto-started)"
fi

# Preflight.
echo
echo "--- [preflight] backend healthy + serving ---"
assert_healthy backend
assert_status GET "${BACKEND_BASE_URL}/health" 200

# The single admin this stack's one-time /setup mints. Created HERE via the CLI
# (CR-01 proof), then re-used by the phase12 keystone re-run + every live
# criterion below (all of which authenticate as this admin).
ADMIN_EMAIL_TEST="phase12-admin@example.com"
ADMIN_PW_TEST="phase12-acceptance-pw"   # >= 12 chars (CAUTH-03 / WR-04 policy)
: "${SESSION_COOKIE_NAME:=console_session}"

# =============================================================================
# CR-01 (anti-false-green): the FIRST-RUN admin is created by DRIVING THE CLI's
# `admin create --via-setup` against the live backend — NOT a raw curl. This is
# the one /setup this stack allows, so if the CLI's /setup body is malformed
# (the CR-01 blocker: missing the required `name`), the admin is NEVER created,
# the phase12 keystone re-run + every subsequent login FAILS, and the whole gate
# goes RED. The bootstrap token comes from the backend's boot log; the admin
# password arrives via CONSOLE_ADMIN_PASSWORD / the bootstrap token via
# CONSOLE_BOOTSTRAP_TOKEN env (NEVER argv).
# =============================================================================
echo
echo "============================================================"
echo " CR-01 — first-run admin via the CLI (admin create --via-setup)"
echo "============================================================"
SETUP_TOKEN_CLI="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"
state_pre="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
pre_init=0
printf '%s' "$state_pre" | grep -q '"initialized":true' && pre_init=1

if [ "$pre_init" = "1" ]; then
  _pass "[CR-01] console already initialized on this (re-used) stack — skipping the CLI create (idempotent)"
elif [ -z "$SETUP_TOKEN_CLI" ]; then
  _fail "[CR-01] could not read the FIRST-RUN SETUP TOKEN from the backend log (cannot drive the CLI create)"
else
  echo
  echo "--- [CR-01] docker compose run --rm cli admin create --via-setup (token+password via env, never argv) ---"
  cli_create_out="$($DC --profile cli run --rm \
      -e CONSOLE_API_URL="http://backend:8080" \
      -e CONSOLE_BOOTSTRAP_TOKEN="$SETUP_TOKEN_CLI" \
      -e CONSOLE_ADMIN_PASSWORD="$ADMIN_PW_TEST" \
      cli admin create --via-setup \
        --name "Phase19 CLI Admin" \
        --email "$ADMIN_EMAIL_TEST" 2>&1)"
  cli_create_rc=$?
  state_post="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
  post_init=0
  printf '%s' "$state_post" | grep -q '"initialized":true' && post_init=1
  if [ "$cli_create_rc" = "0" ] && [ "$post_init" = "1" ]; then
    _pass "[CR-01] the CLI 'admin create --via-setup' created the first-run admin (console now initialized — proven end-to-end through the CLI)"
  else
    _fail "[CR-01] CLI admin create --via-setup FAILED rc='$cli_create_rc' initialized='$post_init' (out: $(printf '%s' "$cli_create_out" | head -c 400))"
  fi
  # The CLI must NOT echo the password.
  if printf '%s' "$cli_create_out" | grep -qF "$ADMIN_PW_TEST"; then
    _fail "[BACK-07] the CLI admin-create output echoed the admin password (must never print the secret)"
  else
    _pass "[BACK-07] the CLI admin-create output did not echo the password"
  fi
fi

# =============================================================================
# OPTIONALITY (CLI-02): re-run the phase12 feature-toggle keystone gate against
# the ALREADY-UP stack (REUSE_STACK=1) — it must pass with NO cli present. This
# is the "full feature set works without the CLI" proof + a Phase-13..18-class
# regression rider (the keystone exercises auth/csrf/audit/feature routes).
# NOTE: /setup is already consumed by the CLI create above, so phase12's own
# /setup call takes its 404-already-init branch and logs in as the CLI-created
# admin — which only exists if the CLI's /setup body was correct (CR-01).
# =============================================================================
echo
echo "============================================================"
echo " OPTIONALITY (CLI-02) — phase12 keystone re-run, NO cli started"
echo "============================================================"
echo
echo "--- re-running scripts/verify/phase12-acceptance.sh against the live stack (REUSE_STACK=1) ---"
if MSYS_NO_PATHCONV=1 REUSE_STACK=1 KEEP_STACK=1 SKIP_EGRESS=1 BACKEND_PORT="${BACKEND_PORT:-8080}" \
     DC="$DC" bash "${REPO_ROOT}/scripts/verify/phase12-acceptance.sh"; then
  _pass "[CLI-02] the phase12 feature-toggle keystone gate PASSED with NO cli present (full feature set works without the CLI)"
else
  _fail "[CLI-02] the phase12 keystone re-run FAILED with no cli present (optionality / feature-set regression)"
fi

# =============================================================================
# Authenticate a console session as the CLI-created admin (login only — /setup
# was already driven through the CLI above; ADMIN_EMAIL_TEST / ADMIN_PW_TEST /
# SESSION_COOKIE_NAME were defined there). If the CLI create silently no-op'd,
# this /login fails and the live criteria below cannot run — a hard red.
# =============================================================================
echo
echo "--- [auth] login as the CLI-created admin for an authenticated session ---"
state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
if printf '%s' "$state_now" | grep -q '"initialized":true'; then
  _pass "console is initialized (the CLI first-run admin exists) — proceeding to login"
else
  _fail "console is NOT initialized after the CLI create (admin create --via-setup did not take effect)"
fi

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
  _fail "could not obtain a session token from /login (live criteria cannot run)"
  COOKIE_HEADER=""; CSRF_TOKEN=""
else
  _pass "obtained an authenticated session token from /login"
  COOKIE_HEADER="Cookie: ${SESSION_COOKIE_NAME}=${SESSION_TOKEN}"
  CSRF_TOKEN="$(_csrf_for_email "$ADMIN_EMAIL_TEST")"
  if [ -n "$CSRF_TOKEN" ]; then
    _pass "obtained the per-session CSRF token"
  else
    _fail "could not read csrf_token (mutations would 403)"
  fi
fi

if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo; _fail "no authenticated session/CSRF — skipping the live Phase-19 criteria"
  summary; exit $?
fi

FEATURES_URL="${BACKEND_BASE_URL}/api/console/features"
APIKEYS_URL="${BACKEND_BASE_URL}/api/console/api-keys"
AUDIT_URL="${BACKEND_BASE_URL}/api/console/audit"

_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 60 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }

# Read a feature's enabled bool via the session GET.
_feature_enabled() {
  local key="$1"
  curl -s --max-time 20 -H "$COOKIE_HEADER" "$FEATURES_URL" 2>/dev/null | KEY="$key" node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(0); }
    const f = d && d.features && d.features[process.env.KEY];
    process.stdout.write(f ? String(!!f.enabled) : "missing");' 2>/dev/null
}

# =============================================================================
# API-KEY AUTH end-to-end (CLI-02 / T-19-17).
# =============================================================================
echo
echo "============================================================"
echo " API-KEY AUTH (CLI-02) — valid 200 / revoked+invalid 401 /"
echo "                          csrf-exempt / audited / session-unchanged"
echo "============================================================"

# Issue a key (session + CSRF). The raw key is returned EXACTLY ONCE as `key`.
echo
echo "--- [CLI-02] issue a console API key (POST /api/console/api-keys) ---"
issue_resp="$(_auth_mut POST "$APIKEYS_URL" '{"name":"phase19-cli-key"}')"
issue_code="$(_code_of "$issue_resp")"; issue_body="$(_body_of "$issue_resp")"
RAW_KEY="$(printf '%s' "$issue_body" | node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)}process.stdout.write(d&&d.key?d.key:"")' 2>/dev/null)"
KEY_ID="$(printf '%s' "$issue_body" | node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)}process.stdout.write(d&&d.id?d.id:"")' 2>/dev/null)"
if { [ "$issue_code" = "200" ] || [ "$issue_code" = "201" ]; } && [ -n "$RAW_KEY" ] && [ -n "$KEY_ID" ]; then
  _pass "[CLI-02] issued an API key (one-time raw reveal + id) -> $issue_code"
else
  _fail "[CLI-02] could not issue an API key -> code='$issue_code' (body: $(printf '%s' "$issue_body" | head -c 300))"
  summary; exit $?
fi

APIKEY_HEADER="Authorization: Api-Key ${RAW_KEY}"

# (a) protected GET with ONLY the api-key header (no cookie, no CSRF) -> 200.
echo
echo "--- [CLI-02] api-key GET /api/console/features (no cookie, no CSRF) -> 200 ---"
ak_get_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "$APIKEY_HEADER" "$FEATURES_URL" 2>/dev/null)"
if [ "$ak_get_code" = "200" ]; then
  _pass "[CLI-02] api-key GET /api/console/features -> 200 (api-key authenticates a protected read)"
else
  _fail "[CLI-02] api-key GET -> '$ak_get_code' (want 200)"
fi

# (b) protected PUT (csrf-exempt) flips a flag. Use `account_experience` so we
# never disturb saml's seeded baseline; flip to the OPPOSITE of its current state.
echo
echo "--- [CLI-02/T-19-17] api-key PUT feature toggle (NO CSRF) -> 200 AND the flag flips (csrf-exempt, live) ---"
TOGGLE_KEY="account_experience"
BEFORE_FLAG="$(_feature_enabled "$TOGGLE_KEY")"
[ "$BEFORE_FLAG" = "true" ] && TARGET="false" || TARGET="true"
ak_put_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT \
  -H "$APIKEY_HEADER" -H 'Content-Type: application/json' \
  --data "{\"enabled\":${TARGET}}" "${FEATURES_URL}/${TOGGLE_KEY}" 2>/dev/null)"
AFTER_FLAG="$(_feature_enabled "$TOGGLE_KEY")"
if [ "$ak_put_code" = "200" ] && [ "$AFTER_FLAG" = "$TARGET" ]; then
  _pass "[CLI-02/T-19-17] api-key PUT (no X-CSRF-Token) -> 200 and ${TOGGLE_KEY} flipped ${BEFORE_FLAG}->${AFTER_FLAG} (CSRF-EXEMPT, proven live)"
else
  _fail "[CLI-02/T-19-17] api-key PUT -> code='$ak_put_code' flag '${BEFORE_FLAG}'->'${AFTER_FLAG}' (want 200 + flip to ${TARGET})"
fi
# Restore the flag to its prior value (keep the baseline clean).
curl -s -o /dev/null --max-time 30 -X PUT -H "$APIKEY_HEADER" -H 'Content-Type: application/json' \
  --data "{\"enabled\":${BEFORE_FLAG}}" "${FEATURES_URL}/${TOGGLE_KEY}" 2>/dev/null || true

# (d) a syntactically-plausible UNKNOWN key -> 401 (anti-false-green: explicit 401).
echo
echo "--- [T-19-17] an unknown (well-formed) api-key -> 401 ---"
UNKNOWN_KEY="oc_$(_gen_b64 | tr -dc 'A-Za-z0-9' | head -c 40)"
unknown_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
  -H "Authorization: Api-Key ${UNKNOWN_KEY}" "$FEATURES_URL" 2>/dev/null)"
if [ "$unknown_code" = "401" ]; then
  _pass "[T-19-17] unknown api-key -> 401 (fail-closed, not a fall-through to the session path)"
else
  _fail "[T-19-17] unknown api-key -> '$unknown_code' (want explicit 401)"
fi

# (e) the audit log shows a row for the api-key PUT (audited) BEFORE we revoke.
echo
echo "--- [T-19-17] the audit log records the api-key feature PUT (audited) ---"
audit_body="$(curl -s --max-time 30 -H "$COOKIE_HEADER" "${AUDIT_URL}?limit=80" 2>/dev/null)"
if printf '%s' "$audit_body" | node -e '
    let d; try { d = JSON.parse(require("fs").readFileSync(0,"utf8")); } catch(e){ process.exit(1); }
    const arr = Array.isArray(d) ? d : (d.rows||d.items||[]);
    if (!arr.length) process.exit(1);
    const hit = arr.find(r => {
      const s = JSON.stringify(r).toLowerCase();
      return s.includes("/api/console/features/") && s.includes("put");
    });
    process.exit(hit ? 0 : 1);
  ' 2>/dev/null; then
  _pass "[T-19-17] the audit log records a PUT /api/console/features/{key} (the api-key mutation is AUDITED)"
else
  _fail "[T-19-17] no audit row for the feature PUT (sample: $(printf '%s' "$audit_body" | head -c 300))"
fi

# (c) REVOKE the key, then the same PUT -> 401.
echo
echo "--- [T-19-17] revoke the key, repeat the api-key PUT -> 401 ---"
revoke_code="$(_code_of "$(_auth_mut POST "${APIKEYS_URL}/${KEY_ID}/revoke")")"
if [ "$revoke_code" = "200" ] || [ "$revoke_code" = "201" ] || [ "$revoke_code" = "204" ]; then
  _pass "[T-19-17] revoked the api-key (POST /api/console/api-keys/{id}/revoke -> $revoke_code)"
else
  _fail "[T-19-17] could not revoke the api-key -> '$revoke_code'"
fi
revoked_put_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT \
  -H "$APIKEY_HEADER" -H 'Content-Type: application/json' \
  --data "{\"enabled\":false}" "${FEATURES_URL}/${TOGGLE_KEY}" 2>/dev/null)"
if [ "$revoked_put_code" = "401" ]; then
  _pass "[T-19-17] a REVOKED api-key PUT -> 401 (revocation is enforced, fail-closed)"
else
  _fail "[T-19-17] revoked api-key PUT -> '$revoked_put_code' (want explicit 401)"
fi

# SESSION-UNCHANGED: a valid SESSION PUT with NO X-CSRF-Token -> 403.
echo
echo "--- [T-19-17] session path UNCHANGED: a session PUT WITHOUT X-CSRF-Token -> 403 ---"
sess_nocsrf_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT \
  -H "$COOKIE_HEADER" -H 'Content-Type: application/json' \
  --data "{\"enabled\":false}" "${FEATURES_URL}/${TOGGLE_KEY}" 2>/dev/null)"
if [ "$sess_nocsrf_code" = "403" ]; then
  _pass "[T-19-17] session PUT without X-CSRF-Token -> 403 (the session CSRF guard is UNCHANGED — exemption is api-key-only)"
else
  _fail "[T-19-17] session PUT without CSRF -> '$sess_nocsrf_code' (want 403 — session path must be unchanged)"
fi

# =============================================================================
# NEVER A SECOND WRITER (CLI-02/03 / T-19-18) — the cli flips a flag THROUGH the
# route. Issue a FRESH key (the prior one is revoked), pass it to the cli via
# CONSOLE_API_KEY, run `cli feature enable/disable`, read the flag back.
# =============================================================================
echo
echo "============================================================"
echo " NEVER A SECOND WRITER (CLI-02/03) — cli drives the BACKEND ROUTE"
echo "============================================================"

echo
echo "--- issue a fresh api-key for the cli run ---"
issue2="$(_auth_mut POST "$APIKEYS_URL" '{"name":"phase19-cli-run-key"}')"
RAW_KEY2="$(printf '%s' "$(_body_of "$issue2")" | node -e 'let d;try{d=JSON.parse(require("fs").readFileSync(0,"utf8"))}catch(e){process.exit(0)}process.stdout.write(d&&d.key?d.key:"")' 2>/dev/null)"
if [ -n "$RAW_KEY2" ]; then
  _pass "issued a fresh api-key for the cli online run"
else
  _fail "could not issue the cli-run api-key (cli online proof cannot run)"
fi

if [ -n "$RAW_KEY2" ]; then
  CLI_TOGGLE_KEY="event_streams"
  CLI_BEFORE="$(_feature_enabled "$CLI_TOGGLE_KEY")"
  [ "$CLI_BEFORE" = "true" ] && CLI_VERB="disable" && CLI_EXPECT="false" || { CLI_VERB="enable"; CLI_EXPECT="true"; }
  echo
  echo "--- [T-19-18] docker compose run --rm cli feature ${CLI_VERB} ${CLI_TOGGLE_KEY} (online, via the route) ---"
  # The cli reaches backend:8080 on the internal network; CONSOLE_API_KEY is the
  # issued raw key (NEVER on argv). No repo bind-mount needed for an online op.
  cli_run_out="$($DC --profile cli run --rm \
      -e CONSOLE_API_KEY="$RAW_KEY2" \
      -e CONSOLE_API_URL="http://backend:8080" \
      cli feature "$CLI_VERB" "$CLI_TOGGLE_KEY" 2>&1)"
  cli_run_rc=$?
  CLI_AFTER="$(_feature_enabled "$CLI_TOGGLE_KEY")"
  if [ "$cli_run_rc" = "0" ] && [ "$CLI_AFTER" = "$CLI_EXPECT" ]; then
    _pass "[T-19-18] the cli flipped ${CLI_TOGGLE_KEY} ${CLI_BEFORE}->${CLI_AFTER} THROUGH the backend route (no direct DB/YAML write)"
  else
    _fail "[T-19-18] cli online op rc='$cli_run_rc' flag '${CLI_BEFORE}'->'${CLI_AFTER}' (want rc=0 + flip to ${CLI_EXPECT}; out: $(printf '%s' "$cli_run_out" | head -c 300))"
  fi
  # The cli output must NOT echo the api-key (BACK-07).
  if printf '%s' "$cli_run_out" | grep -qF "$RAW_KEY2"; then
    _fail "[BACK-07] the cli output echoed the raw api-key (must never print the secret)"
  else
    _pass "[BACK-07] the cli output did not echo the raw api-key"
  fi
  # Restore the flag.
  curl -s -o /dev/null --max-time 30 -X PUT -H "Authorization: Api-Key ${RAW_KEY2}" \
    -H 'Content-Type: application/json' --data "{\"enabled\":${CLI_BEFORE}}" \
    "${FEATURES_URL}/${CLI_TOGGLE_KEY}" 2>/dev/null || true
fi

# =============================================================================
# BOOTSTRAP GITIGNORED (CLI-04/06 / T-19-19) — `cli oauth github set` writes a
# gitignored .env with the repo root bind-mounted; the secret value comes from an
# env var (NOT argv); the value is NOT echoed; `git check-ignore` matches.
# =============================================================================
echo
echo "============================================================"
echo " BOOTSTRAP GITIGNORED (CLI-04/06) — cli writes only gitignored paths"
echo "============================================================"

BOOT_SECRET="phase19-gh-secret-$(_gen_b64 | tr -dc 'A-Za-z0-9' | head -c 24)"
BOOT_CLIENT_ID="phase19-gh-client-id"
echo
echo "--- [T-19-19] docker compose run (repo root bind-mounted) cli oauth github set -> gitignored ${BOOTSTRAP_ENV_REL} ---"
# Bind-mount the repo root at /work (the cli WORKDIR); write to the temp .env.
# The secret arrives via GITHUB_OAUTH_CLIENT_SECRET env (NEVER argv).
boot_out="$($DC --profile cli run --rm \
    -e GITHUB_OAUTH_CLIENT_ID="$BOOT_CLIENT_ID" \
    -e GITHUB_OAUTH_CLIENT_SECRET="$BOOT_SECRET" \
    -v "${REPO_ROOT}:/work" \
    cli oauth github set --env-file "/work/${BOOTSTRAP_ENV_REL}" 2>&1)"
boot_rc=$?
if [ "$boot_rc" != "0" ]; then
  # The exact flag surface may differ; report the cli's own usage for diagnosis.
  _fail "[T-19-19] cli oauth github set exited rc='$boot_rc' (out: $(printf '%s' "$boot_out" | head -c 400))"
fi
# Assert the file exists and carries BOTH keys.
if [ -f "$BOOTSTRAP_ENV_ABS" ] \
   && grep -q '^GITHUB_OAUTH_CLIENT_ID=' "$BOOTSTRAP_ENV_ABS" \
   && grep -q '^GITHUB_OAUTH_CLIENT_SECRET=' "$BOOTSTRAP_ENV_ABS"; then
  _pass "[T-19-19] the bootstrap write produced ${BOOTSTRAP_ENV_REL} with GITHUB_OAUTH_CLIENT_ID + _SECRET"
else
  _fail "[T-19-19] the bootstrap .env is missing or lacks the GITHUB_OAUTH_* keys (out: $(printf '%s' "$boot_out" | head -c 300))"
fi
# `git check-ignore` MUST match (the written path is gitignored) — explicit match.
# Run from the repo root (the script already cd'd there) with a RELATIVE path:
# `git -C "<MSYS path with spaces>"` does not survive MSYS_NO_PATHCONV=1 path
# translation, which spuriously fails the chdir and false-reds this assertion.
if ( cd "$REPO_ROOT" && git check-ignore "$BOOTSTRAP_ENV_REL" ) >/dev/null 2>&1; then
  _pass "[T-19-19] git check-ignore matches ${BOOTSTRAP_ENV_REL} (the bootstrap write targets only gitignored paths)"
else
  _fail "[T-19-19] git check-ignore did NOT match ${BOOTSTRAP_ENV_REL} (a bootstrap secret file could be committed!)"
fi
# The secret VALUE must NOT appear in the command output (BACK-07 / T-19-19).
if printf '%s' "$boot_out" | grep -qF "$BOOT_SECRET"; then
  _fail "[T-19-19] the cli output echoed the github secret VALUE (must print key names only, never the value)"
else
  _pass "[T-19-19] the cli output did NOT echo the github secret value (key names only)"
fi

# =============================================================================
# PRIOR INVARIANTS — INFRA-05 admin-port isolation + the cli surface (with the
# cli image present, post-run). BACK-05 restart-broker scope unchanged.
# =============================================================================
echo
echo "============================================================"
echo " v-INVARIANT REGRESSION — INFRA-05 / BACK-05 (cli present)"
echo "============================================================"

echo
echo "--- [INFRA-05] no Ory Admin port is host-published (refused from host; reachable internally) ---"
for port in $ADMIN_PORTS; do
  assert_port_refused "$port"
done
assert_internal_reachable backend "http://kratos:4434/health/ready"

echo
echo "--- [BACK-05] restarts route ONLY through the scoped socket-proxy; backend holds NO socket ---"
assert_broker_allowed POST "/${API_VER}/containers/${KRATOS_CONTAINER}/restart"
assert_broker_denied  GET  "/${API_VER}/containers/json"
assert_broker_denied  POST "/${API_VER}/containers/postgres/restart"
assert_no_socket_mount backend

echo
summary
exit $?
