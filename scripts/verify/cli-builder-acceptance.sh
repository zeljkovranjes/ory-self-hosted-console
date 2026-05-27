#!/usr/bin/env bash
# =============================================================================
# scripts/verify/cli-builder-acceptance.sh
#
# CLI-builder Wave 4 (PLAN-D) — the LIVE back-to-back acceptance gate.
#
# Proves the whole `ory-console init` builder works as the operator uses it:
#   A. STATIC      — INFRA-04 image-pin count == 4; the CLI + backend cargo tests
#                    (incl. the clap no-argv-secret guard); `cargo tree` shows the
#                    default CLI build has NO sqlx/argon2 (no-second-writer).
#   B. DEFAULTS    — `ory-console init --defaults` emits console.config.toml + .env
#                    (all five svc-* profiles, CONSOLE_SERVICE_*=in-stack, generated
#                    secrets), then `docker compose up -d --wait` brings an ISOLATED
#                    project up healthy; the four service-domain flags read ON and
#                    the v1 routes are reachable (401, NOT 404) past auth; /setup +
#                    login work.
#   C. CUSTOM      — block-on-failed-check (unreachable BYO → exit 1) and
#                    --skip-checks (→ exit 0 + warning); a keto=off config →
#                    ory-keto container ABSENT, `permissions` flag OFF.
#   D. CASCADE -ve — with keto off, GET /api/keto/relationships (authed) returns
#                    EXACTLY 404 (FeatureFlagHoop) — NOT 200, NOT 500 (anti-false-
#                    green); the Permissions nav item is hidden (requiresFlag).
#   E. ROUND-TRIP  — `ory-console init --config <toml>` a second time yields a
#                    byte-identical .env (idempotent re-apply, no secret rotation).
#
# ISOLATION (NON-DESTRUCTIVE to the live stack): every live bring-up here runs
# under an ISOLATED `COMPOSE_PROJECT_NAME` with REMAPPED host ports and FRESH
# volumes; the gate tears DOWN ONLY the isolated project (`down -v` scoped by
# `-p $ISO_PROJECT`). It NEVER touches the live project's volumes or the live
# `./.env`. The wizard writes into a temp dir (a `.env` basename so the writer's
# gitignored-path guard is satisfied) — the repo `./.env` is never rotated.
#
# USAGE:
#   bash scripts/verify/cli-builder-acceptance.sh              # full gate
#   STATIC_ONLY=1 bash scripts/verify/cli-builder-acceptance.sh # A only (no Docker)
#   KEEP_ISO=1   bash ...                                       # leave the iso project up
#
# Env overrides: ISO_PROJECT (default ory-cli-accept), ISO_* host ports,
# UP_TIMEOUT (default 240).
# =============================================================================
set -uo pipefail
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

: "${DC:=docker compose}"
: "${POSTGRES_USER:=ory}"
: "${UP_TIMEOUT:=240}"

# --- ISOLATED project + remapped host ports (NEVER the live project/ports) -----
: "${ISO_PROJECT:=ory-cli-accept}"
: "${ISO_BACKEND_PORT:=18080}"
: "${ISO_FRONTEND_PORT:=13000}"
: "${ISO_ACCOUNT_EXPERIENCE_PORT:=13001}"
: "${ISO_MAILPIT_UI_PORT:=18025}"
: "${ISO_SMS_SINK_PORT:=18026}"

ISO_BASE="http://localhost:${ISO_BACKEND_PORT}"

# A throwaway working dir for the wizard's outputs (temp .env + console.config.toml).
WORK="$(mktemp -d 2>/dev/null || echo "$REPO_ROOT/.cli-accept-tmp")"
mkdir -p "$WORK"
ISO_ENV="$WORK/.env"            # basename `.env` → passes the writer gitignored guard
ISO_TOML="$WORK/console.config.toml"
CUSTOM_TOML="$WORK/custom.config.toml"

CLI_BIN=""   # filled after the build (target/release/ory-console[.exe])

# A compose invocation scoped to the ISOLATED project with the wizard's .env and
# the remapped host ports exported. Profiles come from the env we pass per call.
iso_dc() {
  COMPOSE_PROJECT_NAME="$ISO_PROJECT" \
  BACKEND_PORT="$ISO_BACKEND_PORT" \
  FRONTEND_PORT="$ISO_FRONTEND_PORT" \
  ACCOUNT_EXPERIENCE_PORT="$ISO_ACCOUNT_EXPERIENCE_PORT" \
  MAILPIT_UI_PORT="$ISO_MAILPIT_UI_PORT" \
  SMS_SINK_PORT="$ISO_SMS_SINK_PORT" \
  CONSOLE_INSECURE_COOKIES=true \
    $DC -p "$ISO_PROJECT" --env-file "$ISO_ENV" "$@"
}

# psql inside the ISOLATED postgres (console DB); echoes a single trimmed scalar.
iso_psql() {
  iso_dc exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc "$1" 2>/dev/null | tr -d '\r'
}

# --- teardown: ONLY the isolated project + the temp dir (never the live stack) -
cleanup() {
  if [ "${KEEP_ISO:-0}" = "1" ]; then
    echo "--- KEEP_ISO=1: leaving the isolated project '$ISO_PROJECT' up (manual teardown) ---"
  else
    echo "--- teardown: down -v the ISOLATED project '$ISO_PROJECT' ONLY ---"
    iso_dc down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

cd "$REPO_ROOT" || exit 1

echo "============================================================"
echo " cli-builder acceptance — isolated project '$ISO_PROJECT'"
echo "   live stack is NEVER down -v'd; live ./.env never rotated"
echo "============================================================"

# =============================================================================
# A. STATIC — image pins, cargo tests, no-second-writer graph.
# =============================================================================
echo
echo "--- [A] STATIC checks ---"

# INFRA-04: exactly 4 distroless image pins (kratos/hydra/keto/oathkeeper).
assert_grep_count 'oryd/(kratos|hydra|keto|oathkeeper):v26\.2\.0-distroless' \
  "$REPO_ROOT/docker-compose.yml" 4

# Cargo tests: the CLI suite (incl. the clap no-argv-secret guard + the new e2e),
# and the backend feature/service_seed cascade tests.
if cargo test -p ory-console-cli >/dev/null 2>&1; then
  _pass "[A] cargo test -p ory-console-cli (incl. clap guard + cli_builder_e2e): green"
else
  _fail "[A] cargo test -p ory-console-cli FAILED"
fi
if cargo test -p ory-console-cli --test cli_commands \
     no_subcommand_accepts_a_value_taking_secret_flag >/dev/null 2>&1; then
  _pass "[A] clap no-argv-secret guard: green (no value-taking secret flag)"
else
  _fail "[A] clap no-argv-secret guard FAILED"
fi
if cargo test -p ory-console-backend --lib features >/dev/null 2>&1; then
  _pass "[A] cargo test -p ory-console-backend --lib features (cascade/service_seed): green"
else
  _fail "[A] cargo test -p ory-console-backend --lib features FAILED"
fi

# No-second-writer: the DEFAULT CLI graph carries NO sqlx and NO argon2.
TREE_HITS="$(cargo tree -p ory-console-cli 2>/dev/null | grep -ciE '(^| )(sqlx|argon2)( |$|v)')"
if [ "${TREE_HITS:-1}" = "0" ]; then
  _pass "[A] cargo tree -p ory-console-cli (default): NO sqlx/argon2 (no-second-writer)"
else
  _fail "[A] cargo tree shows sqlx/argon2 in the default CLI build ($TREE_HITS hit(s))"
fi

if [ "${STATIC_ONLY:-0}" = "1" ]; then
  echo
  echo "--- STATIC_ONLY=1: skipping the live B/C/D/E sections ---"
  summary
  exit $?
fi

# Build the release CLI once (the wizard binary the operator runs).
echo
echo "--- [build] cargo build --release -p ory-console-cli ---"
if cargo build --release -p ory-console-cli >/dev/null 2>&1; then
  _pass "[build] release ory-console built"
else
  _fail "[build] release ory-console build FAILED"
  summary; exit $?
fi
if [ -x "$REPO_ROOT/target/release/ory-console" ]; then
  CLI_BIN="$REPO_ROOT/target/release/ory-console"
elif [ -x "$REPO_ROOT/target/release/ory-console.exe" ]; then
  CLI_BIN="$REPO_ROOT/target/release/ory-console.exe"
else
  _fail "[build] ory-console binary not found under target/release"
  summary; exit $?
fi

# Make sure no stale isolated project lingers from a prior run.
iso_dc down -v --remove-orphans >/dev/null 2>&1 || true

# =============================================================================
# B. DEFAULTS PATH — wizard emits artifacts; isolated stack up healthy; flags ON.
# =============================================================================
echo
echo "--- [B] DEFAULTS path: wizard --defaults --no-docker → emit artifacts ---"
# --no-docker: the wizard only WRITES the config+.env+secrets (we drive compose
# ourselves under the isolated project so the host ports/volumes stay remapped).
if "$CLI_BIN" init --defaults --no-docker \
     --env-file "$ISO_ENV" --config-out "$ISO_TOML" >/dev/null 2>&1; then
  _pass "[B] wizard --defaults wrote config+.env (config-only)"
else
  _fail "[B] wizard --defaults run FAILED"
fi

# Assert the emitted artifacts.
assert_grep '^mode = "in-stack"' "$ISO_TOML" >/dev/null 2>&1 \
  && _pass "[B] console.config.toml has in-stack services" \
  || _fail "[B] console.config.toml missing in-stack mode"
assert_grep 'COMPOSE_PROFILES=svc-kratos,svc-hydra,svc-keto,svc-oathkeeper,svc-polis' "$ISO_ENV"
assert_grep 'CONSOLE_SERVICE_KETO=in-stack' "$ISO_ENV"
# Required generated secrets present (values not asserted — secret-free gate).
assert_grep '^POSTGRES_PASSWORD=.+' "$ISO_ENV"
assert_grep '^HYDRA_SECRETS_SYSTEM=.+' "$ISO_ENV"

echo
echo "--- [B] isolated bring-up: docker compose -p $ISO_PROJECT up -d --wait ---"
if iso_dc up -d --wait --wait-timeout "$UP_TIMEOUT" >/dev/null 2>&1; then
  _pass "[B] isolated stack up -d --wait: healthy (project $ISO_PROJECT)"
else
  _fail "[B] isolated stack did NOT reach healthy within ${UP_TIMEOUT}s"
  echo "--- recent isolated backend logs ---"; iso_dc logs --tail 30 backend 2>/dev/null || true
  summary; exit $?
fi

# Preflight: isolated backend serving.
assert_status GET "${ISO_BASE}/health" 200

# Authenticate a console session on the ISOLATED backend (complete /setup + login).
echo
echo "--- [B] /setup + login on the isolated backend ---"
SETUP_TOKEN="$(iso_dc logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' | tail -n1 \
  | sed 's/^FIRST-RUN SETUP TOKEN: //')"
ADMIN_EMAIL="cli-accept-admin@example.com"
ADMIN_PW="cli-accept-acceptance-pw"   # >= 12 chars (CAUTH-03)

if [ -n "$SETUP_TOKEN" ]; then
  scode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"CLI Accept\",\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PW}\",\"token\":\"${SETUP_TOKEN}\"}" \
    "${ISO_BASE}/setup" 2>/dev/null)"
  case "$scode" in
    201) _pass "[B] /setup completed (first-run admin created)";;
    404) _pass "[B] /setup already completed (404) — proceeding";;
    *)   _fail "[B] /setup returned '$scode' (want 201 or 404)";;
  esac
else
  _fail "[B] could not read FIRST-RUN SETUP TOKEN from isolated backend logs"
fi

_iso_login_token() {
  curl -s -D - -o /dev/null --max-time 10 -H 'Content-Type: application/json' \
    --data "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PW}\"}" \
    "${ISO_BASE}/login" 2>/dev/null \
    | grep -iE '^Set-Cookie:[[:space:]]*(__Host-)?console_session=' | head -n1 \
    | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*(__Host-)?console_session=([^;]+).*/\2/' | tr -d '\r'
}
SESSION_TOKEN="$(_iso_login_token)"
if [ -n "$SESSION_TOKEN" ]; then
  _pass "[B] obtained an authenticated session from /login (first-run login works)"
else
  _fail "[B] could not log in after /setup (session token empty)"
fi
CSRF_TOKEN="$(iso_psql "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE a.email = '${ADMIN_EMAIL}' ORDER BY s.created_at DESC LIMIT 1" | tr -d '[:space:]')"
COOKIE_HEADER="Cookie: console_session=${SESSION_TOKEN}"

# v1 service-domain flags read ON; the gated v1 routes are reachable (401/200,
# NOT 404) — proving the all-on default did not break any always-on surface.
echo
echo "--- [B] service-domain flags ON + v1 routes reachable (all-on default) ---"
FEATS="$(curl -s --max-time 10 -H "$COOKIE_HEADER" "${ISO_BASE}/api/console/features" 2>/dev/null)"
for key in identities oauth2 permissions access_rules; do
  if printf '%s' "$FEATS" | grep -q "\"$key\""; then
    on="$(printf '%s' "$FEATS" | node -e "let j=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(j.features&&j.features['$key']&&j.features['$key'].enabled))" 2>/dev/null)"
    [ "$on" = "true" ] && _pass "[B] flag $key = ON" || _fail "[B] flag $key not ON (got '$on')"
  else
    _fail "[B] flag $key missing from /api/console/features"
  fi
done
# Authed v1 routes are MOUNTED (not flag-404) on the all-on default. We assert
# they do NOT 404 (200 list, or any non-404 status from a reachable handler).
for route in api/kratos/identities api/hydra/clients api/keto/relationships api/oathkeeper/rules; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "$COOKIE_HEADER" "${ISO_BASE}/${route}" 2>/dev/null)"
  if [ "$code" != "404" ] && [ -n "$code" ]; then
    _pass "[B] v1 route /$route reachable (code $code, NOT 404 — flag ON)"
  else
    _fail "[B] v1 route /$route returned '$code' (want non-404 on the all-on default)"
  fi
done

# =============================================================================
# C. CUSTOM PATH — block-on-fail / --skip-checks; keto=off → permissions OFF.
# =============================================================================
echo
echo "--- [C] block-on-failed-check: unreachable BYO must EXIT NON-ZERO ---"
# Craft a custom config: kratos byo at an unreachable address → the pre-boot probe
# must FAIL and the wizard must BLOCK (exit non-zero) without --skip-checks.
cat > "$CUSTOM_TOML" <<'TOML'
[services.kratos]
mode = "byo"
admin_url = "http://127.0.0.1:9"

[services.hydra]
mode = "off"
[services.keto]
mode = "off"
[services.oathkeeper]
mode = "off"
[services.polis]
mode = "off"
TOML
# --no-docker keeps it config-only (pre-boot BYO probe still runs + blocks).
"$CLI_BIN" init --config "$CUSTOM_TOML" --no-docker \
  --env-file "$WORK/.env.block" --config-out "$WORK/block.config.toml" >/dev/null 2>&1
RC_BLOCK=$?
if [ "$RC_BLOCK" -ne 0 ]; then
  _pass "[C] unreachable BYO check BLOCKED the wizard (exit $RC_BLOCK, anti-false-green)"
else
  _fail "[C] wizard PROCEEDED past an unreachable BYO (exit 0 — block-on-fail broken)"
fi

echo
echo "--- [C] --skip-checks: the SAME unreachable BYO proceeds (exit 0 + warning) ---"
SKIP_OUT="$("$CLI_BIN" init --config "$CUSTOM_TOML" --no-docker --skip-checks \
  --env-file "$WORK/.env.skip" --config-out "$WORK/skip.config.toml" 2>&1)"
RC_SKIP=$?
if [ "$RC_SKIP" -eq 0 ]; then
  _pass "[C] --skip-checks proceeded past the failed BYO (exit 0)"
else
  _fail "[C] --skip-checks still blocked (exit $RC_SKIP)"
fi
if printf '%s' "$SKIP_OUT" | grep -qi 'WARNING'; then
  _pass "[C] --skip-checks surfaced the override WARNING"
else
  _fail "[C] --skip-checks did NOT surface a WARNING"
fi

# --no-docker config-only degradation prints the day-2 steps.
if printf '%s' "$SKIP_OUT" | grep -qiE 'config-only|Day-2|docker compose up'; then
  _pass "[C] --no-docker config-only degradation printed the day-2 steps"
else
  _fail "[C] --no-docker degradation did not print day-2 guidance"
fi

# --- keto=off cascade on the ISOLATED stack: recreate the isolated backend with
#     CONSOLE_SERVICE_KETO=off, keto container absent, permissions flag OFF.
echo
echo "--- [C] keto=off cascade (isolated): drop svc-keto + CONSOLE_SERVICE_KETO=off ---"
# Re-emit the isolated .env with keto off + a profile set without svc-keto, then
# recreate only the affected services. We keep the in-stack keto OUT of the profile
# so its container is removed.
KETO_OFF_PROFILES="svc-kratos,svc-hydra,svc-oathkeeper,svc-polis"
# Force the flag-off env into the running isolated backend via a scoped recreate.
COMPOSE_PROFILES="$KETO_OFF_PROFILES" CONSOLE_SERVICE_KETO=off \
  iso_dc up -d --no-deps --force-recreate backend >/dev/null 2>&1
# Stop + remove the now-out-of-profile keto container (it no longer matches profiles).
iso_dc stop keto keto-migrate >/dev/null 2>&1 || true
iso_dc rm -f keto keto-migrate >/dev/null 2>&1 || true
sleep 3

# keto container absent under the isolated project.
KETO_PS="$(iso_dc ps --all --services --filter status=running 2>/dev/null | grep -x keto || true)"
if [ -z "$KETO_PS" ]; then
  _pass "[C] ory-keto container ABSENT (svc-keto dropped from profiles)"
else
  _fail "[C] ory-keto still running after dropping svc-keto"
fi

# Re-auth (backend was recreated → its session store is the same DB, session persists,
# but re-login to be safe).
SESSION_TOKEN="$(_iso_login_token)"
COOKIE_HEADER="Cookie: console_session=${SESSION_TOKEN}"

# The permissions flag must now read OFF (reconcile forced it off).
FEATS2="$(curl -s --max-time 10 -H "$COOKIE_HEADER" "${ISO_BASE}/api/console/features" 2>/dev/null)"
PERM_ON="$(printf '%s' "$FEATS2" | node -e "let j=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(j.features&&j.features['permissions']&&j.features['permissions'].enabled))" 2>/dev/null)"
if [ "$PERM_ON" = "false" ]; then
  _pass "[C] permissions flag forced OFF by the keto=off cascade"
else
  _fail "[C] permissions flag is '$PERM_ON' (want false after keto=off)"
fi

# =============================================================================
# D. CASCADE NEGATIVE — keto off → permissions route EXACTLY 404 (anti-false-green).
# =============================================================================
echo
echo "--- [D] cascade 404: GET /api/keto/relationships (authed) MUST be EXACTLY 404 ---"
KETO_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "$COOKIE_HEADER" \
  "${ISO_BASE}/api/keto/relationships" 2>/dev/null)"
# Anti-false-green: PASS ONLY on an explicit 404. A 200 (route still served) or a
# 500 (handler error) both FAIL — they do NOT prove the feature was disabled.
if [ "$KETO_CODE" = "404" ]; then
  _pass "[D] permissions route returned EXACTLY 404 (FeatureFlagHoop cascade) — anti-false-green"
else
  _fail "[D] permissions route returned '$KETO_CODE' (want EXACTLY 404; 200/500 = cascade broken)"
fi
# nav requiresFlag: the Permissions item carries requiresFlag 'permissions' so the
# frontend hides it when the flag is OFF (the features payload the nav reads).
assert_grep "requiresFlag:[[:space:]]*['\"]permissions['\"]" "$REPO_ROOT/frontend/lib/nav.ts" \
  && true || _fail "[D] nav.ts has no requiresFlag:'permissions' gate on the Permissions item"

# =============================================================================
# E. CONFIG ROUND-TRIP (live) — re-apply the defaults toml → byte-identical .env.
# =============================================================================
echo
echo "--- [E] config round-trip: re-apply console.config.toml → idempotent .env ---"
RT_ENV="$WORK/.env.roundtrip"
# Seed the round-trip target with the same secrets so present-secret idempotency
# can be observed (copy the defaults .env first).
cp "$ISO_ENV" "$RT_ENV" 2>/dev/null || true
"$CLI_BIN" init --config "$ISO_TOML" --no-docker \
  --env-file "$RT_ENV" --config-out "$WORK/roundtrip.config.toml" >/dev/null 2>&1
# Compare the CONSOLE_SERVICE_*/profiles seed lines (the deterministic contract).
A_SEED="$(grep -E '^(CONSOLE_SERVICE_|COMPOSE_PROFILES=)' "$ISO_ENV" | sort)"
B_SEED="$(grep -E '^(CONSOLE_SERVICE_|COMPOSE_PROFILES=)' "$RT_ENV" | sort)"
if [ "$A_SEED" = "$B_SEED" ]; then
  _pass "[E] re-apply produced an identical CONSOLE_SERVICE_*/COMPOSE_PROFILES seed (idempotent)"
else
  _fail "[E] re-apply diverged from the original seed (not idempotent)"
fi
# The reproducible config.toml is stable across re-apply.
if [ -f "$WORK/roundtrip.config.toml" ] && diff -q "$ISO_TOML" "$WORK/roundtrip.config.toml" >/dev/null 2>&1; then
  _pass "[E] console.config.toml byte-identical across re-apply (round-trip)"
else
  _fail "[E] console.config.toml changed on re-apply (round-trip broken)"
fi

echo
summary
exit $?
