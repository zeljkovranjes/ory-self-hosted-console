#!/usr/bin/env bash
# scripts/verify/phase7-acceptance.sh
# -----------------------------------------------------------------------------
# Phase 7 (authentication-config) live-stack acceptance gate. Proves the whole
# phase end-to-end against the REAL compose stack: a representative key per
# Kratos auth SECTION group is written through the Phase-4 transactional engine
# (validate -> write -> restart ONLY Kratos -> healthy -> GET reflects, secrets
# masked), invalid input is refused 422 with NO disk write, sensitive/out-of-scope
# keys are refused 403, and the FE-05 bundle-egress invariant still holds.
#
# Every negative assertion PASSes ONLY on the EXACT expected refusal (anti-false-
# green, lib.sh T-03/T-06 contract): a 2xx where a 4xx is due, an empty body, or
# a missing refusal all FAIL — a SKIP is never a silent pass.
#
# The assertion groups (each a labeled section below):
#   1. Positive writes per section group (AUTH-01/03/04/06/07/09/10/11/HOOK-04):
#      each PUT validates -> writes -> 200 {status:healthy} -> ONLY Kratos
#      restarted (Hydra/Keto/Oathkeeper StartedAt unchanged) -> GET reflects.
#      OIDC + SMTP additionally prove SECRET MASKING and the untouched-secret
#      PRESERVE (no-clobber) round-trip, plus a retype-overwrites leg.
#   2. Negative — invalid value -> 422 with NO disk write (bad AAL enum, bad
#      duration); sensitive (/dsn, /secrets/*, /serve/admin, connection_uri via
#      the section path) -> 403; per-index OIDC pointer -> 403; auth/CSRF
#      (unauth -> 401, authed-no-CSRF -> 403).
#   3. CLI-compat: the resulting kratos.yml stays a config Kratos boots on (the
#      stack is healthy after all the writes = valid-Ory-config proof).
#   4. Egress regression (FE-05): bundle-egress.sh -> no Ory host/port/SDK/CDN in
#      the built bundle.
#
# Run against a FRESH-volume bring-up (Git Bash on Windows: prefix compose with
# MSYS_NO_PATHCONV=1 so leading-slash URL paths are not mangled). This script
# does the FULL lifecycle itself (build -> up --wait -> drive -> down -v) unless
# you ask it to reuse a stack you already brought up:
#
#   MSYS_NO_PATHCONV=1 bash scripts/verify/phase7-acceptance.sh
#
# Env (all optional):
#   KEEP_STACK=1     do NOT `docker compose down -v` on exit (debugging)
#   REUSE_STACK=1    assume the stack is already up (skip build + up); still
#                    runs the bundle gate and the live assertions
#   SKIP_EGRESS=1    skip the (slow) bundle-egress build gate (live-only run)
#   UP_TIMEOUT=1500  seconds to allow `docker compose up -d --wait` (default 1500
#                    = 25min — the frontend image build + boot is heavy)
# -----------------------------------------------------------------------------
set -u

# shellcheck source=scripts/verify/lib.sh
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${BACKEND_BASE_URL:=http://localhost:${BACKEND_PORT:-8080}}"
: "${UP_TIMEOUT:=1500}"

# The live Kratos config FILE (bind-mounted RW into backend, RO into Kratos). The
# backend writes here on a config PUT; the host sees the same path. We back it up
# at start and restore it on exit so the gate is idempotent.
KRATOS_YAML="${REPO_ROOT}/config/kratos/kratos.yml"
: "${KRATOS_CTR:=ory-kratos}"
: "${HYDRA_CTR:=ory-hydra}"
: "${KETO_CTR:=ory-keto}"
: "${OATHKEEPER_CTR:=ory-oathkeeper}"

# The masked-secret sentinel literal — MUST equal backend secret_merge::MASKED.
# We do NOT rely on this hardcoded value for the PRESERVE assertions; those echo
# back the EXACT literal captured from a GET. This is only used for the masked
# GET assertion's human-readable message.
MASKED_SENTINEL="__ory_console_masked__"

echo "=== Phase 7 acceptance: authentication config (AUTH-01/03/04/06..11 + HOOK-04) ==="
echo "Backend base URL: ${BACKEND_BASE_URL}"
echo "Repo root:        ${REPO_ROOT}"
echo "Kratos config:    ${KRATOS_YAML}"

# -----------------------------------------------------------------------------
# Idempotence: preserve the ORIGINAL kratos.yml and restore it on exit (every
# positive write mutates it in place + triggers a Kratos restart). Then
# `docker compose down -v` unless KEEP_STACK=1.
# -----------------------------------------------------------------------------
ORIG_YAML_SNAPSHOT="$(mktemp 2>/dev/null || echo "${KRATOS_YAML}.orig.$$")"
cp "$KRATOS_YAML" "$ORIG_YAML_SNAPSHOT" 2>/dev/null || true

teardown() {
  # Restore the original kratos.yml (idempotent gate).
  if [ -f "$ORIG_YAML_SNAPSHOT" ]; then
    cp "$ORIG_YAML_SNAPSHOT" "$KRATOS_YAML" 2>/dev/null || true
    rm -f "$ORIG_YAML_SNAPSHOT" 2>/dev/null || true
  fi
  rm -f "${KRATOS_YAML}.bak" 2>/dev/null || true
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
# CRITERION 4 (FE-05) FIRST — bundle egress. The cheapest hard gate; it builds
# the frontend and greps the built output, and must hold regardless of the live
# stack. (Run before bring-up so a leaked literal fails fast.)
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
# Bring the stack up (unless REUSE_STACK=1) for the live assertions. Use insecure
# cookies for THIS ephemeral run so curl can replay the session cookie over the
# plain-HTTP compose edge (mirrors the phase4/5/6 gates).
# =============================================================================
export CONSOLE_INSECURE_COOKIES=true

if [ "${REUSE_STACK:-0}" != "1" ]; then
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
    echo "--- recent kratos logs ---";  $DC logs --tail 40 "$KRATOS_CTR" 2>/dev/null || true
    summary
    exit $?
  fi
fi

# Preflight: backend + all four Ory services healthy and serving.
echo
echo "--- [preflight] backend + ory services healthy ---"
assert_healthy backend
assert_healthy "$KRATOS_CTR"
assert_status GET "${BACKEND_BASE_URL}/health" 200
if [ -f "$KRATOS_YAML" ]; then
  _pass "live kratos.yml present: $KRATOS_YAML"
else
  _fail "live kratos.yml MISSING: $KRATOS_YAML (cannot run the config-edit criteria)"
fi

# =============================================================================
# Authenticate a console session (complete /setup + login). Mirrors the Phase-6
# gate: parse the one-time FIRST-RUN SETUP TOKEN from the backend logs, then
# replay the session cookie + the per-session CSRF token (read from the console
# DB session row) on every mutating call.
# =============================================================================
echo
echo "--- [auth] complete /setup + login for an authenticated session ---"
SETUP_TOKEN="$($DC logs backend 2>/dev/null \
  | grep -oE 'FIRST-RUN SETUP TOKEN: [A-Za-z0-9_-]+' \
  | tail -n1 | sed 's/^FIRST-RUN SETUP TOKEN: //')"

ADMIN_EMAIL_TEST="phase7-admin@example.com"
ADMIN_PW_TEST="phase7-acceptance-pw"   # >= 12 chars (CAUTH-03 policy)
: "${SESSION_COOKIE_NAME:=console_session}"   # insecure-cookie run => dev name

state_now="$(curl -s --max-time 10 "${BACKEND_BASE_URL}/api/console/state" 2>/dev/null)"
already_init=0
printf '%s' "$state_now" | grep -q '"initialized":true' && already_init=1

if [ -n "$SETUP_TOKEN" ]; then
  setup_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Phase7 Admin\",\"email\":\"${ADMIN_EMAIL_TEST}\",\"password\":\"${ADMIN_PW_TEST}\",\"token\":\"${SETUP_TOKEN}\"}" \
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

_csrf_for_email() {
  local email="$1"
  $DC exec -T postgres psql -U "$POSTGRES_USER" -d console -tAc \
    "SELECT s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
     WHERE a.email = '${email}' ORDER BY s.created_at DESC LIMIT 1" 2>/dev/null \
    | tr -d '[:space:]'
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

# Guard: without an authenticated session the live criteria cannot run.
if [ -z "${COOKIE_HEADER:-}" ] || [ -z "${CSRF_TOKEN:-}" ]; then
  echo
  _fail "no authenticated session/CSRF — skipping the live Phase-7 criteria"
  summary
  exit $?
fi

CFG_URL="${BACKEND_BASE_URL}/api/config/kratos"
SMTP_URL="${BACKEND_BASE_URL}/api/kratos/smtp-connection"

# Authenticated GET (cookie only; GET is CSRF-exempt). Echo "CODE<newline>BODY".
_auth_get() {
  curl -s -w '\n%{http_code}' --max-time 30 -H "$COOKIE_HEADER" "$1" 2>/dev/null
}
# Authenticated mutating call (cookie + CSRF + JSON body). Echo "CODE<newline>BODY".
_auth_mut() {
  local method="$1" url="$2" json="${3:-}"
  local -a a=(-s -w '\n%{http_code}' --max-time 200 -X "$method" \
    -H "$COOKIE_HEADER" -H "X-CSRF-Token: ${CSRF_TOKEN}")
  [ -n "$json" ] && a+=(-H 'Content-Type: application/json' --data "$json")
  curl "${a[@]}" "$url" 2>/dev/null
}
_code_of() { printf '%s' "$1" | tail -n1; }
_body_of() { printf '%s' "$1" | sed '$d'; }

# Pull a JSON field from a body via node (the toolchain is present per CLAUDE.md).
# Usage: _json_field "<body>" '<js-expr-over-data>'  (prints the result or empty)
_json_field() {
  printf '%s' "$1" | EXPR="$2" node -e '
    const expr = process.env.EXPR;
    let input = require("fs").readFileSync(0, "utf8");
    let data; try { data = JSON.parse(input); } catch (e) { process.exit(0); }
    let out;
    try { out = (function(){ return eval(expr); })(); } catch (e) { process.exit(0); }
    if (out === undefined || out === null) process.exit(0);
    process.stdout.write(typeof out === "string" ? out : JSON.stringify(out));
  ' 2>/dev/null
}

# A PUT-section helper that asserts: 200 {status:healthy} AND only Kratos
# restarted. Usage: put_section_healthy "<label>" "<section>" "<json-body>"
put_section_healthy() {
  local label="$1" section="$2" body="$3" resp code rbody
  snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
  resp="$(_auth_mut PUT "${CFG_URL}/${section}" "$body")"
  code="$(_code_of "$resp")"; rbody="$(_body_of "$resp")"
  if [ "$code" = "200" ] && printf '%s' "$rbody" | grep -q '"status":"healthy"'; then
    _pass "${label}: PUT /${section} -> 200 {status:healthy} (validated + written + Kratos healthy)"
  else
    _fail "${label}: PUT /${section} -> '$code' (want 200 {status:healthy}; body: $rbody)"
    return 1
  fi
  assert_only_container_restarted "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
  wait_container_healthy "$KRATOS_CTR" 90
  return 0
}

echo
echo "============================================================"
echo " GROUP 1 — positive writes per section group (live engine)"
echo "============================================================"

# --- AUTH-01: Methods toggle ------------------------------------------------
echo
echo "--- [AUTH-01] methods: toggle code.enabled -> write/restart-Kratos-only/GET ---"
if put_section_healthy "[AUTH-01]" "methods" '{"/selfservice/methods/code/enabled": true}'; then
  m_get="$(_body_of "$(_auth_get "${CFG_URL}/methods")")"
  if [ "$(_json_field "$m_get" 'data["/selfservice/methods/code/enabled"]')" = "true" ]; then
    _pass "[AUTH-01] GET /methods reflects code.enabled=true"
  else
    _fail "[AUTH-01] GET /methods does NOT reflect the toggle (body: $m_get)"
  fi
fi

# --- AUTH-06: Sessions lifespan --------------------------------------------
echo
echo "--- [AUTH-06] sessions: set session.lifespan=48h -> write/restart/GET ---"
if put_section_healthy "[AUTH-06]" "sessions" '{"/session/lifespan":"48h"}'; then
  s_get="$(_body_of "$(_auth_get "${CFG_URL}/sessions")")"
  if [ "$(_json_field "$s_get" 'data["/session/lifespan"]')" = "48h" ]; then
    _pass "[AUTH-06] GET /sessions reflects session.lifespan=48h"
  else
    _fail "[AUTH-06] GET /sessions does NOT reflect lifespan (body: $s_get)"
  fi
fi

# --- AUTH-03: MFA required_aal=highest_available (Pitfall 1 corrected enum) --
# The schema-valid AAL enforcement pointer in v26.2.0 is /session/whoami/required_aal
# (the `flows.login` object is additionalProperties:false with NO required_aal —
# Plan-05 finding; see SUMMARY deviations). The MFA page owns this edit; the pointer
# is in both KRATOS_MFA and KRATOS_SESSIONS allowlists. We assert the CORRECTED enum
# `highest_available` (Pitfall 1: NOT `highest_aal`) writes and reflects.
echo
echo "--- [AUTH-03] mfa: set whoami.required_aal=highest_available -> write/restart/GET ---"
if put_section_healthy "[AUTH-03]" "mfa" '{"/session/whoami/required_aal":"highest_available"}'; then
  a_get="$(_body_of "$(_auth_get "${CFG_URL}/mfa")")"
  if [ "$(_json_field "$a_get" 'data["/session/whoami/required_aal"]')" = "highest_available" ]; then
    _pass "[AUTH-03] GET /mfa reflects required_aal=highest_available (corrected enum, Pitfall 1)"
  else
    _fail "[AUTH-03] GET /mfa does NOT reflect required_aal (body: $a_get)"
  fi
fi

# NOTE: AUTH-07 (recovery enabled) is exercised AFTER the SMTP connection_uri is
# set — the v26.2.0 schema's allOf[0] makes `courier` a REQUIRED top-level property
# whenever recovery/verification is enabled, so the courier block must exist first
# (Plan-05 finding; see SUMMARY deviations). It runs in the SMTP group below.

# --- AUTH-04: OIDC provider (array) + masked secret + PRESERVE round-trip ---
echo
echo "--- [AUTH-04] oidc: add a provider (whole-array) w/ client_secret + base64 mapper ---"
OIDC_MAPPER_SRC='function(ctx) { identity: { traits: { email: ctx.claims.email } } }'
# providers is a whole-array value; oidc.enabled co-set so the method is on.
OIDC_BODY="$(MAPPER="$OIDC_MAPPER_SRC" node -e '
  const mapper = process.env.MAPPER;
  const body = {
    "/selfservice/methods/oidc/enabled": true,
    "/selfservice/methods/oidc/config/providers": [{
      id: "acme",
      provider: "generic",
      client_id: "acme-client-id",
      client_secret: "s3cret",
      mapper_url: mapper,
      issuer_url: "https://accounts.example.com"
    }]
  };
  process.stdout.write(JSON.stringify(body));
')"
OIDC_OK=0
if put_section_healthy "[AUTH-04]" "oidc" "$OIDC_BODY"; then
  OIDC_OK=1
  o_get="$(_body_of "$(_auth_get "${CFG_URL}/oidc")")"
  # Capture the EXACT masked literal the backend emits for client_secret (do NOT
  # hardcode a guessed sentinel — the PRESERVE leg echoes THIS back verbatim).
  CAP_SECRET="$(_json_field "$o_get" '
    var ps = data["/selfservice/methods/oidc/config/providers"];
    var p = ps && ps.find(function(x){return x.id==="acme";});
    p ? p.client_secret : null
  ')"
  CAP_MAPPER="$(_json_field "$o_get" '
    var ps = data["/selfservice/methods/oidc/config/providers"];
    var p = ps && ps.find(function(x){return x.id==="acme";});
    p ? p.mapper_url : null
  ')"
  # 1) the provider is present.
  if [ -n "$CAP_SECRET" ]; then
    _pass "[AUTH-04] GET /oidc returns the 'acme' provider"
  else
    _fail "[AUTH-04] GET /oidc does NOT return the 'acme' provider (body: $o_get)"
  fi
  # 2) the secret is MASKED — never the real value.
  if [ "$CAP_SECRET" != "s3cret" ] && [ -n "$CAP_SECRET" ]; then
    _pass "[AUTH-04] client_secret is MASKED on GET (got '$CAP_SECRET', not 's3cret'; sentinel=$MASKED_SENTINEL)"
  else
    _fail "[AUTH-04] client_secret LEAKED on GET (got '$CAP_SECRET' — must NOT be the real 's3cret')"
  fi
  # 3) the mapper is DECODED to source (not a raw base64:// URI).
  if printf '%s' "$CAP_MAPPER" | grep -q 'ctx.claims.email' \
     && ! printf '%s' "$CAP_MAPPER" | grep -q 'base64://'; then
    _pass "[AUTH-04] mapper_url decoded to Jsonnet source on GET (not raw base64://)"
  else
    _fail "[AUTH-04] mapper_url NOT decoded to source on GET (got '$CAP_MAPPER')"
  fi
else
  _fail "[AUTH-04] OIDC initial write failed — skipping the PRESERVE/retype legs"
fi

# --- AUTH-04: untouched-secret PRESERVE (no clobber) + retype-replace -------
if [ "$OIDC_OK" = "1" ] && [ -n "${CAP_SECRET:-}" ]; then
  echo
  echo "--- [AUTH-04] OIDC untouched-secret PRESERVE: re-PUT echoing the captured mask ---"
  # Re-PUT the SAME provider but with client_secret = the EXACT masked literal
  # captured from the GET (verbatim), changing only a non-secret field (scope).
  # If merge-by-id works, the ORIGINAL 's3cret' is preserved (no clobber).
  PRESERVE_BODY="$(MAPPER="$OIDC_MAPPER_SRC" MASK="$CAP_SECRET" node -e '
    const mapper = process.env.MAPPER, mask = process.env.MASK;
    const body = {
      "/selfservice/methods/oidc/enabled": true,
      "/selfservice/methods/oidc/config/providers": [{
        id: "acme",
        provider: "generic",
        client_id: "acme-client-id",
        client_secret: mask,
        mapper_url: mapper,
        issuer_url: "https://accounts.example.com",
        scope: ["openid", "email"]
      }]
    };
    process.stdout.write(JSON.stringify(body));
  ')"
  if put_section_healthy "[AUTH-04 preserve]" "oidc" "$PRESERVE_BODY"; then
    # Re-GET: the secret must STILL be masked/set (i.e. NOT cleared to the literal
    # mask string in the file, and NOT empty) — proving 's3cret' was preserved.
    o_get2="$(_body_of "$(_auth_get "${CFG_URL}/oidc")")"
    SEC2="$(_json_field "$o_get2" '
      var ps = data["/selfservice/methods/oidc/config/providers"];
      var p = ps && ps.find(function(x){return x.id==="acme";});
      p ? p.client_secret : null
    ')"
    SCOPE2="$(_json_field "$o_get2" '
      var ps = data["/selfservice/methods/oidc/config/providers"];
      var p = ps && ps.find(function(x){return x.id==="acme";});
      (p && p.scope) ? p.scope.join(",") : null
    ')"
    if [ -n "$SEC2" ] && [ "$SEC2" != "s3cret" ]; then
      _pass "[AUTH-04] secret still MASKED/SET after a mask-echo PUT (original preserved, no clobber)"
    else
      _fail "[AUTH-04] secret NOT preserved after mask-echo PUT (got '$SEC2' — clobbered!)"
    fi
    if [ "$SCOPE2" = "openid,email" ]; then
      _pass "[AUTH-04] the non-secret field (scope) was updated by the same PUT"
    else
      _fail "[AUTH-04] the non-secret scope did NOT update (got '$SCOPE2')"
    fi
  fi

  # Backstop the preserve claim against the FILE: the masked literal must NOT have
  # been written verbatim as the stored secret (would mean the real secret was
  # clobbered with the sentinel string).
  echo
  echo "--- [AUTH-04] file backstop: the mask sentinel was NOT written as the stored secret ---"
  if grep -Fq "$MASKED_SENTINEL" "$KRATOS_YAML"; then
    _fail "[AUTH-04] the mask sentinel '$MASKED_SENTINEL' is in kratos.yml — the real secret was clobbered!"
  else
    _pass "[AUTH-04] the mask sentinel is absent from kratos.yml (real secret preserved on disk)"
  fi

  echo
  echo "--- [AUTH-04] OIDC retype-replace: a real new client_secret overwrites ---"
  RETYPE_BODY="$(MAPPER="$OIDC_MAPPER_SRC" node -e '
    const mapper = process.env.MAPPER;
    const body = {
      "/selfservice/methods/oidc/enabled": true,
      "/selfservice/methods/oidc/config/providers": [{
        id: "acme",
        provider: "generic",
        client_id: "acme-client-id",
        client_secret: "n3w-s3cret",
        mapper_url: mapper,
        issuer_url: "https://accounts.example.com",
        scope: ["openid", "email"]
      }]
    };
    process.stdout.write(JSON.stringify(body));
  ')"
  if put_section_healthy "[AUTH-04 retype]" "oidc" "$RETYPE_BODY"; then
    o_get3="$(_body_of "$(_auth_get "${CFG_URL}/oidc")")"
    SEC3="$(_json_field "$o_get3" '
      var ps = data["/selfservice/methods/oidc/config/providers"];
      var p = ps && ps.find(function(x){return x.id==="acme";});
      p ? p.client_secret : null
    ')"
    # The new secret must still be masked on GET (write-only), and the file must
    # NOT carry the OLD 's3cret' anymore (overwrite took effect).
    if [ -n "$SEC3" ] && [ "$SEC3" != "n3w-s3cret" ]; then
      _pass "[AUTH-04] retyped secret is also masked on GET (write-only round-trip holds)"
    else
      _fail "[AUTH-04] retyped secret leaked or empty on GET (got '$SEC3')"
    fi
  fi
fi

# --- AUTH-10: SMS channel (array) + base64 body -----------------------------
echo
echo "--- [AUTH-10] sms: add an http 'sms' channel (whole-array) w/ base64 body ---"
SMS_BODY_SRC='function(ctx) { body: "code: " + ctx.Body }'
SMS_BODY="$(BODY="$SMS_BODY_SRC" node -e '
  const b = process.env.BODY;
  const body = {
    "/courier/channels": [{
      id: "sms",
      type: "http",
      request_config: {
        url: "https://sms.example.com/send",
        method: "POST",
        body: b,
        auth: { type: "basic_auth", config: { user: "u", password: "p4ss" } }
      }
    }]
  };
  process.stdout.write(JSON.stringify(body));
')"
if put_section_healthy "[AUTH-10]" "sms" "$SMS_BODY"; then
  sms_get="$(_body_of "$(_auth_get "${CFG_URL}/sms")")"
  SMS_ID="$(_json_field "$sms_get" '
    var ch = data["/courier/channels"];
    (ch && ch[0]) ? ch[0].id : null
  ')"
  SMS_PW="$(_json_field "$sms_get" '
    var ch = data["/courier/channels"];
    (ch && ch[0] && ch[0].request_config && ch[0].request_config.auth && ch[0].request_config.auth.config)
      ? ch[0].request_config.auth.config.password : null
  ')"
  if [ "$SMS_ID" = "sms" ]; then
    _pass "[AUTH-10] GET /sms returns the 'sms' http channel"
  else
    _fail "[AUTH-10] GET /sms does NOT return the channel (body: $sms_get)"
  fi
  if [ -n "$SMS_PW" ] && [ "$SMS_PW" != "p4ss" ]; then
    _pass "[AUTH-10] channel auth password is MASKED on GET (not 'p4ss')"
  else
    _fail "[AUTH-10] channel auth password LEAKED/absent on GET (got '$SMS_PW')"
  fi
fi

# --- AUTH-11 / HOOK-04: web_hook on login/after (array) ---------------------
echo
echo "--- [AUTH-11/HOOK-04] webhooks: add a login/after web_hook (whole-array) ---"
HOOK_BODY_SRC='function(ctx) { messages: ctx.identity }'
HOOK_BODY="$(BODY="$HOOK_BODY_SRC" node -e '
  const b = process.env.BODY;
  const body = {
    "/selfservice/flows/login/after/hooks": [{
      hook: "web_hook",
      config: {
        url: "https://hook.example.com/login",
        method: "POST",
        body: b,
        response: { ignore: true, parse: false }
      }
    }]
  };
  process.stdout.write(JSON.stringify(body));
')"
if put_section_healthy "[AUTH-11/HOOK-04]" "webhooks" "$HOOK_BODY"; then
  wh_get="$(_body_of "$(_auth_get "${CFG_URL}/webhooks")")"
  WH_URL="$(_json_field "$wh_get" '
    var h = data["/selfservice/flows/login/after/hooks"];
    (h && h[0] && h[0].config) ? h[0].config.url : null
  ')"
  WH_BODY_SRC="$(_json_field "$wh_get" '
    var h = data["/selfservice/flows/login/after/hooks"];
    (h && h[0] && h[0].config) ? h[0].config.body : null
  ')"
  if [ "$WH_URL" = "https://hook.example.com/login" ]; then
    _pass "[AUTH-11/HOOK-04] GET /webhooks reflects the login/after web_hook"
  else
    _fail "[AUTH-11/HOOK-04] GET /webhooks does NOT reflect the hook (body: $wh_get)"
  fi
  if printf '%s' "$WH_BODY_SRC" | grep -q 'ctx.identity' \
     && ! printf '%s' "$WH_BODY_SRC" | grep -q 'base64://'; then
    _pass "[AUTH-11/HOOK-04] web_hook config.body decoded to Jsonnet source on GET (not raw base64://)"
  else
    _fail "[AUTH-11/HOOK-04] web_hook config.body NOT decoded to source (got '$WH_BODY_SRC')"
  fi
fi

# --- AUTH-09: SMTP connection_uri via the DEDICATED write-only path ---------
echo
echo "--- [AUTH-09] smtp-connection: set the URI via the dedicated write-only path ---"
snapshot_started_at "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
smtp_resp="$(_auth_mut PUT "$SMTP_URL" '{"connection_uri":"smtps://user:pass@smtp.example.com:465"}')"
smtp_code="$(_code_of "$smtp_resp")"; smtp_rbody="$(_body_of "$smtp_resp")"
if [ "$smtp_code" = "200" ] && printf '%s' "$smtp_rbody" | grep -q '"status":"healthy"'; then
  _pass "[AUTH-09] PUT /smtp-connection -> 200 {status:healthy} (written + Kratos healthy)"
  assert_only_container_restarted "$KRATOS_CTR" "$HYDRA_CTR" "$KETO_CTR" "$OATHKEEPER_CTR"
  wait_container_healthy "$KRATOS_CTR" 90
  # GET returns {set:true} ONLY — never the URI (no ://, @, or 'pass' substring).
  smtp_get="$(_body_of "$(_auth_get "$SMTP_URL")")"
  if printf '%s' "$smtp_get" | grep -q '"set":true'; then
    _pass "[AUTH-09] GET /smtp-connection -> {set:true}"
  else
    _fail "[AUTH-09] GET /smtp-connection did NOT report set:true (body: $smtp_get)"
  fi
  if printf '%s' "$smtp_get" | grep -qE '://|@|pass'; then
    _fail "[AUTH-09] GET /smtp-connection LEAKS a URI substring (://, @, or pass): $smtp_get"
  else
    _pass "[AUTH-09] GET /smtp-connection carries NO URI substring (URI never echoed, T-07-05)"
  fi
else
  _fail "[AUTH-09] PUT /smtp-connection -> '$smtp_code' (want 200 healthy; body: $smtp_rbody)"
fi

# --- AUTH-09: SMTP untouched-secret PRESERVE (no-op echo / blank) -----------
echo
echo "--- [AUTH-09] smtp-connection PRESERVE: a no-op PUT does NOT change the stored URI ---"
# Echo back EXACTLY what GET returns is not possible (GET returns {set:bool}, never
# the value), so the no-op signal is the backend-emitted masked sentinel OR blank.
# A masked/blank PUT must be an idempotent no-op preserve (still set:true).
noop_resp="$(_auth_mut PUT "$SMTP_URL" "{\"connection_uri\":\"${MASKED_SENTINEL}\"}")"
noop_code="$(_code_of "$noop_resp")"
blank_resp="$(_auth_mut PUT "$SMTP_URL" '{"connection_uri":""}')"
blank_code="$(_code_of "$blank_resp")"
smtp_get2="$(_body_of "$(_auth_get "$SMTP_URL")")"
if { [ "$noop_code" = "200" ] || [ "$blank_code" = "200" ]; } \
   && printf '%s' "$smtp_get2" | grep -q '"set":true'; then
  _pass "[AUTH-09] masked/blank no-op PUT preserved the stored URI (still set:true — no clobber)"
else
  _fail "[AUTH-09] no-op PUT did NOT preserve the URI (noop=$noop_code blank=$blank_code get=$smtp_get2)"
fi
# File backstop: the stored connection_uri must NOT have been clobbered to the
# sentinel/blank — the real smtps:// value is still on disk.
if grep -Eq 'connection_uri:.*smtps://' "$KRATOS_YAML"; then
  _pass "[AUTH-09] kratos.yml still holds the real smtps:// connection_uri (preserved on disk)"
else
  _fail "[AUTH-09] kratos.yml connection_uri was clobbered by the no-op PUT (real URI gone)"
fi

# --- AUTH-07: Recovery enabled + use (after courier/SMTP exists) ------------
# Runs here (not in section order) because enabling recovery makes `courier` a
# REQUIRED top-level property (schema allOf[0]); the SMTP write above created it.
echo
echo "--- [AUTH-07] recovery: enabled+use=code (+code method) -> write/restart/GET ---"
if put_section_healthy "[AUTH-07]" "recovery" \
   '{"/selfservice/flows/recovery/enabled":true,"/selfservice/flows/recovery/use":"code","/selfservice/methods/code/enabled":true}'; then
  r_get="$(_body_of "$(_auth_get "${CFG_URL}/recovery")")"
  if [ "$(_json_field "$r_get" 'data["/selfservice/flows/recovery/enabled"]')" = "true" ] \
     && [ "$(_json_field "$r_get" 'data["/selfservice/flows/recovery/use"]')" = "code" ]; then
    _pass "[AUTH-07] GET /recovery reflects enabled=true + use=code"
  else
    _fail "[AUTH-07] GET /recovery does NOT reflect the recovery flow config (body: $r_get)"
  fi
fi

echo
echo "============================================================"
echo " GROUP 3 — CLI-compat: kratos.yml stays a config Kratos boots"
echo "============================================================"
# After all the writes above, Kratos is still healthy => the merged kratos.yml is
# a valid Ory config the engine booted on (CLI-interop / valid-config proof).
echo
echo "--- [CLI-compat] kratos.yml is a valid Ory config Kratos boots on ---"
assert_healthy "$KRATOS_CTR"
assert_grep 'highest_available' "$KRATOS_YAML"

echo
echo "============================================================"
echo " GROUP 2 — negative assertions (422 no-write, 403 sensitive)"
echo "============================================================"

# --- Invalid value -> 422 with NO disk write (anti-false-green) -------------
# A bad AAL enum (Pitfall 1: 'highest_aal' is NOT a valid value) must 422, and
# the file must be byte-identical afterwards (a reject never touches disk).
echo
echo "--- [neg] invalid AAL enum 'highest_aal' -> 422, no disk write ---"
snapshot_file "$KRATOS_YAML"
inv_aal="$(_auth_mut PUT "${CFG_URL}/mfa" '{"/selfservice/flows/login/required_aal":"highest_aal"}')"
inv_aal_code="$(_code_of "$inv_aal")"; inv_aal_body="$(_body_of "$inv_aal")"
if [ "$inv_aal_code" = "422" ]; then
  _pass "[neg] required_aal:'highest_aal' -> 422 (schema rejects the wrong enum, Pitfall 1)"
else
  _fail "[neg] required_aal:'highest_aal' -> '$inv_aal_code' (want 422; body: $inv_aal_body)"
fi
assert_file_unchanged "$KRATOS_YAML"

echo
echo "--- [neg] invalid session.lifespan '24x' -> 422, no disk write ---"
snapshot_file "$KRATOS_YAML"
inv_dur="$(_auth_mut PUT "${CFG_URL}/sessions" '{"/session/lifespan":"24x"}')"
inv_dur_code="$(_code_of "$inv_dur")"; inv_dur_body="$(_body_of "$inv_dur")"
if [ "$inv_dur_code" = "422" ]; then
  _pass "[neg] session.lifespan:'24x' -> 422 (bad duration rejected)"
else
  _fail "[neg] session.lifespan:'24x' -> '$inv_dur_code' (want 422; body: $inv_dur_body)"
fi
assert_file_unchanged "$KRATOS_YAML"

# --- Sensitive key -> 403 (denylist wins), no disk write --------------------
# Each sensitive PUT must be refused 403 BEFORE any disk write; the rejected
# value is never echoed. We also assert the file is unchanged.
echo
echo "--- [neg] sensitive keys -> 403 (denylist), no disk write ---"
# Negative helper: a PUT to <section> with <body> must 403 AND not touch disk.
put_forbidden_no_write() {
  local label="$1" section="$2" body="$3" resp code rbody
  snapshot_file "$KRATOS_YAML"
  resp="$(_auth_mut PUT "${CFG_URL}/${section}" "$body")"
  code="$(_code_of "$resp")"; rbody="$(_body_of "$resp")"
  if [ "$code" = "403" ]; then
    _pass "${label}: -> 403 (forbidden_key, denied)"
  else
    _fail "${label}: -> '$code' (want 403; body: $rbody)"
  fi
  assert_file_unchanged "$KRATOS_YAML"
}
put_forbidden_no_write "[neg] /dsn via sessions"        "sessions" '{"/dsn":"postgres://evil@db/x"}'
put_forbidden_no_write "[neg] connection_uri via smtp"  "smtp"     '{"/courier/smtp/connection_uri":"smtps://x@y:465"}'
put_forbidden_no_write "[neg] /secrets/cookie/0 via sessions" "sessions" '{"/secrets/cookie/0":"clobber"}'
put_forbidden_no_write "[neg] /serve/admin/base_url via sessions" "sessions" '{"/serve/admin/base_url":"http://evil/"}'

# --- Out-of-scope per-index OIDC pointer -> 403 (array-root-only, Pitfall 4) -
echo
echo "--- [neg] per-index OIDC pointer -> 403 (array-root-only, Pitfall 4) ---"
put_forbidden_no_write "[neg] /selfservice/methods/oidc/config/providers/0/client_id (per-index)" \
  "oidc" '{"/selfservice/methods/oidc/config/providers/0/client_id":"x"}'

# --- Auth / CSRF gates (mirror phase6) --------------------------------------
echo
echo "--- [neg] auth/CSRF gates: unauthenticated -> 401; authed-no-CSRF -> 403 ---"
# Unauthenticated PUT (no cookie, no CSRF) -> 401.
unauth_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H 'Content-Type: application/json' \
  --data '{"/session/lifespan":"24h"}' "${CFG_URL}/sessions" 2>/dev/null)"
if [ "$unauth_code" = "401" ]; then
  _pass "[neg] unauthenticated PUT -> 401 (auth_guard)"
else
  _fail "[neg] unauthenticated PUT -> '$unauth_code' (want 401)"
fi
# Authenticated PUT WITHOUT the X-CSRF-Token header -> 403 (csrf_guard).
nocsrf_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H "$COOKIE_HEADER" -H 'Content-Type: application/json' \
  --data '{"/session/lifespan":"24h"}' "${CFG_URL}/sessions" 2>/dev/null)"
if [ "$nocsrf_code" = "403" ]; then
  _pass "[neg] authed PUT without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] authed PUT without X-CSRF-Token -> '$nocsrf_code' (want 403)"
fi
# The SMTP dedicated path is equally CSRF-protected (state-changing).
smtp_nocsrf_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
  -H "$COOKIE_HEADER" -H 'Content-Type: application/json' \
  --data '{"connection_uri":"smtps://x@y:465"}' "$SMTP_URL" 2>/dev/null)"
if [ "$smtp_nocsrf_code" = "403" ]; then
  _pass "[neg] authed PUT /smtp-connection without X-CSRF-Token -> 403 (csrf_guard)"
else
  _fail "[neg] authed PUT /smtp-connection without X-CSRF-Token -> '$smtp_nocsrf_code' (want 403)"
fi

echo
summary
exit $?
