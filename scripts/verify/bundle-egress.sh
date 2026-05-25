#!/usr/bin/env bash
# scripts/verify/bundle-egress.sh
# -----------------------------------------------------------------------------
# FE-05 / BACK-01 hard invariant: the frontend NEVER talks to Ory directly and
# no internal/Ory hostname, admin port, or Ory SDK string may appear in the
# built client bundle. The browser's ONLY backend reference is the literal
# `/backend` (same-origin Next rewrite, 05-RESEARCH Pattern 1) — the internal
# backend host is read server-side at config-eval time and is never inlined.
#
# This gate (a) builds the frontend, then (b) greps the emitted client output
# (.next/static + the standalone server's .next) for forbidden patterns. ANY hit
# fails the build (exit 1). It follows the Phase-1 lib.sh PASS/FAIL convention
# and the anti-false-green contract: PASS is granted only on the explicit
# ABSENCE of every forbidden pattern over a build that actually produced output.
#
# Usage:  bash scripts/verify/bundle-egress.sh
# Env:    SKIP_BUILD=1   reuse an existing .next (CI may build separately)
#         FRONTEND_DIR   override the frontend directory (default: ./frontend)
# -----------------------------------------------------------------------------
set -u

# Resolve the frontend directory relative to this script's repo location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FRONTEND_DIR="${FRONTEND_DIR:-${REPO_ROOT}/frontend}"

# Forbidden patterns — tuned to avoid false positives in minified output while
# still catching any genuine Ory leak. Bare substrings are too loose: `hydra`
# substring-matches React/TanStack `dehydrated`/`hydrateRoot`, and `4445`
# substring-matches Turbopack module IDs like `34457`. So each forbidden token is
# anchored to a URL/host CONTEXT:
#   * Service hostnames (kratos/hydra/keto/oathkeeper) only when preceded by a
#     URL host delimiter (`/`, `:`, `@`, `"`, `'`, or `//`) — i.e. an actual host
#     position, never as an internal substring of a longer identifier.
#   * The Ory SDK package strings `ory-client` and `@ory/` (no Ory crate/SDK may
#     ship to the browser at all).
#   * The `oryd/` image-namespace string (config/host leak).
#   * Admin ports only as a real URL port `:<port>` with a non-digit trailing
#     boundary (catches `kratos:4434/...`, not `34457`).
# Admin ports: kratos 4434/4445, hydra 4445, keto 4466/4467, oathkeeper 4456/4457.
FORBIDDEN_HOSTNAMES='[/:@"'"'"']/?(kratos|hydra|keto|oathkeeper)([/:."'"'"']|$)'
FORBIDDEN_SDK='ory-client|@ory/|oryd/'
FORBIDDEN_PORTS=':(4434|4445|4466|4456|4467|4457)([^0-9]|$)'
# FE-04 / threat T-05-11: Monaco must load from our OWN origin (public/monaco/vs
# via loader.config paths), NEVER from the @monaco-editor/react default CDN. Any
# jsDelivr / unpkg / cdnjs host in the built bundle is a supply-chain + air-gap
# violation — fail the gate. (Same-origin "/monaco/vs" is a bare path with no
# host, so it never matches these host patterns.)
FORBIDDEN_CDN='cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com'
FORBIDDEN="${FORBIDDEN_HOSTNAMES}|${FORBIDDEN_SDK}|${FORBIDDEN_PORTS}|${FORBIDDEN_CDN}"

# Search roots: the client static chunks and the standalone server's compiled
# .next (the server bundle would also carry a leaked literal). We do NOT grep
# node_modules or source — only built output, which is what ships to browsers.
STATIC_DIR="${FRONTEND_DIR}/.next/static"
STANDALONE_NEXT="${FRONTEND_DIR}/.next/standalone/.next"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# 1) Build (unless explicitly skipped).
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  printf 'bundle-egress: building frontend (next build) ...\n'
  ( cd "${FRONTEND_DIR}" && npm run build ) || fail "next build failed (cannot assert egress on an unbuilt app)"
fi

# 2) The static dir MUST exist after a build — its absence means no output was
#    produced, so we must NOT green on absence (anti-false-green).
[ -d "${STATIC_DIR}" ] || fail "build output ${STATIC_DIR} not found — nothing to assert against"

# 3) Grep the built output. -r recurse, -I skip binary, -E extended regex,
#    -i case-insensitive, -l list files. Missing standalone dir is tolerated
#    (only present when output:"standalone"); the static dir is the hard gate.
SEARCH_ROOTS=("${STATIC_DIR}")
[ -d "${STANDALONE_NEXT}" ] && SEARCH_ROOTS+=("${STANDALONE_NEXT}")

HITS="$(grep -rIEli "${FORBIDDEN}" "${SEARCH_ROOTS[@]}" 2>/dev/null || true)"

if [ -n "${HITS}" ]; then
  printf 'FAIL: Ory hostname/port/SDK reference found in built bundle:\n' >&2
  printf '%s\n' "${HITS}" >&2
  printf 'Pattern: %s\n' "${FORBIDDEN}" >&2
  exit 1
fi

printf 'PASS: no Ory hostname/port/SDK in built bundle (pattern: %s)\n' "${FORBIDDEN}"
printf 'PASS: searched %s\n' "${SEARCH_ROOTS[*]}"
exit 0
