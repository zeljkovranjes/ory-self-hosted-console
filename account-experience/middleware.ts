import { createOryMiddleware } from "@ory/nextjs/middleware"
import { NextRequest, NextResponse } from "next/server"
import oryConfig from "./ory.config"

// =============================================================================
// AX edge middleware — TWO concerns merged into the single allowed middleware:
//
//   1. The @ory/nextjs same-origin proxy (the cookie/CSRF linchpin — AX-01/AX-05).
//      `createOryMiddleware(oryConfig)` intercepts the Kratos self-service API
//      paths (/self-service, /sessions/whoami, /ui, /.well-known/ory, /.ory) on
//      the AX origin and SERVER-SIDE proxies them to `ORY_SDK_URL` (Kratos PUBLIC
//      :4433). It rewrites every `Set-Cookie` Domain to the AX host (via `psl`)
//      and rewrites Kratos base URLs in redirect Location headers + bodies to the
//      AX origin, so the browser only ever talks to the AX origin (same-origin)
//      and Kratos's anti-CSRF double-submit + session cookie are first-party.
//      Do NOT hand-roll a Next `rewrites()` to Kratos public (15-RESEARCH Pitfall 1).
//
//   2. CR-01 (stored-XSS defense-in-depth, LAYER 3) — a STRICT, per-request
//      nonce Content-Security-Policy. Next's App Router emits inline bootstrap /
//      hydration scripts; a static `script-src 'unsafe-inline'` (the prior policy
//      in next.config.mjs) would let an injected inline <script> EXECUTE. We now
//      mint a fresh nonce per request, advertise it via the REQUEST
//      `Content-Security-Policy` header (Next reads it and stamps the nonce onto
//      every inline script it emits), and set the SAME strict policy on the
//      RESPONSE — so `script-src` is `'self' 'nonce-…' 'strict-dynamic'` with NO
//      `'unsafe-inline'`. An attacker-injected inline <script> (even one that
//      bypassed the write-guard + the sink defang) carries no valid nonce and is
//      REFUSED by the browser. `style-src` keeps `'unsafe-inline'` — Elements /
//      Tailwind v4 inject styles, and a style cannot execute script, so that is
//      the deliberately-retained compatibility allowance (the breakout risk is the
//      <script>, killed by the nonce + the '<' rejection on write).
// =============================================================================

const oryMiddleware = createOryMiddleware(oryConfig)

/** Paths the @ory/nextjs proxy owns (mirrors the matcher below). */
const ORY_PROXY_PREFIXES = [
  "/self-service",
  "/sessions",
  "/ui",
  "/.well-known/ory",
  "/.ory",
]

function isOryProxyPath(pathname: string): boolean {
  return ORY_PROXY_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  )
}

/** Build the strict per-request CSP. `style-src 'unsafe-inline'` is retained for
 *  Elements/Tailwind; `script-src` is nonce-locked with NO 'unsafe-inline'. */
function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    // CR-01 LAYER 3: nonce-locked scripts, NO 'unsafe-inline'. `strict-dynamic`
    // lets Next's nonce'd bootstrap load its chunk scripts; non-nonce'd inline
    // <script> (an injection) is refused.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    // style-src keeps 'unsafe-inline' (CSS cannot execute script; required by the
    // Elements / Tailwind v4 style layer).
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
  ].join("; ")
}

export function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname

  // Concern 1: delegate the Kratos self-service API proxy paths to @ory/nextjs
  // UNCHANGED (these are JSON/redirect API responses, not the HTML document the
  // nonce CSP protects — the cookie-domain rewrite must not be disturbed).
  if (isOryProxyPath(pathname)) {
    return oryMiddleware(req)
  }

  // Concern 2 (CR-01 LAYER 3): mint a per-request nonce and attach the strict CSP
  // to BOTH the forwarded request (so Next stamps the nonce onto its inline
  // scripts) and the response (the browser-enforced policy).
  //
  // EDGE-SAFE nonce (WR-03 discipline): middleware runs on the EDGE runtime, which
  // has NO Node built-ins (`Buffer` is unavailable). We use ONLY Web-platform APIs
  // — `crypto.getRandomValues` + `btoa` — which exist in the edge runtime, so this
  // never drags a node built-in into the edge middleware bundle.
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
  const csp = buildCsp(nonce)

  const requestHeaders = new Headers(req.headers)
  requestHeaders.set("x-nonce", nonce)
  requestHeaders.set("Content-Security-Policy", csp)

  const res = NextResponse.next({ request: { headers: requestHeaders } })
  res.headers.set("Content-Security-Policy", csp)
  return res
}

// Run on the proxied Ory API paths AND on document/page routes (so the nonce CSP
// is set on every HTML response). Static assets + Next internals + the image
// optimizer + favicon are EXCLUDED so the middleware never rewrites a static
// asset (and the proxy never intercepts a page render — it only acts on its own
// prefixes above).
export const config = {
  matcher: [
    // Everything except _next static/image internals, the public image
    // optimizer, and favicon. This still covers /auth/*, /settings, and the Ory
    // proxy prefixes (which the handler dispatches by path).
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
}
