import { createOryMiddleware } from "@ory/nextjs/middleware"
import oryConfig from "./ory.config"

// =============================================================================
// The @ory/nextjs same-origin proxy (the cookie/CSRF linchpin — AX-01/AX-05).
//
// `createOryMiddleware(oryConfig)` intercepts `/self-service`, `/sessions/whoami`,
// `/ui`, `/.well-known/ory`, and `/.ory` on the AX origin and SERVER-SIDE proxies
// them to `ORY_SDK_URL` (= Kratos PUBLIC :4433). It rewrites every `Set-Cookie`
// Domain attribute to the AX request host (via the `psl` public-suffix list) and
// rewrites Kratos base URLs in redirect Location headers + response bodies to the
// AX origin. The browser therefore ONLY ever talks to the AX origin (same-origin),
// so Kratos's anti-CSRF double-submit cookie + the session cookie are first-party
// and CSRF succeeds.
//
// Do NOT hand-roll a Next `rewrites()` to Kratos public — a bare rewrite does not
// rewrite Set-Cookie domains and reintroduces the CSRF break (15-RESEARCH Pitfall 1).
// =============================================================================

export const middleware = createOryMiddleware(oryConfig)

// Run the middleware on the proxied Ory paths only. Static assets, the Next
// internals, and the rendered flow PAGES (/auth/*, /settings) are excluded so the
// proxy never intercepts a page render — only the Kratos API calls those pages
// make. (`/ui` is included because @ory/nextjs maps legacy `/ui/*` to the config
// ui_url paths during rewrite.)
export const config = {
  matcher: [
    "/self-service/:path*",
    "/sessions/:path*",
    "/ui/:path*",
    "/.well-known/ory/:path*",
    "/.ory/:path*",
  ],
}
