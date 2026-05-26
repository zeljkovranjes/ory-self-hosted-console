// @ts-check

// =============================================================================
// Account Experience (AX) Next.js config.
//
// `output: "standalone"` emits a self-contained server bundle (.next/standalone)
// so the runtime Docker stage copies only the standalone output + static assets
// and runs `node server.js` (mirrors frontend/next.config.ts; no full
// node_modules tree).
//
// NO `rewrites()` to Kratos — the @ory/nextjs `createOryMiddleware` (middleware.ts)
// IS the Kratos-public proxy. A hand-rolled rewrite would not rewrite Set-Cookie
// domains and would break CSRF (15-RESEARCH Anti-Patterns / Pitfall 1).
//
// CSP (AX-05 / threat T-15-02): the AX surface sets its OWN Content-Security-Policy,
// DISTINCT from the admin console (which sets none). It is applied to every route
// via `headers()`. Key differences from a generic console policy:
//   - `style-src 'self' 'unsafe-inline'` — Elements injects styles; 'unsafe-inline'
//     is required for the Tailwind v4 / CSS-in-JS theme layer to render.
//   - `connect-src 'self'` — the middleware keeps every Kratos call same-origin,
//     so no external connect target is needed.
//   - `font-src 'self'` — the local vendored font only (next/font/local); no CDN.
//   - `frame-ancestors 'none'` + `form-action 'self'` + `base-uri 'self'` — clickjacking
//     / form-hijack / base-tag hardening.
// `script-src` includes 'unsafe-inline' because Next injects an inline bootstrap
// script for the App Router; tighten to a nonce in a later hardening pass if the
// Next runtime supports it without breaking hydration.
// =============================================================================

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
].join("; ")

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: CSP },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
        ],
      },
    ]
  },
}

export default nextConfig
