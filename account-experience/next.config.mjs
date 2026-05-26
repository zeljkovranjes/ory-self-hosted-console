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
// CSP (AX-05 / threat T-15-02 + CR-01 LAYER 3): the AX surface sets its OWN
// Content-Security-Policy, DISTINCT from the admin console (which sets none).
//
// The CSP is now built PER-REQUEST in `middleware.ts` (a fresh `script-src` nonce
// each request) rather than as a static header here — a static policy could only
// carry `script-src 'unsafe-inline'`, which would let an injected inline <script>
// EXECUTE (the CR-01 stored-XSS payload). The middleware mints a nonce, advertises
// it on the request header (Next stamps it onto its inline bootstrap scripts), and
// sets the strict policy on the response: `script-src 'self' 'nonce-…'
// 'strict-dynamic'` with NO 'unsafe-inline'. `style-src` keeps 'unsafe-inline'
// (Elements/Tailwind v4 styles; CSS cannot execute script). See middleware.ts.
//
// The remaining non-CSP security headers (clickjacking / sniffing / referrer) are
// static and stay here, applied to every route.
// =============================================================================

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          // Content-Security-Policy is set per-request in middleware.ts (nonce).
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
        ],
      },
    ]
  },
}

export default nextConfig
