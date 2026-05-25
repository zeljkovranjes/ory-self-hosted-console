import type { NextConfig } from "next";

// Same-origin backend egress (FE-05 / BACK-01 invariant, 05-RESEARCH Pattern 1).
// The browser ONLY ever calls /backend/* on its own origin; the Next server
// rewrites those to the internal Rust backend. BACKEND_INTERNAL_URL is read at
// config-eval time on the SERVER ONLY — it is NEVER NEXT_PUBLIC_ and is never
// inlined into client JS, so no internal/Ory host reaches the bundle (asserted
// by scripts/verify/bundle-egress.sh). The __Host-console_session cookie stays
// first-party on the frontend origin (no CORS, no cross-site cookie issues).
//
// NOTE for the live gate (wired in 05-07): the compose `frontend` service must
// set BACKEND_INTERNAL_URL (defaults to http://backend:8080 — the backend
// container's address on the shared `edge` docker network).
const BACKEND_INTERNAL = process.env.BACKEND_INTERNAL_URL ?? "http://backend:8080";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle (.next/standalone) so the runtime
  // Docker stage stays minimal — it copies only the standalone output and runs
  // `node server.js`, no full node_modules tree (T-02-image-bloat mitigation).
  output: "standalone",
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/backend/:path*", destination: `${BACKEND_INTERNAL}/:path*` },
    ];
  },
};

export default nextConfig;
