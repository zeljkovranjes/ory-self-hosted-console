import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle (.next/standalone) so the runtime
  // Docker stage stays minimal — it copies only the standalone output and runs
  // `node server.js`, no full node_modules tree (T-02-image-bloat mitigation).
  output: "standalone",
  reactStrictMode: true,
};

export default nextConfig;
