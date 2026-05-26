import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"
import { fileURLToPath } from "node:url"

// Vitest + React Testing Library harness for the AX service (mirrors
// frontend/vitest.config.ts). jsdom so RTL can render the Elements flow
// components against a MOCKED flow object — the LIVE A1 proof is the acceptance
// gate (scripts/verify/phase15-acceptance.sh), this is the unit smoke.
// The `@/...` alias mirrors tsconfig paths so `@/ory.config` resolves in tests.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["**/*.{test,spec}.{ts,tsx}"],
    exclude: ["node_modules/**", ".next/**", "e2e/**"],
    server: {
      deps: {
        // @ory/elements-react ships ESM with EXTENSIONLESS relative imports
        // (e.g. `./session-provider`, resolved by Node via the package's own
        // logic). Vitest's externalized-module path does not apply that
        // resolution, so it must be inlined and run through Vite's transform
        // pipeline (which resolves the `.mjs` extension). Same for @ory/nextjs.
        inline: [/@ory\/elements-react/, /@ory\/nextjs/],
      },
    },
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
    },
  },
})
