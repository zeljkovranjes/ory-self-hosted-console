import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// Vitest + React Testing Library harness (Wave 0). jsdom environment so RTL can
// render the three Phase-5 primitives; the react plugin enables JSX/TSX. The
// `@/...` alias mirrors tsconfig.json paths so component imports resolve in tests.
// Playwright e2e specs live under e2e/ and are excluded here (run via `npm run e2e`).
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["**/*.{test,spec}.{ts,tsx}"],
    exclude: ["node_modules/**", ".next/**", "e2e/**"],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
    },
  },
});
