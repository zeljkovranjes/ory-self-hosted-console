import { defineConfig, devices } from "@playwright/test";

// Playwright e2e harness (Wave 0). Specs live under e2e/. The authoritative
// FE-01 flow (/setup -> /login -> authenticated shell, 401 redirects) runs
// against the live compose stack at the phase gate; baseURL points at the
// frontend container's published port. No webServer is started here — the
// live gate brings the stack up via docker compose (wired in 05-07).
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
