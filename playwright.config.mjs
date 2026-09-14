import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./smartflow-ui/e2e",
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node scripts/serve-ui.mjs",
    url: "http://127.0.0.1:4173",
    // A stale process can make Playwright believe the port is ready and then
    // disappear before the first navigation.  Release verification must own a
    // fresh deterministic server; opt into reuse explicitly for local work.
    reuseExistingServer: process.env.REUSE_E2E_SERVER === "1" && !process.env.CI,
    timeout: 15_000
  }
});
