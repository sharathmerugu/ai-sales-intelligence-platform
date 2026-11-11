import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.FIRMABLE_URL;
if (!baseURL) throw new Error("set FIRMABLE_URL (e.g. https://firmable-api-production.up.railway.app)");

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  retries: 0,
  workers: 2,
  reporter: [["list"]],
  use: {
    baseURL,
    httpCredentials: { username: process.env.FIRMABLE_USER ?? "", password: process.env.FIRMABLE_PASSWORD ?? "" },
    trace: "retain-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] }, testMatch: /page\.spec\.ts/ },
  ],
});
