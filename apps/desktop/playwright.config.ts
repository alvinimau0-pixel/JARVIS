import { defineConfig } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

// One throwaway token + workspace per run, shared by the backend and the Vite dev server.
const token = process.env.E2E_TOKEN ?? randomBytes(32).toString("base64url");
process.env.E2E_TOKEN = token;
const workspace = process.env.E2E_WORKSPACE ?? mkdtempSync(join(tmpdir(), "jarvis-e2e-"));
if (!process.env.E2E_WORKSPACE) {
  execFileSync("git", ["init", "-q", workspace]);
  writeFileSync(join(workspace, "README.md"), "e2e workspace\n");
  // A deliberately slow test so the emergency stop has a real running process tree to kill.
  writeFileSync(join(workspace, "test_slow.py"), "import time\n\ndef test_slow():\n    time.sleep(60)\n");
}
process.env.E2E_WORKSPACE = workspace;
// Required: a DISPOSABLE database. The e2e run drops and recreates its schema.
const db = process.env.E2E_DATABASE_URL;
if (!db) throw new Error("Set E2E_DATABASE_URL to a disposable PostgreSQL database (it is wiped on each run).");
const backendDir = resolve(import.meta.dirname, "../../backend");
const port = 8799;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:1420",
    trace: "off",
    launchOptions: { executablePath: process.env.E2E_CHROMIUM ?? undefined },
  },
  webServer: [
    {
      command: `uv run alembic downgrade base && uv run alembic upgrade head && uv run jarvis-backend --port ${port}`,
      cwd: backendDir,
      url: `http://127.0.0.1:${port}/api/v1/health/live`,
      reuseExistingServer: false,
      env: {
        JARVIS_DATABASE_URL: db,
        JARVIS_SESSION_TOKEN: token,
        JARVIS_WORKSPACES: workspace,
        // Throwaway audit key and data dir: the e2e database is wiped on every run.
        JARVIS_AUDIT_KEY: randomBytes(32).toString("base64url"),
        JARVIS_DATA_DIR: mkdtempSync(join(tmpdir(), "jarvis-e2e-data-")),
      },
      stdout: "ignore",
      stderr: "pipe",
    },
    {
      command: "pnpm exec vite --port 1420 --strictPort",
      url: "http://127.0.0.1:1420",
      reuseExistingServer: false,
      env: { VITE_JARVIS_API: `http://127.0.0.1:${port}`, VITE_JARVIS_DEV_TOKEN: token },
    },
  ],
});
