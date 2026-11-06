import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

const shots = resolve(import.meta.dirname, "../../../docs/evidence");
mkdirSync(shots, { recursive: true });
const shot = (page: Page, name: string) => page.screenshot({ path: `${shots}/${name}.png`, fullPage: false });

async function ready(page: Page) {
  await page.goto("/");
  await expect(page.getByTestId("visual-state")).toHaveText("IDLE", { timeout: 15_000 });
}

async function submit(page: Page, executable: string, args: string) {
  await page.getByRole("button", { name: /^CODEX/ }).click();
  await page.getByLabel("Executable").selectOption(executable);
  await page.getByLabel("Arguments").fill(args);
  await page.getByRole("button", { name: "Submit" }).click();
}

test.describe.configure({ mode: "serial" });

test("three sections navigate and show honest status", async ({ page }) => {
  await ready(page);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("button")).toHaveCount(3);
  await shot(page, "01-brain-idle");

  await nav.getByRole("button", { name: /^CLAUDE/ }).click();
  await expect(page.getByText("Not configured", { exact: true })).toBeVisible();
  await expect(page.getByText("No Claude Code jobs")).toBeVisible();
  await shot(page, "02-claude");

  await nav.getByRole("button", { name: /^CODEX/ }).click();
  await expect(page.getByRole("form", { name: "Controlled execution" })).toBeVisible();
  await shot(page, "03-codex");
});

test("drawers open and close", async ({ page }) => {
  await ready(page);
  for (const [chip, title] of [["Health", "System health"], ["Audit", "Audit log"], [/^Approvals/, "Approvals"]] as const) {
    await page.getByRole("button", { name: chip }).first().click();
    const dialog = page.getByRole("dialog", { name: title });
    await expect(dialog).toBeVisible();
    if (title === "System health") {
      await expect(dialog.getByText("database", { exact: true })).toBeVisible();
      await shot(page, "04-health");
    }
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
  }
});

test("L0 command runs for real and output is shown", async ({ page }) => {
  await ready(page);
  await submit(page, "git", "status --porcelain");
  await expect(page.getByText(/Accepted as L0/)).toBeVisible();
  const task = page.getByTestId("task").first();
  await expect(task).toHaveAttribute("data-status", "completed", { timeout: 15_000 });
  await task.getByRole("button").first().click();
  await expect(task.locator("pre.out")).toContainText("README.md");
  await shot(page, "05-exec-completed");
});

test("disallowed command is denied by the backend", async ({ page }) => {
  await ready(page);
  await submit(page, "git", "commit -m sneaky");
  await expect(page.getByRole("alert")).toContainText("not_allowlisted");
});

test("L2 action requires approval, then runs with the exact approved params", async ({ page }) => {
  await ready(page);
  await submit(page, "git-push", "origin main");
  await expect(page.getByText(/needs your approval/)).toBeVisible();
  const dialog = page.getByRole("dialog", { name: "Approvals" });
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId("visual-state")).toHaveText("WAITING APPROVAL");
  const card = dialog.getByTestId("approval").first();
  await expect(card).toContainText("git-push");
  await expect(card).toContainText("L2 SENSITIVE");
  await shot(page, "06-approval-pending");
  await card.getByRole("button", { name: "Approve" }).click();
  await expect(dialog.getByRole("status")).toContainText("Approved");
  await dialog.getByRole("button", { name: "Run approved action" }).click();
  await expect(dialog.getByRole("status")).toContainText("Submitted with approval");
  await page.keyboard.press("Escape");
  // The workspace has no remote, so the push genuinely fails. The UI must say so.
  const task = page.getByTestId("task").first();
  await expect(task).toHaveAttribute("data-status", "failed", { timeout: 15_000 });
  await task.getByRole("button").first().click();
  await expect(task.locator("pre.err")).toContainText(/origin|repository/i);
  await shot(page, "07-approved-push-failed-honestly");
});

test("emergency stop kills a running job and blocks new work until an L3 reset", async ({ page }) => {
  await ready(page);
  await submit(page, "python", "-m pytest -q test_slow.py");
  await expect(page.getByTestId("visual-state")).toHaveText("EXECUTING", { timeout: 15_000 });
  await shot(page, "08-executing");

  await page.getByRole("button", { name: /emergency stop/i }).click();
  await expect(page.getByText("1 job(s) cancelled · all processes stopped")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("visual-state")).toHaveText("ERROR");
  await expect(page.getByTestId("task").first()).toHaveAttribute("data-status", "cancelled", { timeout: 15_000 });
  await shot(page, "09-emergency-stop");

  await submit(page, "git", "status");
  await expect(page.getByRole("alert")).toContainText("emergency_stop_active");

  await page.getByRole("button", { name: "Health" }).click();
  await page.getByRole("button", { name: /Request emergency-stop reset/ }).click();
  const approvals = page.getByRole("dialog", { name: "Approvals" });
  const card = approvals.getByTestId("approval").first();
  await expect(card).toContainText("L3 CRITICAL");
  await card.getByRole("button", { name: "Approve" }).click();
  await approvals.getByRole("button", { name: "Run approved action" }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("visual-state")).toHaveText(/IDLE|COMPLETED/, { timeout: 10_000 });
});

test("iPhone viewport keeps three sections and the stop control reachable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await ready(page);
  await expect(page.getByRole("navigation", { name: "Primary" }).getByRole("button")).toHaveCount(3);
  await expect(page.getByRole("button", { name: /emergency stop/i })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
  await shot(page, "10-iphone");
});

test("backend loss is shown as OFFLINE, never as working", async ({ page }) => {
  await ready(page);
  // Simulate losing the backend by blocking the event socket and forcing a reconnect.
  await page.routeWebSocket(/\/api\/v1\/ws/, (ws) => ws.close({ code: 1011 }));
  await page.reload();
  await expect(page.getByTestId("visual-state")).toHaveText("OFFLINE", { timeout: 10_000 });
  await shot(page, "11-offline");
});
