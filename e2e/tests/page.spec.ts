import { expect, test } from "@playwright/test";

// Salesperson workflow on the deployed page: outreach list, views, filters, segment, account, evidence.
// Scoring v3: priority, ownership and evidence are separate columns; there is no score column.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#rows tr").first()).toBeVisible();
  await expect(page.locator("#snapshot")).toContainText("Snapshot 2026-11-07");
});

test("outreach list loads with separate priority, ownership and evidence and no network providers", async ({ page }) => {
  const rows = page.locator("#rows tr");
  await expect(rows).toHaveCount(50);
  await expect(rows.first().locator("td").first()).toHaveText("1");
  await expect(page.locator("#count")).toContainText("1–50 of");
  await expect(page.locator("#rows")).not.toContainText("net:");
  const headers = await page.locator("thead th").allTextContents();
  expect(headers.map((h) => h.trim())).toEqual(["#", "Account", "Priority", "Ownership", "Evidence", "Top signals"]);
  await expect(rows.first().locator("td").nth(2)).toContainText(/High|Medium|Low/);
  await expect(rows.first().locator("td").nth(2)).toContainText(/above \d+%/);
  await expect(rows.first().locator("td").nth(3)).toContainText(/high|medium/);
  await expect(rows.first()).toContainText("actionable");
});

test("review and excluded views are separate from the outreach list", async ({ page }) => {
  await page.getByLabel("View").selectOption("review");
  await expect(page.locator("#rows tr").first()).toContainText("review:");
  await page.getByLabel("View").selectOption("excluded");
  await expect(page.locator("#rows tr").first()).toContainText("excluded: not a prospect");
  await expect(page.locator("#rows tr").first().locator("td").first()).toHaveText("—");
});

test("search narrows the list", async ({ page }) => {
  await page.getByRole("searchbox").fill("university");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.locator("#rows tr").first()).toContainText(/universi/i);
  const count = await page.locator("#count").textContent();
  expect(Number(count!.split(" of ")[1])).toBeGreaterThan(10);
});

test("signal, tier and country filters apply", async ({ page }) => {
  await page.locator("input[name=signal][value=S01]").check();
  await page.locator("input[name=tier][value=A1]").check();
  await page.locator("input[name=country]").fill("US");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.locator("#rows tr").first().locator("td").nth(3)).toContainText("tier A1");
  await expect(page.locator("#rows tr").first()).toContainText("S01");
});

test("network-provider segment is separate and explicitly selected", async ({ page }) => {
  await page.getByLabel("Segment").selectOption("network_provider");
  await expect(page.locator("#rows tr").first()).toContainText("net:");
  await expect(page.locator("#rows tr").first().locator("td").nth(3)).toContainText("tier P");
});

test("account detail explains the priority and shows fact, risk and hypothesis separately", async ({ page }) => {
  await page.locator("#rows tr").first().click();
  const detail = page.locator("#detail");
  await expect(detail.locator("h2")).toBeVisible();
  await expect(detail).toContainText("not a purchase probability");
  await expect(detail).toContainText("Why this priority");
  await expect(detail.locator("dl.kv").first()).toContainText("Ownership");
  await expect(detail.locator("dl.kv").first()).toContainText("Evidence quality");
  await expect(detail).toContainText("Legacy v2 score (comparison only)");
  await expect(detail.locator("li").filter({ hasText: /^Ownership confidence/ })).toContainText("not verified");
  const card = detail.locator(".card").filter({ hasText: "Observed fact" }).first();
  await expect(card).toContainText("Observed fact");
  await expect(card).toContainText("Inferred risk");
  await expect(card).toContainText("Hypothesis");
  await card.locator("summary").click();
  await expect(card).toContainText("SHA-256");
  await expect(card).toContainText("withheld in this deployment");
});

test("deep link opens an account", async ({ page }) => {
  const id = await page.locator("#rows tr").nth(2).locator(".acct-id").textContent();
  await page.goto(`/#account=${encodeURIComponent(id!)}`);
  await expect(page.locator("#detail")).toContainText(id!);
});

test("pagination moves to the next page", async ({ page }) => {
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.locator("#count")).toContainText("51–100 of");
  // ranks may skip accounts held for review, but never go backwards
  const first = Number(await page.locator("#rows tr").first().locator("td").first().textContent());
  expect(first).toBeGreaterThanOrEqual(51);
});
