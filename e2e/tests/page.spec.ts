import { expect, test } from "@playwright/test";

// Salesperson workflow (serving v4, docs/sales-brief.md): prospecting lens, research states,
// plain-language list, five-question brief, endpoint records on demand, technical detail collapsed.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#rows tr").first()).toBeVisible();
  await expect(page.locator("#snapshot")).toContainText("2026-11-07");
});

test("research list loads in plain language with no internal codes or network providers", async ({ page }) => {
  const rows = page.locator("#rows tr");
  await expect(rows).toHaveCount(50);
  await expect(rows.first().locator("td").first()).toHaveText("1");
  await expect(page.locator("#count")).toContainText("1–50 of");
  const headers = await page.locator("thead th").allTextContents();
  expect(headers.map((h) => h.trim())).toEqual(["#", "Account", "Main finding", "Ownership", "Status"]);
  await expect(page.getByLabel("Prospecting lens")).toHaveValue("");
  await expect(page.getByLabel("Prospecting lens").locator("option").first()).toContainText("All supported use cases");
  await expect(page.locator("#lens-help")).toHaveText("Choose a use case to narrow the research list.");
  await expect(rows.first()).toContainText("Pursue");
  const listText = await page.locator("#rows").innerText();
  expect(listText).not.toMatch(/\bS\d\d\b/);
  expect(listText).not.toContain("net:");
  expect(listText).not.toMatch(/actionable/i);
  await expect(page.locator("input[name=country]")).toHaveValue("");
  await expect(page.getByLabel("Observed infrastructure location")).toBeVisible();
});

test("a use case narrows and re-ranks the list", async ({ page }) => {
  await page.getByLabel("Prospecting lens").selectOption("data_security");
  await expect(page.locator("#lens-help")).toContainText("Database");
  await expect(page.locator("#rows tr").first().locator("td").nth(2)).toContainText("Exposed data stores");
  await expect(page.locator("#list-note")).toContainText("ranked on exposed data stores evidence only");
});

test("statuses are separate lists", async ({ page }) => {
  await page.getByLabel("Status").selectOption("hygiene");
  await expect(page.locator("#rows tr").first()).toContainText("Pursue for certificate management");
  await page.getByLabel("Status").selectOption("verify");
  await expect(page.locator("#rows tr").first()).toContainText("Confirm ownership first");
  await page.getByLabel("Status").selectOption("context");
  await expect(page.locator("#rows tr").first()).toContainText("Monitor");
  await page.getByLabel("Status").selectOption("excluded");
  await expect(page.locator("#rows tr").first()).toContainText("Do not pursue");
  await expect(page.locator("#rows tr").first().locator("td").first()).toHaveText("—");
});

test("search narrows the list", async ({ page }) => {
  await page.getByRole("searchbox").fill("university");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.locator("#rows tr").first()).toContainText(/universi/i);
  const count = await page.locator("#count").textContent();
  expect(Number(count!.split(" of ")[1])).toBeGreaterThan(10);
});

test("account report leads with findings, threats, reasons, pitch and plan; evidence below", async ({ page }) => {
  await page.locator("#rows tr").first().click();
  const detail = page.locator("#detail");
  await expect(detail.locator("h2")).toBeVisible();
  await expect(detail.locator(".status-bar")).toContainText("Pursue");
  await expect(detail.locator("#priority-line")).toContainText(/Top \d+% of [\d,]+ organisations by exposure/);
  const headings = (await detail.locator("h3").allTextContents()).map((h) => h.trim().toLowerCase());
  expect(headings.slice(0, 6)).toEqual(["summary", "key threats", "why target them", "recommended pitch",
                                        "action plan", "confirm on the call"]);
  expect(headings).toContain("supporting evidence");
  await expect(detail.locator("blockquote")).toBeVisible();
  const report = await detail.innerText();
  expect(report).not.toMatch(/\b(may|might|not observed|not a weakness)\b/i);
  // technical detail is collapsed, not in the report
  await expect(detail.getByText(/100 × relevance/)).toBeHidden();
  // endpoint records on demand, with provenance
  const bucket = detail.locator("details.finding").first();
  await bucket.locator("summary").click();
  await bucket.getByRole("button", { name: /Show endpoint records/ }).click();
  const record = bucket.locator(".records .card").first();
  await expect(record).toContainText("Observed");
  await record.locator("summary").click();
  await expect(record).toContainText("SHA-256");
  await expect(record).toContainText("withheld in this deployment");
});

test("deep link opens an account", async ({ page }) => {
  const id = await page.locator("#rows tr").nth(2).getAttribute("data-id");
  await page.goto(`/#account=${encodeURIComponent(id!)}`);
  await page.locator("#detail details.technical > summary").click();
  await expect(page.locator("#detail")).toContainText(id!);
});

test("pagination moves to the next page", async ({ page }) => {
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.locator("#count")).toContainText("51–100 of");
  // ranks may skip accounts in other research states, but never go backwards
  const first = Number(await page.locator("#rows tr").first().locator("td").first().textContent());
  expect(first).toBeGreaterThanOrEqual(51);
});

// Signal brief (docs/agentic-briefs.md): decision, finding / relevance / action cards, evidence drawer and
// follow-ups. Works with or without a model: without one the page shows the factual brief in the same shape.
test("an account opens with a decision, signal cards and cited evidence", async ({ page }) => {
  await page.getByLabel("Prospecting lens").selectOption("remote_access");
  await page.locator("#rows tr").first().click();
  const brief = page.locator("#ai-brief");
  await expect(brief.locator(".decision")).toBeVisible();
  const card = brief.locator(".sig-card").first();
  await expect(card).toContainText("Found");
  await expect(card).toContainText("Why it matters");
  await expect(card).toContainText("Next");
  await expect(card.locator(".sig-meta")).toContainText("Ownership:");
  await expect(card.locator(".sig-meta")).toContainText("Observed");
  expect(await brief.innerText()).not.toMatch(/\bS\d\d\b/);
  await card.getByRole("button", { name: /Evidence/ }).click();
  await expect(page.locator("#drawer")).toBeVisible();
  await expect(page.locator("#drawer-body .card").first()).toContainText("Observed");
  await page.locator("#drawer-close").click();
  await expect(page.locator("#drawer")).toBeHidden();
  await expect(brief.locator(".followups")).toBeVisible();
});

test("the certificate lens leads with certificate findings", async ({ page }) => {
  await page.getByLabel("Prospecting lens").selectOption("certificate_management");
  await page.locator("#rows tr").first().click();
  await expect(page.locator("#ai-brief .sig-card").first()).toContainText(/certificate|TLS/i);
});
