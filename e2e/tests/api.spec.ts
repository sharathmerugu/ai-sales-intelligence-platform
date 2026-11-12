import { expect, test } from "@playwright/test";

// Access controls and public-response safety against the deployment.
// Plain fetch: the test runner's request contexts inherit the configured credentials.
test("health is open; everything else needs credentials", async ({ baseURL }) => {
  expect((await fetch(`${baseURL}/health`)).status).toBe(200);
  for (const path of ["/", "/accounts", "/signals", "/docs", "/openapi.json"]) {
    const r = await fetch(`${baseURL}${path}`);
    expect(r.status, path).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("Basic");
  }
  const wrong = await fetch(`${baseURL}/accounts`, { headers: { Authorization: "Basic " + btoa("x:y") } });
  expect(wrong.status).toBe(401);
});

test("responses are not cached or indexed", async ({ request }) => {
  const r = await request.get("/accounts?limit=1");
  expect(r.status()).toBe(200);
  expect(r.headers()["cache-control"]).toBe("no-store");
  expect(r.headers()["x-robots-tag"]).toBe("noindex, nofollow");
});

test("evidence never exposes raw file coordinates or NTLM fields", async ({ request }) => {
  const list = await (await request.get("/accounts?signal=S03&limit=20")).json();
  expect(list.items.length).toBeGreaterThan(0);
  for (const a of list.items.slice(0, 10)) {
    const r = await request.get(`/accounts/${encodeURIComponent(a.account_id)}/evidence?limit=200`);
    const text = await r.text();
    expect(text.toLowerCase()).not.toContain("ntlm");   // no field, value or reason code
    expect(text).not.toContain("evidence_json");
    for (const e of JSON.parse(text).items) {
      expect(e.provenance.file_id).toBeNull();
      expect(e.provenance.byte_offset).toBeNull();
      expect(e.provenance.record_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(e.attribution_reasons).not.toContain("dom_ntlm");
    }
  }
});

test("segment filter is validated", async ({ request }) => {
  expect((await request.get("/accounts?segment=everything")).status()).toBe(422);
  const np = await (await request.get("/accounts?segment=network_provider&limit=5")).json();
  for (const a of np.items) expect(a.segment).toBe("network_provider");
});

// Scoring v3 (docs/ranking-v3.md): priority and ownership are separate fields; no bare score.
test("account items keep priority, ownership and evidence apart and carry the legacy score separately", async ({ request }) => {
  const body = await (await request.get("/accounts?limit=50")).json();
  expect(body.view).toBe("research");
  for (const a of body.items) {
    expect(a.score).toBeUndefined();
    expect(a.components).toBeUndefined();
    expect(["High", "Medium", "Low"]).toContain(a.priority.band);
    expect(a.priority.percentile).toBeLessThanOrEqual(99);
    expect(a.priority.note).toContain("not a purchase probability");
    expect(["high", "medium"]).toContain(a.ownership.confidence);
    expect(a.priority.confidence).toBeUndefined();
    expect(a.actionable).toBe(true);
    expect(a.research_state.code).toBe("research_candidate");
    expect(a.legacy.scoring_version).toBe(2);
  }
  const ranks = body.items.map((a: any) => a.rank);
  expect(ranks).toEqual([...ranks].sort((x: number, y: number) => x - y));
});

test("views and filters are validated; excluded accounts are unranked", async ({ request }) => {
  expect((await request.get("/accounts?view=everything")).status()).toBe(422);
  expect((await request.get("/accounts?band=hot")).status()).toBe(422);
  expect((await request.get("/accounts?min_score=10")).status()).toBe(200); // unknown params are ignored
  const ex = await (await request.get("/accounts?view=excluded&limit=20")).json();
  expect(ex.total).toBeGreaterThan(0);
  for (const a of ex.items) {
    expect(a.rank).toBeNull();
    expect(a.priority.band).toBeNull();
    expect(a.eligibility.status).toBe("excluded");
    expect(a.actionable).toBe(false);
  }
  const rv = await (await request.get("/accounts?view=review&band=High&limit=20")).json();
  for (const a of rv.items) {
    expect(a.actionable).toBe(false);
    expect(a.actionable_blockers.length).toBeGreaterThan(0);
  }
});

// Serving v4: use cases come only from implemented signals; locations are IP geolocation.
test("use cases and locations", async ({ request }) => {
  const uc = await (await request.get("/use-cases")).json();
  expect(uc.items.map((u: any) => u.id)).toEqual(["remote_access", "exposure_management", "data_security",
    "admin_consoles", "certificate_management", "vendor_footprint"]);
  for (const u of uc.items) expect(u.counts.total).toBeGreaterThan(0);
  const lens = await (await request.get("/accounts?use_case=remote_access&limit=20")).json();
  const ranks = lens.items.map((a: any) => a.use_case.rank);
  expect(ranks).toEqual([...ranks].sort((x: number, y: number) => x - y));
  for (const a of lens.items) expect(a.use_case.signal_ids.every((s: string) => ["S01", "S03"].includes(s))).toBe(true);
  expect((await request.get("/accounts?use_case=everything")).status()).toBe(422);
  const loc = await (await request.get("/locations")).json();
  expect(loc.note).toContain("geolocation");
});
