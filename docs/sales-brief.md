# Salesperson workflow: research states, use-case lenses and the account brief (serving v4)

Implements P0 of `sales-intelligence-product-spec.md` (2026-11-12). That spec file ends at §6
step 1; its later sections (component specs, acceptance criteria) were not in the repository, so
this work follows its §4 diagnosis and §5 P0 list. Nothing in the accounts layer changed: the
`accounts`, `account_signals` and `account_evidence` tables of the rebuilt serving DB are
row-for-row identical to the serving-v3 build (`EXCEPT` both ways: 0 rows). Everything below is
derived from them at serving-DB build time or in the API.

## 1. Audit before presentation (snapshot 2026-11-07, attribution v5, scoring v3)

| Check | Result |
|---|---|
| A service attributed to more than one account | 0 |
| Account `n_services` / `n_ips` ≠ distinct services / IPs in its evidence | 0 |
| Duplicate evidence rows per (account, signal, service) | 0 |
| A large university: "101 services" vs "942 attributed services" | Two populations: 101 services with a finding; 942 services the attribution links to the org, with or without a finding (used for ownership). Now named and defined in the brief. |
| SQL Server Browser (UDP 1434) | 115 evidence rows on 85 accounts; for 53 accounts it is their only counted data-store finding. Was worded "data-store response" under "Database / object store reachable". |
| Band of the first 50 research candidates (default list) | 50 / 50 High: the default sort is by rank, so the top of the list is the top 1% by construction. |
| Education names (`univ|college|school|institut|academ|education|research`) | 1.25% of eligible enterprise accounts, 172 of the 869 High research candidates, 32 of the top 50. |
| Ties | 8 accounts tie at the maximum priority (99.433); the v3 tie-break is exposure, then **more counted IPs**, so ties go to the biggest network. |
| What passes the "actionable" gate | 58,451 of 60,722 enterprise accounts (96%) pass on certificate / TLS findings alone (S06 matches on a TLS basis, above the gate's quality bar); 2,271 have a counted exposure. "Actionable outreach" was mostly self-signed or expired certificates. |

Counting is sound; the problems were wording, unnamed populations, and size. Size bias comes from
the score's design: relevance is a noisy-OR over distinct signals and breadth grows with IPs up to
16, so large networks (universities with /16 allocations) collect every signal type. Median IPs in
the overall top 50 is 41.5.

## 2. Wording v3 (signal registry `WORDING_VERSION = 3`; detection unchanged, `Signal.version` stays 1)

v2 removed unsupported hypotheses but read as hedged ("the scan shows a gateway answered, not a
weakness in it"). Salesperson feedback (2026-11-12): the report must be direct and confident. v3:

- Threats are stated firmly at the **device-class** level, where they are true: internet-facing VPN
  gateways are the most exploited entry point; exposed RDP/VNC is a top ransomware access route;
  open data stores are a leading breach cause; exposed admin consoles control everything else;
  certificate defects fail audits and enable interception.
- The report never claims the **account** is vulnerable, breached, buying or running something old:
  one external scan cannot show that, and a wrong claim loses the call. Facts the scan does not
  capture (firmware, MFA, who runs the device) are a "Confirm on the call" checklist, not caveats.
- Each signal carries `short_name`, `noun_one` / `noun_many`, `offering` (what to lead with),
  `pitch`, `opener` (first line to the prospect, filled with the products seen),
  `discovery_questions`, `confirm_on_call` and `detail_notes`. SQL Server Browser keeps its exact
  scope, stated directly: the UDP 1434 discovery service lists instance names and ports.
- `hypothesis` stays in the registry and API (with "may") for reviewers; the report does not show it.
- Tests (`tests/test_signals.py`, `tests/test_brief.py`, `e2e/tests/page.spec.ts`) fail on hedges
  (may, might, not observed, not a weakness, depends on, …) and on account claims (is vulnerable,
  breached, compromised, legacy, intends to, …) in sales text, and on signal codes.

## 3. Use-case lenses (`firmable.accounts.use_cases`, `USE_CASES_VERSION = 1`)

Only categories backed by implemented signals; no ICP, industry or size data is invented.

| Lens | Signals | Enterprise research candidates |
|---|---|---|
| Remote access security | S01, S03 | 1,628 |
| Exposure management | S01, S03, S04, S05 | 2,268 |
| Database and data-store security | S04 | 87 |
| Admin and DevOps console exposure | S05 | 719 |
| Certificate and TLS management | S06 | 59,489 (TLS findings count as the reason here) |
| Security vendor footprint (context only) | S16 | 1,143 (+10,149 certificate findings only) |

- An account is in a lens only with counted evidence from a lens signal; security lenses also need
  one lens row on a product, protocol, TLS or title match (the research-candidate bar).
- A row suppressed by a signal *outside* the lens counts inside it (an S04 database on an S01
  gateway counts for data security); a row suppressed by a lens signal stays uncounted, so a service
  counts once per lens.
- Lens priority = scoring-v3 `opportunity_priority` over lens signals and lens IPs only. Ranked per
  lens and segment over eligible accounts. Ties: priority, **evidence quality**, IPs, id — quality
  before size.
- Effect on size bias (education names in each lens's top 50 research candidates): remote access
  22, exposure management 29, data security 15, admin consoles 23, certificates 9, vendor
  footprint 17, against 32 overall. Lenses reduce but do not remove it.
- Table `account_use_cases` (205,796 rows). Aggregated in DuckDB (`lens_rows_sql`); the Python
  `lens_rows` is the reference implementation and a test checks they agree on 3,000 random rows.
  Serving build 8.8 s, peak RSS 1.08 GB (`/usr/bin/time -l`).

## 4. Research states (replace "actionable outreach")

The scoring-v3 gate (`scoring.actionability`) is unchanged; the states split it by what passed it:

| State | Rule | Enterprise accounts |
|---|---|---|
| Pursue (`research_candidate`) | passes the gate **and** has a counted exposure (gateway, remote administration, data store, console). In the certificate lens, passing the gate is enough. | 2,271 |
| Pursue for certificate management (`hygiene_only`) | passes the gate on certificate / TLS findings alone | 58,451 |
| Confirm ownership first (`verify_ownership`) | eligible, ownership low or an open review flag | 34,241 |
| Monitor (`context_only`) | eligible and owned, but only technographic or tag-level evidence | 84,487 |
| Do not pursue (`not_a_prospect`) | excluded (placeholder, pool label, provider sub-allocation) | 281 |

API `view`: `research` (default), `hygiene`, `verify`, `context`, `excluded`, `all`; `actionable`
(the whole gate) and `review` remain as aliases. Every item carries `research_state` {code, label,
summary}; the state depends on the lens (`use_case`). "Verify ownership first" says the link is
unconfirmed only when ownership is low; with review flags alone it says the flags need checking.

## 5. Account report (`firmable.api.brief`, `GET /accounts/{id}` → `brief`)

Order on the page:

1. Status (Pursue / Pursue for certificate management / Confirm ownership first / Monitor / Do not
   pursue) and rank ("Top 1% of 179,450 organisations by exposure").
2. **Summary**: one paragraph of what the organisation exposes, with counts and products, and what to
   lead with.
3. **Key threats**: one entry per security finding (count, products, threat).
4. **Why target them**: rank, lens rank, breadth, ownership evidence, security vendors in place.
5. **Recommended pitch**: lead offering, who to reach, opening line, talking points, discovery
   questions.
6. **Action plan**: numbered steps for the status.
7. **Confirm on the call**: what the scan does not capture.
8. **Competitive context**: vendors already in front of the services.
9. **Supporting evidence**: one collapsible bucket per finding (products, notes, counting, endpoint
   records with provenance), ownership evidence with count definitions, rank by solution area,
   ranking and scoring details, data source.

Codes, tiers, the formula and the legacy score are only in "Ranking and scoring details".

New endpoints: `GET /use-cases` (lenses with counts by status), `GET /locations` (IP-geolocation
countries, labelled "Observed infrastructure location"; no default country).

## 6. Verification

- `uv run pytest -m "not slow"`: all pass, including `tests/test_use_cases.py`,
  `tests/test_brief.py` and the new API tests.
- Serving DB rebuilt (`firmable build-phase3 2026-11-07 --steps serving`, 13 s) and public DB
  republished (157.3 MB). Previous serving-v3 DBs kept as `2026-11-07.serving-v3.duckdb` and
  `2026-11-07.public.serving-v3.duckdb`.
- Playwright against a local server over the public DB with Basic auth: 21 / 21 (desktop and
  Pixel 7). Checked by hand in Chrome at 1400 px and 400 px wide: no console errors.
- Independent review (static, one reviewer agent): 0 blocking, 6 risks, 1 question. Fixed:
  research candidates were 96% certificate-only (new state above); "verify ownership" wording with
  review flags only; lens chips on excluded accounts; breadth sentence counted vendor-only IPs;
  stale responses could overwrite the list or brief (request counters); lens build loaded all
  evidence rows into Python (now DuckDB). Kept: lens evidence quality averages every lens service,
  including tag-level ones, like the overall evidence quality. Also fixed after review: vendor
  fingerprints led certificate findings as "main finding"; TLS flags repeated the detail text.
- **Not deployed.** Production still runs serving v3; the app refuses a mismatched serving DB, so
  image and public DB must be deployed together (`docs/deployment.md`).

## 7. Open issues

- Size bias remains in the overall ranking; a size-normalised breadth (e.g. exposed IPs per
  attributed service) is a candidate scoring change but needs labels to justify (P1).
- SQL Server Browser still counts as a data-store exposure at relevance 0.65 in the score; only its
  wording changed. Down-weighting it is a scoring change (P1).
- The spec's 30 s / 60 s usability targets are untested; no salesperson has used this build.
- `docs/signal-catalog.md` keeps the research-phase hypotheses as historical record; the registry
  is the source of sales wording.
- P1 (shortlist, export) not started.
