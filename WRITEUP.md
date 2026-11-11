# Write-up: cybersecurity sales intelligence from internet-scan data

**Live app:** <https://firmable-api-production.up.railway.app> (HTTP Basic auth; `/health` is
open).

This app helps a B2B security salesperson find companies, rank them, and decide what to say. It
works from one internet-scan snapshot: 137 GB of Shodan-format banners (16,988,823 records from
2026-11-07). Each account shows why it ranks where it does, and every claim links back to the scan
records behind it. Detailed results are in [`docs/SUBMISSION.md`](docs/SUBMISSION.md).

## Approach

1. **Research before code.** I profiled the full file with DuckDB first; every number is
   reproducible from `sql/exploration.sql`. Four findings shaped everything after that:
   - **Most rows are not evidence.** 57% of rows have an empty banner, and two network operators (a CDN and
     a cloud) hold 56% of all rows. A "port open" signal would mostly measure CDN behaviour.
   - **The scanner's labels can't be taken at face value.** A module name says which probe ran,
     not what it found. Honeypots and a "fingerprint-soup" decoy class create fake products and
     about 29k fake KEV hits.
   - **CVEs are inferred from version strings.** 99.99% are unverified, so they can amplify a
     signal but never be its headline.
   - **Attribution is the binding constraint, not detection.** 63% of signal-eligible services
     can't be tied to any company.

   Details: `docs/research-findings.md`, `docs/signal-catalog.md`, `docs/company-attribution.md`.
2. **Build a vertical slice, layer by layer.** Each layer is versioned and written separately,
   so each one can be tested on its own and rebuilt without the others.

   ```
   raw NDJSON → normalized observations (provenance per row) → services (ip, port, transport, SNI)
     → signals → attribution → account eligibility and scoring → serving DB → FastAPI + page
   ```

3. **Start with six signals**, the ones best supported by the data and most relevant to a
   seller:

   | Code | Signal |
   |---|---|
   | S01 | remote-access gateways / SSL-VPN |
   | S03 | remote-admin protocols |
   | S04 | exposed databases |
   | S05 | management planes |
   | S06 | TLS hygiene |
   | S16 | security-vendor technographics |

   The other eleven catalogued signals are documented but not built.
4. **Write a claim only in the allowed wording.** Every sales-facing statement is one of three
   labelled kinds:
   - an *observed fact* with its timestamp and record;
   - an *inferred risk*;
   - an *unverified hypothesis*.

   The app never claims a vulnerability, a breach, purchase intent or a change over time. This is
   one snapshot.

## Key decisions

| Decision | Why | Record |
|---|---|---|
| Stream the 137 GB file with Python and orjson, using byte-range workers. Keep file, offset, length and SHA-256 on every observation | The whole file can't be loaded at once. Each claim must trace back to its exact source bytes, and malformed lines must be quarantined, not lost | ADR 0002, `docs/ingestion-architecture.md` |
| Explicit snapshots with a seal step | Ingestion can be retried and stays idempotent. Account roll-ups only run on complete data | ADR 0003 |
| Precompute everything, then serve a read-only DuckDB file through FastAPI | Simple, fast (median 8–18 ms on the server) and runs on one machine. No database to operate | ADR 0004 |
| Attribution uses only the service's own record, picks a strict winner, or abstains | Shared hosting and ISP space would otherwise assign infrastructure to an arbitrary customer. Abstaining (tier C) is safer than guessing | ADR 0005 |
| Network providers are classified from pinned OpenASN data and shown in a separate segment | ISPs and hosters are infrastructure, not prospects. Name heuristics alone missed many of them | ADR 0008 |
| NTLM internal names are restricted evidence. The deployed DB is a sanitized copy | They are sensitive, and they never name an owner on their own | ADR 0007 |
| **Scoring v3: priority, ownership and evidence quality are three axes, never multiplied** | Scoring v2 multiplied attribution confidence into the score. A high score could mean "strong exposure" or only "sure who owns it", and it correlated 0.755 with attribution confidence. In v3 that correlation is 0.121 | ADR 0009, `docs/ranking-v3.md` |
| Bands and percentiles instead of decimal scores. "High" requires an exposure signal | The exact order inside the top 40 carries little information, and hygiene or technographics alone should never look urgent | ADR 0009 |
| An `actionable` outreach list built from four gates | Registry placeholder names, accounts whose ownership is uncorroborated, and possible hosters are held for review instead of being sent to sales. See the gates below | `docs/ranking-v3.md` §3.6 |
| A small, explainable rule set over a learned model | There are no labels to train or tune on. Rules can be explained claim by claim | `docs/experiments/` |

An account is actionable only when all four hold:

- it is eligible;
- its ownership is corroborated;
- it has no open review flag;
- it has at least one product- or protocol-level security observation.

## How I measured whether it works

**Built and behaving as specified [measured]:**

- **Tests.** 813 unit and integration tests cover parsers, attribution rules, eligibility, scoring,
  the holdout sampler, the metrics and the API.
- **Browser tests.** 22 end-to-end tests (Playwright, desktop and mobile) pass locally and on the
  live deployment.
- **The live service matches the code.** Ten live endpoints return responses byte-identical to a
  local server on the same commit.
- **Builds are reproducible.** A rebuild of the accounts is identical row for row, and the
  evaluation sample regenerates byte-identical.
- **Performance.**
  - Ingestion runs at 254 MiB/s with 6 workers, under 250 MiB per worker. The full file goes from
    raw to services in about 15.6 minutes on a 16 GiB laptop.
  - The live API takes 8–18 ms (median) on the server.
- **Signals.** Signal counts were reconciled with the research SQL. A sample of records was checked
  by hand for each signal.

**Ranking sanity, measured without labels:**

- **Known negatives.** IP-registry placeholder names ("Leased Line Customer LAN", "non-portable")
  fell out of the top 100: from 12 under scoring v2 to 0 under v3. No account in the
  likely-enterprise class (universities, hospitals, banks, government) was excluded.
- **Ownership checked against the raw records.** In the top 40, a certificate, SNI or HTTP Host
  names the account for 32 accounts under v3, against 23 under v2. This check is a heuristic, not
  a label.
- **Stability.** With all weights jittered ±10%, the top 20 keeps 98% of its members on average.
  Resampling which services were observed (bootstrap), it keeps about 66%. So the band matters
  more than the exact rank.

**Quality against human judgement: not yet measured.**

- I built a 155-case stratified holdout. 88 of its cases were never seen during development, and a
  blind version hides every system output.
- The labelling rubric is in [`docs/labelling-guide.md`](docs/labelling-guide.md). It covers
  entity type, commercial qualification, ownership attribution and evidence support.
- `firmable holdout-metrics` computes Precision@k, attribution correctness and evidence support,
  each with Wilson intervals. It refuses files with model-suggestion columns, and reviewer names that
  name a model.
- **The holdout has 0 labels**, so I report no precision figure. Labelling it is the next step.
  The top 40 was read during development, so its precision can only ever be a census of
  development data. Clean figures will come from the strata below the top.

## Known limitations

- **One snapshot.** Nothing can be said about change over time or activity.
- **Many services can't be attributed.** About 70% of services abstain, and cloud-hosted firms
  appear only when a certificate or SNI names them.
- **Some hosters and telcos still leak into the enterprise segment.**
- **The ranking favours large organisations.** Breadth saturates at 16 IPs, so the top is mostly
  universities and public bodies.
- **The outreach list is mostly TLS hygiene.** 96% of it is hygiene leads, and the list view
  doesn't label exposure-led vs hygiene leads (the detail view does).
- **Thresholds are hypotheses** set without labels.

Full list: `docs/SUBMISSION.md` §7.

## How it was built

I built it with Claude Code, an AI coding agent, under my direction:

- I set the priorities and approved deployments. The agent implemented and measured.
- Deterministic logic was written test-first.
- Every important change was reviewed by a separate reviewer agent before deployment.
- Results were reported only from real runs.
- No model output is ever used as an evaluation label.

Details: `docs/SUBMISSION.md` §9.

## Run it

```bash
uv sync && uv run pytest                                   # 813 tests, ~1 min
uv run firmable register ~/Downloads/firmable_dataset --snapshot 2026-11-07
uv run firmable run --workers 6 && uv run firmable build-services 2026-11-07 && uv run firmable seal 2026-11-07
uv run firmable build-phase3 2026-11-07 && uv run firmable serve 2026-11-07
```
