# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Mission

Firmable five-day take-home: a working, hosted cybersecurity sales intelligence platform that helps B2B salespeople find, rank and target companies using evidence-backed buying signals from internet-scan data. Ship a complete vertical slice before adding infrastructure or UI polish.

Priorities, in order:

1. Signal correctness and commercial relevance
2. Accurate company attribution
3. Explainable account ranking
4. Reliable, scalable ingestion
5. Working hosted application
6. Measurable evaluation and verification

## Current state

Research is complete. Ingestion (normalized observations, manifest, classification, services) is built in `src/firmable/`; see `docs/ingestion-architecture.md` and `README.md`. Phase 3 vertical slice is built: signals S01/S03/S04/S05/S06/S16, attribution v1, account roll-up and scoring v1, serving DB and FastAPI app (`uv run firmable build-phase3 SNAPSHOT`, `uv run firmable serve SNAPSHOT`); see `docs/phase3-plan.md` (contracts) and `docs/phase3-results.md` (measurements, limitations). Hardening: NTLM is restricted evidence (ADR 0007), network type comes from pinned OpenASN data with separate enterprise / network-provider segments (ADR 0008, `docs/network-classification.md`), the sanitized app is deployed on Railway (`docs/deployment.md`), and evaluation uses a reviewed sample (`docs/evaluation.md`); results in `docs/phase3-hardening-results.md`. Scoring v3 ranks eligible accounts by opportunity priority, with ownership confidence, evidence quality and an `actionable` gate as separate fields; the v2 score is kept as `legacy_score` (ADR 0009, `docs/ranking-v3.md`; `uv run firmable compare-rankings SNAPSHOT`). Attribution v5 folds accents in org names and adds corroborated provider entries (`docs/attribution-implementation.md` §7). Evaluation uses a deterministic scoring-v3 holdout with a development-case registry (`firmable holdout-set` / `holdout-metrics`, `docs/evaluation.md`); it has no labels yet; human reviewers follow `docs/labelling-guide.md`. Account ids from older builds redirect by rule (`docs/api.md`). Serving v4 (ADR 0010, `docs/sales-brief.md`): research states replace "actionable outreach", use-case lenses rank on lens signals only (`firmable.accounts.use_cases`), the API serves a plain-language brief (`firmable.api.brief`), and sales wording lives in the registry (`WORDING_VERSION`, separate from detection). Submission summary: `docs/SUBMISSION.md`. Agentic briefs (ADR 0011, `docs/agentic-briefs.md`): `firmable.semantic` (typed objects over the serving DB), `firmable.agent` (one bounded tool-using agent, code-enforced publication checks, deterministic fallback cards, SQLite runs and cache), `/semantic/*`, `/briefs`, `/ask`, `/runs`; `firmable agent-brief` / `agent-eval`. Only mock models have been run; no real-provider result exists yet.

```bash
uv sync                                   # Python 3.12 env
uv run pytest                             # all tests (~40 s); -m "not slow" skips the memory test
uv run firmable register PATH --snapshot ID && uv run firmable run --workers 6
uv run firmable status | build-services ID | seal ID | evidence OBS_ID | retry FILE_ID | replay FILE_ID
```

Readers must take observation files from `Pipeline.committed_observation_files()`, never a glob.

Phase 3 (signals, attribution, API, app) starts from `docs/PHASE3_HANDOFF.md`: data locations, schemas, contracts and known defects.

Build order: (1) normalized ingestion, (2) attribution and signal validation, (3) deterministic account scoring, (4) searchable API, (5) hosted salesperson app, (6) end-to-end evaluation. First signals: **S01, S03, S04, S05, S06, S16**. Add the other signals only after the app works end to end.

## Read before changing ingestion, attribution, signals or scoring

| File | Holds |
|---|---|
| `docs/research-findings.md` | Start here: headline findings, fact / inference / hypothesis wording (§3), data-quality traps (§4), scoring-design implications (§5), open questions (§6) |
| `docs/data-profile.md` | Field dictionary, coverage, distributions, noise classes |
| `docs/signal-catalog.md` | S01–S17 and compounds C1–C6: rule, evidence layers, prevalence, examples and counterexamples |
| `docs/company-attribution.md` | Attribution evidence sources, provider classification, tiers A1/A2/B/C, known precision problems |
| `sql/exploration.sql` | Reproducible queries behind every doc number; header lists the DuckDB 2.0 gotchas and memory limits |

Build on this research instead of redoing it. The existing SQL already implements the noise flags, the `(ip, port, transport, SNI)` service key, attribution tiers and the signal rules; port that logic and keep the versions and citations.

## Data

- Raw dataset: `~/Downloads/firmable_dataset` — 137 GB NDJSON, 16,988,823 Shodan-format banners from one crawl on 2026-11-07. Stream it with bounded memory and never load it whole.
- Large working artifacts (Parquet, DuckDB databases) go in `~/firmable-work/`, outside the repo.
- `sample.jsonl` and `distributed_sample.jsonl` are local, gitignored copies of raw data (they contain real IPs). Regenerate them byte-identically from the repo root:
  - `head -n 5000 ~/Downloads/firmable_dataset > sample.jsonl` — biased toward early HTTP rows, so use it for schema inspection only.
  - `python3 scripts/distributed_sample.py` — 250 evenly spaced offsets × 8 lines; representative, so use it for fast iteration.

## Running the research SQL

```bash
mkdir -p ~/firmable-work
duckdb ~/firmable-work/research.duckdb \
  -c "SET VARIABLE sample='sample.jsonl';" \
  -c "SET VARIABLE dist='distributed_sample.jsonl';" \
  -c "SET VARIABLE dataset='$HOME/Downloads/firmable_dataset';" \
  -c "SET VARIABLE slim='$HOME/firmable-work/full_slim.parquet';" \
  -c ".read sql/exploration.sql"
```

- The full file takes about 6.5 minutes. To iterate in about 23 seconds, set `dataset` to `distributed_sample.jsonl` and `slim` to another Parquet path.
- `~/firmable-work/` starts empty, so run the script once before querying the saved tables (`obs`, `svc`, `signal_hits`, `account_summary`).
- The `slim` view reads `getvariable('slim')`, so run `SET VARIABLE slim=...` again in every new session.
- DuckDB uses "agent mode" output when `AI_AGENT` is set; pass `-no-agent` for normal output.

## Engineering principles

- Batch processing uses Python, DuckDB, PyArrow and Parquet. Prefer streaming, bounded-memory operations, and benchmark performance claims.
- Provenance on every observation: source file, byte offset, record length, observation ID, content hash.
- Ingestion must be idempotent, retryable and reproducible. Support IPv4, IPv6, SNI and multiple snapshots.
- Keep five layers separate: raw observations → classification → signals → attribution → account scoring. Version the extractors, attribution rules and scoring algorithms.
- Use a single machine unless a requirement proves it insufficient.

## Cybersecurity intelligence rules

- A scanner module name says which probe ran, not which product it found.
- An open port is not a vulnerability, and a missing security fingerprint does not prove a control is absent.
- CVEs from `vulns` are inferred from version strings and are unverified (99.99% `verified:false`). Use them as amplifiers or timing triggers, not headline claims.
- Treat hosting providers and ISPs as infrastructure, not customers. Never assign shared infrastructure to an arbitrary customer domain. Keep attribution uncertainty visible and allow abstention (tier C contributes to no account).
- Every sales-facing claim must trace to its supporting observations and use the allowed wording in `research-findings.md` §3. Never claim company activity, purchase intent or historical change (the dataset is one snapshot).
- Sensitive details (NTLM internal names, compromise indicators, OT exposure) sit behind human review. Mask example IPs to /24 in docs.

## Workflow

- Write specs with testable acceptance criteria. Use TDD for deterministic logic (parsers, attribution rules, scoring), and run the tests after every implementation change.
- Get an independent code review for important changes. Run parallel agents only on independent tasks with clear ownership.
- Report success only with real test output or measured results.
- Record architectural decisions as ADRs in `docs/decisions/` (create the directory with the first ADR).
- Before a major task, check `git status`, the relevant docs and ADRs, and what already exists, then reuse it. After a milestone, update the implementation docs in `docs/` with completed work, commands, verification results and known limitations. Keep progress logs and handoffs in `docs/`; this file holds only durable guidance.
