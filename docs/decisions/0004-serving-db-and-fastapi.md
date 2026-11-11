# 0004 — Precomputed layers served from a read-only DuckDB file through FastAPI

Status: accepted (2026-11-10)

## Context
The salesperson API needs ranked accounts, search, filters, account detail and
evidence. The full snapshot yields 180,010 accounts and about 0.7 M evidence
rows; the upstream layers (services 1.2 GB, attribution evidence 15 M rows)
are far larger than what the API needs. No user writes (notes, feedback) are
required yet. Hosting target is undecided.

## Decision
`firmable build-phase3` precomputes every layer as versioned Parquet and then
copies only `accounts`, `account_signals`, `account_evidence` and the signal
registry into one DuckDB file (`<workdir>/serving/<snapshot>.duckdb`). A
FastAPI app opens it read-only; every request value is a bound parameter. A
static page (vanilla JS, no build step) is served by the same process.

## Consequences
- One self-contained artifact per snapshot; the API never reads the 137 GB
  source or the large layers, so it can be hosted on a small container.
- Rebuild, not update: new snapshot or new scoring version means a new file.
- No user state; adding notes or feedback later needs a writable store
  (Postgres or MotherDuck), recorded as a new ADR.
- The serving file name carries the snapshot but not the layer versions;
  versions live in the rows (`signal_version`, `attribution_version`,
  `scoring_version`).
