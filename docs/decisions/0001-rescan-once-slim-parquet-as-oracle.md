# 0001 — Rescan the source once; keep the research slim Parquet as a frozen oracle

Status: accepted (2026-11-09)

## Context
The research slim Parquet (16,988,823 rows, 59 columns) has no provenance:
no source offset, no `_shodan.id`, no banner hash, and it was written with
`preserve_insertion_order=false`, so row number is not line number. It also
drops per-CVE vulns, cert SAN names, HTTP components and protocol objects.
The 451 parse failures became anonymous all-NULL rows.

## Decision
Run the new ingestion pipeline once over the 137 GB source to produce
provenance-bearing observations. Freeze the slim Parquet at
`~/firmable-work/legacy/full_slim_v2.parquet` and use it as a regression
oracle: row counts and key distributions of the new output must match it,
except for documented differences (recovered surrogate lines).

## Consequences
One extra full pass (cost in `docs/ingestion-benchmark.md`). The pass also
stores raw-but-cheap extras (`protocol_json`, compact vulns), so new signals
should not need another rescan. `sql/exploration.sql` stays unchanged and
reproducible.
