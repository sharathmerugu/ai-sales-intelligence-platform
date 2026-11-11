# 0002 — Parse with Python + orjson per line, not DuckDB read_json

Status: accepted (2026-11-09)

## Context
DuckDB `read_json` parsed the full file in about 2 minutes, but with
`ignore_errors` a bad line becomes an anonymous all-NULL row: there is no
byte offset, no quarantine and no per-field drift count. The ingestion
contract requires that no malformed data is dropped without being counted
and identifiable.

## Decision
Workers read newline-aligned byte ranges and parse each line with orjson,
falling back to the stdlib parser (which accepts lone surrogate escapes).
Rejected lines go to quarantine with offset and error class. DuckDB handles
every set-based stage after Parquet is written.

## Consequences
Per-core throughput is lower than DuckDB's; measured numbers are in
`docs/ingestion-benchmark.md`. Line-level provenance and exact accounting
come for free. The 451 surrogate lines are recovered instead of dropped.
