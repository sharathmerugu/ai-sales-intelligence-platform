# Ingestion Architecture

Status: v1 design, implemented as the first vertical slice (see §13 for what
is built vs. designed only). Decisions with real trade-offs are recorded in
`docs/decisions/`. Domain terms are defined in `GLOSSARY.md`.

## 0. Goals and non-goals

**Goal:** turn delivered NDJSON scan files into typed, provenance-bearing
Parquet observations, reproducibly, with bounded memory, exact error
accounting and idempotent retries. The output feeds classification,
services, signals, attribution and account scoring.

**Non-goals for the five-day build:** distributed queues, Kafka/Spark/K8s,
lease-based multi-host workers, UI, scoring. Section 11 says how the design
grows into those without rework.

## 1. Pipeline layers

Each layer is a separate dataset with its own version. A later layer never
writes into an earlier one.

| # | Layer | Content | Kind | Version tag |
|---|---|---|---|---|
| 1 | `observations` | One row per scanner banner: scanner-asserted facts + provenance | fact | `normalizer_version` |
| 2 | `observation_flags` | Noise classification: empty, honeypot-tagged, fingerprint soup, CDN edge, eligible | our heuristic | `classifier_version` |
| 3 | `services` | Latest eligible observation per service per snapshot, with dedup | derived fact | `services_version` |
| 4 | `signal_hits` | Service matched a signal rule + evidence columns | fact match | `signal_id@version` |
| 5 | `attribution_evidence` / `service_attribution` | Candidate owners per service, one row per evidence source | **inference** | `attribution_version` |
| 6 | `account_signals` | Signals rolled up to accounts | inference | `rollup_version` |

Scanner claims (`tags`, `product`, `vulns`, `cpe23`) are stored in layer 1
as *scanner-asserted* values, never re-labelled as our findings. Inferred
risk and buying-hypothesis wording lives in the **signal registry** (static
per signal version), not in rows.

## 2. File lifecycle and manifest

The manifest is a SQLite database (`~/firmable-work/manifest.sqlite`, WAL
mode). One coordinator process owns it; workers never touch it.

```
file:   registered ──run──▶ processing ──all chunks done──▶ completed
                                  │
                                  └─ any chunk exhausted retries ─▶ failed
        registered ── content_sha256 already known ──▶ duplicate (no work)

chunk:  pending ──dispatch──▶ running ──ok──▶ done
                                 │
                                 └─error─▶ failed (attempts += 1)
        running (from a dead run) ──next run start──▶ pending
```

Tables: `files`, `deliveries`, `chunks`, `snapshots`, `runs`. Per-chunk
metrics are stored on the chunk row: lines, bytes, rows, quarantined by
class, warnings by field, unknown keys, wall time, and the worker
process's peak RSS. The RSS figure is a lifetime high-water mark of a pooled
worker, so it is an upper bound for any single chunk.

- **Run lock:** `run` takes an exclusive `flock` on `workdir/run.lock`, so
  a second coordinator is refused instead of resetting the first one's
  chunks.
- **Attempts are charged only for real failures:**
  - A worker exception counts as a failure.
  - A worker process death counts as a failure.
  - A chunk interrupted by a dead coordinator is reset to `pending`
    without a charge.
- **Bounded submission:** at most `workers` chunks are in flight at once.
- **Worker crash:** if a worker process dies (OOM, kill), the pool breaks,
  and every chunk that was in flight is re-run **alone** in a one-process
  pool. The crash is therefore charged to the chunk that caused it, and the
  run continues with a fresh pool.
- **File completion:** a file is `completed` only when every chunk is
  `done` *and* the chunks' `bytes_read` sum to the file size (the per-file
  accounting invariant). Otherwise the file is `failed`.

## 3. File identity and idempotency

- **`file_id` = full-file SHA-256** of the delivered bytes, computed
  sequentially at `register`. SHA-256 runs at hundreds of MB/s, well
  under the parse cost, so the 137 GB file costs one sequential read (measured
  in the benchmark report).
- **`input_digest`** (per chunk) = SHA-256 over the sequence of
  `(byte_offset, byte_length, record_sha256)` of the lines the chunk owns.
  It is a digest *of record hashes*, not a SHA-256 of the chunk's bytes and
  not a file identity, and it is never combined into one. A re-read whose
  digest differs from the last successful read fails with `SourceChanged`
  **before** any output is replaced, so good Parquet is never overwritten
  with output from changed bytes. A chunk that has never succeeded has no
  reference digest; evidence retrieval still catches a changed source
  through `record_sha256`.
- **Duplicate delivery:** registering bytes whose SHA-256 already exists
  records a new delivery row pointing at the existing `file_id` with
  outcome `duplicate`. No chunk is processed twice. The file **keeps the
  snapshot it was first registered into**, even if the redelivery names
  another snapshot. The requested snapshot is recorded on the delivery row
  and logged, because the same bytes cannot be two snapshots' evidence.
- **Source files are read in place, read-only.** The 137 GB file is not
  copied. `register` stores the absolute path; evidence retrieval re-reads
  it and checks `record_sha256`. Retention of delivered files is a
  requirement for evidence (see §7).
- **Deterministic outputs:** a chunk's output path is a function of
  `(normalizer_version, snapshot_id, file_id, chunk_index)`. Row content is
  a function of the input bytes and the normalizer version only; run IDs and
  wall-clock times live in the manifest, not in Parquet. A retry or replay
  overwrites the same path with the same rows.
- **Atomic commit:** write to `_tmp/<run>/…`, then `os.replace` into the final
  path, then mark the chunk `done` in the manifest. Readers select chunk
  files **from the manifest**, so a partially processed file is never read
  as complete.

## 4. Streaming parse and error handling

- **Work unit = chunk:** a byte range of one file, default 256 MB, aligned so
  that each line belongs to exactly one chunk (the line *starting* inside
  `[start, end)` belongs to that chunk). The 137 GB file has about 512 chunks.
  Small files are one chunk.
- Parse with **orjson**. On failure, retry with the stdlib `json` parser,
  which accepts the lone UTF-16 surrogate escapes that broke 451 lines in
  research; lone surrogates are replaced with U+FFFD and the row gets
  `unicode_repaired = true`.
- **Rejected lines go to quarantine** (`quarantine/…/chunk-NNNNN.jsonl`):
  offset, length, error class, message and up to 64 KB of raw bytes.
  Error classes:
  - `malformed_json`
  - `not_an_object`
  - `missing_required`
  - `invalid_value`, e.g. a port out of range or an unparseable IP or
    timestamp
  - `oversized`, a line over 32 MB
  - `normalizer_error`, a catch-all, so that a poison line can never fail
    its chunk
  - `schema_mismatch`, a value the normalizer accepted that does not fit
    the Arrow schema. Only that row is isolated and quarantined.
- **Partially valid rows are kept.** A wrong type on an optional field nulls
  that field and appends `field:reason` to `parse_warnings`.
- **Schema drift** is counted, not fatal: unknown top-level keys and
  per-field type mismatches are counted per chunk in the manifest.
- **Accounting invariant**, checked per chunk and per file:
  `lines = rows_written + quarantined + blank_lines`. A violation fails the
  chunk.
- **Out-of-range integers** (for example a 40-bit `http.status` in an
  int32 column) become NULL with a `field:range` warning.
- **Empty banner** means `data` is empty after stripping *all* whitespace
  (Python `str.strip()`). The research SQL used DuckDB `trim()`, which
  strips spaces only, so a banner of just `\r\n` counted as non-empty
  there. Whitespace-only payloads carry no evidence, so v1 treats them as
  empty. The size of this difference is measured against the slim oracle
  in `docs/ingestion-benchmark.md`.
- **Bounded memory:** a worker holds at most one Arrow batch (default 20,000
  rows) of *extracted* fields; large blobs (`data`, HTML, favicon, CVE
  summaries) are never retained. A `ParquetWriter` streams batches to disk.

## 5. Observation schema and partitions

Partition layout (Hive style, outside Git under `~/firmable-work/lake/`):

```
observations/normalizer=v1/snapshot=<snapshot_id>/file=<file_id[:16]>/chunk-00042.parquet
quarantine/normalizer=v1/snapshot=<snapshot_id>/file=<file_id[:16]>/chunk-00042.jsonl
observation_flags/classifier=v1/normalizer=v1/snapshot=<snapshot_id>/flags.parquet
services/services=v1/normalizer=v1/snapshot=<snapshot_id>/services.parquet
```

Snapshot is the main query boundary; file and chunk give independent,
overwrite-safe units. Rows stay in source order within a chunk
(deterministic; service-sorted layout belongs to the `services` layer).
Zstd, row groups of 100k rows.

Column groups (full list in `src/firmable/ingest/schema.py`):

| Group | Columns |
|---|---|
| Provenance | `observation_id`, `file_id`, `snapshot_id`, `byte_offset`, `byte_length`, `record_sha256`, `normalizer_version`, `unicode_repaired`, `parse_warnings` |
| Service identity | `service_id`, `ip`, `ip_version`, `port`, `transport`, `sni` |
| Scanner metadata | `observed_at`, `shodan_id`, `banner_hash`, `crawler`, `module` |
| Network | `org`, `isp`, `asn`, `country_code`, `cloud_provider`, `cloud_service`, `cloud_region` |
| Fingerprint (scanner-asserted) | `product`, `version`, `os`, `devicetype`, `info`, `cpe23`, `tags`, `hostnames`, `domains` |
| Banner | `banner_len`, `banner_head` (160 chars) |
| HTTP | status, title, server, host, waf, favicon hash, html hash, `has_securitytxt`, `has_hsts`, `has_csp`, `x_powered_by`, `www_authenticate`, `http_components` (names) |
| TLS | `has_ssl`, versions, cert dates/expired, subject/issuer CN+O, `cert_san_dns` (parsed from DER), sig alg, key type/bits, cert SHA-256, Mozilla trust, JARM |
| Other protocols | `ssh_hassh`, NTLM domain/netbios/fqdn/os_build, `protocol_json` (raw JSON of small protocol objects: `isakmp`, `rdp_encryption`, `vnc`, `snmp`, `hp_ilo`, `fortinet`, `mikrotik_routeros`, …) |
| Vulns (scanner-inferred, unverified) | `vulns` as `list<struct<cve, cvss, kev, verified, epss, ransomware_known>>`, `any_kev`, `any_verified` |

**Gaps closed versus the research slim Parquet:** provenance, `_shodan.id`,
banner hash, crawler, per-CVE vulns, cert SAN names, HTTP components, HTML
hash, protocol objects, IPv6-aware service key, and identifiable parse
failures. The slim Parquet is frozen at `~/firmable-work/legacy/` as the
regression oracle (ADR 0001).

## 6. Service identity, snapshots and timestamps

- **`service key = (ip, port, transport, sni)`**
  - `ip`: `ip_str`, or `ipv6` when `ip_str` is absent (IPv6 records carry
    only `ipv6`). Canonicalized with `ipaddress`: compressed IPv6;
    IPv4-mapped IPv6 folded to IPv4.
  - `transport`: lower-case `tcp`/`udp`.
  - `sni`: `_shodan.options.hostname`, lower-cased, trailing dot removed,
    `''` when absent. Two vhosts on one IP are two services.
  - `service_id`: first 16 bytes of SHA-256 over the canonical string, as hex.
- **`observed_at`**: scanner `timestamp`, a naive ISO string, interpreted as
  UTC.
- **`snapshot_id`**: declared at `register` (`--snapshot`, default the UTC
  delivery date). Many files may share a snapshot. A snapshot is **sealed**
  explicitly once all its files are complete. Attribution and account
  rollups run only on sealed snapshots, because they use snapshot-wide
  aggregates (infrastructure domains on ≥1,000 IPs, multi-tenant orgs).
  Registering a new file into a sealed snapshot unseals it (ADR 0003).

## 7. Evidence and provenance

Each observation row carries `(file_id, byte_offset, byte_length,
record_sha256)` plus small excerpts (`banner_head`, `http_title`,
`cert_subject_cn`). `firmable evidence <observation_id>` looks up the
source path in the manifest, reads exactly that byte range from the
read-only source, verifies the hash, and prints the original record. Raw
banners are not copied into the lake.

## 8. Deduplication and safe retries

- **`observation_id`** = `_shodan.id` when present (unique on all 7,000
  sampled rows; full-file uniqueness is checked by the full run), else
  `c:` + SHA-256 of `(service key, observed_at, banner_hash)`.
- **Deduplication happens in the `services` layer, not at write time,** so
  chunks stay independent: `DISTINCT ON observation_id` (keep the lowest
  `(file_id, byte_offset)`), then the latest eligible observation per
  `(snapshot_id, service_id)`.
- The same service seen in two snapshots is a **repeat observation**, not a
  duplicate. Each snapshot gets its own service row.
- Retry after interruption: chunks left `running` by a dead run are reset to
  `pending` at the next `run`. Their deterministic output is overwritten.
  Orphans in `_tmp/` are deleted at run start.

## 9. Signal extraction interface and versioning

Each signal is a registry entry:

```python
Signal(id="S01", version=1, family="exposure",
       sql_predicate="...",          # over the services table
       evidence_columns=[...],       # what the salesperson can be shown
       observed_fact="...", inferred_risk="...", hypothesis="...",
       allowed_tiers={...})
```

`signal_hits` rows carry `signal_id`, `signal_version`, `service_id`,
`snapshot_id`, `observation_id` and the evidence columns. Changing a rule
bumps its version; only layers 4–6 re-run, reading Parquet, never JSONL.
First signals: S01, S03, S04, S05, S06, S16.

## 10. Attribution and incremental account updates (designed; next phase)

- `attribution_evidence` keeps **one row per (service, source, name)**:
  `org`, `hostname`, `sni`, `http_host`, `cert_cn`, `cert_san`, `ntlm`, with
  filter outcome (`ptr_like`, `non_company`, `infra_domain`, kept).
- A service gets an owner only when evidence agrees; **no
  `customer_domains[1]`**. Multiple unrelated domains ⇒ `ambiguous_shared`,
  allowed for web/technographic signals only, never infrastructure exposure.
  Tier C abstains.
- v0 rules from `sql/exploration.sql` are ported as `attribution_version=0`
  and labelled experimental.
- **Incremental unit = snapshot partition.** A newly completed file
  recomputes layers 2–4 for its snapshot; sealing recomputes 5–6. DuckDB
  over about 1 GB of Parquet is minutes at most, so row-level upserts are
  unnecessary.

## 11. Scaling to thousands of files per month

- Chunks are independent and stateless; throughput scales with worker count
  until disk or CPU saturates. Measure per-worker throughput first (§12).
- Single host: `ProcessPoolExecutor` with N workers; coordinator owns the
  manifest.
- Hosted growth path (designed, not built): object storage for landing and
  lake; Postgres manifest with the same tables plus a `lease_until` column;
  workers claim chunks with `UPDATE … WHERE status='pending' … RETURNING`
  (`SKIP LOCKED`). No Kafka or Spark needed at this volume: 137 GB/month is
  about 50 KB/s average.

## 12. Operations: metrics, cost, failure modes

- **Logs:** JSON lines to stderr (`event`, `run_id`, `file_id`, `chunk`,
  counts, durations).
- **Metrics per chunk:** lines, bytes, rows, quarantined by class, warnings,
  drift keys, wall time, MB/s, peak RSS. `firmable status` aggregates them.
- **Failure modes:**
  - Worker crash: the suspect chunks are isolated, and the crashing chunk
    is retried up to 3 attempts.
  - Coordinator crash: `running` chunks are reset on the next run, with no
    attempt charged.
  - Disk full: the write fails before the rename, so there is no partial
    output.
  - Source changed after a successful read: the `input_digest` mismatch
    fails the chunk before any output is replaced.
  - Poison line or out-of-schema value: quarantined; the chunk does not
    fail.
  - Normalizer version bump: chunks written by an older version count as
    `stale_chunks` in `status` and are hidden from readers until replayed.
- **Cost:** CPU-bound JSON parsing dominates. One full pass costs the number
  of worker-minutes measured in `docs/ingestion-benchmark.md`. Storage is
  about 1 GB Parquet per 137 GB input.
- **Trade-offs:** per-line Python parsing is slower than DuckDB
  `read_json`, but it gives exact error accounting (ADR 0002). Dedup at read
  time costs a window function per snapshot but keeps writes independent.

## 13. Built vs. designed

| Item | State |
|---|---|
| Manifest, register (full SHA-256), duplicate detection, chunk planning | built |
| Streaming normalizer, quarantine, drift counts, accounting invariant | built |
| Parquet writer, atomic commit, idempotent replay, interruption recovery | built |
| Evidence retrieval, status, snapshot seal | built |
| Classification (`observation_flags`) and services layers (DuckDB SQL) | built |
| Full 137 GB run, oracle comparison, benchmark (`docs/ingestion-benchmark.md`) | done: 16,988,823 rows, 0 quarantined, 451 repaired, 5,233,493 services |
| Signals S01/S03/S04/S05/S06/S16, attribution evidence, account rollup | next phase |
| Postgres manifest, leases, object storage, multi-host workers | designed only |
