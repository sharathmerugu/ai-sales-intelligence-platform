# Ingestion Benchmark — normalizer v1

All numbers below were measured on 2026-11-09 with the code at the commit
that adds this file. Nothing is extrapolated except where §5 says so.

## Environment

| Item | Value |
|---|---|
| Machine | MacBook Pro, Intel Core i7-9750H, 6 physical / 12 logical cores, 16 GiB RAM, internal SSD |
| Software | Python 3.12.13, orjson 3.13.0, PyArrow 26.0.1, DuckDB 2.0.0 |
| Input | `~/Downloads/firmable_dataset`: 137,113,095,904 bytes, 16,988,823 lines, read in place (never copied) |
| Chunking | 256 MiB byte ranges, giving 511 chunks; batch of 20,000 rows; zstd Parquet |

## 1. Worker scaling (real data, `scripts/benchmark_ingest.py`)

The production worker (`process_chunk`) runs over disjoint 256 MiB chunks
spread across the time-ordered file.

| Workers | Chunks | Input | Wall | Aggregate | Per worker | Rows/s | Peak RSS per worker |
|---|---|---|---|---|---|---|---|
| 1 | 2 | 0.50 GiB | 8.2 s | 62 MiB/s | 62 MiB/s | 6,336 | 196 MiB |
| 2 | 4 | 1.00 GiB | 9.8 s | 104 MiB/s | 52 MiB/s | 12,411 | 210 MiB |
| 4 | 8 | 2.00 GiB | 11.8 s | 173 MiB/s | 43 MiB/s | 24,768 | 194 MiB |
| 6 | 6 | 1.50 GiB | 6.0 s | 255 MiB/s | 43 MiB/s | 28,963 | 175 MiB |
| 8 | 8 | 2.00 GiB | 8.5 s | 240 MiB/s | 30 MiB/s | 34,431 | 186 MiB |

- **Memory:** flat at about 200 MiB per worker regardless of worker count.
  It was checked at 2–4 workers before concurrency was raised.
- **Scaling:** stops at the 6 physical cores; at 8 workers, hyperthreads
  add contention. Per-worker throughput drops from 62 to 43 MiB/s by 4
  workers (shared cache, turbo frequency).
- **Caveat:** the 6- and 8-worker runs re-read chunk ranges used earlier, so
  the page cache may flatter them slightly. The full run (§2) is the
  uncached reference.
- **Where one worker's time goes** (profile of a 64 MiB real slice):
  - orjson parse: about 30%
  - per-line SHA-256: about 15%
  - Python field extraction: about 50%
  - Arrow conversion and Parquet write: the rest
- **Bottleneck:** CPU. The disk sustains at least 420 MiB/s (§2, register).

## 2. Full-file run (snapshot `2026-11-07`)

| Step | Wall | Throughput | Peak RSS |
|---|---|---|---|
| `register`: full-file SHA-256 | 311 s | 420 MiB/s (sequential) | 59 MiB |
| `run --workers 6`: 511 chunks | 516 s | 254 MiB/s; 32,955 rows/s | 249 MiB per worker process |
| `build-services`: flags + services | 108 s | — | 5.7 GiB (DuckDB `memory_limit=6GB`) |
| Oracle comparison (`scripts/compare_with_slim.py`) | 17 s | — | — |

- **Worker CPU:** 3,076 worker-seconds of chunk processing in total. That
  is 0.85 worker-hours per 137 GB, or **42.5 MiB/s per worker-second**.
- **End to end:** about 15.6 minutes from raw file to the services table,
  on one laptop.

### Accounting

| Measure | Value |
|---|---|
| Lines read | 16,988,823 |
| Rows written | 16,988,823 |
| Quarantined | 0 |
| Blank | 0 |
| Bytes accounted | 137,113,095,904 (exactly the file size) |
| Unicode-repaired rows | **451**: exactly the 451 lines the research parser dropped, now recovered |
| Failed chunks | 0 |
| Retries | 0 |
| Parse warnings | 564, all `protocol_json:oversized` (unknown top-level blobs over 64 KiB: `screenshot`, `html`) |
| Unknown top-level keys | 120 distinct (e.g. `screenshot` 1,650, `synology_dsm` 1,160, `smb` 444, `cisco_anyconnect` 145, `redis` 141). Preserved in `protocol_json` |
| Duplicate observations | **0**. `_shodan.id` is unique across all 16,988,823 rows, which confirms it as the observation key |

### Layer outputs

| Layer | Rows | Size |
|---|---|---|
| `observations` (511 files) | 16,988,823 | 2.95 GiB (46× smaller than input) |
| `observation_flags` | 16,988,823 | 752 MiB |
| `services` | 5,233,493 | 1.2 GiB |

Compressed size by column in `observations`:

| Column | Share |
|---|---|
| `record_sha256` | 19.0% |
| `observation_id` | 11.6% |
| `shodan_id` | 11.6% |
| `service_id` | 10.3% |
| `hostnames` | 6.5% |
| `banner_head` | 4.7% |
| `ip` | 4.1% |
| `protocol_json` | 2.5% |
| `vulns` | 2.3% |

## 3. Regression oracle: v1 vs the research slim Parquet

| Metric | Legacy slim | Normalizer v1 | Delta | Explanation |
|---|---|---|---|---|
| rows | 16,988,372 | 16,988,823 | +451 | The 451 surrogate lines are recovered instead of dropped |
| IPv4 rows | 16,760,878 | 16,761,304 | +426 | Recovered rows |
| IPv6-only rows | 227,494 | 227,519 | +25 | Recovered rows |
| distinct IPv4 | 4,187,088 | 4,187,327 | +239 | Recovered rows |
| distinct IPv6 | 70,922 | 70,926 | +4 | Recovered rows |
| UDP rows | 1,277,559 | 1,277,559 | 0 | |
| rows with SNI | 947,073 | 947,208 | +135 | Recovered rows |
| empty banner, research rule (spaces-only `trim`) | 9,661,100 | 9,661,100 | 0 | Identical under the same rule |
| empty banner, v1 rule (all whitespace) | 9,668,102 | 9,668,102 | 0 | 7,002 whitespace-only banners (`\r\n`, `\n`) |
| honeypot-tagged | 196,309 | 196,309 | 0 | |
| fingerprint soup | 65,706 | 65,706 | 0 | |
| TLS rows | 1,305,753 | 1,305,953 | +200 | Recovered rows |
| HTTP rows | 4,795,353 | 4,795,803 | +450 | Recovered rows (bad surrogates sit in HTML) |
| NTLM rows | 15,701 | 15,701 | 0 | |
| any KEV | 238,391 | 238,465 | +74 | Recovered rows |
| product present | 2,282,769 | 2,282,847 | +78 | Recovered rows |
| distinct service keys | 14,589,475 | 14,589,872 | +397 | Recovered rows |

**Eligible observations: research 7,099,796, v1 7,100,193, delta +397.**
This reconciles exactly:

- +451 recovered rows, all eligible
- −54 whitespace-only banners that the research counted as eligible
  (the other 6,948 whitespace-only rows are honeypot or decoy rows anyway)

**Services: 5,233,493**, which matches the research figure of 5.23M.

## 4. Correctness tests (`uv run pytest`)

73 tests pass in about 40 s:

- **Normalizer unit tests:** identity, IPv6 and IPv4-mapped addresses,
  SNI/vhosts, rejection classes, surrogate repair, drift, range checks.
- **Line ownership:** checked across chunk sizes from 1 byte upwards.
- **Pipeline integration:**
  - accounting and per-file byte accounting
  - provenance and evidence, including tamper detection
  - quarantine
  - duplicate delivery, including into another snapshot
  - replay determinism
  - injected failures and retry
  - worker crash isolation
  - source change detected before overwrite
  - stale normalizer version
  - run lock
  - seal
- **SIGKILL recovery:** a single kill, and four consecutive kills.
- **Services:** dedup, latest observation, vhosts, IPv6, repeats across
  snapshots, the persisted flags layer.
- **Bounded memory:** peak RSS stays under 400 MiB, and grows by less than
  64 MiB when the input grows 4× with 3 MB records.
- **Sanitized real-banner regression:** 16 records.

## 5. Cost and scaling projection

This section is **extrapolated** from the measured 42.5 MiB/s per
worker-second; it is not measured.

- **CPU cost:** about 6.2 worker-hours per TB of NDJSON, plus about 0.7
  sequential hours per TB for SHA-256 registration.
- **Example:** at "thousands of files per month", say 2 TB/month, that is
  about 12.5 worker-hours/month. A single 8-core host clears it in about
  2 hours, so no distributed infrastructure is needed at this volume.
- **Where to scale next:**
  - Chunks are independent, so a host gets the throughput of its physical
    cores.
  - Several hosts need only the Postgres manifest with leases described in
    `ingestion-architecture.md` §11.
- **Storage:** about 23 GB of Parquet per TB of input (observations, flags
  and services).

## 6. Known limitations and next optimisations

1. **Hex identifiers take 52% of observation storage.** Store
   `record_sha256` and `service_id` as fixed binary, and stop storing
   `shodan_id` separately from `observation_id`. Expected saving: about
   35% of size. This needs normalizer v2.
2. **`protocol_json` drops objects over 64 KiB** (564 rows, from
   `screenshot`/`html` blobs). v2 should exclude known blob keys and record
   only their presence.
3. **Python field extraction is about 50% of worker CPU.** Inlining the
   typed accessors is the cheapest speed-up if throughput ever matters.
4. **`build-services` peaks at 5.7 GiB.** That is fine on 16 GiB, but the
   limit should be lowered when it runs next to 6 ingest workers.
5. **The empty-banner rule differs from the research** (7,002 rows, 54 of
   them eligible). This is intentional and documented in
   `ingestion-architecture.md` §4.
