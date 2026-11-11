# Phase 3 Handoff — signals, attribution, ranked-account API

Written 2026-11-09 at the end of Phase 2 (ingestion). Every path, command
and number below was checked against the repository and `~/firmable-work/`
on that date. The repository is the source of truth; if this file and the
code disagree, trust the code and fix this file.

**Updated 2026-11-11.** §1 status, §17 (current scoring implementation) and §18 (recommended
changes from the data-science experiments in `docs/experiments/`) reflect the code at `22e22b2`.
Sections 2–16 are kept as written on 2026-11-09. For the current per-layer state, read
`docs/phase3-results.md`, `docs/phase3-hardening-results.md` and `docs/DATA_SCIENTIST_HANDOFF.md`.

Read first, in order: `CLAUDE.md` → this file → `docs/research-findings.md`
→ `docs/signal-catalog.md` (S01, S03, S04, S05, S06, S16) →
`docs/company-attribution.md` → `docs/ingestion-architecture.md`.

---

## 1. Status

| Milestone | State |
|---|---|
| Research: data profile, 17 signals, 6 compounds, attribution tiers | **done** (`docs/`, `sql/exploration.sql`) |
| Ingestion: manifest, streaming normalizer, Parquet observations, quarantine, provenance, evidence | **done, tested, full 137 GB run complete** |
| Classification layer (`observation_flags`) and services layer | **done** for snapshot `2026-11-07` |
| Benchmark and regression comparison with the research output | **done** (`docs/ingestion-benchmark.md`) |
| Signals S01, S03, S04, S05, S06, S16 as versioned Python/SQL modules | **done 2026-11-10** (`docs/signals-implementation.md`) |
| Attribution (per-source evidence, abstention) | **done**; now v4: OpenASN network types, tier P, NTLM restricted (ADR 0007, 0008; `docs/attribution-implementation.md`, `docs/network-classification.md`) |
| Account roll-up and scoring | **done**; now scoring v2 (v1 formula, ranked per segment; ADR 0006; §17) |
| Ranked-account API and hosted app | **done and deployed** on Railway with Basic auth and rate limit (`docs/deployment.md`, `docs/api.md`) |
| Evaluation | review set (104 cases) and source-record inspection built; **0 human labels** (`docs/evaluation.md`, `docs/phase3-hardening-results.md`) |
| Data-science experiments on scoring v2 | **done 2026-11-11**, read-only (`docs/experiments/`; §18) |
| Scoring v3: priority apart from ownership and evidence, eligibility, bands | **done 2026-11-11**, built offline on the full snapshot; v2 kept as legacy (`docs/ranking-v3.md`, ADR 0009) |
| Snapshot `2026-11-07` sealed | **yes** (sealed 2026-11-09 after the services rebuild) |

Build order from `CLAUDE.md`: (1) ingestion ✔ → (2) attribution and signal
validation → (3) deterministic account scoring → (4) searchable API →
(5) hosted salesperson app → (6) end-to-end evaluation. The user wants a
**working ranked-account API and hosted app as soon as possible**. Add
signals beyond S01/S03/S04/S05/S06/S16 only after the app works end to end.

## 2. Repository layout and entry points

```
CLAUDE.md                      durable agent guidance (mission, rules, commands)
README.md                      operator runbook: ingest, evidence, recovery, replay
GLOSSARY.md                    domain terms (Observation, Service, Snapshot, Signal Hit, Attribution, Account …)
pyproject.toml / uv.lock       package "firmable-intel", Python 3.12, console script `firmable`
docs/
  research-findings.md         start here for research; §3 allowed wording, §4 data traps
  data-profile.md              field dictionary, coverage, noise classes
  signal-catalog.md            S01–S17, C1–C6: rules, examples, counterexamples, prevalence
  company-attribution.md       evidence sources, provider classification, tiers A1/A2/B/C
  ingestion-architecture.md    layer model, lifecycle, identity, dedup, scaling (§13 = built vs designed)
  ingestion-benchmark.md       measured full-run numbers and the comparison with the slim oracle
  decisions/0001..0003-*.md    ADRs: rescan once / Python parser / explicit snapshots + seal
  PHASE3_HANDOFF.md            this file
sql/exploration.sql            research queries; reusable macros and signal rules (see §11)
scripts/
  distributed_sample.py        regenerates distributed_sample.jsonl (gitignored raw sample)
  make_regression_fixture.py   regenerates tests/fixtures/real_sanitized.jsonl from the raw sample
  benchmark_ingest.py          worker throughput benchmark on byte ranges of the real file
  compare_with_slim.py         regression comparison: v1 observations vs frozen research slim Parquet
src/firmable/
  cli.py                       `firmable` CLI (argparse); entry point main()
  logs.py                      log(event, **fields): JSON lines on stderr
  ingest/normalize.py          normalize_line(bytes) -> dict | Rejection; service_id(); canonical_ip(); canonical_sni(); san_dns_names()
  ingest/schema.py             OBSERVATION_SCHEMA (Arrow), NORMALIZED_COLUMNS
  ingest/chunks.py             plan_chunks(), iter_chunk_lines(): line-ownership framing
  ingest/worker.py             process_chunk(ChunkTask): one chunk to Parquet plus quarantine, atomic rename
  ingest/manifest.py           SQLite DDL: files, deliveries, chunks, snapshots, runs
  ingest/pipeline.py           Pipeline: register/run/retry/replay/seal/status/evidence/committed_observation_files
  transform/services.py        build_services(pipe, snapshot): classifier v1 + services v1 (DuckDB)
tests/                         73 tests (see §16); fixtures/real_sanitized.jsonl = 16 sanitized real banners
```

`tests/fixtures/*.jsonl` is explicitly allowed in `.gitignore`; every other
`*.jsonl`/`*.parquet`/`*.duckdb` stays out of Git.

## 3. Git state

- **Superseded 2026-11-10:** ingestion is on `main`; Phase 3 commits follow
  `22b5267` on `main`. The rest of this section is the Phase 2 state.
- **Commits on the branch, oldest first:**
  - `558f448` Add provenance-bearing ingestion slice with manifest and
    services layer
  - `58101af` Fix ingestion review findings: poison lines, crash
    isolation, retries
  - `5c422a0` Add ingestion benchmark report and full-run oracle
    comparison
  - `0103b3e` Add Phase 3 handoff
  - plus the commit fixing the services-schema defects (see §13)
- **Untracked:** `session1.txt`, a transcript of the research session.
  It is deliberately not committed; the user decides whether to keep it.
- **Remote:** none configured.

## 4. Ingestion architecture (summary; details in `docs/ingestion-architecture.md`)

Layers are separate, versioned datasets, and a later layer never writes into
an earlier one:

```
observations (normalizer v1) → observation_flags (classifier v1) → services (services v1)
   → [Phase 3] signal_hits (signal_id@version) → attribution_evidence / service_attribution (attribution vN)
   → account_signals / scores
```

Key decisions:
- **ADR 0001:** rescan the source once, and keep the research slim
  Parquet frozen as the regression oracle.
- **ADR 0002:** parse with Python + orjson per line, with a stdlib
  fallback for lone surrogates, rather than DuckDB `read_json`. This
  gives exact error accounting.
- **ADR 0003:** explicit snapshot ids plus a seal step. Attribution and
  roll-ups run only on sealed snapshots, because they use snapshot-wide
  aggregates.
- **File identity:** `file_id` is the SHA-256 of the full file. The
  per-chunk `input_digest` is a SHA-256 over
  `(offset, length, record_sha256)` tuples. It verifies re-reads and is
  **not** a file hash.
- **Work unit:** a 256 MiB byte range. Each line belongs to the chunk that
  contains its first byte.
- **Visibility:** a chunk's output is published by atomic rename, then
  marked `done` in the manifest. Readers take files from the manifest,
  never from a glob.
- **Coordinator:** a single process with an `flock` run lock and bounded
  in-flight submission.
- **Worker crash:** suspect chunks are re-run alone.
- **Attempts:** charged only for real failures.
- **Per-file completion:** a file is completed only when its chunks'
  `bytes_read` sum to the file size.
- **Noise is flagged, never dropped:** all 16,988,823 rows are kept in
  `observations`. Columns were projected at ingest: no full banner, HTML,
  favicon image, CVE text or certificate chain is stored.

## 5. Commands (verified)

```bash
uv sync                                    # Python 3.12.13 venv (.venv/), orjson, pyarrow, duckdb, pytest
uv run pytest                              # 73 tests, ~36–40 s
uv run pytest -m "not slow"                # skip tests/test_memory.py

# Global options go BEFORE the subcommand. --workdir defaults to $FIRMABLE_WORKDIR or ~/firmable-work
uv run firmable --workdir ~/firmable-work status
uv run firmable register PATH --snapshot 2026-11-07   # full-file SHA-256 (~5 min for 137 GB)
uv run firmable run --workers 6                       # exit 1 if any chunk exhausted retries
uv run firmable retry FILE_ID                         # failed chunks get a fresh attempt budget
uv run firmable replay FILE_ID                        # reprocess all chunks (normalizer change)
uv run firmable build-services 2026-11-07             # observation_flags + services (default memory_limit 4GB)
uv run firmable seal 2026-11-07
uv run firmable evidence OBSERVATION_ID               # re-read source bytes, verify sha256, print record

uv run python scripts/compare_with_slim.py --snapshot 2026-11-07          # ~17 s
uv run python scripts/benchmark_ingest.py --workers 1 2 4 --chunks-per-worker 2 --chunk-mb 256
```

The full-data services build was run through Python with
`build_services(Pipeline('~/firmable-work'), '2026-11-07', memory_limit='6GB')`.
The `build-services` CLI uses the 4 GB default and has only been run on
test fixtures.

**Do not re-run ingestion of the 137 GB file.** The data is already
registered and completed. Re-registering the same bytes yields
`duplicate`; a replay would cost about 9 minutes of 6 cores.

## 6. Measured results (full file, i7-9750H 6C/12T, 16 GiB; see `docs/ingestion-benchmark.md`)

| Step | Wall | Throughput | Memory |
|---|---|---|---|
| register (SHA-256) | 311 s | 420 MiB/s | 59 MiB |
| run, 6 workers, 511 chunks | 516 s | 254 MiB/s; 32,955 rows/s; 42.5 MiB/s per worker-second | 249 MiB peak per worker process |
| build services (flags + services) | 108 s | — | 5.7 GiB (DuckDB limit 6 GB) |

**Worker scaling:**

| Workers | Throughput |
|---|---|
| 1 | 62 MiB/s |
| 2 | 104 MiB/s |
| 4 | 173 MiB/s |
| 6 | 255 MiB/s |
| 8 | 240 MiB/s |

Throughput stops scaling at the physical core count.

**Accounting:**
- 16,988,823 lines became 16,988,823 rows: 0 quarantined, 0 blank,
  0 failed chunks.
- The chunks' bytes sum exactly to the file size.
- 451 rows were unicode-repaired. These are exactly the 451 lines the
  research parser dropped.
- `_shodan.id` has 0 duplicates across all rows.
- 564 rows have the warning `protocol_json:oversized`.
- 120 distinct unknown top-level keys were found.

**Classification and services:**

| Measure | Count |
|---|---|
| empty banner | 9,668,102 |
| honeypot-tagged | 196,309 |
| fingerprint soup | 65,706 |
| eligible observations | 7,100,193 |
| **services** | **5,233,493** |
| … of which IPv6 | 173,618 |
| … with SNI | 802,565 |
| … with `is_cdn` | 1,648,005 |

**Comparison with the research slim Parquet:** every delta is reconciled.
Eligible observations are +397, which is +451 recovered rows minus 54
whitespace-only banners.

## 7. Schemas

**`observations`** is defined in `src/firmable/ingest/schema.py`
(`OBSERVATION_SCHEMA`, 80 columns). The column groups are:

- **Provenance:** `file_id`, `snapshot_id`, `chunk_index`, `byte_offset`,
  `byte_length`, `record_sha256`, `normalizer_version`.
- **Identity:** `observation_id`, `service_id`, `ip`, `ip_version`,
  `port`, `transport`, `sni`, `observed_at`.
- **Scanner metadata:** `shodan_id`, `banner_hash`, `crawler`, `module`.
- **Network:** `org`, `isp`, `asn`, `country_code`, `city`,
  `cloud_provider`/`service`/`region`.
- **Fingerprint (scanner-asserted):** `product`, `version`, `os`,
  `devicetype`, `info`, `cpe23[]`, `tags[]`, `hostnames[]`, `domains[]`.
- **Banner:** `banner_len` (length after stripping *all* whitespace),
  `banner_head` (first 160 chars).
- **HTTP:** `http_status`, `http_title` (≤200 chars), `http_server`,
  `http_host`, `http_waf`, `http_html_hash`, `favicon_hash`,
  `has_securitytxt`, `has_hsts`, `has_csp`, `x_powered_by`,
  `www_authenticate`, `http_components[]` (component names only, sorted).
- **TLS:**
  - flags: `has_ssl`, `ssl_versions[]` (a `-` prefix means *disabled*;
    match entries exactly)
  - expiry and dates: `cert_expired`, `cert_expires`, `cert_issued`
  - names: `cert_subject_cn`/`_o`, `cert_issuer_cn`/`_o`, `cert_san_dns[]`
    (parsed from DER)
  - key and signature: `cert_sig_alg`, `cert_key_type` (`dsa` is ECDSA in
    this feed), `cert_key_bits`
  - identity and trust: `cert_sha256`, `cert_trust_mozilla` (NULL means
    not evaluated), `jarm`
- **Other protocols:**
  - `ssh_hassh`
  - NTLM: `ntlm_dns_domain`, `ntlm_netbios_domain`, `ntlm_fqdn`,
    `ntlm_os_build`
  - `protocol_json`: sorted-key JSON of the small protocol objects
    (`isakmp`, `rdp_encryption`, `vnc`, `snmp`, `hp_ilo`, `fortinet`,
    `mikrotik_*`, …) **plus any unknown top-level key** (e.g. `redis`,
    `smb`, `cisco_anyconnect`, `sonicwall`). It is NULL if over 64 KiB.
- **Vulns (inferred, unverified):**
  `vulns: list<struct<cve, cvss, kev, verified, epss, ransomware_known>>`,
  `any_kev`, `any_verified`.
- **Quality:** `unicode_repaired`, `parse_warnings[]`, `unknown_keys[]`.

**`observation_flags`** (one row per distinct observation):
- Keys: `observation_id`, `service_id`, `snapshot_id`, `file_id`,
  `byte_offset`, `observed_at`.
- Flags: `is_empty`, `is_honeypot_tagged`, `is_fp_soup`, `is_cdn`,
  `eligible`, `classifier_version`.
- Exactly these 12 columns, enforced by
  `test_layer_schemas_are_exact_with_no_leaked_partition_columns`.

**`services`** (one row per `(snapshot, service_id)`, sorted by
`service_id`):
- every observation column of the latest eligible observation;
- `is_empty`, `is_honeypot_tagged`, `is_fp_soup`, `is_cdn`;
- `n_observations`, `n_eligible_observations` (both BIGINT), `first_seen`,
  `last_seen`;
- `classifier_version`, `services_version`.

That is 89 columns, exactly; the same test enforces it.
`sum(n_eligible_observations)` = 7,100,193, which equals the eligible
observation count.

**Manifest** (`~/firmable-work/manifest.sqlite`): the DDL is in
`src/firmable/ingest/manifest.py`. It holds one file
(`10cf8b1df608e34482bf4c76cd9d32bdf22d7271d61277fd5064c08152be4b33`,
status `completed`), one finished run and snapshot `2026-11-07` (`sealed`).

## 8. Physical locations (outside Git)

| What | Path | Size |
|---|---|---|
| Raw source (read-only; needed for evidence) | `~/Downloads/firmable_dataset` | 137,113,095,904 B |
| Manifest | `~/firmable-work/manifest.sqlite` | 448 KB |
| Observations (511 files) | `~/firmable-work/lake/observations/normalizer=v1/snapshot=2026-11-07/file=10cf8b1df608e344/chunk-00000..00510.parquet` | 3.2 GB |
| Quarantine (all empty) | `~/firmable-work/lake/quarantine/normalizer=v1/snapshot=2026-11-07/file=10cf8b1df608e344/` | — |
| Observation flags | `~/firmable-work/lake/observation_flags/classifier=v1/normalizer=v1/snapshot=2026-11-07/flags.parquet` | 752 MB |
| **Services (Phase 3 input)** | `~/firmable-work/lake/services/services=v1/normalizer=v1/snapshot=2026-11-07/services.parquet` | 1.2 GB |
| Frozen research slim Parquet (oracle) | `~/firmable-work/legacy/full_slim_v2.parquet` | 0.86 GB |
| Research random-offset sample (raw, 19,606 lines) | `~/firmable-work/legacy/offset_sample.jsonl` | 307 MB |
| Full-run logs | `~/firmable-work/logs/full-run.{out,err}` | — |
| Run lock (normal, empty) | `~/firmable-work/run.lock` | 0 B |
| Raw samples (gitignored, contain real IPs) | repo root `sample.jsonl`, `distributed_sample.jsonl` | 53 MB / 19 MB |

## 9. How Phase 3 should read data (do not touch the 137 GB file)

- **Signals and attribution start from `services.parquet`.** It already
  holds the latest *eligible* observation per service, with every column
  the research rules need.
- **Read it with Hive partitioning disabled.** The files themselves are
  clean, but the directory names are `key=value`, so DuckDB's default
  auto-detection would add `services`/`normalizer`/`snapshot` columns at
  read time:
  ```sql
  SELECT * FROM read_parquet('~/firmable-work/lake/services/services=v1/normalizer=v1/snapshot=2026-11-07/services.parquet',
                             hive_partitioning = false)
  ```
- **In Python,** derive the path with
  `firmable.transform.services.services_path(Pipeline('~/firmable-work'), '2026-11-07')`.
- **Snapshot-wide aggregates** that are not limited to eligible services,
  such as the research `infra_domains` (≥1,000 IPs, computed over **all**
  observations' hostnames) or the per-org CDN/cloud share:
  - Read the observation files listed by
    `Pipeline(...).committed_observation_files('2026-11-07')`, never a
    glob, and project only the needed columns.
  - Projected scans of the 3 GB take seconds in DuckDB.
  - Join to `observation_flags` on `observation_id` for eligibility.
- **Memory:** set DuckDB `memory_limit` (4–6 GB) and `temp_directory`.
  The machine has 16 GiB.

## 10. Identity, snapshots, provenance, evidence

- **`service_id`:** `sha256(f"{ip}|{port}|{transport}|{sni}").hexdigest()[:32]`
  (`normalize.py:service_id`).
  - `ip` is canonical: compressed IPv6, with IPv4-mapped IPv6 folded to
    IPv4.
  - `transport` is lower-case `tcp`/`udp`.
  - `sni` is `_shodan.options.hostname`, lower-cased, trailing dot
    stripped, or `''` when absent.
  - Two virtual hosts on one IP are two services.
  - Test oracle: `192.0.2.1|443|tcp|` → `823196974f91caafef5719c2af183b83`.
- **`observation_id`:** `_shodan.id`, which is unique on the full file.
  The fallback is `"c:" + sha256(ip|port|transport|sni|observed_at|banner_hash)[:32]`.
  A **Duplicate Observation** has the same `observation_id`. A **Repeat
  Observation** is the same service observed again; it is not a
  duplicate.
- **Snapshots:** each file has exactly one snapshot, set at first
  registration. A redelivery of the same bytes under another snapshot is
  recorded as a duplicate delivery and the file does not move. Services
  are computed per snapshot. `seal` requires every file in the snapshot
  to be completed and refuses unknown ids. Registering a new file into a
  sealed snapshot reopens it.
- **Timestamps:** `observed_at` is the scanner timestamp, assumed UTC and
  stored naive. The dataset is **one crawl**
  (2026-11-07 10:24–15:06 UTC). No change-over-time claims are possible.
- **Evidence:**
  - Every observation, and therefore every service row, carries
    `file_id`, `byte_offset`, `byte_length` and `record_sha256`.
  - `Pipeline.evidence(observation_id)` and the CLI `evidence` re-read
    those bytes from the path stored in the manifest and verify the
    SHA-256, raising `hash mismatch` if the source changed.
  - Measured: 0.9 s for one lookup, because it scans `observation_id`
    across 511 files.
  - For an API, use the service row's own
    `(file_id, byte_offset, byte_length, record_sha256)` and read the bytes
    directly; no observation scan is needed.

## 11. Reusable logic (exists today)

| Need | Where | Notes |
|---|---|---|
| Noise flags | `src/firmable/transform/services.py` `FLAGS_SQL`, `ELIGIBLE_SQL` | Classifier v1; same rule as research §4, except for whitespace-only banners |
| Org normalization | `sql/exploration.sql:259` `norm_org` | Lower-cases, strips punctuation and legal suffixes |
| Provider/platform org name heuristic | `sql/exploration.sql:267` `is_provider_org` | Known to miss ISPs (BIGLOBE, MTN, "IP pools") |
| PTR-style hostname detection | `sql/exploration.sql:271` `is_ptr_like` | |
| Non-company names (`.local`, vendor default CNs, dynamic DNS) | `sql/exploration.sql:277` `is_non_company_name` | |
| Registrable domain (approximate, no PSL) | `sql/exploration.sql:282` `reg_domain` | Wrong for `github.io`, `herokuapp.com`, … |
| Long-form domain evidence per source | `sql/exploration.sql:316` `domain_evidence` | **Source-specific rows:** `hostname`, `sni_scan`, `http_host`, `cert_cn`, `ntlm`. Add `cert_san` now that `cert_san_dns` exists |
| Infrastructure domains (≥1,000 IPs) | `sql/exploration.sql:332` `infra_domains` | Computed over all observations |
| Org profile / platform classification | `sql/exploration.sql:348` `org_profile` | >100 customer domains misclassifies UnitedHealth |
| Tier assignment A1/A2/B/C | `sql/exploration.sql:366` (`svc`) | v0; **uses `customer_domains[1]` downstream (line 541), which must not be ported** |
| Signal rules S01–S17 | `sql/exploration.sql:411–483` | S01 l.412, S03 l.420, S04 l.424, S05 l.430, S06 l.435, S16 l.478 |
| Compounds and account roll-up | `sql/exploration.sql:539–567` | Research only |

The research SQL column names map to v1 columns as follows:

| Research SQL | v1 |
|---|---|
| `scan_hostname` | `sni` (`''` instead of NULL) |
| `ipv6` | `ip` with `ip_version = 6` |
| `ts` | `observed_at` |
| `cc` | `country_code` |
| `vuln_ids` | `vulns[].cve` |
| `cvss_list` | `vulns[].cvss` |
| `p_l` | `lower(coalesce(product, ''))` |
| `t_l` | `lower(coalesce(http_title, ''))` |

`cert_trust_mozilla` is now BOOLEAN; it was VARCHAR in the research.

## 12. Data contracts Phase 3 must preserve

1. Never modify `observations`, `observation_flags` or `services` files in
   place. New logic writes a **new layer with its own version tag** (e.g.
   `lake/signal_hits/signals=…/normalizer=v1/snapshot=…/`) and records
   `signal_id`, `signal_version`, `service_id`, `snapshot_id`,
   `observation_id` and the evidence columns.
2. `service_id` and `observation_id` formulas are frozen. Changing them
   requires a normalizer version bump and a replay.
3. Every sales-facing claim must trace to `observation_id` and the
   provenance tuple, and use the wording in `research-findings.md` §3.
   Keep three things separate:
   - **observed fact** (signal hit)
   - **inferred risk** (registry text)
   - **hypothesis**
4. Attribution is inference. Keep **one row per (service, source, name)**
   with its filter outcome. Never pick `customer_domains[1]`. Allow
   abstention: tier C contributes to no account. Shared hosting with more
   than one unrelated domain must not receive infrastructure-exposure
   signals.
5. Readers obtain observation files from
   `Pipeline.committed_observation_files()`, not globs.
6. `scripts/compare_with_slim.py` must keep reconciling. If you change the
   classifier, record the new deltas in `docs/ingestion-benchmark.md`.
7. Raw data, Parquet and DuckDB files stay outside Git. Example IPs in
   docs are masked to /24. No records go to external LLM APIs.

## 13. Known defects, limitations, technical debt, open decisions

**Defects found at handoff, fixed on 2026-11-09:**
1. **Leaked Hive partition columns.** `file`, `normalizer` and `snapshot`
   (DATE) leaked into `services.parquet` and `flags.parquet`, because
   DuckDB auto-detects `key=value` directories.
   - Fixed: every `read_parquet` in `transform/services.py`,
     `Pipeline.evidence` and `scripts/compare_with_slim.py` now passes
     `hive_partitioning = false`.
   - **Readers outside these modules must do the same.**
2. **`n_eligible_observations` was DOUBLE.** It is now explicitly cast to
   BIGINT, and so is `n_observations`.
3. **Verification.**
   - Test `test_layer_schemas_are_exact_with_no_leaked_partition_columns`
     (red before the fix, green after).
   - Full services rebuild: 110 s, 6.1 GB peak RSS, counts identical.
   - The comparison with the slim Parquet is unchanged.
   - Evidence retrieval verified on an IPv6 service.
   - The snapshot was then sealed.

**Open defect:** the `build-services` CLI uses a 4 GB default
`memory_limit`. The full snapshot peaks at about 6 GB under a 6 GB limit
and has not been run with 4 GB. Run it through Python with
`memory_limit='6GB'`, or add a `--memory-limit` CLI flag.

**Limitations and technical debt:**
- **Hex identifiers take 52% of observation storage.** The fix is binary
  digests and not storing `shodan_id` twice; it needs normalizer v2.
- **`protocol_json` drops objects over 64 KiB** (564 rows, from
  `screenshot`/`html` blobs).
- **Empty-banner rule.** v1 strips all whitespace; the research `trim`
  strips only spaces. The difference is 7,002 rows, 54 of them eligible.
  This is intentional and documented.
- **`peak_rss_bytes`** per chunk is the worker process's lifetime
  high-water mark, so it is an upper bound.
- **Changed-source detection on first read.** The input digest catches a
  changed source only for chunks that have succeeded before. Evidence
  retrieval always verifies `record_sha256`.
- **No real database banner in the regression fixture.** S04 has no
  real-data regression example yet. `~/firmable-work/legacy/offset_sample.jsonl`
  can supply one: extend `scripts/make_regression_fixture.py` with a
  `--source` option.
- **Test hooks in production code.** The environment variables
  `FIRMABLE_TEST_FAIL_CHUNK`, `FIRMABLE_TEST_CRASH_CHUNK` and
  `FIRMABLE_TEST_CHUNK_DELAY` live in `ingest/worker.py`; they are
  env-gated and documented.
- **Designed but not built:** the Postgres manifest with leases,
  multi-host workers and object storage (`ingestion-architecture.md` §11).

**Open decisions for Phase 3:**
- **API storage.** Option A: ship the account and signal Parquet files and
  query them through embedded DuckDB in the API. Option B: load them into
  a hosted Postgres or MotherDuck if user writes (notes, feedback) are
  needed. Not decided.
- **Hosting target.** Not decided. The Vercel plugin is available in the
  environment; the DuckDB/Parquet size, about 1.2 GB for services, matters.
- **Provider classification.** The keyword regex should become a curated
  ASN/org-type table (research recommendation, `company-attribution.md` §4).
- **Public Suffix List** for `reg_domain`.
- **Sensitive signals.** S10 (NTLM), S11 (OT) and S12 (compromise) need
  a policy decision before use.

## 14. Research findings that constrain Phase 3

- **Most rows are not evidence.**
  - 57% of rows are empty banners.
  - Incapsula and Google together hold 56% of rows.
  - A module name is the probe that ran, not a detection.
  - A port alone never proves anything.
- **CDN edges describe the CDN, not the customer.** Exclude `is_cdn`
  rows from exposure and TLS signals (S01, S03, S04, S05, S06). S16
  technographics may use them.
- **`vulns` is version inference.** 99.99% `verified:false`. Use it only
  as an amplifier or timing trigger, never as "vulnerable".
- **TLS traps:**
  - `ssl_versions` uses `-TLSv1` to mean disabled, so match entries
    exactly.
  - `cert_key_type = 'dsa'` with 256/384 bits is ECDSA.
  - RDP certificates are self-signed by design, so exclude RDP from the
    self-signed rule.
  - `cert_trust_mozilla IS NULL` means not evaluated.
- **WAF block pages** ("Request Rejected", "Access denied") lack
  `http_waf`. Do not read them as "no WAF".
- **Attribution is the binding constraint.** Of the 5.23M eligible
  services:

  | Tier | Share |
  |---|---|
  | A1 | 11.9% |
  | A2 | 2.8% |
  | B | 22.3% |
  | C (unattributable) | 63.0% |

  - A1 still contains ISPs; treat its counts as upper bounds.
  - Tier-B evidence strength, strongest first:
    1. NTLM
    2. SNI and certificate CN agreeing
    3. non-wildcard certificate CN
    4. HTTP host or SNI alone
    5. hostname alone
  - Records with more than 3 unrelated domains mean shared hosting.
- **Prevalence of the first signals** (owned = A1+A2; research numbers):

  | Signal | Services | Owned services | Owned orgs | Tier-B domains |
  |---|---|---|---|---|
  | S01 | 26,700 | 8,285 | 3,393 | 2,417 |
  | S03 | 26,114 | 5,745 | 1,905 | — |
  | S04 | 9,930 | 1,628 | — | — |
  | S05 | 35,678 | 7,680 | — | — |
  | S06 | 217,036 | 48,898 | — | — |
  | S16 | 1,522,317 | 72,701 | — | 107,588 |

  S16 is the safest commercially, because it makes no security claim.
- **Same-service compounds are rare.** Only 30 IPs have S01 plus EOL/KEV
  on the same port.
- **No labels exist.** Precision and recall of signals and tiers are
  **unmeasured**. Do not invent evaluation results.

## 15. Recommended next steps

1. ~~Fix the services-schema defects and seal the snapshot.~~ Done on
   2026-11-09 (§13).
2. **Build the signal registry** in a new module, e.g.
   `src/firmable/signals/`. Each `Signal` entry carries:
   - id, version and family
   - a SQL predicate over `services`
   - evidence columns
   - observed-fact, inferred-risk and hypothesis text
   - allowed attribution tiers

   Port the six rules from `sql/exploration.sql` §6, with the v1 column
   mapping from §11:
   - **S01** (l.412): product/title regexes, `transport='tcp'`,
     `NOT is_cdn`. Also consider `cisco_anyconnect`/`sonicwall` keys in
     `protocol_json` (new evidence from v1).
   - **S03** (l.420): `module IN (rdp, telnet, x11, rlogin, nomachine)` or
     a product regex, `NOT is_cdn`.
   - **S04** (l.424): product regex, or a DB module whose banner is not
     HTTP, or the `database` tag, `NOT is_cdn`. `protocol_json` now holds
     `redis`, `mysqlx`, `influxdb` objects.
   - **S05** (l.430): management-plane regex over product and title, or
     the `devops` tag, `NOT is_cdn`.
   - **S06** (l.435): `has_ssl AND NOT is_cdn`, plus any of:
     - expired certificate
     - legacy protocol (exact list match)
     - RSA key under 2048 bits
     - SHA-1 or MD5 signature
     - self-signed outside RDP, HTTP only

     Keep the sub-flags as columns.
   - **S16** (l.478): `http_waf IS NOT NULL` or a security-appliance
     product regex. CDN rows are allowed.

   Write `signal_hits` Parquet under its own versioned path.
3. **TDD each rule.** Use synthetic positives, plus the research
   counterexamples from `signal-catalog.md`, plus the sanitized real
   fixture. Then run all six on full `services` and compare per-signal
   service counts with the research prevalence table. Explain any delta
   the way `ingestion-benchmark.md` §3 does.
4. **Attribution v1:**
   - Build `attribution_evidence` (service, source, name, reg_domain,
     filter outcome), adding `cert_san` as a source.
   - Build `service_attribution` (tier, account key, confidence, reasons;
     may abstain).
   - Port the v0 macros. Label the output experimental. Never use
     `customer_domains[1]`.
5. **Account roll-up and a deterministic, explainable score.**
   - Per account: signals, contributing services, evidence pointers,
     attribution confidence.
   - Severity and attribution confidence stay separate terms.
6. **Ranked-account API, then the hosted app**, reading precomputed
   account and signal tables, not the 137 GB file.

## 16. Verification Phase 3 must keep green

- **`uv run pytest`**: 73 tests across 7 files when this was written. On 2026-11-10,
  `uv run pytest -m "not slow"` gave 554 passed, 1 deselected (`docs/phase3-hardening-results.md`).

  | File | Covers |
  |---|---|
  | `test_normalize.py` | identity, IPv6/mapped, SNI/vhosts, rejection classes, surrogate repair, drift, range checks, SAN, vulns |
  | `test_chunks.py` | line ownership for chunk sizes 1…1000, oversized lines |
  | `test_pipeline.py` | accounting, provenance and evidence, quarantine, duplicate delivery, replay determinism, retry, worker crash, source change, stale normalizer, run lock, seal |
  | `test_recovery.py` | SIGKILL mid-run, four consecutive interruptions |
  | `test_services.py` | dedup, latest eligible observation, repeats across snapshots, noise flags, flags layer, exact layer schemas |
  | `test_memory.py` | `slow` marker; bounded RSS |
  | `test_real_regression.py` | 16 sanitized real banners end to end |

- **`uv run python scripts/compare_with_slim.py --snapshot 2026-11-07`**
  must still reconcile with `docs/ingestion-benchmark.md` §3.
- **For new code:**
  - TDD for rules, attribution and scoring.
  - Assert expected values from independent sources (catalog examples,
    hand-worked cases), never recomputed by the code under test.
  - Report only measured results.
- **Before claiming a milestone:**
  - Run the code-review skill (Standards + Spec) against the previous
    commit.
  - Update `docs/` with commands, verification output and known
    limitations.

## 17. Scoring v2 implementation (now the legacy score; see `docs/ranking-v3.md` for scoring v3)

**Formula** (`src/firmable/accounts/scoring.py`, `SCORING_VERSION = 2`; ADR 0006):

```
score = 100 × R × S × A × Q
R = 1 − Π_s (1 − RELEVANCE[s])           over the account's distinct counted signals (noisy-OR)
S = 0.5 + 0.5 · min(1, log2(n_ips) / 4)  n_ips = distinct IPs with counted evidence (1 → 0.5, 16+ → 1.0)
A = mean over counted services of the service's attribution confidence
Q = mean over counted services of the best BASIS_QUALITY of its matches
```

| Constant | Values |
|---|---|
| `RELEVANCE` | S01 0.80, S03 0.70, S04 0.65, S05 0.55, S06 0.20, S16 0.25 |
| `BASIS_QUALITY` | product 1.0, protocol 1.0, tls 0.9, waf 0.9, title 0.7, tag 0.5 (anything else 0.5) |
| Attribution confidence (`src/firmable/attribution/build.py`) | A1 0.9, A2 0.85, P 0.8. B = winning domain-rule score (NTLM-corroborated 1.0 … hostname only 0.25) × 0.85 for 2–3 candidate domains, × 0.6 for 4 or more. C = no account |

None of these values were fitted; no outcomes exist. The score is a relative priority, not a
probability.

**Roll-up** (`src/firmable/accounts/rollup.py`, `build_accounts`):

- Joins `signal_hits` to `service_attribution`. Tier C is dropped.
- Exposure-family hits count only where `allows_infra_signals` is true: A1, A2, P, or tier B with
  one strongly evidenced domain.
- Per service, only the highest-relevance exposure counts. Appliance-only S16 is suppressed when the
  same service is S01. Suppressed rows stay as evidence with `counted = false` and `suppressed_by`.
- `A` and `Q` are averaged per service, not per row.
- **Segments:** `net:` accounts form `network_provider`; everything else is `enterprise`.
- **Ranking:** per segment, by score desc, then counted IPs desc, then `account_id`.
- Each account stores its four components and a written explanation (`_explain`).

**Paths:**

| What | Where |
|---|---|
| Scoring, roll-up | `src/firmable/accounts/scoring.py`, `src/firmable/accounts/rollup.py` |
| Signals, attribution | `src/firmable/signals/registry.py`, `src/firmable/attribution/build.py` |
| API, page | `src/firmable/api/app.py`, `src/firmable/api/static/index.html` (list shows `fmt(score, 1)`) |
| Evaluation | `src/firmable/evaluation/review.py`, `src/firmable/evaluation/inspect.py` |
| Scoring tests | `tests/test_scoring.py`, `tests/test_accounts.py`, `tests/test_api_rollup.py` |
| Account tables | `~/firmable-work/lake/accounts/scoring=v2/attribution=v4/normalizer=v1/snapshot=2026-11-07/{accounts,account_signals,account_evidence}.parquet` (frozen v4 reproduction; current tables are `scoring=v3/attribution=v5`, see `attribution-implementation.md` §7) |
| Serving DBs | `~/firmable-work/serving/2026-11-07.duckdb`, `2026-11-07.public.duckdb` (deployed) |

**Rebuild after a scoring change:**
`uv run firmable build-phase3 2026-11-07 --steps accounts serving`. Then run
`uv run firmable publish-public 2026-11-07` and `scripts/stage_deploy.sh 2026-11-07` to redeploy.
Bump `SCORING_VERSION` for any formula or weight change, so outputs land under a new versioned path.

**Measured** (enterprise segment, 179,669 accounts; `docs/experiments/`):

- median score 7.2, p99 44.6, max 86.4;
- one product-identified S01 on one A1 IP scores 36.0, which is the top 1.55%;
- the top 1,000 is 665 A1, 301 A2 and 34 tier-B accounts.

## 18. Recommended changes (from `docs/experiments/`, 2026-11-11)

**Status 2026-11-11:** items 2–5 are implemented as scoring v3 and eligibility v1 (`docs/ranking-v3.md`,
ADR 0009). Items 1 and 6–9 remain open; item 1 (human labels) is still the gate for any precision claim.

Ordered by value for effort. Each changes scoring or evaluation, so it needs
a spec with acceptance criteria, TDD, a new `SCORING_VERSION` and a review (CLAUDE.md workflow).

1. **Get human labels before tuning anything** (exp 04). Fill the `manual_*` columns of the 104-case
   review set. Add a random stratum from below the top k so recall errors become visible. WHOIS/RDAP
   and CT cannot replace this: A1 and A2 rest only on the registry org, and about 60% of tier B on
   certificates that CT also logs.
2. **Stop pool and customer labels from ranking** (exp 02, 06).
   - 642 enterprise accounts have pool or customer names. Their median rank equals that of
     banks and health organisations, 4 are in the top 100, and 8.7% would fall in a top-1% band.
   - Add a regression test that counts them in the top 100, then fix them in attribution
     (`providers.py` / OpenASN rules), not in the scorer.
3. **Separate the reason to act from the reason to trust** (exp 05).
   - Attribution is the largest driver of rank (log-variance 0.101 against relevance 0.071; rank
     correlation 0.75). It also locks tier-B, mostly cloud-hosted, accounts out of the top 1,000.
   - Rank on R × S (× Q). Show attribution as the existing `confidence_band`, plus a
     minimum-confidence gate for outreach.
4. **Show bands and percentiles within a peer group instead of `score` with decimals** (exp 06).
   - 23,353 accounts tie at 5.85.
   - A score of 30 is at the 99.6th percentile for domain accounts but the 73rd for A1 orgs.
   - Cut bands only after step 2. Label them "relative priority in this snapshot". Industry and size
     peer groups need Firmable's company index.
5. **Report ranking stability in evaluation** (exp 02). Under ±50% weight changes the top 40 keeps
   only 0.61 overlap on average (0.68 under a bootstrap); the top 1,000 keeps 0.81–0.85. Add these
   overlaps to `review-metrics` output, and do not present order within the top 40 as meaningful.
6. **Keep the weight structure; do not adopt the rejected options** (exp 02, 03).
   - Rarity weights would make S04 the strongest signal and S01 the weakest exposure.
   - Per-service KEV/EPSS weights would rank S06 (11.8% KEV-flagged) above S01 (0.6%), because edge
     devices hide versions.
   - Dollar-risk figures break the wording rules in `docs/research-findings.md` §3.
   - If weights are re-grounded, use cited class-level breach statistics and keep them labelled as
     hypotheses.
7. **Attribution fill for cloud-hosted firms** (exp 01, 04). Of 67,248 abstained exposure services,
   only 9.6% carry a domain-like name.
   - Use a forward-DNS check at scan time, the organisation field of OV/EV certificates, and
     Firmable's company/domain index.
   - Do not use WHOIS, passive DNS on cloud IPs (risk of naming an earlier tenant) or an LLM.
8. **Version proxy for edge devices** (exp 01). S01 shows a version on only 4.5% of services, but
   FortiGate login pages fall into 179 HTML hashes over 3,948 services. A cited hash-to-firmware
   reference table would allow version-range claims, worded as an inference.
9. **Size normalization** (exp 02, 06): blocked on firmographics. Until then, breadth saturating at 16
   IPs is the only size control.
