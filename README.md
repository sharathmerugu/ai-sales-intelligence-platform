# Firmable — cybersecurity sales intelligence

**Start here:** [`WRITEUP.md`](WRITEUP.md) (approach, key decisions, how it was measured). Live app:
<https://firmable-api-production.up.railway.app>.

> **Public snapshot.** This repository is a single-commit snapshot of the project's private
> development history. Commit hashes cited in the docs (for example the deployed commit) refer to
> that history. For the public copy, named organisations in exposure examples, internal NTLM
> names and example IPs (already masked to /24) are redacted. Code, tests, rules and aggregate
> measurements are unchanged. Raw scan data, holdout files and the serving database are not
> included. Submission summary: `docs/SUBMISSION.md`.

Evidence-backed cybersecurity buying signals from internet-scan data.
Research: `docs/research-findings.md`. Ingestion design:
`docs/ingestion-architecture.md`. Benchmarks: `docs/ingestion-benchmark.md`.

## Setup

```bash
uv sync                      # Python 3.12 venv with orjson, pyarrow, duckdb, pytest
uv run pytest                # full suite (~25 s; includes a SIGKILL recovery and a memory test)
uv run pytest -m "not slow"  # skip the memory test
```

Working data lives outside Git in `~/firmable-work/`. Override it with
`--workdir` or `FIRMABLE_WORKDIR`:

```
~/firmable-work/
  manifest.sqlite                      # files, deliveries, chunks, snapshots, runs
  lake/observations/normalizer=v1/snapshot=<id>/file=<id16>/chunk-NNNNN.parquet
  lake/quarantine/normalizer=v1/snapshot=<id>/file=<id16>/chunk-NNNNN.jsonl
  lake/services/services=v1/normalizer=v1/snapshot=<id>/services.parquet
  legacy/full_slim_v2.parquet          # frozen research output (regression oracle)
```

## Ingest a file

```bash
uv run firmable register ~/Downloads/firmable_dataset --snapshot 2026-11-07
uv run firmable run --workers 6
uv run firmable status
uv run firmable build-services 2026-11-07
uv run firmable seal 2026-11-07
```

- `register` computes the full-file SHA-256, which becomes the `file_id`, and
  plans 256 MB chunks. It reads the source in place and never copies it.
  Registering the same bytes again, at any path, records a `duplicate`
  delivery and schedules no work.
- `run` processes pending and failed chunks. Each chunk writes its Parquet and
  quarantine files to `_tmp/`, then renames them atomically, then is marked
  `done`.
- Logs are JSON lines on stderr. Per-chunk metrics (lines, rows, quarantined
  by class, warnings, unknown keys, MiB/s, peak RSS) are kept in the
  manifest, and `status` sums them.
- Accounting invariant per chunk: `lines = rows + quarantined + blank`.

Use 6 workers on the 6-core development laptop. Scaling stops at the
physical core count; see `docs/ingestion-benchmark.md`.

## Look up the evidence for an observation

```bash
uv run firmable evidence <observation_id>
```

This re-reads the exact byte range from the source file, verifies its SHA-256
against `record_sha256`, and prints the original record. If the source was
modified or moved, the command fails with `hash mismatch` instead of showing
the wrong evidence.

## Recover from failures

| Situation | What happens | What to do |
|---|---|---|
| Coordinator killed (Ctrl-C, OOM, reboot) | Chunks left `running` and orphaned `_tmp/` files are reset at the next `run`. Committed chunks are kept. | `firmable run` |
| Chunk raised an error | Retried up to `--max-attempts` (default 3) in the same run, then marked `failed`. The file becomes `failed` and its observations are not readable. | Fix the cause, then `firmable retry <file_id>` and `firmable run` |
| Malformed or unusable line | Quarantined with offset, error class and up to 64 KB of raw bytes. The chunk still succeeds. | Inspect `lake/quarantine/...` |
| Source bytes changed after a successful read | The re-read chunk fails with `source bytes changed`, and `evidence` reports a hash mismatch. | Treat it as a new delivery: `register` the new file |
| Same file delivered twice | `register` returns `outcome: duplicate`. | Nothing |

## Replay a file

```bash
uv run firmable replay <file_id>   # reset every chunk to pending
uv run firmable run --workers 6
```

Output paths are a function of `(normalizer version, snapshot, file_id,
chunk)`, and rows depend only on the input bytes and the normalizer version.
A replay therefore overwrites the same files with identical rows; this is
tested. After a normalizer version bump, the new version writes into a new
`normalizer=vN` tree, and the old tree stays readable until it is deleted.

## Readers

Read observations through `Pipeline.committed_observation_files(snapshot)`,
never through a glob. It returns only chunks of *completed* files at the
current normalizer version.

## Phase 3: signals, attribution, accounts, API

```bash
uv run firmable build-phase3 2026-11-07 --memory-limit 6GB --threads 6   # ~3 min, sealed snapshot only
uv run firmable serve 2026-11-07 --port 8000                             # http://127.0.0.1:8000/
```

Contracts: `docs/phase3-plan.md`. Measurements and limitations: `docs/phase3-results.md`. API: `docs/api.md`.

## Hardening, deployment and evaluation

```bash
uv run firmable publish-public 2026-11-07            # sanitized serving DB for deployment (ADR 0007)
scripts/stage_deploy.sh 2026-11-07                   # private build context + `railway up`
uv run firmable review-set 2026-11-07                # stratified review CSV in ~/firmable-work/eval
uv run firmable review-metrics ~/firmable-work/eval/2026-11-07-review.csv
cd e2e && npm ci && FIRMABLE_URL=... FIRMABLE_USER=... FIRMABLE_PASSWORD=... npx playwright test
```

Network classification (OpenASN, segments): `docs/network-classification.md`, ADR 0008.
Deployment: `docs/deployment.md`. Evaluation rubric: `docs/evaluation.md`. Results:
`docs/phase3-hardening-results.md`.

## Scoring v3, attribution v5 and the evaluation holdout

```bash
uv run firmable build-phase3 2026-11-07 --steps attribution accounts serving   # attribution v5, scoring v3
uv run firmable holdout-set 2026-11-07          # deterministic holdout CSV + blind CSV in ~/firmable-work/eval
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv   # manual labels only
```

Ranking: `docs/ranking-v3.md`, ADR 0009. Attribution v5: `docs/attribution-implementation.md` §7.
Holdout: `docs/evaluation.md`. Prospecting modes: `docs/prospecting-modes.md`.
**Submission summary, verification and limitations: `docs/SUBMISSION.md`.**

## Research reproduction

See `CLAUDE.md` → "Running the research SQL". `sql/exploration.sql` is
unchanged by the pipeline.
