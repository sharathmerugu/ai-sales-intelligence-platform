"""Benchmark the ingestion worker on byte ranges of the real source file.

Runs `process_chunk` (the production worker) over disjoint chunks spread
evenly across the file, for each worker count. The source is read in place;
outputs go to a scratch lake under --out and are deleted afterwards.

    uv run python scripts/benchmark_ingest.py --workers 1 2 4 --chunks-per-worker 2 --chunk-mb 256
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from firmable.ingest.chunks import plan_chunks
from firmable.ingest.worker import ChunkTask, process_chunk

MIB = 2**20


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(Path.home() / "Downloads/firmable_dataset"))
    ap.add_argument("--out", default=str(Path.home() / "firmable-work/bench"))
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4])
    ap.add_argument("--chunks-per-worker", type=int, default=2)
    ap.add_argument("--chunk-mb", type=int, default=256)
    ap.add_argument("--batch-rows", type=int, default=20_000)
    args = ap.parse_args()

    src = Path(args.source)
    all_chunks = plan_chunks(src.stat().st_size, args.chunk_mb * MIB)
    needed = sum(w * args.chunks_per_worker for w in args.workers)
    stride = max(1, len(all_chunks) // needed)
    pool_of_chunks = all_chunks[::stride]  # spread across the file (it is time-ordered)
    out = Path(args.out)
    results = []
    cursor = 0
    for w in args.workers:
        n = w * args.chunks_per_worker
        chunks = pool_of_chunks[cursor : cursor + n]
        cursor += n
        lake = out / f"w{w}"
        tasks = [
            ChunkTask("bench" + "0" * 59, "bench", str(src), c.index, c.start, c.end,
                      str(lake / f"chunk-{c.index:05d}.parquet"), str(lake / f"chunk-{c.index:05d}.jsonl"),
                      str(lake / "_tmp"), args.batch_rows, 32 * MIB)
            for c in chunks
        ]
        t0 = time.perf_counter()
        with ProcessPoolExecutor(max_workers=w) as pool:
            per_chunk = list(pool.map(process_chunk, tasks))
        wall = time.perf_counter() - t0
        nbytes = sum(r["bytes_read"] for r in per_chunk)
        rows = sum(r["rows"] for r in per_chunk)
        out_bytes = sum(Path(t.output_path).stat().st_size for t in tasks)
        res = {
            "workers": w,
            "chunks": len(chunks),
            "chunk_indexes": [c.index for c in chunks],
            "input_gib": round(nbytes / 2**30, 2),
            "rows": rows,
            "quarantined": sum(r["quarantined"] for r in per_chunk),
            "unicode_repaired": sum(r["unicode_repaired"] for r in per_chunk),
            "wall_s": round(wall, 1),
            "aggregate_mib_s": round(nbytes / MIB / wall, 1),
            "aggregate_rows_s": round(rows / wall),
            "per_worker_mib_s": round(nbytes / MIB / wall / w, 1),
            "chunk_mib_s_min_max": [round(min(r["bytes_read"] / MIB / r["wall_seconds"] for r in per_chunk), 1),
                                    round(max(r["bytes_read"] / MIB / r["wall_seconds"] for r in per_chunk), 1)],
            "peak_rss_mib_max": round(max(r["peak_rss_bytes"] for r in per_chunk) / MIB),
            "output_mib": round(out_bytes / MIB, 1),
            "compression_ratio": round(nbytes / max(out_bytes, 1), 1),
        }
        results.append(res)
        print(json.dumps(res), flush=True)
        shutil.rmtree(lake, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps({"args": vars(args), "results": results}, indent=2))


if __name__ == "__main__":
    main()
