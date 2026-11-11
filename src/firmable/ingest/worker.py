"""Process one chunk: read owned lines, normalize, write Parquet + quarantine atomically.

Runs in a worker process. Pure with respect to the manifest: it returns a
result dict and the coordinator records it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import resource
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson
import pyarrow as pa
import pyarrow.parquet as pq

from .chunks import OVERSIZED, iter_chunk_lines
from .normalize import NORMALIZER_VERSION, Rejection, normalize_line
from .schema import NORMALIZED_COLUMNS, OBSERVATION_SCHEMA

QUARANTINE_RAW_PREFIX_BYTES = 65536


@dataclass(frozen=True)
class ChunkTask:
    file_id: str
    snapshot_id: str
    source_path: str
    chunk_index: int
    start: int
    end: int
    output_path: str
    quarantine_path: str
    tmp_dir: str
    batch_rows: int
    max_line_bytes: int
    expected_input_digest: str | None = None  # digest from the last successful read, if any


class SourceChanged(RuntimeError):
    """The chunk's source bytes differ from the last successful read; nothing is overwritten."""


def _peak_rss_bytes() -> int:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024  # macOS reports bytes, Linux KiB


def _to_table(rows: list[dict[str, Any]], provenance: dict[str, list[Any]]) -> pa.Table:
    columns = dict(provenance)
    for name in NORMALIZED_COLUMNS:
        columns[name] = [r[name] for r in rows]
    return pa.Table.from_pydict(columns, schema=OBSERVATION_SCHEMA)


def process_chunk(task: ChunkTask) -> dict[str, Any]:
    started = time.perf_counter()
    fail = os.environ.get("FIRMABLE_TEST_FAIL_CHUNK")  # test hook: fault injection
    if fail is not None and int(fail) == task.chunk_index:
        raise RuntimeError(f"injected failure in chunk {task.chunk_index}")
    crash = os.environ.get("FIRMABLE_TEST_CRASH_CHUNK")  # test hook: simulate an OOM-killed worker
    if crash is not None and int(crash) == task.chunk_index:
        os._exit(137)
    delay = os.environ.get("FIRMABLE_TEST_CHUNK_DELAY")  # test hook: widen the crash window
    if delay:
        time.sleep(float(delay))

    tmp_dir = Path(task.tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_parquet = tmp_dir / f"{task.file_id[:16]}-{task.chunk_index:05d}.parquet"
    tmp_quarantine = tmp_dir / f"{task.file_id[:16]}-{task.chunk_index:05d}.jsonl"

    lines = blank = rows_written = repaired = bytes_read = 0
    quarantined: Counter[str] = Counter()
    warnings: Counter[str] = Counter()
    unknown: Counter[str] = Counter()
    digest = hashlib.sha256()
    batch: list[dict[str, Any]] = []
    prov: dict[str, list[Any]] = {k: [] for k in ("byte_offset", "byte_length", "record_sha256")}

    def quarantine(offset: int, length: int, error_class: str, message: str, raw: bytes) -> None:
        quarantined[error_class] += 1
        qf.write(
            orjson.dumps(
                {
                    "file_id": task.file_id,
                    "chunk_index": task.chunk_index,
                    "byte_offset": offset,
                    "byte_length": length,
                    "error_class": error_class,
                    "message": message,
                    "raw_prefix_b64": base64.b64encode(raw[:QUARANTINE_RAW_PREFIX_BYTES]).decode(),
                }
            )
            + b"\n"
        )

    def provenance(rows: list[int]) -> dict[str, list[Any]]:
        n = len(rows)
        return {
            "file_id": [task.file_id] * n,
            "snapshot_id": [task.snapshot_id] * n,
            "chunk_index": [task.chunk_index] * n,
            **{k: [v[i] for i in rows] for k, v in prov.items()},
            "normalizer_version": [NORMALIZER_VERSION] * n,
        }

    def flush() -> None:
        nonlocal rows_written
        if not batch:
            return
        try:
            table = _to_table(batch, provenance(list(range(len(batch)))))
        except (pa.ArrowInvalid, pa.ArrowTypeError, OverflowError):
            # A value the normalizer accepted does not fit the schema: isolate and quarantine that row only.
            good = []
            for i, row in enumerate(batch):
                try:
                    _to_table([row], provenance([i]))
                    good.append(i)
                except (pa.ArrowInvalid, pa.ArrowTypeError, OverflowError) as exc:
                    quarantine(prov["byte_offset"][i], prov["byte_length"][i], "schema_mismatch", str(exc)[:200], b"")
            table = _to_table([batch[i] for i in good], provenance(good))
        writer.write_table(table)
        rows_written += table.num_rows
        batch.clear()
        for v in prov.values():
            v.clear()

    with (
        pq.ParquetWriter(tmp_parquet, OBSERVATION_SCHEMA, compression="zstd") as writer,
        open(tmp_quarantine, "wb") as qf,
    ):
        for offset, raw, length in iter_chunk_lines(task.source_path, task.start, task.end, task.max_line_bytes):
            lines += 1
            bytes_read += length
            if raw is OVERSIZED:
                result: dict[str, Any] | Rejection = Rejection("oversized", f"{length} bytes")
                record_digest = None
            elif not raw.strip():
                blank += 1
                digest.update(f"{offset}:{length}:blank\n".encode())
                continue
            else:
                record_digest = hashlib.sha256(raw).hexdigest()
                result = normalize_line(raw)
            digest.update(f"{offset}:{length}:{record_digest}\n".encode())

            if isinstance(result, Rejection):
                quarantine(offset, length, result.error_class, result.message, raw)
                continue

            warnings.update(w.split(":", 1)[0] for w in result["parse_warnings"])
            unknown.update(result["unknown_keys"])
            repaired += result["unicode_repaired"]
            batch.append(result)
            prov["byte_offset"].append(offset)
            prov["byte_length"].append(length)
            prov["record_sha256"].append(record_digest)
            if len(batch) >= task.batch_rows:
                flush()
        flush()

    n_quarantined = sum(quarantined.values())
    if lines != rows_written + n_quarantined + blank:
        raise RuntimeError(f"accounting violated: {lines} != {rows_written}+{n_quarantined}+{blank}")

    input_digest = digest.hexdigest()
    if task.expected_input_digest and task.expected_input_digest != input_digest:
        tmp_parquet.unlink(missing_ok=True)
        tmp_quarantine.unlink(missing_ok=True)
        raise SourceChanged(f"source bytes changed since the last successful read of chunk {task.chunk_index}")

    for tmp, final in ((tmp_parquet, task.output_path), (tmp_quarantine, task.quarantine_path)):
        Path(final).parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, final)  # atomic within one filesystem

    return {
        "chunk_index": task.chunk_index,
        "lines": lines,
        "rows": rows_written,
        "blank": blank,
        "quarantined": n_quarantined,
        "quarantined_by_class": dict(quarantined),
        "warnings": sum(warnings.values()),
        "warnings_by_field": dict(warnings),
        "unknown_keys": dict(unknown),
        "unicode_repaired": repaired,
        "bytes_read": bytes_read,
        "input_digest": input_digest,
        "wall_seconds": time.perf_counter() - started,
        "peak_rss_bytes": _peak_rss_bytes(),
        "normalizer_version": NORMALIZER_VERSION,
    }
