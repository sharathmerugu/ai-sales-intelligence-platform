"""Ingestion coordinator: register, run, retry, replay, seal, status, evidence.

Layout under ``workdir``::

    manifest.sqlite
    lake/observations/normalizer=v1/snapshot=<id>/file=<id16>/chunk-00042.parquet
    lake/quarantine/normalizer=v1/snapshot=<id>/file=<id16>/chunk-00042.jsonl
    lake/_tmp/<run_id>/...
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import shutil
import uuid
from collections import deque
from collections.abc import Iterator
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import orjson

from ..logs import log
from .chunks import plan_chunks
from .manifest import connect
from .normalize import NORMALIZER_VERSION
from .worker import ChunkTask, process_chunk

DEFAULT_CHUNK_BYTES = 256 * 1024 * 1024
DEFAULT_BATCH_ROWS = 20_000
DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024
HASH_READ_BYTES = 8 * 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(HASH_READ_BYTES):
            h.update(block)
    return h.hexdigest()


@dataclass(frozen=True)
class RegisterResult:
    file_id: str
    outcome: str  # new | duplicate
    chunks: int
    snapshot_id: str  # for a duplicate: the snapshot the bytes were first registered into


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    processed_chunks: int
    failed_chunks: int
    rows: int
    quarantined: int
    bytes_read: int
    wall_seconds: float


class Pipeline:
    def __init__(
        self,
        workdir: Path | str,
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
        batch_rows: int = DEFAULT_BATCH_ROWS,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        self.workdir = Path(workdir).expanduser()
        self.lake = self.workdir / "lake"
        self.chunk_bytes = chunk_bytes
        self.batch_rows = batch_rows
        self.max_line_bytes = max_line_bytes
        self.db = connect(self.workdir / "manifest.sqlite")

    # ------------------------------------------------------------------ paths
    def _partition(self, layer: str, snapshot_id: str, file_id: str) -> Path:
        return self.lake / layer / f"normalizer=v{NORMALIZER_VERSION}" / f"snapshot={snapshot_id}" / f"file={file_id[:16]}"

    def _output_paths(self, snapshot_id: str, file_id: str, chunk_index: int) -> tuple[Path, Path]:
        name = f"chunk-{chunk_index:05d}"
        return (
            self._partition("observations", snapshot_id, file_id) / f"{name}.parquet",
            self._partition("quarantine", snapshot_id, file_id) / f"{name}.jsonl",
        )

    # --------------------------------------------------------------- register
    def register(self, path: Path | str, snapshot_id: str | None = None) -> RegisterResult:
        """Hash the full file and plan its chunks. Re-delivered bytes keep their original snapshot."""
        path = Path(path).expanduser().resolve()
        requested = snapshot_id or datetime.now(UTC).date().isoformat()
        log("register.hashing", path=str(path), size_bytes=path.stat().st_size)
        file_id = sha256_file(path)
        size = path.stat().st_size
        db = self.db
        db.execute("BEGIN IMMEDIATE")
        try:
            existing = db.execute("SELECT snapshot_id FROM files WHERE file_id = ?", (file_id,)).fetchone()
            outcome = "duplicate" if existing else "new"
            snapshot = existing["snapshot_id"] if existing else requested
            if not existing:
                db.execute(
                    "INSERT INTO files (file_id, path, size_bytes, snapshot_id, chunk_bytes, status, registered_at)"
                    " VALUES (?, ?, ?, ?, ?, 'registered', ?)",
                    (file_id, str(path), size, snapshot, self.chunk_bytes, _now()),
                )
                db.executemany(
                    "INSERT INTO chunks (file_id, chunk_index, start_byte, end_byte, status) VALUES (?, ?, ?, ?, 'pending')",
                    [(file_id, c.index, c.start, c.end) for c in plan_chunks(size, self.chunk_bytes)],
                )
                db.execute(
                    "INSERT INTO snapshots (snapshot_id, status) VALUES (?, 'open')"
                    " ON CONFLICT(snapshot_id) DO UPDATE SET status = 'open', sealed_at = NULL",
                    (snapshot,),
                )
            db.execute(
                "INSERT INTO deliveries (path, file_id, snapshot_id, outcome, registered_at) VALUES (?, ?, ?, ?, ?)",
                (str(path), file_id, requested, outcome, _now()),
            )
            n_chunks = db.execute("SELECT count(*) FROM chunks WHERE file_id = ?", (file_id,)).fetchone()[0]
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        if existing and requested != snapshot:
            log("register.duplicate_other_snapshot", file_id=file_id, requested=requested, kept=snapshot)
        log("register.done", file_id=file_id, outcome=outcome, snapshot_id=snapshot, chunks=n_chunks)
        return RegisterResult(file_id, outcome, n_chunks, snapshot)

    # -------------------------------------------------------------------- run
    @contextmanager
    def run_lock(self) -> Iterator[None]:
        """Exclusive per-workdir lock: one coordinator at a time."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        with open(self.workdir / "run.lock", "w") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError(f"another run holds {self.workdir / 'run.lock'}") from None
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def run(self, workers: int = 2, max_attempts: int = 3, file_ids: list[str] | None = None) -> RunSummary:
        with self.run_lock():
            return self._run(workers, max_attempts, file_ids)

    def _run(self, workers: int, max_attempts: int, file_ids: list[str] | None) -> RunSummary:
        run_id = uuid.uuid4().hex[:12]
        started = datetime.now(UTC)
        db = self.db
        # A chunk left 'running' belongs to a dead coordinator. It never finished, so it is not charged an attempt.
        stale = db.execute("UPDATE chunks SET status = 'pending', run_id = NULL WHERE status = 'running'").rowcount
        shutil.rmtree(self.lake / "_tmp", ignore_errors=True)
        db.execute("INSERT INTO runs (run_id, started_at, workers, status) VALUES (?, ?, ?, 'running')",
                   (run_id, _now(), workers))
        log("run.start", run_id=run_id, workers=workers, recovered_stale_chunks=stale)

        where = "c.status IN ('pending', 'failed') AND c.attempts < ?"
        params: list[Any] = [max_attempts]
        if file_ids:
            where += f" AND c.file_id IN ({','.join('?' * len(file_ids))})"
            params += file_ids
        queue = deque(db.execute(
            f"SELECT c.*, f.path, f.snapshot_id FROM chunks c JOIN files f USING (file_id) WHERE {where}"
            " ORDER BY c.file_id, c.chunk_index",
            params,
        ).fetchall())
        for fid in {r["file_id"] for r in queue}:
            db.execute("UPDATE files SET status = 'processing' WHERE file_id = ?", (fid,))

        tally = {"processed": 0, "failed": 0, "rows": 0, "quarantined": 0, "bytes_read": 0}
        tmp_dir = self.lake / "_tmp" / run_id

        def task_for(r: Any) -> ChunkTask:
            out, qpath = self._output_paths(r["snapshot_id"], r["file_id"], r["chunk_index"])
            return ChunkTask(
                file_id=r["file_id"], snapshot_id=r["snapshot_id"], source_path=r["path"],
                chunk_index=r["chunk_index"], start=r["start_byte"], end=r["end_byte"],
                output_path=str(out), quarantine_path=str(qpath), tmp_dir=str(tmp_dir),
                batch_rows=self.batch_rows, max_line_bytes=self.max_line_bytes,
                expected_input_digest=r["input_digest"],
            )

        def mark_running(r: Any) -> None:
            db.execute("UPDATE chunks SET status = 'running', run_id = ? WHERE file_id = ? AND chunk_index = ?",
                       (run_id, r["file_id"], r["chunk_index"]))

        def record_failure(r: Any, exc: BaseException) -> bool:
            """Charge one attempt; return True if the chunk may be retried."""
            key = (r["file_id"], r["chunk_index"])
            err = f"{type(exc).__name__}: {exc}"[:500]
            db.execute("UPDATE chunks SET status = 'failed', attempts = attempts + 1, last_error = ?"
                       " WHERE file_id = ? AND chunk_index = ?", (err, *key))
            attempts = db.execute("SELECT attempts FROM chunks WHERE file_id = ? AND chunk_index = ?", key).fetchone()[0]
            log("chunk.failed", run_id=run_id, file_id=key[0][:16], chunk=key[1], attempts=attempts, error=err)
            if attempts < max_attempts:
                return True
            tally["failed"] += 1
            return False

        def record_success(r: Any, res: dict[str, Any]) -> None:
            key = (r["file_id"], r["chunk_index"])
            out, qpath = self._output_paths(r["snapshot_id"], *key)
            db.execute(
                """UPDATE chunks SET status = 'done', last_error = NULL, normalizer_version = ?,
                   output_path = ?, quarantine_path = ?, input_digest = ?, lines = ?, rows = ?, blank = ?,
                   quarantined = ?, quarantined_by_class = ?, warnings = ?, warnings_by_field = ?,
                   unknown_keys = ?, unicode_repaired = ?, bytes_read = ?, wall_seconds = ?, peak_rss_bytes = ?
                   WHERE file_id = ? AND chunk_index = ?""",
                (res["normalizer_version"], str(out), str(qpath), res["input_digest"], res["lines"],
                 res["rows"], res["blank"], res["quarantined"], orjson.dumps(res["quarantined_by_class"]).decode(),
                 res["warnings"], orjson.dumps(res["warnings_by_field"]).decode(),
                 orjson.dumps(res["unknown_keys"]).decode(), res["unicode_repaired"], res["bytes_read"],
                 res["wall_seconds"], res["peak_rss_bytes"], *key),
            )
            tally["processed"] += 1
            for k in ("rows", "quarantined", "bytes_read"):
                tally[k] += res[k]
            log("chunk.done", run_id=run_id, file_id=key[0][:16], chunk=key[1], rows=res["rows"],
                quarantined=res["quarantined"],
                mib_s=round(res["bytes_read"] / 2**20 / max(res["wall_seconds"], 1e-9), 1),
                worker_peak_rss_mib=round(res["peak_rss_bytes"] / 2**20))

        def run_isolated(r: Any) -> None:
            """After a worker died, run a suspect chunk alone so a crash is charged to the right chunk."""
            while True:
                mark_running(r)
                with ProcessPoolExecutor(max_workers=1) as solo:
                    try:
                        record_success(r, solo.submit(process_chunk, task_for(r)).result())
                        return
                    except Exception as exc:  # noqa: BLE001 - includes BrokenProcessPool
                        if not record_failure(r, exc):
                            return

        try:
            while queue:
                inflight: dict[Any, Any] = {}
                suspects: list[Any] = []
                with ProcessPoolExecutor(max_workers=workers) as pool:
                    # Bounded submission: at most `workers` chunks in flight, so a pool crash has few suspects.
                    while queue or inflight:
                        broken = False
                        while queue and len(inflight) < workers:
                            r = queue.popleft()
                            mark_running(r)
                            try:
                                inflight[pool.submit(process_chunk, task_for(r))] = r
                            except BrokenProcessPool:  # a worker died since the last wait(); r never ran
                                queue.appendleft(r)
                                broken = True
                                break
                        done, _ = wait(inflight, return_when=FIRST_COMPLETED) if not broken else (set(), set())
                        for fut in done:
                            r = inflight.pop(fut)
                            try:
                                record_success(r, fut.result())
                            except BrokenProcessPool:
                                broken = True
                                suspects.append(r)
                            except Exception as exc:  # noqa: BLE001 - every worker failure is recorded
                                if record_failure(r, exc):
                                    queue.append(r)
                        if broken:
                            suspects.extend(inflight.values())
                            inflight.clear()
                            log("run.worker_crashed", run_id=run_id, suspects=[s["chunk_index"] for s in suspects])
                            break
                for r in suspects:
                    run_isolated(r)
        except BaseException:
            db.execute("UPDATE runs SET status = 'interrupted', finished_at = ? WHERE run_id = ?", (_now(), run_id))
            raise
        finally:
            self._refresh_file_status()
            shutil.rmtree(tmp_dir, ignore_errors=True)

        wall = (datetime.now(UTC) - started).total_seconds()
        db.execute("UPDATE runs SET status = 'finished', finished_at = ? WHERE run_id = ?", (_now(), run_id))
        summary = RunSummary(run_id, tally["processed"], tally["failed"], tally["rows"], tally["quarantined"],
                             tally["bytes_read"], wall)
        log("run.finish", **summary.__dict__)
        return summary

    def _refresh_file_status(self) -> None:
        """completed = every chunk done at the current normalizer AND chunk bytes add up to the file size."""
        rows = self.db.execute(
            """SELECT f.file_id, f.size_bytes, f.status,
                      sum(c.status = 'done') AS done, count(*) AS chunks, sum(c.status = 'failed') AS failed,
                      coalesce(sum(CASE WHEN c.status = 'done' THEN c.bytes_read END), 0) AS bytes_read
               FROM files f JOIN chunks c USING (file_id)
               WHERE f.status IN ('processing', 'failed', 'registered') GROUP BY f.file_id"""
        ).fetchall()
        for r in rows:
            if r["done"] == r["chunks"]:
                if r["bytes_read"] != r["size_bytes"]:
                    status = "failed"
                    log("file.accounting_mismatch", file_id=r["file_id"], bytes_read=r["bytes_read"], size=r["size_bytes"])
                else:
                    status = "completed"
            elif r["failed"]:
                status = "failed"
            else:
                status = r["status"]
            self.db.execute(
                "UPDATE files SET status = ?, completed_at = CASE WHEN ? = 'completed' THEN coalesce(completed_at, ?) END"
                " WHERE file_id = ?",
                (status, status, _now(), r["file_id"]),
            )

    # ------------------------------------------------------ recovery commands
    def retry(self, file_id: str) -> int:
        """Give failed chunks of a file a fresh attempt budget."""
        n = self.db.execute(
            "UPDATE chunks SET status = 'pending', attempts = 0 WHERE file_id = ? AND status = 'failed'", (file_id,)
        ).rowcount
        log("retry", file_id=file_id, chunks=n)
        return n

    def replay(self, file_id: str) -> int:
        """Reprocess every chunk of a file (e.g. after a normalizer change). Outputs are overwritten in place."""
        n = self.db.execute(
            "UPDATE chunks SET status = 'pending', attempts = 0 WHERE file_id = ?", (file_id,)
        ).rowcount
        self.db.execute("UPDATE files SET status = 'registered', completed_at = NULL WHERE file_id = ?", (file_id,))
        log("replay", file_id=file_id, chunks=n)
        return n

    def seal(self, snapshot_id: str) -> None:
        if self.db.execute("SELECT 1 FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)).fetchone() is None:
            raise ValueError(f"unknown snapshot {snapshot_id}")
        incomplete = self.db.execute(
            "SELECT count(*) FROM files WHERE snapshot_id = ? AND status <> 'completed'", (snapshot_id,)
        ).fetchone()[0]
        if incomplete:
            raise ValueError(f"snapshot {snapshot_id}: {incomplete} file(s) not completed")
        self.db.execute("UPDATE snapshots SET status = 'sealed', sealed_at = ? WHERE snapshot_id = ?", (_now(), snapshot_id))
        log("seal", snapshot_id=snapshot_id)

    def chunk_states(self, file_id: str | None = None) -> dict[int, str]:
        file_id = file_id or self.db.execute("SELECT file_id FROM files ORDER BY registered_at LIMIT 1").fetchone()[0]
        return {r[0]: r[1] for r in self.db.execute(
            "SELECT chunk_index, status FROM chunks WHERE file_id = ? ORDER BY chunk_index", (file_id,))}

    # ---------------------------------------------------------------- readers
    def committed_observation_files(self, snapshot_id: str | None = None) -> list[Path]:
        """Observation Parquet files of *completed* files only. Readers must use this, never a glob."""
        sql = ("SELECT c.output_path FROM chunks c JOIN files f USING (file_id)"
               " WHERE f.status = 'completed' AND c.status = 'done' AND c.normalizer_version = ?")
        params: list[Any] = [NORMALIZER_VERSION]
        if snapshot_id:
            sql += " AND f.snapshot_id = ?"
            params.append(snapshot_id)
        return [Path(r[0]) for r in self.db.execute(sql + " ORDER BY c.file_id, c.chunk_index", params)]

    def quarantine_entries(self, file_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT quarantine_path FROM chunks WHERE status = 'done'"
        params: list[Any] = []
        if file_id:
            sql += " AND file_id = ?"
            params.append(file_id)
        out = []
        for (qpath,) in self.db.execute(sql, params):
            with open(qpath, "rb") as fh:
                for raw in fh:
                    e = orjson.loads(raw)
                    e["raw_prefix"] = base64.b64decode(e.pop("raw_prefix_b64"))
                    out.append(e)
        return out

    def evidence(self, observation_id: str) -> tuple[bytes, dict[str, Any]]:
        """Re-read the exact source bytes of an observation and verify their hash."""
        files = [str(p) for p in self.committed_observation_files()]
        if not files:
            raise KeyError(observation_id)
        with duckdb.connect() as con:
            hit = con.execute(
                "SELECT file_id, byte_offset, byte_length, record_sha256 FROM read_parquet(?, hive_partitioning = false) "
                "WHERE observation_id = ? ORDER BY file_id, byte_offset LIMIT 1",
                [files, observation_id],
            ).fetchone()
        if hit is None:
            raise KeyError(observation_id)
        file_id, offset, length, digest = hit
        raw = self.read_record(file_id, offset, length, digest, label=observation_id)
        (path,) = self.db.execute("SELECT path FROM files WHERE file_id = ?", (file_id,)).fetchone()
        return raw, {"file_id": file_id, "path": path, "byte_offset": offset, "byte_length": length, "record_sha256": digest}

    def read_record(self, file_id: str, byte_offset: int, byte_length: int, record_sha256: str,
                    label: str | None = None) -> bytes:
        """Exact source bytes at a known provenance tuple (one seek, no index scan), hash-verified."""
        (path,) = self.db.execute("SELECT path FROM files WHERE file_id = ?", (file_id,)).fetchone()
        with open(path, "rb") as fh:
            fh.seek(byte_offset)
            raw = fh.read(byte_length)
        if hashlib.sha256(raw).hexdigest() != record_sha256:
            raise ValueError(f"hash mismatch for {label or file_id + '@' + str(byte_offset)}: "
                             f"source {path} changed since ingestion")
        return raw

    def status(self) -> dict[str, Any]:
        files = []
        for f in self.db.execute("SELECT * FROM files ORDER BY registered_at, file_id"):
            agg = self.db.execute(
                """SELECT count(*) chunks, sum(status = 'done') done, sum(status = 'failed') failed,
                          coalesce(sum(lines), 0) lines, coalesce(sum(rows), 0) rows, coalesce(sum(blank), 0) blank,
                          coalesce(sum(quarantined), 0) quarantined, coalesce(sum(warnings), 0) warnings,
                          coalesce(sum(unicode_repaired), 0) unicode_repaired, coalesce(sum(bytes_read), 0) bytes_read,
                          coalesce(sum(wall_seconds), 0) worker_seconds, max(peak_rss_bytes) peak_rss_bytes,
                          max(last_error) last_error,
                          coalesce(sum(status = 'done' AND normalizer_version IS NOT ?), 0) stale_chunks
                   FROM chunks WHERE file_id = ?""",
                (NORMALIZER_VERSION, f["file_id"]),
            ).fetchone()
            by_class: dict[str, int] = {}
            for (js,) in self.db.execute("SELECT quarantined_by_class FROM chunks WHERE file_id = ? AND quarantined_by_class IS NOT NULL", (f["file_id"],)):
                for k, v in orjson.loads(js).items():
                    by_class[k] = by_class.get(k, 0) + v
            files.append({**dict(f), **dict(agg), "quarantined_by_class": by_class})
        snapshots = {r["snapshot_id"]: r["status"] for r in self.db.execute("SELECT * FROM snapshots")}
        deliveries = [dict(r) for r in self.db.execute("SELECT * FROM deliveries ORDER BY delivery_id")]
        return {"files": files, "snapshots": snapshots, "deliveries": deliveries}
