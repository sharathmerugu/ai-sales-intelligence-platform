"""Application state: agent runs and published briefs, in SQLite (stdlib, one file, no server).

This is application state, not analytics: the serving DuckDB stays read-only. One active run per cache
key is enforced by a partial unique index, so concurrent requests for the same brief share one job.
A published row is written only for a run that passed the checks; fallbacks are recorded on the run.
Runs left `queued` or `running` by a stopped process are marked `failed / interrupted` at start-up.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY,
    cache_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    account_id TEXT NOT NULL,
    snapshot_id TEXT,
    use_case TEXT,
    question TEXT,
    signal_id TEXT,
    scope TEXT NOT NULL,
    context_digest TEXT NOT NULL,
    versions_json TEXT NOT NULL,
    status TEXT NOT NULL,
    disposition TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    metrics_json TEXT,
    trace_json TEXT,
    issues_json TEXT,
    output_json TEXT,
    error TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_run ON agent_runs (cache_key) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS runs_by_key ON agent_runs (cache_key, created_at);
CREATE INDEX IF NOT EXISTS runs_by_scope ON agent_runs (scope, created_at);
CREATE TABLE IF NOT EXISTS published (
    cache_key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    account_id TEXT NOT NULL,
    context_digest TEXT NOT NULL,
    created_at REAL NOT NULL,
    output_json TEXT NOT NULL
);
"""
ACTIVE = ("queued", "running")
JSON_COLUMNS = ("versions_json", "metrics_json", "trace_json", "issues_json", "output_json")


def _loads(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for c in JSON_COLUMNS:
        if c in out:
            out[c.removesuffix("_json")] = json.loads(out.pop(c)) if out[c] else None
    return out


class RunStore:
    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._con.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            if str(path) != ":memory:":
                self._con.execute("PRAGMA journal_mode=WAL")
            self._con.executescript(SCHEMA)

    def close(self) -> None:
        self._con.close()

    def _one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._con.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._con.execute(sql, params).fetchall()

    def _exec(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            return self._con.execute(sql, params).rowcount

    # -- runs -------------------------------------------------------------------

    def create_run(self, *, cache_key: str, kind: str, account_id: str, snapshot_id: str | None,
                   use_case: str | None, scope: str, context_digest: str, versions: dict[str, Any],
                   question: str | None = None, signal_id: str | None = None) -> tuple[str, bool]:
        """(run_id, created). When a run for this key is already active, returns it with created=False."""
        run_id = uuid.uuid4().hex
        try:
            self._exec(
                "INSERT INTO agent_runs (run_id, cache_key, kind, account_id, snapshot_id, use_case, question, "
                "signal_id, scope, context_digest, versions_json, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
                (run_id, cache_key, kind, account_id, snapshot_id, use_case, question, signal_id, scope,
                 context_digest, json.dumps(versions, sort_keys=True), time.time()))
            return run_id, True
        except sqlite3.IntegrityError:
            active = self.active_run(cache_key)
            if active is None:  # finished between the insert and the lookup: try once more
                return self.create_run(cache_key=cache_key, kind=kind, account_id=account_id,
                                       snapshot_id=snapshot_id, use_case=use_case, scope=scope,
                                       context_digest=context_digest, versions=versions, question=question,
                                       signal_id=signal_id)
            return active["run_id"], False

    def mark_running(self, run_id: str) -> None:
        self._exec("UPDATE agent_runs SET status = 'running', started_at = ? WHERE run_id = ? AND status = 'queued'",
                   (time.time(), run_id))

    def finish(self, run_id: str, *, status: str, disposition: str, metrics: dict[str, Any] | None,
               trace: list[dict[str, Any]] | None, issues: list[str] | None, output: dict[str, Any] | None,
               error: str | None = None) -> None:
        now = time.time()
        out_json = json.dumps(output, default=str) if output is not None else None
        # Status and publication change together, so no reader sees a finished run without its brief.
        with self._lock:
            con = self._con
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "UPDATE agent_runs SET status = ?, disposition = ?, finished_at = ?, metrics_json = ?, "
                    "trace_json = ?, issues_json = ?, output_json = ?, error = ? WHERE run_id = ?",
                    (status, disposition, now, json.dumps(metrics, default=str), json.dumps(trace, default=str),
                     json.dumps(issues or []), out_json, error, run_id))
                if status == "succeeded" and output is not None:
                    con.execute(
                        "INSERT OR REPLACE INTO published (cache_key, run_id, kind, scope, account_id, context_digest, "
                        "created_at, output_json) SELECT cache_key, run_id, kind, scope, account_id, context_digest, "
                        "?, ? FROM agent_runs WHERE run_id = ?", (now, out_json, run_id))
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise

    def fail(self, run_id: str, disposition: str) -> None:
        """Last-resort transition out of queued / running."""
        try:
            self._exec("UPDATE agent_runs SET status = 'failed', disposition = ?, finished_at = ? "
                       "WHERE run_id = ? AND status IN ('queued', 'running')", (disposition, time.time(), run_id))
        except sqlite3.Error:
            pass

    def cost_since(self, since: float) -> float:
        """Recorded USD of runs created since `since` (all scopes)."""
        total = 0.0
        for r in self._all("SELECT metrics_json FROM agent_runs WHERE created_at >= ? AND metrics_json IS NOT NULL",
                           (since,)):
            total += (json.loads(r["metrics_json"]) or {}).get("cost_usd") or 0.0
        return total

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return _loads(self._one("SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)))

    def active_run(self, cache_key: str) -> dict[str, Any] | None:
        return _loads(self._one("SELECT * FROM agent_runs WHERE cache_key = ? AND status IN ('queued', 'running')",
                                (cache_key,)))

    def latest_finished(self, cache_key: str) -> dict[str, Any] | None:
        return _loads(self._one("SELECT * FROM agent_runs WHERE cache_key = ? AND finished_at IS NOT NULL "
                                "ORDER BY finished_at DESC LIMIT 1", (cache_key,)))

    def published(self, cache_key: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM published WHERE cache_key = ?", (cache_key,))
        return _loads(row)

    def runs_since(self, scope: str, since: float) -> int:
        return self._one("SELECT count(*) AS n FROM agent_runs WHERE scope = ? AND created_at >= ?",
                         (scope, since))["n"]

    def recover_interrupted(self) -> int:
        return self._exec("UPDATE agent_runs SET status = 'failed', disposition = 'interrupted', finished_at = ? "
                          "WHERE status IN ('queued', 'running')", (time.time(),))

    def list_runs(self, scope: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        where, params = ("WHERE scope = ?", (scope,)) if scope else ("", ())
        rows = self._all(f"SELECT run_id, kind, account_id, snapshot_id, use_case, question, status, disposition, "
                         f"created_at, finished_at, metrics_json FROM agent_runs {where} ORDER BY created_at DESC "
                         f"LIMIT ?", (*params, limit))
        return [_loads(r) for r in rows]  # type: ignore[misc]

    def all_runs(self) -> list[dict[str, Any]]:
        return [_loads(r) for r in self._all("SELECT * FROM agent_runs ORDER BY created_at")]  # type: ignore[misc]
