"""Crash recovery: SIGKILL the coordinator and its workers mid-run, then resume."""

import os
import signal
import sqlite3
import subprocess
import sys
import time

import duckdb

from firmable.ingest.pipeline import Pipeline

from factories import mixed_fixture_lines, write_fixture


def _cli(workdir, *args, env=None, **kw):
    cmd = [sys.executable, "-m", "firmable.cli", "--workdir", str(workdir), "--chunk-bytes", "1500", *args]
    return subprocess.Popen(cmd, env={**os.environ, **(env or {})}, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, start_new_session=True, **kw)


def _observations(pipe):
    files = [str(f) for f in pipe.committed_observation_files()]
    with duckdb.connect() as con:
        return con.execute(
            "SELECT * EXCLUDE (chunk_index) FROM read_parquet(?) ORDER BY byte_offset", [files]
        ).fetchall()


def test_run_resumes_after_coordinator_is_killed(tmp_path):
    src = tmp_path / "scan.jsonl"
    write_fixture(src, mixed_fixture_lines() * 3)  # ~12 chunks at 1500 bytes
    crashed, clean = tmp_path / "crashed", tmp_path / "clean"
    for wd in (crashed, clean):
        assert _cli(wd, "register", str(src), "--snapshot", "s1").wait() == 0

    proc = _cli(crashed, "run", "--workers", "1", env={"FIRMABLE_TEST_CHUNK_DELAY": "0.3"})
    db = sqlite3.connect(crashed / "manifest.sqlite")
    deadline = time.time() + 30
    while time.time() < deadline:
        done = db.execute("SELECT count(*) FROM chunks WHERE status = 'done'").fetchone()[0]
        if done >= 2:
            break
        time.sleep(0.05)
    os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    total = db.execute("SELECT count(*) FROM chunks").fetchone()[0]
    done_at_crash = db.execute("SELECT count(*) FROM chunks WHERE status = 'done'").fetchone()[0]
    db.close()
    assert 2 <= done_at_crash < total  # genuinely interrupted mid-file

    assert Pipeline(crashed, chunk_bytes=1500).committed_observation_files() == []  # partial file invisible
    assert _cli(crashed, "run", "--workers", "2").wait() == 0
    assert _cli(clean, "run", "--workers", "2").wait() == 0

    resumed, reference = Pipeline(crashed, chunk_bytes=1500), Pipeline(clean, chunk_bytes=1500)
    assert resumed.status()["files"][0]["status"] == "completed"
    assert resumed.status()["files"][0]["rows"] == 27
    assert _observations(resumed) == _observations(reference)


def test_repeated_interruptions_do_not_exhaust_retry_attempts(tmp_path):
    # Review finding C2: each interrupted run used to burn an attempt on every queued chunk.
    src = tmp_path / "scan.jsonl"
    write_fixture(src, mixed_fixture_lines() * 3)
    wd = tmp_path / "work"
    assert _cli(wd, "register", str(src), "--snapshot", "s1").wait() == 0
    db = sqlite3.connect(wd / "manifest.sqlite")
    for _ in range(4):
        done_before = db.execute("SELECT count(*) FROM chunks WHERE status = 'done'").fetchone()[0]
        proc = _cli(wd, "run", "--workers", "1", env={"FIRMABLE_TEST_CHUNK_DELAY": "0.3"})
        deadline = time.time() + 30
        while time.time() < deadline:
            if db.execute("SELECT count(*) FROM chunks WHERE status = 'done'").fetchone()[0] > done_before:
                break
            time.sleep(0.05)
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    db.close()

    assert _cli(wd, "run", "--workers", "2").wait() == 0
    assert Pipeline(wd, chunk_bytes=1500).status()["files"][0]["status"] == "completed"
