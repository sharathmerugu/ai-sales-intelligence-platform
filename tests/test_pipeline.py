"""Integration tests: synthetic delivery -> manifest -> Parquet observations."""

import hashlib
import shutil

import duckdb
import pyarrow.parquet as pq
import pytest

from firmable.ingest.pipeline import Pipeline
from firmable.ingest.schema import OBSERVATION_SCHEMA

from factories import mixed_fixture_lines, write_fixture


@pytest.fixture
def pipe(tmp_path):
    return Pipeline(tmp_path / "work", chunk_bytes=1500, batch_rows=4)


@pytest.fixture
def source(tmp_path):
    p = tmp_path / "landing" / "scan-001.jsonl"
    p.parent.mkdir()
    write_fixture(p)
    return p


def _query(sql, params=None):
    with duckdb.connect() as con:
        return con.execute(sql, params or []).fetchall()


def _rows(pipe, snapshot="2026-11-07"):
    files = [str(f) for f in pipe.committed_observation_files(snapshot)]
    return _query("SELECT * FROM read_parquet(?) ORDER BY byte_offset", [files]) if files else []


def test_sample_file_ingests_to_parquet_with_exact_accounting(pipe, source):
    reg = pipe.register(source, snapshot_id="2026-11-07")
    summary = pipe.run(workers=2)

    assert reg.outcome == "new"
    assert reg.file_id == hashlib.sha256(source.read_bytes()).hexdigest()
    assert summary.failed_chunks == 0
    f = pipe.status()["files"][0]
    assert f["status"] == "completed"
    assert f["chunks"] > 1  # the fixture spans several chunks
    assert (f["lines"], f["rows"], f["quarantined"], f["blank"]) == (13, 9, 3, 1)
    assert f["quarantined_by_class"] == {"malformed_json": 1, "missing_required": 1, "invalid_value": 1}

    files = pipe.committed_observation_files("2026-11-07")
    assert all(pq.read_schema(p).equals(OBSERVATION_SCHEMA, check_metadata=False) for p in files)
    assert len(_rows(pipe)) == 9


def test_provenance_points_at_the_exact_source_line(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)
    content = source.read_bytes()

    rows = _query(
        "SELECT observation_id, byte_offset, byte_length, record_sha256 FROM read_parquet(?)",
        [[str(f) for f in pipe.committed_observation_files("2026-11-07")]],
    )

    for obs_id, off, length, digest in rows:
        assert hashlib.sha256(content[off : off + length]).hexdigest() == digest
    obs_id, off, length, digest = rows[0]
    assert pipe.evidence(obs_id)[0] == content[off : off + length]
    file_id = _query("SELECT file_id FROM read_parquet(?) LIMIT 1",
                     [[str(f) for f in pipe.committed_observation_files("2026-11-07")]])[0][0]
    assert pipe.read_record(file_id, off, length, digest) == content[off : off + length]
    with pytest.raises(ValueError, match="hash mismatch"):
        pipe.read_record(file_id, off, length, "0" * 64)


def test_quarantine_keeps_rejected_lines_with_location(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)

    entries = pipe.quarantine_entries()

    assert sorted(e["error_class"] for e in entries) == ["invalid_value", "malformed_json", "missing_required"]
    content = source.read_bytes()
    for e in entries:
        assert content[e["byte_offset"] : e["byte_offset"] + e["byte_length"]].startswith(e["raw_prefix"])


def test_duplicate_delivery_is_detected_and_not_reprocessed(pipe, source, tmp_path):
    first = pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)
    copy = tmp_path / "landing" / "scan-001-redelivered.jsonl"
    shutil.copy(source, copy)

    again = pipe.register(copy, snapshot_id="2026-11-07")
    summary = pipe.run(workers=1)

    assert again.outcome == "duplicate" and again.file_id == first.file_id
    assert summary.processed_chunks == 0
    assert len(_rows(pipe)) == 9


def test_replay_reproduces_identical_observations(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=2)
    before = _rows(pipe)

    pipe.replay(pipe.status()["files"][0]["file_id"])
    pipe.run(workers=2)

    assert _rows(pipe) == before


def test_failed_chunk_is_retried_then_recovered(pipe, source, monkeypatch):
    pipe.register(source, snapshot_id="2026-11-07")
    monkeypatch.setenv("FIRMABLE_TEST_FAIL_CHUNK", "1")
    summary = pipe.run(workers=1, max_attempts=2)

    f = pipe.status()["files"][0]
    assert summary.failed_chunks == 1
    assert f["status"] == "failed"
    assert "injected failure" in f["last_error"]
    assert pipe.committed_observation_files("2026-11-07") == []  # an incomplete file is not readable

    monkeypatch.delenv("FIRMABLE_TEST_FAIL_CHUNK")
    pipe.retry(f["file_id"])
    pipe.run(workers=1)

    assert pipe.status()["files"][0]["status"] == "completed"
    assert len(_rows(pipe)) == 9


def test_seal_requires_all_files_complete_and_new_file_unseals(pipe, source, tmp_path):
    pipe.register(source, snapshot_id="2026-11-07")
    with pytest.raises(ValueError, match="not completed"):
        pipe.seal("2026-11-07")

    pipe.run(workers=1)
    pipe.seal("2026-11-07")
    assert pipe.status()["snapshots"]["2026-11-07"] == "sealed"

    other = tmp_path / "landing" / "scan-002.jsonl"
    write_fixture(other, mixed_fixture_lines()[:2])
    pipe.register(other, snapshot_id="2026-11-07")
    assert pipe.status()["snapshots"]["2026-11-07"] == "open"


def test_evidence_detects_a_modified_source(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)
    obs_id = _rows(pipe)[0][OBSERVATION_SCHEMA.names.index("observation_id")]
    source.write_bytes(source.read_bytes().replace(b"Example Corp", b"Tampered Co."))

    with pytest.raises(ValueError, match="hash mismatch"):
        pipe.evidence(obs_id)


def test_accounting_covers_every_byte_of_the_file(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=2)

    f = pipe.status()["files"][0]
    assert f["bytes_read"] == source.stat().st_size


def test_duplicate_delivered_into_another_snapshot_keeps_its_original_snapshot(pipe, source, tmp_path):
    pipe.register(source, snapshot_id="2026-11-07")
    again = pipe.register(source, snapshot_id="2026-12-01")

    assert again.outcome == "duplicate"
    assert again.snapshot_id == "2026-11-07"
    assert "2026-12-01" not in pipe.status()["snapshots"]


def test_sealing_an_unknown_snapshot_is_an_error(pipe):
    with pytest.raises(ValueError, match="unknown snapshot"):
        pipe.seal("2099-01-01")


def test_second_concurrent_run_is_refused(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    with pipe.run_lock():
        with pytest.raises(RuntimeError, match="another run"):
            pipe.run(workers=1)


def test_source_changed_before_replay_fails_without_overwriting_good_output(pipe, source):
    pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)
    before = _rows(pipe)
    source.write_bytes(source.read_bytes().replace(b"Example Corp", b"Tampered Co."))

    pipe.replay(pipe.status()["files"][0]["file_id"])
    summary = pipe.run(workers=1, max_attempts=1)

    assert summary.failed_chunks >= 1
    assert "source" in pipe.status()["files"][0]["last_error"]
    pipe_files = [str(p) for p in sorted((pipe.lake / "observations").rglob("*.parquet"))]
    assert _query("SELECT * FROM read_parquet(?) ORDER BY byte_offset", [pipe_files]) == before


def test_worker_process_crash_fails_only_its_chunk(pipe, source, monkeypatch):
    pipe.register(source, snapshot_id="2026-11-07")
    monkeypatch.setenv("FIRMABLE_TEST_CRASH_CHUNK", "1")  # worker calls os._exit, like an OOM kill
    summary = pipe.run(workers=2, max_attempts=2)

    chunks = pipe.chunk_states()
    assert summary.failed_chunks == 1
    assert chunks[1] == "failed"
    assert all(state == "done" for idx, state in chunks.items() if idx != 1)

    monkeypatch.delenv("FIRMABLE_TEST_CRASH_CHUNK")
    pipe.retry(pipe.status()["files"][0]["file_id"])
    pipe.run(workers=2)
    assert pipe.status()["files"][0]["status"] == "completed"


def test_files_from_an_older_normalizer_are_stale_until_replayed(pipe, source):
    reg = pipe.register(source, snapshot_id="2026-11-07")
    pipe.run(workers=1)
    # Simulate output written by a previous normalizer version.
    pipe.db.execute("UPDATE chunks SET normalizer_version = 0")

    assert pipe.committed_observation_files("2026-11-07") == []
    assert pipe.status()["files"][0]["stale_chunks"] == pipe.status()["files"][0]["chunks"]

    pipe.replay(reg.file_id)
    pipe.run(workers=1)
    assert len(_rows(pipe)) == 9
    assert pipe.status()["files"][0]["stale_chunks"] == 0
