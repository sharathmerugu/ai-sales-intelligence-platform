"""Bounded memory: worker peak RSS must not grow with input size or record size."""

import pytest

from firmable.ingest.pipeline import Pipeline

from factories import line, record

MIB = 2**20


def _big_file(path, copies: int) -> int:
    big = line(http={**{"status": 200}, "html": "x" * (2 * MIB)}, data="y" * MIB)  # ~3 MB record
    small = line()
    with open(path, "wb") as fh:
        for _ in range(copies):
            fh.write(big)
            for _ in range(500):
                fh.write(small)
    return path.stat().st_size


def _peak(tmp_path, name, copies):
    src = tmp_path / f"{name}.jsonl"
    size = _big_file(src, copies)
    pipe = Pipeline(tmp_path / name, chunk_bytes=64 * MIB, batch_rows=2000)
    pipe.register(src, snapshot_id="mem")
    pipe.run(workers=1)
    f = pipe.status()["files"][0]
    assert f["status"] == "completed"
    return size, f["peak_rss_bytes"]


@pytest.mark.slow
def test_worker_peak_memory_is_independent_of_input_size(tmp_path):
    small_size, small_peak = _peak(tmp_path, "small", copies=40)
    large_size, large_peak = _peak(tmp_path, "large", copies=160)

    assert large_size > 3.5 * small_size
    assert large_peak < 400 * MIB
    assert large_peak - small_peak < 64 * MIB, (small_peak / MIB, large_peak / MIB)
