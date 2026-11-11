import pytest

from firmable.ingest.chunks import OVERSIZED, iter_chunk_lines, plan_chunks


def _write(tmp_path, content: bytes):
    p = tmp_path / "input.jsonl"
    p.write_bytes(content)
    return p


def _all_lines(path, chunk_bytes, max_line_bytes=1 << 20):
    out = []
    for chunk in plan_chunks(path.stat().st_size, chunk_bytes):
        out.extend(iter_chunk_lines(path, chunk.start, chunk.end, max_line_bytes))
    return out


LINES = [b"aaaa\n", b"bb\n", b"\n", b"cccccccccc\n", b"d\n", b"eeeeee"]  # no trailing newline at EOF


@pytest.mark.parametrize("chunk_bytes", [1, 2, 3, 5, 7, 11, 1000])
def test_every_line_is_read_exactly_once_with_its_byte_offset(tmp_path, chunk_bytes):
    path = _write(tmp_path, b"".join(LINES))
    expected, offset = [], 0
    for ln in LINES:
        expected.append((offset, ln))
        offset += len(ln)

    got = [(off, raw) for off, raw, _ in _all_lines(path, chunk_bytes)]

    assert got == expected


def test_plan_covers_file_without_gaps():
    chunks = plan_chunks(10, 4)

    assert [(c.index, c.start, c.end) for c in chunks] == [(0, 0, 4), (1, 4, 8), (2, 8, 10)]
    assert plan_chunks(0, 4) == []


def test_line_longer_than_limit_is_reported_oversized_and_skipped(tmp_path):
    path = _write(tmp_path, b"ok\n" + b"x" * 100 + b"\n" + b"after\n")

    got = _all_lines(path, chunk_bytes=1000, max_line_bytes=50)

    assert got == [(0, b"ok\n", 3), (3, OVERSIZED, 101), (104, b"after\n", 6)]
