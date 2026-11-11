"""Byte-range chunk planning and line framing.

Ownership rule: a line belongs to the chunk containing its *first* byte. A
reader for ``[start, end)`` skips the partial line that began before
``start`` and reads every line starting before ``end``, even if it ends
past ``end``. Every line is therefore read by exactly one chunk.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

OVERSIZED = b""  # sentinel payload for lines longer than the limit (never a real line: real lines are non-empty)
_READ_BUFFER = 1 << 20


@dataclass(frozen=True)
class Chunk:
    index: int
    start: int
    end: int


def plan_chunks(file_size: int, chunk_bytes: int) -> list[Chunk]:
    return [
        Chunk(i, start, min(start + chunk_bytes, file_size))
        for i, start in enumerate(range(0, file_size, chunk_bytes))
    ]


def iter_chunk_lines(
    path: Path | str, start: int, end: int, max_line_bytes: int
) -> Iterator[tuple[int, bytes, int]]:
    """Yield ``(byte_offset, line_bytes, byte_length)``; oversized lines yield ``OVERSIZED``."""
    with open(path, "rb", buffering=_READ_BUFFER) as fh:
        pos = start
        if start > 0:
            fh.seek(start - 1)
            pos = start - 1 + _skip_line(fh)
        while pos < end:
            line = fh.readline(max_line_bytes + 1)
            if not line:
                return
            if len(line) > max_line_bytes and not line.endswith(b"\n"):
                length = len(line) + _skip_line(fh)
                yield pos, OVERSIZED, length
            else:
                length = len(line)
                yield pos, line, length
            pos += length


def _skip_line(fh) -> int:
    """Consume through the next newline in bounded pieces; return bytes consumed."""
    consumed = 0
    while True:
        piece = fh.readline(_READ_BUFFER)
        consumed += len(piece)
        if not piece or piece.endswith(b"\n"):
            return consumed
