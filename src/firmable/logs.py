"""Structured JSON-lines logging to stderr."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from typing import Any

import orjson


def log(event: str, **fields: Any) -> None:
    # Containers set FIRMABLE_LOG_STREAM=stdout: platforms such as Railway treat stderr as errors.
    stream = sys.stdout if os.environ.get("FIRMABLE_LOG_STREAM") == "stdout" else sys.stderr
    record = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "event": event, **fields}
    stream.write(orjson.dumps(record, default=str).decode() + "\n")
    stream.flush()
