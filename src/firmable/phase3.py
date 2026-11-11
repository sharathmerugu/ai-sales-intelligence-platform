"""Phase 3 orchestration for one sealed snapshot.

services -> signal_hits -> attribution -> accounts -> serving DB.
Each step writes its own versioned layer and never touches earlier ones.
Attribution and roll-ups use snapshot-wide aggregates, so the snapshot must be
sealed first (ADR 0003).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .logs import log

STEPS = ("signals", "attribution", "accounts", "serving")


def serving_path(pipe: Any, snapshot_id: str) -> Path:
    return pipe.workdir / "serving" / f"{snapshot_id}.duckdb"


def build_phase3(pipe: Any, snapshot_id: str, steps: tuple[str, ...] = STEPS,
                 memory_limit: str = "4GB", threads: int = 4) -> dict[str, Any]:
    from .accounts import accounts_dir, build_accounts
    from .api.store import build_serving_db
    from .attribution.build import attribution_dir, build_attribution_for_snapshot
    from .signals import SIGNALS, build_signal_hits, signal_hits_path
    from .transform.services import services_path

    unknown = set(steps) - set(STEPS)
    if unknown:
        raise ValueError(f"unknown steps: {sorted(unknown)}")
    status = pipe.status()["snapshots"].get(snapshot_id)
    if status != "sealed":
        raise ValueError(f"snapshot {snapshot_id} is {status or 'unknown'}, not sealed")

    tmp_dir = pipe.workdir / "duckdb_tmp"
    hits = signal_hits_path(pipe, snapshot_id)
    attr = attribution_dir(pipe, snapshot_id)
    acc = accounts_dir(pipe, snapshot_id)
    result: dict[str, Any] = {"snapshot_id": snapshot_id}
    started = time.perf_counter()

    if "signals" in steps:
        result["signals"] = build_signal_hits(services_path(pipe, snapshot_id), hits, snapshot_id=snapshot_id,
                                              memory_limit=memory_limit, threads=threads, temp_directory=tmp_dir)
    if "attribution" in steps:
        result["attribution"] = build_attribution_for_snapshot(pipe, snapshot_id, memory_limit=memory_limit,
                                                               threads=threads, temp_directory=tmp_dir)
    if "accounts" in steps:
        result["accounts"] = build_accounts(hits, attr / "service_attribution.parquet", acc,
                                            memory_limit=memory_limit, threads=threads, temp_directory=tmp_dir,
                                            attribution_evidence_parquet=attr / "evidence.parquet",
                                            services_parquet=services_path(pipe, snapshot_id))
    if "serving" in steps:
        result["serving"] = build_serving_db(acc, list(SIGNALS), serving_path(pipe, snapshot_id),
                                             snapshot_id=snapshot_id)
    result["wall_seconds"] = round(time.perf_counter() - started, 2)
    log("phase3.built", snapshot_id=snapshot_id, steps=list(steps), wall_seconds=result["wall_seconds"])
    return result
