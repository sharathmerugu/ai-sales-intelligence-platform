"""Layers 2-3: noise classification and the per-snapshot services table.

Classifier v1 ports the research eligibility filter (sql/exploration.sql §4):
empty banner, scanner `honeypot` tag, fingerprint-soup decoy. `is_cdn` is a
flag carried forward for signal rules, not an exclusion.

Services v1: deduplicate observations by `observation_id` (lowest
file_id/byte_offset wins), then keep the latest eligible observation per
(snapshot_id, service_id), with observation counts and first/last seen.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import duckdb

from ..ingest.normalize import NORMALIZER_VERSION
from ..logs import log

CLASSIFIER_VERSION = 1
SERVICES_VERSION = 1

FLAGS_SQL = """
    coalesce(banner_len, 0) = 0                                           AS is_empty,
    coalesce(list_contains(tags, 'honeypot'), false)                      AS is_honeypot_tagged,
    coalesce(len(cpe23) >= 8
             AND list_contains(cpe23, 'cpe:2.3:a:adobe:coldfusion')
             AND list_contains(cpe23, 'cpe:2.3:a:wordpress:wordpress'), false) AS is_fp_soup,
    coalesce(list_contains(tags, 'cdn'), false)                           AS is_cdn
"""


ELIGIBLE_SQL = "NOT is_empty AND NOT is_honeypot_tagged AND NOT is_fp_soup"


def _sql_str(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _layer_path(pipe: Any, layer: str, version_tag: str, snapshot_id: str, name: str) -> Path:
    return (pipe.lake / layer / version_tag / f"normalizer=v{NORMALIZER_VERSION}"
            / f"snapshot={snapshot_id}" / name)


def services_path(pipe: Any, snapshot_id: str) -> Path:
    return _layer_path(pipe, "services", f"services=v{SERVICES_VERSION}", snapshot_id, "services.parquet")


def flags_path(pipe: Any, snapshot_id: str) -> Path:
    return _layer_path(pipe, "observation_flags", f"classifier=v{CLASSIFIER_VERSION}", snapshot_id, "flags.parquet")


def build_services(pipe: Any, snapshot_id: str, memory_limit: str = "4GB", threads: int | None = None) -> dict[str, Any]:
    """Write layer 2 (observation_flags, one row per distinct observation) and layer 3 (services)."""
    files = [str(p) for p in pipe.committed_observation_files(snapshot_id)]
    if not files:
        raise ValueError(f"snapshot {snapshot_id}: no completed observation files")
    out, flags_out = services_path(pipe, snapshot_id), flags_path(pipe, snapshot_id)
    for path in (out, flags_out):
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp, flags_tmp = out.with_suffix(".parquet.tmp"), flags_out.with_suffix(".parquet.tmp")
    started = time.perf_counter()

    # hive_partitioning = false: our `key=value` directories must not leak in as columns.
    src = "read_parquet([" + ", ".join(_sql_str(f) for f in files) + "], hive_partitioning = false)"
    with duckdb.connect() as con:
        con.execute(f"SET memory_limit = {_sql_str(memory_limit)}")
        con.execute(f"SET threads = {int(threads or os.cpu_count() or 1)}")
        con.execute(f"SET temp_directory = {_sql_str(pipe.workdir / 'duckdb_tmp')}")
        con.execute("SET preserve_insertion_order = false")
        con.execute("SET enable_progress_bar = false")
        # Window functions run over narrow key columns only; wide rows are joined back once at the end.
        con.execute(
            f"""CREATE TEMP TABLE duplicate_observations AS
                SELECT file_id, byte_offset FROM {src}
                QUALIFY row_number() OVER (PARTITION BY observation_id ORDER BY file_id, byte_offset) > 1"""
        )
        # Layer 2: classification of every distinct observation (eligible or not), persisted on its own.
        con.execute(
            f"""COPY (
                  SELECT observation_id, service_id, snapshot_id, file_id, byte_offset, observed_at,
                         {FLAGS_SQL}
                  FROM {src} ANTI JOIN duplicate_observations USING (file_id, byte_offset)
                ) TO {_sql_str(flags_tmp)} (FORMAT parquet, COMPRESSION zstd)"""
        )
        con.execute(
            f"""CREATE TEMP VIEW flags AS
                SELECT *, {ELIGIBLE_SQL} AS eligible, {CLASSIFIER_VERSION} AS classifier_version
                FROM read_parquet({_sql_str(flags_tmp)}, hive_partitioning = false)"""
        )
        con.execute(
            """CREATE TEMP TABLE service_latest AS
               SELECT k.file_id, k.byte_offset, c.*
               FROM (SELECT * FROM flags WHERE eligible
                     QUALIFY row_number() OVER (PARTITION BY service_id ORDER BY observed_at DESC, observation_id) = 1) k
               JOIN (SELECT service_id, count(*)::BIGINT AS n_observations, count_if(eligible)::BIGINT AS n_eligible_observations,
                            min(observed_at) AS first_seen, max(observed_at) AS last_seen
                     FROM flags GROUP BY service_id) c USING (service_id)"""
        )
        con.execute(
            f"""COPY (
                  SELECT o.*, {FLAGS_SQL}, s.n_observations, s.n_eligible_observations, s.first_seen, s.last_seen,
                         {CLASSIFIER_VERSION} AS classifier_version, {SERVICES_VERSION} AS services_version
                  FROM {src} o JOIN service_latest s USING (file_id, byte_offset)
                  ORDER BY o.service_id
                ) TO {_sql_str(tmp)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100000)"""
        )
        stats = con.execute(
            f"""SELECT (SELECT count(*) FROM {src}) AS raw_rows,
                       count(*) AS observations,
                       count_if(is_empty) AS empty_banner,
                       count_if(is_honeypot_tagged) AS honeypot_tagged,
                       count_if(is_fp_soup) AS fingerprint_soup,
                       count_if(eligible) AS eligible_observations,
                       (SELECT count(*) FROM service_latest) AS services
                FROM flags"""
        ).fetchone()
        # Materialize the final flags file with the derived columns, then publish both atomically.
        con.execute(f"COPY (SELECT * FROM flags) TO {_sql_str(flags_out.with_suffix('.parquet.final'))} (FORMAT parquet, COMPRESSION zstd)")
    os.replace(flags_out.with_suffix(".parquet.final"), flags_out)
    flags_tmp.unlink(missing_ok=True)
    os.replace(tmp, out)

    raw_rows, observations, empty, honeypot, soup, eligible, services = stats
    result = {
        "snapshot_id": snapshot_id,
        "path": str(out),
        "flags_path": str(flags_out),
        "raw_rows": raw_rows,
        "observations": observations,
        "duplicate_observations": raw_rows - observations,
        "empty_banner": empty,
        "honeypot_tagged": honeypot,
        "fingerprint_soup": soup,
        "eligible_observations": eligible,
        "services": services,
        "wall_seconds": round(time.perf_counter() - started, 2),
        "classifier_version": CLASSIFIER_VERSION,
        "services_version": SERVICES_VERSION,
    }
    log("services.built", **result)
    return result
