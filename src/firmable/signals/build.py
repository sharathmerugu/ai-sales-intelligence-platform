"""Layer 4: `signal_hits` — one row per (signal_id, service_id) for the registry signals.

Reads the services layer (never writes it) and publishes
`lake/signal_hits/signals=v1/normalizer=v1/snapshot=S/signal_hits.parquet`
via a temp file and `os.replace`. Column contract: `docs/phase3-plan.md`.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import duckdb

from ..logs import log
from ..transform.services import _layer_path, _sql_str
from .registry import BASE_DERIVED2_SQL, BASE_DERIVED_SQL, SIGNALS, SIGNALS_VERSION, Signal

# Service columns the rules or the output need (the services row is ~85 columns wide).
INPUT_COLUMNS = [
    "snapshot_id", "service_id", "observation_id", "file_id", "byte_offset", "byte_length", "record_sha256",
    "ip", "port", "transport", "sni", "observed_at", "is_cdn", "country_code",
    "product", "version", "http_title", "module",
    "tags", "banner_head", "protocol_json", "http_status", "http_waf",
    "has_ssl", "ssl_versions", "cert_expired", "cert_expires", "cert_key_type", "cert_key_bits", "cert_sig_alg",
    "cert_subject_cn",
]

PASSTHROUGH = [
    "service_id", "observation_id", "file_id", "byte_offset", "byte_length", "record_sha256",
    "ip", "port", "transport", "sni", "observed_at", "is_cdn", "country_code",
    "product", "version", "http_title", "module",
]


def signal_hits_path(pipe: Any, snapshot_id: str) -> Path:
    return _layer_path(pipe, "signal_hits", f"signals=v{SIGNALS_VERSION}", snapshot_id, "signal_hits.parquet")


def _branch(sig: Signal) -> str:
    return (
        f"SELECT snapshot_id, '{sig.id}' AS signal_id, {int(sig.version)}::INTEGER AS signal_version, "
        f"'{sig.family}' AS family, {', '.join(PASSTHROUGH)}, "
        f"({sig.match_basis_sql})::VARCHAR AS match_basis, ({sig.detail_sql})::VARCHAR AS detail, "
        f"({sig.sub_flags_sql})::VARCHAR[] AS sub_flags, ({sig.evidence_json_sql})::VARCHAR AS evidence_json "
        f"FROM m WHERE hit_{sig.id}"
    )


def signal_hits_sql(source_sql: str, signals: tuple[Signal, ...] = SIGNALS) -> str:
    """SELECT producing the signal_hits contract columns from a services relation (SQL text)."""
    hits = ", ".join(f"coalesce(({s.predicate_sql}), false) AS hit_{s.id}" for s in signals)
    any_hit = " OR ".join(f"hit_{s.id}" for s in signals)
    return f"""
        WITH b0 AS (SELECT {', '.join(INPUT_COLUMNS)}, {BASE_DERIVED_SQL} FROM {source_sql}),
             b AS (SELECT *, {BASE_DERIVED2_SQL} FROM b0),
             m AS MATERIALIZED (SELECT * FROM (SELECT *, {hits} FROM b) WHERE {any_hit})
        {' UNION ALL '.join(_branch(s) for s in signals)}
    """


def evaluate(con: duckdb.DuckDBPyConnection, services_relation: str) -> duckdb.DuckDBPyRelation:
    """Signal hits over `services_relation` (a table/view name or a parenthesised subquery)."""
    return con.sql(signal_hits_sql(services_relation))


def build_signal_hits(
    services_parquet: str | Path,
    out_parquet: str | Path,
    snapshot_id: str | None = None,
    memory_limit: str = "4GB",
    threads: int = 4,
    temp_directory: str | Path | None = None,
) -> dict[str, Any]:
    out = Path(out_parquet)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".parquet.tmp")
    started = time.perf_counter()
    where = f" WHERE snapshot_id = {_sql_str(snapshot_id)}" if snapshot_id is not None else ""
    # hive_partitioning = false: `key=value` directories must not leak in as columns.
    source = f"(SELECT * FROM read_parquet({_sql_str(services_parquet)}, hive_partitioning = false){where})"
    with duckdb.connect() as con:
        con.execute(f"SET memory_limit = {_sql_str(memory_limit)}")
        con.execute(f"SET threads = {int(threads)}")
        if temp_directory is not None:
            con.execute(f"SET temp_directory = {_sql_str(temp_directory)}")
        con.execute("SET preserve_insertion_order = false")
        con.execute("SET enable_progress_bar = false")
        con.execute(
            f"COPY ({signal_hits_sql(source)} ORDER BY signal_id, service_id) "
            f"TO {_sql_str(tmp)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100000)"
        )
        counts = dict(
            con.execute(
                f"SELECT signal_id, count(*) FROM read_parquet({_sql_str(tmp)}, hive_partitioning = false) GROUP BY 1"
            ).fetchall()
        )
    os.replace(tmp, out)
    result = {
        "path": str(out),
        "snapshot_id": snapshot_id,
        "signals_version": SIGNALS_VERSION,
        "counts": {s.id: int(counts.get(s.id, 0)) for s in SIGNALS},
        "rows": int(sum(counts.values())),
        "wall_seconds": round(time.perf_counter() - started, 2),
    }
    log("signal_hits.built", **result)
    return result
