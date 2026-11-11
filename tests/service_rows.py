"""Synthetic rows of the `services` layer (services v1 schema) for Phase 3 tests.

No real scan data. Every row is a full services-schema row; tests override only
the fields a rule reads. `write_services(path, rows)` writes a Parquet file with
the exact production schema, so code under test reads it like the real layer.
"""

from __future__ import annotations

import hashlib
import itertools
from datetime import datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from firmable.ingest.normalize import service_id
from firmable.ingest.schema import OBSERVATION_SCHEMA

SERVICES_SCHEMA = pa.schema(
    list(OBSERVATION_SCHEMA)
    + [
        pa.field("is_empty", pa.bool_()),
        pa.field("is_honeypot_tagged", pa.bool_()),
        pa.field("is_fp_soup", pa.bool_()),
        pa.field("is_cdn", pa.bool_()),
        pa.field("n_observations", pa.int64()),
        pa.field("n_eligible_observations", pa.int64()),
        pa.field("first_seen", pa.timestamp("us")),
        pa.field("last_seen", pa.timestamp("us")),
        pa.field("classifier_version", pa.int32()),
        pa.field("services_version", pa.int32()),
    ]
)

_counter = itertools.count(1)
OBSERVED_AT = datetime(2026, 11, 7, 14, 52, 1)


def service_row(**overrides: Any) -> dict[str, Any]:
    """A plausible eligible, non-CDN HTTPS service on an enterprise-owned IP.

    `service_id`/`observation_id`/provenance are derived unless overridden.
    Defaults: ip 192.0.2.N, port 443/tcp, no SNI, org 'Example Corp', isp 'Example ISP'.
    """
    n = next(_counter)
    row: dict[str, Any] = {f.name: None for f in SERVICES_SCHEMA}
    row.update(
        file_id="f" * 64,
        snapshot_id="s1",
        chunk_index=0,
        byte_offset=n * 1000,
        byte_length=900,
        record_sha256=hashlib.sha256(str(n).encode()).hexdigest(),
        normalizer_version=1,
        observation_id=f"00000000-0000-0000-0000-{n:012d}",
        ip=f"192.0.2.{n % 250 + 1}",
        ip_version=4,
        port=443,
        transport="tcp",
        sni="",
        observed_at=OBSERVED_AT,
        module="https",
        org="Example Corp",
        isp="Example ISP",
        asn="AS64500",
        country_code="AU",
        cpe23=[],
        tags=[],
        hostnames=[],
        domains=[],
        banner_len=100,
        banner_head="HTTP/1.1 200 OK",
        http_components=[],
        has_ssl=False,
        ssl_versions=[],
        cert_san_dns=[],
        vulns=[],
        any_kev=False,
        any_verified=False,
        unicode_repaired=False,
        parse_warnings=[],
        unknown_keys=[],
        is_empty=False,
        is_honeypot_tagged=False,
        is_fp_soup=False,
        is_cdn=False,
        n_observations=1,
        n_eligible_observations=1,
        first_seen=OBSERVED_AT,
        last_seen=OBSERVED_AT,
        classifier_version=1,
        services_version=1,
    )
    row.update(overrides)
    if "service_id" not in overrides:
        row["service_id"] = service_id(row["ip"], row["port"], row["transport"], row["sni"] or "")
    return row


def write_services(path: str | Path, rows: list[dict[str, Any]]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=SERVICES_SCHEMA), path)
    return path
