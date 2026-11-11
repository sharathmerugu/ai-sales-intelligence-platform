"""Contract check: the API serves what the real account roll-up writes.

Runs `firmable.accounts.build_accounts` over tiny synthetic signal hits and
service attribution, builds the serving DB from its output and reads it back
over HTTP. Guards against column drift between M3 and M4.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from urllib.parse import quote

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient

from firmable.accounts import build_accounts
from firmable.accounts.rollup import ACCOUNTS_SCHEMA
from firmable.api.app import create_app
from firmable.api.store import build_serving_db

S, I32, I64, B, F64 = pa.string(), pa.int32(), pa.int64(), pa.bool_(), pa.float64()
LS = pa.list_(pa.string())

HITS_SCHEMA = pa.schema([
    ("snapshot_id", S), ("signal_id", S), ("signal_version", I32), ("family", S),
    ("service_id", S), ("observation_id", S),
    ("file_id", S), ("byte_offset", I64), ("byte_length", I32), ("record_sha256", S),
    ("ip", S), ("port", I32), ("transport", S), ("sni", S), ("observed_at", pa.timestamp("us")),
    ("is_cdn", B), ("country_code", S),
    ("product", S), ("version", S), ("http_title", S), ("module", S),
    ("match_basis", S), ("detail", S), ("sub_flags", LS), ("evidence_json", S),
])
ATTR_SCHEMA = pa.schema([
    ("snapshot_id", S), ("service_id", S), ("attribution_version", I32),
    ("tier", S), ("account_id", S), ("account_name", S),
    ("confidence", F64), ("confidence_band", S), ("reasons", LS), ("candidate_domains", LS),
    ("allows_infra_signals", B), ("org", S), ("isp", S), ("org_class", S),
])
FAMILY = {"S04": "exposure", "S05": "exposure", "S06": "hygiene"}


def hit(n, signal_id, service_id, detail, match_basis="product", sub_flags=()):
    return dict(
        snapshot_id="2026-11-07", signal_id=signal_id, signal_version=1, family=FAMILY[signal_id],
        service_id=service_id, observation_id=f"obs-{n}", file_id="f" * 64, byte_offset=n * 100,
        byte_length=90, record_sha256=f"{n:064d}", ip="192.0.2.9", port=9000, transport="tcp", sni="",
        observed_at=datetime(2026, 11, 7, 14, 52), is_cdn=False, country_code="AU",
        product=detail, version=None, http_title=None, module="http", match_basis=match_basis,
        detail=detail, sub_flags=list(sub_flags), evidence_json="{}",
    )


# Registry entries as objects (the real registry uses attribute access).
REGISTRY = [
    SimpleNamespace(id="S04", version=1, name="Datastore exposed", family="exposure",
                    observed_fact_template="On {observed_at} UTC, {ip}:{port} returned {product} {version}.",
                    inferred_risk="A datastore interface is internet-reachable.",
                    hypothesis="This account may be reviewing data-store exposure.", infra_exposure=True),
    SimpleNamespace(id="S05", version=1, name="Management plane exposed", family="exposure",
                    observed_fact_template="On {observed_at} UTC, {ip}:{port} served {detail}.",
                    inferred_risk="A management plane is internet-reachable.",
                    hypothesis="This account may be reviewing admin-surface exposure.", infra_exposure=True),
]


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("rollup")
    hits = [hit(1, "S04", "svc-minio", "MinIO"), hit(2, "S05", "svc-minio", "MinIO", match_basis="title")]
    attrs = [dict(snapshot_id="2026-11-07", service_id="svc-minio", attribution_version=1, tier="A1",
                  account_id="org:example corp", account_name="Example Corp", confidence=0.9,
                  confidence_band="high", reasons=["org_not_provider"], candidate_domains=[],
                  allows_infra_signals=True, org="Example Corp", isp="Example Corp", org_class="business")]
    pq.write_table(pa.Table.from_pylist(hits, schema=HITS_SCHEMA), d / "signal_hits.parquet")
    pq.write_table(pa.Table.from_pylist(attrs, schema=ATTR_SCHEMA), d / "service_attribution.parquet")
    # the service's own SNI names the account, so ownership is corroborated and the account is actionable
    evidence = [dict(snapshot_id="2026-11-07", service_id="svc-minio", source="sni", raw_name="minio.examplecorp.com",
                     name="minio.examplecorp.com", reg_domain="examplecorp.com", outcome="accepted",
                     attribution_version=4)]
    pq.write_table(pa.Table.from_pylist(evidence), d / "evidence.parquet")
    build_accounts(d / "signal_hits.parquet", d / "service_attribution.parquet", d / "accounts",
                   attribution_evidence_parquet=d / "evidence.parquet")
    stats = build_serving_db(d / "accounts", REGISTRY, d / "serving.duckdb")
    assert stats["snapshot_id"] == "2026-11-07"  # inferred from the evidence
    with TestClient(create_app(d / "serving.duckdb")) as c:
        yield c


def test_rollup_output_is_served(client):
    body = client.get("/accounts").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["account_id"] == "org:example corp"
    assert item["rank"] == 1
    # one S04 on one IP: priority 100 * 0.65 * 0.5; alone in its population, so percentile 0, band Low
    assert item["priority"]["value"] == pytest.approx(32.5)
    assert (item["priority"]["percentile"], item["priority"]["band"]) == (0, "Low")
    assert (item["ownership"]["confidence"], item["ownership"]["named_public_services"]) == ("high", 1)
    assert item["evidence"]["quality"] == "high"
    assert item["actionable"] is True
    assert item["top_signals"] == [{"signal_id": "S04", "name": "Datastore exposed"}]
    assert item["legacy"]["score"] == pytest.approx(29.25)  # 32.5 x attribution 0.9 x evidence 1.0


def test_detail_explanation_keeps_priority_ownership_and_evidence_apart(client):
    body = client.get("/accounts/" + quote("org:example corp", safe=":")).json()
    lines = body["explanation"]
    assert lines[0].startswith("Low relative priority: higher than 0% of eligible enterprise accounts")
    assert "Not a purchase probability, a confirmed vulnerability or a loss estimate" in lines[0]
    assert "attribution" not in lines[0].lower()  # the priority line carries no attribution term
    own = next(line for line in lines if line.startswith("Ownership confidence"))
    assert "high" in own and "SNI" in own and "not verified" in own
    assert any(line.startswith("Evidence quality high") for line in lines)
    assert any(line == "Outreach: actionable on this evidence." for line in lines)


def test_suppressed_duplicate_is_served_with_suppressed_by(client):
    ev = client.get("/accounts/" + quote("org:example corp", safe=":") + "/evidence").json()
    by_signal = {e["signal_id"]: e for e in ev["items"]}
    assert by_signal["S04"]["counted"] is True
    assert by_signal["S04"]["suppressed_by"] is None
    assert by_signal["S05"]["counted"] is False
    assert by_signal["S05"]["suppressed_by"] == "S04"  # MinIO counts as S04, not S04 + S05
    assert by_signal["S04"]["observed_fact"] == "On 2026-11-07 14:52 UTC, 192.0.2.9:9000 returned MinIO —."
    assert by_signal["S04"]["provenance"]["record_sha256"] == f"{1:064d}"


def test_real_registry_loads_when_available(tmp_path):
    signals = pytest.importorskip("firmable.signals.registry")
    d = tmp_path / "accounts"
    d.mkdir()
    # Empty account tables are enough to load the registry.
    import duckdb

    con = duckdb.connect()
    pq.write_table(ACCOUNTS_SCHEMA.empty_table(), d / "accounts.parquet")
    for name, cols in {
        "account_signals": "account_id VARCHAR, signal_id VARCHAR, family VARCHAR, n_services BIGINT, "
        "n_ips BIGINT, n_counted_services BIGINT, details VARCHAR[], sub_flags VARCHAR[], "
        "max_attribution_confidence DOUBLE, contribution DOUBLE",
    }.items():
        con.execute(f"CREATE TABLE {name} ({cols})")
        con.execute(f"COPY {name} TO '{d / (name + '.parquet')}' (FORMAT parquet)")
    hits = d.parent / "hits.parquet"
    pq.write_table(pa.Table.from_pylist([], schema=HITS_SCHEMA), hits)
    con.execute(
        f"COPY (SELECT NULL::VARCHAR AS account_id, *, NULL::VARCHAR AS tier, NULL::DOUBLE AS attribution_confidence, "
        f"NULL::VARCHAR[] AS attribution_reasons, NULL::BOOLEAN AS counted, NULL::VARCHAR AS suppressed_by, "
        f"NULL::INTEGER AS attribution_version, NULL::VARCHAR[] AS attribution_domains "
        f"FROM read_parquet('{hits}') LIMIT 0) TO '{d / 'account_evidence.parquet'}' (FORMAT parquet)"
    )
    build_serving_db(d, list(signals.SIGNALS), tmp_path / "s.duckdb", snapshot_id="x")
    with TestClient(create_app(tmp_path / "s.duckdb")) as c:
        body = c.get("/signals").json()
    assert {"S01", "S03", "S04", "S05", "S06", "S16"} <= {s["id"] for s in body["signals"]}
    for s in body["signals"]:
        assert s["name"] and s["inferred_risk"] and s["hypothesis"] and s["observed_fact_template"]
