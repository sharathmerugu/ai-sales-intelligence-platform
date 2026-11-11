"""Services layer: dedup, latest eligible observation per (snapshot, service)."""

import duckdb
import pytest

from firmable.ingest.pipeline import Pipeline
from firmable.transform.services import build_services

from factories import BASE, line, mixed_fixture_lines, write_fixture


@pytest.fixture
def pipe(tmp_path):
    p = Pipeline(tmp_path / "work", chunk_bytes=1500, batch_rows=4)
    src = tmp_path / "s1.jsonl"
    write_fixture(src)
    p.register(src, snapshot_id="s1")
    p.run(workers=1)
    return p


def _services(path):
    with duckdb.connect() as con:
        return {
            (r[0], r[1], r[2], r[3]): r[4:]
            for r in con.execute(
                "SELECT ip, port, transport, sni, observation_id, n_observations, first_seen, last_seen "
                "FROM read_parquet(?)", [str(path)]
            ).fetchall()
        }


def test_services_keep_latest_eligible_observation_and_count_distinct_observations(pipe):
    result = build_services(pipe, "s1")
    svc = _services(result["path"])

    assert set(svc) == {
        ("192.0.2.1", 443, "tcp", ""),
        ("192.0.2.1", 443, "tcp", "a.example.com"),
        ("192.0.2.1", 443, "tcp", "b.example.com"),
        ("2001:db8::10", 443, "tcp", ""),
        ("192.0.2.1", 22, "tcp", ""),
    }
    obs_id, n_obs, *_ = svc[("192.0.2.1", 443, "tcp", "")]
    assert obs_id == "00000000-0000-0000-0000-000000000005"  # the 15:00 repeat wins
    assert n_obs == 3  # ids 1, 5, 8; the duplicate delivery of id 1 counts once
    assert result["raw_rows"] == 9
    assert result["observations"] == 8
    assert result["duplicate_observations"] == 1
    assert result["empty_banner"] == 1  # the 3389 row is excluded from services
    assert result["services"] == 5


def test_repeat_observation_in_a_new_snapshot_does_not_change_the_old_one(pipe, tmp_path):
    s1_before = _services(build_services(pipe, "s1")["path"])
    src2 = tmp_path / "s2.jsonl"
    write_fixture(src2, [line(_shodan={**BASE["_shodan"], "id": "snap2-obs"}, timestamp="2026-12-07T10:00:00")])
    pipe.register(src2, snapshot_id="s2")
    pipe.run(workers=1)

    s2 = _services(build_services(pipe, "s2")["path"])
    s1_after = _services(build_services(pipe, "s1")["path"])

    assert s1_after == s1_before
    assert list(s2) == [("192.0.2.1", 443, "tcp", "")]
    assert s2[("192.0.2.1", 443, "tcp", "")][0] == "snap2-obs"


def test_noise_rows_are_flagged_not_promoted(tmp_path):
    p = Pipeline(tmp_path / "work")
    src = tmp_path / "noise.jsonl"
    soup = ["cpe:2.3:a:adobe:coldfusion", "cpe:2.3:a:wordpress:wordpress"] + [f"cpe:2.3:a:v{i}:p{i}" for i in range(8)]
    write_fixture(src, [
        line(_shodan={**BASE["_shodan"], "id": "honeypot"}, port=1, tags=["honeypot"]),
        line(_shodan={**BASE["_shodan"], "id": "soup"}, port=2, cpe23=soup),
        line(_shodan={**BASE["_shodan"], "id": "real"}, port=3),
    ])
    p.register(src, snapshot_id="n")
    p.run(workers=1)

    result = build_services(p, "n")

    assert (result["honeypot_tagged"], result["fingerprint_soup"], result["services"]) == (1, 1, 1)


def test_classification_is_persisted_as_its_own_layer_for_every_observation(pipe):
    result = build_services(pipe, "s1")

    with duckdb.connect() as con:
        flags = con.execute(
            "SELECT observation_id, is_empty, eligible, classifier_version FROM read_parquet(?)",
            [result["flags_path"]],
        ).fetchall()
    assert len(flags) == 8  # every distinct observation, including ineligible ones
    empty = [f for f in flags if f[0] == "00000000-0000-0000-0000-000000000010"]
    assert empty == [("00000000-0000-0000-0000-000000000010", True, False, 1)]


def _schema(path):
    with duckdb.connect() as con:
        return con.execute(
            "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM read_parquet(?, hive_partitioning = false))",
            [str(path)],
        ).fetchall()


def test_layer_schemas_are_exact_with_no_leaked_partition_columns(pipe):
    # Review of the full run found hive `key=value` directories leaking in as columns
    # (file, normalizer, snapshot as DATE) and n_eligible_observations typed DOUBLE.
    from firmable.ingest.schema import OBSERVATION_SCHEMA

    result = build_services(pipe, "s1")
    services = _schema(result["path"])
    flags = _schema(result["flags_path"])

    flag_cols = [("is_empty", "BOOLEAN"), ("is_honeypot_tagged", "BOOLEAN"), ("is_fp_soup", "BOOLEAN"), ("is_cdn", "BOOLEAN")]
    assert [c for c, _ in services] == OBSERVATION_SCHEMA.names + [c for c, _ in flag_cols] + [
        "n_observations", "n_eligible_observations", "first_seen", "last_seen", "classifier_version", "services_version",
    ]
    types = dict(services)
    assert types["n_observations"] == "BIGINT"
    assert types["n_eligible_observations"] == "BIGINT"
    assert types["snapshot_id"] == "VARCHAR"
    assert flags == [
        ("observation_id", "VARCHAR"), ("service_id", "VARCHAR"), ("snapshot_id", "VARCHAR"), ("file_id", "VARCHAR"),
        ("byte_offset", "BIGINT"), ("observed_at", "TIMESTAMP"), *flag_cols,
        ("eligible", "BOOLEAN"), ("classifier_version", "INTEGER"),
    ]
