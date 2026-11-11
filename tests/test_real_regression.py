"""Regression on sanitized real banners (tests/fixtures/real_sanitized.jsonl).

Expectations come from what each selected record is known to contain
(its selection label), not from re-running the normalizer.
"""

import json
from pathlib import Path

import duckdb
import pytest

from firmable.ingest.normalize import Rejection, normalize_line
from firmable.ingest.pipeline import Pipeline
from firmable.transform.services import build_services

FIXTURE = Path(__file__).parent / "fixtures" / "real_sanitized.jsonl"
LINES = FIXTURE.read_bytes().splitlines(keepends=True)
BY_LABEL = {json.loads(raw)["_fixture_label"]: normalize_line(raw) for raw in LINES}


def test_every_real_record_normalizes_without_warnings():
    assert len(BY_LABEL) == 16
    for label, obs in BY_LABEL.items():
        assert not isinstance(obs, Rejection), label
        assert obs["parse_warnings"] == [], label
        assert obs["unknown_keys"] == ["_fixture_label"], label  # the only non-scanner key


@pytest.mark.parametrize(
    "label, check",
    [
        ("ipv6", lambda o: o["ip_version"] == 6 and o["ip"].startswith("2001:db8::")),
        ("vhost_sni", lambda o: o["sni"].endswith(".example.org")),
        ("s03_rdp_ntlm", lambda o: o["ntlm_dns_domain"] is not None and o["port"] == 3389),
        ("s06_legacy_tls", lambda o: "TLSv1" in o["ssl_versions"] and o["has_ssl"]),
        ("s06_expired_cert", lambda o: o["cert_expired"] is True and o["cert_expires"] is not None),
        ("san_cert", lambda o: len(o["cert_san_dns"]) >= 1 and all(n.endswith("example.org") for n in o["cert_san_dns"])),
        ("s16_waf", lambda o: o["http_waf"] is not None),
        ("vulns_kev", lambda o: o["any_kev"] and any(v["kev"] for v in o["vulns"]) and not o["any_verified"]),
        ("empty_banner", lambda o: o["banner_len"] == 0),
        ("honeypot", lambda o: "honeypot" in o["tags"]),
        ("udp_ike", lambda o: o["transport"] == "udp" and '"isakmp"' in o["protocol_json"]),
        ("ssh", lambda o: o["ssh_hassh"] is not None),
        ("s05_mgmt_plane", lambda o: "Plesk" in o["http_title"]),
    ],
)
def test_real_record_fields_survive_normalization(label, check):
    assert check(BY_LABEL[label])


def test_real_fixture_end_to_end_to_services(tmp_path):
    pipe = Pipeline(tmp_path / "work", chunk_bytes=8192)
    pipe.register(FIXTURE, snapshot_id="regression")
    pipe.run(workers=2)
    f = pipe.status()["files"][0]
    assert (f["status"], f["lines"], f["rows"], f["quarantined"]) == ("completed", 16, 16, 0)

    result = build_services(pipe, "regression")

    assert result["empty_banner"] == 2 and result["honeypot_tagged"] == 1  # the real honeypot row is also empty
    with duckdb.connect() as con:
        ports = {r[0] for r in con.execute("SELECT port FROM read_parquet(?)", [result["path"]]).fetchall()}
    assert 12281 not in ports and 12146 not in ports  # empty-banner and honeypot ports excluded
    assert result["services"] == 14
