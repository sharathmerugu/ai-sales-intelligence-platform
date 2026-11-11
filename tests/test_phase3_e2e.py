"""End-to-end vertical slice on synthetic banners:
ingest -> services -> seal -> signals -> attribution -> accounts -> serving DB -> HTTP API.
"""

import pytest
from fastapi.testclient import TestClient

from firmable.api.app import create_app
from firmable.ingest.pipeline import Pipeline
from firmable.phase3 import build_phase3
from firmable.transform.services import build_services

from factories import BASE, line


def _sh(n, **opts):
    return {**BASE["_shodan"], "id": f"e2e-{n}", "options": opts}


@pytest.fixture
def pipe(tmp_path):
    p = Pipeline(tmp_path / "work")
    src = tmp_path / "s1.jsonl"
    src.write_bytes(b"".join([
        # Owned SonicWall SSL-VPN portal on an enterprise range; its reverse DNS names the company.
        line(_shodan=_sh(1), ip_str="192.0.2.10", org="Contoso Manufacturing Pty Ltd",
             isp="Contoso Manufacturing Pty Ltd", product="SonicWALL SSL-VPN http proxy",
             hostnames=["vpn.contoso.com"], domains=["contoso.com"]),
        # RDP on a hosting provider with no customer name: must abstain (tier C).
        line(_shodan={**_sh(2), "module": "rdp"}, ip_str="198.51.100.20", port=3389,
             org="DigitalOcean, LLC", isp="DigitalOcean, LLC", hostnames=[], domains=[],
             data="\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00"),
    ]))
    p.register(src, snapshot_id="s1")
    p.run(workers=1)
    build_services(p, "s1")
    return p


def test_open_snapshot_is_refused(pipe):
    with pytest.raises(ValueError, match="sealed"):
        build_phase3(pipe, "s1")


def test_sealed_snapshot_flows_to_a_ranked_account_in_the_api(pipe):
    pipe.seal("s1")
    result = build_phase3(pipe, "s1")
    assert set(result) >= {"signals", "attribution", "accounts", "serving"}

    client = TestClient(create_app(result["serving"]["path"]))
    body = client.get("/accounts").json()
    ids = [a["account_id"] for a in body["items"]]
    assert ids == ["org:contoso manufacturing"]
    assert body["items"][0]["signal_ids"] == ["S01", "S16"]  # the appliance is also a vendor footprint
    own = body["items"][0]["ownership"]
    assert (own["confidence"], own["named_rdns_services"], own["named_public_services"]) == ("medium", 1, 0)
    assert body["items"][0]["actionable"] is True

    detail = client.get("/accounts/org:contoso manufacturing").json()
    s16 = next(s for s in detail["signals"] if s["signal_id"] == "S16")
    assert (s16["n_services"], s16["n_counted_services"]) == (1, 0)  # same device as S01, not counted twice

    ev = client.get("/accounts/org:contoso manufacturing/evidence").json()
    assert ev["items"][0]["provenance"]["observation_id"] == "e2e-1"
