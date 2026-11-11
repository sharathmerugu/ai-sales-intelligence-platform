"""Privacy and access regression tests for the public deployment.

NTLM policy (docs/decisions/0007-ntlm-restricted-evidence-and-public-db.md):
- internal AD domains and hostnames never appear in any public API response;
- NTLM alone never creates a prospect account;
- the public serving DB keeps observation_id + record_sha256 but drops raw file offsets.

Seam: the whole vertical slice (banners -> build_phase3 -> publish_public_db -> HTTP API).
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import duckdb
import pytest
from fastapi.testclient import TestClient

from firmable.api.app import create_app
from firmable.api.publish import publish_public_db
from firmable.ingest.pipeline import Pipeline
from firmable.phase3 import build_phase3
from firmable.transform.services import build_services

from factories import BASE, line

RDP = "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00"

# Internal names that must never leave the internal layers.
SECRETS = (
    "corp.acme-energy.com", "acme-energy", "ACMEENERGY", "rdp01.corp.acme-energy.com",
    "ad.globex-mining.com", "GLOBEXAD", "dc7.ad.globex-mining.com",
)


def _sh(n):
    return {**BASE["_shodan"], "id": f"priv-{n}", "module": "rdp", "options": {}}


def _cert(cn):
    return {"cert": {"expired": False, "expires": "20270101120000Z", "issued": "20260101120000Z",
                     "subject": {"CN": cn}, "issuer": {"CN": "Example CA", "O": "Example CA Inc"},
                     "sig_alg": "sha256WithRSAEncryption", "pubkey": {"type": "rsa", "bits": 2048},
                     "fingerprint": {"sha256": "cd" * 32}, "extensions": []},
            "versions": ["TLSv1.2"]}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("privacy")
    p = Pipeline(tmp / "work")
    src = tmp / "s1.jsonl"
    src.write_bytes(b"".join([
        # RDP on a hoster, named only by NTLM: restricted, must abstain.
        line(_shodan=_sh(1), ip_str="198.51.100.20", port=3389, org="DigitalOcean, LLC", isp="DigitalOcean, LLC",
             hostnames=[], domains=[], data=RDP,
             ntlm={"dns_domain_name": "corp.acme-energy.com", "netbios_domain_name": "ACMEENERGY",
                   "fqdn": "rdp01.corp.acme-energy.com", "os_build": "10.0.17763"}),
        # RDP on a hoster, NTLM corroborated by the public certificate: account on the public domain only.
        line(_shodan=_sh(2), ip_str="198.51.100.21", port=3389, org="DigitalOcean, LLC", isp="DigitalOcean, LLC",
             hostnames=[], domains=[], data=RDP, ssl=_cert("rdp.globex-mining.com"),
             ntlm={"dns_domain_name": "ad.globex-mining.com", "netbios_domain_name": "GLOBEXAD",
                   "fqdn": "dc7.ad.globex-mining.com", "os_build": "10.0.17763"}),
    ]))
    p.register(src, snapshot_id="s1")
    p.run(workers=1)
    build_services(p, "s1")
    p.seal("s1")
    result = build_phase3(p, "s1")
    public = tmp / "public.duckdb"
    publish_public_db(result["serving"]["path"], public)
    return result, public


def _crawl(client: TestClient) -> list[str]:
    bodies = []
    for path in ("/", "/health", "/signals", "/openapi.json", "/accounts", "/accounts?q=acme", "/accounts?q=globex"):
        r = client.get(path)
        assert r.status_code == 200, path
        bodies.append(r.text)
    for item in client.get("/accounts?limit=200").json()["items"]:
        aid = quote(item["account_id"], safe=":")
        for path in (f"/accounts/{aid}", f"/accounts/{aid}/evidence?limit=200"):
            r = client.get(path)
            assert r.status_code == 200, path
            bodies.append(r.text)
    return bodies


def test_ntlm_only_service_creates_no_account(built):
    _, public = built
    client = TestClient(create_app(public))
    ids = [a["account_id"] for a in client.get("/accounts").json()["items"]]
    assert ids == ["dom:globex-mining.com"]


def test_no_internal_ntlm_name_in_any_public_response(built):
    _, public = built
    bodies = "\n".join(_crawl(TestClient(create_app(public)))).lower()
    for secret in SECRETS:
        assert secret.lower() not in bodies, secret
    # not even the fact that a domain is also an internal AD domain
    assert "ntlm" not in bodies


def test_public_db_keeps_trace_ids_but_drops_raw_offsets(built):
    _, public = built
    ev = TestClient(create_app(public)).get("/accounts/dom:globex-mining.com/evidence").json()["items"][0]
    prov = ev["provenance"]
    assert prov["observation_id"] == "priv-2" and len(prov["record_sha256"]) == 64
    assert (prov["file_id"], prov["byte_offset"], prov["byte_length"]) == (None, None, None)
    con = duckdb.connect(str(public), read_only=True)
    assert con.execute("SELECT profile FROM meta").fetchone()[0] == "public"
    cols = {c for (c,) in con.execute("SELECT column_name FROM information_schema.columns").fetchall()}
    assert not {c for c in cols if "ntlm" in c or c == "evidence_json"}


def test_publish_refuses_attribution_before_ntlm_policy(tmp_path, built):
    result, _ = built
    src = tmp_path / "old.duckdb"
    con = duckdb.connect(str(src))
    con.execute(f"ATTACH '{result['serving']['path']}' AS s (READ_ONLY)")
    for t in ("accounts", "account_signals", "account_evidence", "signal_registry", "meta"):
        con.execute(f"CREATE TABLE {t} AS SELECT * FROM s.{t}")
    con.execute("UPDATE account_evidence SET attribution_version = 1")
    con.close()
    with pytest.raises(ValueError, match="attribution_version"):
        publish_public_db(src, tmp_path / "out.duckdb")


# --------------------------------------------------------------------------- access controls
def _auth(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def test_basic_auth_protects_everything_but_health(built):
    _, public = built
    client = TestClient(create_app(public, basic_auth="review:s3cret"))
    assert client.get("/health").status_code == 200
    for path in ("/", "/accounts", "/signals", "/openapi.json", "/docs", "/accounts/dom:globex-mining.com/evidence"):
        r = client.get(path)
        assert r.status_code == 401, path
        assert r.headers["www-authenticate"].startswith("Basic")
    assert client.get("/accounts", headers=_auth("review", "wrong")).status_code == 401
    assert client.get("/accounts", headers=_auth("review", "s3cret")).status_code == 200


def test_require_auth_refuses_to_start_without_credentials(built):
    _, public = built
    with pytest.raises(RuntimeError, match="FIRMABLE_BASIC_AUTH"):
        create_app(public, require_auth=True)


def test_forwarded_headers_are_ignored_unless_the_proxy_is_trusted(built):
    _, public = built
    client = TestClient(create_app(public, rate_limit_per_minute=2))
    codes = [client.get("/accounts", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]          # one real client, however many spoofed addresses


def test_behind_the_proxy_only_the_hop_it_appended_names_the_client(built):
    # clients can send any X-Real-IP or X-Forwarded-For; the edge appends the address it saw last
    _, public = built
    client = TestClient(create_app(public, rate_limit_per_minute=2, rate_limit_key="forwarded"))
    codes = [client.get("/accounts", headers={"X-Real-IP": f"198.51.100.{i}",
                                              "X-Forwarded-For": f"198.51.100.{i}, 203.0.113.5"}).status_code
             for i in range(3)]
    assert codes == [200, 200, 429]


@pytest.mark.parametrize("mode, expected", [("peer", "10.0.0.7"), ("forwarded", "203.0.113.5"), ("global", "*")])
def test_rate_limit_key_modes(mode, expected):
    # Railway: neither forwarded header nor the TCP peer identifies a client (measured), so the
    # image uses one global budget that no header can split.
    from starlette.requests import Request
    from firmable.api.app import _client_key
    req = Request({"type": "http", "headers": [(b"x-forwarded-for", b"198.51.100.9, 203.0.113.5"),
                                               (b"x-real-ip", b"198.51.100.9")],
                   "client": ("10.0.0.7", 5000)})
    assert _client_key(req, mode) == expected


def test_unknown_rate_limit_key_is_refused(built):
    _, public = built
    with pytest.raises(RuntimeError, match="FIRMABLE_RATE_LIMIT_KEY"):
        create_app(public, rate_limit_per_minute=5, rate_limit_key="cookie")


def test_rate_limiter_overflow_does_not_reset_existing_clients():
    from firmable.api.app import RateLimiter
    lim = RateLimiter(per_minute=1, max_keys=2)
    assert lim.allow("a", now=0.0) and not lim.allow("a", now=1.0)
    assert lim.allow("b", now=2.0)
    assert not lim.allow("c", now=3.0)      # table full of live clients: new keys wait
    assert not lim.allow("a", now=4.0)      # "a" is still limited
    assert lim.allow("c", now=61.0)         # stale keys expire


def test_rate_limit_returns_429_per_client(built):
    _, public = built
    client = TestClient(create_app(public, rate_limit_per_minute=3, rate_limit_key="forwarded"))
    codes = [client.get("/accounts", headers={"X-Forwarded-For": "203.0.113.5"}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert client.get("/accounts", headers={"X-Forwarded-For": "203.0.113.6"}).status_code == 200
    assert client.get("/health", headers={"X-Forwarded-For": "203.0.113.5"}).status_code == 200


def test_api_responses_are_not_cached_or_indexed(built):
    _, public = built
    r = TestClient(create_app(public)).get("/accounts")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-robots-tag"] == "noindex, nofollow"
    assert r.headers["x-content-type-options"] == "nosniff"
