"""HTTP API (M4) over a serving DB built from fixture account tables.

Seam: `fastapi.testclient.TestClient` over `create_app(build_serving_db(...))`.
Fixture tables follow the `docs/phase3-plan.md` accounts contract column for
column; every expected value below is hand-written from the fixture.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient

from firmable.accounts.rollup import ACCOUNTS_SCHEMA
from firmable.api.app import create_app
from firmable.api.store import build_serving_db, successor_ids

S, I32, I64, F64, B, TS = pa.string(), pa.int32(), pa.int64(), pa.float64(), pa.bool_(), pa.timestamp("us")
LS = pa.list_(pa.string())

ACCOUNT_SIGNALS_SCHEMA = pa.schema(
    [
        ("account_id", S), ("signal_id", S), ("family", S), ("n_services", I64), ("n_ips", I64),
        ("n_counted_services", I64), ("details", LS), ("sub_flags", LS),
        ("max_attribution_confidence", F64), ("contribution", F64),
    ]
)
# Column order as written by firmable.accounts.rollup (account_evidence COPY).
ACCOUNT_EVIDENCE_SCHEMA = pa.schema(
    [
        ("account_id", S), ("signal_id", S), ("signal_version", I32), ("family", S), ("snapshot_id", S),
        ("service_id", S), ("observation_id", S),
        ("ip", S), ("port", I32), ("transport", S), ("sni", S), ("observed_at", TS),
        ("is_cdn", B), ("country_code", S),
        ("product", S), ("version", S), ("http_title", S), ("module", S),
        ("match_basis", S), ("detail", S), ("sub_flags", LS), ("evidence_json", S),
        ("tier", S), ("attribution_confidence", F64), ("attribution_reasons", LS), ("counted", B),
        ("suppressed_by", S), ("attribution_version", I32), ("attribution_domains", LS),
        ("file_id", S), ("byte_offset", I64), ("byte_length", I32), ("record_sha256", S),
    ]
)

REGISTRY = [
    {
        "id": "S01", "version": 1, "name": "Remote access exposed", "family": "exposure",
        "observed_fact_template": "On {observed_at} UTC, {ip}:{port}/{transport} returned {detail} ({product} {version}).",
        "inferred_risk": "An interactive login surface is internet-reachable; this exposure class is commonly targeted.",
        "hypothesis": "This account may be evaluating ZTNA or remote-access hardening.",
        "infra_exposure": True,
    },
    {
        "id": "S03", "version": 1, "name": "Network security appliance exposed", "family": "exposure",
        "observed_fact_template": "On {observed_at} UTC, {ip}:{port} (SNI {sni}) served a {detail} page titled '{http_title}' via {module}.",
        "inferred_risk": "A perimeter appliance management or VPN portal is internet-reachable.",
        "hypothesis": "This account may be reviewing perimeter appliance lifecycle.",
        "infra_exposure": True,
    },
    {
        "id": "S06", "version": 1, "name": "TLS hygiene debt", "family": "hygiene",
        "observed_fact_template": "On {observed_at} UTC, {ip}:{port} presented TLS with: {sub_flags}.",
        "inferred_risk": "TLS configuration debt suggests certificate or protocol hygiene gaps.",
        "hypothesis": "This account may need certificate lifecycle tooling.",
        "infra_exposure": False,
    },
    {
        "id": "S16", "version": 1, "name": "Security vendor in use", "family": "technographic",
        "observed_fact_template": "On {observed_at} UTC, {ip}:{port} responded with {detail} fingerprints ({sub_flags}).",
        "inferred_risk": "A security product is already deployed on this surface.",
        "hypothesis": "This account may be open to a competitive or complementary product.",
        "infra_exposure": False,
    },
]


def _account(account_id, name, kind, tier, priority, rank, signals, details, countries, comps, n_services=1, n_ips=1,
             segment="enterprise", band="High", pct=99.5, ownership="high", eligibility="enigible", actionable=True,
             blockers=(), legacy_rank=None):
    pr, ss, ac, eq = comps
    return dict(
        account_id=account_id, account_name=name, account_kind=kind, segment=segment, best_tier=tier,
        n_services=n_services, n_ips=n_ips, signal_ids=signals, top_signals=signals[:3], details=details,
        countries=countries, product_relevance=pr, signal_strength=ss, opportunity_priority=priority,
        priority_percentile=pct, priority_band=band, rank=rank,
        eligibility="eligible" if eligibility == "enigible" else eligibility,
        eligibility_reasons=["registry_label_not_an_organisation"] if eligibility == "excluded" else [],
        ownership_confidence=ownership, ownership_reasons=["record_names_account"], review_flags=[],
        attribution_confidence=ac, ownership_services=n_services, named_public_services=1, named_rdns_services=0,
        third_party_domains=0, network_operators=1, subscriber_rdns_services=0,
        evidence_quality=eq, evidence_quality_band="high", actionable=actionable, actionable_blockers=list(blockers),
        legacy_score=round(priority * ac * eq, 4), legacy_rank=legacy_rank if legacy_rank is not None else rank,
        legacy_scoring_version=2, explanation=[f"{name}: rank {rank}"], scoring_version=3, eligibility_version=1,
    )


# Written deliberately out of rank order.
ACCOUNTS = [
    _account("dom:initech.io", "initech.io", "domain", "B", 12.5, 4, ["S01", "S03", "S16"],
             ["RDP", "Fortinet", "Cloudflare"], ["DE"], (0.3, 0.2, 0.4, 0.1), band="Low", pct=10.0),
    _account("org:example corp", "Example Corp", "org", "A1", 82.5, 1, ["S01", "S03"],
             ["RDP", "SonicWall"], ["AU"], (0.9, 0.8, 0.95, 0.7), n_services=3, n_ips=2),
    _account("org:globex:east", "Globex: East Division", "org", "A2", 40.0, 3, ["S16"],
             ["Cloudflare"], ["US"], (0.5, 0.4, 0.6, 0.3), band="Medium", pct=95.0, ownership="medium"),
    _account("dom:acme.com.au", "acme.com.au", "domain", "B", 61.0, 2, ["S01", "S06"],
             ["RDP", "legacy_tls"], ["AU", "NZ"], (0.7, 0.6, 0.5, 0.6), band="High", pct=99.0),
    # Eligible but only the IP registry names it: review queue, not the outreach list.
    _account("org:registry only", "Registry Only Ltd", "org", "A1", 30.0, 5, ["S01"], ["SonicWall"], ["AU"],
             (0.6, 0.5, 0.9, 1.0), band="Medium", pct=91.0, ownership="low", actionable=False,
             blockers=("ownership_low",)),
    # A pool label: excluded, unranked, still inspectable.
    _account("org:leased line customer lan", "Leased Line Customer LAN", "org", "A2", 90.0, None, ["S01", "S03"],
             ["SonicWall"], ["AU"], (0.9, 1.0, 0.85, 1.0), band=None, pct=None, ownership="low",
             eligibility="excluded", actionable=False, blockers=("excluded", "ownership_low"), legacy_rank=1),
    # A network provider's own infrastructure: separate segment, never in the default list.
    _account("net:skyway west", "Skyway West", "org", "P", 90.0, 1, ["S01"], ["SonicWall"], ["CA"],
             (0.8, 1.0, 0.8, 1.0), segment="network_provider"),
]

ACCOUNT_SIGNALS = [
    dict(account_id="org:example corp", signal_id="S01", family="exposure", n_services=2, n_ips=2,
         n_counted_services=2, details=["RDP"], sub_flags=[], max_attribution_confidence=0.95, contribution=30.0),
    dict(account_id="org:example corp", signal_id="S03", family="exposure", n_services=1, n_ips=1,
         n_counted_services=0, details=["SonicWall"], sub_flags=[], max_attribution_confidence=0.9, contribution=0.0),
    dict(account_id="dom:acme.com.au", signal_id="S06", family="hygiene", n_services=1, n_ips=1,
         n_counted_services=1, details=["legacy_tls"], sub_flags=["legacy_tls", "cert_expired"],
         max_attribution_confidence=0.5, contribution=10.0),
]

OBSERVED = datetime(2026, 11, 7, 14, 52, 1)


def _evidence(account_id, signal_id, n, **over):
    row = {f.name: None for f in ACCOUNT_EVIDENCE_SCHEMA}
    row.update(
        account_id=account_id, snapshot_id="2026-11-07", signal_id=signal_id, signal_version=1,
        family="exposure", service_id=f"svc{n}", observation_id=f"obs{n}", file_id="f" * 64,
        byte_offset=1000 * n, byte_length=900, record_sha256=f"{n:064d}", ip=f"192.0.2.{n}",
        port=3389, transport="tcp", sni="", observed_at=OBSERVED, is_cdn=False, country_code="AU",
        product="Remote Desktop Protocol", version="10.0", http_title=None, module="rdp",
        match_basis="protocol", detail="RDP", sub_flags=[], evidence_json="{}",
        tier="A1", attribution_confidence=0.95, attribution_reasons=["org_not_provider"], counted=True,
        attribution_version=1, attribution_domains=[],
    )
    row.update(over)
    return row


ACCOUNT_EVIDENCE = [
    _evidence("org:example corp", "S01", 1),
    _evidence("org:example corp", "S01", 2, port=3390),
    # Every optional field None: rendering must not crash nor print 'None'.
    _evidence("org:example corp", "S03", 3, port=443, sni=None, product=None, version=None,
              http_title=None, module=None, detail="SonicWall", match_basis="title", counted=False, suppressed_by="S01"),
    _evidence("dom:acme.com.au", "S06", 4, port=443, family="hygiene", detail=None, match_basis="tls",
              sub_flags=["legacy_tls", "cert_expired"], tier="B", attribution_confidence=0.5,
              attribution_reasons=["dom_cert_sni_agree"]),
]


@pytest.fixture(scope="module")
def accounts_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("accounts")
    pq.write_table(pa.Table.from_pylist(ACCOUNTS, schema=ACCOUNTS_SCHEMA), d / "accounts.parquet")
    pq.write_table(pa.Table.from_pylist(ACCOUNT_SIGNALS, schema=ACCOUNT_SIGNALS_SCHEMA), d / "account_signals.parquet")
    pq.write_table(pa.Table.from_pylist(ACCOUNT_EVIDENCE, schema=ACCOUNT_EVIDENCE_SCHEMA), d / "account_evidence.parquet")
    return d


@pytest.fixture(scope="module")
def serving_db(accounts_dir, tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("serving") / "2026-11-07.duckdb"
    build_serving_db(accounts_dir, REGISTRY, out, snapshot_id="2026-11-07")
    return out


@pytest.fixture(scope="module")
def client(serving_db) -> TestClient:
    with TestClient(create_app(serving_db)) as c:
        yield c


def ids(resp) -> list[str]:
    assert resp.status_code == 200, resp.text
    return [it["account_id"] for it in resp.json()["items"]]


# --- build -------------------------------------------------------------------


def test_build_reports_counts_and_publishes_atomically(accounts_dir, tmp_path):
    out = tmp_path / "s.duckdb"
    stats = build_serving_db(accounts_dir, REGISTRY, out, snapshot_id="2026-11-07")
    assert stats["accounts"] == 7
    assert stats["account_signals"] == 3
    assert stats["account_evidence"] == 4
    assert stats["signal_registry"] == 4
    assert out.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["s.duckdb"]  # no temp leftovers


# --- health / listing --------------------------------------------------------


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "snapshot_id": "2026-11-07", "n_accounts": 7}


def test_accounts_ranked_by_rank(client):
    assert ids(client.get("/accounts")) == [
        "org:example corp", "dom:acme.com.au", "org:globex:east", "dom:initech.io",
    ]


def test_account_item_shape(client):
    top = client.get("/accounts").json()["items"][0]
    assert top == {
        "account_id": "org:example corp",
        "account_name": "Example Corp",
        "account_kind": "org",
        "segment": "enterprise",
        "rank": 1,
        "priority": {
            "band": "High",
            "percentile": 99,
            "population": "eligible enterprise accounts",
            "value": 82.5,
            "product_relevance": 0.9,
            "signal_strength": 0.8,
            "note": "relative priority in this snapshot; not a purchase probability, confirmed vulnerability "
                    "or loss estimate",
        },
        "ownership": {
            "confidence": "high",
            "reasons": ["record_names_account"],
            "review_flags": [],
            "best_tier": "A1",
            "mean_attribution_confidence": 0.95,
            "services": 3,
            "named_public_services": 1,
            "named_rdns_services": 0,
            "third_party_domains": 0,
            "network_operators": 1,
        },
        "evidence": {"quality": "high", "mean_basis_quality": 0.7},
        "eligibility": {"status": "eligible", "reasons": []},
        "actionable": True,
        "actionable_blockers": [],
        "top_signals": [{"signal_id": "S01", "name": "Remote access exposed"},
                        {"signal_id": "S03", "name": "Network security appliance exposed"}],
        "signal_ids": ["S01", "S03"],
        "best_tier": "A1",
        "n_services": 3,
        "n_ips": 2,
        "countries": ["AU"],
        "details": ["RDP", "SonicWall"],
        "legacy": {
            "scoring_version": 2,
            "score": 54.8625,
            "rank": 1,
            "note": "scoring v2 composite (attribution and evidence quality multiplied in); comparison only",
        },
    }


def test_priority_and_ownership_are_separate_fields_with_no_bare_score(client):
    item = client.get("/accounts", params={"view": "all"}).json()["items"][0]
    assert "score" not in item and "components" not in item
    assert set(item["priority"]) >= {"band", "percentile", "value"}
    assert "confidence" in item["ownership"] and "confidence" not in item["priority"]


def test_views_split_outreach_review_and_excluded(client):
    assert ids(client.get("/accounts", params={"view": "review"})) == ["org:registry only"]
    body = client.get("/accounts", params={"view": "excluded"}).json()
    assert [(it["account_id"], it["rank"], it["priority"]["band"], it["priority"]["percentile"])
            for it in body["items"]] == [("org:leased line customer lan", None, None, None)]
    assert body["items"][0]["eligibility"] == {"status": "excluded",
                                               "reasons": ["registry_label_not_an_organisation"]}
    assert body["items"][0]["legacy"]["rank"] == 1
    # all: ranked accounts by rank, the unranked one last
    assert ids(client.get("/accounts", params={"view": "all"}))[-1] == "org:leased line customer lan"
    assert client.get("/accounts", params={"view": "everything"}).status_code == 422


def test_band_and_ownership_filters(client):
    assert ids(client.get("/accounts", params={"band": "High"})) == ["org:example corp", "dom:acme.com.au"]
    assert ids(client.get("/accounts", params={"ownership": "medium"})) == ["org:globex:east"]
    assert ids(client.get("/accounts", params={"view": "all", "ownership": "low"})) == [
        "org:registry only", "org:leased line customer lan"]
    assert client.get("/accounts", params={"band": "hot"}).status_code == 422


def test_network_provider_segment_is_only_served_when_selected(client):
    assert "net:skyway west" not in ids(client.get("/accounts", params={"limit": 200}))
    body = client.get("/accounts", params={"segment": "network_provider"}).json()
    assert [(it["account_id"], it["segment"], it["rank"]) for it in body["items"]] == \
        [("net:skyway west", "network_provider", 1)]
    assert client.get("/accounts", params={"segment": "everything"}).status_code == 422
    assert client.get("/accounts/net:skyway west").json()["segment"] == "network_provider"


def test_pagination_reports_total(client):
    body = client.get("/accounts", params={"limit": 2, "offset": 1}).json()
    assert body["total"] == 4
    assert body["limit"] == 2
    assert body["offset"] == 1
    assert [it["rank"] for it in body["items"]] == [2, 3]


def test_default_limit_is_50(client):
    assert client.get("/accounts").json()["limit"] == 50


@pytest.mark.parametrize("limit", [0, 201, 500])
def test_limit_is_capped(client, limit):
    assert client.get("/accounts", params={"limit": limit}).status_code == 422


def test_limit_200_allowed(client):
    assert client.get("/accounts", params={"limit": 200}).status_code == 200


def test_negative_offset_rejected(client):
    assert client.get("/accounts", params={"offset": -1}).status_code == 422


# --- search and filters ------------------------------------------------------


@pytest.mark.parametrize(
    ("q", "expected"),
    [
        ("globex", ["org:globex:east"]),            # name, case-insensitive
        ("EXAMPLE corp", ["org:example corp"]),     # name with space
        ("acme.com", ["dom:acme.com.au"]),          # id
        ("fortinet", ["dom:initech.io"]),           # details
        ("rdp", ["org:example corp", "dom:acme.com.au", "dom:initech.io"]),  # details, rank order
        ("%", []),                                  # literal, not a LIKE wildcard
        ("_", ["dom:acme.com.au"]),                # only "legacy_tls" holds a literal "_"
    ],
)
def test_q_search(client, q, expected):
    assert ids(client.get("/accounts", params={"q": q})) == expected


@pytest.mark.parametrize(
    "q", ["'; DROP TABLE accounts; --", "\" OR 1=1 --", "') OR ('1'='1", "x' UNION SELECT * FROM meta --"]
)
def test_injection_like_q_is_a_literal(client, q):
    r = client.get("/accounts", params={"q": q})
    assert r.status_code == 200
    assert r.json()["total"] == 0
    assert client.get("/health").json()["n_accounts"] == 7


def test_signal_filter_requires_all_signals(client):
    assert ids(client.get("/accounts", params=[("signal", "S01"), ("signal", "S03")])) == [
        "org:example corp", "dom:initech.io",
    ]
    assert ids(client.get("/accounts", params={"signal": "S16"})) == ["org:globex:east", "dom:initech.io"]
    assert ids(client.get("/accounts", params=[("signal", "S06"), ("signal", "S16")])) == []


def test_tier_filter_is_any_of(client):
    assert ids(client.get("/accounts", params={"tier": "B"})) == ["dom:acme.com.au", "dom:initech.io"]
    assert ids(client.get("/accounts", params=[("tier", "A1"), ("tier", "A2")])) == [
        "org:example corp", "org:globex:east",
    ]


def test_country_filter_is_any_of(client):
    assert ids(client.get("/accounts", params={"country": "NZ"})) == ["dom:acme.com.au"]
    assert ids(client.get("/accounts", params={"country": "au"})) == ["org:example corp", "dom:acme.com.au"]
    assert ids(client.get("/accounts", params=[("country", "US"), ("country", "DE")])) == [
        "org:globex:east", "dom:initech.io",
    ]


def test_min_priority_is_inclusive(client):
    assert ids(client.get("/accounts", params={"min_priority": 40})) == [
        "org:example corp", "dom:acme.com.au", "org:globex:east",
    ]


def test_filters_combine_and_total_counts_all_matches(client):
    body = client.get("/accounts", params={"signal": "S01", "country": "AU", "limit": 1}).json()
    assert body["total"] == 2
    assert [it["account_id"] for it in body["items"]] == ["org:example corp"]


# --- signals registry --------------------------------------------------------


def test_signals_lists_registry_with_labelled_wording(client):
    body = client.get("/signals").json()
    assert [s["id"] for s in body["signals"]] == ["S01", "S03", "S06", "S16"]
    s01 = body["signals"][0]
    assert s01["name"] == "Remote access exposed"
    assert s01["family"] == "exposure"
    assert s01["infra_exposure"] is True
    assert s01["inferred_risk"] == REGISTRY[0]["inferred_risk"]
    assert s01["hypothesis"] == REGISTRY[0]["hypothesis"]
    assert set(body["labels"]) == {"observed_fact", "inferred_risk", "hypothesis"}
    assert "hypothesis" in body["labels"]["hypothesis"].lower()
    assert "unverified" in body["labels"]["hypothesis"].lower()


# --- account detail ----------------------------------------------------------


def _path(account_id: str, suffix: str = "") -> str:
    return "/accounts/" + quote(account_id, safe=":") + suffix


def test_account_detail_with_space_in_id(client):
    r = client.get(_path("org:example corp"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["account_id"] == "org:example corp"
    assert body["account_name"] == "Example Corp"
    assert body["rank"] == 1
    assert body["priority"]["value"] == 82.5
    assert body["ownership"]["mean_attribution_confidence"] == 0.95
    assert body["explanation"] == ["Example Corp: rank 1"]
    assert (body["scoring_version"], body["eligibility_version"]) == (3, 1)
    assert [s["signal_id"] for s in body["signals"]] == ["S01", "S03"]  # contribution desc
    s01 = body["signals"][0]
    assert s01 == {
        "signal_id": "S01",
        "name": "Remote access exposed",
        "family": "exposure",
        "n_services": 2,
        "n_ips": 2,
        "n_counted_services": 2,
        "details": ["RDP"],
        "sub_flags": [],
        "max_attribution_confidence": 0.95,
        "contribution": 30.0,
        "inferred_risk": REGISTRY[0]["inferred_risk"],
        "hypothesis": REGISTRY[0]["hypothesis"],
    }
    disclaimer = body["disclaimer"].lower()
    assert "not a purchase probability" in disclaimer
    assert "relative priority" in disclaimer
    assert "inferred" in disclaimer


def test_account_detail_with_colons_in_id(client):
    r = client.get(_path("org:globex:east"))
    assert r.status_code == 200, r.text
    assert r.json()["account_name"] == "Globex: East Division"
    assert r.json()["signals"] == []  # no account_signals rows in the fixture


def test_account_detail_404(client):
    assert client.get(_path("org:nope")).status_code == 404
    assert client.get(_path("org:example")).status_code == 404  # prefix is not a match


# --- old account ids (attribution v4 -> v5) -----------------------------------


def test_successor_ids_fold_accents_and_swap_org_and_net_only():
    assert successor_ids("org:Exámple Corp") == ["org:example corp", "net:Exámple Corp", "net:example corp"]
    assert successor_ids("net:skyway west") == ["org:skyway west"]
    assert successor_ids("dom:exámple.com") == ["dom:example.com"]  # never another prefix for a domain
    assert successor_ids("dom:example.com") == []
    assert successor_ids("example corp") == [] and successor_ids("xyz:a") == []


def test_old_accented_id_redirects_to_its_folded_successor(client):
    r = client.get(_path("org:exámple corp"), follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/accounts/org:example%20corp"
    r = client.get(_path("org:exámple corp"))
    assert r.status_code == 200 and r.json()["account_id"] == "org:example corp"


def test_old_org_id_redirects_to_provider_reclassified_successor(client):
    r = client.get(_path("org:skyway west"), follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/accounts/net:skyway%20west"
    assert client.get(_path("org:skyway west")).json()["segment"] == "network_provider"


def test_old_id_evidence_redirect_keeps_query(client):
    r = client.get(_path("org:exámple corp", "/evidence") + "?limit=1&offset=1", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/accounts/org:example%20corp/evidence?limit=1&offset=1"
    body = client.get(_path("org:exámple corp", "/evidence") + "?limit=1").json()
    assert body["account_id"] == "org:example corp" and len(body["items"]) == 1


def test_ids_without_successor_still_404(client):
    for aid in ("org:nope", "org:example", "dom:skyway west", "org:exámple"):
        assert client.get(_path(aid), follow_redirects=False).status_code == 404, aid
        assert client.get(_path(aid, "/evidence"), follow_redirects=False).status_code == 404, aid


@pytest.fixture(scope="module")
def odd_client(tmp_path_factory):
    """Ids with URL-special characters, and an id that ends in `/evidence`."""
    accounts = [
        _account(aid, aid, "org", "A1", 50.0 - i, i + 1, ["S01"], ["RDP"], ["AU"], (0.5, 0.5, 0.5, 0.5))
        for i, aid in enumerate(["org:a/b + c? #1 100%", "org:x/evidence", "org:é/evidence", "org:e"])
    ]
    d = tmp_path_factory.mktemp("odd")
    pq.write_table(pa.Table.from_pylist(accounts, schema=ACCOUNTS_SCHEMA), d / "accounts.parquet")
    pq.write_table(pa.Table.from_pylist([], schema=ACCOUNT_SIGNALS_SCHEMA), d / "account_signals.parquet")
    pq.write_table(pa.Table.from_pylist([], schema=ACCOUNT_EVIDENCE_SCHEMA), d / "account_evidence.parquet")
    out = d / "s.duckdb"
    build_serving_db(d, REGISTRY, out, snapshot_id="2026-11-07")
    with TestClient(create_app(out)) as c:
        yield c


@pytest.mark.parametrize("suffix", ["", "/evidence"])
def test_redirect_quotes_url_special_characters(odd_client, suffix):
    r = odd_client.get(_path("org:á/b + c? #1 100%", suffix) + "?limit=5", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/accounts/org:a%2Fb%20%2B%20c%3F%20%231%20100%25" + suffix + "?limit=5"
    r = odd_client.get(_path("org:á/b + c? #1 100%", suffix))
    assert r.status_code == 200 and r.json()["account_id"] == "org:a/b + c? #1 100%"


def test_evidence_suffix_never_redirects_to_another_account(odd_client):
    # `/accounts/org:x/evidence/evidence` is evidence of `org:x/evidence`; `/accounts/org:x/evidence`
    # reads as evidence of `org:x`, which is missing: it must not 307 to some successor of `org:x`.
    assert odd_client.get(_path("org:x/evidence", "/evidence")).json()["account_id"] == "org:x/evidence"
    assert odd_client.get(_path("org:x", "/evidence"), follow_redirects=False).status_code == 404
    # `org:é` is missing and folds to `org:e`, but the full path is the existing `org:é/evidence`:
    # a redirect to `org:e`'s evidence would serve the wrong account.
    assert odd_client.get(_path("org:é", "/evidence"), follow_redirects=False).status_code == 404


# --- evidence ----------------------------------------------------------------


def test_evidence_rows_render_fact_and_carry_provenance(client):
    body = client.get(_path("org:example corp", "/evidence")).json()
    assert body["total"] == 3
    assert [e["observation_id"] for e in body["items"]] == ["obs1", "obs2", "obs3"]
    first = body["items"][0]
    assert first["signal_id"] == "S01"
    assert first["signal_name"] == "Remote access exposed"
    assert first["observed_fact"] == (
        "On 2026-11-07 14:52 UTC, 192.0.2.1:3389/tcp returned RDP (Remote Desktop Protocol 10.0)."
    )
    assert first["inferred_risk"] == REGISTRY[0]["inferred_risk"]
    assert first["hypothesis"] == REGISTRY[0]["hypothesis"]
    assert first["provenance"] == {
        "observation_id": "obs1",
        "file_id": "f" * 64,
        "byte_offset": 1000,
        "byte_length": 900,
        "record_sha256": f"{1:064d}",
    }
    assert first["service"] == {
        "service_id": "svc1",
        "ip": "192.0.2.1",
        "port": 3389,
        "transport": "tcp",
        "sni": "",
        "observed_at": "2026-11-07T14:52:01Z",
        "country_code": "AU",
        "is_cdn": False,
        "product": "Remote Desktop Protocol",
        "version": "10.0",
        "http_title": None,
        "module": "rdp",
    }
    assert first["match_basis"] == "protocol"
    assert first["detail"] == "RDP"
    assert first["sub_flags"] == []
    assert first["tier"] == "A1"
    assert first["attribution_confidence"] == 0.95
    assert first["attribution_reasons"] == ["org_not_provider"]
    assert first["counted"] is True
    assert first["suppressed_by"] is None
    assert (first["attribution_version"], first["attribution_domains"]) == (1, [])
    assert "evidence_json" not in first  # raw fields stay behind human review
    assert set(body["labels"]) == {"observed_fact", "inferred_risk", "hypothesis"}


def test_evidence_with_none_fields_renders_without_none(client):
    body = client.get(_path("org:example corp", "/evidence"), params={"signal": "S03"}).json()
    assert body["total"] == 1
    row = body["items"][0]
    assert row["counted"] is False
    assert row["suppressed_by"] == "S01"
    assert row["observed_fact"] == (
        "On 2026-11-07 14:52 UTC, 192.0.2.3:443 (SNI —) served a SonicWall page titled '—' via —."
    )
    assert "None" not in row["observed_fact"]


def test_evidence_list_fields_render_as_text(client):
    row = client.get(_path("dom:acme.com.au", "/evidence")).json()["items"][0]
    assert row["observed_fact"] == "On 2026-11-07 14:52 UTC, 192.0.2.4:443 presented TLS with: legacy_tls, cert_expired."
    assert row["tier"] == "B"


def test_evidence_pagination_and_cap(client):
    body = client.get(_path("org:example corp", "/evidence"), params={"limit": 1, "offset": 1}).json()
    assert body["total"] == 3
    assert [e["observation_id"] for e in body["items"]] == ["obs2"]
    assert client.get(_path("org:example corp", "/evidence"), params={"limit": 201}).status_code == 422


def test_evidence_for_account_without_rows_and_404(client):
    body = client.get(_path("org:globex:east", "/evidence")).json()
    assert (body["total"], body["items"]) == (0, [])
    assert client.get(_path("org:nope", "/evidence")).status_code == 404


# --- UI and entry points -----------------------------------------------------


def test_index_serves_salesperson_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    html = r.text
    assert '<meta name="viewport"' in html
    assert "not a purchase probability" in html
    for label in ("Observed fact", "Inferred risk", "Hypothesis"):
        assert label in html
    assert "suppressed_by" in html  # correlated duplicates are explained in the evidence view


def test_module_app_is_built_from_env(serving_db, monkeypatch):
    import importlib

    import firmable.api.app as app_module

    monkeypatch.setenv("FIRMABLE_SERVING_DB", str(serving_db))
    module = importlib.reload(app_module)
    with TestClient(module.app) as c:
        assert c.get("/health").json()["n_accounts"] == 7


def test_create_app_without_db_fails_clearly(monkeypatch, tmp_path):
    monkeypatch.delenv("FIRMABLE_SERVING_DB", raising=False)
    with pytest.raises(RuntimeError, match="FIRMABLE_SERVING_DB"):
        create_app()
    with pytest.raises(FileNotFoundError):
        create_app(tmp_path / "missing.duckdb")


def test_app_refuses_a_serving_db_from_an_older_contract(serving_db, tmp_path):
    import shutil

    import duckdb

    old = tmp_path / "old.duckdb"
    shutil.copy(serving_db, old)
    con = duckdb.connect(str(old))
    con.execute("UPDATE meta SET serving_version = 1")
    con.close()
    with pytest.raises(RuntimeError, match="serving_version 1"):
        create_app(old)


# --- accent-insensitive search (attribution v5 folding) ----------------------


def test_q_search_ignores_accents_both_ways(tmp_path):
    accounts = [
        _account("org:telefonica chile", "TELEFÓNICA CHILE S.A.", "org", "A2", 50.0, 1, ["S01"], ["RDP"], ["CL"],
                 (0.5, 0.5, 0.5, 0.5)),
        _account("org:universitat zurich", "Universitat Zurich", "org", "A1", 40.0, 2, ["S01"], ["RDP"], ["CH"],
                 (0.5, 0.5, 0.5, 0.5)),
        _account("org:istanbul teknik", "İSTANBUL TEKNİK ÜNİVERSİTESİ", "org", "A1", 30.0, 3, ["S01"], ["RDP"], ["TR"],
                 (0.5, 0.5, 0.5, 0.5)),
    ]
    d = tmp_path / "acc"
    d.mkdir()
    pq.write_table(pa.Table.from_pylist(accounts, schema=ACCOUNTS_SCHEMA), d / "accounts.parquet")
    pq.write_table(pa.Table.from_pylist([], schema=ACCOUNT_SIGNALS_SCHEMA), d / "account_signals.parquet")
    pq.write_table(pa.Table.from_pylist([], schema=ACCOUNT_EVIDENCE_SCHEMA), d / "account_evidence.parquet")
    out = tmp_path / "s.duckdb"
    build_serving_db(d, REGISTRY, out, snapshot_id="2026-11-07")
    with TestClient(create_app(out)) as c:
        assert ids(c.get("/accounts", params={"q": "telefonica"})) == ["org:telefonica chile"]
        assert ids(c.get("/accounts", params={"q": "Telefónica"})) == ["org:telefonica chile"]
        assert ids(c.get("/accounts", params={"q": "zürich"})) == ["org:universitat zurich"]
        assert ids(c.get("/accounts", params={"q": "istanbul teknik"})) == ["org:istanbul teknik"]
        assert ids(c.get("/accounts", params={"q": "İstanbul"})) == ["org:istanbul teknik"]
