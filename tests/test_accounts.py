"""Account roll-up v1: signal hits + service attribution -> accounts, account_signals, account_evidence.

Inputs are contract-shaped Parquet files (docs/phase3-plan.md); expected values
are worked by hand.
"""

from __future__ import annotations

import itertools
from datetime import datetime

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from firmable.accounts import build_accounts

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

FAMILY = {"S01": "exposure", "S03": "exposure", "S04": "exposure", "S05": "exposure",
          "S06": "hygiene", "S16": "technographic"}
_n = itertools.count(1)


def hit(signal_id, service_id, ip="192.0.2.1", port=443, match_basis="product", detail="SonicWall",
        sub_flags=(), country_code="AU"):
    n = next(_n)
    return dict(snapshot_id="s1", signal_id=signal_id, signal_version=1, family=FAMILY[signal_id],
                service_id=service_id, observation_id=f"obs-{n}", file_id="f" * 64, byte_offset=n * 100,
                byte_length=90, record_sha256=f"{n:064d}", ip=ip, port=port, transport="tcp", sni="",
                observed_at=datetime(2026, 11, 7, 14, 52), is_cdn=False, country_code=country_code,
                product=detail, version=None, http_title=None, module="https", match_basis=match_basis,
                detail=detail, sub_flags=list(sub_flags), evidence_json="{}")


def attr(service_id, tier="A1", account_id="org:example", account_name="Example Corp", confidence=0.9,
         allows_infra_signals=True, isp="Example Corp"):
    return dict(snapshot_id="s1", service_id=service_id, attribution_version=1, tier=tier,
                account_id=account_id if tier != "C" else None,
                account_name=account_name if tier != "C" else None,
                confidence=confidence if tier != "C" else 0.0, confidence_band="high",
                reasons=[], candidate_domains=[], allows_infra_signals=allows_infra_signals,
                org=account_name, isp=isp, org_class="business")


EVIDENCE_SCHEMA = pa.schema([
    ("snapshot_id", S), ("service_id", S), ("source", S), ("raw_name", S), ("name", S), ("reg_domain", S),
    ("outcome", S), ("attribution_version", I32),
])
SERVICES_SCHEMA = pa.schema([("service_id", S), ("cert_subject_o", S)])


def name_ev(service_id, source, name, outcome="accepted"):
    """One attribution-evidence row: a name on the service's own record."""
    reg = ".".join(name.split(".")[-2:])
    return dict(snapshot_id="s1", service_id=service_id, source=source, raw_name=name, name=name,
                reg_domain=reg, outcome=outcome, attribution_version=4)


@pytest.fixture
def build(tmp_path):
    def _build(hits, attrs, evidence=None, services=None):
        hp, ap = tmp_path / "signal_hits.parquet", tmp_path / "service_attribution.parquet"
        ep, sp = tmp_path / "evidence.parquet", tmp_path / "services.parquet"
        pq.write_table(pa.Table.from_pylist(hits, schema=HITS_SCHEMA), hp)
        pq.write_table(pa.Table.from_pylist(attrs, schema=ATTR_SCHEMA), ap)
        pq.write_table(pa.Table.from_pylist(evidence or [], schema=EVIDENCE_SCHEMA), ep)
        pq.write_table(pa.Table.from_pylist(services or [], schema=SERVICES_SCHEMA), sp)
        out = tmp_path / "accounts"
        result = build_accounts(hp, ap, out, attribution_evidence_parquet=ep, services_parquet=sp)
        con = duckdb.connect()
        tables = {name: con.sql(f"SELECT * FROM read_parquet('{out / (name + '.parquet')}') ORDER BY ALL").to_arrow_table().to_pylist()
                  for name in ("accounts", "account_signals", "account_evidence")}
        return result, tables
    return _build


def test_owned_gateway_becomes_a_ranked_account_and_tier_c_contributes_nothing(build):
    _, t = build(
        hits=[hit("S01", "svc-a"), hit("S03", "svc-c", ip="198.51.100.7", detail="RDP")],
        attrs=[attr("svc-a"), attr("svc-c", tier="C")],
    )
    assert [a["account_id"] for a in t["accounts"]] == ["org:example"]
    row = t["accounts"][0]
    assert row["rank"] == 1
    assert row["legacy_score"] == pytest.approx(36.0)  # 100 * 0.80 * 0.50 * 0.90 * 1.0
    assert row["opportunity_priority"] == pytest.approx(40.0)  # 100 * 0.80 * 0.50
    assert row["signal_ids"] == ["S01"]
    assert len(t["account_evidence"]) == 1


def _by(rows, *keys):
    return {tuple(r[k] for k in keys) if len(keys) > 1 else r[keys[0]]: r for r in rows}


def test_db_and_console_on_one_service_count_as_one_exposure(build):
    # MinIO: S04 (product) and S05 (console title) on the same service.
    _, t = build(hits=[hit("S04", "svc-m", detail="MinIO"), hit("S05", "svc-m", match_basis="title", detail="MinIO Console")],
                 attrs=[attr("svc-m")])
    ev = _by(t["account_evidence"], "signal_id")
    assert ev["S04"]["counted"] is True
    assert ev["S05"]["counted"] is False and ev["S05"]["suppressed_by"] == "S04"
    acc = t["accounts"][0]
    assert acc["signal_ids"] == ["S04", "S05"]  # both facts stay visible
    assert acc["product_relevance"] == pytest.approx(0.65)  # only S04 counts
    assert acc["legacy_score"] == pytest.approx(29.25)  # 100 * 0.65 * 0.50 * 0.90 * 1.0


def test_appliance_technographic_on_a_gateway_is_not_double_counted_but_a_waf_is(build):
    _, t = build(
        hits=[hit("S01", "svc-g", detail="FortiGate"), hit("S16", "svc-g", detail="FortiGate", sub_flags=["appliance"]),
              hit("S16", "svc-w", ip="192.0.2.9", match_basis="waf", detail="Cloudflare", sub_flags=["waf"])],
        attrs=[attr("svc-g"), attr("svc-w")])
    ev = _by(t["account_evidence"], "signal_id", "service_id")
    assert ev[("S16", "svc-g")]["counted"] is False
    assert ev[("S16", "svc-g")]["suppressed_by"] == "S01"
    assert ev[("S16", "svc-w")]["counted"] is True
    sig = _by(t["account_signals"], "signal_id")
    assert (sig["S16"]["n_services"], sig["S16"]["n_counted_services"]) == (2, 1)


def test_tenant_without_strong_evidence_gets_hygiene_but_not_infrastructure_exposure(build):
    result, t = build(
        hits=[hit("S01", "svc-b", detail="SonicWall"), hit("S06", "svc-b", match_basis="tls", detail="TLS",
                                                           sub_flags=["cert_expired"])],
        attrs=[attr("svc-b", tier="B", account_id="dom:example.com", account_name="example.com",
                    confidence=0.3, allows_infra_signals=False)])
    assert [r["signal_id"] for r in t["account_evidence"]] == ["S06"]
    acc = t["accounts"][0]
    assert (acc["account_id"], acc["account_kind"], acc["best_tier"]) == ("dom:example.com", "domain", "B")
    # 100 * 0.20 * 0.50 * 0.30 * 0.90 = 2.70
    assert acc["legacy_score"] == pytest.approx(2.70)
    assert acc["opportunity_priority"] == pytest.approx(10.0)  # 100 * 0.20 * 0.50
    assert (acc["ownership_confidence"], acc["actionable"]) == ("low", False)
    assert result["exposure_rows_blocked_by_attribution"] == 1


def test_ranking_is_by_priority_then_breadth_then_id_and_name_is_the_majority_name(build):
    _, t = build(
        hits=[hit("S03", "a1", ip="192.0.2.1"), hit("S03", "b1", ip="192.0.2.2"),
              hit("S03", "c1", ip="192.0.2.3"), hit("S01", "d1", ip="192.0.2.4")],
        attrs=[attr("a1", account_id="org:zeta", account_name="Zeta Ltd"),
               attr("b1", account_id="org:alpha", account_name="Alpha Inc"),
               attr("c1", account_id="org:alpha", account_name="ALPHA INC."),
               attr("d1", account_id="org:alpha", account_name="Alpha Inc")])
    ranked = sorted(t["accounts"], key=lambda r: r["rank"])
    assert [r["account_id"] for r in ranked] == ["org:alpha", "org:zeta"]
    assert ranked[0]["account_name"] == "Alpha Inc"
    assert ranked[0]["n_ips"] == 3
    assert any("S01 Remote-access gateway / SSL-VPN / firewall portal identified: 1 service(s) on 1 IP(s)" in line for line in ranked[0]["explanation"])
    assert "Not a purchase probability" in ranked[0]["explanation"][0]
    assert "confirmed vulnerability" in ranked[0]["explanation"][0]


def test_evidence_rows_carry_observation_provenance(build):
    h = hit("S01", "svc-p")
    _, t = build(hits=[h], attrs=[attr("svc-p")])
    ev = t["account_evidence"][0]
    for k in ("observation_id", "file_id", "byte_offset", "byte_length", "record_sha256", "observed_at"):
        assert ev[k] == h[k]
    assert (ev["tier"], ev["attribution_confidence"]) == ("A1", 0.9)
    # The attribution rules and the names they accepted travel with the claim.
    assert (ev["attribution_version"], ev["attribution_domains"]) == (1, [])


def test_confidence_and_quality_average_per_service_not_per_evidence_row(build):
    # svc-a: S01 matched on title only (0.7), attribution 0.9.
    # svc-b: S06 (tls 0.9) and S16 (waf 0.9) on one service, attribution 0.5.
    # Per service: quality (0.7 + 0.9) / 2 = 0.80; confidence (0.9 + 0.5) / 2 = 0.70.
    # (Per row would give 0.833 and 0.633: the two-signal service would count twice.)
    _, t = build(
        hits=[hit("S01", "svc-a", match_basis="title"),
              hit("S06", "svc-b", ip="192.0.2.2", match_basis="tls", detail="TLS", sub_flags=["cert_expired"]),
              hit("S16", "svc-b", ip="192.0.2.2", match_basis="waf", detail="Cloudflare", sub_flags=["waf"])],
        attrs=[attr("svc-a", confidence=0.9), attr("svc-b", confidence=0.5)])
    acc = t["accounts"][0]
    assert acc["evidence_quality"] == pytest.approx(0.80)
    assert acc["attribution_confidence"] == pytest.approx(0.70)


def test_network_providers_are_a_separate_segment_ranked_on_their_own(build):
    # provider-operated gateway (tier P) outscores the enterprise, but each segment ranks from 1
    _, t = build(
        hits=[hit("S01", "svc-isp-1", ip="203.0.113.1"), hit("S01", "svc-isp-2", ip="203.0.113.2"),
              hit("S06", "svc-ent", match_basis="tls", detail="TLS")],
        attrs=[attr("svc-isp-1", tier="P", account_id="net:skyway west", account_name="Skyway West", confidence=0.8),
               attr("svc-isp-2", tier="P", account_id="net:skyway west", account_name="Skyway West", confidence=0.8),
               attr("svc-ent")],
    )
    acc = _by(t["accounts"], "account_id")
    isp, ent = acc["net:skyway west"], acc["org:example"]
    assert (isp["segment"], isp["account_kind"], isp["best_tier"], isp["rank"]) == ("network_provider", "org", "P", 1)
    assert (ent["segment"], ent["rank"]) == ("enterprise", 1)
    assert isp["scoring_version"] == 3 and isp["legacy_scoring_version"] == 2
    assert isp["legacy_score"] > ent["legacy_score"]
    assert isp["ownership_confidence"] == "high"


# ----------------------------------------------------------------------------- scoring v3


def test_priority_ignores_attribution_but_ownership_and_legacy_score_show_it(build):
    # Same signal on one IP: one account named by its certificate, one known only from the registry.
    _, t = build(
        hits=[hit("S01", "svc-n", ip="192.0.2.1"), hit("S01", "svc-r", ip="192.0.2.2")],
        attrs=[attr("svc-n", account_id="org:named", account_name="Named Corp"),
               attr("svc-r", tier="A2", account_id="org:registry", account_name="Registry Corp",
                    confidence=0.85, isp="Big Telecom")],
        evidence=[name_ev("svc-n", "cert_cn", "vpn.namedcorp.com")])
    acc = _by(t["accounts"], "account_id")
    named, reg = acc["org:named"], acc["org:registry"]
    assert named["opportunity_priority"] == reg["opportunity_priority"] == pytest.approx(40.0)
    assert named["priority_percentile"] == reg["priority_percentile"]
    assert (named["ownership_confidence"], named["actionable"]) == ("high", True)
    assert (reg["ownership_confidence"], reg["actionable"]) == ("low", False)
    assert reg["actionable_blockers"] == ["ownership_low"]
    assert named["legacy_score"] > reg["legacy_score"]  # 36.0 vs 34.0: v2 multiplied attribution in
    # ties break on an exposure, counted IPs, then account id: deterministic
    assert [named["rank"], reg["rank"]] == [1, 2]
    assert any("not actionable" in line and "ownership not corroborated" in line for line in reg["explanation"])


def test_pool_label_in_a_provider_network_is_excluded_unranked_and_keeps_its_evidence(build):
    _, t = build(
        hits=[hit("S01", "svc-p1", ip="203.0.113.1"), hit("S03", "svc-p2", ip="203.0.113.2", detail="RDP"),
              hit("S06", "svc-e", ip="192.0.2.5", match_basis="tls", detail="TLS")],
        attrs=[attr("svc-p1", tier="A2", account_id="org:leased line customer lan",
                    account_name="Leased Line Customer LAN", confidence=0.85, isp="Big Telecom"),
               attr("svc-p2", tier="A2", account_id="org:leased line customer lan",
                    account_name="Leased Line Customer LAN", confidence=0.85, isp="Big Telecom"),
               attr("svc-e")],
        evidence=[name_ev("svc-e", "sni", "www.examplecorp.com")])
    acc = _by(t["accounts"], "account_id")
    pool, ent = acc["org:leased line customer lan"], acc["org:example"]
    assert pool["eligibility"] == "excluded"
    assert pool["eligibility_reasons"] == ["registry_label_not_an_organisation", "sub_allocation_in_provider_network"]
    assert (pool["rank"], pool["priority_percentile"], pool["priority_band"]) == (None, None, None)
    assert pool["actionable"] is False and pool["actionable_blockers"][0] == "excluded"
    assert pool["legacy_rank"] == 1  # it outranked the enterprise under v2 ...
    assert (ent["rank"], ent["priority_percentile"]) == (1, 0.0)  # ... and is gone from the v3 population
    assert {e["account_id"] for e in t["account_evidence"]} >= {"org:leased line customer lan"}
    assert pool["explanation"][0].startswith("Excluded from the ranking of eligible enterprise accounts")


def test_certificate_subject_o_names_the_account(build):
    _, t = build(hits=[hit("S03", "svc-o", detail="RDP")], attrs=[attr("svc-o")],
                 services=[{"service_id": "svc-o", "cert_subject_o": "Example Corp Pty Ltd"}])
    acc = t["accounts"][0]
    assert (acc["ownership_confidence"], acc["named_public_services"]) == ("high", 1)


def test_reverse_dns_only_is_medium_and_ntlm_never_names_an_account(build):
    _, t = build(hits=[hit("S03", "svc-a", detail="RDP")], attrs=[attr("svc-a")],
                 evidence=[name_ev("svc-a", "hostname", "gw1.examplecorp.net"),
                           name_ev("svc-a", "ntlm", "corp.examplecorp.local")])
    acc = t["accounts"][0]
    assert (acc["ownership_confidence"], acc["named_rdns_services"], acc["named_public_services"]) == ("medium", 1, 0)


def test_technographic_only_accounts_are_not_actionable_and_never_high(build):
    # 100 small TLS-hygiene accounts (priority 100 * 0.20 * 0.50 = 10) and one WAF-only account on 19 IPs
    # (100 * 0.25 * 1.0 = 25): the WAF account is above 100 of 101 (percentile 99.0099) but has no
    # exposure signal, so its band is capped at Medium, and S16 alone is not a security observation.
    # (100/101 = 99.0099%, stored floored to 99.0)
    hits = [hit("S16", f"w{i}", ip=f"192.0.2.{i}", match_basis="waf", detail="Cloudflare", sub_flags=["waf"])
            for i in range(1, 20)]
    attrs = [attr(f"w{i}", account_id="org:wafshield", account_name="Wafshield Ltd") for i in range(1, 20)]
    for i in range(100):
        hits.append(hit("S06", f"t{i}", ip=f"198.51.{i // 250}.{i % 250}", match_basis="tls", detail="TLS"))
        attrs.append(attr(f"t{i}", account_id=f"org:tls {i:03d}", account_name=f"Tls {i:03d}"))
    _, t = build(hits=hits, attrs=attrs, evidence=[name_ev("w1", "cert_cn", "www.wafshield.com")])
    acc = _by(t["accounts"], "account_id")
    waf = acc["org:wafshield"]
    assert (waf["rank"], waf["priority_percentile"], waf["priority_band"]) == (1, 99.0, "Medium")
    assert waf["actionable_blockers"] == ["no_security_observation"]
    assert waf["top_signals"] == ["S16"]
    small = acc["org:tls 000"]
    assert (small["priority_percentile"], small["priority_band"]) == (0.0, "Low")
    # ties: all 100 share priority 10 and one IP, so they rank by account id
    assert [acc[f"org:tls {i:03d}"]["rank"] for i in (0, 1, 99)] == [2, 3, 101]


def test_band_thresholds_see_exact_means_not_float_noise(build):
    # Three title matches: (0.7 + 0.7 + 0.7) / 3 is 0.6999999999999998 in floating point, which would
    # read as "low" evidence. Means are rounded first, so the band is medium.
    hits = [hit("S01", f"q{i}", ip=f"192.0.2.{i}", match_basis="title") for i in range(1, 4)]
    _, t = build(hits=hits, attrs=[attr(f"q{i}") for i in range(1, 4)])
    acc = t["accounts"][0]
    assert (acc["evidence_quality"], acc["evidence_quality_band"]) == (0.7, "medium")
    assert acc["actionable_blockers"] == ["ownership_low"]  # 0.7 meets the minimum security basis


def test_the_top_account_is_never_shown_as_above_100_percent(build):
    # 1 account above 2,999 others: share strictly below = 99.9666...%, floored to 99.96, shown as 99.
    hits = [hit("S01", "top", ip="192.0.2.1")]
    attrs = [attr("top", account_id="org:top", account_name="Top Ltd")]
    for i in range(2999):
        hits.append(hit("S06", f"t{i}", ip=f"10.{i // 250}.{i % 250}.1", match_basis="tls", detail="TLS"))
        attrs.append(attr(f"t{i}", account_id=f"org:t{i:04d}", account_name=f"T{i:04d}"))
    _, t = build(hits=hits, attrs=attrs)
    top = _by(t["accounts"], "account_id")["org:top"]
    assert top["priority_percentile"] == 99.96
    assert "higher than 99% of eligible enterprise accounts" in top["explanation"][0]


# ----------------------------------------------------------------------------- review fixes (2026-11-11)


def test_operator_zone_reverse_dns_does_not_name_a_customer_label(build):
    # "Assigned to Liquid Zimbabwe" contains the ISP's name, but rDNS in the ISP's own zone is how the
    # operator names its subscriber lines: it must not count as the account naming itself.
    attrs = [attr(f"z{i}", tier="A2", account_id="org:assigned to liquid zimbabwe",
                  account_name="Assigned to Liquid Zimbabwe", confidence=0.85, isp="Liquid Telecom") for i in range(3)]
    hits = [hit("S03", f"z{i}", ip=f"203.0.113.{i}", detail="RDP") for i in range(3)]
    ev = [name_ev(f"z{i}", "hostname", f"host-{i}.liquidtelecom.net") for i in range(3)]
    _, t = build(hits=hits, attrs=attrs, evidence=ev)
    acc = t["accounts"][0]
    assert (acc["named_rdns_services"], acc["subscriber_rdns_services"]) == (0, 3)
    assert acc["ownership_confidence"] == "low"


def test_an_operator_naming_its_own_zone_still_counts(build):
    _, t = build(hits=[hit("S03", "o1", detail="RDP")],
                 attrs=[attr("o1", account_id="org:liquid telecom", account_name="Liquid Telecom", isp="Liquid Telecom")],
                 evidence=[name_ev("o1", "hostname", "gw.liquidtelecom.net")])
    assert t["accounts"][0]["ownership_confidence"] == "medium"


def test_shared_default_and_wildcard_certificates_do_not_name_the_account(build):
    ev = [name_ev("c1", "cert_cn", "vpn.examplecorp.com", outcome="provider_cert"),
          dict(name_ev("c1", "cert_san", "examplecorp.com"), raw_name="*.examplecorp.com")]
    _, t = build(hits=[hit("S01", "c1")], attrs=[attr("c1")], evidence=ev)
    assert (t["accounts"][0]["named_public_services"], t["accounts"][0]["ownership_confidence"]) == (0, "low")


def test_isp_spellings_that_differ_only_by_accents_are_one_network_operator(build):
    # attribution v5: ISP names are accent-folded, so one operator written three ways is one operator
    isps = ["Telefónica Chile", "TELEFONICA CHILE", "Telefônica Chile"]
    _, t = build(
        hits=[hit("S01", f"svc-{i}", ip=f"203.0.113.{i}") for i in range(3)],
        attrs=[attr(f"svc-{i}", tier="A2", account_id="org:static ip pool", account_name="Static IP Pool",
                    confidence=0.85, isp=isp) for i, isp in enumerate(isps)])
    row = t["accounts"][0]
    assert row["network_operators"] == 1
    assert "label_spans_network_operators" not in row["eligibility_reasons"] + row["review_flags"]
    assert row["eligibility_version"] == 2   # v2: names folded in eligibility (attribution v5)
