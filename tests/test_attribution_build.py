"""Attribution v1 build: synthetic services in, evidence + service attribution out.

Expected values are hand-written literals (scores per docs/attribution-implementation.md):
A1 0.9, A2 0.85; tier B = evidence score x candidate multiplier (1 / 0.85 for 2-3 / 0.6 for >3).
"""

from __future__ import annotations

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from firmable.attribution.build import build_attribution, compute_infra_domains
from service_rows import service_row, write_services

EVIDENCE_SCHEMA = [
    ("snapshot_id", "string"), ("service_id", "string"), ("source", "string"), ("raw_name", "string"),
    ("name", "string"), ("reg_domain", "string"), ("outcome", "string"), ("attribution_version", "int32"),
]
ATTRIBUTION_SCHEMA = [
    ("snapshot_id", "string"), ("service_id", "string"), ("attribution_version", "int32"),
    ("tier", "string"), ("account_id", "string"), ("account_name", "string"), ("confidence", "double"),
    ("confidence_band", "string"), ("reasons", "list<element: string>"),
    ("candidate_domains", "list<element: string>"), ("allows_infra_signals", "bool"),
    ("org", "string"), ("isp", "string"), ("org_class", "string"),
]


def run(tmp_path: Path, rows: list[dict], **kw):
    services = write_services(tmp_path / "services.parquet", rows)
    out = tmp_path / "attribution"
    kw.setdefault("infra_domains", set())
    result = build_attribution(services, out, memory_limit="1GB", threads=2, **kw)
    ev = pq.read_table(out / "evidence.parquet").to_pylist()
    sa = {r["service_id"]: r for r in pq.read_table(out / "service_attribution.parquet").to_pylist()}
    return result, ev, sa


def _sid(row):
    return row["service_id"]


# ------------------------------------------------------------------------------------- schemas
def test_output_schemas_are_exact(tmp_path):
    rows = [service_row(org="Acme Manufacturing Inc", isp="Acme Manufacturing Inc", sni="www.acme-mfg.com")]
    _, _, _ = run(tmp_path, rows)
    ev = pq.read_schema(tmp_path / "attribution" / "evidence.parquet")
    sa = pq.read_schema(tmp_path / "attribution" / "service_attribution.parquet")
    assert [(f.name, str(f.type)) for f in ev] == EVIDENCE_SCHEMA
    assert [(f.name, str(f.type)) for f in sa] == ATTRIBUTION_SCHEMA
    assert not list((tmp_path / "attribution").glob("*.tmp"))


# ------------------------------------------------------------------------------------- owned tiers
def test_business_org_is_a1(tmp_path):
    r = service_row(org="Acme Manufacturing Inc", isp="Acme Manufacturing Inc")
    _, _, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["account_name"]) == ("A1", "org:acme manufacturing", "Acme Manufacturing Inc")
    assert (a["confidence"], a["confidence_band"], a["allows_infra_signals"]) == (0.9, "high", True)
    assert a["reasons"] == ["org_not_provider", "org_eq_isp"]
    assert (a["org_class"], a["snapshot_id"], a["attribution_version"]) == ("business", "s1", 5)


def test_isp_org_is_not_a1(tmp_path):
    rows = [service_row(org="BIGLOBE Inc.", isp="BIGLOBE Inc."),
            service_row(org="Comcast Cable Communications, LLC", isp="Comcast Cable Communications, LLC")]
    _, _, sa = run(tmp_path, rows)
    for r in rows:
        a = sa[_sid(r)]
        assert (a["tier"], a["account_id"], a["account_name"], a["org_class"]) == ("C", None, None, "isp_telco")
        assert (a["confidence"], a["confidence_band"], a["allows_infra_signals"]) == (0.0, "none", False)
        assert a["reasons"] == ["org_isp", "abstain_no_customer_evidence"]
        assert a["candidate_domains"] == []


def test_byoip_business_org_inside_provider_is_a2(tmp_path):
    r = service_row(org="Wal-Mart Stores, Inc.", isp="Google LLC")
    _, _, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["confidence"], a["allows_infra_signals"]) == ("A2", "org:wal-mart stores", 0.85, True)
    assert a["reasons"] == ["org_not_provider", "byoip_in_provider"]


# ------------------------------------------------------------------------------------- tier B
def test_cdn_tenant_with_cert_and_sni_agreement_is_b_with_infra(tmp_path):
    r = service_row(org="Cloudflare, Inc.", isp="Cloudflare, Inc.", sni="shop.acme-retail.com",
                    cert_subject_cn="shop.acme-retail.com", cert_san_dns=["shop.acme-retail.com", "acme-retail.com"],
                    is_cdn=True, tags=["cdn"])
    _, ev, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["account_name"]) == ("B", "dom:acme-retail.com", "acme-retail.com")
    assert a["candidate_domains"] == ["acme-retail.com"]
    assert a["reasons"] == ["org_cdn", "dom_cert_sni_agree"]
    assert (a["confidence"], a["confidence_band"], a["allows_infra_signals"]) == (0.9, "high", True)
    assert sorted((e["source"], e["name"], e["outcome"]) for e in ev) == [
        ("cert_cn", "shop.acme-retail.com", "accepted"),
        ("cert_san", "acme-retail.com", "accepted"),
        ("cert_san", "shop.acme-retail.com", "accepted"),
        ("sni", "shop.acme-retail.com", "accepted"),
    ]


def test_hostname_only_is_low_confidence_b_without_infra(tmp_path):
    r = service_row(org="Amazon Technologies Inc.", isp="Amazon.com, Inc.", hostnames=["www.smallco.com.au"])
    _, _, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["confidence"], a["confidence_band"]) == ("B", "dom:smallco.com.au", 0.25, "low")
    assert a["reasons"] == ["org_cloud_hosting", "dom_hostname_only"]
    assert a["allows_infra_signals"] is False


def test_ntlm_alone_never_attributes_and_is_not_a_public_candidate(tmp_path):
    # NTLM policy: an internal AD domain alone is restricted evidence; it abstains and is kept internally
    only = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", port=3389, ntlm_dns_domain="corp.acme-energy.com")
    _, ev, sa = run(tmp_path, [only])
    a = sa[_sid(only)]
    assert (a["tier"], a["account_id"], a["account_name"], a["confidence"], a["allows_infra_signals"]) == \
        ("C", None, None, 0.0, False)
    assert a["reasons"] == ["org_cloud_hosting", "abstain_ntlm_uncorroborated"]
    assert a["candidate_domains"] == []
    kept = [(e["source"], e["raw_name"], e["outcome"]) for e in ev if e["service_id"] == _sid(only)]
    assert kept == [("ntlm", "corp.acme-energy.com", "accepted")]


def test_ntlm_does_not_compete_with_another_tenants_public_name(tmp_path):
    mixed = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", port=3389,
                        ntlm_dns_domain="corp.acme-energy.com", hostnames=["mail.other-tenant.com"])
    _, _, sa = run(tmp_path, [mixed])
    b = sa[_sid(mixed)]
    assert (b["tier"], b["account_id"], b["confidence"], b["allows_infra_signals"]) == \
        ("B", "dom:other-tenant.com", 0.25, False)
    assert b["reasons"] == ["org_cloud_hosting", "dom_hostname_only"]
    assert b["candidate_domains"] == ["other-tenant.com"]


def test_ntlm_corroborated_by_certificate_is_strongest(tmp_path):
    cert = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", port=3389,
                       ntlm_dns_domain="corp.acme-energy.com", cert_subject_cn="rdp.acme-energy.com")
    _, _, sa = run(tmp_path, [cert])
    a = sa[_sid(cert)]
    assert (a["tier"], a["account_id"], a["confidence"], a["allows_infra_signals"]) == \
        ("B", "dom:acme-energy.com", 1.0, True)
    assert a["reasons"] == ["org_cloud_hosting", "dom_ntlm_corroborated"]
    assert a["candidate_domains"] == ["acme-energy.com"]


def test_ntlm_with_only_reverse_dns_stays_weak(tmp_path):
    # a PTR name is set by the IP owner; with NTLM it is still not enough for infrastructure signals
    ptr = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", port=3389, ip="203.0.113.9",
                      ntlm_dns_domain="corp.acme-energy.com", hostnames=["rdp.acme-energy.com"])
    _, _, sa = run(tmp_path, [ptr])
    a = sa[_sid(ptr)]
    assert (a["tier"], a["account_id"], a["confidence"], a["allows_infra_signals"]) == \
        ("B", "dom:acme-energy.com", 0.3, False)
    assert a["reasons"] == ["org_cloud_hosting", "dom_hostname_only"]



def test_wildcard_cert_agreeing_with_sni_is_b_without_infra(tmp_path):
    r = service_row(org="DigitalOcean, LLC", isp="DigitalOcean, LLC", sni="api.acme-labs.io",
                    cert_subject_cn="*.acme-labs.io", cert_san_dns=["*.acme-labs.io"])
    _, ev, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["allows_infra_signals"]) == ("B", "dom:acme-labs.io", False)
    assert a["reasons"] == ["org_cloud_hosting", "dom_cert_wildcard_sni_agree"]
    assert a["confidence"] == 0.75          # 0.7 + 0.05 (two evidence families)
    cn = [e for e in ev if e["source"] == "cert_cn"]
    assert [(e["raw_name"], e["name"], e["reg_domain"]) for e in cn] == [("*.acme-labs.io", "acme-labs.io", "acme-labs.io")]


def test_evidence_is_one_row_per_service_source_name(tmp_path):
    # the SAN list names acme-labs.io twice (wildcard and bare): one row, the bare raw name kept
    r = service_row(org="DigitalOcean, LLC", isp="DigitalOcean, LLC", sni="api.acme-labs.io",
                    cert_san_dns=["*.acme-labs.io", "acme-labs.io", "ACME-LABS.IO."])
    _, ev, sa = run(tmp_path, [r])
    san = [e for e in ev if e["source"] == "cert_san"]
    assert [(e["raw_name"], e["name"], e["outcome"]) for e in san] == [("ACME-LABS.IO.", "acme-labs.io", "accepted")]
    assert sa[_sid(r)]["reasons"] == ["org_cloud_hosting", "dom_cert_sni_agree"]


# ------------------------------------------------------------------------------------- abstention
def test_tied_domains_abstain(tmp_path):
    r = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", hostnames=["a-company.com", "b-company.com"])
    _, _, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["confidence"], a["confidence_band"]) == ("C", None, 0.0, "none")
    assert a["reasons"] == ["org_cloud_hosting", "abstain_ambiguous_domains"]
    assert a["candidate_domains"] == ["a-company.com", "b-company.com"]


def test_more_than_three_domains_is_shared_hosting(tmp_path):
    names = ["alpha-bakery.com", "bravo-law.com", "charlie-dental.com", "delta-garage.com"]
    no_sni = service_row(ip="198.51.100.20", org="Unified Layer", isp="Oracle Corporation", hostnames=names)
    vhost = service_row(ip="198.51.100.20", org="Unified Layer", isp="Oracle Corporation", sni="www.bravo-law.com",
                        cert_subject_cn="www.bravo-law.com", hostnames=names)
    _, _, sa = run(tmp_path, [no_sni, vhost])
    a = sa[_sid(no_sni)]
    assert (a["tier"], a["account_id"]) == ("C", None)
    assert a["reasons"] == ["org_cloud_hosting", "abstain_ambiguous_domains", "shared_hosting"]
    b = sa[_sid(vhost)]
    assert (b["tier"], b["account_id"], b["allows_infra_signals"]) == ("B", "dom:bravo-law.com", False)
    assert b["reasons"] == ["org_cloud_hosting", "dom_cert_sni_agree", "shared_hosting"]
    assert b["confidence"] == 0.57          # (0.85 + 2 x 0.05) x 0.6
    assert b["confidence_band"] == "medium"
    assert b["candidate_domains"] == sorted(names)


def test_vhosts_on_one_ip_never_share_evidence(tmp_path):
    ip = "203.0.113.5"
    alpha = service_row(ip=ip, org="Hetzner Online GmbH", isp="Hetzner Online GmbH", sni="alpha-corp.com",
                        cert_subject_cn="alpha-corp.com")
    beta = service_row(ip=ip, org="Hetzner Online GmbH", isp="Hetzner Online GmbH", sni="www.beta-corp.de",
                       cert_subject_cn="www.beta-corp.de")
    bare = service_row(ip=ip, port=22, module="ssh", org="Hetzner Online GmbH", isp="Hetzner Online GmbH")
    _, ev, sa = run(tmp_path, [alpha, beta, bare])
    assert sa[_sid(alpha)]["account_id"] == "dom:alpha-corp.com"
    assert sa[_sid(beta)]["account_id"] == "dom:beta-corp.de"
    assert sa[_sid(alpha)]["candidate_domains"] == ["alpha-corp.com"]
    assert sa[_sid(beta)]["candidate_domains"] == ["beta-corp.de"]
    assert (sa[_sid(bare)]["tier"], sa[_sid(bare)]["account_id"], sa[_sid(bare)]["candidate_domains"]) == ("C", None, [])
    assert [e for e in ev if e["service_id"] == _sid(bare)] == []


def test_vendor_default_and_ptr_names_are_rejected(tmp_path):
    rows = [
        service_row(org="Comcast Cable Communications, LLC", isp="Comcast Cable Communications, LLC",
                    cert_subject_cn="draytek.com"),
        service_row(org="Comcast Cable Communications, LLC", isp="Comcast Cable Communications, LLC",
                    cert_subject_cn="unifi.local", hostnames=["c-198-51-100-7.hsd1.example-isp.net"]),
    ]
    _, ev, sa = run(tmp_path, rows)
    for r in rows:
        assert (sa[_sid(r)]["tier"], sa[_sid(r)]["reasons"]) == ("C", ["org_isp", "abstain_no_customer_evidence"])
    assert sorted((e["raw_name"], e["outcome"]) for e in ev) == [
        ("c-198-51-100-7.hsd1.example-isp.net", "ptr_like"),
        ("draytek.com", "non_company"),
        ("unifi.local", "non_company"),
    ]


def test_infra_domains_are_rejected(tmp_path):
    r = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", hostnames=["vps-alpha.your-server.de"])
    _, ev, sa = run(tmp_path, [r], infra_domains={"your-server.de"})
    assert [(e["name"], e["reg_domain"], e["outcome"]) for e in ev] == [
        ("vps-alpha.your-server.de", "your-server.de", "infra_domain")]
    assert sa[_sid(r)]["tier"] == "C"


def test_certificate_name_shared_by_many_orgs_is_a_provider_cert(tmp_path):
    isps = ["Example Telecom One", "Example Telecom Two", "Example Telecom Three"]
    rows = [service_row(org=o, isp=o, cert_subject_cn="www.bigvendor.com") for o in isps]
    rows.append(service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", sni="www.bigvendor.com"))
    result, ev, sa = run(tmp_path, rows, shared_cert_min_orgs=3)
    assert sorted((e["source"], e["outcome"]) for e in ev) == [
        ("cert_cn", "provider_cert"), ("cert_cn", "provider_cert"), ("cert_cn", "provider_cert"),
        ("sni", "accepted")]
    assert all(sa[_sid(r)]["tier"] == "C" for r in rows[:3])
    assert sa[_sid(rows[3])]["account_id"] == "dom:bigvendor.com"
    assert result["shared_cert_names"] == 1


def test_psl_private_suffix_tenants_are_different_accounts(tmp_path):
    a = service_row(org="GitHub, Inc.", isp="Fastly, Inc.", sni="alice.github.io", cert_subject_cn="*.github.io")
    b = service_row(org="GitHub, Inc.", isp="Fastly, Inc.", sni="bob.github.io", cert_subject_cn="*.github.io")
    _, _, sa = run(tmp_path, [a, b])
    assert sa[_sid(a)]["account_id"] == "dom:alice.github.io"
    assert sa[_sid(b)]["account_id"] == "dom:bob.github.io"
    assert sa[_sid(a)]["reasons"] == ["org_saas_platform", "dom_sni"]


# ------------------------------------------------------------------------------------- org backstops
def test_enterprise_with_many_own_brand_domains_is_not_a_platform(tmp_path):
    uhg = [service_row(org="UnitedHealth Group Incorporated", isp="Unitedhealthcare", sni=f"www.brand{i:03d}.com",
                       cert_subject_cn=f"www.brand{i:03d}.com", cert_subject_o="UnitedHealth Group Inc.")
           for i in range(101)]
    host = [service_row(org="Blue Lantern Media", isp="Blue Lantern Media", sni=f"www.tenant{i:03d}.com",
                        cert_subject_cn=f"www.tenant{i:03d}.com") for i in range(101)]
    _, _, sa = run(tmp_path, uhg + host)
    assert {(sa[_sid(r)]["tier"], sa[_sid(r)]["org_class"], sa[_sid(r)]["account_id"]) for r in uhg} == {
        ("A1", "business", "org:unitedhealth group")}
    h = sa[_sid(host[7])]
    assert (h["tier"], h["org_class"], h["account_id"]) == ("B", "saas_platform", "dom:tenant007.com")
    assert h["reasons"] == ["org_saas_platform", "org_multi_tenant", "dom_cert_sni_agree"]


def test_cdn_cloud_tagged_org_is_a_platform(tmp_path):
    rows = [service_row(org="Nimbus Edge Ltd", isp="Nimbus Edge Ltd", tags=["cloud"]) for _ in range(3)]
    _, _, sa = run(tmp_path, rows)
    a = sa[_sid(rows[0])]
    assert (a["tier"], a["org_class"]) == ("C", "cloud_hosting")
    assert a["reasons"] == ["org_cloud_hosting", "org_cdn_cloud_tagged", "abstain_no_customer_evidence"]


def test_pool_label_and_synthetic_orgs_are_not_accounts(tmp_path):
    rows = [service_row(org="IP pools", isp="Example Telecom"),
            service_row(org="Company 64d3451abc9f", isp="Example Telecom")]
    _, _, sa = run(tmp_path, rows)
    assert (sa[_sid(rows[0])]["tier"], sa[_sid(rows[0])]["org_class"]) == ("C", "isp_telco")
    assert (sa[_sid(rows[1])]["tier"], sa[_sid(rows[1])]["org_class"]) == ("C", "unknown")
    assert sa[_sid(rows[1])]["reasons"] == ["org_unknown", "abstain_no_customer_evidence"]


def test_result_counts(tmp_path):
    rows = [service_row(org="Acme Manufacturing Inc", isp="Acme Manufacturing Inc"),
            service_row(org="Wal-Mart Stores, Inc.", isp="Google LLC"),
            service_row(org="Google LLC", isp="Google LLC", sni="www.acme-retail.com"),
            service_row(org="Google LLC", isp="Google LLC")]
    result, _, _ = run(tmp_path, rows)
    assert result["services"] == 4
    assert result["tiers"] == {"A1": 1, "A2": 1, "P": 0, "B": 1, "C": 1}


# ------------------------------------------------------------------------------------- infra domains
def test_compute_infra_domains_counts_distinct_ips_over_observation_hostnames(tmp_path):
    rows = (
        [{"ip": f"198.51.100.{i}", "hostnames": [f"host-{i}.provider-dns.net"]} for i in range(4)]
        + [{"ip": "198.51.100.0", "hostnames": ["other.provider-dns.net"]}]          # same IP again
        + [{"ip": f"203.0.113.{i}", "hostnames": [f"www.small-{i}.com"]} for i in range(4)]
        + [{"ip": f"192.0.2.{i}", "hostnames": ["shared.tiny-site.org"]} for i in range(2)]
        + [{"ip": "192.0.2.9", "hostnames": []}]
    )
    files = []
    for k in range(2):  # split across two files, as committed observation chunks are
        p = tmp_path / f"chunk-{k}.parquet"
        pq.write_table(pa.Table.from_pylist(rows[k::2], schema=pa.schema(
            [("ip", pa.string()), ("hostnames", pa.list_(pa.string()))])), p)
        files.append(p)
    got = compute_infra_domains(files, min_ips=3, memory_limit="1GB", threads=2)
    assert got == {"provider-dns.net": 4}


def test_infra_domains_cache_is_written_and_reused(tmp_path):
    p = tmp_path / "obs.parquet"
    pq.write_table(pa.Table.from_pylist(
        [{"ip": f"198.51.100.{i}", "hostnames": [f"n{i}.provider-dns.net"]} for i in range(3)],
        schema=pa.schema([("ip", pa.string()), ("hostnames", pa.list_(pa.string()))])), p)
    r = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", hostnames=["www.provider-dns.net"])
    services = write_services(tmp_path / "services.parquet", [r])
    out = tmp_path / "attribution"
    res = build_attribution(services, out, observation_files=[p], infra_min_ips=3, memory_limit="1GB", threads=2)
    assert res["infra_domains"] == 1
    assert pq.read_table(out / "infra_domains.parquet").to_pylist() == [{"domain": "provider-dns.net", "ips": 3}]
    # second run without observation files reuses the cache
    res2 = build_attribution(services, out, memory_limit="1GB", threads=2)
    assert res2["infra_domains"] == 1
    assert pq.read_table(out / "evidence.parquet").column("outcome").to_pylist() == ["infra_domain"]


def test_missing_infra_input_is_an_error(tmp_path):
    services = write_services(tmp_path / "services.parquet", [service_row()])
    with pytest.raises(ValueError, match="infra"):
        build_attribution(services, tmp_path / "attribution", memory_limit="1GB", threads=2)



# ------------------------------------------------------------------------------------- access-network backstop
def _access_rows(org, isp, n, n_access, start=0):
    rows = []
    for i in range(n):
        host = [f"adsl-{start + i}.example-isp.net"] if i < n_access else []
        rows.append(service_row(ip=f"198.51.{(start + i) // 250}.{(start + i) % 250 + 1}", org=org, isp=isp,
                                port=8080, hostnames=host))
    return rows


def test_access_network_org_is_isp(tmp_path):
    isp = _access_rows("Northwind Net", "Northwind Net", 20, 6)                     # share 0.30
    edu = _access_rows("Hillcrest University", "Hillcrest University", 20, 5, 100)  # share 0.25
    small = _access_rows("Tiny Widgets Co", "Tiny Widgets Co", 19, 19, 200)      # < 20 services
    _, _, sa = run(tmp_path, isp + edu + small)
    a = sa[_sid(isp[10])]
    assert (a["tier"], a["org_class"], a["account_id"]) == ("C", "isp_telco", None)
    assert a["reasons"] == ["org_isp", "org_access_network_ptr", "abstain_no_customer_evidence"]
    assert (sa[_sid(edu[0])]["tier"], sa[_sid(edu[0])]["org_class"]) == ("A1", "business")
    assert (sa[_sid(small[0])]["tier"], sa[_sid(small[0])]["org_class"]) == ("A1", "business")


def test_access_network_backstop_applies_to_the_isp_side(tmp_path):
    # the operator only ever appears as `isp`; its subscribers' PTRs mark it as an access network
    pool = _access_rows("Northwind Subscribers", "Northwind Net", 20, 20)
    dental = service_row(org="Acme Dental LLC", isp="Northwind Net")
    _, _, sa = run(tmp_path, pool + [dental])
    a = sa[_sid(dental)]
    assert (a["tier"], a["account_id"], a["reasons"]) == ("A2", "org:acme dental", ["org_not_provider", "byoip_in_provider"])


# ------------------------------------------------------------------------------------- network type (OpenASN)
from firmable.attribution.asn import AsnInfo  # noqa: E402

ASNS = {
    64500: AsnInfo("isp", "access_provider", ()),          # an access ISP
    64501: AsnInfo("hosting", "midsize_transit", ()),      # a hoster
    64502: AsnInfo("hosting", "access_provider", ()),      # big-tech own network filed as hosting
    64503: AsnInfo("business", "stub", ()),
}


def test_operator_of_an_isp_asn_is_not_an_owned_account(tmp_path):
    r = service_row(org="Skyway West", isp="Skyway West", asn="AS64500")
    _, _, sa = run(tmp_path, [r], asn_table=ASNS)
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["org_class"]) == ("C", None, "isp_telco")
    assert a["reasons"] == ["org_isp", "org_asn_isp", "abstain_no_customer_evidence"]


def test_top_org_of_a_hosting_asn_is_its_operator_even_under_another_isp_label(tmp_path):
    # isp label differs ("Devoli"/"Devoli LTD" style), but the org dominates its ASN
    rows = [service_row(org="Devoli LTD", isp="Devoli Networks", asn="AS64501") for _ in range(3)]
    rows.append(service_row(org="Small Customer Pty", isp="Devoli Networks", asn="AS64501"))
    _, _, sa = run(tmp_path, rows, asn_table=ASNS)
    assert {sa[_sid(r)]["org_class"] for r in rows[:3]} == {"cloud_hosting"}
    assert {sa[_sid(r)]["tier"] for r in rows[:3]} == {"C"}
    # the customer on the hoster's ASN keeps its own account: owned space inside a provider (A2)
    c = sa[_sid(rows[3])]
    assert (c["tier"], c["account_id"], c["org_class"]) == ("A2", "org:small customer", "business")
    assert c["reasons"] == ["org_not_provider", "byoip_in_provider"]


def test_customer_sub_allocation_on_an_isp_asn_stays_enterprise(tmp_path):
    isp = [service_row(org="Big Telco", isp="Big Telco", asn="AS64500") for _ in range(3)]
    cust = service_row(org="Contoso Manufacturing Inc", isp="Big Telco", asn="AS64500")
    _, _, sa = run(tmp_path, isp + [cust], asn_table=ASNS)
    a = sa[_sid(cust)]
    assert (a["tier"], a["account_id"], a["allows_infra_signals"]) == ("A2", "org:contoso manufacturing", True)


def test_content_enterprise_filed_as_hosting_stays_owned(tmp_path):
    r = service_row(org="Apple Inc.", isp="Apple Inc.", asn="AS64502")
    _, _, sa = run(tmp_path, [r], asn_table=ASNS)
    assert (sa[_sid(r)]["tier"], sa[_sid(r)]["account_id"]) == ("A1", "org:apple")


def test_unknown_asn_keeps_existing_rules(tmp_path):
    r = service_row(org="Acme Manufacturing Inc", isp="Acme Manufacturing Inc", asn="AS65000")
    _, _, sa = run(tmp_path, [r], asn_table=ASNS)
    assert (sa[_sid(r)]["tier"], sa[_sid(r)]["org_class"]) == ("A1", "business")


def test_provider_operated_service_on_its_own_domain_is_a_network_provider_account(tmp_path):
    own = service_row(org="Skyway West", isp="Skyway West", asn="AS64500", sni="portal.skywaywest.net",
                      cert_subject_cn="portal.skywaywest.net")
    ptr_only = service_row(org="Skyway West", isp="Skyway West", asn="AS64500",
                           hostnames=["host-1-2-3-4.skywaywest.net"])
    tenant = service_row(org="Skyway West", isp="Skyway West", asn="AS64500", sni="www.acme-energy.com",
                         cert_subject_cn="www.acme-energy.com")
    _, _, sa = run(tmp_path, [own, ptr_only, tenant], asn_table=ASNS)
    a = sa[_sid(own)]
    assert (a["tier"], a["account_id"], a["account_name"], a["confidence"], a["allows_infra_signals"]) == \
        ("P", "net:skyway west", "Skyway West", 0.8, True)
    assert a["reasons"] == ["org_isp", "org_asn_isp", "provider_own_domain"]
    # a reverse-DNS name in the ISP's zone is how subscriber lines are named: not sufficient evidence
    assert sa[_sid(ptr_only)]["tier"] in ("B", "C") and sa[_sid(ptr_only)]["account_id"] != "net:skyway west"
    # a tenant's own certificate on the ISP's network stays the tenant's
    assert (sa[_sid(tenant)]["tier"], sa[_sid(tenant)]["account_id"]) == ("B", "dom:acme-energy.com")


def test_customer_vps_with_the_providers_default_certificate_is_not_the_provider(tmp_path):
    # hosters name customer machines in their own zone; a per-host label is not provider evidence
    vps = service_row(org="OVH SAS", isp="OVH SAS", port=3389, cert_subject_cn="vps-5f3a2b1c.vps.ovh.net")
    num = service_row(org="OVH SAS", isp="OVH SAS", port=3389, sni="ns3012345.ip-51-68-1.eu.ovh.net",
                      cert_subject_cn="ns3012345.ip-51-68-1.eu.ovh.net")
    own = service_row(org="OVH SAS", isp="OVH SAS", sni="www.ovh.net", cert_subject_cn="www.ovh.net")
    _, _, sa = run(tmp_path, [vps, num, own], asn_table={})
    assert sa[_sid(vps)]["tier"] != "P" and sa[_sid(num)]["tier"] != "P"
    assert (sa[_sid(own)]["tier"], sa[_sid(own)]["account_id"]) == ("P", "net:ovh")


def test_dominant_org_needs_a_majority_of_the_asn_to_count_as_operator(tmp_path):
    rows = [service_row(org="Contoso Manufacturing Inc", isp="Small Telco", asn="AS64500") for _ in range(2)]
    rows += [service_row(org=f"Customer {i} Pty", isp="Small Telco", asn="AS64500") for i in range(3)]
    _, _, sa = run(tmp_path, rows, asn_table=ASNS)
    assert {sa[_sid(r)]["tier"] for r in rows[:2]} == {"A2"}       # 2 of 5: most services, not a majority


def test_curated_provider_own_domain_is_also_network_provider(tmp_path):
    r = service_row(org="Hetzner Online GmbH", isp="Hetzner Online GmbH", sni="robot.hetzner.com",
                    cert_subject_cn="robot.hetzner.com")
    _, _, sa = run(tmp_path, [r], asn_table={})
    assert (sa[_sid(r)]["tier"], sa[_sid(r)]["account_id"]) == ("P", "net:hetzner online")


# ------------------------------------------------------------------------------------- attribution v5: folding
def test_accented_operator_is_a_network_provider_and_spellings_share_one_key(tmp_path):
    # v4 read "Telefónica" (acute ó) as a business: its own portal made it an owned A1 account
    own = service_row(org="TELEFÓNICA CHILE S.A.", isp="TELEFÓNICA CHILE S.A.", sni="portal.telefonica.cl",
                      cert_subject_cn="portal.telefonica.cl")
    line = service_row(org="TELEFÓNICA CHILE S.A.", isp="TELEFÓNICA CHILE S.A.", port=3389)
    ascii_own = service_row(org="Telefonica Chile SA", isp="Telefonica Chile SA", sni="www.telefonica.cl",
                            cert_subject_cn="www.telefonica.cl")
    _, _, sa = run(tmp_path, [own, line, ascii_own], asn_table={})
    assert {sa[_sid(r)]["org_class"] for r in (own, line, ascii_own)} == {"isp_telco"}
    assert (sa[_sid(own)]["tier"], sa[_sid(own)]["account_id"]) == ("P", "net:telefonica chile")
    assert sa[_sid(ascii_own)]["account_id"] == "net:telefonica chile"     # one key for both spellings
    assert sa[_sid(own)]["account_name"] == "TELEFÓNICA CHILE S.A."         # the raw name is kept for display
    assert sa[_sid(line)]["tier"] == "C"


def test_accented_business_keeps_a1_with_a_folded_key(tmp_path):
    r = service_row(org="Universität Zürich", isp="Universität Zürich")
    _, _, sa = run(tmp_path, [r])
    a = sa[_sid(r)]
    assert (a["tier"], a["account_id"], a["account_name"], a["org_class"]) == \
        ("A1", "org:universitat zurich", "Universität Zürich", "business")
    assert a["reasons"] == ["org_not_provider", "org_eq_isp"]


def test_spelling_variants_of_one_account_share_the_access_backstop(tmp_path):
    # 15 + 15 services: neither spelling alone reaches the 20-service minimum, the account key does
    a = _access_rows("Ørsta Linje AS", "Ørsta Linje AS", 15, 15)
    b = _access_rows("Orsta Linje AS", "Orsta Linje AS", 15, 15, 100)
    _, _, sa = run(tmp_path, a + b)
    assert {(sa[_sid(r)]["org_class"], sa[_sid(r)]["tier"]) for r in a + b} == {("isp_telco", "C")}


def test_spelling_variants_of_the_isp_share_the_isp_side_access_backstop(tmp_path):
    pool = (_access_rows("Ørsta Subscribers", "Ørsta Linje AS", 12, 12)
            + _access_rows("Orsta Subscribers", "Orsta Linje AS", 12, 12, 100))
    dental = service_row(org="Acme Dental LLC", isp="Orsta Linje AS")
    _, _, sa = run(tmp_path, pool + [dental])
    assert sa[_sid(dental)]["tier"] == "A2"


def test_spelling_variants_together_hold_the_asn_majority(tmp_path):
    # 2 + 2 of 7 services: no spelling holds a majority, the account (one key) does
    rows = [service_row(org=o, isp="Small Telco", asn="AS64500")
            for o in ("Contoso Ålesund AS", "Contoso Ålesund AS", "Contoso Alesund AS", "Contoso Alesund AS")]
    rows += [service_row(org=f"Fabrikam {i} Pty", isp="Small Telco", asn="AS64500") for i in range(3)]
    _, _, sa = run(tmp_path, rows, asn_table=ASNS)
    assert {sa[_sid(r)]["org_class"] for r in rows[:4]} == {"isp_telco"}
    assert {sa[_sid(r)]["tier"] for r in rows[4:]} == {"A2"}
