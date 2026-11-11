"""Source-observation inspection: does a raw record independently name the account's business?

Seam: `summarize_record(normalize_line(raw), account_id, account_name)` and
`ownership_verdict(summaries)`. Banners are synthetic (factories); expected values hand-written.
"""

from __future__ import annotations

import pytest

from firmable.evaluation.inspect import ownership_verdict, summarize_record
from firmable.ingest.normalize import normalize_line

from factories import BASE, line


def _cert(cn, o=None, san=()):
    subject = {"CN": cn} | ({"O": o} if o else {})
    ext = [{"name": "subjectAltName", "data": "0%" + "".join(f"\\x82\\x{len(n):02x}{n}" for n in san)}] if san else []
    return {"cert": {"expired": False, "expires": "20270101120000Z", "issued": "20260101120000Z",
                     "subject": subject, "issuer": {"CN": "Example CA"}, "sig_alg": "sha256WithRSAEncryption",
                     "pubkey": {"type": "rsa", "bits": 2048}, "fingerprint": {"sha256": "ab" * 32},
                     "extensions": ext}, "versions": ["TLSv1.2"]}


def obs(**kw):
    kw.setdefault("hostnames", [])
    kw.setdefault("domains", [])
    return normalize_line(line(**kw))


def test_org_account_corroborated_by_its_own_certificate():
    s = summarize_record(obs(org="McGill University", isp="McGill University", ssl=_cert("www.mcgill.ca")),
                         "org:mcgill university", "McGill University")
    assert s["names_account"] == ["cert_cn:mcgill.ca"]
    assert s["third_party"] == []
    assert s["org"] == "McGill University"


def test_certificate_organisation_also_corroborates():
    s = summarize_record(obs(org="Cerner Corporation", isp="Cerner Corporation",
                             ssl=_cert("portal.example-health.org", o="Cerner Corporation")),
                         "org:cerner", "Cerner Corporation")
    assert s["names_account"] == ["cert_o:Cerner Corporation"]
    assert s["third_party"] == ["example-health.org"]


def test_hosted_customer_names_are_third_parties():
    s = summarize_record(obs(org="Weserve BV", isp="Weserve BV", ssl=_cert("shop.munsterhuis.com"),
                             hostnames=["mail.lankhof.nl"]),
                         "org:weserve", "Weserve B.V.")
    assert s["names_account"] == []
    assert s["third_party"] == ["lankhof.nl", "munsterhuis.com"]


def test_domain_account_matches_its_registrable_domain():
    s = summarize_record(obs(org="Amazon.com, Inc.", isp="Amazon.com, Inc.", ssl=_cert("gitlab.tmeic.in"),
                             _shodan={**BASE["_shodan"], "options": {"hostname": "gitlab.tmeic.in"}}),
                         "dom:tmeic.in", "tmeic.in")
    assert "cert_cn:tmeic.in" in s["names_account"]


def test_ntlm_is_reported_without_its_values():
    s = summarize_record(obs(org="DigitalOcean, LLC", isp="DigitalOcean, LLC", port=3389,
                             ntlm={"dns_domain_name": "corp.acme-energy.com", "netbios_domain_name": "ACME",
                                   "fqdn": "dc1.corp.acme-energy.com"}),
                         "dom:acme-energy.com", "acme-energy.com")
    assert (s["ntlm_present"], s["ntlm_names_account"]) == (True, True)
    assert "corp.acme-energy.com" not in repr(s) and "ACME" not in repr(s)
    assert s["names_account"] == []          # NTLM is not public corroboration


def test_signal_context_comes_from_the_record():
    s = summarize_record(obs(org="Acme Inc", isp="Acme Inc", product="FortiGate", version="7.2",
                             http={"title": "FortiGate - Login", "host": "vpn.acme.com"},
                             data="HTTP/1.1 200 OK\r\nServer: xxxxxxxx-xxxxx\r\n\r\n"),
                         "org:acme", "Acme Inc")
    assert (s["product"], s["version"], s["http_title"]) == ("FortiGate", "7.2", "FortiGate - Login")
    assert s["banner_head"].startswith("HTTP/1.1 200 OK")
    assert "http_host:acme.com" in s["names_account"]


@pytest.mark.parametrize("records, verdict", [
    ([{"names_account": ["cert_cn:mcgill.ca"], "third_party": []}, {"names_account": [], "third_party": []}],
     "corroborated"),
    # only reverse DNS names the account: the IP owner's zone, not the service's own name
    ([{"names_account": ["hostname:weserve.nl", "domain:weserve.nl"], "third_party": []}], "reverse_dns_only"),
    ([{"names_account": [], "third_party": ["munsterhuis.com"]},
      {"names_account": [], "third_party": ["lankhof.nl"]}, {"names_account": [], "third_party": []}],
     "contradicted"),
    ([{"names_account": [], "third_party": []}, {"names_account": [], "third_party": []}], "registry_only"),
    ([{"names_account": [], "third_party": ["a.com"]}, {"names_account": [], "third_party": []},
      {"names_account": [], "third_party": []}], "weak"),
    ([], "no_evidence"),
])
def test_ownership_verdict(records, verdict):
    assert ownership_verdict(records) == verdict


# ------------------------------------------------------------------------------ looser name matching
from firmable.evaluation.inspect import dominant_domain, plausibly_names_org  # noqa: E402


@pytest.mark.parametrize("domain, org, ok", [
    ("mit.edu", "Massachusetts Institute of Technology", True),     # initials
    ("rit.edu", "Rochester Institute of Technology", True),
    ("ucsb.edu", "University of California, Santa Barbara", True),
    ("nthu.edu.tw", "National Tsing Hua University", True),
    ("usp.br", "UNIVERSIDADE DE SAO PAULO", True),                  # stopword "de" skipped
    ("ucdavis.edu", "University of California, Davis", True),       # distinctive token inside label
    ("berkeley.edu", "University of California at Berkeley", True),
    ("sap.com", "SAP SE", True),                                    # label equals first token
    ("mcgill.ca", "McGill University", True),                       # attribution matcher still applies
    ("draytek.com", "National Tsing Hua University", False),
    ("munsterhuis.com", "Weserve B.V.", False),
    ("sfr.net", "Completel SAS", False),
    ("universityoffun.com", "University of Utah", False),           # generic words never match
])
def test_plausibly_names_org(domain, org, ok):
    assert plausibly_names_org(domain, org) is ok


def test_acronym_domain_corroborates_in_record_summary():
    s = summarize_record(obs(org="Massachusetts Institute of Technology", isp="Massachusetts Institute of Technology",
                             ssl=_cert("rdp.csail.mit.edu")),
                         "org:massachusetts institute of technology", "Massachusetts Institute of Technology")
    assert s["names_account"] == ["cert_cn:mit.edu"] and s["third_party"] == []


def test_dominant_domain_reports_share_and_whether_it_is_only_reverse_dns():
    recs = [{"third_party": ["sfr.net"], "third_party_sources": {"sfr.net": ["hostname"]}},
            {"third_party": ["sfr.net"], "third_party_sources": {"sfr.net": ["hostname", "domain"]}},
            {"third_party": ["acme.fr"], "third_party_sources": {"acme.fr": ["cert_cn"]}},
            {"third_party": [], "third_party_sources": {}}]
    assert dominant_domain(recs) == {"domain": "sfr.net", "records": 2, "share": 0.5, "reverse_dns_only": True}
    assert dominant_domain([{"third_party": [], "third_party_sources": {}}]) is None


# ------------------------------------------------------------------------------ signal support from the record
from firmable.evaluation.inspect import signal_supported  # noqa: E402


@pytest.mark.parametrize("signal_id, detail, kw, ok", [
    ("S01", "FortiGate", dict(product="FortiGate"), True),
    ("S01", "Ivanti / Pulse Secure", dict(http={"title": "Pulse Secure"}), True),
    ("S03", "RDP", dict(port=3389, _shodan={**BASE["_shodan"], "module": "rdp"}), True),
    ("S01", "SonicWall", dict(product="nginx", data="HTTP/1.1 200 OK\r\n\r\n"), False),
    # vendor names that differ between the signal label and the banner
    ("S04", "Elasticsearch", dict(product="Elastic"), True),
    ("S01", "WatchGuard", dict(http={"title": "Fireware XTM User Authentication"}), True),
    ("S01", "FortiGate", dict(product="Fortinet FortiWiFi-60F"), True),
    ("S16", "F5 BIG-IP", dict(product="BigIP"), True),
    ("S06", "Expired certificate", dict(ssl={**_cert("a.example.com"), "cert": {**_cert("a.example.com")["cert"], "expired": True}}), True),
    ("S06", "TLS 1.0/1.1 accepted", dict(ssl={**_cert("a.example.com"), "versions": ["TLSv1", "TLSv1.2"]}), True),
    ("S06", "TLS 1.0/1.1 accepted", dict(ssl={**_cert("a.example.com"), "versions": ["-TLSv1", "TLSv1.2"]}), False),
])
def test_signal_supported_by_the_raw_record(signal_id, detail, kw, ok):
    assert signal_supported(signal_id, detail, obs(**kw)) is ok


def test_signal_support_folds_accents_on_both_sides():
    from firmable.evaluation.inspect import signal_supported
    assert signal_supported("S01", "Gestion", {"http_title": "Gestión remota"}) is True
    assert signal_supported("S01", "Ñuñoa", {"http_title": "NUNOA portal"}) is True
    assert signal_supported("S01", "Ñuñoa", {"http_title": "Santiago"}) is False
