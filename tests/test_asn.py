"""OpenASN reference table and network-provider rules (pure functions).

Expected values come from the pinned release rows (reference/openasn/v2026.10.18) and the
rules in docs/network-classification.md.
"""

from __future__ import annotations

import pytest

from firmable.attribution.asn import AsnInfo, asn_number, load_openasn, network_provider_class
from firmable.attribution.providers import domain_matches_org


def test_pinned_release_loads_and_verifies():
    table = load_openasn()
    assert len(table) == 119322
    assert table[7922] == AsnInfo("isp", "access_provider", ())                 # Comcast
    assert table[24940] == AsnInfo("hosting", "midsize_transit", ("bad_asn",))  # Hetzner
    assert table[2].category == "education_research"


def test_checksum_mismatch_is_refused(tmp_path):
    bad = tmp_path / "asn-categories.csv"
    bad.write_text("asn,org,country,category,network_role,openasn_flags\n1,,,isp,,\n")
    with pytest.raises(ValueError, match="sha256"):
        load_openasn(bad)


@pytest.mark.parametrize("raw, n", [("AS7922", 7922), ("as24940", 24940), ("7922", 7922), ("", None), (None, None),
                                    ("ASX", None)])
def test_asn_number(raw, n):
    assert asn_number(raw) == n


@pytest.mark.parametrize("info, cls", [
    (AsnInfo("isp", "access_provider", ()), "isp_telco"),
    (AsnInfo("isp", None, ()), "isp_telco"),
    (AsnInfo("hosting", "midsize_transit", ()), "cloud_hosting"),        # Claranet, Telx
    (AsnInfo("hosting", "stub", ()), "cloud_hosting"),
    (AsnInfo("hosting", "access_provider", ("bad_asn",)), "cloud_hosting"),  # DigitalOcean
    (AsnInfo("hosting", "content_network", ("cdn",)), "cdn"),           # Fastly
    # Content and big-tech enterprises OpenASN files under hosting: not network providers.
    (AsnInfo("hosting", "content_network", ()), None),                  # Netflix, Salesforce
    (AsnInfo("hosting", "access_provider", ()), None),                  # Apple AS714, Meta AS32934
    (AsnInfo("business", "stub", ()), None),
    (AsnInfo("education_research", "stub", ()), None),
    (AsnInfo("government_admin", None, ()), None),
    (AsnInfo(None, None, ()), None),                                    # unknown stays unknown
    (None, None),
])
def test_network_provider_class(info, cls):
    assert network_provider_class(info) == cls


@pytest.mark.parametrize("domain, org, ok", [
    ("eastlink.ca", "EastLink", True),
    ("skywaywest.net", "Skyway West", True),               # tokens concatenated
    ("claranet.com", "Claranet Limited", True),
    ("railtelindia.com", "RailTel Corporation of India Ltd.", True),  # label starts with first token
    ("dialog.lk", "Dialog Axiata Plc", True),
    ("sky-way-west.net", "Skyway West", True),             # hyphens ignored
    ("acme-energy.com", "Skyway West", False),
    ("its.com", "ITS Technology Group Limited", False),     # first token shorter than 4: too weak
    ("telxapp.com", "Telx", True),
    ("google.com", "Cloud Telecom", False),
    ("cloudflare.com", "Cloud Telecom", False),            # generic first token: no prefix match
    ("datacenter.com", "Data Systems Inc", False),
    ("ovh.net", "OVH SAS", True),                          # exact concatenation still matches
    (None, "EastLink", False),
    ("eastlink.ca", None, False),
])
def test_domain_matches_org(domain, org, ok):
    assert domain_matches_org(domain, org) is ok
