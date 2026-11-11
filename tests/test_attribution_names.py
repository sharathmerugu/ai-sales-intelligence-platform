"""Attribution v1, pure name functions: registrable domain (PSL) and name filter outcome."""

from __future__ import annotations

import pytest

from firmable.attribution.names import name_outcome, normalize_name, registrable_domain


# ---------------------------------------------------------------- registrable_domain
@pytest.mark.parametrize(
    "name, expected",
    [
        ("www.example.com", "example.com"),
        ("WWW.Example.COM.", "example.com"),          # lower-case, trailing dot
        ("*.example.com", "example.com"),             # wildcard stripped
        ("shop.bbc.co.uk", "bbc.co.uk"),              # ICANN two-level suffix
        ("portal.acme.com.au", "acme.com.au"),
        ("alice.github.io", "alice.github.io"),       # PSL private suffix: each subdomain is a different owner
        ("bob.github.io", "bob.github.io"),
        ("www.alice.github.io", "alice.github.io"),
        ("myapp.herokuapp.com", "myapp.herokuapp.com"),
        ("github.io", None),                          # the private suffix itself is not registrable
        ("co.uk", None),
        ("com", None),
        ("printer.local", None),                      # unknown / non-public TLD
        ("kubernetes", None),
        ("192.0.2.10", None),                         # IP literals
        ("2001:db8::1", None),
        ("[2001:db8::1]", None),
        ("", None),
        (None, None),
    ],
)
def test_registrable_domain(name, expected):
    assert registrable_domain(name) == expected


def test_normalize_name_strips_wildcard_port_and_marks_wildcard():
    assert normalize_name("*.Example.com.") == ("example.com", True)
    assert normalize_name("Example.com:8443") == ("example.com", False)
    assert normalize_name("  www.dlink.com\r") == ("www.dlink.com", False)
    assert normalize_name("a.example.com") == ("a.example.com", False)


# ---------------------------------------------------------------- name_outcome
@pytest.mark.parametrize(
    "name, expected",
    [
        ("www.acme-industries.com", "accepted"),
        ("vpn.acme.co.uk", "accepted"),
        ("alice.github.io", "accepted"),
        ("*.acme.com", "accepted"),
        ("acme.com:443", "accepted"),
        # IP literals
        ("192.0.2.10", "ip_literal"),
        ("2001:db8::1", "ip_literal"),
        ("[2001:db8::1]:443", "ip_literal"),
        # invalid strings
        ("", "invalid"),
        ("   ", "invalid"),
        ("traefik default cert", "invalid"),
        ("yzy@xspeeder.com", "invalid"),
        ("cdn.server,cdn.data.center", "invalid"),
        # provider / ISP reverse DNS
        ("ec2-198-51-100-7.compute-1.amazonaws.com", "ptr_like"),
        ("203-0-113-9.static.example-isp.net", "ptr_like"),
        ("static-100.example-isp.net", "ptr_like"),
        ("dsl-12.example-isp.de", "ptr_like"),
        ("cust123.example-isp.com", "ptr_like"),
        # non-public TLDs and pseudo-TLDs
        ("unifi.local", "non_company"),
        ("nas.lan", "non_company"),
        ("dc01.acme.corp", "non_company"),
        ("localhost", "non_company"),
        ("localhost.localdomain", "non_company"),
        ("router.gateway", "non_company"),
        ("invalid2.invalid", "non_company"),
        ("kubernetes", "non_company"),
        ("traefik.default", "non_company"),
        # vendor default certificate names
        ("draytek.com", "non_company"),
        ("www.draytek.com", "non_company"),
        ("fortinet.com", "non_company"),
        ("tplinkwifi.net", "non_company"),
        ("synology.com", "non_company"),
        ("router.asus.com", "non_company"),
        ("captive-portal.peplink.com", "non_company"),
        ("imap.example.com", "non_company"),
        ("notexist.com", "non_company"),
        ("www.fritz.box", "non_company"),               # AVM router default (.box is a real gTLD)
        # dynamic-DNS / device-cloud parents: per-user subdomains of one vendor zone (fix round 2026-11-10)
        ("shige-yokohama.softether.net", "non_company"),
        ("vpn123456.vpnazure.net", "non_company"),
        ("montividiu.fortiddns.com", "non_company"),
        ("awbury.3cx.us", "non_company"),
        ("innotec.3cx.uk", "non_company"),
        ("ahipl.3cx.com.au", "non_company"),
        ("elfisystems.my3cx.it", "non_company"),
        ("stjo.on3cx.fr", "non_company"),
        ("e430229eb34a.hanwha-security.com", "non_company"),
        ("abc123.us-cal-1.ngrok.io", "non_company"),
        ("tunnel.ngrok-free.app", "non_company"),
        ("myhost.dynv6.net", "non_company"),
        ("hex1234.sn.mynetname.net", "non_company"),
        ("cam1.secomddns.jp", "non_company"),
        ("21500104852sl3602278.huawei.com", "non_company"),   # per-device serial certificate
        ("2s2470002537.huawei.com", "non_company"),
        ("xinsheng.huawei.com", "accepted"),                   # Huawei's own host stays
        ("www.my-3cx-partner.com", "accepted"),               # Alibaba WAF default certificate CN
        ("www.notexist.com", "non_company"),
        # consumer dynamic DNS (many are PSL private suffixes, so match the zone, not the reg domain)
        ("myhome.duckdns.org", "non_company"),
        ("cam.synology.me", "non_company"),
        ("box.myfritz.net", "non_company"),
        ("nas.myqnapcloud.com", "non_company"),
        ("x.no-ip.org", "non_company"),
        # hosting-brand / provider certificate namespaces
        ("srv123.hstgr.cloud", "provider_cert"),
        ("sni.cloudflaressl.com", "provider_cert"),
        ("abc.certfallback.com", "provider_cert"),
        ("x1.a9i3rk.deu-c1.eu1.cloudhub.io", "provider_cert"),   # MuleSoft tenant namespace
        # no registrable domain
        ("github.io", "no_registrable_domain"),
        ("synology", "no_registrable_domain"),
        ("fortigate", "non_company"),                 # bare vendor default CN (ported list)
        ("foo.unknowntld", "no_registrable_domain"),
    ],
)
def test_name_outcome_context_free(name, expected):
    assert name_outcome(name) == expected


def test_name_outcome_infra_domain_is_snapshot_data():
    infra = frozenset({"googleusercontent.com", "ocn.ne.jp"})
    assert name_outcome("p1234.example.ocn.ne.jp", infra_domains=infra) == "infra_domain"
    assert name_outcome("abc.googleusercontent.com", infra_domains=infra) == "infra_domain"
    assert name_outcome("www.acme.com", infra_domains=infra) == "accepted"
    # without the snapshot set the same name is accepted
    assert name_outcome("p1234.example.ocn.ne.jp") == "accepted"


def test_name_outcome_shared_certificate_names_apply_to_cert_sources_only():
    shared = frozenset({"www.bigvendor.com"})
    assert name_outcome("www.bigvendor.com", source="cert_cn", shared_cert_names=shared) == "provider_cert"
    assert name_outcome("*.www.bigvendor.com", source="cert_san", shared_cert_names=shared) == "provider_cert"
    assert name_outcome("www.bigvendor.com", source="sni", shared_cert_names=shared) == "accepted"
    assert name_outcome("other.bigvendor.com", source="cert_cn", shared_cert_names=shared) == "accepted"
