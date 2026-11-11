from datetime import datetime

import pytest

from firmable.ingest.normalize import Rejection, normalize_line

from factories import line, record


def test_valid_ipv4_banner_becomes_observation_with_service_identity():
    obs = normalize_line(line())

    assert not isinstance(obs, Rejection)
    assert obs["ip"] == "192.0.2.1"
    assert obs["ip_version"] == 4
    assert obs["port"] == 443
    assert obs["transport"] == "tcp"
    assert obs["sni"] == ""
    assert obs["observed_at"] == datetime(2026, 11, 7, 14, 52, 1, 123456)
    assert obs["observation_id"] == "00000000-0000-0000-0000-000000000001"
    assert obs["org"] == "Example Corp"
    assert obs["hostnames"] == ["vpn.example.com"]
    assert obs["parse_warnings"] == []


def test_ipv6_only_record_uses_canonical_compressed_ipv6():
    obs = normalize_line(line(ip=..., ip_str=..., ipv6="2001:0DB8:0000:0000:0000:0000:0000:0001"))

    assert obs["ip"] == "2001:db8::1"
    assert obs["ip_version"] == 6


def test_ipv4_mapped_ipv6_folds_to_ipv4_and_shares_service_id():
    v4 = normalize_line(line())
    mapped = normalize_line(line(ip=..., ip_str=..., ipv6="::ffff:192.0.2.1"))

    assert mapped["ip"] == "192.0.2.1"
    assert mapped["ip_version"] == 4
    assert mapped["service_id"] == v4["service_id"]


def test_sni_is_lowercased_without_trailing_dot_and_splits_virtual_hosts():
    shodan = record()["_shodan"]
    a = normalize_line(line(_shodan={**shodan, "options": {"hostname": "WWW.Example.COM."}}))
    b = normalize_line(line(_shodan={**shodan, "options": {"hostname": "shop.example.com"}}))
    bare = normalize_line(line())

    assert a["sni"] == "www.example.com"
    assert len({a["service_id"], b["service_id"], bare["service_id"]}) == 3


def test_service_id_is_stable_known_value():
    # Oracle computed outside the code: sha256(b"192.0.2.1|443|tcp|").hexdigest()[:32]
    obs = normalize_line(line())
    assert obs["service_id"] == "823196974f91caafef5719c2af183b83"


@pytest.mark.parametrize(
    "raw, error_class",
    [
        (b'{"ip_str": "192.0.2.1", "port": 4', "malformed_json"),
        (b"[1, 2, 3]", "not_an_object"),
        (line(port=...), "missing_required"),
        (line(transport=...), "missing_required"),
        (line(timestamp=...), "missing_required"),
        (line(ip=..., ip_str=...), "missing_required"),
        (line(port=70000), "invalid_value"),
        (line(port="https"), "invalid_value"),
        (line(transport="sctp"), "invalid_value"),
        (line(ip_str="999.1.1.1"), "invalid_value"),
        (line(timestamp="yesterday"), "invalid_value"),
    ],
)
def test_unusable_lines_are_rejected_with_an_error_class(raw, error_class):
    result = normalize_line(raw)

    assert isinstance(result, Rejection)
    assert result.error_class == error_class


def test_lone_surrogate_escape_is_repaired_not_dropped():
    # Real failure class from research: 451 lines with invalid UTF-16 surrogate escapes.
    raw = line().replace(b'"Example Corp"', b'"Bad \\ud800 Corp"')

    obs = normalize_line(raw)

    assert not isinstance(obs, Rejection)
    assert obs["org"] == "Bad � Corp"
    assert obs["unicode_repaired"] is True
    assert normalize_line(line())["unicode_repaired"] is False


def test_numeric_string_port_is_schema_drift_coerced_with_warning():
    obs = normalize_line(line(port="443"))

    assert obs["port"] == 443
    assert "port:coerced" in obs["parse_warnings"]


def test_timezone_aware_timestamp_is_stored_as_naive_utc():
    obs = normalize_line(line(timestamp="2026-11-07T16:52:01+02:00"))

    assert obs["observed_at"] == datetime(2026, 11, 7, 14, 52, 1)


def test_missing_scanner_id_falls_back_to_deterministic_content_key():
    shodan = {k: v for k, v in record()["_shodan"].items() if k != "id"}
    a = normalize_line(line(_shodan=shodan))
    b = normalize_line(line(_shodan=shodan))
    c = normalize_line(line(_shodan=shodan, hash=42))

    assert a["observation_id"].startswith("c:")
    assert a["observation_id"] == b["observation_id"]
    assert a["observation_id"] != c["observation_id"]


TLS_HTTP = dict(
    product="nginx",
    version="1.18.0",
    cpe23=["cpe:2.3:a:f5:nginx:1.18.0"],
    tags=["cloud", "self-signed"],
    cloud={"provider": "Amazon", "service": "EC2", "region": "ap-southeast-2"},
    http={
        "status": 200,
        "title": "GlobalProtect Portal",
        "server": "nginx",
        "host": "vpn.example.com",
        "waf": None,
        "html_hash": 987,
        "favicon": {"hash": -12345, "data": "AAAA"},
        "securitytxt": "Contact: mailto:sec@example.com",
        "headers": {"strict-transport-security": "max-age=1", "x-powered-by": "PHP/7.4"},
        "components": {"Imperva": {"categories": ["Security", "CDN"]}, "jQuery": {"categories": ["JS"]}},
        "html": "<html>" + "x" * 5000 + "</html>",
    },
    ssl={
        "versions": ["TLSv1", "-TLSv1.1", "TLSv1.2"],
        "jarm": "2ad2ad",
        "trust": {"browser": {"mozilla": True}},
        "cert": {
            "expired": False,
            "expires": "20270101120000Z",
            "issued": "20260101120000Z",
            "subject": {"CN": "vpn.example.com", "O": "Example Corp"},
            "issuer": {"CN": "Example CA", "O": "Example CA Inc"},
            "sig_alg": "sha256WithRSAEncryption",
            "pubkey": {"type": "rsa", "bits": 2048},
            "fingerprint": {"sha256": "ab" * 32},
            "extensions": [
                {"name": "subjectAltName",
                 "data": "0%\\x82\\x0fvpn.example.com\\x82\\x12portal.example.com"},
            ],
        },
    },
    vulns={
        "CVE-2021-0001": {"cvss": 9.8, "verified": False, "kev": True, "epss": 0.9,
                          "ransomware_campaign": "Known", "summary": "long text"},
        "CVE-2021-0002": {"cvss": 5.0, "verified": False},
    },
    ntlm={"dns_domain_name": "corp.example.com", "netbios_domain_name": "CORP",
          "fqdn": "dc1.corp.example.com", "os_build": "10.0.17763"},
    rdp_encryption={"levels": ["tls"]},
    data="HTTP/1.1 200 OK\r\n" + "y" * 400,
)


def test_tls_http_and_vulns_fields_are_typed_and_compacted():
    obs = normalize_line(line(**TLS_HTTP))

    assert obs["product"] == "nginx" and obs["version"] == "1.18.0"
    assert obs["tags"] == ["cloud", "self-signed"]
    assert obs["cloud_provider"] == "Amazon" and obs["cloud_region"] == "ap-southeast-2"
    assert obs["http_status"] == 200
    assert obs["http_title"] == "GlobalProtect Portal"
    assert obs["http_host"] == "vpn.example.com"
    assert obs["favicon_hash"] == -12345
    assert obs["has_securitytxt"] is True
    assert obs["has_hsts"] is True and obs["has_csp"] is False
    assert obs["x_powered_by"] == "PHP/7.4"
    assert obs["http_components"] == ["Imperva", "jQuery"]
    assert obs["has_ssl"] is True
    assert obs["ssl_versions"] == ["TLSv1", "-TLSv1.1", "TLSv1.2"]
    assert obs["cert_expires"] == datetime(2027, 1, 1, 12, 0, 0)
    assert obs["cert_subject_cn"] == "vpn.example.com"
    assert obs["cert_issuer_o"] == "Example CA Inc"
    assert obs["cert_key_bits"] == 2048
    assert obs["cert_trust_mozilla"] is True
    assert obs["cert_san_dns"] == ["vpn.example.com", "portal.example.com"]
    assert obs["ntlm_dns_domain"] == "corp.example.com"
    assert obs["vulns"] == [
        {"cve": "CVE-2021-0001", "cvss": 9.8, "kev": True, "verified": False, "epss": 0.9, "ransomware_known": True},
        {"cve": "CVE-2021-0002", "cvss": 5.0, "kev": False, "verified": False, "epss": None, "ransomware_known": False},
    ]
    assert obs["any_kev"] is True and obs["any_verified"] is False
    assert obs["banner_len"] == len("HTTP/1.1 200 OK\r\n" + "y" * 400)
    assert len(obs["banner_head"]) == 160
    assert '"rdp_encryption"' in obs["protocol_json"]
    assert obs["parse_warnings"] == []


def test_wrong_typed_optional_fields_become_null_with_warnings():
    obs = normalize_line(line(hostnames="vpn.example.com", tags=None, http={"status": "OK", "title": 5}))

    assert obs["hostnames"] is None
    assert obs["http_status"] is None
    assert obs["http_title"] is None
    assert {"hostnames:type", "http.status:type", "http.title:type"} <= set(obs["parse_warnings"])


def test_unknown_top_level_keys_are_reported_as_schema_drift():
    obs = normalize_line(line(brand_new_probe={"x": 1}))

    assert obs["unknown_keys"] == ["brand_new_probe"]
    assert normalize_line(line())["unknown_keys"] == []


def test_empty_banner_has_zero_length():
    obs = normalize_line(line(data="  \r\n "))

    assert obs["banner_len"] == 0


def test_unknown_protocol_objects_are_preserved_in_protocol_json():
    obs = normalize_line(line(brand_new_probe={"x": 1}))

    assert obs["protocol_json"] == '{"brand_new_probe":{"x":1}}'


def test_malformed_nested_structures_degrade_to_warnings_not_failures():
    # Review finding C1: non-list cert extensions used to raise TypeError and fail the chunk.
    obs = normalize_line(line(ssl={"cert": {"extensions": 5}}, http={"status": 2**40}))

    assert not isinstance(obs, Rejection)
    assert obs["cert_san_dns"] is None and "ssl.cert.extensions:type" in obs["parse_warnings"]
    assert obs["http_status"] is None and "http.status:range" in obs["parse_warnings"]
