"""Signal layer v1 (M1): S01, S03, S04, S05, S06, S16 over synthetic services rows.

Seam: `build_signal_hits(services_parquet, out_parquet)`. Rows come from
`tests/service_rows.py`, which writes the exact production services schema.
Expected values are hand-written literals from the catalog, never recomputed.
"""

from __future__ import annotations

import json
import re
import string
from types import SimpleNamespace

import duckdb
import pytest

from firmable.signals import SIGNALS, build_signal_hits, signal_hits_path
from firmable.signals.registry import FACT_PLACEHOLDERS, SIGNALS_VERSION

from service_rows import service_row, write_services


def _hits(tmp_path, rows, **kw):
    src = write_services(tmp_path / "services.parquet", rows)
    out = tmp_path / "out" / "signal_hits.parquet"
    result = build_signal_hits(src, out, **kw)
    with duckdb.connect() as con:
        cur = con.execute(f"SELECT * FROM read_parquet('{out}', hive_partitioning = false) ORDER BY service_id, signal_id")
        cols = [d[0] for d in cur.description]
        hits = [dict(zip(cols, r)) for r in cur.fetchall()]
    return hits, result


def _by_service(hits):
    """{service_id: {signal_id: (match_basis, detail, sub_flags)}}"""
    out: dict = {}
    for h in hits:
        out.setdefault(h["service_id"], {})[h["signal_id"]] = (h["match_basis"], h["detail"], h["sub_flags"])
    return out


def _signals_for(hits, row):
    return _by_service(hits).get(row["service_id"], {})


# --------------------------------------------------------------------------- contract


EXPECTED_SCHEMA = [
    ("snapshot_id", "VARCHAR"),
    ("signal_id", "VARCHAR"),
    ("signal_version", "INTEGER"),
    ("family", "VARCHAR"),
    ("service_id", "VARCHAR"),
    ("observation_id", "VARCHAR"),
    ("file_id", "VARCHAR"),
    ("byte_offset", "BIGINT"),
    ("byte_length", "INTEGER"),
    ("record_sha256", "VARCHAR"),
    ("ip", "VARCHAR"),
    ("port", "INTEGER"),
    ("transport", "VARCHAR"),
    ("sni", "VARCHAR"),
    ("observed_at", "TIMESTAMP"),
    ("is_cdn", "BOOLEAN"),
    ("country_code", "VARCHAR"),
    ("product", "VARCHAR"),
    ("version", "VARCHAR"),
    ("http_title", "VARCHAR"),
    ("module", "VARCHAR"),
    ("match_basis", "VARCHAR"),
    ("detail", "VARCHAR"),
    ("sub_flags", "VARCHAR[]"),
    ("evidence_json", "VARCHAR"),
]


def test_output_schema_is_exactly_the_contract(tmp_path):
    _, _ = _hits(tmp_path, [service_row(product="SonicWall")])
    out = tmp_path / "out" / "signal_hits.parquet"
    with duckdb.connect() as con:
        schema = con.execute(
            f"DESCRIBE SELECT * FROM read_parquet('{out}', hive_partitioning = false)"
        ).fetchall()
    assert [(r[0], r[1]) for r in schema] == EXPECTED_SCHEMA


def test_schema_is_exact_even_when_nothing_matches(tmp_path):
    hits, result = _hits(tmp_path, [service_row(product="nginx", http_title="Welcome")])
    assert hits == []
    assert result["rows"] == 0
    out = tmp_path / "out" / "signal_hits.parquet"
    with duckdb.connect() as con:
        schema = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{out}')").fetchall()
    assert [(r[0], r[1]) for r in schema] == EXPECTED_SCHEMA


def test_provenance_and_evidence_columns_are_copied_from_the_service(tmp_path):
    row = service_row(
        product="SonicWall", version="7.0", http_title="SonicWall Network Security Login",
        ip="198.51.100.7", port=4433, sni="vpn.example.com", country_code="DE",
        file_id="a" * 64, byte_offset=123456, byte_length=789, record_sha256="b" * 64,
        observation_id="11111111-2222-3333-4444-555555555555", snapshot_id="2026-11-07",
    )
    hits, _ = _hits(tmp_path, [row])
    s01 = next(h for h in hits if h["signal_id"] == "S01")
    assert s01["snapshot_id"] == "2026-11-07"
    assert s01["signal_version"] == 1
    assert s01["family"] == "exposure"
    assert s01["service_id"] == row["service_id"]
    assert s01["observation_id"] == "11111111-2222-3333-4444-555555555555"
    assert (s01["file_id"], s01["byte_offset"], s01["byte_length"], s01["record_sha256"]) == ("a" * 64, 123456, 789, "b" * 64)
    assert (s01["ip"], s01["port"], s01["transport"], s01["sni"]) == ("198.51.100.7", 4433, "tcp", "vpn.example.com")
    assert s01["observed_at"].isoformat() == "2026-11-07T14:52:01"
    assert s01["is_cdn"] is False
    assert s01["country_code"] == "DE"
    assert (s01["product"], s01["version"], s01["http_title"], s01["module"]) == (
        "SonicWall", "7.0", "SonicWall Network Security Login", "https")
    assert json.loads(s01["evidence_json"])["product"] == "SonicWall"


def test_one_row_per_signal_and_service_and_counts_in_result(tmp_path):
    rows = [
        service_row(product="SonicWall"),                         # S01 + S16
        service_row(product="MySQL", module="mysql", port=3306),  # S04
        service_row(product="nginx"),                             # nothing
    ]
    hits, result = _hits(tmp_path, rows)
    keys = [(h["signal_id"], h["service_id"]) for h in hits]
    assert len(keys) == len(set(keys)) == 3
    assert result["counts"] == {"S01": 1, "S03": 0, "S04": 1, "S05": 0, "S06": 0, "S16": 1}
    assert result["rows"] == 3
    assert result["signals_version"] == 1
    assert result["wall_seconds"] >= 0


def test_publish_is_atomic_and_leaves_no_temp_file(tmp_path):
    _hits(tmp_path, [service_row(product="SonicWall")])
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["signal_hits.parquet"]


def test_snapshot_filter_keeps_only_that_snapshot(tmp_path):
    a = service_row(product="SonicWall", snapshot_id="s1")
    b = service_row(product="SonicWall", snapshot_id="s2")
    hits, _ = _hits(tmp_path, [a, b], snapshot_id="s1")
    assert {h["snapshot_id"] for h in hits} == {"s1"}
    assert {h["service_id"] for h in hits} == {a["service_id"]}


def test_signal_hits_path_mirrors_the_services_layout(tmp_path):
    pipe = SimpleNamespace(lake=tmp_path / "lake")
    assert signal_hits_path(pipe, "2026-11-07") == (
        tmp_path / "lake/signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet")


def test_null_lists_do_not_drop_or_crash_rows(tmp_path):
    """DuckDB NULL trap: list_contains(NULL, x) is NULL. NULL tags/ssl_versions must behave like []."""
    mysql = service_row(product="MySQL", module="mysql", port=3306, tags=None)
    plain = service_row(product="nginx", tags=None, ssl_versions=None, has_ssl=True, module=None)
    hits, _ = _hits(tmp_path, [mysql, plain])
    assert _signals_for(hits, mysql) == {"S04": ("product", "MySQL", [])}
    assert _signals_for(hits, plain) == {}


# --------------------------------------------------------------------------- S01


def test_s01_positives_by_product_title_and_protocol_object(tmp_path):
    sonic = service_row(product="SonicWall")
    gp = service_row(http_title="GlobalProtect Portal")
    netscaler = service_row(product="Citrix Netscaler")
    forti_obj = service_row(module="https-simple-new", port=10443,
                            protocol_json='{"fortinet":{"model":"FG100F","serial_number":"FG100FTK00000000"}}')
    anyconnect = service_row(protocol_json='{"cisco_anyconnect":{"config_hash":"1","tunnel_group":"DefaultWEBVPNGroup"}}')
    bigip = service_row(http_title="BIG-IP logout page")
    draytek = service_row(product="DrayTek Vigor2862 Series")
    hits, _ = _hits(tmp_path, [sonic, gp, netscaler, forti_obj, anyconnect, bigip, draytek])
    assert _signals_for(hits, sonic)["S01"] == ("product", "SonicWall", [])
    assert _signals_for(hits, gp)["S01"] == ("title", "Palo Alto GlobalProtect", [])
    assert _signals_for(hits, netscaler)["S01"] == ("product", "Citrix NetScaler", [])
    assert _signals_for(hits, forti_obj)["S01"] == ("protocol", "FortiGate", [])
    assert _signals_for(hits, anyconnect)["S01"] == ("protocol", "Cisco ASA / AnyConnect", [])
    assert _signals_for(hits, bigip)["S01"] == ("title", "F5 BIG-IP", [])
    assert _signals_for(hits, draytek)["S01"] == ("product", "DrayTek", [])


def test_s01_product_beats_title_for_match_basis(tmp_path):
    row = service_row(product="Fortinet FortiGate-60F", http_title="FortiGate")
    hits, _ = _hits(tmp_path, [row])
    assert _signals_for(hits, row)["S01"] == ("product", "FortiGate", [])


def test_s01_counterexamples(tmp_path):
    cdn = service_row(product="SonicWall", is_cdn=True, tags=["cdn"])
    udp = service_row(product="Fortinet FortiGate", transport="udp", port=500)
    parked = service_row(product="nginx", http_title="sslvpn.example.com - Coming Soon")
    fortimanager = service_row(protocol_json='{"fortinet":{"model":"FMG-VM","serial_number":"FMG-VM0000"}}')
    hits, _ = _hits(tmp_path, [cdn, udp, parked, fortimanager])
    assert "S01" not in _signals_for(hits, cdn)
    assert "S01" not in _signals_for(hits, udp)
    assert _signals_for(hits, parked) == {}
    assert _signals_for(hits, fortimanager) == {}


# --------------------------------------------------------------------------- S03


def test_s03_positives(tmp_path):
    rdp = service_row(module="rdp", port=3389, product="Remote Desktop Protocol", banner_head="\x03\x00\x00\x13")
    rdp_noproduct = service_row(module="rdp", port=3389, banner_head="\x03\x00\x00\x13")
    vnc = service_row(module="auto", port=5900, product="VNC", banner_head="RFB 003.008")
    apple = service_row(module="auto", port=5900, product="Apple remote desktop vnc", banner_head="RFB 003.889")
    telnet = service_row(module="telnet", port=23, banner_head="\xff\xfd\x18login:")
    crestron = service_row(module="auto", port=23, product="Creston CP2E control telnetd", banner_head="CP2E Console")
    winrm = service_row(module="http", port=5985, product="WinRM", banner_head="HTTP/1.1 405")
    hits, _ = _hits(tmp_path, [rdp, rdp_noproduct, vnc, apple, telnet, crestron, winrm])
    assert _signals_for(hits, rdp) == {"S03": ("product", "RDP", [])}
    assert _signals_for(hits, rdp_noproduct) == {"S03": ("protocol", "RDP", [])}
    assert _signals_for(hits, vnc) == {"S03": ("product", "VNC", [])}
    assert _signals_for(hits, apple) == {"S03": ("product", "VNC", [])}
    assert _signals_for(hits, telnet) == {"S03": ("protocol", "Telnet", [])}
    assert _signals_for(hits, crestron) == {"S03": ("product", "Telnet", [])}
    assert _signals_for(hits, winrm) == {"S03": ("product", "WinRM", [])}


def test_s03_counterexamples(tmp_path):
    cdn_rdp = service_row(module="rdp", port=3389, is_cdn=True, tags=["cdn"], banner_head="\x03\x00")
    rdp_answered_by_ssh = service_row(module="rdp", port=3389, product="OpenSSH", banner_head="SSH-2.0-OpenSSH_7.4")
    x11_answered_by_http = service_row(module="x11", port=6000, product="nginx", banner_head="HTTP/1.1 400 Bad Request")
    telnet_http_noproduct = service_row(module="telnet", port=23, banner_head="HTTP/1.0 404 FAIL")
    telnet_socks = service_row(module="telnet", port=1080, product="Socks4A", banner_head="[")
    hits, _ = _hits(tmp_path, [cdn_rdp, rdp_answered_by_ssh, x11_answered_by_http, telnet_http_noproduct, telnet_socks])
    for row in (cdn_rdp, rdp_answered_by_ssh, x11_answered_by_http, telnet_http_noproduct, telnet_socks):
        assert "S03" not in _signals_for(hits, row), row["module"]


# --------------------------------------------------------------------------- S04


def test_s04_positives(tmp_path):
    mysql = service_row(module="mysql", port=3306, product="MySQL", banner_head="J\x00\x00\x00\n8.0.36")
    minio = service_row(product="MinIO Server", port=9000, banner_head="HTTP/1.1 403 Forbidden")
    browser = service_row(module="ms-sql-monitor", port=1434, transport="udp", product="SQL Server Browser Service", banner_head="ServerName;X")
    clickhouse = service_row(module="clickhouse-native", port=9000, banner_head="\x00\x02")
    redis_obj = service_row(module="auto", port=6379, banner_head="-NOAUTH", protocol_json='{"redis":{"error":"NOAUTH"}}')
    tagged = service_row(module="https", product="Typesense", tags=["database"], banner_head="HTTP/1.1 401")
    hits, _ = _hits(tmp_path, [mysql, minio, browser, clickhouse, redis_obj, tagged])
    assert _signals_for(hits, mysql) == {"S04": ("product", "MySQL", [])}
    assert _signals_for(hits, minio) == {"S04": ("product", "MinIO", [])}
    assert _signals_for(hits, browser) == {"S04": ("product", "SQL Server Browser", [])}
    assert _signals_for(hits, clickhouse) == {"S04": ("protocol", "ClickHouse", [])}
    assert _signals_for(hits, redis_obj) == {"S04": ("protocol", "Redis", [])}
    assert _signals_for(hits, tagged) == {"S04": ("tag", "Typesense", [])}


def test_s04_counterexamples(tmp_path):
    db_module_http = service_row(module="mysql", port=3306, banner_head="HTTP/1.1 400 Bad Request")
    db_module_ssh = service_row(module="rethinkdb", port=28015, product="OpenSSH", banner_head="SSH-2.0-OpenSSH_8.0")
    cdn_clickhouse = service_row(module="clickhouse-native", port=9000, is_cdn=True, tags=["cdn"], banner_head="\x00\x02")
    # Decision (documented): the `database` tag on a generic web-server front is not
    # evidence of a reachable data store; the catalog saw this on 404 nginx services.
    nginx_tagged = service_row(module="https", product="nginx", tags=["database"], banner_head="HTTP/1.1 404 Not Found")
    hits, _ = _hits(tmp_path, [db_module_http, db_module_ssh, cdn_clickhouse, nginx_tagged])
    for row in (db_module_http, db_module_ssh, cdn_clickhouse, nginx_tagged):
        assert _signals_for(hits, row) == {}, row["module"]


# --------------------------------------------------------------------------- S05


def test_s05_positives(tmp_path):
    whm = service_row(http_title="WHM Login", port=2087)
    grafana = service_row(product="Grafana", http_title="Grafana")
    unifi = service_row(http_title="UniFi OS")
    ilo = service_row(http_title="iLO 5")
    harbor = service_row(product="Harbor", http_title="Harbor", tags=["devops"])
    hits, _ = _hits(tmp_path, [whm, grafana, unifi, ilo, harbor])
    assert _signals_for(hits, whm) == {"S05": ("title", "WHM/cPanel", [])}
    assert _signals_for(hits, grafana) == {"S05": ("product", "Grafana", [])}
    assert _signals_for(hits, unifi) == {"S05": ("title", "UniFi", [])}
    assert _signals_for(hits, ilo) == {"S05": ("title", "HPE iLO", [])}
    assert _signals_for(hits, harbor) == {"S05": ("tag", "Harbor", [])}


def test_s05_counterexamples(tmp_path):
    cdn = service_row(http_title="Grafana", is_cdn=True, tags=["cdn"])
    word_boundary = service_row(http_title="Silo Manager")  # `\bilo\b` must not match inside a word
    hits, _ = _hits(tmp_path, [cdn, word_boundary])
    assert _signals_for(hits, cdn) == {}
    assert _signals_for(hits, word_boundary) == {}


def test_s05_v1_word_boundaries_and_parked_titles(tmp_path):
    """v1 change: research `consul`/`unifi`/`ipmi` matched inside words (734 of 744 'consul' hits were 'Consulting')."""
    consulting = service_row(product="nginx", http_title="GYL Consulting")
    consul = service_row(http_title="Consul by HashiCorp")
    unified = service_row(product="nginx", http_title="Unified Messaging")
    kipm = service_row(http_title="KIPMittelweg - Error - 403")
    ipmi = service_row(product="lighttpd", http_title="ASRockRack IPMI")
    parked = service_row(product="OpenResty", http_title="jenkins.example.com - Coming Soon")
    bitwarden = service_row(product="nginx", http_title="Bitwarden Web vault")
    hits, _ = _hits(tmp_path, [consulting, consul, unified, kipm, ipmi, parked, bitwarden])
    assert _signals_for(hits, consulting) == {}
    assert _signals_for(hits, unified) == {}
    assert _signals_for(hits, kipm) == {}
    assert _signals_for(hits, parked) == {}
    assert _signals_for(hits, consul) == {"S05": ("title", "Consul", [])}
    assert _signals_for(hits, ipmi) == {"S05": ("title", "IPMI", [])}
    assert _signals_for(hits, bitwarden) == {"S05": ("title", "Bitwarden", [])}


# --------------------------------------------------------------------------- S06


def _tls(**kw):
    base = dict(has_ssl=True, ssl_versions=["-TLSv1", "-TLSv1.1", "TLSv1.2", "TLSv1.3"], cert_expired=False,
                cert_key_type="rsa", cert_key_bits=2048, cert_sig_alg="sha256WithRSAEncryption", http_status=200)
    base.update(kw)
    return service_row(**base)


def test_s06_single_sub_flags(tmp_path):
    expired = _tls(cert_expired=True)
    legacy = _tls(ssl_versions=["TLSv1", "TLSv1.1", "TLSv1.2"])
    sslv3 = _tls(ssl_versions=["SSLv3", "TLSv1.2"])
    weak_rsa = _tls(cert_key_bits=1024)
    sha1 = _tls(cert_sig_alg="sha1WithRSAEncryption")
    self_signed = _tls(tags=["self-signed"])
    hits, _ = _hits(tmp_path, [expired, legacy, sslv3, weak_rsa, sha1, self_signed])
    assert _signals_for(hits, expired) == {"S06": ("tls", "Expired certificate", ["cert_expired"])}
    assert _signals_for(hits, legacy) == {"S06": ("tls", "TLS 1.0/1.1 accepted", ["legacy_tls"])}
    assert _signals_for(hits, sslv3) == {"S06": ("tls", "SSLv2/SSLv3 accepted", ["ssl_v2_v3"])}
    assert _signals_for(hits, weak_rsa) == {"S06": ("tls", "RSA key < 2048 bits", ["weak_rsa_key"])}
    assert _signals_for(hits, sha1) == {"S06": ("tls", "SHA-1/MD5 signature", ["weak_signature"])}
    assert _signals_for(hits, self_signed) == {"S06": ("tls", "Self-signed certificate", ["self_signed_http"])}


def test_s06_combined_flags_are_listed_in_fixed_order(tmp_path):
    row = _tls(cert_expired=True, ssl_versions=["SSLv3", "TLSv1"], cert_key_bits=1024,
               cert_sig_alg="md5WithRSAEncryption", tags=["self-signed"])
    hits, _ = _hits(tmp_path, [row])
    assert _signals_for(hits, row) == {"S06": ("tls", "SSLv2/SSLv3 accepted", [
        "cert_expired", "legacy_tls", "ssl_v2_v3", "weak_rsa_key", "weak_signature", "self_signed_http"])}


def test_s06_counterexamples(tmp_path):
    disabled = _tls(ssl_versions=["-SSLv3", "-TLSv1", "-TLSv1.1", "TLSv1.2"])  # '-' means disabled
    ecdsa = _tls(cert_key_type="dsa", cert_key_bits=256, cert_sig_alg="ecdsa-with-SHA256")  # dsa+256 is ECDSA
    rdp_self_signed = _tls(module="rdp", port=3389, tags=["self-signed"], http_status=None)
    rdp_self_signed_with_status = _tls(module="rdp", port=3389, tags=["self-signed"])
    non_http_self_signed = _tls(module="imap-ssl", port=993, tags=["self-signed"], http_status=None)
    cdn_expired = _tls(cert_expired=True, is_cdn=True, tags=["cdn"])
    no_tls_expired = service_row(has_ssl=False, cert_expired=True)
    hits, _ = _hits(tmp_path, [disabled, ecdsa, rdp_self_signed, rdp_self_signed_with_status,
                               non_http_self_signed, cdn_expired, no_tls_expired])
    for row in (disabled, ecdsa, rdp_self_signed, rdp_self_signed_with_status, non_http_self_signed,
                cdn_expired, no_tls_expired):
        assert "S06" not in _signals_for(hits, row)


# --------------------------------------------------------------------------- S16


def test_s16_waf_on_cdn_rows_is_allowed(tmp_path):
    cf = service_row(http_waf="Cloudflare (Cloudflare Inc.)", is_cdn=True, tags=["cdn"])
    incapsula = service_row(http_waf="Incapsula (Imperva Inc.)", is_cdn=True, tags=["cdn"])
    akamai = service_row(http_waf="Kona SiteDefender (Akamai)", is_cdn=True, tags=["cdn"])
    other = service_row(http_waf="Safeline (Chaitin Tech.)")
    hits, _ = _hits(tmp_path, [cf, incapsula, akamai, other])
    assert _signals_for(hits, cf) == {"S16": ("waf", "Cloudflare", ["waf"])}
    assert _signals_for(hits, incapsula) == {"S16": ("waf", "Imperva Incapsula", ["waf"])}
    assert _signals_for(hits, akamai) == {"S16": ("waf", "Akamai", ["waf"])}
    assert _signals_for(hits, other) == {"S16": ("waf", "Safeline", ["waf"])}


def test_s16_appliance_product_and_both(tmp_path):
    bigip = service_row(product="BigIP")
    cp = service_row(product="Checkpoint VPN-1 / Firewall-1", port=264, module="checkpoint-topology")
    both = service_row(product="SonicWall", http_waf="SonicWall (Dell)")
    hits, _ = _hits(tmp_path, [bigip, cp, both])
    assert _signals_for(hits, bigip) == {"S16": ("product", "F5 BIG-IP", ["appliance"])}
    assert _signals_for(hits, cp)["S16"] == ("product", "Check Point", ["appliance"])
    assert _signals_for(hits, both)["S16"] == ("waf", "SonicWall", ["waf", "appliance"])
    assert _signals_for(hits, both)["S01"] == ("product", "SonicWall", [])


# --------------------------------------------------------------------------- registry


def test_registry_holds_the_six_first_signals_with_contract_fields():
    assert SIGNALS_VERSION == 1
    assert [s.id for s in SIGNALS] == ["S01", "S03", "S04", "S05", "S06", "S16"]
    fam = {s.id: s.family for s in SIGNALS}
    assert fam == {"S01": "exposure", "S03": "exposure", "S04": "exposure", "S05": "exposure",
                   "S06": "hygiene", "S16": "technographic"}
    infra = {s.id: s.infra_exposure for s in SIGNALS}
    assert infra == {"S01": True, "S03": True, "S04": True, "S05": True, "S06": False, "S16": False}
    assert all(s.version == 1 for s in SIGNALS)


def test_registry_wording_follows_research_findings_section_3():
    forbidden = ["vulnerable to", "unauthenticated", "breached", "intends to", "is compromised", "no mfa"]
    for s in SIGNALS:
        fields = {name for _, name, _, _ in string.Formatter().parse(s.observed_fact_template) if name}
        assert fields <= FACT_PLACEHOLDERS, (s.id, fields - FACT_PLACEHOLDERS)
        assert "may" in s.hypothesis, s.id
        for text in (s.observed_fact_template, s.inferred_risk, s.hypothesis):
            assert not any(w in text.lower() for w in forbidden), (s.id, text)


# Wording v3 (docs/sales-brief.md §2): direct report language. Threats are stated firmly at the device-class
# level; nothing claims the account is vulnerable, breached, buying or running something old; no hedging.
SALES_HEDGES = re.compile(r"\b(may|might|possibly|perhaps|usually not|not observed|not a weakness|depends on|"
                          r"not verified)\b", re.I)
ACCOUNT_CLAIMS = re.compile(r"\b(is|are) vulnerable\b|\bbreached\b|\bcompromised\b|\blegacy\b|\bintends? to\b|"
                            r"\brenewal opportunity\b|\bthey lack\b|\bmissing\b", re.I)


def test_sales_wording_is_direct_complete_and_claims_nothing_about_the_account():
    for s in SIGNALS:
        assert all((s.short_name, s.noun_one, s.noun_many, s.offering, s.pitch, s.opener, s.discovery_questions,
                    s.confirm_on_call)), s.id
        texts = [s.short_name, s.inferred_risk, s.offering, s.pitch, s.opener, *s.discovery_questions,
                 *s.confirm_on_call, *(note for _, note in s.detail_notes)]
        for text in texts:
            assert not SALES_HEDGES.search(text), (s.id, text)
            assert not ACCOUNT_CLAIMS.search(text), (s.id, text)
            assert not re.search(r"\bS\d\d\b", text), (s.id, text)   # no internal signal codes
        assert all(q.endswith("?") for q in s.discovery_questions), s.id


def test_sql_server_browser_keeps_its_narrow_scope():
    s04 = next(s for s in SIGNALS if s.id == "S04")
    note = dict(s04.detail_notes)["SQL Server Browser"]
    assert "UDP 1434" in note and "lists SQL Server instance names and ports" in note
    assert "data-store response" not in s04.observed_fact_template


def test_fact_template_renders_from_an_evidence_row(tmp_path):
    row = service_row(product="SonicWall", ip="198.51.100.7", port=4433, http_title="SonicWall Network Security Login")
    hits, _ = _hits(tmp_path, [row])
    h = next(h for h in hits if h["signal_id"] == "S01")
    s01 = next(s for s in SIGNALS if s.id == "S01")
    text = s01.observed_fact_template.format(**{k: ("" if h.get(k) is None else h.get(k)) for k in FACT_PLACEHOLDERS})
    assert text == ("On 2026-11-07 14:52:01 UTC, 198.51.100.7:4433/tcp was identified by the scanner as SonicWall "
                    "(product 'SonicWall', title 'SonicWall Network Security Login').")
