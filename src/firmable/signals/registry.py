"""Signal registry v1: S01, S03, S04, S05, S06, S16.

Each rule is ported from the research SQL (`sql/exploration.sql` §6, l.412-480)
with the v1 column mapping (`scan_hostname` -> `sni`, `ts` -> `observed_at`,
`p_l` = lower(coalesce(product, '')), `t_l` = lower(coalesce(http_title, ''))).
Changes from the research rules are listed in `docs/signals-implementation.md`
§2 and marked `# v1 change` below.

All SQL fragments read the derived relation built by `BASE_SELECT_SQL`
(see `build.py`), which adds NULL-safe helper columns:

  p_l, t_l       lower-cased product / HTTP title ('' when NULL)
  module_l       lower(coalesce(module, ''))
  bh             coalesce(banner_head, '')
  tags_l         coalesce(tags, [])           (DuckDB: list_contains(NULL, x) IS NULL)
  vers_l         coalesce(ssl_versions, [])
  pkeys          top-level keys of protocol_json ([] when NULL)
  cdn            coalesce(is_cdn, false)
  foreign_answer the probe was answered by a different service: HTTP or SSH banner,
                 or a product naming a web server / proxy / SSH / mail / FTP daemon
  s01_proto      'cisco anyconnect' | 'sonicwall' | 'fortigate' from protocol_json, else ''

Wording follows `docs/research-findings.md` §3: the observed-fact template states
only what the scanner recorded; risk is an inference; the hypothesis uses "may".
"""

from __future__ import annotations

from dataclasses import dataclass

SIGNALS_VERSION = 1

# Placeholders the API may fill from a signal_hits row when rendering a fact.
FACT_PLACEHOLDERS = frozenset(
    {"observed_at", "ip", "port", "transport", "sni", "product", "version", "http_title", "module", "detail", "sub_flags"}
)


@dataclass(frozen=True)
class Signal:
    id: str
    version: int
    name: str
    family: str  # exposure | hygiene | technographic
    predicate_sql: str
    detail_sql: str
    match_basis_sql: str
    sub_flags_sql: str
    evidence_json_sql: str
    observed_fact_template: str
    inferred_risk: str
    hypothesis: str
    infra_exposure: bool


# --------------------------------------------------------------------------- helpers


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _label_case(pairs: list[tuple[str, str]], exprs: list[str], default: str) -> str:
    """First (expression, regex) hit in priority order wins: every pair is tried on exprs[0], then exprs[1], ..."""
    whens = [f"WHEN regexp_matches({e}, {_q(rx)}) THEN {_q(label)}" for e in exprs for rx, label in pairs]
    return "CASE " + " ".join(whens) + f" ELSE {default} END"


NO_FLAGS = "[]::VARCHAR[]"

# Products that show a probe was answered by some other service (scanner module
# says which probe ran, not what answered). Shared by the S03 and S04 module clauses.
FOREIGN_PRODUCT_RE = r"nginx|apache|\biis\b|openresty|tengine|socks|ssh|http|ftpd|smtpd|imapd|pop3|nntpd|\blpd\b|^tls$|stockfish|vnc"
# Generic web servers: the `database` tag on these is not data-store evidence (S04).
WEB_FRONT_RE = r"^(nginx|openresty|tengine|lighttpd|caddy|apache( httpd)?|microsoft[- ]iis( httpd)?|microsoft httpapi httpd.*)$"

BASE_DERIVED_SQL = r"""
    lower(coalesce(product, ''))                          AS p_l,
    lower(coalesce(http_title, ''))                       AS t_l,
    lower(coalesce(module, ''))                           AS module_l,
    coalesce(banner_head, '')                             AS bh,
    coalesce(tags, []::VARCHAR[])                         AS tags_l,
    coalesce(ssl_versions, []::VARCHAR[])                 AS vers_l,
    coalesce(json_keys(protocol_json), []::VARCHAR[])     AS pkeys,
    coalesce(is_cdn, false)                               AS cdn
"""

# Second projection: helpers that depend on the first ones.
BASE_DERIVED2_SQL = rf"""
    (starts_with(bh, 'HTTP/') OR starts_with(bh, 'SSH-') OR regexp_matches(p_l, '{FOREIGN_PRODUCT_RE}')) AS foreign_answer,
    CASE WHEN list_contains(pkeys, 'cisco_anyconnect') THEN 'cisco anyconnect'
         WHEN list_contains(pkeys, 'sonicwall') THEN 'sonicwall'
         WHEN list_contains(pkeys, 'fortinet')
              AND regexp_matches(upper(coalesce(json_extract_string(protocol_json, '$.fortinet.model'), '')), '^(FG|FWF)')
              THEN 'fortigate'
         ELSE '' END AS s01_proto
"""


# --------------------------------------------------------------------------- S01

S01_PRODUCT_RE = (
    "fortigate|fortinet|sonicwall|check ?point|connectra|cisco asa|cisco vpn|adaptive security|netscaler|citrix|"
    "globalprotect|pan-os|palo alto|pulse secure|ivanti connect|juniper|sophos|zyxel|barracuda|watchguard|fireware|"
    "stormshield|securepoint|openvpn|draytek"
)
S01_TITLE_RE = (
    "globalprotect|fortigate|ssl ?vpn|vpn portal|netscaler|citrix gateway|pulse secure|ivanti connect|fireware|"
    "anyconnect|sonicwall|big-ip logout|sophos|access server client portal"
)
# v1 change: parked pages named after a host ("sslvpn.x.com - Coming Soon", "jenkins.x.com - Coming Soon").
PARKED_TITLE_RE = "coming soon"
S01_LABELS = [
    ("sonicwall", "SonicWall"),
    ("netscaler|citrix", "Citrix NetScaler"),
    ("fortigate|fortinet", "FortiGate"),
    ("draytek", "DrayTek"),
    ("connectra|check ?point", "Check Point"),
    ("big-?ip", "F5 BIG-IP"),
    ("globalprotect|pan-os|palo alto", "Palo Alto GlobalProtect"),
    ("cisco asa|cisco vpn|adaptive security|anyconnect", "Cisco ASA / AnyConnect"),
    ("pulse secure|ivanti connect", "Ivanti / Pulse Secure"),
    ("sophos", "Sophos"),
    ("watchguard|fireware", "WatchGuard"),
    ("openvpn|access server client portal", "OpenVPN Access Server"),
    ("stormshield", "Stormshield"),
    ("juniper", "Juniper"),
    ("zyxel", "Zyxel"),
    ("barracuda", "Barracuda"),
    ("securepoint", "Securepoint"),
    ("ssl ?vpn|vpn portal", "SSL VPN portal (unbranded)"),
]
_S01_P = f"regexp_matches(p_l, {_q(S01_PRODUCT_RE)})"
_S01_T = f"(regexp_matches(t_l, {_q(S01_TITLE_RE)}) AND NOT regexp_matches(t_l, {_q(PARKED_TITLE_RE)}))"

S01 = Signal(
    id="S01",
    version=1,
    name="Remote-access gateway / SSL-VPN / firewall portal identified",
    family="exposure",
    predicate_sql=f"transport = 'tcp' AND NOT cdn AND ({_S01_P} OR s01_proto <> '' OR {_S01_T})",
    detail_sql=_label_case(S01_LABELS, ["p_l", "s01_proto", "t_l"], "coalesce(product, http_title)"),
    match_basis_sql=f"CASE WHEN {_S01_P} THEN 'product' WHEN s01_proto <> '' THEN 'protocol' ELSE 'title' END",
    sub_flags_sql=NO_FLAGS,
    evidence_json_sql=(
        "json_object('product', product, 'http_title', http_title, 'protocol_object', nullif(s01_proto, ''), "
        "'fortinet_model', json_extract_string(protocol_json, '$.fortinet.model'), 'cert_subject_cn', cert_subject_cn)"
    ),
    observed_fact_template=(
        "On {observed_at} UTC, {ip}:{port}/{transport} was identified by the scanner as {detail} "
        "(product '{product}', title '{http_title}')."
    ),
    inferred_risk=(
        "A perimeter remote-access gateway or firewall portal is internet-reachable; this device class is commonly "
        "targeted. Exposure to any specific flaw depends on the firmware version, which is usually not observed."
    ),
    hypothesis=(
        "The account may run a legacy VPN and may be a candidate for ZTNA/SASE, MFA or firewall refresh; "
        "this needs firmographic and timing confirmation."
    ),
    infra_exposure=True,
)


# --------------------------------------------------------------------------- S03

S03_MODULES = ("rdp", "telnet", "x11", "rlogin", "nomachine")
S03_PRODUCT_RE = "remote desktop|vnc|winrm|screenconnect|teamviewer|telnetd"
S03_LABELS = [
    ("vnc", "VNC"),
    ("remote desktop|^rdp$", "RDP"),
    ("winrm", "WinRM"),
    ("screenconnect", "ScreenConnect"),
    ("teamviewer", "TeamViewer"),
    ("telnet", "Telnet"),
    ("^x11$", "X11"),
    ("^rlogin$", "rlogin"),
    ("^nomachine$", "NoMachine"),
]
_S03_P = f"regexp_matches(p_l, {_q(S03_PRODUCT_RE)})"
# v1 change: a remote-admin probe answered by HTTP / SSH / SOCKS / another daemon is not that protocol.
_S03_M = "(module_l IN (" + ", ".join(_q(m) for m in S03_MODULES) + ") AND NOT foreign_answer)"

S03 = Signal(
    id="S03",
    version=1,
    name="Interactive remote-administration protocol reachable",
    family="exposure",
    predicate_sql=f"NOT cdn AND ({_S03_M} OR {_S03_P})",
    detail_sql=_label_case(S03_LABELS, ["p_l", "module_l"], "'Remote administration'"),
    match_basis_sql=f"CASE WHEN {_S03_P} THEN 'product' ELSE 'protocol' END",
    sub_flags_sql=NO_FLAGS,
    evidence_json_sql="json_object('module', module, 'product', product, 'version', version)",
    observed_fact_template=(
        "On {observed_at} UTC, {ip}:{port}/{transport} returned a {detail} protocol response "
        "(scanner module '{module}', product '{product}')."
    ),
    inferred_risk=(
        "An interactive login surface is internet-reachable; this exposure class is commonly targeted by "
        "brute-force and credential attacks. No authentication weakness is observed."
    ),
    hypothesis=(
        "The account may lack a remote-access broker, PAM or ZTNA control in front of this host; "
        "this needs confirmation."
    ),
    infra_exposure=True,
)


# --------------------------------------------------------------------------- S04

S04_PRODUCT_RE = (
    "mysql|mariadb|postgresql|ms-sql|sql server|mongodb|redis|elastic|clickhouse|couchdb|cassandra|influxdb|"
    "memcached|minio|riak|rethinkdb"
)
S04_MODULES = ("mysql", "ms-sql", "mongodb", "redis", "postgresql", "clickhouse-native", "riak", "rethinkdb",
               "oracle-tns", "couchdb", "memcached")
# v1 change: parsed data-store objects in protocol_json (new in normalizer v1).
S04_PROTOCOL_KEYS = ("redis", "mysql", "mysqlx", "mongodb", "influxdb", "mssql_ssrp")
S04_LABELS = [
    ("minio", "MinIO"),
    ("mariadb", "MariaDB"),
    ("mysql", "MySQL"),
    ("sql server browser|mssql_ssrp", "SQL Server Browser"),
    ("ms-sql|mssql|sql server", "MS-SQL"),
    ("postgresql", "PostgreSQL"),
    ("clickhouse", "ClickHouse"),
    ("redis", "Redis"),
    ("mongodb", "MongoDB"),
    ("elastic", "Elasticsearch"),
    ("influxdb", "InfluxDB"),
    ("couchdb", "CouchDB"),
    ("cassandra", "Cassandra"),
    ("memcached", "Memcached"),
    ("riak", "Riak"),
    ("rethinkdb", "RethinkDB"),
    ("oracle-tns", "Oracle TNS"),
]
_S04_KEYS = "[" + ", ".join(_q(k) for k in S04_PROTOCOL_KEYS) + "]"
_S04_P = f"regexp_matches(p_l, {_q(S04_PRODUCT_RE)})"
# Research: module hit only when the banner is not HTTP. v1 change: also not SSH / SOCKS / another daemon.
_S04_M = ("((module_l IN (" + ", ".join(_q(m) for m in S04_MODULES) + ") AND NOT foreign_answer)"
          f" OR list_has_any(pkeys, {_S04_KEYS}))")
# v1 change (catalog counterexample): the `database` tag on a generic web-server front does not count.
_S04_T = f"(list_contains(tags_l, 'database') AND NOT regexp_matches(p_l, {_q(WEB_FRONT_RE)}))"

S04 = Signal(
    id="S04",
    version=1,
    name="Database / object store reachable",
    family="exposure",
    predicate_sql=f"NOT cdn AND ({_S04_P} OR {_S04_M} OR {_S04_T})",
    detail_sql=_label_case(
        S04_LABELS,
        ["p_l", "module_l", f"array_to_string(list_filter(pkeys, lambda k: list_contains({_S04_KEYS}, k)), ' ')"],
        "coalesce(product, 'Database (scanner tag)')",
    ),
    match_basis_sql=f"CASE WHEN {_S04_P} THEN 'product' WHEN {_S04_M} THEN 'protocol' ELSE 'tag' END",
    sub_flags_sql=NO_FLAGS,
    evidence_json_sql=(
        "json_object('module', module, 'product', product, 'version', version, "
        f"'protocol_objects', list_filter(pkeys, lambda k: list_contains({_S04_KEYS}, k)), "
        "'database_tag', list_contains(tags_l, 'database'))"
    ),
    observed_fact_template=(
        "On {observed_at} UTC, {ip}:{port}/{transport} returned a {detail} data-store response "
        "(scanner module '{module}', product '{product}', version '{version}')."
    ),
    inferred_risk=(
        "Data infrastructure is reachable from the internet. Whether authentication is enforced is not observed."
    ),
    hypothesis=(
        "The account may have a cloud or database security posture gap (CSPM/DSPM, database security, "
        "backup resilience); this needs confirmation."
    ),
    infra_exposure=True,
)


# --------------------------------------------------------------------------- S05

# v1 change: word boundaries on consul / unifi / ipmi (research matched "Consulting", "Unified ...", "EquipMinistry").
S05_RE = (
    r"\bilo\b|idrac|\bipmi\b|cisco ios http|winbox|kubernetes|portainer|docker|jenkins|gitlab|grafana|kibana|prometheus|"
    r"airflow|argo cd|rancher|\bconsul\b|\bvault\b|cpanel|\bwhm\b|plesk|webmin|control web panel|cyberpanel|phpmyadmin|"
    r"keycloak|minio console|sonarqube|openstack|vcenter|esxi|proxmox|\bunifi\b|routeros"
)
S05_LABELS = [
    ("routeros|winbox", "MikroTik RouterOS"),
    (r"\bunifi\b", "UniFi"),
    (r"\bwhm\b|cpanel", "WHM/cPanel"),
    ("kubernetes", "Kubernetes"),
    ("plesk", "Plesk"),
    ("minio console", "MinIO Console"),
    ("control web panel", "Control Web Panel"),
    ("cyberpanel", "CyberPanel"),
    ("gitlab", "GitLab"),
    (r"\bilo\b", "HPE iLO"),
    ("idrac", "Dell iDRAC"),
    (r"\bipmi\b", "IPMI"),
    ("prometheus", "Prometheus"),
    (r"\bconsul\b", "Consul"),
    ("grafana", "Grafana"),
    ("portainer", "Portainer"),
    ("cisco ios http", "Cisco IOS HTTP"),
    ("phpmyadmin", "phpMyAdmin"),
    ("airflow", "Apache Airflow"),
    ("bitwarden", "Bitwarden"),
    (r"\bvault\b", "HashiCorp Vault"),
    ("keycloak", "Keycloak"),
    ("jenkins", "Jenkins"),
    ("argo cd", "Argo CD"),
    ("sonarqube", "SonarQube"),
    ("docker", "Docker"),
    ("webmin", "Webmin"),
    ("vcenter|esxi", "VMware vSphere"),
    ("proxmox", "Proxmox VE"),
    ("rancher", "Rancher"),
    ("openstack", "OpenStack"),
    ("kibana", "Kibana"),
]
_S05_P = f"regexp_matches(p_l, {_q(S05_RE)})"
_S05_COMBINED = f"(regexp_matches(p_l || ' ' || t_l, {_q(S05_RE)}) AND NOT regexp_matches(t_l, {_q(PARKED_TITLE_RE)}))"

S05 = Signal(
    id="S05",
    version=1,
    name="Infrastructure / DevOps / hosting management plane reachable",
    family="exposure",
    predicate_sql=f"NOT cdn AND ({_S05_P} OR {_S05_COMBINED} OR list_contains(tags_l, 'devops'))",
    detail_sql=_label_case(S05_LABELS, ["p_l", "t_l", "p_l || ' ' || t_l"],
                           "coalesce(product, http_title, 'Management plane (scanner tag)')"),
    match_basis_sql=(
        f"CASE WHEN {_S05_P} THEN 'product' WHEN {_S05_COMBINED} THEN 'title' ELSE 'tag' END"
    ),
    sub_flags_sql=NO_FLAGS,
    evidence_json_sql=(
        "json_object('product', product, 'http_title', http_title, 'devops_tag', list_contains(tags_l, 'devops'))"
    ),
    observed_fact_template=(
        "On {observed_at} UTC, {ip}:{port}/{transport} was identified by the scanner as a {detail} management "
        "interface (product '{product}', title '{http_title}')."
    ),
    inferred_risk=(
        "An infrastructure or DevOps control plane is internet-reachable. A login page proves reachability only; "
        "authentication bypass is not observed."
    ),
    hypothesis=(
        "The account may have exposure-management, PAM or shadow-IT gaps around this management plane; "
        "hosting panels may belong to the hoster rather than the prospect."
    ),
    infra_exposure=True,
)


# --------------------------------------------------------------------------- S06

S06_FLAGS = [  # (sub-flag, SQL condition); output keeps this order
    ("cert_expired", "coalesce(cert_expired, false)"),
    ("legacy_tls", "list_has_any(vers_l, ['TLSv1', 'TLSv1.1'])"),          # exact membership: '-TLSv1' = disabled
    ("ssl_v2_v3", "list_has_any(vers_l, ['SSLv3', 'SSLv2'])"),
    ("weak_rsa_key", "coalesce(cert_key_type = 'rsa' AND cert_key_bits < 2048, false)"),  # 'dsa' 256/384 = ECDSA
    ("weak_signature", "regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5')"),
    ("self_signed_http", "(list_contains(tags_l, 'self-signed') AND module_l <> 'rdp' AND http_status IS NOT NULL)"),
]
_S06 = dict(S06_FLAGS)
S06 = Signal(
    id="S06",
    version=1,
    name="TLS hygiene defect (non-CDN endpoint)",
    family="hygiene",
    predicate_sql="coalesce(has_ssl, false) AND NOT cdn AND (" + " OR ".join(c for _, c in S06_FLAGS) + ")",
    detail_sql=(
        f"CASE WHEN {_S06['ssl_v2_v3']} THEN 'SSLv2/SSLv3 accepted' "
        f"WHEN {_S06['cert_expired']} THEN 'Expired certificate' "
        f"WHEN {_S06['weak_rsa_key']} THEN 'RSA key < 2048 bits' "
        f"WHEN {_S06['legacy_tls']} THEN 'TLS 1.0/1.1 accepted' "
        f"WHEN {_S06['weak_signature']} THEN 'SHA-1/MD5 signature' "
        "ELSE 'Self-signed certificate' END"
    ),
    match_basis_sql="'tls'",
    sub_flags_sql=(
        "list_filter([" + ", ".join(f"CASE WHEN {c} THEN {_q(f)} END" for f, c in S06_FLAGS) + "], lambda x: x IS NOT NULL)"
    ),
    evidence_json_sql=(
        "json_object('ssl_versions', ssl_versions, 'cert_expired', cert_expired, 'cert_expires', cert_expires, "
        "'cert_key_type', cert_key_type, 'cert_key_bits', cert_key_bits, 'cert_sig_alg', cert_sig_alg, "
        "'self_signed_tag', list_contains(tags_l, 'self-signed'), 'http_status', http_status, "
        "'cert_subject_cn', cert_subject_cn)"
    ),
    observed_fact_template=(
        "On {observed_at} UTC, the TLS service at {ip}:{port}/{transport} (SNI '{sni}') showed: {detail} "
        "(all findings: {sub_flags})."
    ),
    inferred_risk=(
        "Weak TLS or certificate hygiene on this endpoint; expired, self-signed or weak certificates on "
        "user-facing services are commonly associated with certificate-lifecycle debt."
    ),
    hypothesis=(
        "The account may not use certificate lifecycle management (CLM/PKI) tooling for this estate; "
        "this needs confirmation."
    ),
    infra_exposure=False,
)


# --------------------------------------------------------------------------- S16

S16_APPLIANCE_RE = "fortigate|sonicwall|check ?point|zscaler|netscaler|bigip|barracuda|sophos|palo alto|juniper|watchguard"
S16_WAF_LABELS = [
    ("cloudflare", "Cloudflare"),
    ("incapsula", "Imperva Incapsula"),
    ("securesphere", "Imperva SecureSphere"),
    ("cloudfront", "Amazon CloudFront"),
    ("elastic load balancer", "AWS ELB"),
    ("akamai|kona", "Akamai"),
    ("big-ip", "F5 BIG-IP"),
    ("sonicwall", "SonicWall"),
    ("zscaler", "Zscaler"),
    ("netscaler", "Citrix NetScaler"),
    ("azure front door", "Azure Front Door"),
    ("fortiweb", "Fortinet FortiWeb"),
    ("fastly", "Fastly"),
    ("barracuda", "Barracuda"),
    ("sucuri", "Sucuri"),
    ("ddos-guard", "DDoS-Guard"),
    ("aliyundun", "Alibaba Cloud WAF"),
]
S16_APPLIANCE_LABELS = [
    ("fortigate", "FortiGate"),
    ("sonicwall", "SonicWall"),
    ("check ?point", "Check Point"),
    ("zscaler", "Zscaler"),
    ("netscaler", "Citrix NetScaler"),
    ("bigip", "F5 BIG-IP"),
    ("barracuda", "Barracuda"),
    ("sophos", "Sophos"),
    ("palo alto", "Palo Alto Networks"),
    ("juniper", "Juniper"),
    ("watchguard", "WatchGuard"),
]
_S16_A = f"regexp_matches(p_l, {_q(S16_APPLIANCE_RE)})"

S16 = Signal(
    id="S16",
    version=1,
    name="Security-vendor technographics (WAF / security appliance)",
    family="technographic",
    predicate_sql=f"(http_waf IS NOT NULL OR {_S16_A})",  # CDN rows allowed
    detail_sql=(
        "CASE WHEN http_waf IS NOT NULL THEN "
        + _label_case(S16_WAF_LABELS, ["lower(http_waf)"], r"trim(regexp_replace(http_waf, '\s*\(.*\)\s*$', ''))")
        + " ELSE " + _label_case(S16_APPLIANCE_LABELS, ["p_l"], "product") + " END"
    ),
    match_basis_sql="CASE WHEN http_waf IS NOT NULL THEN 'waf' ELSE 'product' END",
    sub_flags_sql=(
        f"list_filter([CASE WHEN http_waf IS NOT NULL THEN 'waf' END, CASE WHEN {_S16_A} THEN 'appliance' END], "
        "lambda x: x IS NOT NULL)"
    ),
    evidence_json_sql="json_object('http_waf', http_waf, 'product', product)",
    observed_fact_template=(
        "On {observed_at} UTC, {ip}:{port}/{transport} carried a {detail} fingerprint "
        "(evidence: {sub_flags}; product '{product}')."
    ),
    inferred_risk="Not a risk: this records the installed security or edge vendor footprint.",
    hypothesis=(
        "The account may be a competitive-displacement or renewal opportunity for this vendor category, "
        "given external renewal-timing data."
    ),
    infra_exposure=False,
)


SIGNALS: tuple[Signal, ...] = (S01, S03, S04, S05, S06, S16)
SIGNALS_BY_ID = {s.id: s for s in SIGNALS}
