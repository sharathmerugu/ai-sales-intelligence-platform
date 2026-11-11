"""Arrow schema of the `observations` layer (normalizer v1).

Column order is part of the contract: Parquet files written by different
runs of the same normalizer version must be schema-identical.
"""

from __future__ import annotations

import pyarrow as pa

S, I32, I64, F64, B, TS = pa.string(), pa.int32(), pa.int64(), pa.float64(), pa.bool_(), pa.timestamp("us")
LS = pa.list_(pa.string())

VULN = pa.struct(
    [("cve", S), ("cvss", F64), ("kev", B), ("verified", B), ("epss", F64), ("ransomware_known", B)]
)

# Provenance columns are filled by the worker, not the normalizer.
PROVENANCE_FIELDS = [
    ("file_id", S),
    ("snapshot_id", S),
    ("chunk_index", I32),
    ("byte_offset", I64),
    ("byte_length", I32),
    ("record_sha256", S),
    ("normalizer_version", I32),
]

NORMALIZED_FIELDS = [
    # identity
    ("observation_id", S),
    ("service_id", S),
    ("ip", S),
    ("ip_version", pa.int8()),
    ("port", I32),
    ("transport", S),
    ("sni", S),
    ("observed_at", TS),
    # scanner metadata
    ("shodan_id", S),
    ("banner_hash", I64),
    ("crawler", S),
    ("module", S),
    # network
    ("org", S),
    ("isp", S),
    ("asn", S),
    ("country_code", S),
    ("city", S),
    ("cloud_provider", S),
    ("cloud_service", S),
    ("cloud_region", S),
    # fingerprint (scanner-asserted)
    ("product", S),
    ("version", S),
    ("os", S),
    ("devicetype", S),
    ("info", S),
    ("cpe23", LS),
    ("tags", LS),
    ("hostnames", LS),
    ("domains", LS),
    # banner excerpt
    ("banner_len", I32),
    ("banner_head", S),
    # http
    ("http_status", I32),
    ("http_title", S),
    ("http_server", S),
    ("http_host", S),
    ("http_waf", S),
    ("http_html_hash", I64),
    ("favicon_hash", I64),
    ("has_securitytxt", B),
    ("has_hsts", B),
    ("has_csp", B),
    ("x_powered_by", S),
    ("www_authenticate", S),
    ("http_components", LS),
    # tls
    ("has_ssl", B),
    ("ssl_versions", LS),
    ("cert_expired", B),
    ("cert_expires", TS),
    ("cert_issued", TS),
    ("cert_subject_cn", S),
    ("cert_subject_o", S),
    ("cert_issuer_cn", S),
    ("cert_issuer_o", S),
    ("cert_san_dns", LS),
    ("cert_sig_alg", S),
    ("cert_key_type", S),
    ("cert_key_bits", I32),
    ("cert_sha256", S),
    ("cert_trust_mozilla", B),
    ("jarm", S),
    # other protocols
    ("ssh_hassh", S),
    ("ntlm_dns_domain", S),
    ("ntlm_netbios_domain", S),
    ("ntlm_fqdn", S),
    ("ntlm_os_build", S),
    ("protocol_json", S),
    # vulns (scanner-inferred from version strings; unverified)
    ("vulns", pa.list_(VULN)),
    ("any_kev", B),
    ("any_verified", B),
    # quality
    ("unicode_repaired", B),
    ("parse_warnings", LS),
    ("unknown_keys", LS),
]

OBSERVATION_SCHEMA = pa.schema(PROVENANCE_FIELDS + NORMALIZED_FIELDS)
NORMALIZED_COLUMNS = [name for name, _ in NORMALIZED_FIELDS]
