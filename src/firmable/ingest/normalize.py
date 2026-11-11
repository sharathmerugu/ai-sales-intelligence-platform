"""Normalize one raw NDJSON line into a typed Observation row (pure function).

Required identity fields (port, transport, timestamp, ip_str|ipv6) reject the
line when missing or invalid. Optional fields degrade to NULL with a
``field:reason`` entry in ``parse_warnings`` so partially valid rows survive.
"""

from __future__ import annotations

import codecs
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import orjson

NORMALIZER_VERSION = 1
TRANSPORTS = frozenset({"tcp", "udp"})
_SURROGATE = re.compile("[\ud800-\udfff]")
BANNER_HEAD_CHARS = 160
TITLE_CHARS = 200
PROTOCOL_JSON_MAX_BYTES = 65536

# Small parsed protocol objects kept verbatim (as JSON) so new signals need no rescan.
PROTOCOL_KEYS = (
    "isakmp", "rdp_encryption", "snmp", "vnc", "ftp", "telnet", "mysql", "dns", "ntp", "sip",
    "pptp", "hikvision", "dahua", "mikrotik_routeros", "mikrotik_winbox", "hp_ilo", "fortinet",
    "kubernetes", "plex", "rsync", "openflow", "upnp", "l2tp", "mpls_ldp", "dav", "open_dir",
    "hermes_agent", "mac", "vendor", "dahua_dvr_web", "mcp", "microsoft_exchange", "draytek_vigor",
    "mssql_ssrp", "bgp", "ldap", "cisco_ipsla", "airplay", "synology_srm",
)
# Top-level keys this normalizer knows about; anything else is counted as schema drift.
KNOWN_KEYS = frozenset(PROTOCOL_KEYS) | {
    "ip", "ip_str", "ipv6", "port", "transport", "timestamp", "hash", "org", "isp", "asn",
    "location", "hostnames", "domains", "tags", "data", "_shodan", "product", "version", "os",
    "devicetype", "info", "cpe", "cpe23", "cpe23_hash", "cloud", "http", "ssl", "ssh", "ntlm",
    "vulns", "link", "tcp", "udp", "uptime", "opts",
}


@dataclass(frozen=True)
class Rejection:
    error_class: str
    message: str


class _Reject(Exception):
    def __init__(self, error_class: str, message: str) -> None:
        super().__init__(message)
        self.error_class = error_class


def canonical_ip(value: str) -> tuple[str, int]:
    ip = ipaddress.ip_address(value.strip())
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip), ip.version


def canonical_sni(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().rstrip(".").lower()


def service_id(ip: str, port: int, transport: str, sni: str) -> str:
    key = f"{ip}|{port}|{transport}|{sni}".encode()
    return hashlib.sha256(key).hexdigest()[:32]


def _repair(value: Any) -> Any:
    """Replace lone UTF-16 surrogates (unencodable in UTF-8/Parquet) with U+FFFD."""
    if isinstance(value, str):
        return _SURROGATE.sub("�", value)
    if isinstance(value, list):
        return [_repair(v) for v in value]
    if isinstance(value, dict):
        return {_repair(k): _repair(v) for k, v in value.items()}
    return value


def _parse(raw: bytes) -> tuple[Any, bool]:
    try:
        return orjson.loads(raw), False
    except orjson.JSONDecodeError:
        pass
    # Fallback: stdlib accepts lone surrogate escapes; invalid UTF-8 bytes are replaced.
    try:
        return _repair(json.loads(raw.decode("utf-8", errors="replace"))), True
    except ValueError as exc:
        raise _Reject("malformed_json", str(exc)[:200]) from None


def _required(rec: dict[str, Any], key: str) -> Any:
    value = rec.get(key)
    if value is None:
        raise _Reject("missing_required", f"{key} absent")
    return value


def _identity(rec: dict[str, Any], warnings: list[str]) -> tuple[str, int, int, str, datetime]:
    port = _required(rec, "port")
    if isinstance(port, str) and port.isdigit():
        port = int(port)
        warnings.append("port:coerced")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise _Reject("invalid_value", f"port={port!r}")

    transport = _required(rec, "transport")
    transport = transport.lower() if isinstance(transport, str) else transport
    if transport not in TRANSPORTS:
        raise _Reject("invalid_value", f"transport={transport!r}")

    ts = _required(rec, "timestamp")
    try:
        observed_at = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        raise _Reject("invalid_value", f"timestamp={ts!r}") from None
    if observed_at.tzinfo is not None:  # scanner emits naive UTC; normalize aware values to naive UTC
        observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)

    raw_ip = rec.get("ip_str") or rec.get("ipv6")
    if raw_ip is None:
        raise _Reject("missing_required", "ip_str and ipv6 absent")
    try:
        ip, ip_version = canonical_ip(str(raw_ip))
    except ValueError:
        raise _Reject("invalid_value", f"ip={raw_ip!r}") from None
    return ip, ip_version, port, transport, observed_at


class _Fields:
    """Typed accessors: wrong types become None plus a `path:type` warning."""

    def __init__(self, warnings: list[str]) -> None:
        self.warnings = warnings

    def obj(self, parent: Any, key: str, path: str) -> dict[str, Any]:
        value = parent.get(key) if isinstance(parent, dict) else None
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.warnings.append(f"{path}:type")
            return {}
        return value

    def get(self, parent: dict[str, Any], key: str, kind: type | tuple[type, ...], path: str) -> Any:
        value = parent.get(key)
        if value is None:
            return None
        if kind is int and isinstance(value, bool):
            ok = False
        elif kind is float:
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
            value = float(value) if ok else value
        else:
            ok = isinstance(value, kind)
        if not ok:
            self.warnings.append(f"{path}:type")
            return None
        return value

    def integer(self, parent: dict[str, Any], key: str, path: str, bits: int) -> int | None:
        value = self.get(parent, key, int, path)
        if value is not None and not -(2 ** (bits - 1)) <= value < 2 ** (bits - 1):
            self.warnings.append(f"{path}:range")
            return None
        return value

    def text(self, parent: dict[str, Any], key: str, path: str, limit: int | None = None) -> str | None:
        value = self.get(parent, key, str, path)
        return value[:limit] if value is not None and limit else value

    def strings(self, parent: dict[str, Any], key: str, path: str) -> list[str] | None:
        value = self.get(parent, key, list, path)
        if value is None:
            return None
        if not all(isinstance(v, str) for v in value):
            self.warnings.append(f"{path}:item_type")
            return [v for v in value if isinstance(v, str)]
        return value

    def cert_time(self, parent: dict[str, Any], key: str, path: str) -> datetime | None:
        value = self.text(parent, key, path)
        if value is None:
            return None
        try:
            return datetime.strptime(value, "%Y%m%d%H%M%SZ")
        except ValueError:
            self.warnings.append(f"{path}:format")
            return None


def san_dns_names(escaped: str) -> list[str]:
    """dNSName entries from a subjectAltName extension given as an escaped DER string."""
    der = codecs.escape_decode(escaped.encode("latin-1", errors="replace"))[0]

    def read_len(pos: int) -> tuple[int, int]:
        first = der[pos]
        if first < 0x80:
            return first, pos + 1
        n = first & 0x7F
        return int.from_bytes(der[pos + 1 : pos + 1 + n], "big"), pos + 1 + n

    if not der or der[0] != 0x30:
        raise ValueError("not a DER sequence")
    length, pos = read_len(1)
    end = min(pos + length, len(der))
    names: list[str] = []
    while pos < end:
        tag = der[pos]
        size, pos = read_len(pos + 1)
        if tag == 0x82:  # [2] dNSName, IA5String
            names.append(der[pos : pos + size].decode("ascii", errors="replace").lower())
        pos += size
    return names


def _vulns(raw: Any, f: _Fields) -> list[dict[str, Any]] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        f.warnings.append("vulns:type")
        return None
    out = []
    for cve in sorted(raw):
        entry = raw[cve] if isinstance(raw[cve], dict) else {}
        out.append(
            {
                "cve": cve,
                "cvss": f.get(entry, "cvss", float, "vulns.cvss"),
                "kev": entry.get("kev") is True,
                "verified": entry.get("verified") is True,
                "epss": f.get(entry, "epss", float, "vulns.epss"),
                "ransomware_known": entry.get("ransomware_campaign") == "Known",
            }
        )
    return out


def _observation_id(shodan: dict[str, Any], ip: str, port: int, transport: str, sni: str,
                    observed_at: datetime, banner_hash: Any) -> str:
    sid = shodan.get("id")
    if isinstance(sid, str) and sid:
        return sid
    key = f"{ip}|{port}|{transport}|{sni}|{observed_at.isoformat()}|{banner_hash}".encode()
    return "c:" + hashlib.sha256(key).hexdigest()[:32]


def normalize_line(raw: bytes) -> dict[str, Any] | Rejection:
    try:
        rec, repaired = _parse(raw)
        if not isinstance(rec, dict):
            raise _Reject("not_an_object", type(rec).__name__)
        warnings: list[str] = []
        identity = _identity(rec, warnings)
        return _extract(rec, repaired, warnings, *identity)
    except _Reject as exc:
        return Rejection(exc.error_class, str(exc))
    except Exception as exc:  # noqa: BLE001 - a poison line must never fail its chunk
        return Rejection("normalizer_error", f"{type(exc).__name__}: {exc}"[:200])


def _extract(rec: dict[str, Any], repaired: bool, warnings: list[str], ip: str, ip_version: int, port: int,
             transport: str, observed_at: datetime) -> dict[str, Any]:
    f = _Fields(warnings)
    shodan = f.obj(rec, "_shodan", "_shodan")
    sni = canonical_sni(f.obj(shodan, "options", "_shodan.options").get("hostname"))
    banner_hash = f.integer(rec, "hash", "hash", 64)
    location = f.obj(rec, "location", "location")
    cloud = f.obj(rec, "cloud", "cloud")
    data = f.text(rec, "data", "data") or ""

    http = f.obj(rec, "http", "http")
    headers = f.obj(http, "headers", "http.headers")
    components = f.obj(http, "components", "http.components")

    ssl = f.obj(rec, "ssl", "ssl")
    cert = f.obj(ssl, "cert", "ssl.cert")
    subject = f.obj(cert, "subject", "ssl.cert.subject")
    issuer = f.obj(cert, "issuer", "ssl.cert.issuer")
    pubkey = f.obj(cert, "pubkey", "ssl.cert.pubkey")
    browser = f.obj(f.obj(ssl, "trust", "ssl.trust"), "browser", "ssl.trust.browser")
    san: list[str] | None = None
    for ext in f.get(cert, "extensions", list, "ssl.cert.extensions") or []:
        if isinstance(ext, dict) and ext.get("name") == "subjectAltName" and isinstance(ext.get("data"), str):
            try:
                san = san_dns_names(ext["data"])
            except (ValueError, IndexError):
                warnings.append("ssl.cert.san:der")
            break

    ntlm = f.obj(rec, "ntlm", "ntlm")
    vulns = _vulns(rec.get("vulns"), f)

    # Known small protocol objects plus any unknown top-level key (schema drift is kept, not lost).
    protocol = {k: v for k, v in rec.items() if v is not None and (k in PROTOCOL_KEYS or k not in KNOWN_KEYS)}
    protocol_json = orjson.dumps(protocol, option=orjson.OPT_SORT_KEYS).decode() if protocol else None
    if protocol_json is not None and len(protocol_json) > PROTOCOL_JSON_MAX_BYTES:
        warnings.append("protocol_json:oversized")
        protocol_json = None

    return {
        "observation_id": _observation_id(shodan, ip, port, transport, sni, observed_at, banner_hash),
        "service_id": service_id(ip, port, transport, sni),
        "ip": ip,
        "ip_version": ip_version,
        "port": port,
        "transport": transport,
        "sni": sni,
        "observed_at": observed_at,
        "shodan_id": f.text(shodan, "id", "_shodan.id"),
        "banner_hash": banner_hash,
        "crawler": f.text(shodan, "crawler", "_shodan.crawler"),
        "module": f.text(shodan, "module", "_shodan.module"),
        "org": f.text(rec, "org", "org"),
        "isp": f.text(rec, "isp", "isp"),
        "asn": f.text(rec, "asn", "asn"),
        "country_code": f.text(location, "country_code", "location.country_code"),
        "city": f.text(location, "city", "location.city"),
        "cloud_provider": f.text(cloud, "provider", "cloud.provider"),
        "cloud_service": f.text(cloud, "service", "cloud.service"),
        "cloud_region": f.text(cloud, "region", "cloud.region"),
        "product": f.text(rec, "product", "product"),
        "version": f.text(rec, "version", "version"),
        "os": f.text(rec, "os", "os"),
        "devicetype": f.text(rec, "devicetype", "devicetype"),
        "info": f.text(rec, "info", "info"),
        "cpe23": f.strings(rec, "cpe23", "cpe23"),
        "tags": f.strings(rec, "tags", "tags"),
        "hostnames": f.strings(rec, "hostnames", "hostnames"),
        "domains": f.strings(rec, "domains", "domains"),
        "banner_len": len(data.strip()),
        "banner_head": data[:BANNER_HEAD_CHARS],
        "http_status": f.integer(http, "status", "http.status", 32),
        "http_title": f.text(http, "title", "http.title", TITLE_CHARS),
        "http_server": f.text(http, "server", "http.server"),
        "http_host": f.text(http, "host", "http.host"),
        "http_waf": f.text(http, "waf", "http.waf"),
        "http_html_hash": f.integer(http, "html_hash", "http.html_hash", 64),
        "favicon_hash": f.integer(f.obj(http, "favicon", "http.favicon"), "hash", "http.favicon.hash", 64),
        "has_securitytxt": http.get("securitytxt") is not None if http else None,
        "has_hsts": "strict-transport-security" in headers if http else None,
        "has_csp": "content-security-policy" in headers if http else None,
        "x_powered_by": f.text(headers, "x-powered-by", "http.headers.x-powered-by"),
        "www_authenticate": f.text(headers, "www-authenticate", "http.headers.www-authenticate"),
        "http_components": sorted(components) if components else None,
        "has_ssl": bool(ssl),
        "ssl_versions": f.strings(ssl, "versions", "ssl.versions"),
        "cert_expired": f.get(cert, "expired", bool, "ssl.cert.expired"),
        "cert_expires": f.cert_time(cert, "expires", "ssl.cert.expires"),
        "cert_issued": f.cert_time(cert, "issued", "ssl.cert.issued"),
        "cert_subject_cn": f.text(subject, "CN", "ssl.cert.subject.CN"),
        "cert_subject_o": f.text(subject, "O", "ssl.cert.subject.O"),
        "cert_issuer_cn": f.text(issuer, "CN", "ssl.cert.issuer.CN"),
        "cert_issuer_o": f.text(issuer, "O", "ssl.cert.issuer.O"),
        "cert_san_dns": san,
        "cert_sig_alg": f.text(cert, "sig_alg", "ssl.cert.sig_alg"),
        "cert_key_type": f.text(pubkey, "type", "ssl.cert.pubkey.type"),
        "cert_key_bits": f.integer(pubkey, "bits", "ssl.cert.pubkey.bits", 32),
        "cert_sha256": f.text(f.obj(cert, "fingerprint", "ssl.cert.fingerprint"), "sha256", "ssl.cert.fingerprint.sha256"),
        "cert_trust_mozilla": f.get(browser, "mozilla", bool, "ssl.trust.browser.mozilla"),
        "jarm": f.text(ssl, "jarm", "ssl.jarm"),
        "ssh_hassh": f.text(f.obj(rec, "ssh", "ssh"), "hassh", "ssh.hassh"),
        "ntlm_dns_domain": f.text(ntlm, "dns_domain_name", "ntlm.dns_domain_name"),
        "ntlm_netbios_domain": f.text(ntlm, "netbios_domain_name", "ntlm.netbios_domain_name"),
        "ntlm_fqdn": f.text(ntlm, "fqdn", "ntlm.fqdn"),
        "ntlm_os_build": f.text(ntlm, "os_build", "ntlm.os_build"),
        "protocol_json": protocol_json,
        "vulns": vulns,
        "any_kev": any(v["kev"] for v in vulns) if vulns else False,
        "any_verified": any(v["verified"] for v in vulns) if vulns else False,
        "unicode_repaired": repaired,
        "parse_warnings": warnings,
        "unknown_keys": sorted(k for k in rec if k not in KNOWN_KEYS),
    }
