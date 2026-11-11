"""Build tests/fixtures/real_sanitized.jsonl from distributed_sample.jsonl.

Selects real banners covering the first-priority signal classes and noise
classes, then sanitizes them:
  * every IPv4/IPv6 address -> documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32)
  * hostnames, domains, SNI, HTTP host, cert CN/SAN, NTLM names -> host-N.example.org
  * org/isp -> "Org N"/"ISP N", ASN -> private range, city/coords dropped
  * bulky or free-text blobs dropped: html, favicon data, robots, sitemap, opts.raw, vulns summaries/references
Product, version, titles, TLS parameters, tags and CPEs are kept because signal rules depend on them.
Run from the repo root:  uv run python scripts/make_regression_fixture.py
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

SRC = Path("distributed_sample.jsonl")
OUT = Path("tests/fixtures/real_sanitized.jsonl")

# (label, predicate) — first matching record per label is taken.
WANT = [
    ("s01_vpn_product", lambda r: re.search(r"fortigate|sonicwall|globalprotect|netscaler|check ?point", (r.get("product") or "") + ((r.get("http") or {}).get("title") or ""), re.I)),
    ("s03_rdp_ntlm", lambda r: r.get("ntlm") and r["port"] == 3389),
    ("s03_remote_admin", lambda r: (r.get("_shodan") or {}).get("module") in ("rdp", "telnet", "vnc")),
    ("s04_database", lambda r: re.search(r"mysql|redis|postgres|mongodb|elastic", r.get("product") or "", re.I)),
    ("s05_mgmt_plane", lambda r: re.search(r"cpanel|plesk|webmin|grafana|jenkins|kibana|idrac|ilo", ((r.get("http") or {}).get("title") or "") + (r.get("product") or ""), re.I)),
    ("s06_legacy_tls", lambda r: "TLSv1" in ((r.get("ssl") or {}).get("versions") or [])),
    ("s06_expired_cert", lambda r: ((r.get("ssl") or {}).get("cert") or {}).get("expired") is True),
    ("s16_waf", lambda r: (r.get("http") or {}).get("waf")),
    ("san_cert", lambda r: any(e.get("name") == "subjectAltName" for e in (((r.get("ssl") or {}).get("cert") or {}).get("extensions") or []))),
    ("vhost_sni", lambda r: ((r.get("_shodan") or {}).get("options") or {}).get("hostname")),
    ("ipv6", lambda r: r.get("ipv6") and not r.get("ip_str")),
    ("vulns_kev", lambda r: any(v.get("kev") for v in (r.get("vulns") or {}).values())),
    ("empty_banner", lambda r: not (r.get("data") or "").strip()),
    ("honeypot", lambda r: "honeypot" in (r.get("tags") or [])),
    ("cdn_edge", lambda r: "cdn" in (r.get("tags") or []) and (r.get("data") or "").strip()),
    ("udp_ike", lambda r: r.get("transport") == "udp" and r.get("isakmp")),
    ("ssh", lambda r: r.get("ssh")),
]

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
IPV6 = re.compile(r"(?<![0-9a-fA-F:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{1,4})*)(?![0-9a-fA-F:])")
DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|de|net|org|io|jp|kr|cn|ru|uk|au|in|br|fr|nl|info|biz|co|us|edu|gov))\b", re.I)
# Vendor / CA / protocol domains that identify products, not prospects.
VENDOR_DOMAINS = re.compile(r"(^|\.)(openssh\.com|openssh\.co|libssh\.org|asp\.net|plesk\.com|sectigo\.com|comodo\.com|comodoca\.com|letsencrypt\.org|digicert\.com|example\.org)$", re.I)
# Titles that name a real organisation are replaced; product-family titles are kept.
REDACT_TITLE = {"san_cert": "Seite nicht gefunden", "vulns_kev": "Example storefront"}
DROP_HTTP = ("html", "robots", "sitemap", "securitytxt", "headers_hash", "html_hash", "dom_hash", "redirects")


class Sanitizer:
    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.orgs: dict[str, str] = {}

    def ip(self, value: str) -> str:
        if value not in self.ips:
            n = len(self.ips) + 1
            try:
                v6 = ipaddress.ip_address(value).version == 6
            except ValueError:
                return value
            self.ips[value] = f"2001:db8::{n:x}" if v6 else (f"192.0.2.{n}" if n < 255 else f"198.51.100.{n - 254}")
        return self.ips[value]

    def name(self, value: str) -> str:
        key = value.lower().rstrip(".")
        if key not in self.names:
            self.names[key] = f"host-{len(self.names) + 1}.example.org"
        return self.names[key]

    def org(self, value: str, kind: str) -> str:
        if value not in self.orgs:
            self.orgs[value] = f"{kind} {len(self.orgs) + 1}"
        return self.orgs[value]

    def text(self, s: str) -> str:
        s = IPV4.sub(lambda m: self.ip(m.group(1)), s)
        s = IPV6.sub(lambda m: self.ip(m.group(1)) if _is_ip(m.group(1)) else m.group(1), s)
        for real, fake in sorted(self.names.items(), key=lambda kv: -len(kv[0])):
            s = re.sub(re.escape(real), fake, s, flags=re.I)
        return DOMAIN.sub(lambda m: m.group(1) if VENDOR_DOMAINS.search(m.group(1)) else self.name(m.group(1)), s)

    def walk(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.walk(x) for x in v]
        if isinstance(v, dict):
            return {k: self.walk(x) for k, x in v.items()}
        return v


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _collect_names(r: dict, san: Sanitizer) -> None:
    names = list(r.get("hostnames") or []) + list(r.get("domains") or [])
    opts = (r.get("_shodan") or {}).get("options") or {}
    names += [opts.get("hostname"), (r.get("http") or {}).get("host"), (r.get("_shodan") or {}).get("ptr")]
    cert = (r.get("ssl") or {}).get("cert") or {}
    names += [(cert.get("subject") or {}).get("CN"), (cert.get("issuer") or {}).get("CN")]
    ntlm = r.get("ntlm") or {}
    names += [ntlm.get(k) for k in ("dns_domain_name", "dns_forest_name", "fqdn", "netbios_domain_name", "netbios_computer_name", "target_realm")]
    for e in cert.get("extensions") or []:
        if e.get("name") == "subjectAltName":
            names += re.findall(r"\\x82\\x[0-9a-f]{2}([A-Za-z0-9*._-]+)", e.get("data") or "")
    for n in names:
        if isinstance(n, str) and n and not _is_ip(n) and ("." in n or n.isupper()):
            san.name(n)


def _fix_san(data: str, san: Sanitizer) -> str:
    """Rewrite dNSName entries with correct DER lengths after renaming."""
    out, total = [], 0
    for real in re.findall(r"\\x82\\x[0-9a-f]{2}([A-Za-z0-9*._-]+)", data):
        fake = san.name(real.lstrip("*.")) if real.startswith("*.") else san.name(real)
        fake = ("*." + fake) if real.startswith("*.") else fake
        out.append(f"\\x82\\x{len(fake):02x}{fake}")
        total += 2 + len(fake)
    return f"0\\x{total:02x}" + "".join(out) if out and total < 128 else ""


def sanitize(r: dict, san: Sanitizer) -> dict:
    _collect_names(r, san)
    r = json.loads(json.dumps(r))
    for k in ("org", "isp"):
        if r.get(k):
            r[k] = san.org(r[k], k.upper() if k == "isp" else "Org")
    r["asn"] = "AS64512"
    r["location"] = {"country_code": (r.get("location") or {}).get("country_code")}
    r.pop("opts", None)
    r.pop("ip", None)
    http = r.get("http")
    if isinstance(http, dict):
        for k in DROP_HTTP:
            http.pop(k, None)
        if isinstance(http.get("favicon"), dict):
            http["favicon"].pop("data", None)
    for v in (r.get("vulns") or {}).values():
        v.pop("summary", None)
        v.pop("references", None)
    cert = (r.get("ssl") or {}).get("cert") or {}
    for e in cert.get("extensions") or []:
        if e.get("name") == "subjectAltName":
            e["data"] = _fix_san(e.get("data") or "", san)
    (r.get("ssl") or {}).pop("chain", None)
    if "data" in r:
        r["data"] = r["data"][:600]
    return san.walk(r)


def main() -> None:
    picked: dict[str, dict] = {}
    for raw in SRC.open("rb"):
        r = json.loads(raw)
        for label, pred in WANT:
            if label not in picked and pred(r):
                picked[label] = r
                break
    san = Sanitizer()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as fh:
        for label, _ in WANT:
            if label in picked:
                rec = sanitize(picked[label], san)
                if label in REDACT_TITLE and isinstance(rec.get("http"), dict):
                    rec["http"]["title"] = REDACT_TITLE[label]
                    rec["data"] = re.sub(r"<title>.*?</title>", "", rec.get("data") or "", flags=re.I | re.S)
                rec["_fixture_label"] = label
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    print(f"wrote {len(picked)} records to {OUT}; missing: {[w for w, _ in WANT if w not in picked]}")


if __name__ == "__main__":
    main()
