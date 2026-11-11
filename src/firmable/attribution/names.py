"""Attribution v1, name layer: normalize candidate names, registrable domain (PSL), filter outcome.

Ports `is_ptr_like`, `is_non_company_name` and `reg_domain` from sql/exploration.sql §4,
with `reg_domain` replaced by the bundled Public Suffix List (offline; private suffixes
such as github.io / herokuapp.com make every subdomain its own owner).

Outcome order (first match wins), identical in `name_outcome` and in `build.py`:
invalid → ip_literal → non_company → ptr_like → provider_cert (curated provider namespace)
→ no_registrable_domain → provider_cert (shared certificate name, cert sources only)
→ infra_domain (snapshot data) → accepted.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Iterable

from publicsuffixlist import PublicSuffixList

ATTRIBUTION_VERSION = 5  # v5: org / ISP names accent-folded before matching (attribution.text.fold_name)

OUTCOMES = (
    "accepted", "ptr_like", "non_company", "infra_domain", "provider_cert",
    "no_registrable_domain", "ip_literal", "invalid",
)
SOURCES = ("ntlm", "cert_cn", "cert_san", "sni", "http_host", "hostname")
CERT_SOURCES = frozenset({"cert_cn", "cert_san"})

# accept_unknown=False: names under TLDs that are not in the PSL (.local, .gateway, .lan) have no
# registrable domain instead of being treated as their own public suffix.
_PSL = PublicSuffixList(accept_unknown=False)

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_VALID_NAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_PORT_SUFFIX = re.compile(r"^(?P<host>[^:\[\]]+):\d{1,5}$")
_BRACKET_V6 = re.compile(r"^\[(?P<addr>[0-9a-f:.]+)\](?::\d{1,5})?$")

# --- ported is_ptr_like (sql/exploration.sql §4) ------------------------------------------------
_PTR_OCTETS = re.compile(r"(\d{1,3}[-._x]){3}\d{1,3}")
_PTR_TOKEN = re.compile(
    r"(^|[.-])(ip|host|static|dynamic|dyn|dhcp|pool|cust|customer|client|dsl|adsl|xdsl|ppp|pppoe|cpe|bb"
    r"|broadband|ftth|fiber|res|user|mobile|nat|gw)[-.]?\d"
)

# --- ported is_non_company_name, plus the cases company-attribution.md §3 lists as unhandled ------
# Non-public / pseudo TLDs. `.gateway` (ISP CPE) is new in v1.
_NON_PUBLIC_TLD = re.compile(
    r"\.(local|lan|internal|localdomain|home|arpa|adsl|corp|intranet|invalid|test|example|gateway"
    r"|localhost|lcl|router|domain|private|workgroup|default|fiberhome|clp)$|^localhost"
)
# Zones matched as a name suffix (not via the registrable domain: many dynamic-DNS zones are PSL
# private suffixes, so `x.duckdns.org` is its own registrable domain).
VENDOR_DEFAULT_ZONES = (
    # ported
    "draytek.com", "fortinet.com", "fortigate", "sonicwall.com", "ubnt.com", "ui.com", "mikrotik.com",
    "synology.me", "myqnapcloud.com", "tplinkdns.com", "asuscomm.com", "ddns.net", "duckdns.org",
    "hopto.org", "zapto.org", "freeddns.org", "myfritz.net", "kubernetes", "traefik.default",
    # v1 additions: vendor default certificate CNs seen on hundreds of unrelated orgs (full-data
    # profile 2026-11-09), RFC 2606 example names, Alibaba WAF default CN
    "synology.com", "tplinkwifi.net", "tplinkmodem.net", "tplinkdeco.net", "tplinklogin.net",
    "tplinkcloud.com", "asusrouter.com", "routerlogin.net", "routerlogin.com", "mwlogin.net",
    "example.com", "example.net", "example.org", "notexist.com", "myfoscam.org", "ikuai8.com",
    "openvpnserver.com", "self.signed", "sytes.net", "dynu.com", "dynu.net", "ddnsfree.com",
    "dnsalias.com", "dnsalias.net", "dnsalias.org", "homeip.net", "serveftp.com", "servehttp.com",
    "myddns.me", "ddns.me", "dynalias.com", "3utilities.com", "kozow.com", "ooguy.com", "linkpc.net",
    "camdvr.org", "ddnsking.com", "gotdns.ch", "mooo.com", "chickenkiller.com", "loseyourip.com",
    "hik-connect.com", "ezvizlife.com", "dahuaddns.com", "quickddns.com", "ipcam.so", "remotewd.com",
    "tailscale.net", "ts.net", "plex.direct", "yunohost.org", "nip.io", "sslip.io", "xip.io", "fritz.box", "myfritz.box",
    # dynamic-DNS / device-cloud / tunnel parents: per-user subdomains of one vendor zone, which would
    # otherwise roll unrelated subscribers into one tier-B account (fix round 2026-11-10)
    "softether.net", "vpnazure.net", "fortiddns.com", "hanwha-security.com", "secomddns.jp",
    "ddnsipcam.com", "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-cname.com",
    "dynv6.net", "dynv6.com", "mynetname.net", "dyn-dns.org", "dyn-dns.com", "freemyip.com",
    "changeip.com", "3322.org", "f3322.net", "oicp.net", "vicp.net", "oray.net", "selfhost.de",
    "spdns.de", "dynvpn.de", "goip.de", "feste-ip.net", "ddnss.de", "dnshome.de", "myvnc.com",
    "redirectme.net", "bounceme.net", "servegame.com", "myftp.biz", "myftp.org", "onthewifi.com",
    "myasustor.com", "dlinkddns.com", "mydlink.com", "ezddns.com", "easyddns.com", "myds.me",
    "quickconnect.to", "wd2go.com", "glddns.com", "keenetic.pro", "keenetic.link",
)
VENDOR_DEFAULT_NAMES = frozenset({
    "router.asus.com", "captive-portal.peplink.com", "securelogin.arubanetworks.com",
    "myrouter.grandstream.com", "console.gl-inet.com", "www.cambiumnetworks.com",
    "scg.ruckuswireless.com", "ont.huawei.com", "www.dlink.com", "www.vivotek.com",
    "www.webgui.nokia.com", "www.matrixcomsec.com", "web.fiberhome", "untangle.example.com",
    "opnsense.localdomain", "firewall.foo.local", "dsldevice.lan", "mediarouter.home",
})


def _zone_re(zones) -> re.Pattern[str]:
    # Anchored on a label boundary, so `example.com` does not match `my-example.com`.
    return re.compile(r"(^|\.)(" + "|".join(re.escape(z) for z in sorted(zones)) + r")$")


# Ported `dyndns.\w+` / `no-ip.\w+` (any TLD) plus the explicit zones.
# 3CX hosted-PBX zones (`<customer>.3cx.us`, `.my3cx.it`, `.on3cx.fr`, `.3cx.com.au`, ...) on any TLD.
_ZONE_RE = re.compile(r"(^|\.)(dyndns\.[a-z]+|no-ip\.[a-z]+|(my|on)?3cx(\.[a-z]{2,3})?\.[a-z]{2,})$|"
                      + _zone_re(VENDOR_DEFAULT_ZONES).pattern)
# Per-device serial certificates under a vendor domain (Huawei CPE: `21500104852sl3602278.huawei.com`).
_DEVICE_SERIAL = re.compile(r"^[a-z0-9]*\d{8,}[a-z0-9]*\.huawei\.com$")

# Hosting-brand and provider certificate namespaces: they name the provider, never the tenant.
PROVIDER_CERT_DOMAINS = frozenset({
    "hstgr.cloud", "cloudflaressl.com", "certfallback.com", "certfallback-esa.com",
    "cloudwaysapps.com", "vercel-infra.com", "plesk.page", "cpanel.net", "cpanel.com",
    "myhostpoint.ch", "wpenginepowered.com", "kinsta.cloud", "pantheonsite.io", "edgekey.net",
    "akamaiedge.net", "akamai.net", "fastly.net", "cloudflare.com", "cloudfront.net",
    "azureedge.net", "azurefd.net", "impervadns.net", "myshopify.com", "shopifycloud.com",
    "squarespace.com", "wixsite.com", "wix.com", "hubspot.net", "hs-sites.com", "zscaler.net",
    "zscalertwo.net", "zscalerthree.net", "zscloud.net", "ctcdn.cn", "cdnhwc3.com", "myqcloud.com",
    "bytecdn.cn", "tbcdn.cn", "alicdn.com", "chinanetcenter.com", "edgenext.com",
    "cloudhub.io",
})
# Matched as a name suffix: several are PSL private suffixes (hstgr.cloud), so the registrable
# domain would be the tenant-looking subdomain.
_PROVIDER_RE = _zone_re(PROVIDER_CERT_DOMAINS)


def normalize_name(raw: str | None) -> tuple[str, bool]:
    """Return (normalized name, was_wildcard). Lower-case, trimmed, no trailing dot, no `*.`, no `:port`.

    The returned string may still be invalid; `name_outcome` decides.
    """
    s = (raw or "").strip().strip("\x00").lower().rstrip(".")
    wildcard = False
    while s.startswith("*."):
        s, wildcard = s[2:], True
    m = _PORT_SUFFIX.match(s)
    if m:
        s = m.group("host")
    return s.rstrip("."), wildcard


def _is_ip_literal(s: str) -> bool:
    m = _BRACKET_V6.match(s)
    if m:
        s = m.group("addr")
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _to_ascii(s: str) -> str | None:
    if s.isascii():
        return s
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError:
        return None


@lru_cache(maxsize=1 << 16)
def _psl(name: str) -> str | None:
    return _PSL.privatesuffix(name)


def _valid(s: str) -> str | None:
    """ASCII form of a syntactically valid DNS name, else None."""
    if not s or len(s) > 253:
        return None
    a = _to_ascii(s)
    if a is None or not _VALID_NAME.match(a):
        return None
    return a


def registrable_domain(name: str | None) -> str | None:
    """PSL registrable domain (eTLD+1 incl. private suffixes) of a host name, or None."""
    if name is None:
        return None
    s, _ = normalize_name(name)
    if not s or _is_ip_literal(s):
        return None
    a = _valid(s)
    return _psl(a) if a else None


def is_ptr_like(name: str) -> bool:
    return bool(_PTR_OCTETS.search(name) or _PTR_TOKEN.search(name))


def is_non_company_name(name: str) -> bool:
    return bool(_NON_PUBLIC_TLD.search(name) or name in VENDOR_DEFAULT_NAMES or _ZONE_RE.search(name)
                or _DEVICE_SERIAL.match(name))


def classify_name(raw: str | None) -> tuple[str, bool, str | None, str]:
    """Context-free classification: (name, wildcard, reg_domain, outcome).

    outcome ∈ invalid, ip_literal, non_company, ptr_like, provider_cert, no_registrable_domain, accepted.
    `reg_domain` is filled whenever the name is a valid DNS name with a registrable domain, even if
    the outcome rejects it (useful context in the evidence table).
    """
    s, wildcard = normalize_name(raw)
    if not s:
        return s, wildcard, None, "invalid"
    if _is_ip_literal(s):
        return s, wildcard, None, "ip_literal"
    a = _valid(s)
    if a is None:
        return s, wildcard, None, "invalid"
    reg = _psl(a)
    if is_non_company_name(a):
        return a, wildcard, reg, "non_company"
    if is_ptr_like(a):
        return a, wildcard, reg, "ptr_like"
    if _PROVIDER_RE.search(a):
        return a, wildcard, reg, "provider_cert"
    if reg is None:
        return a, wildcard, None, "no_registrable_domain"
    return a, wildcard, reg, "accepted"


def contextual_outcome(base: str, source: str | None, name: str, reg_domain: str | None,
                       infra_domains: Iterable[str] = frozenset(),
                       shared_cert_names: Iterable[str] = frozenset()) -> str:
    """Apply snapshot-data rules to a context-free outcome (mirrored in SQL by build.py)."""
    if base != "accepted":
        return base
    if source in CERT_SOURCES and name in shared_cert_names:
        return "provider_cert"
    if reg_domain in infra_domains:
        return "infra_domain"
    return "accepted"


def name_outcome(name: str | None, *, source: str | None = None,
                 infra_domains: Iterable[str] = frozenset(),
                 shared_cert_names: Iterable[str] = frozenset()) -> str:
    """Filter outcome of one candidate name (contract values; see module docstring for the order).

    `infra_domains` (registrable domains on >= 1,000 IPs) and `shared_cert_names` (certificate names
    served by many unrelated orgs) are snapshot data computed by `build_attribution`.
    """
    n, _, reg, base = classify_name(name)
    return contextual_outcome(base, source, n, reg, infra_domains, shared_cert_names)
