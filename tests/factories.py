"""Synthetic Shodan-format banners for tests. No real scan data."""

from __future__ import annotations

import copy
import json
from typing import Any

BASE: dict[str, Any] = {
    "ip": 3221225985,
    "ip_str": "192.0.2.1",
    "port": 443,
    "transport": "tcp",
    "timestamp": "2026-11-07T14:52:01.123456",
    "hash": -123456789,
    "org": "Example Corp",
    "isp": "Example ISP",
    "asn": "AS64500",
    "location": {"country_code": "AU", "city": "Sydney"},
    "hostnames": ["vpn.example.com"],
    "domains": ["example.com"],
    "tags": [],
    "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
    "_shodan": {
        "id": "00000000-0000-0000-0000-000000000001",
        "module": "https",
        "crawler": "crawler-test",
        "options": {},
    },
}


def record(**overrides: Any) -> dict[str, Any]:
    """Return a banner dict; keys set to `...` (Ellipsis) are removed."""
    r = copy.deepcopy(BASE)
    for k, v in overrides.items():
        if v is ...:
            r.pop(k, None)
        else:
            r[k] = v
    return r


def line(**overrides: Any) -> bytes:
    return json.dumps(record(**overrides)).encode() + b"\n"


def mixed_fixture_lines() -> list[bytes]:
    """Synthetic delivery: valid, repeated, vhost, IPv6, malformed and blank lines.

    Expected accounting: 9 lines that normalize, 3 quarantined, 1 blank.
    """
    sh = BASE["_shodan"]

    def sid(n: int) -> dict:
        return {**sh, "id": f"00000000-0000-0000-0000-{n:012d}"}

    return [
        line(_shodan=sid(1)),
        line(_shodan={**sid(2), "options": {"hostname": "a.example.com"}}),  # vhost A on same IP
        line(_shodan={**sid(3), "options": {"hostname": "b.example.com"}}),  # vhost B on same IP
        line(_shodan=sid(4), ip=..., ip_str=..., ipv6="2001:db8::10"),  # IPv6
        line(_shodan=sid(5), timestamp="2026-11-07T15:00:00.000000"),  # repeat of service 1, later
        line(_shodan=sid(1)),  # exact duplicate observation of line 1
        b'{"ip_str": "192.0.2.9", "port": 22, "transpo\n',  # malformed (truncated)
        b"\n",  # blank
        line(_shodan=sid(6), port=...),  # missing required
        line(_shodan=sid(7), ip_str="not-an-ip"),  # invalid value
        line(_shodan=sid(8)).replace(b'"Example Corp"', b'"Bad \\udc80 Corp"'),  # surrogate repair
        line(_shodan=sid(9), port=22, data="SSH-2.0-OpenSSH_8.0\r\n"),
        line(_shodan=sid(10), port=3389, data=""),  # empty banner
    ]


def write_fixture(path, lines: list[bytes] | None = None) -> bytes:
    content = b"".join(lines if lines is not None else mixed_fixture_lines())
    path.write_bytes(content)
    return content
