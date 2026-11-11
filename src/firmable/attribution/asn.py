"""OpenASN network-type reference (CC0), pinned release v2026.10.18.

`asn-categories.csv` gives each ASN a category (isp, hosting, business, education_research,
government_admin or empty), a BGP network role and curation flags. Only the category, role and
flags are used; the file is verified against the release's SHA-256 on load.

`network_provider_class` turns a row into a provider class, or None when the ASN is not a
network provider or is unknown (unknown is preserved: the existing name rules then decide).
OpenASN files content and big-tech networks (Apple AS714, Meta AS32934, Netflix, Salesforce)
under `hosting` with role `access_provider` or `content_network`; without a hosting flag those
are not treated as providers. Evaluation: docs/network-classification.md.
"""

from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Mapping

OPENASN_RELEASE = "v2026.10.18"
OPENASN_SHA256 = "28c49e4302669bc48e4b7dcd4bc5399919edb2e47c770e8443fa634c679e5419"
OPENASN_CSV = (Path(__file__).resolve().parents[3] / "reference" / "openasn" / OPENASN_RELEASE
               / "asn-categories.csv")

HOSTING_FLAGS = frozenset({"bad_asn", "hosting_extra", "vpn_provider"})
NON_PROVIDER_HOSTING_ROLES = frozenset({"access_provider", "content_network"})
_ASN = re.compile(r"^(?:as)?(\d{1,10})$")


@dataclass(frozen=True)
class AsnInfo:
    category: str | None
    network_role: str | None
    flags: tuple[str, ...]


def asn_number(raw: str | None) -> int | None:
    m = _ASN.match((raw or "").strip().lower())
    return int(m.group(1)) if m else None


def network_provider_class(info: AsnInfo | None) -> str | None:
    """`isp_telco`, `cloud_hosting`, `cdn`, or None (not a provider, or unknown)."""
    if info is None:
        return None
    if info.category == "isp":
        return "isp_telco"
    if info.category != "hosting":
        return None
    if "cdn" in info.flags:
        return "cdn"
    if HOSTING_FLAGS.intersection(info.flags) or info.network_role not in NON_PROVIDER_HOSTING_ROLES:
        return "cloud_hosting"
    return None


@lru_cache(maxsize=2)
def _load(path: str) -> Mapping[int, AsnInfo]:
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != OPENASN_SHA256:
        raise ValueError(f"OpenASN sha256 mismatch for {path}: {digest} != {OPENASN_SHA256}")
    table: dict[int, AsnInfo] = {}
    for row in csv.DictReader(data.decode("utf-8").splitlines()):
        n = asn_number(row["asn"])
        if n is None:
            continue
        flags = tuple(f for f in (row.get("openasn_flags") or "").split("|") if f)
        table[n] = AsnInfo(row.get("category") or None, row.get("network_role") or None, flags)
    return table


def load_openasn(path: str | Path | None = None) -> Mapping[int, AsnInfo]:
    """ASN -> AsnInfo from the pinned release; raises ValueError when the checksum differs."""
    return _load(str(path or OPENASN_CSV))
