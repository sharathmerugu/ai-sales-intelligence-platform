"""Product use-case lenses: which accounts carry evidence for one kind of security product, ranked on
that evidence alone (docs/sales-brief.md §3).

A lens is a fixed set of implemented signals. It invents no firmographic or ICP data: an account is in
a lens only when it has counted evidence from one of the lens's signals. Within a lens the account is
ranked by the scoring-v3 opportunity priority computed over the lens's signals only (relevance x
breadth, `scoring.opportunity_priority`), so breadth in unrelated categories cannot lift it.

Counting rules, per evidence row of an account:
- A row counts in a lens when its signal is in the lens and it was counted in the account roll-up,
  or it was set aside only because a signal *outside* the lens was preferred on the same service
  (rollup: one exposure per service). A row suppressed by a signal inside the lens stays uncounted, so
  one service is never counted twice in a lens.
- Security lenses (`requires_quality`) take an account only when one of its lens rows matched on a
  product, protocol, TLS or title basis (`MIN_SECURITY_BASIS_QUALITY`); a scanner tag alone is not
  enough. This is the same bar as the research-candidate gate.

Ranks, percentiles and evidence quality are computed per (lens, segment) over eligible accounts only,
like the overall rank. Ties: lens priority, then evidence quality (stronger match basis first), then
more lens IPs, then account id. Evidence quality comes before size so that equal priorities do not
default to the biggest network.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable

import duckdb
import pyarrow as pa

from .scoring import (BASIS_QUALITY, EXPOSURE_SIGNALS, MIN_SECURITY_BASIS_QUALITY, PRIORITY_DECIMALS,
                      opportunity_priority, percentile_ranks)

USE_CASES_VERSION = 1


@dataclass(frozen=True)
class UseCase:
    id: str
    name: str
    description: str
    signals: tuple[str, ...]
    requires_quality: bool = True  # security lenses need a product/protocol/TLS/title match
    context_only: bool = False     # technographic lens: account context, not a security finding

    @property
    def hygiene_is_the_finding(self) -> bool:
        """A lens of hygiene signals only (certificates): there a TLS finding is the reason to research."""
        return not self.context_only and not (set(self.signals) & EXPOSURE_SIGNALS)


USE_CASES: tuple[UseCase, ...] = (
    UseCase("remote_access", "Remote access security",
            "VPN and firewall portals, and remote-administration services (RDP, VNC, Telnet and similar) "
            "that answered from the internet.", ("S01", "S03")),
    UseCase("exposure_management", "Exposure management",
            "Any internet-reachable gateway, remote-administration service, data store or management console.",
            ("S01", "S03", "S04", "S05")),
    UseCase("data_security", "Database and data-store security",
            "Database, object-storage or database-discovery services that answered from the internet.", ("S04",)),
    UseCase("admin_consoles", "Admin and DevOps console exposure",
            "Infrastructure, DevOps and hosting management consoles that answered from the internet.", ("S05",)),
    UseCase("certificate_management", "Certificate and TLS management",
            "Endpoints with expired, self-signed or weak certificates, or old TLS versions.", ("S06",)),
    UseCase("vendor_footprint", "Security vendor footprint",
            "WAF, CDN-edge and security-appliance vendors seen in front of the account's services. "
            "Context for competitive research; not a security finding.", ("S16",),
            requires_quality=False, context_only=True),
)
USE_CASES_BY_ID = {u.id: u for u in USE_CASES}


def row_counts_in(use_case: UseCase, signal_id: str, counted: bool, suppressed_by: str | None) -> bool:
    """Whether one evidence row counts toward `use_case` (module docstring, counting rules)."""
    if signal_id not in use_case.signals:
        return False
    return counted or (suppressed_by is not None and suppressed_by not in use_case.signals)


def _quality(match_basis: str | None) -> float:
    return BASIS_QUALITY.get(match_basis or "", 0.5)


def lens_rows(evidence: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per (account, lens): the lens's counted signals, services, IPs and evidence quality.

    Reference implementation over Python rows (tests); builds use `lens_rows_sql`, which must agree.

    `evidence` rows need account_id, signal_id, service_id, ip, counted, suppressed_by, match_basis.
    Accounts with no counted lens row, or (security lenses) no row at the quality bar, are left out.
    """
    acc: dict[tuple[str, str], dict[str, Any]] = {}
    for e in evidence:
        for u in USE_CASES:
            if not row_counts_in(u, e["signal_id"], bool(e["counted"]), e["suppressed_by"]):
                continue
            a = acc.setdefault((e["account_id"], u.id), {"signals": set(), "ips": set(), "svc_quality": {}})
            a["signals"].add(e["signal_id"])
            a["ips"].add(e["ip"])
            q = _quality(e["match_basis"])
            a["svc_quality"][e["service_id"]] = max(q, a["svc_quality"].get(e["service_id"], 0.0))
    out = []
    for (account_id, uc_id), a in sorted(acc.items()):
        u = USE_CASES_BY_ID[uc_id]
        qualities = list(a["svc_quality"].values())
        if u.requires_quality and max(qualities) < MIN_SECURITY_BASIS_QUALITY:
            continue
        signals = frozenset(a["signals"])
        out.append(dict(
            account_id=account_id, use_case=uc_id, signal_ids=sorted(signals),
            n_services=len(qualities), n_ips=len(a["ips"]),
            evidence_quality=round(sum(qualities) / len(qualities), 4),
            priority=opportunity_priority(signals, len(a["ips"])),
        ))
    return out


def rank_lenses(rows: list[dict[str, Any]], accounts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Add rank and percentile per (lens, segment) over eligible accounts; others get None.

    `accounts` maps account_id -> {segment, eligibility}. Returns new dicts, sorted by lens, segment, rank.
    """
    out = [dict(r, segment=accounts[r["account_id"]]["segment"], rank=None, percentile=None) for r in rows]
    pools: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in out:
        if accounts[r["account_id"]]["eligibility"] == "eligible":
            pools.setdefault((r["use_case"], r["segment"]), []).append(r)
    for pool in pools.values():
        for r, pct in zip(pool, percentile_ranks([r["priority"] for r in pool])):
            r["percentile"] = math.floor(pct * 100 + 1e-9) / 100  # floored, as the overall percentile
        ordered = sorted(pool, key=lambda r: (-round(r["priority"], PRIORITY_DECIMALS), -r["evidence_quality"],
                                              -r["n_ips"], r["account_id"]))
        for i, r in enumerate(ordered, 1):
            r["rank"] = i
    return sorted(out, key=lambda r: (r["use_case"], r["segment"], r["rank"] is None, r["rank"] or 0, r["account_id"]))


def lens_rows_sql(con: duckdb.DuckDBPyConnection, evidence: str = "account_evidence") -> list[dict[str, Any]]:
    """`lens_rows` aggregated in DuckDB over the `evidence` table, so evidence rows never enter Python.

    Returns one dict per (account, lens), at most accounts x lenses rows, sorted like `lens_rows`.
    """
    defs = [(u.id, s) for u in USE_CASES for s in u.signals]
    con.register("uc_defs", pa.table({"uc_id": pa.array([d[0] for d in defs], pa.string()),
                                      "signal_id": pa.array([d[1] for d in defs], pa.string())}))
    con.register("uc_meta", pa.table({"uc_id": pa.array([u.id for u in USE_CASES], pa.string()),
                                      "requires_quality": pa.array([u.requires_quality for u in USE_CASES])}))
    quality = "CASE e.match_basis " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in sorted(BASIS_QUALITY.items())) \
        + " ELSE 0.5 END::DOUBLE"
    try:
        rows = con.execute(f"""
            WITH e AS (
              SELECT e.account_id, d.uc_id, e.signal_id, e.service_id, e.ip, ({quality}) AS q
              FROM {evidence} e JOIN uc_defs d ON d.signal_id = e.signal_id
              WHERE e.counted OR (e.suppressed_by IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM uc_defs x WHERE x.uc_id = d.uc_id AND x.signal_id = e.suppressed_by))),
            per_lens AS (
              SELECT account_id, uc_id, list_sort(list_distinct(list(signal_id))) AS signal_ids,
                     count(DISTINCT ip) AS n_ips
              FROM e GROUP BY account_id, uc_id),
            per_service AS (
              SELECT account_id, uc_id, service_id, max(q) AS q FROM e GROUP BY account_id, uc_id, service_id),
            quality AS (
              SELECT account_id, uc_id, count(*) AS n_services, sum(q) AS q_sum, max(q) AS q_max
              FROM per_service GROUP BY account_id, uc_id)
            SELECT l.account_id, l.uc_id AS use_case, l.signal_ids, q.n_services, l.n_ips, q.q_sum
            FROM per_lens l JOIN quality q USING (account_id, uc_id) JOIN uc_meta m USING (uc_id)
            WHERE NOT m.requires_quality OR q.q_max >= {MIN_SECURITY_BASIS_QUALITY}
            ORDER BY l.account_id, l.uc_id""").fetchall()
    finally:
        con.unregister("uc_defs")
        con.unregister("uc_meta")
    return [dict(account_id=a, use_case=u, signal_ids=list(sigs), n_services=n, n_ips=ips,
                 evidence_quality=round(q_sum / n, 4), priority=opportunity_priority(frozenset(sigs), ips))
            for a, u, sigs, n, ips, q_sum in rows]
