"""Inspect the source observations behind a ranked account.

For each sampled evidence row the exact source bytes are re-read by provenance (file, byte offset,
length; SHA-256 verified), parsed with the ingestion normalizer, and summarised:

- `names_account`: public names in the record that independently name the account (certificate
  O / CN / SAN, SNI, HTTP Host, hostnames, Shodan domains). The `org` registry field is shown but
  never counts: it is what the attribution already used.
- `third_party`: registrable domains in the record that name someone else (a hosted customer,
  a subscriber, a vendor default).
- NTLM: only whether it is present and whether its domain names the account; never its values.
- Signal context from the record: probe module, product, version, HTTP title, banner head.

`ownership_verdict` turns the sampled summaries into a heuristic, not a label:
`corroborated` (a certificate, SNI or Host in some record names the account), `reverse_dns_only`
(only reverse-DNS names do: the IP owner's zone), `contradicted` (no record names it and at least
half name third parties), `registry_only` (records carry no names: only the IP registry says so),
`weak` (anything else), `no_evidence`. Name matching here is deliberately looser than
attribution's (`plausibly_names_org`: initials, distinctive words); it is a reviewer aid only.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

import duckdb

from ..attribution.names import registrable_domain
from ..attribution.providers import org_names_match, plausibly_names_org
from ..attribution.text import fold_name
from ..ingest.normalize import normalize_line

NAME_SOURCES = ("cert_cn", "cert_san", "sni", "http_host", "hostname", "domain")
REVERSE_DNS_SOURCES = frozenset({"hostname", "domain"})   # Shodan `domains` derive from hostnames
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _account_domain(account_id: str) -> str | None:
    return account_id[4:] if account_id.startswith("dom:") else None


def _names_account(reg: str | None, account_id: str, account_name: str) -> bool:
    if not reg:
        return False
    dom = _account_domain(account_id)
    return reg == dom if dom else plausibly_names_org(reg, account_name)


def _names(o: dict[str, Any]) -> list[tuple[str, str]]:
    out = [("cert_cn", o.get("cert_subject_cn")), ("sni", o.get("sni")), ("http_host", o.get("http_host"))]
    out += [("cert_san", n) for n in o.get("cert_san_dns") or []]
    out += [("hostname", n) for n in o.get("hostnames") or []]
    out += [("domain", n) for n in o.get("domains") or []]
    return [(src, n) for src, n in out if n]


def summarize_record(o: dict[str, Any], account_id: str, account_name: str) -> dict[str, Any]:
    """Summarise one normalized observation against the account it was attributed to."""
    names_account: list[str] = []
    third: dict[str, set[str]] = {}
    cert_o = o.get("cert_subject_o")
    if cert_o and not _account_domain(account_id) and org_names_match(account_name, cert_o):
        names_account.append(f"cert_o:{cert_o}")
    seen: set[str] = set()
    for src in NAME_SOURCES:
        for s, n in _names(o):
            if s != src:
                continue
            reg = registrable_domain(n)
            if not reg:
                continue
            if _names_account(reg, account_id, account_name):
                key = f"{src}:{reg}"
                if key not in seen:
                    seen.add(key)
                    names_account.append(key)
            else:
                third.setdefault(reg, set()).add(src)
    ntlm = o.get("ntlm_dns_domain")
    banner = _CONTROL.sub(" ", o.get("banner_head") or "")[:120]
    return {
        "observation_id": o.get("observation_id"),
        "ip_24": _mask(o.get("ip")), "port": o.get("port"), "transport": o.get("transport"),
        "org": o.get("org"), "isp": o.get("isp"), "asn": o.get("asn"),
        "names_account": names_account, "third_party": sorted(third),
        "third_party_sources": {d: sorted(v) for d, v in sorted(third.items())},
        "cert_o": cert_o,
        "ntlm_present": bool(ntlm),
        "ntlm_names_account": bool(ntlm) and _names_account(registrable_domain(ntlm), account_id, account_name),
        "module": o.get("module"), "product": o.get("product"), "version": o.get("version"),
        "http_title": o.get("http_title"), "banner_head": banner,
    }


def _mask(ip: str | None) -> str | None:
    if not ip:
        return ip
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"
    a, b, c, _ = ip.split(".")
    return f"{a}.{b}.{c}.0/24"


def dominant_domain(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The third-party domain in most sampled records, its share, and whether it only ever came
    from reverse DNS (an ISP or hoster naming its address space) rather than a certificate or SNI."""
    counts: dict[str, int] = {}
    sources: dict[str, set[str]] = {}
    for r in records:
        for d in r["third_party"]:
            counts[d] = counts.get(d, 0) + 1
            sources.setdefault(d, set()).update(r.get("third_party_sources", {}).get(d, []))
    if not counts:
        return None
    d, n = min(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"domain": d, "records": n, "share": round(n / len(records), 4),
            "reverse_dns_only": sources[d] <= REVERSE_DNS_SOURCES}


# Words in signal details that do not identify a product on their own.
_DETAIL_NOISE = frozenset({"portal", "ssl", "vpn", "http", "generic", "unbranded", "server", "web", "login",
                           "console", "management", "and", "the", "for"})
_DETAIL_ALIASES = {
    "rdp": ("rdp", "remote desktop"), "vnc": ("vnc", "rfb"), "ms-sql": ("ms-sql", "mssql", "sql server"),
    "elasticsearch": ("elasticsearch", "elastic"), "watchguard": ("watchguard", "fireware"),
    "fortigate": ("fortigate", "fortinet", "fortiwifi"), "big-ip": ("big-ip", "bigip"),
}
_S06_CHECKS = {
    "Expired certificate": lambda o: bool(o.get("cert_expired")),
    "TLS 1.0/1.1 accepted": lambda o: bool({"TLSv1", "TLSv1.1"} & set(o.get("ssl_versions") or [])),
    "SSLv2/SSLv3 accepted": lambda o: bool({"SSLv2", "SSLv3"} & set(o.get("ssl_versions") or [])),
    "RSA key < 2048 bits": lambda o: o.get("cert_key_type") == "rsa" and (o.get("cert_key_bits") or 4096) < 2048,
    "SHA-1/MD5 signature": lambda o: bool(re.search(r"sha1|md5", (o.get("cert_sig_alg") or "").lower())),
    "Self-signed certificate": lambda o: "self-signed" in (o.get("tags") or []),
}


def _words(s: str) -> list[str]:
    """Split on punctuation, symbols and spaces (hyphens kept); letters of any script and their
    combining marks stay inside a word."""
    return "".join(c if c == "-" or unicodedata.category(c)[0] not in "PSZC" else " " for c in s).split()


def signal_supported(signal_id: str, detail: str | None, o: dict[str, Any]) -> bool | None:
    """Does the re-read record itself show what the signal claims? None when it cannot be judged.

    S06: the TLS fact named by `detail`. Other signals: a word of `detail` appears in the record's
    product, HTTP title, banner, probe module, WAF or HTTP components.
    """
    if not detail:
        return None
    if signal_id == "S06":
        check = _S06_CHECKS.get(detail)
        return check(o) if check else None
    # Both sides accent- and case-folded (`fold_name`), so "Gestión" and "GESTION" meet.
    hay = fold_name(" ".join(str(v) for v in (o.get("product"), o.get("http_title"), o.get("banner_head"),
                                              o.get("module"), o.get("http_waf"),
                                              " ".join(o.get("http_components") or []),
                                              o.get("cert_subject_cn"), o.get("cert_issuer_cn")) if v))
    words = [w for w in _words(fold_name(detail)) if len(w) >= 3 and w not in _DETAIL_NOISE]
    if not words:
        return None
    return any(alias in hay for w in words for alias in _DETAIL_ALIASES.get(w, (w,)))


def ownership_verdict(records: list[dict[str, Any]]) -> str:
    if not records:
        return "no_evidence"
    if any(n.split(":", 1)[0] not in REVERSE_DNS_SOURCES for r in records for n in r["names_account"]):
        return "corroborated"
    if any(r["names_account"] for r in records):
        return "reverse_dns_only"
    with_third = sum(1 for r in records if r["third_party"])
    if with_third == 0:
        return "registry_only"
    if with_third * 2 >= len(records):
        return "contradicted"
    return "weak"


# ----------------------------------------------------------------------------- I/O
def read_record(pipe: Any, file_id: str, byte_offset: int, byte_length: int, record_sha256: str) -> bytes:
    """Exact source bytes for one observation, verified against its SHA-256."""
    return pipe.read_record(file_id, byte_offset, byte_length, record_sha256)


def inspect_account(pipe: Any, accounts_dir: Path, account_id: str, n: int = 8) -> dict[str, Any]:
    """Sample up to `n` evidence rows of one account (counted first, distinct services, exposures
    first) and summarise each source record."""
    ev = str(Path(accounts_dir) / "account_evidence.parquet")
    acc = str(Path(accounts_dir) / "accounts.parquet")
    con = duckdb.connect()
    try:
        cols = {c for (c,) in con.execute("SELECT name FROM parquet_schema(?)", [acc]).fetchall()}
        # scoring v3 reports opportunity priority; v1/v2 a composite score
        score = "opportunity_priority" if "opportunity_priority" in cols else "score"
        meta = con.execute(f"""SELECT account_name, segment, rank, {score}, best_tier, signal_ids
                               FROM read_parquet(?, hive_partitioning = false) WHERE account_id = ?""",
                           [acc, account_id]).fetchone()
        if meta is None:
            raise KeyError(account_id)
        rows = con.execute("""
            SELECT signal_id, detail, match_basis, tier, attribution_reasons, file_id, byte_offset, byte_length,
                   record_sha256
            FROM read_parquet(?, hive_partitioning = false) WHERE account_id = ?
            QUALIFY row_number() OVER (PARTITION BY service_id
                                       ORDER BY counted DESC, family = 'exposure' DESC, signal_id) = 1
            ORDER BY counted DESC, family = 'exposure' DESC, signal_id, service_id
            LIMIT ?""", [ev, account_id, n]).fetchall()
    finally:
        con.close()
    name = meta[0]
    records = []
    for sig, detail, basis, tier, reasons, file_id, off, length, sha in rows:
        o = normalize_line(read_record(pipe, file_id, off, length, sha))
        if not isinstance(o, dict):
            continue
        records.append({"signal_id": sig, "detail": detail, "match_basis": basis, "tier": tier,
                        "attribution_reasons": list(reasons or []),
                        "signal_supported": signal_supported(sig, detail, o),
                        **summarize_record(o, account_id, name)})
    return {"account_id": account_id, "account_name": name, "segment": meta[1], "rank": meta[2],
            "score": meta[3], "best_tier": meta[4], "signal_ids": list(meta[5] or []),
            "sampled": len(records), "verdict": ownership_verdict(records),
            "signals_supported": sum(1 for r in records if r["signal_supported"] is True),
            "signals_unsupported": sum(1 for r in records if r["signal_supported"] is False),
            "dominant_third_party": dominant_domain(records), "records": records}


def inspect_ranked(pipe: Any, accounts_dir: Path, segment: str = "enterprise", top: int = 40,
                   n: int = 8, account_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Inspect `account_ids`, else the top `top` of the segment: with scoring v3, the top of the
    actionable outreach list (what a seller would see first)."""
    if account_ids is None:
        acc = str(Path(accounts_dir) / "accounts.parquet")
        con = duckdb.connect()
        try:
            cols = {c for (c,) in con.execute("SELECT name FROM parquet_schema(?)", [acc]).fetchall()}
            only = "AND actionable" if "actionable" in cols else ""
            account_ids = [r[0] for r in con.execute(
                f"""SELECT account_id FROM read_parquet(?, hive_partitioning = false)
                    WHERE segment = ? {only} ORDER BY rank NULLS LAST, account_id LIMIT ?""",
                [acc, segment, top]).fetchall()]
        finally:
            con.close()
    return [inspect_account(pipe, accounts_dir, aid, n=n) for aid in account_ids]


def to_markdown(reports: list[dict[str, Any]]) -> str:
    """Reviewer worksheet. IPs masked to /24; NTLM values never printed."""
    lines = ["# Source-observation inspection", "",
             "Heuristic verdicts, not labels. `names_account` = public names in the raw record that name",
             "the account; `third_party` = other registrable domains in the same record.", ""]
    for r in reports:
        lines.append(f"## #{r['rank']} {r['account_name']} (`{r['account_id']}`) — **{r['verdict']}**")
        dom = r.get("dominant_third_party")
        dom_txt = (f"; most frequent other domain `{dom['domain']}` in {dom['records']}/{r['sampled']} records"
                   + (" (reverse DNS only)" if dom["reverse_dns_only"] else "")) if dom else ""
        lines.append(f"tier {r['best_tier']}, priority/score {r['score']}, signals {', '.join(r['signal_ids'])}, "
                     f"{r['sampled']} records sampled{dom_txt}")
        lines.append("")
        lines.append("| signal | detail | shown in record | service | org / isp / asn | names account | third parties | product / title | banner |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for x in r["records"]:
            third = ", ".join(x["third_party"][:4]) + (" …" if len(x["third_party"]) > 4 else "")
            lines.append("| " + " | ".join(_cell(v) for v in (
                x["signal_id"], x["detail"], {True: "yes", False: "NO", None: "?"}[x["signal_supported"]],
                f"{x['ip_24']} :{x['port']}/{x['transport']} ({x['module']})",
                f"{x['org']} / {x['isp']} / {x['asn']}",
                ", ".join(x["names_account"]) + (" +NTLM" if x["ntlm_names_account"] else ""),
                third, " / ".join(str(v) for v in (x["product"], x["version"], x["http_title"]) if v),
                x["banner_head"][:60])) + " |")
        lines.append("")
    return "\n".join(lines) + "\n"


def _cell(v: Any) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def to_json(reports: list[dict[str, Any]]) -> str:
    return json.dumps(reports, indent=1, default=str)
