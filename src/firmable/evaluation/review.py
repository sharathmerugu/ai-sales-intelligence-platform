"""Stratified account-review set and the metrics computed from its labels.

`build_review_set` samples about 100 cases from the baseline ranking (scoring v1, attribution v2:
before network classification) and the enriched ranking (the current accounts tables: scoring v2 or v3
over the current attribution version, with OpenASN rules and segments; the 2026-11-07 set was drawn on
scoring v2 / attribution v4). Each case carries the context a reviewer needs and two separate label sets:

- `manual_*`    filled by a human reviewer (the only labels metrics are reported on);
- `suggested_*` model-generated suggestions, kept apart and reported only as provisional.

The CSV holds real names, domains and IPs, so it lives under ~/firmable-work/eval, not in Git.
Rubric: docs/evaluation.md.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path
from typing import Any, Iterable

import duckdb
import pyarrow as pa

from ..attribution.asn import AsnInfo
from ..attribution.build import ASN_REASON

LABEL_COLUMNS = ("entity_type", "qualified", "attribution_correct", "evidence_supported")
LABEL_VALUES = {
    "entity_type": ("enterprise", "network_provider", "unclear"),
    "qualified": ("yes", "no", "unclear"),
    "attribution_correct": ("yes", "no", "unclear"),
    "evidence_supported": ("yes", "no", "unclear"),
}
CONTEXT_COLUMNS = (
    "case_id", "strata", "account_id", "account_name", "segment", "best_tier", "baseline_rank", "enriched_rank",
    "baseline_score", "enriched_score", "signal_ids", "details", "countries", "n_services", "n_ips",
    "org", "isp", "asn", "openasn_category", "attribution_reasons", "sample_domains", "sample_service",
)
CSV_COLUMNS = (CONTEXT_COLUMNS + tuple(f"manual_{c}" for c in LABEL_COLUMNS) + ("manual_reviewer", "manual_notes")
               + tuple(f"suggested_{c}" for c in LABEL_COLUMNS) + ("suggested_by", "suggested_note"))
ATTRIBUTED_TIERS = ("A1", "A2", "P", "B")


def _q(p: str | Path) -> str:
    return "'" + str(p).replace("'", "''") + "'"


def _pq(p: str | Path) -> str:
    return f"read_parquet({_q(p)}, hive_partitioning = false)"


TOP_K, N_PROVIDER, N_SAMPLE = 40, 10, 10


def build_review_set(baseline_accounts: Path, enriched_accounts: Path, enriched_attribution: Path,
                     signal_hits: Path, services: Path, asn_table: dict[int, AsnInfo], out_csv: Path,
                     seed: int = 20261110, overwrite: bool = False) -> dict[str, Any]:
    """Write the review CSV; return the stratum sizes. Deterministic for a given seed.

    Refuses to overwrite an existing CSV (it may hold manual labels) unless `overwrite`.
    `asn_table` is the checksum-verified OpenASN table (`load_openasn()`).
    """
    out_csv = Path(out_csv)
    if out_csv.exists() and not overwrite:
        raise FileExistsError(f"{out_csv} exists and may hold manual labels; pass overwrite to replace it")
    con = duckdb.connect()
    try:
        return _build_review_set(con, baseline_accounts, enriched_accounts, enriched_attribution, signal_hits,
                                 services, asn_table, out_csv, seed)
    finally:
        con.close()


def _build_review_set(con: duckdb.DuckDBPyConnection, baseline_accounts: Path, enriched_accounts: Path,
                      enriched_attribution: Path, signal_hits: Path, services: Path,
                      asn_table: dict[int, AsnInfo], out_csv: Path, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    top_k, n_provider, n_sample = TOP_K, N_PROVIDER, N_SAMPLE
    con.execute("SET memory_limit = '3GB'")
    con.execute(f"CREATE TEMP TABLE base AS SELECT * FROM {_pq(Path(baseline_accounts) / 'accounts.parquet')}")
    con.execute(f"CREATE TEMP TABLE enr AS SELECT * FROM {_pq(Path(enriched_accounts) / 'accounts.parquet')}")
    con.execute(f"CREATE TEMP TABLE sa AS SELECT * FROM {_pq(Path(enriched_attribution) / 'service_attribution.parquet')}")
    con.register("oa", pa.table({"asn_n": pa.array(list(asn_table), pa.int64()),
                                 "category": pa.array([i.category for i in asn_table.values()], pa.string())}))
    con.execute(f"""CREATE TEMP VIEW svc AS SELECT service_id, ip, port, sni, cert_subject_cn, http_title, asn,
                           try_cast(replace(asn, 'AS', '') AS BIGINT) AS asn_n
                    FROM {_pq(services)}""")

    strata: dict[str, list[str]] = {}

    def ids(sql: str, params: list[Any] | None = None) -> list[str]:
        return [r[0] for r in con.execute(sql, params or []).fetchall()]

    strata["top40_baseline"] = ids(f"SELECT account_id FROM base WHERE rank <= {top_k} ORDER BY rank")
    enr_cols = {c for (c,) in con.execute("SELECT column_name FROM (DESCRIBE enr)").fetchall()}
    # scoring v3: the enriched top 40 is the outreach list (actionable), as a seller sees it
    only = "AND actionable" if "actionable" in enr_cols else ""
    strata["top40_enriched"] = ids(f"SELECT account_id FROM enr WHERE segment = 'enterprise' {only} "
                                   f"ORDER BY rank NULLS LAST, account_id LIMIT {top_k}")
    strata["top_network_provider"] = ids(f"SELECT account_id FROM enr WHERE segment = 'network_provider' "
                                         f"AND rank <= {n_provider} ORDER BY rank")
    b_pool = ids("SELECT account_id FROM enr WHERE best_tier = 'B' AND list_has_any(signal_ids, "
                 "['S01', 'S03', 'S04', 'S05']) ORDER BY account_id")
    strata["tier_b_sample"] = sorted(rng.sample(b_pool, min(n_sample, len(b_pool))))
    # baseline org accounts whose org the enriched build moved to a provider class by ASN
    moved = ids("""SELECT b.account_id FROM base b
                   WHERE b.account_kind = 'org' AND b.account_id NOT IN (SELECT account_id FROM enr)
                     AND EXISTS (SELECT 1 FROM sa WHERE sa.org = b.account_name AND list_has_any(
                                   sa.reasons, ?::VARCHAR[]))
                   ORDER BY 1""", [sorted(ASN_REASON.values())])
    strata["asn_reclassified"] = sorted(rng.sample(moved, min(n_sample, len(moved))))
    hits = _pq(signal_hits)
    c_pool = ids(f"""SELECT DISTINCT h.service_id FROM {hits} h JOIN sa USING (service_id)
                     WHERE sa.tier = 'C' AND h.family = 'exposure' ORDER BY 1""")
    abstain = sorted(rng.sample(c_pool, min(n_sample, len(c_pool))))

    by_account: dict[str, list[str]] = {}
    for name, members in strata.items():
        for aid in members:
            by_account.setdefault(aid, []).append(name)

    rows = [_account_case(con, aid, ";".join(names)) for aid, names in by_account.items()]
    rows += [_service_case(con, hits, sid) for sid in abstain]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in CSV_COLUMNS})
    sizes = {k: len(v) for k, v in strata.items()}
    sizes["abstain_sample"] = len(abstain)
    return {"path": str(out_csv), "cases": len(rows), "strata": sizes, "seed": seed}


def _join(xs: Iterable[Any] | None, n: int = 8) -> str:
    xs = [str(x) for x in (xs or []) if x is not None]
    return "|".join(xs[:n]) + ("|..." if len(xs) > n else "")


def _account_case(con: duckdb.DuckDBPyConnection, aid: str, strata: str) -> dict[str, Any]:
    def one(sql: str) -> dict[str, Any] | None:
        cur = con.execute(sql, [aid])
        names = [d[0] for d in cur.description]
        r = cur.fetchone()
        return dict(zip(names, r)) if r else None

    b = one("SELECT rank, score FROM base WHERE account_id = ?") or {}
    e = one("SELECT * FROM enr WHERE account_id = ?")
    if e is not None and "score" not in e:  # scoring v3 reports opportunity priority
        e = {**e, "score": e.get("opportunity_priority")}
    if e is None:  # baseline-only account (moved out of the enterprise list)
        e = one("SELECT * FROM base WHERE account_id = ?") or {}
        e = {**e, "rank": None, "score": None, "segment": "(not an enriched account)"}
    org = one("""SELECT any_value(sa.org) AS org, any_value(sa.isp) AS isp, mode(v.asn) AS asn,
                        mode(oa.category) AS openasn_category, list_distinct(flatten(list(sa.reasons))) AS reasons,
                        list_distinct(flatten(list(sa.candidate_domains))) AS domains,
                        any_value(v.ip || ':' || v.port || coalesce(' sni=' || nullif(v.sni, ''), '')
                                  || coalesce(' cn=' || v.cert_subject_cn, '')
                                  || coalesce(' title=' || left(v.http_title, 60), '')) AS sample
                 FROM sa JOIN svc v USING (service_id) LEFT JOIN oa USING (asn_n)
                 WHERE sa.account_id = ?""") or {}
    if not org.get("org") and aid.startswith("org:"):
        # moved accounts no longer exist in enriched attribution: describe them by org name
        org = one("""SELECT any_value(sa.org) AS org, any_value(sa.isp) AS isp, mode(v.asn) AS asn,
                            mode(oa.category) AS openasn_category, list_distinct(flatten(list(sa.reasons))) AS reasons,
                            list_distinct(flatten(list(sa.candidate_domains))) AS domains,
                            any_value(v.ip || ':' || v.port) AS sample
                     FROM sa JOIN svc v USING (service_id) LEFT JOIN oa USING (asn_n)
                     WHERE sa.org = (SELECT account_name FROM base WHERE account_id = ?)""") or {}
    return {
        "case_id": aid, "strata": strata, "account_id": aid, "account_name": e.get("account_name"),
        "segment": e.get("segment"), "best_tier": e.get("best_tier"),
        "baseline_rank": b.get("rank"), "enriched_rank": e.get("rank"),
        "baseline_score": b.get("score"), "enriched_score": e.get("score"),
        "signal_ids": _join(e.get("signal_ids")), "details": _join(e.get("details")),
        "countries": _join(e.get("countries")), "n_services": e.get("n_services"), "n_ips": e.get("n_ips"),
        "org": org.get("org"), "isp": org.get("isp"), "asn": org.get("asn"),
        "openasn_category": org.get("openasn_category"), "attribution_reasons": _join(org.get("reasons"), 12),
        "sample_domains": _join(org.get("domains"), 5), "sample_service": org.get("sample"),
    }


def _service_case(con: duckdb.DuckDBPyConnection, hits: str, sid: str) -> dict[str, Any]:
    cur = con.execute(f"""SELECT sa.org, sa.isp, v.asn, oa.category, sa.reasons, sa.candidate_domains,
                                 v.ip || ':' || v.port || coalesce(' sni=' || nullif(v.sni, ''), '')
                                   || coalesce(' cn=' || v.cert_subject_cn, '')
                                   || coalesce(' title=' || left(v.http_title, 60), '') AS sample,
                                 (SELECT list(DISTINCT signal_id) FROM {hits} h WHERE h.service_id = sa.service_id) AS sigs,
                                 (SELECT list(DISTINCT detail) FROM {hits} h WHERE h.service_id = sa.service_id) AS dets
                          FROM sa JOIN svc v USING (service_id) LEFT JOIN oa USING (asn_n)
                          WHERE sa.service_id = ?""", [sid])
    org, isp, asn, cat, reasons, doms, sample, sigs, dets = cur.fetchone()
    return {
        "case_id": f"svc:{sid}", "strata": "abstain_sample", "account_id": "", "account_name": "",
        "segment": "", "best_tier": "C", "signal_ids": _join(sorted(sigs or [])), "details": _join(dets),
        "org": org, "isp": isp, "asn": asn, "openasn_category": cat, "attribution_reasons": _join(reasons, 12),
        "sample_domains": _join(doms, 5), "sample_service": sample,
    }


# ----------------------------------------------------------------------------- metrics
def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def _rank(v: Any) -> int | None:
    if v in (None, ""):
        return None
    return int(float(v))


def review_metrics(rows: list[dict[str, Any]], source: str = "manual", ks: tuple[int, ...] = (20, 40)) -> dict[str, Any]:
    """Metrics over `manual_*` labels (default) or, separately, over `suggested_*` suggestions.

    Empty labels are unlabeled and excluded; `unclear` is labeled and counts as a negative.
    """
    if source not in ("manual", "suggested"):
        raise ValueError(f"source must be 'manual' or 'suggested', not {source!r}")

    def lab(r: dict[str, Any], col: str) -> str:
        return (r.get(f"{source}_{col}") or "").strip().lower()

    out: dict[str, Any] = {"source": source, "cases": len(rows),
                           "cases_labeled": sum(1 for r in rows if any(lab(r, c) for c in LABEL_COLUMNS))}
    pak: dict[str, dict[int, dict[str, Any]]] = {}
    for side in ("baseline", "enriched"):
        pak[side] = {}
        for k in ks:
            top = [r for r in rows if (_rank(r.get(f"{side}_rank")) or 10**9) <= k
                   and (side == "baseline" or r.get("segment") == "enterprise")]
            labeled = [r for r in top if lab(r, "qualified")]
            yes = sum(1 for r in labeled if lab(r, "qualified") == "yes")
            pak[side][k] = {"qualified": yes, "labeled": len(labeled), "k": k, "precision": _rate(yes, len(labeled))}
    out["precision_at_k"] = pak

    typed = [r for r in rows if lab(r, "entity_type") and r.get("segment") in ("enterprise", "network_provider")]
    agree = sum(1 for r in typed if lab(r, "entity_type") == r["segment"])
    out["segment_agreement"] = {"agree": agree, "labeled": len(typed), "rate": _rate(agree, len(typed))}

    moved = [r for r in rows if "asn_reclassified" in (r.get("strata") or "") and lab(r, "entity_type")]
    prov = sum(1 for r in moved if lab(r, "entity_type") == "network_provider")
    out["asn_reclassified_provider_rate"] = {"provider": prov, "labeled": len(moved), "rate": _rate(prov, len(moved))}

    # Split by build: cases that are enriched accounts vs accounts only the baseline attributed.
    out["attribution_precision"] = {}
    for side, in_side in (("enriched", lambda r: r.get("segment") in ("enterprise", "network_provider")),
                          ("baseline_only", lambda r: r.get("segment") not in ("enterprise", "network_provider"))):
        att = [r for r in rows if r.get("best_tier") in ATTRIBUTED_TIERS and in_side(r)
               and lab(r, "attribution_correct")]
        ok = sum(1 for r in att if lab(r, "attribution_correct") == "yes")
        out["attribution_precision"][side] = {"correct": ok, "labeled": len(att), "rate": _rate(ok, len(att))}

    ab = [r for r in rows if r.get("best_tier") == "C" and lab(r, "attribution_correct")]
    ok = sum(1 for r in ab if lab(r, "attribution_correct") == "yes")
    out["abstention_correct"] = {"correct": ok, "labeled": len(ab), "rate": _rate(ok, len(ab))}

    ev = [r for r in rows if lab(r, "evidence_supported")]
    ok = sum(1 for r in ev if lab(r, "evidence_supported") == "yes")
    out["evidence_support"] = {"supported": ok, "labeled": len(ev), "rate": _rate(ok, len(ev))}
    return out


def read_review(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for c in LABEL_COLUMNS:
            for src in ("manual", "suggested"):
                v = (r.get(f"{src}_{c}") or "").strip().lower()
                if v and v not in LABEL_VALUES[c]:
                    raise ValueError(f"{r['case_id']}: {src}_{c}={v!r} not in {LABEL_VALUES[c]}")
    return rows
