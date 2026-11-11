"""Offline comparison of the legacy (scoring v2) and candidate (scoring v3) enterprise rankings.

Read-only: it reads two accounts directories and writes nothing but its own report. Measures:

- top-k membership of the legacy list (all enterprise accounts by v2 rank) against the candidate
  outreach list (actionable enterprise accounts by v3 rank);
- known-negative and checker-supported cases. Name classes come from regexes and verdicts from the
  deterministic source-record checker (`inspect-accounts`); neither is ground truth, and both are
  reported as such;
- eligibility coverage, ownership-confidence distribution, and how separable priority and ownership
  are (rank correlation, band x ownership);
- stability: each relevance weight moved by +/-10, 20 and 50 %, random joint weight changes within
  the same ranges, and a bootstrap of services within each account;
- how many manual labels the review set holds (only those could measure precision).

The candidate's eligibility, ownership and actionability do not depend on the weights, so the
perturbations re-rank the same actionable set. Bootstrap resamples counted services only and keeps
the actionable set fixed: it measures priority stability, not eligibility stability.
"""

from __future__ import annotations

import csv
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

import duckdb

from ..accounts.eligibility import is_registry_label
from ..accounts.scoring import BASIS_QUALITY, EXPOSURE_SIGNALS, PRIORITY_DECIMALS, RELEVANCE, signal_strength

KS = (20, 40, 100)
LEVELS = (0.1, 0.2, 0.5)
SEED = 20261111
N_RANDOM = 30
N_BOOTSTRAP = 20
# The experiment-02 name class (docs/experiments/scripts/02_signal_structure.sql): crude, kept for comparability.
EXP02_POOL = re.compile(r"subscriber|customer|leased line|pool|dynamic|broadband|dsl|dhcp|residential|b2b")
LIKELY_ENTERPRISE = re.compile(r"universi|college|school|hospital|health|medical|bank|government|ministry"
                               r"|city of|county|state of|council|gouv|pemerintah")

Service = tuple[str, float, float, tuple[str, ...]]  # ip, attribution confidence, basis quality, signals


def overlap(a: list[str], b: list[str], k: int) -> float:
    """Share of the first k of `a` that are in the first k of `b`."""
    if k <= 0:
        return 0.0
    return len(set(a[:k]) & set(b[:k])) / k


def weight_variants(base: dict[str, float], level: float, rng: random.Random,
                    n_random: int = N_RANDOM) -> list[tuple[str, dict[str, float]]]:
    """Each weight alone x (1 +/- level), then `n_random` joint draws x U(1 - level, 1 + level).
    Weights are capped at 0.95 so noisy-OR stays below 1."""
    out = []
    for sid in sorted(base):
        for sign in (1, -1):
            out.append((f"{sid}{'+' if sign > 0 else '-'}{int(level * 100)}%",
                        {**base, sid: min(0.95, base[sid] * (1 + sign * level))}))
    for i in range(n_random):
        out.append((f"joint#{i}", {k: min(0.95, v * rng.uniform(1 - level, 1 + level)) for k, v in sorted(base.items())}))
    return out


def _relevance(sigs: frozenset[str], w: dict[str, float], cache: dict) -> float:
    key = (sigs, id(w))
    if key not in cache:
        miss = 1.0
        for s in sorted(sigs):
            miss *= 1.0 - w.get(s, 0.0)
        cache[key] = 1.0 - miss
    return cache[key]


def _summ(services: list[Service]) -> tuple[frozenset[str], int, float, float]:
    sigs = frozenset(s for *_, ss in services for s in ss)
    ips = len({ip for ip, *_ in services})
    return sigs, ips, sum(x[1] for x in services) / len(services), sum(x[2] for x in services) / len(services)


def rank_candidate(summ: dict[str, tuple], accounts: Iterable[str], w: dict[str, float]) -> list[str]:
    cache: dict = {}
    keyed = []
    for acc in accounts:
        sigs, ips, _, _ = summ[acc]
        pr = round(100.0 * _relevance(sigs, w, cache) * signal_strength(ips), PRIORITY_DECIMALS)
        keyed.append((-pr, not (sigs & EXPOSURE_SIGNALS), -ips, acc))
    keyed.sort()
    return [k[-1] for k in keyed]


def rank_legacy(summ: dict[str, tuple], accounts: Iterable[str], w: dict[str, float]) -> list[str]:
    cache: dict = {}
    keyed = []
    for acc in accounts:
        sigs, ips, a, q = summ[acc]
        sc = round(100.0 * _relevance(sigs, w, cache) * signal_strength(ips) * a * q, 4)
        keyed.append((-sc, -ips, acc))
    keyed.sort()
    return [k[-1] for k in keyed]


def _stats(values: list[float]) -> dict[str, float]:
    return {"mean": round(sum(values) / len(values), 3), "min": round(min(values), 3)} if values else {}


def _stability(base: dict[str, list[str]], rankers: dict[str, Callable[[dict], list[str]]],
               variants: list[tuple[str, dict[str, float]]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, ranker in rankers.items():
        single, joint = defaultdict(list), defaultdict(list)
        for label, w in variants:
            rk = ranker(w)
            for k in KS:
                (joint if label.startswith("joint") else single)[k].append(overlap(base[name], rk, k))
        out[name] = {"single_weight": {f"top{k}": _stats(v) for k, v in single.items()},
                     "joint_random": {f"top{k}": _stats(v) for k, v in joint.items()}}
    return out


def _spearman(x: list[float], y: list[float]) -> float:
    def ranks(v: list[float]) -> list[float]:
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for t in range(i, j + 1):
                r[order[t]] = (i + j) / 2.0
            i = j + 1
        return r
    rx, ry = ranks(x), ranks(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    sx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    sy = math.sqrt(sum((b - my) ** 2 for b in ry))
    return round(cov / (sx * sy), 3) if sx and sy else 0.0


def _manual_labels(review_csv: Path | None) -> dict[str, Any]:
    if review_csv is None or not Path(review_csv).exists():
        return {"review_csv": None, "cases": 0, "manual_labels": 0}
    with open(review_csv, newline="") as fh:
        rows = list(csv.DictReader(fh))
    labeled = sum(1 for r in rows if any((r.get(c) or "").strip() for c in r if c.startswith("manual_")
                                         and c not in ("manual_reviewer", "manual_notes")))
    return {"review_csv": str(review_csv), "cases": len(rows), "manual_labels": labeled}


def compare_rankings(legacy_dir: Path, candidate_dir: Path, review_csv: Path | None = None,
                     inspect_json: Path | None = None, seed: int = SEED,
                     n_random: int = N_RANDOM, n_bootstrap: int = N_BOOTSTRAP) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (report, local_detail). The report holds counts only (no names, ids or IPs) and can go
    in docs; `local_detail` holds account ids for reviewers and stays under ~/firmable-work."""
    con = duckdb.connect()
    con.execute("SET memory_limit = '5GB'")
    pq = lambda d, f: "read_parquet('" + str(Path(d) / f).replace("'", "''") + "', hive_partitioning = false)"  # noqa: E731
    legacy = con.execute(f"""SELECT account_id, rank, score FROM {pq(legacy_dir, 'accounts.parquet')}
                             WHERE segment = 'enterprise' ORDER BY rank""").fetchall()
    cand_cols = ("account_id", "account_name", "account_kind", "best_tier", "rank", "opportunity_priority",
                 "priority_percentile", "priority_band", "eligibility", "eligibility_reasons",
                 "ownership_confidence", "review_flags", "actionable", "actionable_blockers",
                 "attribution_confidence", "legacy_score", "legacy_rank")
    cand = {r[0]: dict(zip(cand_cols, r)) for r in con.execute(
        f"SELECT {', '.join(cand_cols)} FROM {pq(candidate_dir, 'accounts.parquet')} WHERE segment = 'enterprise'"
    ).fetchall()}
    quality = "CASE match_basis " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in BASIS_QUALITY.items()) + " ELSE 0.5 END"
    svc_rows = con.execute(f"""
        SELECT account_id, service_id, any_value(ip), max(attribution_confidence)::DOUBLE, max({quality})::DOUBLE,
               list(DISTINCT signal_id ORDER BY signal_id)
        FROM {pq(candidate_dir, 'account_evidence.parquet')} e
        WHERE counted AND NOT starts_with(account_id, 'net:')
        GROUP BY account_id, service_id ORDER BY account_id, service_id""").fetchall()
    con.close()
    services: dict[str, list[Service]] = defaultdict(list)
    for acc, _svc, ip, conf, q, sigs in svc_rows:
        services[acc].append((ip, conf, q, tuple(sigs)))

    missing = [a for a, _, _ in legacy if a not in cand]
    if missing:
        raise ValueError(f"{len(missing)} legacy enterprise accounts are not in the candidate tables "
                         f"(different attribution version?), e.g. {missing[:3]}")
    legacy_list = [a for a, _, _ in legacy]
    actionable = [a for a, r in cand.items() if r["actionable"]]
    cand_list = sorted(actionable, key=lambda a: cand[a]["rank"])
    eligible = [a for a, r in cand.items() if r["eligibility"] == "eligible"]

    # -- reproducibility of the legacy score inside v3
    legacy_rank = {a: r for a, r, _ in legacy}
    legacy_score = {a: s for a, _, s in legacy}
    legacy_check = {
        "accounts": len(legacy),
        "rank_equal": sum(1 for a, r in cand.items() if r["legacy_rank"] == legacy_rank.get(a)),
        "score_equal": sum(1 for a, r in cand.items() if r["legacy_score"] == legacy_score.get(a)),
    }

    # -- top-k membership
    membership = {}
    for k in KS + (1000,):
        lt, ct = legacy_list[:k], cand_list[:k]
        membership[f"top{k}"] = {
            "overlap": len(set(lt) & set(ct)),
            "legacy_topk_now": dict(Counter("actionable" if cand[a]["actionable"] else
                                            "excluded" if cand[a]["eligibility"] == "excluded" else "review"
                                            for a in lt)),
            "legacy_topk_blockers": dict(Counter(b for a in lt for b in cand[a]["actionable_blockers"])),
            "candidate_topk_ownership": dict(Counter(cand[a]["ownership_confidence"] for a in ct)),
            "candidate_topk_tier": dict(Counter(cand[a]["best_tier"] for a in ct)),
            "candidate_topk_band": dict(Counter(cand[a]["priority_band"] for a in ct)),
            "legacy_topk_tier": dict(Counter(cand[a]["best_tier"] for a in lt)),
        }

    # -- known negatives (name classes; not labels)
    def where(ids: set[str]) -> dict[str, Any]:
        out = {"accounts": len(ids)}
        for k in KS + (1000,):
            out[f"legacy_top{k}"] = len(ids & set(legacy_list[:k]))
            out[f"candidate_top{k}"] = len(ids & set(cand_list[:k]))
        out["candidate_excluded"] = sum(1 for a in ids if cand[a]["eligibility"] == "excluded")
        out["candidate_actionable"] = sum(1 for a in ids if cand[a]["actionable"])
        out["candidate_high_band_actionable"] = sum(1 for a in ids if cand[a]["actionable"]
                                                    and cand[a]["priority_band"] == "High")
        return out

    orgs = [a for a, r in cand.items() if r["account_kind"] == "org"]
    label_class = {a for a in orgs if is_registry_label(cand[a]["account_name"])}
    exp02_class = {a for a, r in cand.items() if EXP02_POOL.search((r["account_name"] or "").lower())}
    likely_ent = {a for a in orgs if LIKELY_ENTERPRISE.search((cand[a]["account_name"] or "").lower())}
    negatives = {"registry_label_class": where(label_class), "experiment02_pool_regex_class": where(exp02_class)}
    likely = where(likely_ent)

    # -- checker-supported cases (deterministic source-record checker on the legacy top 40; not labels)
    checker: dict[str, Any] = {"source": None}
    if inspect_json is not None and Path(inspect_json).exists():
        reports = json.loads(Path(inspect_json).read_text())
        by_verdict: dict[str, list[str]] = defaultdict(list)
        for r in reports:
            by_verdict[r["verdict"]].append(r["account_id"])
        checker = {"source": "inspect-accounts verdicts on the legacy enterprise top 40 (heuristic, not labels)"}
        for verdict, ids in sorted(by_verdict.items()):
            checker[verdict] = {
                "accounts": len(ids),
                "candidate_actionable": sum(1 for a in ids if a in cand and cand[a]["actionable"]),
                "candidate_excluded": sum(1 for a in ids if a in cand and cand[a]["eligibility"] == "excluded"),
                "candidate_review": sum(1 for a in ids if a in cand and cand[a]["eligibility"] == "eligible"
                                        and not cand[a]["actionable"]),
                "candidate_top40": len(set(ids) & set(cand_list[:40])),
            }

    # -- coverage and confidence distribution
    coverage = {
        "enterprise_accounts": len(cand),
        "eligibility": dict(Counter(r["eligibility"] for r in cand.values())),
        "exclusion_reasons": dict(Counter(x for r in cand.values() for x in r["eligibility_reasons"])),
        "actionable": len(actionable),
        "review": sum(1 for r in cand.values() if r["eligibility"] == "eligible" and not r["actionable"]),
        "blockers": dict(Counter(b for r in cand.values() for b in r["actionable_blockers"])),
        "review_flags": dict(Counter(f for r in cand.values() for f in r["review_flags"])),
        "bands_eligible": dict(Counter(cand[a]["priority_band"] for a in eligible)),
        "bands_actionable": dict(Counter(cand[a]["priority_band"] for a in actionable)),
    }
    ownership = {
        "by_tier": {t: dict(Counter(r["ownership_confidence"] for r in cand.values() if r["best_tier"] == t))
                    for t in sorted({r["best_tier"] for r in cand.values()})},
        "eligible": dict(Counter(cand[a]["ownership_confidence"] for a in eligible)),
        "band_x_ownership": {b: dict(Counter(cand[a]["ownership_confidence"] for a in eligible
                                             if cand[a]["priority_band"] == b)) for b in ("High", "Medium", "Low")},
        "spearman_priority_vs_attribution_confidence_eligible": _spearman(
            [cand[a]["opportunity_priority"] for a in eligible], [cand[a]["attribution_confidence"] for a in eligible]),
        "spearman_legacy_score_vs_attribution_confidence_all": _spearman(
            [cand[a]["legacy_score"] for a in cand], [cand[a]["attribution_confidence"] for a in cand]),
    }

    # -- stability
    summ = {a: _summ(sv) for a, sv in services.items()}
    base = {"candidate": rank_candidate(summ, actionable, RELEVANCE),
            "legacy": rank_legacy(summ, list(cand), RELEVANCE)}
    recompute = {"candidate_top100_matches_stored_rank_order": sum(
                     1 for x, y in zip(base["candidate"][:100], cand_list[:100]) if x == y),
                 "legacy_top100_matches_stored_rank_order": sum(
                     1 for x, y in zip(base["legacy"][:100], legacy_list[:100]) if x == y)}
    rankers = {"candidate": lambda w: rank_candidate(summ, actionable, w),
               "legacy": lambda w: rank_legacy(summ, list(cand), w)}
    rng = random.Random(seed)
    stability = {f"pm{int(lv * 100)}": _stability(base, rankers, weight_variants(RELEVANCE, lv, rng, n_random))
                 for lv in LEVELS}
    boot = {"candidate": defaultdict(list), "legacy": defaultdict(list)}
    for _ in range(n_bootstrap):
        bs = {a: _summ([rng.choice(sv) for _ in sv]) for a, sv in services.items()}
        for name, ranker in (("candidate", rank_candidate(bs, actionable, RELEVANCE)),
                             ("legacy", rank_legacy(bs, list(cand), RELEVANCE))):
            for k in KS:
                boot[name][k].append(overlap(base[name], ranker, k))
    stability["bootstrap_services"] = {n: {f"top{k}": _stats(v) for k, v in d.items()} for n, d in boot.items()}

    report = {
        "legacy": str(legacy_dir), "candidate": str(candidate_dir), "seed": seed,
        "random_runs_per_level": n_random, "bootstrap_runs": n_bootstrap,
        "legacy_reproduced": legacy_check, "recomputed_baselines": recompute,
        "membership": membership, "known_negatives": negatives, "likely_enterprise_name_class": likely,
        "checker_supported": checker, "coverage": coverage, "ownership": ownership, "stability": stability,
        "labels": _manual_labels(review_csv),
    }
    detail = {
        "legacy_top40": [{"account_id": a, **{k: cand[a][k] for k in ("eligibility", "actionable",
                                                                       "actionable_blockers", "ownership_confidence",
                                                                       "rank")}} for a in legacy_list[:40]],
        "candidate_top40": [{"account_id": a, "legacy_rank": cand[a]["legacy_rank"],
                             "ownership": cand[a]["ownership_confidence"], "band": cand[a]["priority_band"],
                             "percentile": cand[a]["priority_percentile"]} for a in cand_list[:40]],
        "excluded": sorted(a for a, r in cand.items() if r["eligibility"] == "excluded"),
        "likely_enterprise_not_actionable": sorted(a for a in likely_ent if not cand[a]["actionable"]),
    }
    return report, detail
