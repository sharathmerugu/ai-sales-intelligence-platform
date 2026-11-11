"""Experiment 02 (part 2): weight sensitivity and bootstrap stability of the enterprise ranking.

Read-only. Recomputes scoring v2 in memory from account_evidence (counted rows only), using the
weights and functions from `firmable.accounts.scoring`, then re-ranks under alternative weights and
under bootstrap resamples of each account's services.

    uv run python docs/experiments/scripts/02_sensitivity.py \
        ~/firmable-work/lake/accounts/scoring=v2/attribution=v4/normalizer=v1/snapshot=2026-11-07

    (A frozen v4 reproduction: that table stays unchanged on disk; see docs/attribution-implementation.md §7.)

Runtime about 1 minute; stdlib + duckdb only.
"""

from __future__ import annotations

import math
import random
import sys
from collections import defaultdict

import duckdb

from firmable.accounts.scoring import BASIS_QUALITY, RELEVANCE, signal_strength

SEED = 20261111
DIR = sys.argv[1]
W0 = dict(RELEVANCE)


def load() -> tuple[dict[str, list[tuple]], dict[str, int]]:
    con = duckdb.connect()
    con.execute("SET memory_limit = '5GB'")
    quality = ("CASE match_basis " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in BASIS_QUALITY.items())
               + " ELSE 0.5 END")
    rows = con.execute(f"""
        SELECT e.account_id, e.service_id, any_value(e.ip), max(e.attribution_confidence)::DOUBLE,
               max({quality})::DOUBLE, list(DISTINCT e.signal_id)
        FROM read_parquet('{DIR}/account_evidence.parquet', hive_partitioning = false) e
        JOIN read_parquet('{DIR}/accounts.parquet', hive_partitioning = false) a USING (account_id)
        WHERE e.counted AND a.segment = 'enterprise'
        GROUP BY e.account_id, e.service_id""").fetchall()
    ranks = dict(con.execute(f"""SELECT account_id, rank
        FROM read_parquet('{DIR}/accounts.parquet', hive_partitioning = false)
        WHERE segment = 'enterprise'""").fetchall())
    services: dict[str, list[tuple]] = defaultdict(list)
    for account, _service, ip, conf, q, sigs in rows:
        services[account].append((ip, conf, q, tuple(sigs)))
    return services, ranks


SERVICES, BASE_RANK = load()
ACCOUNTS = sorted(SERVICES)


def score(services: list[tuple], w: dict[str, float]) -> tuple[float, int]:
    sigs, ips = set(), set()
    for ip, _c, _q, ss in services:
        sigs.update(ss)
        ips.add(ip)
    miss = 1.0
    for s in sigs:
        miss *= 1.0 - w.get(s, 0.0)
    a = sum(x[1] for x in services) / len(services)
    q = sum(x[2] for x in services) / len(services)
    return 100.0 * (1.0 - miss) * signal_strength(len(ips)) * a * q, len(ips)


def ranking(w: dict[str, float], resample=None) -> list[str]:
    keyed = []
    for acc in ACCOUNTS:
        sv = SERVICES[acc] if resample is None else resample(SERVICES[acc])
        sc, n = score(sv, w)
        keyed.append((-sc, -n, acc))  # same tie-break as rollup: score, counted IPs, account_id
    keyed.sort()
    return [acc for _, _, acc in keyed]


def overlap(a: list[str], b: list[str], k: int) -> float:
    return len(set(a[:k]) & set(b[:k])) / k


def line(name: str, rk: list[str]) -> None:
    print(f"{name:46s} top40 {overlap(BASE, rk, 40):.2f}  top100 {overlap(BASE, rk, 100):.2f}"
          f"  top1000 {overlap(BASE, rk, 1000):.2f}")


def summary(name: str, runs: dict[int, list[float]]) -> None:
    print(f"{name:46s} " + "  ".join(f"top{k} mean {sum(v) / len(v):.2f} min {min(v):.2f}" for k, v in runs.items()))


BASE = ranking(W0)
match = sum(1 for i, acc in enumerate(BASE[:1000]) if BASE_RANK[acc] == i + 1)
print(f"enterprise accounts: {len(ACCOUNTS)}; recomputed baseline matches accounts.parquet rank on {match}/1000 of the top 1000")

rng = random.Random(SEED)
runs: dict[int, list[float]] = defaultdict(list)
for _ in range(30):
    rk = ranking({k: min(0.95, v * rng.uniform(0.5, 1.5)) for k, v in W0.items()})
    for k in (40, 100, 1000):
        runs[k].append(overlap(BASE, rk, k))
summary("random weights x U(0.5, 1.5), 30 runs", runs)

# Information-content weights: self-information -ln(p) of each signal's account prevalence, max scaled to 0.80.
n_acc = len(ACCOUNTS)
prevalence = defaultdict(int)
for acc in ACCOUNTS:
    for s in {s for *_, ss in SERVICES[acc] for s in ss}:
        prevalence[s] += 1
info = {s: -math.log(prevalence[s] / n_acc) for s in W0}
w_info = {s: 0.80 * v / max(info.values()) for s, v in info.items()}
print("self-information weights:", {k: round(v, 3) for k, v in sorted(w_info.items())})
line("self-information (inverse-frequency) weights", ranking(w_info))
line("equal weights 0.5", ranking({k: 0.5 for k in W0}))
line("S01 and S03 weights swapped", ranking({**W0, "S01": W0["S03"], "S03": W0["S01"]}))

runs = defaultdict(list)
for _ in range(20):
    rk = ranking(W0, resample=lambda sv: [rng.choice(sv) for _ in sv])
    for k in (40, 100, 1000):
        runs[k].append(overlap(BASE, rk, k))
summary("bootstrap services within account, 20 runs", runs)
