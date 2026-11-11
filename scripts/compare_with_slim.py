"""Regression oracle: compare normalizer-v1 observations with the frozen research slim Parquet.

Both are projections of the same 137 GB file, so totals and key distributions
must agree except for documented, explained differences.

    uv run python scripts/compare_with_slim.py --snapshot 2026-11-07
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb

from firmable.ingest.pipeline import Pipeline

LEGACY = Path.home() / "firmable-work/legacy/full_slim_v2.parquet"

METRICS = {
    # name: (legacy SQL over `slim` with parse failures removed, new SQL over `obs`)
    "rows": ("count(*)", "count(*)"),
    "ipv4_rows": ("count(ip)", "count_if(ip_version = 4)"),
    "ipv6_only_rows": ("count_if(ip IS NULL)", "count_if(ip_version = 6)"),
    "distinct_ipv4": ("count(DISTINCT ip)", "count(DISTINCT ip) FILTER (WHERE ip_version = 4)"),
    "distinct_ipv6": ("count(DISTINCT ipv6) FILTER (WHERE ip IS NULL)", "count(DISTINCT ip) FILTER (WHERE ip_version = 6)"),
    "udp_rows": ("count_if(transport = 'udp')", "count_if(transport = 'udp')"),
    "sni_rows": ("count(scan_hostname)", "count_if(sni <> '')"),
    "empty_banner_research_trim": ("count_if(coalesce(banner_len, 0) = 0)", "count_if(length(trim(banner_head)) = 0 AND banner_len = 0)"),
    "empty_banner_whitespace": ("count_if(length(trim(regexp_replace(coalesce(banner_head, ''), '\\s', '', 'g'))) = 0 AND coalesce(banner_len, 0) <= 160)", "count_if(banner_len = 0)"),
    "honeypot_tagged": ("count_if(coalesce(list_contains(tags, 'honeypot'), false))", "count_if(coalesce(list_contains(tags, 'honeypot'), false))"),
    "fingerprint_soup": (
        "count_if(coalesce(len(cpe23) >= 8 AND list_contains(cpe23, 'cpe:2.3:a:adobe:coldfusion') AND list_contains(cpe23, 'cpe:2.3:a:wordpress:wordpress'), false))",
        "count_if(coalesce(len(cpe23) >= 8 AND list_contains(cpe23, 'cpe:2.3:a:adobe:coldfusion') AND list_contains(cpe23, 'cpe:2.3:a:wordpress:wordpress'), false))",
    ),
    "has_ssl": ("count_if(has_ssl)", "count_if(has_ssl)"),
    "http_rows": ("count(http_status)", "count(http_status)"),
    "ntlm_rows": ("count(ntlm_dns_domain)", "count(ntlm_dns_domain)"),
    "any_kev": ("count_if(any_kev)", "count_if(any_kev)"),
    "product_rows": ("count(product)", "count(product)"),
    "distinct_service_keys": (
        "count(DISTINCT (coalesce(ip, ipv6), port, transport, coalesce(scan_hostname, '')))",
        "count(DISTINCT service_id)",
    ),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default="~/firmable-work")
    ap.add_argument("--snapshot", required=True)
    args = ap.parse_args()
    pipe = Pipeline(args.workdir)
    files = [str(p) for p in pipe.committed_observation_files(args.snapshot)]
    with duckdb.connect() as con:
        con.execute("SET memory_limit = '6GB'")
        con.execute("SET enable_progress_bar = false")
        con.execute(f"CREATE VIEW slim AS SELECT * FROM read_parquet('{LEGACY}') WHERE ts IS NOT NULL")
        con.execute("CREATE VIEW obs AS SELECT * FROM read_parquet([" + ",".join(f"'{f}'" for f in files) + "], hive_partitioning = false)")
        legacy = con.execute("SELECT " + ", ".join(f"{sql_l} AS {k}" for k, (sql_l, _) in METRICS.items()) + " FROM slim").fetchone()
        new = con.execute("SELECT " + ", ".join(f"{sql_n} AS {k}" for k, (_, sql_n) in METRICS.items()) + " FROM obs").fetchone()
        legacy_failures = con.execute(f"SELECT count(*) FROM read_parquet('{LEGACY}') WHERE ts IS NULL").fetchone()[0]
        repaired = con.execute("SELECT count_if(unicode_repaired), count(DISTINCT observation_id), count(*) FROM obs").fetchone()
    rows = []
    for (k, _), lv, nv in zip(METRICS.items(), legacy, new):
        rows.append({"metric": k, "legacy_slim": lv, "normalizer_v1": nv, "delta": nv - lv})
    report = {
        "legacy_parse_failures_dropped": legacy_failures,
        "v1_unicode_repaired": repaired[0],
        "v1_distinct_observation_ids": repaired[1],
        "v1_rows": repaired[2],
        "metrics": rows,
    }
    print(json.dumps(report, indent=2))
    print("\n| metric | legacy slim | normalizer v1 | delta |\n|---|---|---|---|")
    for r in rows:
        print(f"| {r['metric']} | {r['legacy_slim']:,} | {r['normalizer_v1']:,} | {r['delta']:+,} |")


if __name__ == "__main__":
    main()
