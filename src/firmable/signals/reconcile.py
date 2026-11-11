"""Reconcile v1 `signal_hits` with the research rules on the frozen research slim Parquet.

Verification tool (not used by the pipeline). It rebuilds the research `svc`
table from `~/firmable-work/legacy/full_slim_v2.parquet`, applies the research
predicates verbatim (sql/exploration.sql §6), applies the same predicates to v1
`services`, and attributes every count difference to a named cause:

    uv run python -m firmable.signals.reconcile --snapshot 2026-11-07

Takes ~40 s with memory_limit 4GB / 4 threads. Results: docs/signals-implementation.md §4.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import duckdb

from ..transform.services import _sql_str
from .registry import PARKED_TITLE_RE

RESEARCH_RULES = {
    "S01": """transport = 'tcp' AND NOT is_cdn AND (
     regexp_matches(p_l, 'fortigate|fortinet|sonicwall|check ?point|connectra|cisco asa|cisco vpn|adaptive security|netscaler|citrix|globalprotect|pan-os|palo alto|pulse secure|ivanti connect|juniper|sophos|zyxel|barracuda|watchguard|fireware|stormshield|securepoint|openvpn|draytek')
  OR regexp_matches(t_l, 'globalprotect|fortigate|ssl ?vpn|vpn portal|netscaler|citrix gateway|pulse secure|ivanti connect|fireware|anyconnect|sonicwall|big-ip logout|sophos|access server client portal'))""",
    "S03": """NOT is_cdn AND (module IN ('rdp', 'telnet', 'x11', 'rlogin', 'nomachine')
  OR regexp_matches(p_l, 'remote desktop|vnc|winrm|screenconnect|teamviewer|telnetd'))""",
    "S04": """NOT is_cdn AND (
     regexp_matches(p_l, 'mysql|mariadb|postgresql|ms-sql|sql server|mongodb|redis|elastic|clickhouse|couchdb|cassandra|influxdb|memcached|minio|riak|rethinkdb')
  OR (module IN ('mysql','ms-sql','mongodb','redis','postgresql','clickhouse-native','riak','rethinkdb','oracle-tns','couchdb','memcached') AND NOT banner_head LIKE 'HTTP/%')
  OR coalesce(list_contains(tags, 'database'), false))""",
    "S05": r"""NOT is_cdn AND (regexp_matches(p_l || ' ' || t_l,
  '\bilo\b|idrac|ipmi|cisco ios http|winbox|kubernetes|portainer|docker|jenkins|gitlab|grafana|kibana|prometheus|airflow|argo cd|rancher|consul|\bvault\b|cpanel|\bwhm\b|plesk|webmin|control web panel|cyberpanel|phpmyadmin|keycloak|minio console|sonarqube|openstack|vcenter|esxi|proxmox|unifi|routeros')
  OR coalesce(list_contains(tags, 'devops'), false))""",
    "S06": """has_ssl AND NOT is_cdn AND (
     cert_expired
  OR list_has_any(ssl_versions, ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'])
  OR (cert_key_type = 'rsa' AND cert_key_bits < 2048)
  OR regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5')
  OR (coalesce(list_contains(tags, 'self-signed'), false) AND module NOT IN ('rdp') AND http_status IS NOT NULL))""",
    "S16": """http_waf IS NOT NULL
  OR regexp_matches(p_l, 'fortigate|sonicwall|check ?point|zscaler|netscaler|bigip|barracuda|sophos|palo alto|juniper|watchguard')""",
}
_COLS = ("port, transport, module, product, http_title, tags, banner_head, has_ssl, ssl_versions, cert_expired, "
         "cert_key_type, cert_key_bits, cert_sig_alg, http_status, http_waf")
_KEY = "ipk, port, transport, snik"


def _hits(rel: str, extra: str) -> str:
    return " UNION ALL ".join(
        f"SELECT '{sid}' AS sid, {_KEY}{extra} FROM {rel} WHERE {pred}" for sid, pred in RESEARCH_RULES.items()
    )


def reconcile(slim: Path, services: Path, hits: Path, memory_limit: str = "4GB", threads: int = 4,
              temp_directory: Path | None = None) -> list[dict]:
    con = duckdb.connect()
    con.execute(f"SET memory_limit = {_sql_str(memory_limit)}")
    con.execute(f"SET threads = {int(threads)}")
    con.execute("SET preserve_insertion_order = false")
    con.execute("SET enable_progress_bar = false")
    if temp_directory:
        con.execute(f"SET temp_directory = {_sql_str(temp_directory)}")
    # Research svc (exploration.sql §4-5): eligible rows, latest ts per (ip, port, transport, raw SNI).
    # Its inner JOIN on org_profile silently dropped NULL-org rows; keep them flagged instead.
    con.execute(f"""CREATE TEMP TABLE legacy_svc AS
        SELECT coalesce(ip, ipv6) AS ipk, lower(rtrim(coalesce(scan_hostname, ''), '.')) AS snik, org,
               coalesce(list_contains(tags, 'cdn'), false) AS is_cdn,
               lower(coalesce(product, '')) AS p_l, lower(coalesce(http_title, '')) AS t_l, {_COLS}
        FROM read_parquet({_sql_str(slim)}, hive_partitioning = false)
        WHERE ts IS NOT NULL AND coalesce(banner_len, 0) > 0 AND NOT coalesce(list_contains(tags, 'honeypot'), false)
          AND NOT coalesce(len(cpe23) >= 8 AND list_contains(cpe23, 'cpe:2.3:a:adobe:coldfusion')
                           AND list_contains(cpe23, 'cpe:2.3:a:wordpress:wordpress'), false)
        QUALIFY row_number() OVER (PARTITION BY coalesce(ip, ipv6), port, transport, coalesce(scan_hostname, '')
                                   ORDER BY ts DESC) = 1""")
    con.execute(f"CREATE TEMP TABLE legacy_hits AS {_hits('legacy_svc', ', org IS NULL AS null_org')}")
    con.execute(f"""CREATE TEMP TABLE v1_svc AS
        SELECT ip AS ipk, sni AS snik, service_id, org, is_cdn, unicode_repaired,
               lower(coalesce(product, '')) AS p_l, lower(coalesce(http_title, '')) AS t_l, {_COLS}
        FROM read_parquet({_sql_str(services)}, hive_partitioning = false)""")
    con.execute(f"CREATE TEMP TABLE faithful AS {_hits('v1_svc', ', service_id')}")
    con.execute(f"""CREATE TEMP TABLE v1 AS SELECT signal_id AS sid, service_id, match_basis
                    FROM read_parquet({_sql_str(hits)}, hive_partitioning = false)""")
    con.execute(f"""CREATE TEMP TABLE removed AS
        SELECT f.sid, s.* FROM (SELECT sid, service_id FROM faithful ANTI JOIN v1 USING (sid, service_id)) f
        JOIN v1_svc s USING (service_id)""")
    rows = con.execute(f"""
        WITH lk AS (SELECT DISTINCT {_KEY} FROM legacy_svc), vk AS (SELECT DISTINCT {_KEY} FROM v1_svc),
        sids AS (SELECT DISTINCT sid FROM faithful)
        SELECT sid,
          (SELECT count(*) FROM legacy_hits l WHERE l.sid = s.sid AND NOT null_org)                    AS research_published,
          (SELECT count(*) FROM legacy_hits l WHERE l.sid = s.sid AND null_org)                        AS null_org_kept,
          (SELECT count(*) FROM faithful f ANTI JOIN lk USING ({_KEY}) WHERE f.sid = s.sid)            AS recovered_rows,
          -(SELECT count(*) FROM legacy_hits l ANTI JOIN vk USING ({_KEY}) WHERE l.sid = s.sid)        AS whitespace_banner,
          -(SELECT count(*) - count(DISTINCT ({_KEY})) FROM legacy_hits l WHERE l.sid = s.sid)         AS sni_case_merged,
          (SELECT count(*) FROM faithful f WHERE f.sid = s.sid)                                        AS research_rule_on_v1,
          (SELECT count(*) FROM v1 ANTI JOIN faithful f USING (sid, service_id) WHERE v1.sid = s.sid)  AS rule_added,
          -(SELECT count(*) FROM removed r WHERE r.sid = s.sid)                                        AS rule_removed,
          (SELECT count(*) FROM v1 WHERE v1.sid = s.sid)                                               AS v1
        FROM sids s ORDER BY sid""").fetchall()
    cols = ["sid", "research_published", "null_org_kept", "recovered_rows", "whitespace_banner", "sni_case_merged",
            "research_rule_on_v1", "rule_added", "rule_removed", "v1"]
    out = [dict(zip(cols, r)) for r in rows]
    reasons = con.execute(rf"""
        SELECT sid, CASE
            WHEN regexp_matches(t_l, {_sql_str(PARKED_TITLE_RE)}) THEN 'parked title'
            WHEN sid = 'S05' AND regexp_matches(p_l || ' ' || t_l, 'consul|unifi|ipmi') THEN 'keyword inside a word'
            WHEN starts_with(coalesce(banner_head, ''), 'HTTP/') THEN 'probe answered by HTTP'
            WHEN starts_with(coalesce(banner_head, ''), 'SSH-') THEN 'probe answered by SSH'
            ELSE 'product names another service' END AS reason, count(*) AS n
        FROM removed GROUP BY ALL ORDER BY sid, n DESC""").fetchall()
    con.close()
    for r in out:
        r["removed_by_reason"] = {reason: -n for sid, reason, n in reasons if sid == r["sid"]}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--workdir", default="~/firmable-work")
    args = ap.parse_args()
    w = Path(args.workdir).expanduser()
    snap = f"normalizer=v1/snapshot={args.snapshot}"
    started = time.perf_counter()
    rows = reconcile(
        w / "legacy/full_slim_v2.parquet",
        w / f"lake/services/services=v1/{snap}/services.parquet",
        w / f"lake/signal_hits/signals=v1/{snap}/signal_hits.parquet",
        temp_directory=w / "duckdb_tmp_signals",
    )
    cols = [c for c in rows[0] if c != "removed_by_reason"]
    print("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols))
    for r in rows:
        print("| " + " | ".join(f"{r[c]:+,}" if isinstance(r[c], int) and c not in ("research_published", "research_rule_on_v1", "v1") else (f"{r[c]:,}" if isinstance(r[c], int) else r[c]) for c in cols) + " |")
    for r in rows:
        if r["removed_by_reason"]:
            print(r["sid"], r["removed_by_reason"])
    print(f"wall {time.perf_counter() - started:.1f}s")


if __name__ == "__main__":
    main()
