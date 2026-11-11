"""Attribution v1 build: services in, `evidence.parquet` + `service_attribution.parquet` out.

Evidence comes only from a service's own record (NTLM DNS domain, certificate CN and SANs,
SNI, HTTP Host, hostnames). Names are classified once per distinct raw string in Python
(`names.classify_name`, PSL), snapshot rules (infra domains, shared certificate names) are
applied in SQL exactly as `names.contextual_outcome` does.

Tiering (contract in docs/phase3-plan.md, rules in docs/attribution-implementation.md):
- A1  org_class business and (org == isp or the isp is not a provider)
- A2  org_class business inside a provider isp or provider ASN (BYOIP / sub-allocation)
- P   network provider (ISP, hoster, CDN) whose service's own record names the provider's own
      domain (certificate, SNI or HTTP Host; reverse DNS is not enough): network-provider segment
- B   any other org, and the record's own evidence names a domain that strictly wins
- C   abstain (no accepted domain, or a tie for the best evidence)

All scores, multipliers and thresholds are documented hypotheses, not measured values.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from ..ingest.normalize import NORMALIZER_VERSION
from ..logs import log
from .asn import AsnInfo, asn_number, network_provider_class
from .names import ATTRIBUTION_VERSION, classify_name, registrable_domain
from .providers import (ACCESS_PTR_PATTERN, PROVIDER_CLASSES, classify_org, domain_matches_org,
                        is_per_host_name, norm_org, org_backstop, org_names_match)

INFRA_MIN_IPS = 1000          # research: registrable domain in hostnames on >= 1,000 distinct IPs
SHARED_CERT_MIN_ORGS = 20     # certificate name served by >= 20 distinct registrant orgs
A1_CONFIDENCE = 0.9
A2_CONFIDENCE = 0.85
P_CONFIDENCE = 0.8            # provider-operated: the provider's own name on the record
NETWORK_PROVIDER_CLASSES = ("isp_telco", "cloud_hosting", "cdn")
OPERATOR_MIN_SHARE = 0.5      # an org that is neither named like the isp must hold a majority of the ASN
PROVIDER_EVIDENCE = ("(e.source IN ('cert_cn', 'cert_san', 'sni', 'http_host') "
                     "AND e.outcome IN ('accepted', 'infra_domain') AND NOT e.wildcard)")
ASN_REASON = {"isp_telco": "org_asn_isp", "cloud_hosting": "org_asn_hosting", "cdn": "org_asn_cdn"}
CORROBORATION_BONUS = 0.05    # per extra evidence family (ntlm, cert, vhost = sni/http_host, hostname)
MULTI_DOMAIN_FACTOR = 0.85    # 2-3 candidate domains
SHARED_HOSTING_FACTOR = 0.6   # > 3 candidate domains
SHARED_HOSTING_MIN = 4

# Evidence score per (service, registrable domain): first matching row wins.
DOMAIN_RULES = (
    # NTLM only corroborates a certificate, SNI or Host naming the same domain; reverse DNS is set
    # by the IP owner and is not enough to make an internal AD domain decisive.
    ("ntlm AND (cert_nw OR cert_w OR sni OR http_host)", 1.0, "dom_ntlm_corroborated"),
    ("cert_nw AND sni", 0.85, "dom_cert_sni_agree"),
    ("cert_w AND sni", 0.7, "dom_cert_wildcard_sni_agree"),
    ("cert_cn_nw", 0.6, "dom_cert"),
    ("cert_nw", 0.55, "dom_cert_san"),
    ("sni", 0.45, "dom_sni"),
    ("http_host", 0.45, "dom_http_host"),
    ("cert_w", 0.4, "dom_cert_wildcard"),
    ("hostname", 0.25, "dom_hostname_only"),
)
ORG_REASON = {
    "cloud_hosting": "org_cloud_hosting", "cdn": "org_cdn", "isp_telco": "org_isp",
    "saas_platform": "org_saas_platform", "unknown": "org_unknown",
}


def _sql_str(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def attribution_dir(pipe: Any, snapshot_id: str) -> Path:
    return (pipe.lake / "attribution" / f"attribution=v{ATTRIBUTION_VERSION}"
            / f"normalizer=v{NORMALIZER_VERSION}" / f"snapshot={snapshot_id}")


def _connect(memory_limit: str, threads: int, temp_directory: str | Path) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute(f"SET memory_limit = {_sql_str(memory_limit)}")
    con.execute(f"SET threads = {int(threads)}")
    con.execute(f"SET temp_directory = {_sql_str(temp_directory)}")
    con.execute("SET preserve_insertion_order = false")
    con.execute("SET enable_progress_bar = false")
    return con


def _map_batches(con: duckdb.DuckDBPyConnection, sql: str, fn, schema: pa.Schema, batch: int = 200_000) -> pa.Table:
    """Run `fn` over a one-column query in Arrow batches; returns the mapped table."""
    out = []
    reader = con.sql(sql).to_arrow_reader(batch)
    for rb in reader:
        values = rb.column(0).to_pylist()
        out.append(pa.Table.from_pylist([fn(v) for v in values], schema=schema))
    return pa.concat_tables(out) if out else schema.empty_table()


def compute_infra_domains(observation_files: Iterable[str | Path], min_ips: int = INFRA_MIN_IPS,
                          memory_limit: str = "4GB", threads: int = 4,
                          temp_directory: str | Path | None = None) -> dict[str, int]:
    """Registrable domains (PSL) seen in `hostnames` on >= `min_ips` distinct IPs over all observations."""
    files = [str(f) for f in observation_files]
    if not files:
        return {}
    with tempfile.TemporaryDirectory(prefix="attr-infra-") as tmpd:
        con = _connect(memory_limit, threads, temp_directory or tmpd)
        try:
            src = "read_parquet([" + ", ".join(_sql_str(f) for f in files) + "], hive_partitioning = false)"
            con.execute(f"""CREATE TEMP TABLE ip_host AS
                            SELECT DISTINCT ip, h FROM (SELECT ip, unnest(hostnames) AS h FROM {src}
                                                        WHERE len(hostnames) > 0)
                            WHERE ip IS NOT NULL AND h IS NOT NULL""")
            schema = pa.schema([("h", pa.string()), ("domain", pa.string())])
            hmap = _map_batches(con, "SELECT DISTINCT h FROM ip_host",
                                lambda h: {"h": h, "domain": registrable_domain(h)}, schema)
            con.register("hmap", hmap)
            rows = con.execute(f"""SELECT m.domain, count(DISTINCT i.ip) AS ips
                                   FROM ip_host i JOIN hmap m USING (h) WHERE m.domain IS NOT NULL
                                   GROUP BY 1 HAVING count(DISTINCT i.ip) >= {int(min_ips)}""").fetchall()
        finally:
            con.close()
    return {d: int(n) for d, n in rows}


def _write_infra_cache(path: Path, infra: dict[str, int]) -> None:
    tmp = path.with_suffix(".parquet.tmp")
    items = sorted(infra.items())
    pq.write_table(pa.table({"domain": pa.array([d for d, _ in items], pa.string()),
                             "ips": pa.array([n for _, n in items], pa.int64())}), tmp)
    os.replace(tmp, path)


def _resolve_infra(out_dir: Path, infra_domains, observation_files, refresh_infra: bool, min_ips: int,
                   memory_limit: str, threads: int, temp_directory) -> tuple[set[str], str]:
    cache = out_dir / "infra_domains.parquet"
    if infra_domains is not None:
        return set(infra_domains), "argument"
    if cache.exists() and not (refresh_infra and observation_files):
        return set(pq.read_table(cache).column("domain").to_pylist()), "cache"
    if observation_files:
        infra = compute_infra_domains(observation_files, min_ips, memory_limit, threads, temp_directory)
        _write_infra_cache(cache, infra)
        return set(infra), "computed"
    raise ValueError("infra domains: pass infra_domains, observation_files, or build once to create "
                     f"the cache {cache}")


def _score_sql() -> tuple[str, str, str]:
    score = "CASE " + " ".join(f"WHEN {c} THEN {s}" for c, s, _ in DOMAIN_RULES) + " END"
    reason = "CASE " + " ".join(f"WHEN {c} THEN '{r}'" for c, _, r in DOMAIN_RULES) + " END"
    families = "(ntlm::INT + (cert_nw OR cert_w)::INT + (sni OR http_host)::INT + hostname::INT)"
    return score, reason, families


def build_attribution(services_parquet: str | Path, out_dir: str | Path,
                      infra_domains: Iterable[str] | None = None,
                      observation_files: Iterable[str | Path] | None = None,
                      snapshot_id: str | None = None, memory_limit: str = "4GB", threads: int = 4,
                      temp_directory: str | Path | None = None, refresh_infra: bool = False,
                      infra_min_ips: int = INFRA_MIN_IPS,
                      shared_cert_min_orgs: int = SHARED_CERT_MIN_ORGS,
                      asn_table: Mapping[int, AsnInfo] | None = None) -> dict[str, Any]:
    """Write evidence.parquet and service_attribution.parquet for one snapshot's services.

    `asn_table` (ASN -> OpenASN row) adds network-type rules; None means every ASN is unknown.

    Infra domains come from `infra_domains`, else the cached `infra_domains.parquet` in `out_dir`,
    else are computed from `observation_files` (all observations of the snapshot) and cached.
    """
    started = time.perf_counter()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    obs_files = [str(f) for f in observation_files] if observation_files else []
    infra, infra_source = _resolve_infra(out_dir, infra_domains, obs_files, refresh_infra, infra_min_ips,
                                         memory_limit, threads, temp_directory)
    t_infra = time.perf_counter() - started
    ev_out, sa_out = out_dir / "evidence.parquet", out_dir / "service_attribution.parquet"
    ev_tmp, sa_tmp = ev_out.with_suffix(".parquet.tmp"), sa_out.with_suffix(".parquet.tmp")

    with tempfile.TemporaryDirectory(prefix="attr-") as tmpd:
        con = _connect(memory_limit, threads, temp_directory or tmpd)
        try:
            stats = _build(con, Path(services_parquet), infra, snapshot_id, shared_cert_min_orgs, ev_tmp, sa_tmp,
                           asn_table or {})
        finally:
            con.close()
    os.replace(ev_tmp, ev_out)
    os.replace(sa_tmp, sa_out)
    result = {
        "evidence_path": str(ev_out),
        "service_attribution_path": str(sa_out),
        "attribution_version": ATTRIBUTION_VERSION,
        "infra_domains": len(infra),
        "infra_source": infra_source,
        "infra_seconds": round(t_infra, 2),
        **stats,
        "wall_seconds": round(time.perf_counter() - started, 2),
    }
    log("attribution.built", **{k: v for k, v in result.items() if not isinstance(v, dict)})
    return result


def _build(con: duckdb.DuckDBPyConnection, services: Path, infra: set[str], snapshot_id: str | None,
           shared_cert_min_orgs: int, ev_tmp: Path, sa_tmp: Path,
           asn_table: Mapping[int, AsnInfo]) -> dict[str, Any]:
    V = ATTRIBUTION_VERSION
    snap = _sql_str(snapshot_id) if snapshot_id else "NULL"
    con.execute(f"""CREATE TEMP VIEW svc AS
                    SELECT service_id, coalesce({snap}, snapshot_id) AS snapshot_id, sni, org, isp, tags,
                           hostnames, cert_subject_cn, cert_subject_o, cert_san_dns, http_host, ntlm_dns_domain,
                           asn
                    FROM read_parquet({_sql_str(services)}, hive_partitioning = false)""")

    # 1. raw candidate names, from each service's own record only
    ip_host = r"^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-f]*:[0-9a-f]*:[0-9a-f:.]*\]?)(:\d+)?$"
    con.execute(f"""CREATE TEMP TABLE ev_raw AS
        SELECT service_id, 'ntlm' AS source, ntlm_dns_domain AS raw_name FROM svc WHERE ntlm_dns_domain LIKE '%.%'
        UNION ALL SELECT service_id, 'cert_cn', cert_subject_cn FROM svc WHERE trim(coalesce(cert_subject_cn, '')) <> ''
        UNION ALL SELECT service_id, 'cert_san', n FROM (SELECT service_id, unnest(cert_san_dns) AS n FROM svc
                                                         WHERE len(cert_san_dns) > 0) WHERE trim(coalesce(n, '')) <> ''
        UNION ALL SELECT service_id, 'sni', sni FROM svc WHERE coalesce(sni, '') <> ''
        UNION ALL SELECT service_id, 'http_host', http_host FROM svc
                  WHERE trim(coalesce(http_host, '')) <> '' AND NOT regexp_matches(lower(trim(http_host)), '{ip_host}')
        UNION ALL SELECT service_id, 'hostname', n FROM (SELECT service_id, unnest(hostnames) AS n FROM svc
                                                         WHERE len(hostnames) > 0) WHERE trim(coalesce(n, '')) <> ''""")

    # 2. context-free classification once per distinct raw string (PSL in Python)
    schema = pa.schema([("raw_name", pa.string()), ("name", pa.string()), ("wildcard", pa.bool_()),
                        ("reg_domain", pa.string()), ("base_outcome", pa.string())])

    def classify(raw: str) -> dict[str, Any]:
        name, wildcard, reg, outcome = classify_name(raw)
        return {"raw_name": raw, "name": name, "wildcard": wildcard, "reg_domain": reg, "base_outcome": outcome}

    name_map = _map_batches(con, "SELECT DISTINCT raw_name FROM ev_raw", classify, schema)
    con.register("name_map_arrow", name_map)
    con.execute("CREATE TEMP TABLE name_map AS SELECT * FROM name_map_arrow")
    con.unregister("name_map_arrow")
    del name_map
    con.register("infra_arrow", pa.table({"domain": pa.array(sorted(infra), pa.string())}))
    con.execute("CREATE TEMP TABLE infra AS SELECT DISTINCT domain FROM infra_arrow")
    con.unregister("infra_arrow")

    con.execute("""CREATE TEMP TABLE ev AS
                   SELECT e.service_id, e.source, e.raw_name, m.name, m.wildcard, m.reg_domain, m.base_outcome
                   FROM ev_raw e JOIN name_map m USING (raw_name)""")
    con.execute("DROP TABLE ev_raw")

    # 3. snapshot rule: certificate names served by many unrelated registrant orgs are shared/default certs
    con.execute(f"""CREATE TEMP TABLE shared_cert AS
                    SELECT e.name, count(DISTINCT s.org) AS orgs
                    FROM ev e JOIN svc s USING (service_id)
                    WHERE e.source IN ('cert_cn', 'cert_san') AND e.base_outcome = 'accepted'
                    GROUP BY 1 HAVING count(DISTINCT s.org) >= {int(shared_cert_min_orgs)}""")

    # 4. evidence: one row per (service, source, name); prefer a non-wildcard raw name
    con.execute("""CREATE TEMP TABLE evidence AS
        SELECT e.service_id, e.source, e.name,
               substr(min(CASE WHEN e.wildcard THEN '1' ELSE '0' END || e.raw_name), 2) AS raw_name,
               bool_and(e.wildcard) AS wildcard, any_value(e.reg_domain) AS reg_domain,
               CASE WHEN any_value(e.base_outcome) <> 'accepted' THEN any_value(e.base_outcome)
                    WHEN e.source IN ('cert_cn', 'cert_san') AND bool_or(sc.name IS NOT NULL) THEN 'provider_cert'
                    WHEN bool_or(i.domain IS NOT NULL) THEN 'infra_domain'
                    ELSE 'accepted' END AS outcome
        FROM ev e
        LEFT JOIN shared_cert sc ON sc.name = e.name
        LEFT JOIN infra i ON i.domain = e.reg_domain
        GROUP BY e.service_id, e.source, e.name""")
    con.execute("DROP TABLE ev")
    con.execute(f"""COPY (SELECT s.snapshot_id, e.service_id, e.source, e.raw_name, e.name, e.reg_domain, e.outcome,
                                 {V}::INTEGER AS attribution_version
                          FROM evidence e JOIN svc s USING (service_id)
                          ORDER BY e.service_id, e.source, e.name)
                    TO {_sql_str(ev_tmp)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 200000)""")

    # 5. per (service, registrable domain) evidence strength
    score, reason, families = _score_sql()
    con.execute(f"""CREATE TEMP TABLE dom AS
        WITH f AS (
          SELECT service_id, reg_domain,
                 bool_or(source = 'ntlm') AS ntlm,
                 bool_or(source IN ('cert_cn', 'cert_san') AND NOT wildcard) AS cert_nw,
                 bool_or(source = 'cert_cn' AND NOT wildcard) AS cert_cn_nw,
                 bool_or(source IN ('cert_cn', 'cert_san') AND wildcard) AS cert_w,
                 bool_or(source = 'sni') AS sni, bool_or(source = 'http_host') AS http_host,
                 bool_or(source = 'hostname') AS hostname
          FROM evidence WHERE outcome = 'accepted' GROUP BY 1, 2)
        SELECT service_id, reg_domain,
               round(least(1.0, {score} + {CORROBORATION_BONUS} * ({families} - 1)), 4) AS score,
               {reason} AS reason, ((ntlm AND (cert_nw OR cert_w OR sni OR http_host)) OR (cert_nw AND sni)) AS strong
        FROM f
        -- NTLM policy: an internal AD domain is restricted evidence. It never names a candidate on its
        -- own; it only corroborates a domain that a public source (cert, SNI, Host, PTR) also names.
        WHERE cert_nw OR cert_w OR sni OR http_host OR hostname""")
    con.execute("""CREATE TEMP TABLE ntlm_svc AS
                   SELECT DISTINCT service_id FROM evidence WHERE source = 'ntlm' AND outcome = 'accepted'""")
    con.execute("""CREATE TEMP TABLE svc_dom AS
        SELECT service_id, list_sort(list(reg_domain)) AS candidates, count(*) AS n_cand,
               max(score) AS top, coalesce(list_sort(list(score), 'DESC')[2], -1) AS second,
               arg_max(reg_domain, score) AS win_domain, arg_max(reason, score) AS win_reason,
               arg_max(strong, score) AS win_strong
        FROM dom GROUP BY 1""")

    # 6. org profile: curated name class + data-driven backstops per account key. Backstops, the isp-side
    # access rule and the ASN majority are keyed by `norm_org` (the account key), so spelling variants of
    # one account ("Ørsta Linje AS" / "Orsta Linje AS") are profiled together and get one class.
    access = (f"coalesce(list_bool_or(list_transform(coalesce(hostnames, []::VARCHAR[]), "
              f"lambda h: regexp_matches(lower(h), {_sql_str(ACCESS_PTR_PATTERN)}))), false)")
    con.execute(f"""CREATE TEMP TABLE svc_access AS
                    SELECT coalesce(org, '') AS org, coalesce(isp, '') AS isp, {access} AS access FROM svc""")
    raw_names = [n for (n,) in con.execute("""SELECT DISTINCT org FROM svc_access
                                              UNION SELECT DISTINCT isp FROM svc_access""").fetchall()]
    keys = {n: norm_org(n) for n in raw_names}
    con.register("org_key_arrow", pa.table({"org": pa.array(raw_names, pa.string()),
                                            "k": pa.array([keys[n] for n in raw_names], pa.string())}))
    con.execute("CREATE TEMP TABLE org_key AS SELECT * FROM org_key_arrow")
    con.unregister("org_key_arrow")
    con.execute("""CREATE TEMP TABLE org_feat AS
        WITH s AS (SELECT s.service_id, s.tags, s.cert_subject_o, k.k
                   FROM svc s JOIN org_key k ON k.org = coalesce(s.org, '')),
        base AS (
          SELECT k, count(*) AS n_services,
                 avg(list_has_any(coalesce(tags, []), ['cdn', 'cloud'])::INT) AS cdn_cloud_share,
                 avg(list_contains(coalesce(tags, []), 'cdn')::INT) AS cdn_share
          FROM s GROUP BY 1),
        acc AS (SELECT k.k, count_if(a.access) AS access_services
                FROM svc_access a JOIN org_key k USING (org) GROUP BY 1),
        doms AS (SELECT s.k, count(DISTINCT d.reg_domain) AS n_domains FROM dom d JOIN s USING (service_id) GROUP BY 1),
        certo AS (SELECT k, cert_subject_o, count(*) AS n FROM s WHERE cert_subject_o IS NOT NULL GROUP BY 1, 2)
        SELECT b.*, coalesce(d.n_domains, 0) AS n_domains, coalesce(a.access_services, 0) AS access_services,
               (SELECT list({'o': c.cert_subject_o, 'n': c.n}) FROM certo c WHERE c.k = b.k) AS cert_os
        FROM base b LEFT JOIN doms d USING (k) LEFT JOIN acc a USING (k)""")
    feats = con.execute("""SELECT k, n_services, cdn_cloud_share, cdn_share, n_domains, access_services, cert_os
                           FROM org_feat""").fetchall()
    org_side = [o for (o,) in con.execute("SELECT DISTINCT org FROM svc_access").fetchall()]
    business_keys: dict[str, str] = {}   # key -> one raw spelling that the name table reads as a business
    for o in sorted(org_side):
        if classify_org(o, None) == "business":
            business_keys.setdefault(keys[o], o)
    backstop: dict[str, tuple[str, str]] = {}
    for k, n_services, cc_share, cdn_share, n_domains, n_access, cert_os in feats:
        if k not in business_keys:
            continue
        own = sum(c["n"] for c in (cert_os or []) if org_names_match(business_keys[k], c["o"]))
        with_o = sum(c["n"] for c in (cert_os or []))
        hit = org_backstop(n_domains, n_services, own, with_o, cc_share, cdn_share, n_access)
        if hit:
            backstop[k] = hit
    # access-network backstop on the isp side too: an operator that only appears as `isp`
    isp_counts: dict[str, list[int]] = {}
    for isp, n, a in con.execute("SELECT isp, count(*), count_if(access) FROM svc_access GROUP BY 1").fetchall():
        c = isp_counts.setdefault(keys[isp], [0, 0])
        c[0] += n
        c[1] += a
    isp_access = {k for k, (n, a) in isp_counts.items() if org_backstop(0, n, 0, 0, 0.0, 0.0, a)}

    # network type of each ASN (OpenASN) and the account that operates it: the key with the most services
    triples = con.execute("""SELECT coalesce(org, '') AS org, coalesce(isp, '') AS isp, asn, count(*) AS n
                             FROM svc GROUP BY 1, 2, 3""").fetchall()
    asn_n = {raw: asn_number(raw) for raw in {t[2] for t in triples}}
    per_asn: dict[int, dict[str, int]] = {}
    for org, _, raw, n in triples:
        if asn_n[raw] is not None:
            counts = per_asn.setdefault(asn_n[raw], {})
            counts[keys[org]] = counts.get(keys[org], 0) + n
    top_org = {}
    for a, c in per_asn.items():
        k, n = min(c.items(), key=lambda kv: (-kv[1], kv[0]))
        if n / sum(c.values()) >= OPERATOR_MIN_SHARE:
            top_org[a] = k
    asn_cls = {a: network_provider_class(asn_table.get(a)) for a in per_asn}

    cls_rows = []
    for org, isp, raw, _ in triples:
        a = asn_n[raw]
        provider_asn = asn_cls.get(a) if a is not None else None
        operator = keys[org] == keys[isp] or org_names_match(org, isp) or top_org.get(a) == keys[org]
        name_cls = classify_org(org, isp)
        org_cls, extra = name_cls, None
        if name_cls == "business" and provider_asn and operator:
            org_cls, extra = provider_asn, ASN_REASON[provider_asn]
        elif name_cls == "business" and keys[org] in backstop:
            org_cls, extra = backstop[keys[org]]
        isp_cls = classify_org(isp, None)
        isp_provider = (isp_cls in PROVIDER_CLASSES or provider_asn is not None
                        or (isp_cls == "business" and (keys[isp] in backstop or keys[isp] in isp_access)))
        key = keys[org]
        cls_rows.append({
            "org": org, "isp": isp, "asn": raw, "org_class": org_cls, "extra_reason": extra,
            "org_key": key, "same_org": key == keys[isp], "isp_provider": isp_provider,
        })
    cls_schema = pa.schema([("org", pa.string()), ("isp", pa.string()), ("asn", pa.string()),
                            ("org_class", pa.string()), ("extra_reason", pa.string()), ("org_key", pa.string()),
                            ("same_org", pa.bool_()), ("isp_provider", pa.bool_())])
    con.register("org_cls_arrow", pa.Table.from_pylist(cls_rows, schema=cls_schema))
    con.execute("CREATE TEMP TABLE org_cls AS SELECT * FROM org_cls_arrow")
    con.unregister("org_cls_arrow")

    # provider-operated services: a network provider's record names the provider's own domain in a
    # certificate, SNI or HTTP Host (reverse DNS is how subscriber lines are named, so it is not enough)
    net_classes = "[" + ", ".join(f"'{c}'" for c in NETWORK_PROVIDER_CLASSES) + "]"
    # Hosters name customer machines in their own zone (vps-5f3a2b1c.vps.example.net), so a per-host
    # name is not provider evidence either.
    pairs = con.execute(f"""SELECT DISTINCT c.org, e.reg_domain, e.name
        FROM evidence e JOIN svc s USING (service_id)
        JOIN org_cls c ON c.org = coalesce(s.org, '') AND c.isp = coalesce(s.isp, '')
                      AND c.asn IS NOT DISTINCT FROM s.asn
        WHERE list_contains({net_classes}, c.org_class) AND e.reg_domain IS NOT NULL
          AND {PROVIDER_EVIDENCE}""").fetchall()
    own = [{"org": o, "name": n} for o, d, n in pairs if domain_matches_org(d, o) and not is_per_host_name(n)]
    con.register("own_arrow", pa.Table.from_pylist(own, schema=pa.schema([("org", pa.string()),
                                                                            ("name", pa.string())])))
    con.execute(f"""CREATE TEMP TABLE own_svc AS
        SELECT DISTINCT e.service_id FROM evidence e JOIN svc s USING (service_id)
        JOIN own_arrow o ON o.org = coalesce(s.org, '') AND o.name = e.name
        WHERE {PROVIDER_EVIDENCE}""")
    con.unregister("own_arrow")

    # 7. tiering
    org_reason = "CASE c.org_class " + " ".join(f"WHEN '{k}' THEN '{v}'" for k, v in ORG_REASON.items()) + " END"
    con.execute(f"""CREATE TEMP TABLE attr AS
        WITH j AS (
          SELECT s.snapshot_id, s.service_id, s.org, s.isp, c.org_class, c.extra_reason, c.org_key, c.same_org,
                 c.isp_provider, coalesce(d.candidates, []::VARCHAR[]) AS candidates, coalesce(d.n_cand, 0) AS n_cand,
                 d.top, d.second, d.win_domain, d.win_reason, d.win_strong,
                 {org_reason} AS org_reason, n.service_id IS NOT NULL AS has_ntlm,
                 o.service_id IS NOT NULL AND list_contains({net_classes}, c.org_class) AS provider_own
          FROM svc s
          JOIN org_cls c ON c.org = coalesce(s.org, '') AND c.isp = coalesce(s.isp, '')
                        AND c.asn IS NOT DISTINCT FROM s.asn
          LEFT JOIN svc_dom d USING (service_id)
          LEFT JOIN ntlm_svc n USING (service_id)
          LEFT JOIN own_svc o USING (service_id)),
        t AS (
          SELECT *,
                 CASE WHEN org_class = 'business' AND (same_org OR NOT isp_provider) THEN 'A1'
                      WHEN org_class = 'business' THEN 'A2'
                      WHEN provider_own THEN 'P'
                      WHEN n_cand > 0 AND top > second THEN 'B'
                      ELSE 'C' END AS tier
          FROM j)
        SELECT snapshot_id, service_id, {ATTRIBUTION_VERSION}::INTEGER AS attribution_version, tier,
               CASE tier WHEN 'A1' THEN 'org:' || org_key WHEN 'A2' THEN 'org:' || org_key
                         WHEN 'P' THEN 'net:' || org_key WHEN 'B' THEN 'dom:' || win_domain END AS account_id,
               CASE WHEN tier IN ('A1', 'A2', 'P') THEN org WHEN tier = 'B' THEN win_domain END AS account_name,
               round(CASE tier WHEN 'A1' THEN {A1_CONFIDENCE} WHEN 'A2' THEN {A2_CONFIDENCE}
                     WHEN 'P' THEN {P_CONFIDENCE}
                     WHEN 'B' THEN top * CASE WHEN n_cand >= {SHARED_HOSTING_MIN} THEN {SHARED_HOSTING_FACTOR}
                                              WHEN n_cand > 1 THEN {MULTI_DOMAIN_FACTOR} ELSE 1.0 END
                     ELSE 0.0 END, 3)::DOUBLE AS confidence,
               CASE WHEN tier = 'A1' THEN ['org_not_provider', CASE WHEN same_org THEN 'org_eq_isp' ELSE 'isp_not_provider' END]
                    WHEN tier = 'A2' THEN ['org_not_provider', 'byoip_in_provider']
                    WHEN tier = 'P' THEN list_filter([org_reason, extra_reason, 'provider_own_domain'],
                                                     lambda x: x IS NOT NULL)
                    ELSE list_filter([org_reason, extra_reason,
                                      CASE WHEN tier = 'B' THEN win_reason
                                           WHEN n_cand = 0 AND has_ntlm THEN 'abstain_ntlm_uncorroborated'
                                           WHEN n_cand = 0 THEN 'abstain_no_customer_evidence'
                                           ELSE 'abstain_ambiguous_domains' END,
                                      CASE WHEN n_cand >= {SHARED_HOSTING_MIN} THEN 'shared_hosting'
                                           WHEN tier = 'B' AND n_cand > 1 THEN 'multiple_candidate_domains' END],
                                     lambda x: x IS NOT NULL)
               END AS reasons,
               candidates AS candidate_domains,
               CASE WHEN tier IN ('A1', 'A2', 'P') THEN true
                    WHEN tier = 'B' THEN n_cand = 1 AND win_strong
                    ELSE false END AS allows_infra_signals,
               org, isp, org_class
        FROM t""")
    con.execute(f"""COPY (SELECT snapshot_id, service_id, attribution_version, tier, account_id, account_name,
                                 confidence,
                                 CASE WHEN confidence >= 0.75 THEN 'high' WHEN confidence >= 0.5 THEN 'medium'
                                      WHEN confidence > 0 THEN 'low' ELSE 'none' END AS confidence_band,
                                 reasons, candidate_domains, allows_infra_signals, org, isp, org_class
                          FROM attr ORDER BY service_id)
                    TO {_sql_str(sa_tmp)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 200000)""")

    tiers = dict(con.execute("SELECT tier, count(*) FROM attr GROUP BY 1 ORDER BY 1").fetchall())
    sources = {s: {"rows": r, "accepted": a, "accepted_domains": d} for s, r, a, d in con.execute(
        """SELECT source, count(*), count_if(outcome = 'accepted'),
                  count(DISTINCT reg_domain) FILTER (WHERE outcome = 'accepted')
           FROM evidence GROUP BY 1 ORDER BY 1""").fetchall()}
    outcomes = dict(con.execute("SELECT outcome, count(*) FROM evidence GROUP BY 1 ORDER BY 1").fetchall())
    services, b_infra = con.execute(
        "SELECT count(*), count_if(tier = 'B' AND allows_infra_signals) FROM attr").fetchone()
    n_shared = con.execute("SELECT count(*) FROM shared_cert").fetchone()[0]
    n_ntlm_abstain = con.execute(
        "SELECT count(*) FROM attr WHERE list_contains(reasons, 'abstain_ntlm_uncorroborated')").fetchone()[0]
    return {
        "services": services,
        "tiers": {k: tiers.get(k, 0) for k in ("A1", "A2", "P", "B", "C")},
        "asn_known": sum(1 for a in per_asn if asn_table.get(a) is not None),
        "asn_provider": sum(1 for c in asn_cls.values() if c),
        "orgs_reclassified_by_asn": len({r["org"] for r in cls_rows if r["extra_reason"] in ASN_REASON.values()}),
        "b_allows_infra_signals": b_infra,
        "evidence_rows": sum(outcomes.values()),
        "evidence_outcomes": outcomes,
        "evidence_sources": sources,
        "shared_cert_names": n_shared,
        "ntlm_uncorroborated_abstained": n_ntlm_abstain,
        "backstop_orgs": len(backstop),
        "backstop_reasons": {r: sum(1 for _, why in backstop.values() if why == r)
                             for r in ("org_access_network_ptr", "org_cdn_cloud_tagged", "org_multi_tenant")},
        "access_network_isps": len(isp_access),
    }


def build_attribution_for_snapshot(pipe: Any, snapshot_id: str, **kw: Any) -> dict[str, Any]:
    """Wire the real layer paths: services v1 in, attribution v1 dir out, committed observation files."""
    from ..transform.services import services_path

    kw.setdefault("observation_files", pipe.committed_observation_files(snapshot_id))
    kw.setdefault("snapshot_id", snapshot_id)
    if "asn_table" not in kw:
        from .asn import load_openasn
        kw["asn_table"] = load_openasn()
    return build_attribution(services_path(pipe, snapshot_id), attribution_dir(pipe, snapshot_id), **kw)
