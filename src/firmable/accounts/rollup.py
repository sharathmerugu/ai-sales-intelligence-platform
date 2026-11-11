"""Account roll-up v1: signal hits x service attribution -> account tables.

Rules (docs/phase3-plan.md, company-attribution.md §5):
- Tier C (account_id NULL) contributes to no account.
- Infrastructure-exposure signals (family `exposure`) attach only where the
  attribution allows them (A1/A2, or tier B with one strongly evidenced domain).
- Correlated hits on one service are kept as evidence but counted once:
  * exposure family: only the highest-relevance exposure signal on a service
    counts (a MinIO service is one exposure, not S04 + S05);
  * S16 from an appliance product does not count when the same service is an
    S01 gateway (same device, same fact).
- Every evidence row keeps its observation provenance.
- Segments (scoring v2): `net:` accounts (tier P, a network provider's own infrastructure) form the
  `network_provider` segment; everything else is `enterprise`. Ranks restart at 1 per segment, and
  the API serves `enterprise` unless `network_provider` is asked for explicitly.
- Scoring v3 (docs/ranking-v3.md, ADR 0009): ownership evidence per account is read from attribution
  evidence and services (records that name the account, third-party domains, operators, subscriber
  reverse DNS), `eligibility.assess` decides eligibility and ownership confidence, and the rank is by
  opportunity priority within the eligible accounts of a segment. Excluded accounts keep their
  evidence and get no rank. The v2 composite score and rank are kept as `legacy_score`/`legacy_rank`.
"""

from __future__ import annotations

import math
import os
import time
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from ..attribution.providers import (ACCESS_PTR_PATTERN, domain_matches_org, norm_org, org_names_match,
                                     ownership_names_org, plausibly_names_org)
from ..attribution.text import fold_name
from ..logs import log
from .eligibility import ELIGIBILITY_VERSION, Assessment, OwnershipEvidence, assess
from .scoring import (BASIS_QUALITY, EXPOSURE_SIGNALS, LEGACY_SCORING_VERSION, MIN_SECURITY_BASIS_QUALITY,
                      RELEVANCE, SCORING_VERSION, SECURITY_SIGNALS, AccountInput, actionability,
                      evidence_quality_band, opportunity_priority, percentile_ranks, priority_band,
                      score_account)

def _signal_names() -> dict[str, str]:
    from ..signals import SIGNALS  # the registry owns signal names
    return {s.id: s.name for s in SIGNALS}

LS = pa.list_(pa.string())
ACCOUNTS_SCHEMA = pa.schema([
    ("account_id", pa.string()), ("account_name", pa.string()), ("account_kind", pa.string()),
    ("segment", pa.string()), ("best_tier", pa.string()), ("n_services", pa.int64()), ("n_ips", pa.int64()),
    ("signal_ids", LS), ("top_signals", LS), ("details", LS), ("countries", LS),
    # why to act: opportunity priority (no attribution or evidence-quality term)
    ("product_relevance", pa.float64()), ("signal_strength", pa.float64()),
    ("opportunity_priority", pa.float64()), ("priority_percentile", pa.float64()), ("priority_band", pa.string()),
    ("rank", pa.int64()),
    # who owns it: eligibility and ownership confidence
    ("eligibility", pa.string()), ("eligibility_reasons", LS), ("ownership_confidence", pa.string()),
    ("ownership_reasons", LS), ("review_flags", LS), ("attribution_confidence", pa.float64()),
    ("ownership_services", pa.int64()), ("named_public_services", pa.int64()), ("named_rdns_services", pa.int64()),
    ("third_party_domains", pa.int64()), ("network_operators", pa.int64()), ("subscriber_rdns_services", pa.int64()),
    # how good the observations are
    ("evidence_quality", pa.float64()), ("evidence_quality_band", pa.string()),
    ("actionable", pa.bool_()), ("actionable_blockers", LS),
    # scoring v2, kept for before/after comparison
    ("legacy_score", pa.float64()), ("legacy_rank", pa.int64()), ("legacy_scoring_version", pa.int32()),
    ("explanation", LS), ("scoring_version", pa.int32()), ("eligibility_version", pa.int32()),
])

PUBLIC_NAME_SOURCES = ("cert_cn", "cert_san", "sni", "http_host")
# Names that may corroborate ownership: the outcomes attribution itself trusts (no shared/default
# certificates, no non-company names), non-wildcard for public names.
PUBLIC_NAME_OUTCOMES = ("accepted", "infra_domain")
RDNS_NAME_OUTCOMES = ("accepted", "ptr_like", "infra_domain")
MEAN_DECIMALS = 9  # per-account means are rounded before use so multi-threaded summation order cannot matter


def _sql_str(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _case(column: str, mapping: dict[str, float], default: float) -> str:
    whens = " ".join(f"WHEN {_sql_str(k)} THEN {v}" for k, v in sorted(mapping.items()))
    return f"(CASE {column} {whens} ELSE {default} END)"


def accounts_dir(pipe: Any, snapshot_id: str) -> Path:
    from ..attribution.names import ATTRIBUTION_VERSION
    from ..ingest.normalize import NORMALIZER_VERSION
    return (pipe.lake / "accounts" / f"scoring=v{SCORING_VERSION}" / f"attribution=v{ATTRIBUTION_VERSION}"
            / f"normalizer=v{NORMALIZER_VERSION}" / f"snapshot={snapshot_id}")


SEGMENT_POPULATION = {"enterprise": "eligible enterprise accounts", "network_provider": "network-provider accounts"}
OWNERSHIP_TEXT = {
    "record_names_account": "a certificate, SNI or HTTP Host on {named_public_services} of {ownership_services} "
                            "attributed services names this account",
    "reverse_dns_names_account": "only reverse-DNS names on {named_rdns_services} of {ownership_services} "
                                 "attributed services name this account",
    "registry_only": "no scanned record names this account; only the IP registry does",
    "tenant_domain_named_by_record": "the services' own records name this domain (mean rule confidence "
                                     "{attribution_confidence:.2f})",
    "provider_own_domain": "the provider's own domain is on its services' records",
}
FLAG_TEXT = {
    "registry_label_name": "the name reads like an IP-registry or pool label",
    "possible_network_provider": "records name {third_party_domains} other organisations' domains, more than "
                                 "10 times the {named_public_services} service(s) whose certificate, SNI or Host "
                                 "names this account (possible hosting or ISP)",
    "label_spans_network_operators": "the name is registered under {network_operators} network operators",
    "subscriber_reverse_dns": "{subscriber_rdns_services} services carry subscriber or operator reverse DNS",
}
EXCLUSION_TEXT = {
    "registry_label_not_an_organisation": "the name is an IP-registry placeholder or pool label",
    "sub_allocation_in_provider_network": "the block is a sub-allocation inside a provider network",
    "label_spans_network_operators": "the label is registered under {network_operators} network operators",
    "subscriber_reverse_dns": "{subscriber_rdns_services} of {ownership_services} services carry subscriber "
                              "or operator reverse DNS",
}
BLOCKER_TEXT = {
    "excluded": "excluded from the prospect population",
    "ownership_low": "ownership not corroborated by any record",
    "review_flags": "open review flags",
    "no_security_observation": "no counted security observation on a product, protocol, TLS or title match",
}


def _explain(row: dict[str, Any], sigs: list[dict[str, Any]], legacy) -> list[str]:
    """Plain-English explanation, priority first, then ownership, evidence and outreach status.
    Uses the allowed wording of docs/research-findings.md §3: observed facts, inferred risk."""
    population = SEGMENT_POPULATION[row["segment"]]
    if row["eligibility"] == "excluded":
        why = "; ".join(EXCLUSION_TEXT[r].format(**row) for r in row["eligibility_reasons"])
        lines = [f"Excluded from the ranking of {population}: {why}. Its evidence is kept for review."]
    else:
        lines = [
            f"{row['priority_band']} relative priority: higher than {int(row['priority_percentile'])}% of "
            f"{population} in this snapshot (priority {row['opportunity_priority']:.1f} = 100 x relevance "
            f"{row['product_relevance']:.2f} x breadth {row['signal_strength']:.2f}). Not a purchase "
            "probability, a confirmed vulnerability or a loss estimate."]
    names = _signal_names()
    for g in sorted(sigs, key=lambda g: (-RELEVANCE.get(g["signal_id"], 0.0), g["signal_id"])):
        details = ", ".join(g["details"][:3]) + (" ..." if len(g["details"]) > 3 else "")
        line = (f"{g['signal_id']} {names.get(g['signal_id'], '')}: {g['n_services']} service(s)"
                f" on {g['n_ips']} IP(s)" + (f" [{details}]" if details else ""))
        uncounted = g["n_services"] - g["n_counted_services"]
        if uncounted:
            line += f"; {uncounted} correlated with a stronger signal on the same service, not counted twice"
        lines.append(line)
    own = "; ".join(OWNERSHIP_TEXT[r].format(**row) for r in row["ownership_reasons"])
    lines.append(f"Ownership confidence {row['ownership_confidence']} (tier {row['best_tier']}): {own}. "
                 "Inferred from scan records, not verified.")
    lines.append(f"Evidence quality {row['evidence_quality_band']}: mean match basis {row['evidence_quality']:.2f} "
                 "over counted services; every observation traces to its source record.")
    if row["review_flags"]:
        lines.append("Review: " + "; ".join(FLAG_TEXT[f].format(**row) for f in row["review_flags"]) + ".")
    if row["actionable"]:
        lines.append("Outreach: actionable on this evidence.")
    else:
        lines.append("Outreach: not actionable until reviewed: "
                     + "; ".join(BLOCKER_TEXT[b] for b in row["actionable_blockers"]) + ".")
    lines.append(f"Legacy v2 score {legacy.score:.1f} (attribution and evidence quality multiplied in), "
                 f"kept for comparison only.")
    return lines


def _ownership_features(con: duckdb.DuckDBPyConnection, attrs: str, evidence_parquet: str | Path | None,
                        services_parquet: str | Path | None) -> dict[str, dict[str, int]]:
    """Per org/provider account (those in `acc_names`): what the records say about ownership, over
    all of the account's attributed services. NTLM is never read (ADR 0007)."""
    con.execute(f"""CREATE TEMP TABLE own_svc AS
        SELECT a.service_id, a.account_id, coalesce(a.isp, '') AS isp
        FROM {attrs} a SEMI JOIN acc_names n USING (account_id)
        WHERE NOT starts_with(a.account_id, 'dom:')""")
    names = dict(con.execute("SELECT account_id, account_name FROM acc_names").fetchall())
    if evidence_parquet is not None:
        con.execute(f"""CREATE TEMP TABLE own_ev AS
            SELECT e.service_id, e.source, e.name, e.reg_domain, e.outcome,
                   starts_with(coalesce(e.raw_name, ''), '*.') AS wildcard
            FROM read_parquet({_sql_str(evidence_parquet)}, hive_partitioning = false) e SEMI JOIN own_svc USING (service_id)
            WHERE e.reg_domain IS NOT NULL AND e.source <> 'ntlm'""")
    else:
        con.execute("CREATE TEMP TABLE own_ev (service_id VARCHAR, source VARCHAR, name VARCHAR, "
                    "reg_domain VARCHAR, outcome VARCHAR, wildcard BOOLEAN)")
    pairs = con.execute("""SELECT DISTINCT o.account_id, e.reg_domain FROM own_ev e JOIN own_svc o USING (service_id)""").fetchall()
    own_pairs = [(a, d) for a, d in pairs if ownership_names_org(d, names[a])]
    own_dom = pa.table({"account_id": pa.array([a for a, _ in own_pairs], pa.string()),
                        "reg_domain": pa.array([d for _, d in own_pairs], pa.string())})
    isp_pairs = con.execute("""SELECT DISTINCT o.isp, e.reg_domain FROM own_ev e JOIN own_svc o USING (service_id)
                               WHERE e.source = 'hostname' AND o.isp <> ''""").fetchall()
    zone = [(i, d) for i, d in isp_pairs if domain_matches_org(d, i) or plausibly_names_org(d, i)]
    isp_zone = pa.table({"isp": pa.array([i for i, _ in zone], pa.string()),
                         "reg_domain": pa.array([d for _, d in zone], pa.string())})
    # An account is its own operator when its name is the ISP's: then the operator's zone is its own.
    acct_isps = con.execute("SELECT DISTINCT account_id, isp FROM own_svc WHERE isp <> ''").fetchall()
    operator = [(a, i) for a, i in acct_isps
                if norm_org(names[a]) == norm_org(i) or org_names_match(names[a], i)]
    is_operator = pa.table({"account_id": pa.array([a for a, _ in operator], pa.string()),
                            "isp": pa.array([i for _, i in operator], pa.string())})
    # one operator spelled with and without accents ("Telefónica" / "TELEFONICA") counts once
    isps = [i for (i,) in con.execute("SELECT DISTINCT isp FROM own_svc").fetchall()]
    isp_key = pa.table({"isp": pa.array(isps, pa.string()),
                        "k": pa.array([fold_name(i).strip() for i in isps], pa.string())})
    if services_parquet is not None:
        con.execute(f"""CREATE TEMP TABLE own_certo AS
            SELECT s.service_id, s.cert_subject_o
            FROM read_parquet({_sql_str(services_parquet)}, hive_partitioning = false) s SEMI JOIN own_svc USING (service_id)
            WHERE s.cert_subject_o IS NOT NULL""")
    else:
        con.execute("CREATE TEMP TABLE own_certo (service_id VARCHAR, cert_subject_o VARCHAR)")
    certo = con.execute("""SELECT DISTINCT o.account_id, c.cert_subject_o FROM own_certo c
                           JOIN own_svc o USING (service_id)""").fetchall()
    own_o = [(a, o) for a, o in certo if org_names_match(names[a], o)]
    own_co = pa.table({"account_id": pa.array([a for a, _ in own_o], pa.string()),
                       "o": pa.array([o for _, o in own_o], pa.string())})
    con.register("own_dom", own_dom)
    con.register("isp_zone", isp_zone)
    con.register("own_co", own_co)
    con.register("is_operator", is_operator)
    con.register("isp_key", isp_key)
    public = "[" + ", ".join(_sql_str(x) for x in PUBLIC_NAME_SOURCES) + "]"
    public_ok = "[" + ", ".join(_sql_str(x) for x in PUBLIC_NAME_OUTCOMES) + "]"
    rdns_ok = "[" + ", ".join(_sql_str(x) for x in RDNS_NAME_OUTCOMES) + "]"
    rows = con.sql(f"""
        WITH e AS (
          SELECT o.account_id, o.service_id, e.source, e.name, e.reg_domain, e.outcome, e.wildcard,
                 od.reg_domain IS NOT NULL AS own,
                 -- the operator's zone names the operator, not a customer block inside it
                 iz.reg_domain IS NOT NULL AND op.account_id IS NULL AS operator_zone
          FROM own_svc o JOIN own_ev e USING (service_id)
          LEFT JOIN own_dom od ON od.account_id = o.account_id AND od.reg_domain = e.reg_domain
          LEFT JOIN isp_zone iz ON iz.isp = o.isp AND iz.reg_domain = e.reg_domain
          LEFT JOIN is_operator op ON op.account_id = o.account_id AND op.isp = o.isp),
        per_svc AS (
          SELECT account_id, service_id,
                 bool_or(own AND NOT operator_zone AND list_contains({public}, source)
                         AND list_contains({public_ok}, outcome) AND NOT wildcard) AS named_public,
                 bool_or(own AND NOT operator_zone AND source = 'hostname'
                         AND list_contains({rdns_ok}, outcome)) AS named_rdns,
                 bool_or(source = 'hostname' AND (operator_zone OR (NOT own
                         AND regexp_matches(lower(name), {_sql_str(ACCESS_PTR_PATTERN)})))) AS subscriber
          FROM e GROUP BY 1, 2),
        certo AS (
          SELECT DISTINCT o.account_id, o.service_id FROM own_svc o JOIN own_certo c USING (service_id)
          JOIN own_co x ON x.account_id = o.account_id AND x.o = c.cert_subject_o),
        third AS (
          SELECT account_id, count(DISTINCT reg_domain) AS n FROM e
          WHERE list_contains({public}, source) AND outcome = 'accepted' AND NOT own GROUP BY 1)
        SELECT o.account_id, count(*) AS ownership_services,
               count_if(coalesce(p.named_public, false) OR c.service_id IS NOT NULL) AS named_public_services,
               count_if(coalesce(p.named_rdns, false)) AS named_rdns_services,
               coalesce(any_value(t.n), 0) AS third_party_domains,
               count(DISTINCT nullif(ik.k, '')) AS network_operators,
               count_if(coalesce(p.subscriber, false)) AS subscriber_rdns_services
        FROM own_svc o LEFT JOIN per_svc p USING (account_id, service_id)
        LEFT JOIN certo c USING (account_id, service_id) LEFT JOIN third t USING (account_id)
        LEFT JOIN isp_key ik ON ik.isp = o.isp
        GROUP BY o.account_id""").to_arrow_table().to_pylist()
    for name in ("own_dom", "isp_zone", "own_co", "is_operator", "isp_key"):
        con.unregister(name)
    return {r.pop("account_id"): r for r in rows}


def build_accounts(signal_hits_parquet: str | Path, service_attribution_parquet: str | Path,
                   out_dir: str | Path, memory_limit: str = "4GB", threads: int = 4,
                   temp_directory: str | Path | None = None,
                   attribution_evidence_parquet: str | Path | None = None,
                   services_parquet: str | Path | None = None) -> dict[str, Any]:
    """Write accounts, account_signals and account_evidence for one snapshot.

    `attribution_evidence_parquet` (attribution `evidence.parquet`) and `services_parquet` supply the
    names on each service's record used for ownership confidence. Without them, no record can name
    an org account, so its ownership is registry-only (low).
    """
    started = time.perf_counter()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    hits = f"read_parquet({_sql_str(signal_hits_parquet)}, hive_partitioning = false)"
    attrs = f"read_parquet({_sql_str(service_attribution_parquet)}, hive_partitioning = false)"
    weight = _case("h.signal_id", RELEVANCE, 0.0)
    quality = _case("match_basis", BASIS_QUALITY, 0.5)
    security = "[" + ", ".join(_sql_str(x) for x in sorted(SECURITY_SIGNALS)) + "]"
    tmp = {name: out / f".{name}.parquet.tmp" for name in ("accounts", "account_signals", "account_evidence")}

    with duckdb.connect() as con:
        con.execute(f"SET memory_limit = {_sql_str(memory_limit)}")
        con.execute(f"SET threads = {int(threads)}")
        con.execute("SET preserve_insertion_order = false")
        if temp_directory is not None:
            con.execute(f"SET temp_directory = {_sql_str(temp_directory)}")
        con.execute(f"""
            CREATE TEMP TABLE joined AS
            SELECT h.*, {weight} AS relevance, a.tier, a.account_id, a.account_name,
                   a.confidence AS attribution_confidence, a.reasons AS attribution_reasons,
                   a.attribution_version, a.candidate_domains AS attribution_domains, a.allows_infra_signals
            FROM {hits} h JOIN {attrs} a USING (snapshot_id, service_id)
            WHERE a.account_id IS NOT NULL AND a.tier IN ('A1', 'A2', 'P', 'B')""")
        n_joined, n_blocked = con.execute(
            "SELECT count(*), count_if(family = 'exposure' AND NOT coalesce(allows_infra_signals, false)) FROM joined"
        ).fetchone()
        con.execute(f"""
            CREATE TEMP TABLE ev AS
            WITH allowed AS (
              SELECT * FROM joined WHERE family <> 'exposure' OR coalesce(allows_infra_signals, false)),
            ranked AS (
              SELECT *,
                row_number() OVER (PARTITION BY service_id, family = 'exposure'
                                   ORDER BY relevance DESC, signal_id) AS exposure_rank,
                first_value(signal_id) OVER (PARTITION BY service_id, family = 'exposure'
                                             ORDER BY relevance DESC, signal_id) AS top_exposure,
                bool_or(signal_id = 'S01') OVER (PARTITION BY service_id) AS service_has_s01
              FROM allowed)
            SELECT * EXCLUDE (exposure_rank, top_exposure, service_has_s01),
              CASE WHEN family = 'exposure' AND exposure_rank > 1 THEN top_exposure
                   WHEN signal_id = 'S16' AND list_sort(sub_flags) = ['appliance'] AND service_has_s01 THEN 'S01'
              END AS suppressed_by,
              {quality} AS basis_quality
            FROM ranked""")
        con.execute("ALTER TABLE ev ADD COLUMN counted BOOLEAN")
        con.execute("UPDATE ev SET counted = suppressed_by IS NULL")

        con.execute(f"""COPY (
            SELECT account_id, signal_id, signal_version, family, snapshot_id, service_id, observation_id,
                   ip, port, transport, sni, observed_at, is_cdn, country_code,
                   product, version, http_title, module, match_basis, detail, sub_flags, evidence_json,
                   tier, attribution_confidence, attribution_reasons, counted, suppressed_by,
                   attribution_version, attribution_domains,
                   file_id, byte_offset, byte_length, record_sha256
            FROM ev ORDER BY account_id, signal_id, service_id
          ) TO {_sql_str(tmp['account_evidence'])} (FORMAT parquet, COMPRESSION zstd)""")
        con.execute(f"""
            CREATE TEMP TABLE sig AS
            SELECT account_id, signal_id, any_value(family) AS family,
                   count(DISTINCT service_id) AS n_services, count(DISTINCT ip) AS n_ips,
                   count(DISTINCT service_id) FILTER (WHERE counted) AS n_counted_services,
                   list_sort(list_distinct(list(detail) FILTER (WHERE detail IS NOT NULL))) AS details,
                   list_sort(list_distinct(flatten(list(sub_flags)))) AS sub_flags,
                   max(attribution_confidence) AS max_attribution_confidence,
                   CASE WHEN count_if(counted) > 0 THEN max(relevance) ELSE 0 END AS contribution
            FROM ev GROUP BY ALL""")
        con.execute(f"COPY (SELECT * FROM sig ORDER BY account_id, signal_id) TO {_sql_str(tmp['account_signals'])} "
                    "(FORMAT parquet, COMPRESSION zstd)")
        con.execute("""
            CREATE TEMP TABLE acc_names AS
            SELECT account_id, account_name
            FROM (SELECT account_id, account_name, count(*) AS n FROM ev GROUP BY account_id, account_name)
            QUALIFY row_number() OVER (PARTITION BY account_id ORDER BY n DESC, account_name) = 1""")
        features = _ownership_features(con, attrs, attribution_evidence_parquet, services_parquet)
        acc_rows = con.sql(f"""
            WITH
            -- Confidence and quality are averaged per counted service, so a service with several
            -- signals does not outweigh a service with one.
            per_service AS (
              SELECT account_id, avg(confidence) AS mean_confidence, avg(quality) AS mean_quality
              FROM (SELECT account_id, service_id, max(attribution_confidence) AS confidence,
                           max(basis_quality) AS quality
                    FROM ev WHERE counted GROUP BY account_id, service_id)
              GROUP BY account_id)
            SELECT e.account_id, n.account_name,
                   CASE WHEN starts_with(e.account_id, 'dom:') THEN 'domain' ELSE 'org' END AS account_kind,
                   CASE WHEN starts_with(e.account_id, 'net:') THEN 'network_provider' ELSE 'enterprise' END
                     AS segment,
                   min(tier) AS best_tier,
                   count(DISTINCT service_id) AS n_services, count(DISTINCT ip) AS n_ips,
                   list_sort(list_distinct(list(signal_id))) AS signal_ids,
                   list_sort(list_distinct(list(signal_id) FILTER (WHERE counted))) AS counted_signal_ids,
                   list_sort(list_distinct(list(detail) FILTER (WHERE detail IS NOT NULL))) AS details,
                   list_sort(list_distinct(list(country_code) FILTER (WHERE country_code IS NOT NULL))) AS countries,
                   count(DISTINCT ip) FILTER (WHERE counted) AS n_counted_ips,
                   count_if(counted AND list_contains({security}, signal_id)
                            AND basis_quality >= {MIN_SECURITY_BASIS_QUALITY}) > 0 AS has_security_observation,
                   any_value(ps.mean_confidence) AS mean_confidence, any_value(ps.mean_quality) AS mean_quality
            FROM ev e JOIN acc_names n USING (account_id) JOIN per_service ps USING (account_id)
            GROUP BY e.account_id, n.account_name""").to_arrow_table().to_pylist()
        sig_rows = con.sql("SELECT * FROM sig").to_arrow_table().to_pylist()

    sigs_by_account: dict[str, list[dict[str, Any]]] = {}
    for g in sig_rows:
        sigs_by_account.setdefault(g["account_id"], []).append(g)

    empty = dict(ownership_services=0, named_public_services=0, named_rdns_services=0, third_party_domains=0,
                 network_operators=0, subscriber_rdns_services=0)
    rows = []
    for a in acc_rows:
        # Parallel avg() can differ in the last bits between runs; round before any score, band or tie.
        a["mean_confidence"] = round(a["mean_confidence"], MEAN_DECIMALS)
        a["mean_quality"] = round(a["mean_quality"], MEAN_DECIMALS)
        counted = frozenset(a["counted_signal_ids"])
        legacy = score_account(AccountInput(counted, a["n_counted_ips"], a["mean_confidence"], a["mean_quality"]))
        f = features.get(a["account_id"], empty) if a["account_kind"] == "org" else empty
        verdict: Assessment = assess(OwnershipEvidence(
            account_kind=a["account_kind"], best_tier=a["best_tier"], account_name=a["account_name"] or "",
            n_services=f["ownership_services"], named_public_services=f["named_public_services"],
            named_rdns_services=f["named_rdns_services"], third_party_domains=f["third_party_domains"],
            network_operators=f["network_operators"], subscriber_rdns_services=f["subscriber_rdns_services"],
            mean_attribution_confidence=a["mean_confidence"]))
        actionable, blockers = actionability(verdict.eligibility, verdict.ownership_confidence, verdict.review_flags,
                                             a["has_security_observation"])
        rows.append(dict(
            a, **f, legacy=legacy, has_exposure=bool(counted & EXPOSURE_SIGNALS),
            opportunity_priority=opportunity_priority(counted, a["n_counted_ips"]),
            top_signals=sorted(counted, key=lambda s: (-RELEVANCE.get(s, 0.0), s)),
            eligibility=verdict.eligibility, eligibility_reasons=list(verdict.eligibility_reasons),
            ownership_confidence=verdict.ownership_confidence, ownership_reasons=list(verdict.ownership_reasons),
            review_flags=list(verdict.review_flags), actionable=actionable, actionable_blockers=list(blockers),
            evidence_quality_band=evidence_quality_band(a["mean_quality"]),
            product_relevance=round(legacy.product_relevance, 4), signal_strength=round(legacy.signal_strength, 4),
            attribution_confidence=round(a["mean_confidence"], 4), evidence_quality=round(a["mean_quality"], 4),
        ))

    # legacy v2 rank: every account, per segment, by composite score, counted IPs, id
    next_legacy: dict[str, int] = {}
    for r in sorted(rows, key=lambda r: (r["segment"], -r["legacy"].score, -r["n_counted_ips"], r["account_id"])):
        r["legacy_rank"] = next_legacy[r["segment"]] = next_legacy.get(r["segment"], 0) + 1
    # v3 rank, percentile and band: eligible accounts only, per segment. Ties: priority, an exposure
    # signal first, more counted IPs, account id.
    next_rank: dict[str, int] = {}
    for segment in sorted({r["segment"] for r in rows}):
        pool = [r for r in rows if r["segment"] == segment and r["eligibility"] == "eligible"]
        for r, pct in zip(pool, percentile_ranks([r["opportunity_priority"] for r in pool])):
            # floored, never rounded up: "higher than 100%" of a population that includes the account is impossible
            r["priority_percentile"] = math.floor(pct * 100 + 1e-9) / 100
            r["priority_band"] = priority_band(pct, r["has_exposure"])
        for r in sorted(pool, key=lambda r: (-r["opportunity_priority"], not r["has_exposure"],
                                             -r["n_counted_ips"], r["account_id"])):
            r["rank"] = next_rank[segment] = next_rank.get(segment, 0) + 1

    out_rows = []
    for r in sorted(rows, key=lambda r: (r["segment"], r.get("rank") is None, r.get("rank") or 0,
                                         -r["opportunity_priority"], r["account_id"])):
        r.setdefault("rank", None)
        r.setdefault("priority_percentile", None)
        r.setdefault("priority_band", None)
        r["explanation"] = _explain(r, sigs_by_account.get(r["account_id"], []), r["legacy"])
        out_rows.append({k: r.get(k) for k in ACCOUNTS_SCHEMA.names if k not in
                         ("legacy_score", "legacy_scoring_version", "scoring_version", "eligibility_version")}
                        | dict(legacy_score=r["legacy"].score, legacy_scoring_version=LEGACY_SCORING_VERSION,
                               scoring_version=SCORING_VERSION, eligibility_version=ELIGIBILITY_VERSION))
    pq.write_table(pa.Table.from_pylist(out_rows, schema=ACCOUNTS_SCHEMA), tmp["accounts"], compression="zstd")
    for name, path in tmp.items():
        os.replace(path, out / f"{name}.parquet")

    def _count(key: str) -> dict[str, int]:
        c: dict[str, int] = {}
        for r in out_rows:
            if r["segment"] == "enterprise":
                c[str(r[key])] = c.get(str(r[key]), 0) + 1
        return dict(sorted(c.items()))

    result = {
        "out_dir": str(out),
        "accounts": len(out_rows),
        "accounts_by_segment": {s: sum(1 for r in out_rows if r["segment"] == s)
                                for s in sorted({r["segment"] for r in out_rows})},
        "ranked_by_segment": dict(sorted(next_rank.items())),
        "enterprise_eligibility": _count("eligibility"),
        "enterprise_ownership": _count("ownership_confidence"),
        "enterprise_actionable": _count("actionable"),
        "enterprise_band": _count("priority_band"),
        "evidence_rows_attributed": n_joined,
        "exposure_rows_blocked_by_attribution": n_blocked,
        "wall_seconds": round(time.perf_counter() - started, 2),
        "scoring_version": SCORING_VERSION,
        "eligibility_version": ELIGIBILITY_VERSION,
    }
    log("accounts.built", **{k: v for k, v in result.items() if not isinstance(v, dict)})
    return result
