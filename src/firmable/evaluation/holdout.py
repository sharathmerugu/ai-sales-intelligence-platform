"""Scoring-v3 evaluation holdout: a fresh stratified review set that excludes development cases,
and metrics computed from human labels only (docs/evaluation.md, "Scoring-v3 holdout").

Three parts:

- **Development-case registry** (`load_dev_registry`): every account already looked at while the
  scoring-v3 rules were developed (earlier review sets, legacy top 100, the actionable top 400 used
  for the provider flag, exclusions and registry labels, inspect worksheets, the ranking-compare
  detail, the provider-flag spot-check, ids named in docs, and optional `SNAPSHOT-dev-*.json` files).
  Accounts match by id, or by normalized name when an attribution rebuild changed the id.
- **Holdout selection** (`select_holdout`): deterministic strata over the current scoring-v3 tables.
  Random strata draw only non-development accounts, except `rank_41_200`, whose whole frame was
  development data; it is filled from development accounts, each marked `dev_case=yes`.
- **Metrics** (`holdout_metrics`): from `manual_*` labels only. Blank = unlabeled and excluded from
  every denominator; `unclear` = labeled negative. Every rate carries numerator, denominator,
  unlabeled count and a Wilson 95% interval, for all cases, held-out cases and development cases.

The CSV holds real names, domains and IPs, so it lives under ~/firmable-work/eval, out of Git. It
carries no model or heuristic judgement (no `suggested_*` columns, no `inspect-accounts` verdict)
and never an NTLM value.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import random
import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote

import duckdb
import pyarrow as pa

from ..accounts.eligibility import is_registry_label
from ..attribution.providers import norm_org
from ..attribution.text import fold_name
from .review import LABEL_COLUMNS, LABEL_VALUES

HOLDOUT_SEED = 20261112
EXPOSURE_SIGNALS = frozenset({"S01", "S03", "S04", "S05"})
SECURITY_SIGNALS = EXPOSURE_SIGNALS | {"S06"}
LEGACY_TOP_K = 100            # the scoring-v2 enterprise top 100 (eligibility-rule development)
V3_ACTIONABLE_TOP_K = 400     # the actionable top 400 (provider-flag development)
TOP_K = 40                    # top_enterprise: Precision@20/40
PRECISION_KS = (20, 40)
SAMPLES_PER_CASE = 3          # observations / services referenced per case
PUBLIC_NAME_SOURCES = ("cert_cn", "cert_san", "sni", "http_host")
NAMING_OUTCOMES = ("accepted", "infra_domain", "ptr_like")
MIN_NAME_MATCH = 4            # shorter normalized names never match by name alone ("ibm", "abc")


@dataclass(frozen=True)
class Stratum:
    name: str
    size: int
    mode: str          # "take" (frame order, development cases allowed), "non_dev", "non_dev_then_dev"
    frame: str         # what the sampling frame is


STRATA: tuple[Stratum, ...] = (
    Stratum("top_enterprise", TOP_K, "take", "actionable enterprise outreach positions 1-40"),
    Stratum("rank_41_200", 25, "non_dev_then_dev", "actionable enterprise outreach positions 41-200"),
    Stratum("rank_401_2000", 15, "non_dev", "actionable enterprise outreach positions 401-2000"),
    Stratum("random_eligible", 25, "non_dev", "eligible enterprise accounts, any rank"),
    Stratum("network_provider/top5", 5, "take", "network-provider ranks 1-5"),
    Stratum("network_provider/random", 10, "non_dev", "network-provider ranks 6+"),
    Stratum("low_confidence_review/ownership_low", 10, "non_dev",
            "eligible enterprise, not actionable, ownership low, no review flag"),
    Stratum("low_confidence_review/review_flag", 10, "non_dev",
            "eligible enterprise, not actionable, at least one review flag"),
    Stratum("technographic_only", 15, "non_dev", "eligible enterprise, S16 and no S01/S03/S04/S05/S06 signal"),
)

ID_COLUMNS = ("case_id", "strata", "dev_case", "dev_sources", "account_id", "account_ref", "account_name",
              "segment", "best_tier", "account_kind")
SYSTEM_COLUMNS = (
    "system_rank", "system_outreach_position", "system_priority_percentile", "system_priority_band",
    "system_opportunity_priority", "system_ownership_confidence", "system_ownership_reasons",
    "system_evidence_quality_band", "system_eligibility", "system_eligibility_reasons", "system_actionable",
    "system_actionable_blockers", "system_review_flags", "system_legacy_rank", "system_legacy_score",
)
SIGNAL_COLUMNS = ("signal_ids", "signal_services", "details", "countries", "n_services", "n_ips")
OWNERSHIP_COLUMNS = (
    "ownership_services", "named_public_services", "named_rdns_services", "third_party_domains",
    "network_operators", "subscriber_rdns_services", "sample_naming_domains", "sample_third_party_domains",
    "org", "isp", "asn", "openasn_category", "attribution_reasons",
)
SOURCE_COLUMNS = ("sample_observation_ids", "sample_service_ids", "sample_services", "app_path",
                  "evidence_command", "inspect_command")
MANUAL_COLUMNS = tuple(f"manual_{c}" for c in LABEL_COLUMNS) + ("manual_reviewer", "manual_notes")
CSV_COLUMNS = ID_COLUMNS + SYSTEM_COLUMNS + SIGNAL_COLUMNS + OWNERSHIP_COLUMNS + SOURCE_COLUMNS + MANUAL_COLUMNS
# The blind variant hides what the system decided (segment, strata, development status, rank, band,
# ownership, eligibility, flags, tier, attribution rules) so the reviewer judges the evidence, not the
# system's verdict. The account id (its org:/dom:/net: prefix is the segment and tier) and every
# reference that embeds it (app path, inspect command) are replaced by `account_ref`, a seeded hash.
BLIND_HIDDEN = frozenset({"strata", "dev_case", "dev_sources", "segment", "account_id", "best_tier", "account_kind",
                          "attribution_reasons", "app_path", "inspect_command", *SYSTEM_COLUMNS})
BLIND_COLUMNS = tuple(c for c in CSV_COLUMNS if c not in BLIND_HIDDEN)


# ----------------------------------------------------------------------------- dev registry
def _punct_to_space(s: str) -> str:
    """Punctuation, symbols, separators and controls as spaces; letters, digits and combining marks kept."""
    return "".join(" " if unicodedata.category(c)[0] in "PSZC" else c for c in s)


def norm_name(name: str | None) -> str:
    """`fold_name` (the attribution fold), punctuation as space, then `norm_org` (legal suffixes)."""
    return " ".join(norm_org(_punct_to_space(fold_name(name))).split())


def _id_name(account_id: str) -> str:
    return account_id.split(":", 1)[1] if ":" in account_id else account_id


@dataclass
class DevRegistry:
    """Development cases by account id and by normalized name, each with the sources that saw it."""

    ids: dict[str, set[str]] = field(default_factory=dict)
    names: dict[str, set[str]] = field(default_factory=dict)
    inputs: list[dict[str, Any]] = field(default_factory=list)

    def add(self, source: str, account_id: str | None = None, name: str | None = None) -> None:
        if account_id:
            self.ids.setdefault(account_id, set()).add(source)
            n = norm_name(_id_name(account_id))
            if n:
                self.names.setdefault(n, set()).add(source)
        n = norm_name(name)
        if n:
            self.names.setdefault(n, set()).add(source)

    def match(self, account_id: str, name: str | None) -> tuple[str, ...]:
        """Sources that saw this account: by id, then (suffixed `@name`) by normalized name only.
        Names shorter than MIN_NAME_MATCH never match by name."""
        by_id = self.ids.get(account_id, set())
        by_name: set[str] = set()
        for n in {norm_name(name), norm_name(_id_name(account_id))}:
            if len(n) >= MIN_NAME_MATCH:
                by_name |= self.names.get(n, set())
        return tuple(sorted(by_id)) + tuple(sorted(f"{s}@name" for s in by_name - by_id))

    def counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for ids_or_names, key in ((self.ids, "ids"), (self.names, "names")):
            for srcs in ids_or_names.values():
                for s in srcs:
                    out.setdefault(s, {"ids": 0, "names": 0})[key] += 1
        return dict(sorted(out.items()))


@dataclass
class DevInputs:
    review_csvs: list[Path] = field(default_factory=list)       # earlier review sets (suggested_* were seen)
    legacy_dirs: list[Path] = field(default_factory=list)       # scoring-v2 accounts dirs
    v3_dirs: list[Path] = field(default_factory=list)           # scoring-v3 accounts dirs (any attribution)
    inspect_jsons: list[Path] = field(default_factory=list)     # inspect-accounts worksheets
    compare_details: list[Path] = field(default_factory=list)   # compare-rankings -detail files
    dev_files: list[Path] = field(default_factory=list)         # SNAPSHOT-dev-*.json (optional, may appear later)
    doc_paths: list[Path] = field(default_factory=list)         # docs scanned for account ids


def _pq(p: str | Path) -> str:
    return "read_parquet('" + str(p).replace("'", "''") + "', hive_partitioning = false)"


DOC_ID = re.compile(r"(?<![\w/])((?:org|dom|net):[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])")


def load_dev_registry(inputs: DevInputs) -> DevRegistry:
    reg = DevRegistry()

    def note(source: str, path: Path, present: bool, rows: int = 0) -> None:
        reg.inputs.append({"source": source, "path": str(path), "present": present, "rows": rows})

    for p in inputs.review_csvs:
        if not Path(p).exists():
            note("review_set", p, False)
            continue
        with Path(p).open(newline="") as f:
            rows = [r for r in csv.DictReader(f) if (r.get("account_id") or "").strip()]
        for r in rows:
            reg.add("review_set", r["account_id"], r.get("account_name"))
        note("review_set", p, True, len(rows))

    con = duckdb.connect()
    try:
        for d in inputs.legacy_dirs:
            acc = Path(d) / "accounts.parquet"
            if not acc.exists():
                note("legacy_top100", acc, False)
                continue
            cols = {c for (c,) in con.execute("SELECT name FROM parquet_schema(?)", [str(acc)]).fetchall()}
            seg = "segment = 'enterprise' AND" if "segment" in cols else ""
            rows = con.execute(f"SELECT account_id, account_name FROM {_pq(acc)} WHERE {seg} rank <= ? "
                               "ORDER BY rank", [LEGACY_TOP_K]).fetchall()
            for aid, name in rows:
                reg.add("legacy_top100", aid, name)
            note("legacy_top100", acc, True, len(rows))
        for d in inputs.v3_dirs:
            acc = Path(d) / "accounts.parquet"
            if not acc.exists():
                note("v3_tables", acc, False)
                continue
            rows = con.execute(f"""SELECT account_id, account_name, segment, rank, eligibility, actionable,
                                          list_contains(review_flags, 'possible_network_provider')
                                   FROM {_pq(acc)} ORDER BY account_id""").fetchall()
            top = sorted((r for r in rows if r[2] == "enterprise" and r[5]), key=lambda r: (r[3], r[0]))
            for aid, name, *_ in top[:V3_ACTIONABLE_TOP_K]:
                reg.add("v3_actionable_top400", aid, name)
            for aid, name, _seg, _rank, elig, _act, pnp in rows:
                if elig == "excluded":
                    reg.add("v3_excluded", aid, name)
                if is_registry_label(name):
                    reg.add("registry_label_name", aid, name)
                if pnp:
                    # docs/ranking-v3.md §4 spot-check: not reproducible from the rebuilt tables, so
                    # every flagged account counts as seen (the recovered names come as a dev file).
                    reg.add("provider_flag_all", aid, name)
            note("v3_tables", acc, True, len(rows))
    finally:
        con.close()

    for p in inputs.inspect_jsons:
        if not Path(p).exists():
            note("inspect_worksheet", p, False)
            continue
        reports = json.loads(Path(p).read_text())
        for r in reports:
            reg.add("inspect_worksheet", r.get("account_id"), r.get("account_name"))
        note("inspect_worksheet", p, True, len(reports))

    for p in inputs.compare_details:
        if not Path(p).exists():
            note("ranking_compare_detail", p, False)
            continue
        detail = json.loads(Path(p).read_text())
        n = 0
        for items in detail.values():
            for it in items:
                aid = it.get("account_id") if isinstance(it, dict) else it
                if isinstance(aid, str):
                    reg.add("ranking_compare_detail", aid)
                    n += 1
        note("ranking_compare_detail", p, True, n)

    for p in inputs.doc_paths:
        if not Path(p).exists():
            note("doc_reference", p, False)
            continue
        ids = sorted(set(DOC_ID.findall(Path(p).read_text(errors="replace"))))
        for aid in ids:
            reg.add("doc_reference", aid)
        if ids:
            note("doc_reference", p, True, len(ids))

    for p in inputs.dev_files:
        p = Path(p)
        default_source = "dev_file:" + p.stem.split("-dev-", 1)[-1]
        if not p.exists():
            note(default_source, p, False)
            continue
        data = json.loads(p.read_text())
        source = data.get("source") or default_source
        ids, names = data.get("account_ids") or [], (data.get("orgs") or []) + (data.get("names") or [])
        for aid in ids:
            reg.add(source, aid)
        for name in names:
            reg.add(source, None, name)
        note(source, p, True, len(ids) + len(names))
    return reg


def with_attribution_version(path: Path, version: int) -> Path:
    """`path` (from `accounts_dir` / `attribution_dir`) with its `attribution=vN` component replaced."""
    parts = Path(path).parts
    if not any(p.startswith("attribution=v") for p in parts):
        raise ValueError(f"{path} has no attribution=vN component")
    return Path(*[f"attribution=v{version}" if p.startswith("attribution=v") else p for p in parts])


def discover_dev_inputs(lake: Path, eval_dir: Path, snapshot: str, docs_dir: Path | None,
                        scoring_version: int, legacy_scoring_version: int) -> DevInputs:
    """Every development input that exists for `snapshot`. Lake paths follow the scoring version tags;
    every attribution and normalizer version of a scoring build counts (conservative). An absent
    `docs_dir` is kept as an input so the registry records it as missing."""
    def builds(scoring: int) -> list[Path]:
        root = Path(lake) / "accounts" / f"scoring=v{scoring}"
        return sorted(p.parent for p in root.glob(f"attribution=v*/normalizer=v*/snapshot={snapshot}/accounts.parquet"))

    ev = Path(eval_dir)
    docs: list[Path] = []
    if docs_dir is not None:
        docs = (sorted(p for p in Path(docs_dir).rglob("*") if p.suffix in (".md", ".txt", ".sql", ".py"))
                if Path(docs_dir).is_dir() else [Path(docs_dir)])
    return DevInputs(
        review_csvs=sorted(ev.glob(f"{snapshot}-review*.csv")),
        legacy_dirs=builds(legacy_scoring_version),
        v3_dirs=builds(scoring_version),
        inspect_jsons=sorted(ev.glob(f"{snapshot}-inspect-*.json")),
        compare_details=sorted(ev.glob(f"{snapshot}-ranking-compare-detail*.json")),
        dev_files=sorted(ev.glob(f"{snapshot}-dev-*.json")),
        doc_paths=docs,
    )


# ----------------------------------------------------------------------------- selection
FRAME_COLUMNS = ("account_id", "account_name", "segment", "rank", "eligibility", "actionable",
                 "ownership_confidence", "review_flags", "signal_ids")


def frames(rows: list[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Sampling frame per stratum (account ids in frame order) and the outreach position of each
    actionable enterprise account (its position in the list a seller sees)."""
    ent = [r for r in rows if r["segment"] == "enterprise"]
    outreach = sorted((r for r in ent if r["actionable"]), key=lambda r: (r["rank"], r["account_id"]))
    pos = {r["account_id"]: i + 1 for i, r in enumerate(outreach)}
    eligible = sorted((r for r in ent if r["eligibility"] == "eligible"), key=lambda r: r["account_id"])
    review = [r for r in eligible if not r["actionable"]]
    provider = sorted((r for r in rows if r["segment"] == "network_provider" and r["eligibility"] == "eligible"
                       and r["rank"] is not None), key=lambda r: (r["rank"], r["account_id"]))
    by_pos = [r["account_id"] for r in outreach]
    out = {
        "top_enterprise": by_pos[:TOP_K],
        "rank_41_200": by_pos[40:200],
        "rank_401_2000": by_pos[400:2000],
        "random_eligible": [r["account_id"] for r in eligible],
        "network_provider/top5": [r["account_id"] for r in provider[:5]],
        "network_provider/random": [r["account_id"] for r in provider[5:]],
        "low_confidence_review/ownership_low": [r["account_id"] for r in review
                                                if r["ownership_confidence"] == "low" and not r["review_flags"]],
        "low_confidence_review/review_flag": [r["account_id"] for r in review if r["review_flags"]],
        "technographic_only": [r["account_id"] for r in eligible
                               if "S16" in (r["signal_ids"] or ()) and not set(r["signal_ids"]) & SECURITY_SIGNALS],
    }
    return out, pos


def select_holdout(rows: list[dict[str, Any]], is_dev: Callable[[str], bool], seed: int = HOLDOUT_SEED,
                   strata: Iterable[Stratum] = STRATA) -> tuple[list[tuple[str, list[str]]], dict[str, Any], dict[str, int]]:
    """Return (cases in review order as (account_id, strata), per-stratum summary, outreach positions).

    Deterministic for `seed`: each stratum draws with its own `Random(f"{seed}:{name}")` from its
    frame sorted by account id; the review order is a seeded shuffle, so ranks are not grouped.
    """
    fr, pos = frames(rows)
    chosen: dict[str, list[str]] = {}
    summary: dict[str, Any] = {}
    for s in strata:
        frame = fr[s.name]
        pool = sorted(a for a in frame if not is_dev(a))
        if s.mode == "take":
            drawn = frame[: s.size]
        else:
            rng = random.Random(f"{seed}:{s.name}")
            drawn = rng.sample(pool, min(s.size, len(pool)))
            if s.mode == "non_dev_then_dev" and len(drawn) < s.size:
                dev_pool = sorted(a for a in frame if is_dev(a))
                fill = random.Random(f"{seed}:{s.name}:dev_fill")
                drawn += fill.sample(dev_pool, min(s.size - len(drawn), len(dev_pool)))
            drawn = sorted(drawn)
        chosen[s.name] = drawn
        summary[s.name] = {"frame": s.frame, "mode": s.mode, "target": s.size, "frame_n": len(frame),
                           "frame_non_dev_n": len(pool), "drawn": len(drawn),
                           "drawn_dev": sum(1 for a in drawn if is_dev(a))}
    by_account: dict[str, list[str]] = {}
    for name, ids in chosen.items():
        for a in ids:
            by_account.setdefault(a, []).append(name)
    order = sorted(by_account)
    random.Random(f"{seed}:order").shuffle(order)
    return [(a, by_account[a]) for a in order], summary, pos


# ----------------------------------------------------------------------------- case context
def _join(xs: Iterable[Any] | None, n: int = 8) -> str:
    xs = [str(x) for x in (xs or []) if x is not None and str(x) != ""]
    return "|".join(xs[:n]) + ("|..." if len(xs) > n else "")


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return _join(v, 12)
    return str(v)


def _case_context(con: duckdb.DuckDBPyConnection, accounts_dir: Path, attribution_dir: Path, services: Path,
                  asn_table: Mapping[int, Any], ids: list[str]) -> dict[str, dict[str, Any]]:
    from ..attribution.providers import ownership_names_org

    con.register("sel", pa.table({"account_id": pa.array(sorted(ids), pa.string())}))
    con.register("oa", pa.table({"asn_n": pa.array(sorted(asn_table), pa.int64()),
                                 "category": pa.array([asn_table[k].category for k in sorted(asn_table)],
                                                      pa.string())}))
    acc = Path(accounts_dir)
    att = Path(attribution_dir)

    def rows(sql: str) -> list[dict[str, Any]]:
        cur = con.execute(sql)
        names = [d[0] for d in cur.description]
        return [dict(zip(names, r)) for r in cur.fetchall()]

    ctx = {r["account_id"]: r for r in rows(f"SELECT a.* FROM {_pq(acc / 'accounts.parquet')} a SEMI JOIN sel USING (account_id)")}
    for r in rows(f"""SELECT account_id, string_agg(signal_id || ' svc=' || n_services || ' counted=' || n_counted_services
                                                     || ' ips=' || n_ips, '|' ORDER BY signal_id) AS signal_services
                      FROM {_pq(acc / 'account_signals.parquet')} SEMI JOIN sel USING (account_id) GROUP BY 1"""):
        ctx[r["account_id"]]["signal_services"] = r["signal_services"]

    con.execute(f"""CREATE OR REPLACE TEMP TABLE hs AS
        SELECT a.service_id, a.account_id, a.org, a.isp, a.reasons, v.asn,
               try_cast(replace(upper(v.asn), 'AS', '') AS BIGINT) AS asn_n
        FROM {_pq(att / 'service_attribution.parquet')} a SEMI JOIN sel USING (account_id)
        LEFT JOIN (SELECT service_id, asn FROM {_pq(services)}) v USING (service_id)""")

    def mode_of(col: str, key: str, src: str = "hs") -> None:
        for r in rows(f"""SELECT account_id, {col} AS v FROM (
                            SELECT account_id, {col}, count(*) AS n FROM {src} WHERE {col} IS NOT NULL GROUP BY ALL)
                          QUALIFY row_number() OVER (PARTITION BY account_id ORDER BY n DESC, {col}) = 1"""):
            ctx[r["account_id"]][key] = r["v"]

    mode_of("org", "org")
    mode_of("isp", "isp")
    mode_of("asn", "asn")
    con.execute("CREATE OR REPLACE TEMP TABLE hs_cat AS SELECT hs.account_id, oa.category FROM hs JOIN oa USING (asn_n)")
    mode_of("category", "openasn_category", "hs_cat")
    for r in rows("""SELECT account_id, list_sort(list_distinct(flatten(list(reasons)))) AS reasons
                     FROM hs GROUP BY 1"""):
        ctx[r["account_id"]]["attribution_reasons"] = r["reasons"]

    # Names on the services' records (never NTLM, ADR 0007): which name the account, which name others.
    con.execute(f"""CREATE OR REPLACE TEMP TABLE hn AS
        SELECT hs.account_id, e.service_id, e.source, e.reg_domain, e.outcome
        FROM {_pq(att / 'evidence.parquet')} e JOIN hs USING (service_id)
        WHERE e.reg_domain IS NOT NULL AND e.source <> 'ntlm'""")
    pairs = con.execute("SELECT DISTINCT account_id, reg_domain FROM hn ORDER BY 1, 2").fetchall()
    own = [(a, d) for a, d in pairs
           if (d == _id_name(a) if a.startswith("dom:") else ownership_names_org(d, ctx[a].get("account_name") or ""))]
    con.register("own_pairs", pa.table({"account_id": pa.array([a for a, _ in own], pa.string()),
                                        "reg_domain": pa.array([d for _, d in own], pa.string())}))
    public = "[" + ", ".join(f"'{s}'" for s in PUBLIC_NAME_SOURCES) + "]"
    naming_ok = "[" + ", ".join(f"'{s}'" for s in NAMING_OUTCOMES) + "]"
    naming: dict[str, dict[str, int]] = {}
    third: dict[str, dict[str, int]] = {}
    for r in rows(f"""SELECT hn.account_id, hn.reg_domain, o.account_id IS NOT NULL AS names_it,
                             count(DISTINCT hn.service_id) AS n
                      FROM hn LEFT JOIN own_pairs o USING (account_id, reg_domain)
                      WHERE (o.account_id IS NOT NULL AND list_contains({naming_ok}, hn.outcome))
                         OR (o.account_id IS NULL AND list_contains({public}, hn.source) AND hn.outcome = 'accepted')
                      GROUP BY ALL"""):
        (naming if r["names_it"] else third).setdefault(r["account_id"], {})[r["reg_domain"]] = r["n"]
    con.unregister("own_pairs")

    def top(d: dict[str, int], n: int = 5) -> str:
        return _join([f"{k}({v})" for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))], n)

    for a in ctx:
        ctx[a]["sample_naming_domains"] = top(naming.get(a, {}))
        ctx[a]["sample_third_party_domains"] = top(third.get(a, {}))

    # Source references: one row per service, counted first, exposures first.
    samples = rows(f"""WITH per_svc AS (
          SELECT account_id, service_id, observation_id, ip, port, sni, counted, family, signal_id
          FROM {_pq(acc / 'account_evidence.parquet')} SEMI JOIN sel USING (account_id)
          QUALIFY row_number() OVER (PARTITION BY account_id, service_id
                                     ORDER BY counted DESC, family = 'exposure' DESC, signal_id, observation_id) = 1)
        SELECT * FROM per_svc
        QUALIFY row_number() OVER (PARTITION BY account_id
                                   ORDER BY counted DESC, family = 'exposure' DESC, signal_id, service_id) <= {SAMPLES_PER_CASE}
        ORDER BY account_id, counted DESC, family = 'exposure' DESC, signal_id, service_id""")
    for r in samples:
        c = ctx[r["account_id"]]
        c.setdefault("_obs", []).append(r["observation_id"])
        c.setdefault("_svc", []).append(r["service_id"])
        c.setdefault("_where", []).append(f"{r['ip']}:{r['port']}" + (f" sni={r['sni']}" if r["sni"] else "")
                                          + f" {r['signal_id']}")
    for name in ("sel", "oa"):
        con.unregister(name)
    return ctx


def account_ref(seed: int, account_id: str) -> str:
    """Non-revealing, seeded reference for an account (the blind file's cross-check with the full one)."""
    return "A" + hashlib.sha256(f"{seed}:{account_id}".encode()).hexdigest()[:12]


def _case_row(case_id: str, aid: str, strata: list[str], dev_sources: tuple[str, ...], c: dict[str, Any],
              pos: dict[str, int], snapshot: str, seed: int) -> dict[str, str]:
    obs = c.get("_obs", [])
    seg = c.get("segment") or "enterprise"
    row = {
        "case_id": case_id, "strata": ";".join(strata), "dev_case": "yes" if dev_sources else "no",
        "dev_sources": ";".join(dev_sources), "account_id": aid, "account_ref": account_ref(seed, aid),
        "account_name": c.get("account_name"),
        "segment": seg, "best_tier": c.get("best_tier"), "account_kind": c.get("account_kind"),
        "system_rank": c.get("rank"), "system_outreach_position": pos.get(aid),
        "system_priority_percentile": c.get("priority_percentile"), "system_priority_band": c.get("priority_band"),
        "system_opportunity_priority": c.get("opportunity_priority"),
        "system_ownership_confidence": c.get("ownership_confidence"),
        "system_ownership_reasons": c.get("ownership_reasons"),
        "system_evidence_quality_band": c.get("evidence_quality_band"), "system_eligibility": c.get("eligibility"),
        "system_eligibility_reasons": c.get("eligibility_reasons"), "system_actionable": c.get("actionable"),
        "system_actionable_blockers": c.get("actionable_blockers"), "system_review_flags": c.get("review_flags"),
        "system_legacy_rank": c.get("legacy_rank"), "system_legacy_score": c.get("legacy_score"),
        "signal_ids": c.get("signal_ids"), "signal_services": c.get("signal_services"),
        "details": _join(c.get("details"), 8), "countries": c.get("countries"),
        "n_services": c.get("n_services"), "n_ips": c.get("n_ips"),
        **{k: c.get(k) for k in OWNERSHIP_COLUMNS},
        "attribution_reasons": _join(c.get("attribution_reasons"), 12),
        "sample_observation_ids": _join(obs), "sample_service_ids": _join(c.get("_svc", [])),
        "sample_services": _join(c.get("_where", [])),
        "app_path": "/accounts/" + quote(aid, safe=":"),
        "evidence_command": f"uv run firmable evidence {obs[0]}" if obs else "",
        "inspect_command": (f"uv run firmable inspect-accounts {snapshot} --segment {seg} --account {shlex.quote(aid)}"
                            f" --out ~/firmable-work/eval/holdout-inspect/{case_id}"),
    }
    return {k: _cell(row.get(k)) for k in CSV_COLUMNS}


FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def escape_cell(v: str) -> str:
    """Prefix `'` to a cell a spreadsheet would read as a formula (CSV injection)."""
    return "'" + v if v.startswith(FORMULA_START) else v


def _csv_bytes(rows: list[dict[str, str]], columns: tuple[str, ...]) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=columns, lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: escape_cell(r.get(c, "")) for c in columns})
    return buf.getvalue().encode()


def _git_root(path: Path) -> Path | None:
    for d in Path(path).expanduser().resolve().parents:
        if (d / ".git").exists():
            return d
    return None


def companion_paths(out_csv: Path) -> dict[str, Path]:
    out_csv = Path(out_csv)
    stem = out_csv.with_suffix("")
    return {"blind": Path(f"{stem}.blind.csv"), "registry": Path(f"{stem}.dev-registry.json"),
            "manifest": Path(f"{stem}.manifest.json")}


def build_holdout(accounts_dir: Path, attribution_dir: Path, services: Path, asn_table: Mapping[int, Any],
                  dev_inputs: DevInputs, out_csv: Path, snapshot: str, seed: int = HOLDOUT_SEED,
                  overwrite: bool = False, blind: bool = True, versions: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write the holdout CSV (+ blind variant, dev registry, manifest); return the manifest.

    Refuses to overwrite an existing CSV or blind CSV (they may hold manual labels) unless `overwrite`,
    even when no blind file is requested: a stale blind file must never sit beside new cases. With
    `overwrite` and no blind output, a stale blind file is removed. Refuses an `out_csv` inside a Git
    repository (the CSV holds real names, domains and IPs).
    """
    out_csv = Path(out_csv)
    repo = _git_root(out_csv)
    if repo is not None:
        raise ValueError(f"{out_csv} is inside the Git repository {repo}; write holdout files under ~/firmable-work/eval")
    side = companion_paths(out_csv)
    for p in (out_csv, side["blind"]):
        if p.exists() and not overwrite:
            raise FileExistsError(f"{p} exists and may hold manual labels; pass overwrite to replace it")
    acc = Path(accounts_dir) / "accounts.parquet"
    if not acc.exists():
        raise FileNotFoundError(f"{acc} not found: build the scoring-v3 accounts first (build-phase3)")

    reg = load_dev_registry(dev_inputs)
    con = duckdb.connect()
    try:
        con.execute("SET memory_limit = '4GB'")
        frame_rows = [dict(zip(FRAME_COLUMNS, r)) for r in con.execute(
            f"SELECT {', '.join(FRAME_COLUMNS)} FROM {_pq(acc)} ORDER BY account_id").fetchall()]
        names = {r["account_id"]: r["account_name"] for r in frame_rows}
        dev_cache: dict[str, tuple[str, ...]] = {}

        def dev_sources(aid: str) -> tuple[str, ...]:
            if aid not in dev_cache:
                dev_cache[aid] = reg.match(aid, names.get(aid))
            return dev_cache[aid]

        cases, summary, pos = select_holdout(frame_rows, lambda a: bool(dev_sources(a)), seed)
        ctx = _case_context(con, Path(accounts_dir), Path(attribution_dir), Path(services), asn_table,
                            [a for a, _ in cases])
    finally:
        con.close()

    rows = [_case_row(f"H{i:03d}", aid, strata, dev_sources(aid), ctx[aid], pos, snapshot, seed)
            for i, (aid, strata) in enumerate(cases, start=1)]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    data = _csv_bytes(rows, CSV_COLUMNS)
    out_csv.write_bytes(data)
    if blind:
        side["blind"].write_bytes(_csv_bytes(rows, BLIND_COLUMNS))
    else:
        side["blind"].unlink(missing_ok=True)

    # Frame-wide development counts: how many accounts of the current build each source marks.
    frame_dev: dict[str, int] = {}
    for r in frame_rows:
        for s in dev_sources(r["account_id"]):
            frame_dev[s] = frame_dev.get(s, 0) + 1
    registry = {
        "snapshot": snapshot, "inputs": reg.inputs, "counts_by_source": reg.counts(),
        "current_build_accounts_marked_dev": sum(1 for r in frame_rows if dev_sources(r["account_id"])),
        "current_build_accounts_by_source": dict(sorted(frame_dev.items())),
        "dev_ids": {a: sorted(s) for a, s in sorted(reg.ids.items())},
        "dev_names": {n: sorted(s) for n, s in sorted(reg.names.items())},
    }
    side["registry"].write_text(json.dumps(registry, indent=1, sort_keys=True) + "\n")
    manifest = {
        "path": str(out_csv), "blind_path": str(side["blind"]) if blind else None,
        "registry_path": str(side["registry"]), "snapshot": snapshot, "seed": seed,
        "accounts_dir": str(accounts_dir), "attribution_dir": str(attribution_dir), **(versions or {}),
        "csv_sha256": hashlib.sha256(data).hexdigest(), "cases": len(rows),
        "unique_accounts": len({r["account_id"] for r in rows}),
        "stratum_memberships": sum(len(strata) for _, strata in cases),
        "dev_cases": sum(1 for r in rows if r["dev_case"] == "yes"),
        "held_out_cases": sum(1 for r in rows if r["dev_case"] == "no"),
        "strata": summary,
        "current_build_accounts": len(frame_rows),
        "current_build_accounts_marked_dev": registry["current_build_accounts_marked_dev"],
    }
    side["manifest"].write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    return manifest


# ----------------------------------------------------------------------------- metrics
Z95 = 1.959963984540054
# Guard only: a reviewer that names a model family or "AI" / "model" as a whole word.
MODEL_REVIEWER = re.compile(r"\b(claude|chatgpt|gpt(-?\w+)?|gemini|haiku|sonnet|opus|fable|llama|mistral|copilot"
                            r"|openai|anthropic|llm|ai|model)\b", re.I)


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials; None when n = 0."""
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def _lab(r: Mapping[str, Any], col: str) -> str:
    return (r.get(f"manual_{col}") or "").strip().lower()


def rate(rows: list[Mapping[str, Any]], col: str, positive: str) -> dict[str, Any]:
    labeled = [r for r in rows if _lab(r, col)]
    k = sum(1 for r in labeled if _lab(r, col) == positive)
    out: dict[str, Any] = {"num": k, "den": len(labeled), "unlabeled": len(rows) - len(labeled), "cases": len(rows)}
    if labeled:
        out.update(rate=round(k / len(labeled), 4), wilson95=list(wilson(k, len(labeled)) or ()))
    else:
        out.update(rate=None, wilson95=None, note="no labels in this subgroup")
    return out


def _split(rows: list[Mapping[str, Any]], col: str, positive: str) -> dict[str, Any]:
    return {"all": rate(rows, col, positive),
            "held_out": rate([r for r in rows if r.get("dev_case") == "no"], col, positive),
            "dev": rate([r for r in rows if r.get("dev_case") == "yes"], col, positive)}


def _strata(r: Mapping[str, Any]) -> list[str]:
    names = [s for s in (r.get("strata") or "").split(";") if s]
    return names + sorted({s.split("/", 1)[0] for s in names if "/" in s})


def _signal_group(r: Mapping[str, Any]) -> str:
    sigs = set((r.get("signal_ids") or "").replace("|...", "").split("|")) - {""}
    if sigs & EXPOSURE_SIGNALS:
        return "exposure"
    if "S06" in sigs:
        return "hygiene_no_exposure"
    return "technographic_only" if "S16" in sigs else "no_signal"


def _pos(v: Any) -> int | None:
    return int(float(v)) if v not in (None, "") else None


CLEAN_PRECISION_REASON = ("Precision@k is a census of the top k; development cases cannot be dropped from it "
                          "without changing what is measured, so no clean value exists. Use the held-out "
                          "rank_401_2000 and random strata for uncontaminated rates.")


def holdout_metrics(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Metrics from `manual_*` labels only (see module docstring)."""
    labeled = sum(1 for r in rows if any(_lab(r, c) for c in LABEL_COLUMNS))
    by = lambda pool, name: [r for r in pool if name in _strata(r)]  # noqa: E731
    strata_of = lambda pool: sorted({s for r in pool for s in _strata(r)})  # noqa: E731
    ent = [r for r in rows if r.get("segment") == "enterprise"]
    prov = [r for r in rows if r.get("segment") == "network_provider"]
    top = [r for r in rows if "top_enterprise" in _strata(r)]
    out: dict[str, Any] = {
        "source": "manual",
        "cases": len(rows), "cases_labeled": labeled,
        "held_out_cases": sum(1 for r in rows if r.get("dev_case") == "no"),
        "dev_cases": sum(1 for r in rows if r.get("dev_case") == "yes"),
        "notes": [
            "Labels: manual_* columns only. Blank = unlabeled (excluded from denominators); unclear = negative.",
            "Precision@k is a census of top_enterprise, which was read during development; it has no clean value.",
            "Intervals: Wilson 95%. Strata are not weighted to their frames; per-stratum rates describe the stratum.",
        ],
    }
    if labeled == 0:
        out["notes"].append("no labels: every denominator is 0 and no rate is reported")
    n_dev = sum(1 for r in top if r.get("dev_case") == "yes")
    pk: dict[str, Any] = {"contamination": "top_enterprise is entirely development data" if top and n_dev == len(top)
                          else f"{n_dev} of {len(top)} top_enterprise cases are development data"}
    for k in PRECISION_KS:
        topk = [r for r in top if (_pos(r.get("system_outreach_position")) or 10**9) <= k]
        pk[str(k)] = {"census": rate(topk, "qualified", "yes"),
                      "dev_cases": sum(1 for r in topk if r.get("dev_case") == "yes"),
                      "clean": None, "clean_reason": CLEAN_PRECISION_REASON}
    out["precision_at_k"] = pk
    out["attribution_correct"] = {"overall": _split(list(rows), "attribution_correct", "yes"),
                                  "by_stratum": {s: _split(by(rows, s), "attribution_correct", "yes")
                                                 for s in strata_of(rows)}}
    out["evidence_supported"] = {"overall": _split(list(rows), "evidence_supported", "yes"),
                                 "by_stratum": {s: _split(by(rows, s), "evidence_supported", "yes")
                                                for s in strata_of(rows)}}
    # Network-provider strata answer "is this a provider?", not "would a seller prospect it?".
    out["entity_type_agreement"] = {
        "by_segment": {seg: _split([r for r in rows if r.get("segment") == seg], "entity_type", seg)
                       for seg in ("enterprise", "network_provider")},
        "by_stratum": {s: _split(by(prov, s), "entity_type", "network_provider") for s in strata_of(prov)},
    }
    out["qualified"] = {
        "overall_enterprise": _split(ent, "qualified", "yes"),
        "by_stratum": {s: _split(by(ent, s), "qualified", "yes") for s in strata_of(ent)},
        "by_actionable": {k: _split([r for r in ent if r.get("system_actionable") == v], "qualified", "yes")
                          for k, v in (("actionable", "yes"), ("not_actionable", "no"))},
        "by_signal_group": {g: _split([r for r in ent if _signal_group(r) == g], "qualified", "yes")
                            for g in ("exposure", "hygiene_no_exposure", "technographic_only")},
    }
    return out


REQUIRED_COLUMNS = ("case_id", "strata", "dev_case", "account_id", "account_ref", "segment", "system_actionable",
                    "system_outreach_position", "signal_ids") + MANUAL_COLUMNS


def _check_rows(rows: list[dict[str, Any]], path: Path, full: bool) -> None:
    seen: set[str] = set()
    for r in rows:
        cid = (r.get("case_id") or "").strip()
        if not cid:
            raise ValueError(f"{path}: a row has no case_id")
        if cid in seen:
            raise ValueError(f"{path}: duplicate case_id {cid}")
        seen.add(cid)
        if full and r.get("dev_case") not in ("yes", "no"):
            raise ValueError(f"{path}: {cid}: dev_case={r.get('dev_case')!r} not in ('yes', 'no')")
        for c in LABEL_COLUMNS:
            v = _lab(r, c)
            if v and v not in LABEL_VALUES[c]:
                raise ValueError(f"{path}: {cid}: manual_{c}={v!r} not in {LABEL_VALUES[c]}")
        who = (r.get("manual_reviewer") or "").strip()
        if who and MODEL_REVIEWER.search(who):
            raise ValueError(f"{path}: {cid}: manual_reviewer={who!r} names a model; model output is never a label")


def _read(path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    try:
        with Path(path).open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            cols = list(reader.fieldnames or [])
    except UnicodeDecodeError as e:
        raise ValueError(f"{path} is not UTF-8 ({e.reason} at byte {e.start}); save it as UTF-8 CSV") from None
    suggested = [c for c in cols if c.startswith("suggested_")]
    if suggested:
        raise ValueError(f"{path} has {suggested}: the holdout takes manual labels only; "
                         "model suggestions are never a label source")
    return cols, rows


def read_holdout(path: str | Path, labels: str | Path | None = None) -> list[dict[str, Any]]:
    """Read a holdout CSV. With `labels` (a labeled blind CSV), its `manual_*` columns are joined onto
    the full CSV strictly by case_id (same case set, no duplicates, matching `account_ref`); the full
    CSV must then carry no labels of its own."""
    path = Path(path)
    cols, rows = _read(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in cols]
    if missing:
        raise ValueError(f"{path} is not a holdout CSV: missing {missing}")
    _check_rows(rows, path, full=True)
    if labels is None:
        return rows
    labels = Path(labels)
    if any(_lab(r, c) for r in rows for c in LABEL_COLUMNS):
        raise ValueError(f"{path} already holds manual labels; label one file only")
    lcols, lrows = _read(labels)
    missing = [c for c in ("case_id", "account_ref", *MANUAL_COLUMNS) if c not in lcols]
    if missing:
        raise ValueError(f"{labels} is not a blind holdout CSV: missing {missing}")
    _check_rows(lrows, labels, full=False)
    by_case = {r["case_id"]: r for r in lrows}
    if len(lrows) != len(rows) or set(by_case) != {r["case_id"] for r in rows}:
        raise ValueError(f"{labels} ({len(lrows)} rows) and {path} ({len(rows)} rows) hold different cases")
    for r in rows:
        lr = by_case[r["case_id"]]
        if lr["account_ref"] != r["account_ref"]:
            raise ValueError(f"{labels}: {r['case_id']}: account_ref {lr['account_ref']!r} differs from "
                             f"{r['account_ref']!r} in {path}")
        for c in MANUAL_COLUMNS:
            r[c] = lr.get(c, "")
    return rows
