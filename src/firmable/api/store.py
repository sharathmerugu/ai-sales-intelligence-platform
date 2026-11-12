"""Serving DB for the API: build once from the accounts layer, then read only.

`build_serving_db` loads `accounts.parquet`, `account_signals.parquet`,
`account_evidence.parquet` (the `docs/phase3-plan.md` accounts contract) and
the signal registry into one DuckDB file, written to a temp name and
published with `os.replace`. `Store` opens that file read-only and answers the
API queries. Every value that comes from a request is a bound parameter.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa

from ..accounts.scoring import EXPOSURE_SIGNALS
from ..accounts.use_cases import USE_CASES_BY_ID, USE_CASES_VERSION, lens_rows_sql, rank_lenses
from ..attribution.text import fold_name

# v2: scoring v3 contract (priority, ownership, evidence, eligibility, legacy score)
# v3: accent-folded search_text (attribution v5 `fold_name`); queries are folded the same way
# v4: research states (views research / verify / context), use-case lenses (`account_use_cases`),
#     sales wording columns in `signal_registry` (signals WORDING_VERSION 2)
SERVING_VERSION = 4

REGISTRY_COLUMNS = (
    "id", "version", "name", "family", "observed_fact_template", "inferred_risk", "hypothesis", "infra_exposure",
    "short_name", "noun_one", "noun_many", "offering", "pitch", "opener", "discovery_questions", "confirm_on_call",
    "detail_notes",
)
REGISTRY_DDL = """
    CREATE TABLE signal_registry (
        id VARCHAR PRIMARY KEY, version INTEGER, name VARCHAR, family VARCHAR,
        observed_fact_template VARCHAR, inferred_risk VARCHAR, hypothesis VARCHAR, infra_exposure BOOLEAN,
        short_name VARCHAR, noun_one VARCHAR, noun_many VARCHAR, offering VARCHAR, pitch VARCHAR, opener VARCHAR,
        discovery_questions VARCHAR[], confirm_on_call VARCHAR[],
        detail_notes VARCHAR  -- JSON object: detail label -> note
    )
"""
USE_CASE_COLUMNS = (
    "account_id", "uc_id", "uc_signal_ids", "uc_n_services", "uc_n_ips", "uc_priority", "uc_rank",
    "uc_percentile", "uc_evidence_quality",
)

ACCOUNT_COLUMNS = (
    "account_id", "account_name", "account_kind", "segment", "best_tier", "n_services", "n_ips", "signal_ids",
    "top_signals", "details", "countries",
    "product_relevance", "signal_strength", "opportunity_priority", "priority_percentile", "priority_band", "rank",
    "eligibility", "eligibility_reasons", "ownership_confidence", "ownership_reasons", "review_flags",
    "attribution_confidence", "ownership_services", "named_public_services", "named_rdns_services",
    "third_party_domains", "network_operators", "subscriber_rdns_services",
    "evidence_quality", "evidence_quality_band", "actionable", "actionable_blockers",
    "legacy_score", "legacy_rank", "legacy_scoring_version", "explanation", "scoring_version", "eligibility_version",
)
# Which accounts a listing shows, by research state (docs/sales-brief.md §4):
# `research`: research candidates: the scoring-v3 `actionable` gate (eligible, ownership medium or
#   high, no review flag, a counted security observation above a scanner tag) AND a counted exposure
#   signal. In a lens of hygiene signals only (certificates) the exposure condition is dropped;
# `hygiene`: passes the gate on certificate / TLS findings alone (96% of gated accounts, 2026-11-07);
# `verify`: eligible, but ownership must be verified first (low ownership or an open review flag);
# `context`: eligible and owned, but only technographic or tag-level evidence (context only);
# `excluded`: not a prospect (registry placeholders, pool labels, provider sub-allocations).
# `actionable` and `review` are the pre-v4 names, kept as aliases (`review` = verify + context).
_VERIFY = "(list_contains(actionable_blockers, 'ownership_low') OR list_contains(actionable_blockers, 'review_flags'))"
# `top_signals` holds the account's counted signals
_EXPOSURE = "list_has_any(top_signals, [" + ", ".join(f"'{s}'" for s in sorted(EXPOSURE_SIGNALS)) + "])"
VIEWS = {
    "research": f"actionable AND {_EXPOSURE}",
    "hygiene": f"actionable AND NOT {_EXPOSURE}",
    "verify": f"eligibility = 'eligible' AND NOT actionable AND {_VERIFY}",
    "context": f"eligibility = 'eligible' AND NOT actionable AND NOT {_VERIFY}",
    "excluded": "eligibility = 'excluded'",
    "all": None,
    "actionable": "actionable",
    "review": "eligibility = 'eligible' AND NOT actionable",
}
STATE_VIEWS = ("research", "hygiene", "verify", "context", "excluded")  # one per research state


def view_sql(view: str, use_case: str | None = None) -> str | None:
    """SQL of a view; in a hygiene-only lens (certificates) TLS findings make a research candidate."""
    uc = USE_CASES_BY_ID.get(use_case or "")
    if uc is not None and uc.hygiene_is_the_finding:
        if view == "research":
            return "actionable"
        if view == "hygiene":
            return "false"
    return VIEWS[view]


ACCOUNT_ORDER = "rank NULLS LAST, opportunity_priority DESC, account_id"

# Account ids are derived from names, so an attribution rebuild can change them. Old links are
# resolved by rule, with no alias table: attribution v5 accent-folds org keys (`org:telefónica chile`
# -> `org:telefonica chile`), and provider reclassification moves an org key between `org:` and `net:`.
ACCOUNT_PREFIXES = ("org", "net", "dom")
SWAPPABLE_PREFIXES = {"org": "net", "net": "org"}


def successor_ids(account_id: str) -> list[str]:
    """Ids an older build's `account_id` may have now, in lookup order, excluding the id itself.

    The accent-folded id first, then (org and net only) the same org key under the other prefix,
    as written and folded. Domain accounts never change prefix.
    """
    prefix, sep, key = account_id.partition(":")
    if not sep or prefix not in ACCOUNT_PREFIXES:
        return []
    out = [f"{prefix}:{fold_name(key)}"]
    if prefix in SWAPPABLE_PREFIXES:
        other = SWAPPABLE_PREFIXES[prefix]
        out += [f"{other}:{key}", f"{other}:{fold_name(key)}"]
    return [c for c in dict.fromkeys(out) if c != account_id]


ACCOUNT_SIGNAL_COLUMNS = (
    "account_id", "signal_id", "family", "n_services", "n_ips", "n_counted_services", "details",
    "sub_flags", "max_attribution_confidence", "contribution",
)

# Evidence columns the API reads. `evidence_json` is deliberately not served:
# it can carry sensitive raw fields (e.g. NTLM internal names) that sit behind
# human review (CLAUDE.md, cybersecurity rules).
EVIDENCE_COLUMNS = (
    "account_id", "snapshot_id", "signal_id", "signal_version", "family", "service_id", "observation_id",
    "file_id", "byte_offset", "byte_length", "record_sha256", "ip", "port", "transport", "sni",
    "observed_at", "is_cdn", "country_code", "product", "version", "http_title", "module",
    "match_basis", "detail", "sub_flags", "tier", "attribution_confidence", "attribution_reasons", "counted",
    "suppressed_by", "attribution_version", "attribution_domains",
)


def quote_columns(cols: tuple[str, ...]) -> str:
    return ", ".join(f'"{c}"' for c in cols)


def build_serving_db(
    accounts_dir: str | Path,
    registry: list[dict[str, Any]],
    out_path: str | Path,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    """Build the read-only serving DB at `out_path`; return row counts.

    `registry` is the signal registry (dicts with at least `REGISTRY_COLUMNS`;
    extra keys such as the SQL predicate are ignored). `snapshot_id`, when not
    given, is taken from `account_evidence.snapshot_id` if it is unique.
    """
    accounts_dir = Path(accounts_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(f".{out_path.name}.tmp-{os.getpid()}")
    for p in (tmp, Path(f"{tmp}.wal")):
        p.unlink(missing_ok=True)

    src = {name: str(accounts_dir / f"{name}.parquet") for name in ("accounts", "account_signals", "account_evidence")}
    for path in src.values():
        if not Path(path).exists():
            raise FileNotFoundError(path)

    try:
        con = duckdb.connect(str(tmp))
        try:
            # search text is folded like org names (accents, case), so "telefonica" finds "Telefónica";
            # folded in Python once per distinct text (DuckDB has no equivalent of `fold_name`)
            raw_text = "concat_ws(chr(10), account_name, account_id, array_to_string(coalesce(details, []), chr(10)))"
            texts = [t for (t,) in con.execute(
                f"SELECT DISTINCT {raw_text} FROM read_parquet(?, hive_partitioning = false)", [src["accounts"]]
            ).fetchall()]
            con.register("search_fold", pa.table({"raw": pa.array(texts, pa.string()),
                                                  "folded": pa.array([fold_name(t) for t in texts], pa.string())}))
            con.execute(
                f"""
                CREATE TABLE accounts AS
                SELECT {quote_columns(ACCOUNT_COLUMNS)}, folded AS search_text
                FROM read_parquet(?, hive_partitioning = false) JOIN search_fold ON raw = {raw_text}
                ORDER BY segment, {ACCOUNT_ORDER}
                """,
                [src["accounts"]],
            )
            con.unregister("search_fold")
            con.execute(
                f"""
                CREATE TABLE account_signals AS
                SELECT {quote_columns(ACCOUNT_SIGNAL_COLUMNS)}
                FROM read_parquet(?, hive_partitioning = false)
                ORDER BY account_id, contribution DESC, signal_id
                """,
                [src["account_signals"]],
            )
            con.execute(
                f"""
                CREATE TABLE account_evidence AS
                SELECT {quote_columns(EVIDENCE_COLUMNS)}
                FROM read_parquet(?, hive_partitioning = false)
                ORDER BY account_id, signal_id, counted DESC, ip, port, transport, sni, service_id
                """,
                [src["account_evidence"]],
            )
            con.execute(REGISTRY_DDL)
            con.executemany(
                f"INSERT INTO signal_registry VALUES ({', '.join('?' * len(REGISTRY_COLUMNS))})",
                [[_registry_value(entry, c) for c in REGISTRY_COLUMNS] for entry in registry],
            )
            _build_use_cases(con)
            if snapshot_id is None:
                snaps = con.execute("SELECT DISTINCT snapshot_id FROM account_evidence").fetchall()
                snapshot_id = snaps[0][0] if len(snaps) == 1 else None
            from ..signals.registry import WORDING_VERSION
            con.execute(
                "CREATE TABLE meta AS SELECT ?::VARCHAR AS snapshot_id, ?::INTEGER AS serving_version, "
                "?::TIMESTAMP AS built_at, 'internal' AS profile, ?::INTEGER AS wording_version, "
                "?::INTEGER AS use_cases_version",
                [snapshot_id, SERVING_VERSION, datetime.now(), WORDING_VERSION, USE_CASES_VERSION],
            )
            con.execute("CREATE UNIQUE INDEX accounts_id ON accounts (account_id)")
            con.execute("CREATE INDEX account_signals_id ON account_signals (account_id)")
            con.execute("CREATE INDEX account_evidence_id ON account_evidence (account_id)")
            con.execute("CREATE INDEX account_use_cases_id ON account_use_cases (uc_id, account_id)")
            stats: dict[str, Any] = {
                t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                for t in ("accounts", "account_signals", "account_evidence", "signal_registry", "account_use_cases")
            }
            con.execute("CHECKPOINT")
        finally:
            con.close()
        os.replace(tmp, out_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        Path(f"{tmp}.wal").unlink(missing_ok=True)
        raise
    stats["snapshot_id"] = snapshot_id
    stats["path"] = str(out_path)
    return stats


def _field(entry: Any, name: str) -> Any:
    """Registry entries may be mappings or objects (e.g. dataclasses)."""
    if isinstance(entry, dict):
        return entry.get(name)
    return getattr(entry, name, None)


def _registry_value(entry: Any, name: str) -> Any:
    value = _field(entry, name)
    if name in ("discovery_questions", "confirm_on_call"):
        return list(value or [])
    if name == "detail_notes":
        return json.dumps(dict(value or {}), sort_keys=True)
    return value


def _build_use_cases(con: duckdb.DuckDBPyConnection) -> None:
    """`account_use_cases`: per account and lens, lens evidence, priority and rank (accounts.use_cases)."""
    accounts = {r["account_id"]: r for r in _rows(con.execute(
        "SELECT account_id, segment, eligibility FROM accounts"))}
    ranked = rank_lenses(lens_rows_sql(con), accounts)
    con.execute("""CREATE TABLE account_use_cases (
        account_id VARCHAR, uc_id VARCHAR, uc_signal_ids VARCHAR[], uc_n_services BIGINT, uc_n_ips BIGINT,
        uc_priority DOUBLE, uc_rank BIGINT, uc_percentile DOUBLE, uc_evidence_quality DOUBLE)""")
    table = pa.table({
        "account_id": pa.array([r["account_id"] for r in ranked], pa.string()),
        "uc_id": pa.array([r["use_case"] for r in ranked], pa.string()),
        "uc_signal_ids": pa.array([r["signal_ids"] for r in ranked], pa.list_(pa.string())),
        "uc_n_services": pa.array([r["n_services"] for r in ranked], pa.int64()),
        "uc_n_ips": pa.array([r["n_ips"] for r in ranked], pa.int64()),
        "uc_priority": pa.array([r["priority"] for r in ranked], pa.float64()),
        "uc_rank": pa.array([r["rank"] for r in ranked], pa.int64()),
        "uc_percentile": pa.array([r["percentile"] for r in ranked], pa.float64()),
        "uc_evidence_quality": pa.array([r["evidence_quality"] for r in ranked], pa.float64()),
    })
    con.register("uc_rows", table)
    con.execute(f"INSERT INTO account_use_cases SELECT {quote_columns(USE_CASE_COLUMNS)} FROM uc_rows "
                "ORDER BY uc_id, uc_rank NULLS LAST, account_id")
    con.unregister("uc_rows")


def _rows(cur: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


class Store:
    """Read-only query layer over a serving DB. Thread-safe: one cursor per call."""

    def __init__(self, db_path: str | Path, memory_limit: str | None = None, threads: int | None = None):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"serving DB not found: {self.db_path}")
        config: dict[str, Any] = {}
        if memory_limit:
            config["memory_limit"] = memory_limit
        if threads:
            config["threads"] = threads
        self._con = duckdb.connect(str(self.db_path), read_only=True, config=config)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._con.close()

    def _query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._con.cursor()
        try:
            return _rows(cur.execute(sql, params or []))
        finally:
            cur.close()

    # -- metadata -----------------------------------------------------------

    def meta(self) -> dict[str, Any]:
        row = self._query(
            "SELECT m.snapshot_id, m.serving_version, (SELECT count(*) FROM accounts) AS n_accounts FROM meta m"
        )
        return row[0]

    def registry(self) -> list[dict[str, Any]]:
        rows = self._query(f"SELECT {quote_columns(REGISTRY_COLUMNS)} FROM signal_registry ORDER BY id")
        for r in rows:
            r["detail_notes"] = json.loads(r["detail_notes"] or "{}")
            r["discovery_questions"] = list(r["discovery_questions"] or [])
            r["confirm_on_call"] = list(r["confirm_on_call"] or [])
        return rows

    # -- accounts -------------------------------------------------------------

    def search_accounts(
        self,
        q: str | None = None,
        segment: str | None = "enterprise",
        signals: list[str] | None = None,
        tiers: list[str] | None = None,
        countries: list[str] | None = None,
        min_priority: float | None = None,
        view: str = "research",
        bands: list[str] | None = None,
        ownership: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
        use_case: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Accounts matching every given filter, by priority rank; returns (total, page).

        segment: `enterprise` (default) or `network_provider`; ranks restart per segment.
        view: `research` (default), `verify`, `context`, `excluded` or `all` (see VIEWS).
        use_case: only accounts with evidence for that lens, ordered by the lens rank; each row then
        carries the `uc_*` lens columns.
        q: case- and accent-insensitive literal substring of name, id or details (`fold_name`).
        signals: account has ALL of them. tiers, bands, ownership, countries: ANY of them.
        """
        if view not in VIEWS:
            raise ValueError(f"unknown view: {view}")
        where: list[str] = []
        params: list[Any] = []
        if VIEWS[view]:
            where.append(view_sql(view, use_case))
        if segment:
            where.append("segment = ?")
            params.append(segment)
        if q:
            where.append("contains(search_text, ?)")
            params.append(fold_name(q))
        if signals:
            where.append("list_has_all(signal_ids, ?::VARCHAR[])")
            params.append(list(signals))
        if tiers:
            where.append("list_contains(?::VARCHAR[], best_tier)")
            params.append(list(tiers))
        if bands:
            where.append("list_contains(?::VARCHAR[], priority_band)")
            params.append(list(bands))
        if ownership:
            where.append("list_contains(?::VARCHAR[], ownership_confidence)")
            params.append(list(ownership))
        if countries:
            where.append("list_has_any(countries, ?::VARCHAR[])")
            params.append([c.upper() for c in countries])
        if min_priority is not None:
            where.append("opportunity_priority >= ?")
            params.append(min_priority)
        source, cols, order = "accounts", quote_columns(ACCOUNT_COLUMNS), ACCOUNT_ORDER
        if use_case:
            source = "accounts JOIN account_use_cases USING (account_id)"
            cols += ", " + quote_columns(USE_CASE_COLUMNS[1:])
            order = "uc_rank NULLS LAST, uc_priority DESC, account_id"
            where.insert(0, "uc_id = ?")
            params.insert(0, use_case)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self._query(f"SELECT count(*) AS n FROM {source} {clause}", params)[0]["n"]
        items = self._query(
            f"SELECT {cols} FROM {source} {clause} ORDER BY {order} LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return total, items

    def use_case_counts(self, segment: str = "enterprise") -> dict[str, dict[str, int]]:
        """Per lens: accounts with lens evidence by research view (STATE_VIEWS)."""
        out = {}
        for uc_id in USE_CASES_BY_ID:
            cases = ", ".join(f"count_if({view_sql(v, uc_id)}) AS {v}" for v in STATE_VIEWS)
            out[uc_id] = self._query(
                f"SELECT count(*) AS total, {cases} FROM accounts JOIN account_use_cases USING (account_id) "
                "WHERE segment = ? AND uc_id = ?", [segment, uc_id])[0]
        return out

    def population_sizes(self) -> dict[str, dict[str, Any]]:
        """Per segment: eligible (ranked) accounts, and ranked accounts per lens."""
        out: dict[str, dict[str, Any]] = {}
        for r in self._query("SELECT segment, count(rank) AS n FROM accounts GROUP BY segment"):
            out[r["segment"]] = {"eligible": r["n"], "lenses": {}}
        for r in self._query("SELECT segment, uc_id, count(uc_rank) AS n FROM accounts JOIN account_use_cases "
                             "USING (account_id) GROUP BY segment, uc_id"):
            out.setdefault(r["segment"], {"eligible": 0, "lenses": {}})["lenses"][r["uc_id"]] = r["n"]
        return out

    def view_counts(self, segment: str = "enterprise") -> dict[str, int]:
        cases = ", ".join(f"count_if({VIEWS[v]}) AS {v}" for v in STATE_VIEWS)
        return self._query(f"SELECT count(*) AS total, {cases} FROM accounts WHERE segment = ?", [segment])[0]

    def locations(self, segment: str = "enterprise", limit: int = 300) -> list[dict[str, Any]]:
        """Observed infrastructure locations (IP geolocation country codes) by number of research candidates."""
        return self._query(
            f"""SELECT c AS country_code, count(*) AS accounts, count_if({VIEWS['research']}) AS research
                FROM (SELECT unnest(countries) AS c, actionable, eligibility, actionable_blockers, top_signals
                      FROM accounts WHERE segment = ?)
                GROUP BY c ORDER BY research DESC, accounts DESC, c LIMIT ?""", [segment, limit])

    def account_use_cases(self, account_id: str) -> list[dict[str, Any]]:
        return self._query(
            f"SELECT {quote_columns(USE_CASE_COLUMNS[1:])} FROM account_use_cases WHERE account_id = ? ORDER BY uc_id",
            [account_id])

    def signals_for_accounts(self, account_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        """Per-signal summaries for several accounts at once (list rows' main finding)."""
        if not account_ids:
            return {}
        rows = self._query(
            f"SELECT {quote_columns(ACCOUNT_SIGNAL_COLUMNS)} FROM account_signals "
            "WHERE list_contains(?::VARCHAR[], account_id) ORDER BY account_id, contribution DESC NULLS LAST, signal_id",
            [account_ids])
        out: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            out.setdefault(r["account_id"], []).append(r)
        return out

    def get_account(self, account_id: str) -> dict[str, Any] | None:
        rows = self._query(f"SELECT {quote_columns(ACCOUNT_COLUMNS)} FROM accounts WHERE account_id = ?", [account_id])
        return rows[0] if rows else None

    def resolve_account_id(self, account_id: str) -> str | None:
        """`account_id` if it exists, else the first existing `successor_ids`, else None."""
        candidates = [account_id, *successor_ids(account_id)]
        rows = self._query("SELECT account_id FROM accounts WHERE list_contains(?::VARCHAR[], account_id)", [candidates])
        found = {r["account_id"] for r in rows}
        return next((c for c in candidates if c in found), None)

    def account_signals(self, account_id: str) -> list[dict[str, Any]]:
        """Per-signal summary with the registry name and wording."""
        return self._query(
            """
            SELECT s.signal_id, r.name, coalesce(s.family, r.family) AS family, s.n_services, s.n_ips,
                   s.n_counted_services, s.details, s.sub_flags, s.max_attribution_confidence,
                   s.contribution, r.inferred_risk, r.hypothesis
            FROM account_signals s LEFT JOIN signal_registry r ON r.id = s.signal_id
            WHERE s.account_id = ?
            ORDER BY s.contribution DESC NULLS LAST, s.signal_id
            """,
            [account_id],
        )

    # -- semantic-layer helpers (read only; docs/agentic-briefs.md) ---------------

    def meta_full(self) -> dict[str, Any]:
        """Every `meta` column (snapshot, serving / wording / use-case versions, profile, built_at)."""
        return self._query("SELECT * FROM meta")[0]

    def signal_coverage(self, account_id: str) -> dict[str, dict[str, Any]]:
        """Per signal of one account: evidence rows, counted / suppressed rows, observation dates and a
        content digest of the observation ids (cache invalidation)."""
        rows = self._query(
            """SELECT signal_id, count(*) AS n_rows, count_if(counted) AS n_counted,
                      count_if(NOT counted) AS n_suppressed, min(observed_at) AS first_observed,
                      max(observed_at) AS last_observed, bit_xor(hash(observation_id)) AS ids_digest
               FROM account_evidence WHERE account_id = ? GROUP BY signal_id ORDER BY signal_id""",
            [account_id])
        return {r["signal_id"]: r for r in rows}

    def evidence_by_ids(self, account_id: str, observation_ids: list[str],
                        signal: str | None = None) -> list[dict[str, Any]]:
        """Evidence rows of one account with the given observation ids (same columns as `account_evidence`).
        Ids that belong to another account return nothing."""
        if not observation_ids:
            return []
        cols = ", ".join(f"e.{c}" for c in quote_columns(EVIDENCE_COLUMNS).split(", "))
        params: list[Any] = [account_id, list(observation_ids)]
        extra = ""
        if signal:
            extra = " AND e.signal_id = ?"
            params.append(signal)
        return self._query(
            f"""SELECT {cols}, r.name AS signal_name, r.observed_fact_template, r.inferred_risk, r.hypothesis
                FROM account_evidence e LEFT JOIN signal_registry r ON r.id = e.signal_id
                WHERE e.account_id = ? AND list_contains(?::VARCHAR[], e.observation_id){extra}
                ORDER BY e.signal_id, e.counted DESC, e.ip, e.port, e.transport, e.sni, e.service_id""", params)

    def product_vocabulary(self) -> list[str]:
        """Every product / detail label any account carries: the vocabulary a brief may not name unless the
        account itself carries it."""
        rows = self._query("SELECT DISTINCT unnest(details) AS d FROM account_signals WHERE details IS NOT NULL")
        return sorted({r["d"] for r in rows if r["d"]})

    def account_evidence(
        self, account_id: str, signal: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[int, list[dict[str, Any]]]:
        """Evidence rows for one account (optionally one signal) with registry wording."""
        where = "e.account_id = ?"
        params: list[Any] = [account_id]
        if signal:
            where += " AND e.signal_id = ?"
            params.append(signal)
        total = self._query(f"SELECT count(*) AS n FROM account_evidence e WHERE {where}", params)[0]["n"]
        cols = ", ".join(f"e.{c}" for c in quote_columns(EVIDENCE_COLUMNS).split(", "))
        items = self._query(
            f"""
            SELECT {cols}, r.name AS signal_name, r.observed_fact_template, r.inferred_risk, r.hypothesis
            FROM account_evidence e LEFT JOIN signal_registry r ON r.id = e.signal_id
            WHERE {where}
            ORDER BY e.signal_id, e.counted DESC, e.ip, e.port, e.transport, e.sni, e.service_id
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        )
        return total, items
