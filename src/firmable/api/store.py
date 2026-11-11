"""Serving DB for the API: build once from the accounts layer, then read only.

`build_serving_db` loads `accounts.parquet`, `account_signals.parquet`,
`account_evidence.parquet` (the `docs/phase3-plan.md` accounts contract) and
the signal registry into one DuckDB file, written to a temp name and
published with `os.replace`. `Store` opens that file read-only and answers the
API queries. Every value that comes from a request is a bound parameter.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa

from ..attribution.text import fold_name

# v2: scoring v3 contract (priority, ownership, evidence, eligibility, legacy score)
# v3: accent-folded search_text (attribution v5 `fold_name`); queries are folded the same way
SERVING_VERSION = 3

REGISTRY_COLUMNS = (
    "id", "version", "name", "family", "observed_fact_template", "inferred_risk", "hypothesis", "infra_exposure",
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
# Which accounts a listing shows. `actionable` is the outreach list; `review` holds eligible accounts
# with low ownership, open review flags or no security observation; `excluded` holds accounts that
# are not in the prospect population (registry placeholders, pool labels).
VIEWS = {
    "actionable": "actionable",
    "review": "eligibility = 'eligible' AND NOT actionable",
    "excluded": "eligibility = 'excluded'",
    "all": None,
}
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
            con.execute(
                """
                CREATE TABLE signal_registry (
                    id VARCHAR PRIMARY KEY, version INTEGER, name VARCHAR, family VARCHAR,
                    observed_fact_template VARCHAR, inferred_risk VARCHAR, hypothesis VARCHAR,
                    infra_exposure BOOLEAN
                )
                """
            )
            con.executemany(
                "INSERT INTO signal_registry VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [[_field(entry, c) for c in REGISTRY_COLUMNS] for entry in registry],
            )
            if snapshot_id is None:
                snaps = con.execute("SELECT DISTINCT snapshot_id FROM account_evidence").fetchall()
                snapshot_id = snaps[0][0] if len(snaps) == 1 else None
            con.execute(
                "CREATE TABLE meta AS SELECT ?::VARCHAR AS snapshot_id, ?::INTEGER AS serving_version, "
                "?::TIMESTAMP AS built_at, 'internal' AS profile",
                [snapshot_id, SERVING_VERSION, datetime.now()],
            )
            con.execute("CREATE UNIQUE INDEX accounts_id ON accounts (account_id)")
            con.execute("CREATE INDEX account_signals_id ON account_signals (account_id)")
            con.execute("CREATE INDEX account_evidence_id ON account_evidence (account_id)")
            stats: dict[str, Any] = {
                t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                for t in ("accounts", "account_signals", "account_evidence", "signal_registry")
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
        return self._query(f"SELECT {quote_columns(REGISTRY_COLUMNS)} FROM signal_registry ORDER BY id")

    # -- accounts -------------------------------------------------------------

    def search_accounts(
        self,
        q: str | None = None,
        segment: str | None = "enterprise",
        signals: list[str] | None = None,
        tiers: list[str] | None = None,
        countries: list[str] | None = None,
        min_priority: float | None = None,
        view: str = "actionable",
        bands: list[str] | None = None,
        ownership: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Accounts matching every given filter, by priority rank; returns (total, page).

        segment: `enterprise` (default) or `network_provider`; ranks restart per segment.
        view: `actionable` (default), `review`, `excluded` or `all` (see VIEWS).
        q: case- and accent-insensitive literal substring of name, id or details (`fold_name`).
        signals: account has ALL of them. tiers, bands, ownership, countries: ANY of them.
        """
        if view not in VIEWS:
            raise ValueError(f"unknown view: {view}")
        where: list[str] = []
        params: list[Any] = []
        if VIEWS[view]:
            where.append(VIEWS[view])
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
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self._query(f"SELECT count(*) AS n FROM accounts {clause}", params)[0]["n"]
        items = self._query(
            f"SELECT {quote_columns(ACCOUNT_COLUMNS)} FROM accounts {clause} ORDER BY {ACCOUNT_ORDER} LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return total, items

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
