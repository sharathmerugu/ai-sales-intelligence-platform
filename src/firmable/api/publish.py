"""Public serving DB: a sanitized copy of the internal serving DB for deployment.

The internal serving DB keeps full provenance (raw file id, byte offset, length). The public
copy keeps `observation_id` and `record_sha256`, which are enough to trace a claim back inside
Firmable, and nulls the raw file coordinates. It refuses input that predates the NTLM policy
(attribution v2, ADR 0007), so an NTLM-only attribution can never be deployed.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from .store import ACCOUNT_COLUMNS, ACCOUNT_ORDER, ACCOUNT_SIGNAL_COLUMNS, EVIDENCE_COLUMNS, REGISTRY_COLUMNS, quote_columns

MIN_ATTRIBUTION_VERSION = 2          # NTLM-restricted attribution
INTERNAL_ONLY = {"file_id": "VARCHAR", "byte_offset": "BIGINT", "byte_length": "INTEGER"}  # nulled
FORBIDDEN_COLUMN_MARKERS = ("ntlm", "evidence_json")
# Attribution v1 reason for an NTLM-won domain; v2 only allows NTLM as corroboration.
FORBIDDEN_REASONS = ("dom_ntlm",)
# Public wording for internal reason codes that would reveal an internal AD domain equals this one.
PUBLIC_REASON = {"dom_ntlm_corroborated": "dom_multi_source_corroborated"}


def _check(con: duckdb.DuckDBPyConnection) -> None:
    lo = con.execute("SELECT min(attribution_version) FROM s.account_evidence").fetchone()[0]
    if lo is not None and lo < MIN_ATTRIBUTION_VERSION:
        raise ValueError(f"account_evidence has attribution_version {lo} < {MIN_ATTRIBUTION_VERSION} "
                         "(pre NTLM policy); rebuild attribution before publishing")
    bad = con.execute("SELECT count(*) FROM s.account_evidence WHERE list_has_any(attribution_reasons, ?)",
                      [list(FORBIDDEN_REASONS)]).fetchone()[0]
    if bad:
        raise ValueError(f"{bad} evidence rows carry NTLM-only attribution reasons {FORBIDDEN_REASONS}")


def publish_public_db(src: str | Path, out_path: str | Path) -> dict[str, Any]:
    """Write the sanitized public serving DB at `out_path` from the internal one at `src`."""
    src, out_path = Path(src), Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(f".{out_path.name}.tmp-{os.getpid()}")
    tmp.unlink(missing_ok=True)
    reasons = "list_transform(attribution_reasons, lambda x: CASE x " + " ".join(
        f"WHEN '{k}' THEN '{v}'" for k, v in PUBLIC_REASON.items()) + " ELSE x END) AS attribution_reasons"
    ev_cols = ", ".join(f'NULL::{INTERNAL_ONLY[c]} AS "{c}"' if c in INTERNAL_ONLY
                        else reasons if c == "attribution_reasons" else f'"{c}"' for c in EVIDENCE_COLUMNS)
    try:
        con = duckdb.connect(str(tmp))
        try:
            con.execute(f"ATTACH {_q(src)} AS s (READ_ONLY)")
            _check(con)
            con.execute(f"CREATE TABLE accounts AS SELECT {quote_columns(ACCOUNT_COLUMNS)}, search_text "
                        f"FROM s.accounts ORDER BY segment, {ACCOUNT_ORDER}")
            con.execute(f"CREATE TABLE account_signals AS SELECT {quote_columns(ACCOUNT_SIGNAL_COLUMNS)} "
                        "FROM s.account_signals ORDER BY account_id, contribution DESC, signal_id")
            con.execute(f"CREATE TABLE account_evidence AS SELECT {ev_cols} FROM s.account_evidence "
                        "ORDER BY account_id, signal_id, counted DESC, ip, port, transport, sni, service_id")
            con.execute(f"CREATE TABLE signal_registry AS SELECT {quote_columns(REGISTRY_COLUMNS)} FROM s.signal_registry")
            con.execute("""CREATE TABLE meta AS
                           SELECT snapshot_id, serving_version, ?::TIMESTAMP AS built_at, 'public' AS profile
                           FROM s.meta""", [datetime.now()])
            con.execute("DETACH s")
            cols = [c for (c,) in con.execute("SELECT column_name FROM information_schema.columns").fetchall()]
            leaked = [c for c in cols if any(m in c.lower() for m in FORBIDDEN_COLUMN_MARKERS)]
            if leaked:
                raise ValueError(f"forbidden columns in public DB: {leaked}")
            con.execute("CREATE UNIQUE INDEX accounts_id ON accounts (account_id)")
            con.execute("CREATE INDEX account_signals_id ON account_signals (account_id)")
            con.execute("CREATE INDEX account_evidence_id ON account_evidence (account_id)")
            stats = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                     for t in ("accounts", "account_signals", "account_evidence", "signal_registry")}
            con.execute("CHECKPOINT")
        finally:
            con.close()
        os.replace(tmp, out_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        Path(f"{tmp}.wal").unlink(missing_ok=True)
        raise
    return {**stats, "path": str(out_path), "bytes": out_path.stat().st_size}


def _q(p: Path) -> str:
    return "'" + str(p).replace("'", "''") + "'"

