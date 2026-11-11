"""FastAPI app over the read-only serving DB.

Wording follows `docs/research-findings.md` §3: observed facts, inferred
risks and unverified hypotheses are separate, labelled fields. Opportunity
priority, ownership confidence and evidence quality are separate fields
(scoring v3, docs/ranking-v3.md); none is a purchase probability, a confirmed
vulnerability or an expected loss.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from firmable.logs import log

from firmable.api.store import SERVING_VERSION, Store
from firmable.api.wording import render_fact

ENV_DB = "FIRMABLE_SERVING_DB"
ENV_AUTH = "FIRMABLE_BASIC_AUTH"            # "user:password"; protects every route but /health
ENV_REQUIRE_AUTH = "FIRMABLE_REQUIRE_AUTH"  # "1": refuse to start without ENV_AUTH (set in the image)
ENV_RATE = "FIRMABLE_RATE_LIMIT_PER_MIN"    # requests per client per minute; unset or 0 = off
ENV_RATE_KEY = "FIRMABLE_RATE_LIMIT_KEY"    # peer (default) | forwarded | global
RATE_LIMIT_KEYS = ("peer", "forwarded", "global")
ENV_DUCKDB_MEMORY = "FIRMABLE_DUCKDB_MEMORY_LIMIT"
ENV_DUCKDB_THREADS = "FIRMABLE_DUCKDB_THREADS"
OPEN_PATHS = frozenset({"/health"})
SECURITY_HEADERS = {
    "cache-control": "no-store",
    "x-robots-tag": "noindex, nofollow",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}
STATIC_DIR = Path(__file__).parent / "static"
MAX_LIMIT = 200

LABELS = {
    "observed_fact": "Directly observed fact: what the scanner recorded on the snapshot date.",
    "inferred_risk": "Inferred security risk: a risk class suggested by the observation, "
    "not a verified vulnerability or exploitability claim.",
    "hypothesis": "Unverified hypothesis: a sales conversation starter that may or may not hold; "
    "not evidence of intent, budget, missing controls or compromise.",
}

DISCLAIMER = (
    "Priority bands and percentiles are a relative priority within this snapshot, among eligible "
    "accounts of the same segment. They are not a purchase probability, a confirmed vulnerability "
    "or an expected loss. Ownership confidence is a separate, inferred judgement from scan records "
    "and may be wrong; it is not multiplied into the priority. All observations come from a single "
    "snapshot and say nothing about change over time."
)
PRIORITY_NOTE = "relative priority in this snapshot; not a purchase probability, confirmed vulnerability or loss estimate"
POPULATION = {"enterprise": "eligible enterprise accounts", "network_provider": "network-provider accounts"}


def _signal_ref(signal_id: str, names: dict[str, str]) -> dict[str, Any]:
    return {"signal_id": signal_id, "name": names.get(signal_id)}


def _account_item(row: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    pct = row["priority_percentile"]
    return {
        "account_id": row["account_id"],
        "account_name": row["account_name"],
        "account_kind": row["account_kind"],
        "segment": row["segment"],
        "rank": row["rank"],
        "priority": {
            "band": row["priority_band"],
            "percentile": None if pct is None else int(pct),
            "population": POPULATION.get(row["segment"]),
            "value": row["opportunity_priority"],
            "product_relevance": row["product_relevance"],
            "signal_strength": row["signal_strength"],
            "note": PRIORITY_NOTE,
        },
        "ownership": {
            "confidence": row["ownership_confidence"],
            "reasons": list(row["ownership_reasons"] or []),
            "review_flags": list(row["review_flags"] or []),
            "best_tier": row["best_tier"],
            "mean_attribution_confidence": row["attribution_confidence"],
            "services": row["ownership_services"],
            "named_public_services": row["named_public_services"],
            "named_rdns_services": row["named_rdns_services"],
            "third_party_domains": row["third_party_domains"],
            "network_operators": row["network_operators"],
        },
        "evidence": {
            "quality": row["evidence_quality_band"],
            "mean_basis_quality": row["evidence_quality"],
        },
        "eligibility": {"status": row["eligibility"], "reasons": list(row["eligibility_reasons"] or [])},
        "actionable": row["actionable"],
        "actionable_blockers": list(row["actionable_blockers"] or []),
        "top_signals": [_signal_ref(sid, names) for sid in (row["top_signals"] or [])],
        "signal_ids": list(row["signal_ids"] or []),
        "best_tier": row["best_tier"],
        "n_services": row["n_services"],
        "n_ips": row["n_ips"],
        "countries": list(row["countries"] or []),
        "details": list(row["details"] or []),
        "legacy": {
            "scoring_version": row["legacy_scoring_version"],
            "score": row["legacy_score"],
            "rank": row["legacy_rank"],
            "note": "scoring v2 composite (attribution and evidence quality multiplied in); comparison only",
        },
    }


def _iso_utc(value: datetime | None) -> str | None:
    return None if value is None else value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "signal_id": row["signal_id"],
        "signal_name": row["signal_name"],
        "family": row["family"],
        "observed_fact": render_fact(row["observed_fact_template"], row),
        "inferred_risk": row["inferred_risk"],
        "hypothesis": row["hypothesis"],
        "service": {
            "service_id": row["service_id"],
            "ip": row["ip"],
            "port": row["port"],
            "transport": row["transport"],
            "sni": row["sni"],
            "observed_at": _iso_utc(row["observed_at"]),
            "country_code": row["country_code"],
            "is_cdn": row["is_cdn"],
            "product": row["product"],
            "version": row["version"],
            "http_title": row["http_title"],
            "module": row["module"],
        },
        "match_basis": row["match_basis"],
        "detail": row["detail"],
        "sub_flags": list(row["sub_flags"] or []),
        "tier": row["tier"],
        "attribution_confidence": row["attribution_confidence"],
        "attribution_reasons": list(row["attribution_reasons"] or []),
        "counted": row["counted"],
        "suppressed_by": row["suppressed_by"],
        "attribution_version": row["attribution_version"],
        "attribution_domains": list(row["attribution_domains"] or []),
        "observation_id": row["observation_id"],
        "provenance": {
            "observation_id": row["observation_id"],
            "file_id": row["file_id"],
            "byte_offset": row["byte_offset"],
            "byte_length": row["byte_length"],
            "record_sha256": row["record_sha256"],
        },
    }


class RateLimiter:
    """Sliding one-minute window per client key, in memory (one process).

    At most `max_keys` clients are tracked. When the table is full, keys idle for a minute are
    dropped; if it is still full, new keys are refused until one expires. Existing clients are never
    reset, so flooding the table with new keys cannot lift anyone's limit.
    """

    WINDOW = 60.0

    def __init__(self, per_minute: int, max_keys: int = 10_000):
        self.per_minute = per_minute
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                for k in [k for k, q in self._hits.items() if not q or now - q[-1] >= self.WINDOW]:
                    del self._hits[k]
                if len(self._hits) >= self.max_keys:
                    return False
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= self.WINDOW:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            return True


def _client_key(request: Request, mode: str) -> str:
    """Rate-limit key: `peer` (TCP peer), `forwarded` (right-most X-Forwarded-For hop, only behind a
    proxy that appends it) or `global` (one budget for everyone).

    On Railway spoofed X-Real-IP / X-Forwarded-For values reached the app and the edge connects from
    changing peer addresses (measured 2026-11-10), so the image uses `global`.
    """
    if mode == "global":
        return "*"
    if mode == "forwarded":
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _authorized(request: Request, expected: bytes) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        given = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return secrets.compare_digest(given, expected)


def create_app(
    db_path: str | Path | None = None,
    basic_auth: str | None = None,
    require_auth: bool | None = None,
    rate_limit_per_minute: int | None = None,
    rate_limit_key: str | None = None,
) -> FastAPI:
    """Build the API over the serving DB at `db_path` (default: $FIRMABLE_SERVING_DB).

    `basic_auth` ("user:password", default $FIRMABLE_BASIC_AUTH) protects every route except
    /health. `require_auth` (default $FIRMABLE_REQUIRE_AUTH == "1") refuses to start without it.
    `rate_limit_per_minute` (default $FIRMABLE_RATE_LIMIT_PER_MIN) limits each key of
    `rate_limit_key` (default $FIRMABLE_RATE_LIMIT_KEY or `peer`; see `_client_key`).
    """
    if db_path is None:
        db_path = os.environ.get(ENV_DB)
        if not db_path:
            raise RuntimeError(f"no serving DB: pass db_path or set {ENV_DB}")
    if basic_auth is None:
        basic_auth = os.environ.get(ENV_AUTH) or None
    if require_auth is None:
        require_auth = os.environ.get(ENV_REQUIRE_AUTH) == "1"
    if rate_limit_per_minute is None:
        rate_limit_per_minute = int(os.environ.get(ENV_RATE) or 0)
    if rate_limit_key is None:
        rate_limit_key = os.environ.get(ENV_RATE_KEY) or "peer"
    if rate_limit_key not in RATE_LIMIT_KEYS:
        raise RuntimeError(f"{ENV_RATE_KEY} must be one of {RATE_LIMIT_KEYS}, not {rate_limit_key!r}")
    if basic_auth is not None and ":" not in basic_auth:
        raise RuntimeError(f"{ENV_AUTH} must be 'user:password'")
    if require_auth and not basic_auth:
        raise RuntimeError(f"authentication required: set {ENV_AUTH}='user:password'")
    expected = basic_auth.encode() if basic_auth else None
    limiter = RateLimiter(rate_limit_per_minute) if rate_limit_per_minute > 0 else None
    # In a container DuckDB would size itself from the host's RAM; cap it explicitly.
    store = Store(db_path, memory_limit=os.environ.get(ENV_DUCKDB_MEMORY) or None,
                  threads=int(os.environ.get(ENV_DUCKDB_THREADS) or 0) or None)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        store.close()

    app = FastAPI(
        title="Firmable cybersecurity sales intelligence",
        description="Evidence-backed account ranking from one internet-scan snapshot. "
        "Priority, ownership confidence and evidence quality are separate; priorities are relative, "
        "not purchase probabilities.",
        lifespan=lifespan,
    )
    found = store.meta()["serving_version"]
    if found != SERVING_VERSION:
        store.close()
        raise RuntimeError(f"serving DB {db_path} has serving_version {found}, this app needs {SERVING_VERSION}: "
                           "rebuild it with `firmable build-phase3 SNAPSHOT --steps accounts serving`")
    app.state.store = store
    signal_names = {r["id"]: r["name"] for r in store.registry()}

    @app.middleware("http")
    async def access_controls(request: Request, call_next):
        started = time.perf_counter()
        path = request.url.path
        if path in OPEN_PATHS:
            response = await call_next(request)
        elif limiter is not None and not limiter.allow(_client_key(request, rate_limit_key)):
            response = JSONResponse({"detail": "rate limit exceeded"}, status_code=429,
                                    headers={"retry-after": "60"})
        elif expected is not None and not _authorized(request, expected):
            response = Response("authentication required", status_code=401,
                                headers={"www-authenticate": 'Basic realm="firmable", charset="UTF-8"'})
        else:
            response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        log("http.request", method=request.method, path=path, status=response.status_code,
            ms=round((time.perf_counter() - started) * 1000, 1))
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.get("/health")
    def health() -> dict[str, Any]:
        meta = store.meta()
        return {"status": "ok", "snapshot_id": meta["snapshot_id"], "n_accounts": meta["n_accounts"]}

    @app.get("/accounts")
    def accounts(
        q: str | None = Query(None, max_length=200),
        segment: Literal["enterprise", "network_provider"] = Query(
            "enterprise", description="enterprise prospects (default) or network providers' own infrastructure"),
        signal: list[str] = Query(default_factory=list),
        tier: list[str] = Query(default_factory=list),
        country: list[str] = Query(default_factory=list),
        view: Literal["actionable", "review", "excluded", "all"] = Query(
            "actionable", description="actionable outreach list (default), review queue, excluded, or all"),
        band: list[Literal["High", "Medium", "Low"]] = Query(default_factory=list),
        ownership: list[Literal["high", "medium", "low"]] = Query(default_factory=list),
        min_priority: float | None = Query(None, ge=0, le=100),
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        total, rows = store.search_accounts(
            q=q, segment=segment, signals=signal, tiers=tier, countries=country, min_priority=min_priority,
            view=view, bands=list(band), ownership=list(ownership), limit=limit, offset=offset,
        )
        return {"total": total, "limit": limit, "offset": offset, "view": view,
                "items": [_account_item(r, signal_names) for r in rows]}

    @app.get("/signals")
    def signals() -> dict[str, Any]:
        return {"labels": LABELS, "signals": store.registry()}

    def _successor_or_404(account_id: str, suffix: str, request: Request) -> RedirectResponse:
        """Temporary redirect from an older build's account id to its current id (`successor_ids`)."""
        successor = store.resolve_account_id(account_id)
        if successor is None or successor == account_id:
            raise HTTPException(status_code=404, detail="account not found")
        url = "/accounts/" + quote(successor, safe=":") + suffix
        if request.url.query:
            url += "?" + request.url.query
        return RedirectResponse(url, status_code=307)

    # Declared before the detail route: `{account_id:path}` is greedy.
    @app.get("/accounts/{account_id:path}/evidence")
    def account_evidence(
        account_id: str,
        request: Request,
        signal: str | None = Query(None, max_length=32),
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
    ) -> Any:
        if store.get_account(account_id) is None:
            # The greedy path cannot tell evidence of `X` from an id `X/evidence`; never redirect then.
            if store.resolve_account_id(account_id + "/evidence") is not None:
                raise HTTPException(status_code=404, detail="account not found")
            return _successor_or_404(account_id, "/evidence", request)
        total, rows = store.account_evidence(account_id, signal=signal, limit=limit, offset=offset)
        return {
            "account_id": account_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "labels": LABELS,
            "disclaimer": DISCLAIMER,
            "items": [_evidence_item(r) for r in rows],
        }

    @app.get("/accounts/{account_id:path}")
    def account_detail(account_id: str, request: Request) -> Any:
        row = store.get_account(account_id)
        if row is None:
            return _successor_or_404(account_id, "", request)
        body = _account_item(row, signal_names)
        body["explanation"] = list(row["explanation"] or [])
        body["scoring_version"] = row["scoring_version"]
        body["eligibility_version"] = row["eligibility_version"]
        body["signals"] = [
            {**s, "details": list(s["details"] or []), "sub_flags": list(s["sub_flags"] or [])}
            for s in store.account_signals(account_id)
        ]
        body["labels"] = LABELS
        body["disclaimer"] = DISCLAIMER
        return body

    return app


def __getattr__(name: str) -> Any:
    # `uvicorn firmable.api.app:app` builds the app lazily from $FIRMABLE_SERVING_DB,
    # so importing this module (e.g. in tests) needs no serving DB.
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
