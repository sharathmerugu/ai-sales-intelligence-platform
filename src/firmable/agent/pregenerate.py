"""Generate briefs once and keep them (`firmable agent-pregenerate`).

For a fixed snapshot the evidence does not change, so the agent runs once per (account, lens) in a
chosen cohort, plus the follow-up questions each brief suggests, and the checked output is stored in a
SQLite file. The app opens that file read-only (`FIRMABLE_PREGENERATED_DB`) and serves it before anything
else, with no model at serve time. Accounts outside the cohort get the deterministic brief. The run is
resumable: anything already published in the file is a cache hit and is not generated again.

Cohort, per lens (remote access, certificate management): the evaluation cases (`agent_eval.select_cases`),
the top `per_lens` research candidates and the top `verify` ownership-unresolved accounts.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..logs import log
from .service import BriefService

SHARED_SCOPE = "shared:pregenerated"
LENSES = ("remote_access", "certificate_management")


def cohort(service: BriefService, per_lens: int, verify: int = 2) -> list[dict[str, Any]]:
    from ..evaluation.agent_eval import select_cases

    store = service.semantic.store
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(account_id: str, lens: str, why: str) -> None:
        if (account_id, lens) not in seen:
            seen.add((account_id, lens))
            out.append({"account_id": account_id, "use_case": lens, "why": why})

    for case in select_cases(store):
        add(case["account_id"], case["use_case"], f"eval:{case['kind']}")
    for lens in LENSES:
        for r in store.search_accounts(view="research", use_case=lens, limit=per_lens)[1]:
            add(r["account_id"], lens, "top")
        for r in store.search_accounts(view="verify", use_case=lens, limit=verify)[1]:
            add(r["account_id"], lens, "verify")
    # Alternate lenses so a request budget that stops early still covers both prospecting flows.
    by_lens = [[i for i in out if i["use_case"] == lens] for lens in LENSES]
    mixed = [x for pair in zip(*by_lens) for x in pair]
    longest = max(by_lens, key=len)
    return mixed + longest[len(mixed) // 2:]


def pregenerate(service: BriefService, items: list[dict[str, Any]], answers_per_lens: int,
                progress_path: Path, max_requests: int | None = None) -> dict[str, Any]:
    """`max_requests` caps model calls across the whole run (free tiers count requests per day): a new run
    starts only while a full per-run budget still fits."""
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    answered: dict[str, int] = {}
    tally: dict[str, int] = {}
    started = time.time()
    used = 0
    per_run = service.config.max_model_calls + service.config.max_transient_retries

    def budget_left() -> bool:
        return max_requests is None or used + per_run <= max_requests

    with progress_path.open("a") as progress:
        def record(kind: str, item: dict[str, Any], resp: dict[str, Any], question: str | None = None) -> None:
            run = resp.get("run") or {}
            row = {"t": round(time.time() - started, 1), "kind": kind, "account_id": item["account_id"],
                   "use_case": item["use_case"], "question": question, "state": resp["state"],
                   "cache": resp.get("cache"), "disposition": run.get("disposition"),
                   "latency_ms": (run.get("metrics") or {}).get("latency_ms"),
                   "model_calls": (run.get("metrics") or {}).get("model_calls")}
            progress.write(json.dumps(row) + "\n")
            progress.flush()
            key = f"{kind}:{'already_stored' if row['cache'] == 'hit' else row['disposition'] or row['cache']}"
            tally[key] = tally.get(key, 0) + 1
            log("agent.pregenerate", **row)
            nonlocal used
            if row["cache"] != "hit":
                used += (row["model_calls"] or 0) + ((run.get("metrics") or {}).get("retries") or 0)

        for item in items:
            if not budget_left():
                tally["stopped:request_budget"] = tally.get("stopped:request_budget", 0) + 1
                continue
            stored = service.runs.published_by_content(
                service.content_key("brief", item["account_id"], item["use_case"]))
            if stored is not None:  # generated earlier, under any scope
                resp = {"state": "ready", "cache": "hit", "output": stored["output"],
                        "run": service.runs.get_run(stored["run_id"])}
            else:
                resp = service.run_now(kind="brief", account_id=item["account_id"], use_case=item["use_case"],
                                       scope=SHARED_SCOPE)
            record("brief", item, resp)
            out = resp.get("output") or {}
            lens = item["use_case"]
            if out.get("kind") != "agent" or answered.get(lens, 0) >= answers_per_lens:
                continue
            answered[lens] = answered.get(lens, 0) + 1
            for q in (out.get("follow_up_questions") or [])[:3]:
                if not budget_left():
                    break
                a = service.run_now(kind="ask", account_id=item["account_id"], use_case=lens, scope=SHARED_SCOPE,
                                    question=q)
                record("ask", item, a, q)
    return {"items": len(items), "tally": tally, "model_requests": used, "seconds": round(time.time() - started, 1)}
