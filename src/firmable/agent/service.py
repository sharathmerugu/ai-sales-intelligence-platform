"""Brief service: cache, deduplicate, rate-limit and run agent jobs in the API process.

Cache key = hash of (kind, account, snapshot, evidence digest, seller lens + playbook version, access
scope, follow-up question and focus finding, prompt / tool / validator / semantic / model versions).
Any change to the evidence, scores, wording, seller context, access scope or a generation version gives
a new key, so stale output is never served as current. A delivered run is re-checked against the
caller's scope and the current evidence digest.

Jobs run on a small thread pool inside the API process: the smallest addition that fits the single
Railway service. Durable job state lives in SQLite (`runs.py`); a multi-replica deployment would move
it to Postgres with the same table shapes (docs/agentic-briefs.md §8).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from ..logs import log
from ..semantic.layer import SemanticLayer
from .config import AgentConfig
from .llm import LLMClient, make_client
from .loop import InvestigationAgent, versions
from .runs import RunStore
from .tools import ToolContext

MAX_QUESTION_CHARS = 300


def normalize_question(q: str) -> str:
    return re.sub(r"\s+", " ", q or "").strip()


class BriefService:
    def __init__(self, semantic: SemanticLayer, config: AgentConfig, runs: RunStore | None = None,
                 client: LLMClient | None = None):
        self.semantic = semantic
        self.config = config
        self.runs = runs or RunStore(config.app_db)
        self.client = client if client is not None else (make_client(config) if config.enabled else None)
        self.agent = InvestigationAgent(semantic, self.client, config)
        self.pool = ThreadPoolExecutor(max_workers=max(1, config.workers), thread_name_prefix="agent")
        self.futures: dict[str, Future] = {}
        recovered = self.runs.recover_interrupted()
        if recovered:
            log("agent.recovered", runs=recovered)

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.runs.close()

    # -- identity -----------------------------------------------------------------

    def cache_key(self, kind: str, account_id: str, use_case: str | None, scope: str, question: str | None = None,
                  signal_id: str | None = None) -> tuple[str, str]:
        digest = self.semantic.context_digest(account_id)
        playbook = self.semantic.get_seller_playbook(use_case)
        payload = {
            "kind": kind, "account_id": account_id, "snapshot_id": self.semantic.snapshot.snapshot_id,
            "evidence_digest": digest, "use_case": use_case, "playbook": [playbook.id, playbook.version],
            "scope": scope, "question": normalize_question(question or "").lower() or None, "signal_id": signal_id,
            "versions": versions(self.config),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:40], digest

    def _ctx(self, account_id: str, use_case: str | None, scope: str, mode: str = "brief",
             question: str | None = None, signal_id: str | None = None) -> ToolContext:
        return ToolContext(account_id=account_id, snapshot_id=self.semantic.snapshot.snapshot_id, use_case=use_case,
                           scope=scope, mode=mode, question=question, focus_signal=signal_id)

    # -- requests -----------------------------------------------------------------

    def request(self, *, kind: str, account_id: str, use_case: str | None, scope: str, question: str | None = None,
                signal_id: str | None = None, refresh: bool = False) -> dict[str, Any]:
        """Serve a brief (`kind='brief'`) or a follow-up answer (`kind='ask'`): cached output, an existing or new
        job, or the factual fallback. Never blocks on the model."""
        account = self.semantic.get_account(account_id, use_case)
        if account is None:
            raise KeyError(account_id)
        account_id = account.account_id
        mode = "brief" if kind == "brief" else "ask"
        question = normalize_question(question or "")[:MAX_QUESTION_CHARS] or None
        ctx = self._ctx(account_id, use_case, scope, mode, question, signal_id)
        key, digest = self.cache_key(kind, account_id, use_case, scope, question, signal_id)
        base = {"kind": kind, "account_id": account_id, "use_case": use_case, "agent": self.config.public()}

        def fallback(reason: str, run_id: str | None = None, output: dict[str, Any] | None = None) -> dict[str, Any]:
            out = output or self.agent.fallback(ctx, reason, {**versions(self.config), "run_id": run_id})
            return {**base, "state": "fallback", "cache": reason, "run_id": run_id, "output": out}

        if not self.enabled:
            return fallback("llm_disabled")
        if not refresh:
            hit = self.runs.published(key)
            if hit is not None:
                return {**base, "state": "ready", "cache": "hit", "run_id": hit["run_id"], "output": hit["output"]}
        active = self.runs.active_run(key)
        if active is not None:
            return {**base, "state": "pending", "cache": "in_progress", "run_id": active["run_id"],
                    "output": self.agent.fallback(ctx, "pending", versions(self.config)) if kind == "brief" else None}
        last = self.runs.latest_finished(key)
        if last is not None and last["status"] in ("fallback", "failed") and \
                time.time() - last["finished_at"] < self.config.retry_cooldown_s:
            return fallback("cooldown", last["run_id"], last.get("output"))
        if self.runs.runs_since(scope, time.time() - 3600) >= self.config.runs_per_hour:
            return fallback("rate_limited")
        run_id, created = self.runs.create_run(cache_key=key, kind=kind, account_id=account_id,
                                               snapshot_id=self.semantic.snapshot.snapshot_id, use_case=use_case,
                                               scope=scope, context_digest=digest, versions=versions(self.config),
                                               question=question, signal_id=signal_id)
        if created:
            self.futures[run_id] = self.pool.submit(self._execute, run_id, ctx)
        return {**base, "state": "pending", "cache": "miss" if created else "in_progress", "run_id": run_id,
                "output": self.agent.fallback(ctx, "pending", versions(self.config)) if kind == "brief" else None}

    def run_now(self, *, kind: str, account_id: str, use_case: str | None, scope: str, question: str | None = None,
                signal_id: str | None = None) -> dict[str, Any]:
        """Synchronous run for the CLI and evaluation; persisted like any other run. Uses the cache."""
        resp = self.request(kind=kind, account_id=account_id, use_case=use_case, scope=scope, question=question,
                            signal_id=signal_id)
        if resp["state"] == "pending":
            fut = self.futures.get(resp["run_id"])
            if fut is not None:
                fut.result()
            run = self.runs.get_run(resp["run_id"])
            assert run is not None
            return {**resp, "state": "ready" if run["status"] == "succeeded" else "fallback",
                    "output": run["output"], "run": run}
        run = self.runs.get_run(resp["run_id"]) if resp.get("run_id") else None
        return {**resp, "run": run}

    def _execute(self, run_id: str, ctx: ToolContext) -> None:
        self.runs.mark_running(run_id)
        try:
            result = self.agent.run(ctx, run_id)
            self.runs.finish(run_id, status=result.status, disposition=result.disposition, metrics=result.metrics,
                             trace=result.trace, issues=result.issues, output=result.output)
            log("agent.run", run_id=run_id, kind=ctx.mode, account_id=ctx.account_id, use_case=ctx.use_case,
                status=result.status, disposition=result.disposition,
                **{k: result.metrics.get(k) for k in ("model_calls", "tool_calls", "input_tokens", "output_tokens",
                                                      "cache_read_tokens", "retries", "repairs", "cost_usd",
                                                      "latency_ms")})
        except Exception as e:  # never leave a run active; serve the factual fallback
            output = None
            try:
                output = self.agent.fallback(ctx, "internal_error", {**versions(self.config), "run_id": run_id})
            except Exception:
                pass
            self.runs.finish(run_id, status="failed", disposition="internal_error", metrics=None, trace=None,
                             issues=None, output=output, error=f"{type(e).__name__}: {e}"[:500])
            log("agent.run_error", run_id=run_id, error=f"{type(e).__name__}: {e}"[:300])
        finally:
            self.futures.pop(run_id, None)

    def get_run(self, run_id: str, scope: str, include_trace: bool = False) -> dict[str, Any] | None:
        """A run as the API serves it; None when unknown or owned by another scope (no existence leak)."""
        run = self.runs.get_run(run_id)
        if run is None or run["scope"] != scope:
            return None
        stale = run["context_digest"] != self.semantic.context_digest(run["account_id"])
        state = {"queued": "pending", "running": "pending", "succeeded": "ready"}.get(run["status"], "fallback")
        body = {
            "run_id": run_id, "kind": run["kind"], "state": state, "status": run["status"],
            "disposition": run["disposition"], "account_id": run["account_id"], "snapshot_id": run["snapshot_id"],
            "use_case": run["use_case"], "question": run["question"], "created_at": run["created_at"],
            "finished_at": run["finished_at"], "metrics": run["metrics"], "issues": run["issues"],
            "stale": stale, "output": None if stale else run["output"], "versions": run["versions"],
        }
        if include_trace:
            body["trace"] = run["trace"]
        return body
