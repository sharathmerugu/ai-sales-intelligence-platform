"""The agent's tools: semantic-layer queries bound to one account, snapshot, lens and access scope.

The server binds the account, snapshot, seller lens and access scope (`ToolContext`); tool arguments
can narrow a query (which signal, which page) but never widen it. Arguments outside a tool's schema are
rejected, so a model cannot ask for another account. Every evidence row a tool returns is recorded in
the run's ledger: a published claim may cite only rows the agent actually retrieved.

Tool results are JSON data. Scanner text inside them (page titles, product strings, hostnames) is
untrusted and is never treated as an instruction.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..semantic.layer import SemanticLayer
from ..semantic.models import EvidenceItem, SignalOccurrence, dump

TOOLS_VERSION = 1
MAX_EVIDENCE_PER_CALL = 10
MAX_TEXT = 160

_CARD = {
    "type": "object",
    "properties": {
        "signal_id": {"type": "string", "description": "the finding this card is about (e.g. S01)"},
        "headline": {"type": "string", "description": "under 12 words, states the finding or the move"},
        "finding": {"type": "string", "description": "what we found: one or two sentences of supported fact"},
        "relevance": {"type": "string", "description": "why it matters for this seller's offering: one sentence"},
        "action": {"type": "string", "description": "what to do next: one imperative sentence"},
        "evidence_refs": {"type": "array", "items": {"type": "string"},
                          "description": "observation_ids retrieved with get_signal_evidence that support the finding"},
        "discovery_question": {"type": "string", "description": "one question for the call, ending with '?'"},
    },
    "required": ["signal_id", "headline", "finding", "relevance", "action", "evidence_refs", "discovery_question"],
    "additionalProperties": False,
}

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "get_account",
        "description": "The account under investigation: name, segment, research status (from the backend gate), "
                       "ownership assessment with its reasons and review flags, rank and priority summary, and the "
                       "lens rank for the seller's use case. Takes no arguments: the account is fixed.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_signals",
        "description": "Findings (signal occurrences) on this account, lens findings first: service and IP counts, "
                       "products or defects seen, whether it is in the seller's lens, evidence coverage "
                       "(rows, counted, suppressed) and observation dates. Returns total and a page.",
        "input_schema": {"type": "object", "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            "offset": {"type": "integer", "minimum": 0}}, "additionalProperties": False},
    },
    {
        "name": "get_signal_evidence",
        "description": "Endpoint records behind one finding on this account: observation_id, observation time, "
                       "the observed fact, service (ip, port, TLS name, product, page title), match basis, "
                       "whether it is counted or suppressed by a stronger finding, and how it is linked to the "
                       "account (tier, confidence, reasons, domains). `complete` is false when more rows exist. "
                       "Cite observation_ids from here in the brief.",
        "input_schema": {"type": "object", "properties": {
            "signal_id": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVIDENCE_PER_CALL},
            "offset": {"type": "integer", "minimum": 0}},
            "required": ["signal_id"], "additionalProperties": False},
    },
    {
        "name": "explain_priority",
        "description": "Why the account ranks where it does: backend rank, band, percentile, the scoring-v3 "
                       "components, the lens rank, and the gate blockers. These are computed values: report "
                       "them, never recompute them.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_seller_playbook",
        "description": "The seller's offering for the selected use case: buyers, value angle, approved "
                       "positioning, why each finding matters for this offering, discovery questions and claims "
                       "to avoid.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]

SUBMIT_BRIEF = {
    "name": "submit_brief",
    "description": "Publish the account brief. Call once, after investigating. The server checks every ID, "
                   "number, product name and claim against the records you retrieved and rejects unsupported "
                   "or contradictory text with reasons you must fix.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string"},
            "decision": {"type": "string", "description": "one sentence: the move for this account"},
            "cards": {"type": "array", "items": _CARD, "description": "1 to 3 findings, strongest for the seller first"},
            "follow_up_questions": {"type": "array", "items": {"type": "string"},
                                    "description": "2 to 4 short questions the salesperson could ask you next"},
        },
        "required": ["snapshot_id", "decision", "cards", "follow_up_questions"],
        "additionalProperties": False,
    },
}

SUBMIT_ANSWER = {
    "name": "submit_answer",
    "description": "Publish the answer to the salesperson's follow-up question. The server checks it like a brief.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string"},
            "answer": {"type": "string", "description": "direct answer, at most 60 words"},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "follow_up_questions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["snapshot_id", "answer", "evidence_refs", "follow_up_questions"],
        "additionalProperties": False,
    },
}

RETRIEVAL_TOOLS = frozenset(t["name"] for t in TOOL_SPECS)


def tool_specs(mode: str) -> list[dict[str, Any]]:
    return [*TOOL_SPECS, SUBMIT_BRIEF if mode == "brief" else SUBMIT_ANSWER]


@dataclass
class ToolContext:
    """Server-bound scope of one run. Nothing here comes from the model."""
    account_id: str
    snapshot_id: str | None
    use_case: str | None
    scope: str
    mode: str = "brief"                 # brief | ask
    question: str | None = None
    focus_signal: str | None = None


class EvidenceIndex:
    """Retrieved evidence keyed by (observation_id, signal_id): one banner can support several signals."""

    def __init__(self, items: list[EvidenceItem] | None = None):
        self._by: dict[tuple[str, str], EvidenceItem] = {}
        for e in items or []:
            self.add(e)

    def add(self, e: EvidenceItem) -> None:
        self._by[(e.observation_id, e.signal_id)] = e

    def get(self, observation_id: str, signal_id: str | None = None) -> EvidenceItem | None:
        if signal_id is not None:
            return self._by.get((observation_id, signal_id))
        return next((e for (o, _), e in self._by.items() if o == observation_id), None)

    def signals_of(self, observation_id: str) -> set[str]:
        return {s for (o, s) in self._by if o == observation_id}

    def values(self) -> list[EvidenceItem]:
        return list(self._by.values())

    def __len__(self) -> int:
        return len(self._by)


@dataclass
class Ledger:
    evidence: EvidenceIndex = field(default_factory=EvidenceIndex)
    signals: dict[str, SignalOccurrence] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def called(self, name: str) -> bool:
        return any(c["name"] == name and c["ok"] for c in self.calls)


class ToolError(Exception):
    pass


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_TEXT:
        return value[:MAX_TEXT] + "…"
    return value


def _evidence_for_model(e: EvidenceItem) -> dict[str, Any]:
    s = e.service
    return {
        "observation_id": e.observation_id, "signal_id": e.signal_id, "observed_at": e.observed_at,
        "observed_fact": _clip(e.observed_fact),
        "service": {"ip": s.ip, "port": s.port, "transport": s.transport, "tls_name": _clip(s.sni) or None,
                    "product": _clip(s.product), "version": _clip(s.version), "page_title": _clip(s.http_title),
                    "scanner_probe": s.module, "country": s.country_code, "cdn": s.is_cdn},
        "match_basis": e.match_basis, "detail": _clip(e.detail), "defects": e.sub_flags,
        "counted": e.counted, "suppressed_by": e.suppressed_by,
        "link": {"tier": e.attribution_tier, "confidence": e.attribution_confidence,
                 "reasons": e.attribution_reasons, "domains": [_clip(d) for d in e.attribution_domains[:5]]},
    }


def _int_arg(args: dict[str, Any], name: str, default: int, lo: int, hi: int) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError(f"`{name}` must be an integer")
    if not lo <= value <= hi:
        raise ToolError(f"`{name}` must be between {lo} and {hi}")
    return value


class ToolExecutor:
    def __init__(self, semantic: SemanticLayer, ctx: ToolContext):
        self.semantic = semantic
        self.ctx = ctx
        self.ledger = Ledger()
        # Snapshot consistency: a run reads one snapshot; a swapped serving DB fails the run.
        if ctx.snapshot_id != semantic.snapshot.snapshot_id:
            raise ToolError(f"run is bound to snapshot {ctx.snapshot_id}, store serves "
                            f"{semantic.snapshot.snapshot_id}")

    def _check_args(self, name: str, args: Any) -> dict[str, Any]:
        spec = next(t for t in TOOL_SPECS if t["name"] == name)
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        allowed = set(spec["input_schema"]["properties"])
        extra = sorted(set(args) - allowed)
        if extra:
            raise ToolError(f"unexpected argument(s) {extra}: the account, snapshot and seller are fixed by the "
                            "server and cannot be changed")
        for req in spec["input_schema"].get("required", []):
            if req not in args:
                raise ToolError(f"missing required argument `{req}`")
        return args

    def execute(self, name: str, args: Any) -> tuple[str, bool]:
        """Run one tool; returns (JSON content, is_error). Never raises for model mistakes."""
        started = time.perf_counter()
        ok, summary = True, ""
        try:
            if name not in RETRIEVAL_TOOLS:
                raise ToolError(f"unknown tool `{name}`")
            args = self._check_args(name, args)
            data = getattr(self, f"_t_{name}")(args)
            summary = data.pop("_summary", "")
            content = json.dumps({"snapshot_id": self.ctx.snapshot_id, "data": data}, default=str)
        except ToolError as e:
            ok = False
            content = json.dumps({"error": str(e)})
        self.ledger.calls.append({"name": name, "input": args if isinstance(args, dict) else str(args), "ok": ok,
                                  "ms": round((time.perf_counter() - started) * 1000, 1), "result": summary})
        return content, not ok

    # -- tools -------------------------------------------------------------------

    def _t_get_account(self, args: dict[str, Any]) -> dict[str, Any]:
        a = self.semantic.get_account(self.ctx.account_id, self.ctx.use_case)
        if a is None:
            raise ToolError("account not found")
        d = dump(a)
        d.pop("snapshot", None)
        d["_summary"] = f"status {a.status.code}, ownership {a.ownership.level}"
        return d

    def _signals(self) -> list[SignalOccurrence]:
        items = self.semantic.signal_occurrences(self.ctx.account_id, self.ctx.use_case)
        for s in items:
            self.ledger.signals[s.signal_id] = s
        return items

    def _t_list_signals(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = _int_arg(args, "limit", 10, 1, 20)
        offset = _int_arg(args, "offset", 0, 0, 10_000)
        items = self._signals()
        page = items[offset:offset + limit]
        return {"total": len(items), "offset": offset, "limit": limit,
                "items": [{k: v for k, v in dump(s).items() if k != "occurrence_id"} for s in page],
                "_summary": f"{len(page)} of {len(items)} signals"}

    def _t_get_signal_evidence(self, args: dict[str, Any]) -> dict[str, Any]:
        signal_id = args.get("signal_id")
        if not isinstance(signal_id, str):
            raise ToolError("`signal_id` must be a string")
        known = {s.signal_id for s in self._signals()}
        if signal_id not in known:
            raise ToolError(f"signal {signal_id!r} is not on this account; its signals are {sorted(known)}")
        limit = _int_arg(args, "limit", 5, 1, MAX_EVIDENCE_PER_CALL)
        offset = _int_arg(args, "offset", 0, 0, 100_000)
        page = self.semantic.get_signal_evidence(self.ctx.account_id, signal_id, limit=limit, offset=offset)
        assert page is not None
        for e in page.items:
            self.ledger.evidence.add(e)
        return {"signal_id": signal_id, "total": page.total, "counted_total": page.counted_total,
                "suppressed_total": page.suppressed_total, "offset": offset, "returned": len(page.items),
                "complete": page.complete, "items": [_evidence_for_model(e) for e in page.items],
                "_summary": f"{signal_id}: {len(page.items)} of {page.total} rows"}

    def _t_explain_priority(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self.semantic.explain_priority(self.ctx.account_id, self.ctx.use_case)
        if p is None:
            raise ToolError("account not found")
        d = dump(p)
        d["_summary"] = f"rank {p.rank}"
        return d

    def _t_get_seller_playbook(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self.semantic.get_seller_playbook(self.ctx.use_case)
        d = dump(p)
        d["_summary"] = p.id
        return d
