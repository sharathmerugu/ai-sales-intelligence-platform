"""Turn a checked draft into the published brief / answer the API serves.

The model writes words; code attaches every number the UI shows as a field: status, priority, ownership
confidence, observation dates and evidence links all come from the semantic layer, never from the model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..semantic.models import AccountView, EvidenceItem, SellerPlaybook, SignalOccurrence
from .tools import EvidenceIndex

BRIEF_SCHEMA_VERSION = 1


def _evidence_link(e: EvidenceItem) -> dict[str, Any]:
    s = e.service
    label = f"{s.ip}:{s.port}/{s.transport}" + (f" · {s.sni}" if s.sni else "")
    return {"observation_id": e.observation_id, "signal_id": e.signal_id, "observed_at": e.observed_at,
            "service": label, "product": s.product, "counted": e.counted}


def _observed(items: list[EvidenceItem], s: SignalOccurrence | None) -> dict[str, str | None]:
    dates = sorted(e.observed_at for e in items if e.observed_at)
    if dates:
        return {"first": dates[0], "last": dates[-1]}
    return {"first": s.first_observed if s else None, "last": s.last_observed if s else None}


def publish_brief(draft: dict[str, Any], *, kind: str, account: AccountView, signals: list[SignalOccurrence],
                  evidence: EvidenceIndex, playbook: SellerPlaybook, generation: dict[str, Any],
                  issues_repaired: int = 0, fallback_reason: str | None = None) -> dict[str, Any]:
    by_id = {s.signal_id: s for s in signals}
    cards = []
    for card in draft["cards"]:
        s = by_id.get(card["signal_id"])
        items = [e for e in (evidence.get(r, card["signal_id"]) for r in card["evidence_refs"]) if e is not None]
        cards.append({
            "signal_id": card["signal_id"],
            "signal_name": s.name if s else card["signal_id"],
            "in_lens": card["signal_id"] in playbook.lens_signals,
            "headline": card["headline"],
            "finding": card["finding"],
            "relevance": card["relevance"],
            "action": card["action"],
            "discovery_question": card["discovery_question"],
            "confidence": {"ownership": account.ownership.label, "ownership_level": account.ownership.level},
            "observed": _observed(items, s),
            "counts": None if s is None else {"services": s.n_services, "ips": s.n_ips,
                                              "evidence_rows": s.evidence_rows},
            "evidence": [_evidence_link(e) for e in items],
        })
    return {
        "schema_version": BRIEF_SCHEMA_VERSION,
        "kind": kind,                                   # agent | fallback
        "fallback_reason": fallback_reason,
        "account_id": account.account_id,
        "account_name": account.name,
        "snapshot_id": account.snapshot.snapshot_id,
        "scan_date": account.snapshot.scan_date,
        "use_case": playbook.use_case,
        "offering": playbook.offering,
        "status": account.status.model_dump(),
        "decision": draft["decision"],
        "priority_summary": account.priority_summary,
        "ownership": {"label": account.ownership.label, "level": account.ownership.level,
                      "summary": account.ownership.summary},
        "cards": cards,
        "follow_up_questions": list(draft.get("follow_up_questions") or []),
        "checks": {"passed": True, "issues_repaired": issues_repaired},
        "generation": {**generation, "published_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }


def publish_answer(draft: dict[str, Any], *, kind: str, account: AccountView, evidence: EvidenceIndex,
                   question: str, focus_signal: str | None, generation: dict[str, Any],
                   fallback_reason: str | None = None) -> dict[str, Any]:
    items = [e for e in (evidence.get(r) for r in draft.get("evidence_refs") or []) if e is not None]
    return {
        "schema_version": BRIEF_SCHEMA_VERSION,
        "kind": kind,
        "fallback_reason": fallback_reason,
        "account_id": account.account_id,
        "snapshot_id": account.snapshot.snapshot_id,
        "question": question,
        "signal_id": focus_signal,
        "answer": draft["answer"],
        "evidence": [_evidence_link(e) for e in items],
        "follow_up_questions": list(draft.get("follow_up_questions") or [])[:4],
        "generation": {**generation, "published_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }
