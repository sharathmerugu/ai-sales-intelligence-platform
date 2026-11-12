"""Deterministic account brief in the agent's card format.

Built only from semantic-layer fields, the seller playbook and the signal registry wording. It is
what the salesperson sees instantly, when no model is configured, while a run is pending, and when a
run fails or is rejected. It passes the same publication checks as an agent brief
(tests/test_agent.py). The serving-v4 report (`api.brief.build_brief`) stays available unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from ..api.brief import BUYER
from ..semantic.layer import SemanticLayer
from ..semantic.models import AccountView, SellerPlaybook, SignalOccurrence
from .tools import EvidenceIndex

FALLBACK_VERSION = 1
MAX_PRODUCTS = 3
REFS_PER_CARD = 3

FOLLOW_UPS = {
    "remote_access": ["Which gateway products did the scan see?", "What ties these services to the organisation?",
                      "How does this account rank for remote access?"],
    "certificate_management": ["Which certificate defects appear here?",
                               "What ties these endpoints to the organisation?",
                               "How does this account rank for certificate management?"],
}
GENERAL_FOLLOW_UPS = ["What ties these services to the organisation?", "Which finding is strongest here?"]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _offering(text: str | None) -> str:
    """'Remote access security (ZTNA, MFA, gateway hardening)' -> 'remote access security'."""
    text = re.sub(r"\s*\(.*?\)", "", text or "").strip()
    return text[:1].lower() + text[1:] if text else "this finding"


def _products(s: SignalOccurrence) -> str:
    items = list(dict.fromkeys(s.products + s.defects))
    if not items:
        return ""
    shown = items[:MAX_PRODUCTS]
    tail = " and others" if len(items) > len(shown) else ""
    return ": " + ", ".join(shown) + tail


def _decision(account: AccountView, lead: SignalOccurrence | None, playbook: SellerPlaybook,
              registry: dict[str, dict[str, Any]], has_lens_finding: bool) -> str:
    code = account.status.code
    lens_gap = bool(playbook.lens_signals) and not has_lens_finding
    if code == "not_a_prospect":
        return "Do not pursue: the backend excludes this account as not an organisation."
    if code == "verify_ownership":
        return "Verify who operates these services before outreach" + (
            f"; no {playbook.offering} finding here." if lens_gap else ".")
    if code == "context_only":
        return ("Monitor this account: no finding is strong enough to open a conversation."
                if not lens_gap else f"Monitor this account: no {playbook.offering} finding here.")
    if lead is None:
        return "Monitor this account: no security finding is linked to it."
    if lens_gap:
        return (f"No {playbook.offering} finding here; lead with "
                f"{_offering(registry.get(lead.signal_id, {}).get('offering'))}.")
    if lead.signal_id in playbook.lens_signals:
        return f"Lead with {playbook.offering}."
    return f"Lead with {_offering(registry.get(lead.signal_id, {}).get('offering'))}."


def _action(account: AccountView, s: SignalOccurrence, playbook: SellerPlaybook,
            registry: dict[str, dict[str, Any]], used: set[str], first: bool) -> tuple[str, str]:
    """(action, discovery question); questions already used on an earlier card are skipped."""
    reg = registry.get(s.signal_id, {})
    in_lens = s.signal_id in playbook.lens_signals
    pool = (list(playbook.discovery_questions) if in_lens and not used else []) + list(reg.get("discovery_questions") or [])
    fresh = [q for q in dict.fromkeys(pool) if q not in used] or ["Who owns these services?"]
    q1 = fresh[0]
    q2 = fresh[1] if len(fresh) > 1 else q1
    used.update({q1, q2})
    code = account.status.code
    if code == "verify_ownership":
        if first:
            return ("Verify who operates these services: check the addresses against the organisation's DNS or ask "
                    "its IT team.", q1)
        return f"Include the {s.name.lower()} in the same ownership check.", q1
    if code in ("context_only", "not_a_prospect") or s.context_only:
        if first:
            return "Keep this as account context; recheck it after the next scan.", q1
        return f"Note the {s.name.lower()} beside the first finding; they need no separate outreach.", q1
    buyer = playbook.buyers[0] if in_lens and playbook.buyers else BUYER.get(s.signal_id, "the CISO")
    buyer = buyer if buyer.startswith("the ") else "the " + buyer
    return f"Ask {buyer}: “{q1}”", q2


def fallback_draft(semantic: SemanticLayer, account: AccountView, use_case: str | None,
                   playbook: SellerPlaybook) -> tuple[dict[str, Any], EvidenceIndex, list[SignalOccurrence]]:
    """(draft in submit_brief shape, the evidence it cites, the account's signals)."""
    signals = semantic.signal_occurrences(account.account_id, use_case)
    security = [s for s in signals if not s.context_only]
    chosen = security[:3] if security else signals[:1]
    if account.status.code == "not_a_prospect":
        chosen = []
    has_lens = any(s.signal_id in playbook.lens_signals for s in security)
    evidence = EvidenceIndex()
    cards = []
    used: set[str] = set()
    for s in chosen:
        page = semantic.get_signal_evidence(account.account_id, s.signal_id, limit=REFS_PER_CARD)
        refs = [e.observation_id for e in (page.items if page else [])]
        for e in page.items if page else []:
            evidence.add(e)
        action, question = _action(account, s, playbook, semantic.registry, used, not cards)
        cards.append({
            "signal_id": s.signal_id,
            "headline": f"{s.name}: {_plural(s.n_services, 'service')}",
            "finding": (f"{_plural(s.n_services, 'service')} on {_plural(s.n_ips, 'IP address', 'IP addresses')}"
                        f"{_products(s)}."),
            "relevance": playbook.signal_angles.get(s.signal_id)
                         or (semantic.registry.get(s.signal_id, {}).get("pitch") or "").split(". ")[0].rstrip(".") + ".",
            "action": action,
            "evidence_refs": refs,
            "discovery_question": question,
        })
    draft = {
        "snapshot_id": semantic.snapshot.snapshot_id,
        "decision": _decision(account, security[0] if security else None, playbook, semantic.registry, has_lens),
        "cards": cards,
        "follow_up_questions": FOLLOW_UPS.get(use_case or "", GENERAL_FOLLOW_UPS)[:3],
    }
    return draft, evidence, signals
