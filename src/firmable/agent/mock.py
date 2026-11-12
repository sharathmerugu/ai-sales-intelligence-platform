"""`mock-heuristic`: a deterministic, offline stand-in for the model (FIRMABLE_LLM_PROVIDER=mock).

It drives the real loop through the real tools: it reads the account, findings and playbook, decides
which evidence to fetch (lens findings first; the priority explanation when ownership is unresolved),
then writes a brief from what the tools returned. It exists to test and demonstrate the harness
(tool use, budgets, checks, persistence, UI) without credentials. It is not a language model and its
output says nothing about model quality; runs record `mock-heuristic` as the model.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .llm import LLMResponse, Usage

ACTIONS = {
    "S01": "Ask {buyer} how access through these gateways is controlled.",
    "S03": "Ask {buyer} who can reach these admin logins from outside.",
    "S04": "Ask {buyer} who owns these data stores and who can reach them.",
    "S05": "Ask {buyer} who manages these consoles and who can reach them.",
    "S06": "Ask {buyer} who renews these certificates and how expiry is tracked.",
    "S16": "Map {buyer}'s current vendors before positioning against them.",
}
KEYWORDS = [("S06", r"certif|tls|ssl|expir"), ("S01", r"gateway|vpn|remote|firewall"), ("S03", r"rdp|admin|vnc|ssh"),
            ("S04", r"data|database|storage"), ("S05", r"console|devops"), ("S16", r"vendor|waf|cdn|competit")]
FOLLOW_UPS = {
    "remote_access": ["Which gateway products did the scan see?", "What ties these services to the organisation?"],
    "certificate_management": ["Which certificate defects appear here?",
                               "What ties these endpoints to the organisation?"],
}


def _n(n: int, one: str) -> str:
    return f"{n:,} {one}" + ("" if n == 1 else ("es" if one.endswith("ss") else "s"))


def _tool_results(messages: list[dict[str, Any]]) -> tuple[list[tuple[str, dict[str, Any], Any]], list[str]]:
    """[(tool name, input, parsed result)] in order, and the error texts of the last submission."""
    names: dict[str, tuple[str, dict[str, Any]]] = {}
    out: list[tuple[str, dict[str, Any], Any]] = []
    submit_errors: list[str] = []
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            b = b if isinstance(b, dict) else getattr(b, "model_dump", lambda: {})()
            if b.get("type") == "tool_use":
                names[b["id"]] = (b["name"], b.get("input") or {})
            elif b.get("type") == "tool_result":
                name, args = names.get(b["tool_use_id"], ("?", {}))
                if name.startswith("submit_"):
                    submit_errors = [b.get("content", "")] if b.get("is_error") else []
                    continue
                try:
                    out.append((name, args, json.loads(b.get("content") or "{}")))
                except json.JSONDecodeError:
                    out.append((name, args, {}))
    return out, submit_errors


class HeuristicModel:
    model = "mock-heuristic"

    def __init__(self) -> None:
        self._n = 0

    def _use(self, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        self._n += 1
        return {"type": "tool_use", "id": f"mock_{self._n}", "name": name, "input": args or {}}

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout: float) -> LLMResponse:
        blocks = self._decide(messages, tools)
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
        chars = sum(len(json.dumps(m.get("content"), default=str)) for m in messages)
        return LLMResponse(blocks=blocks, stop_reason=stop, usage=Usage(input_tokens=chars // 4, output_tokens=150),
                           model=self.model)

    def _decide(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        mode = "answer" if any(t["name"] == "submit_answer" for t in tools) else "brief"
        first = messages[0]["content"] if isinstance(messages[0]["content"], str) else ""
        question = (re.search(r"<question>(.*?)</question>", first, re.S) or [None, ""])[1]
        focus = (re.search(r"Focus finding: (S\d\d)", first) or [None, None])[1]
        results, submit_errors = _tool_results(messages)
        data = {name: r.get("data") for name, _, r in results if isinstance(r, dict) and "data" in r}
        if not {"get_account", "list_signals", "get_seller_playbook"} <= set(data):
            return [self._use(n) for n in ("get_account", "list_signals", "get_seller_playbook") if n not in data]
        account, signals, playbook = data["get_account"], data["list_signals"]["items"], data["get_seller_playbook"]
        evidence: dict[str, list[dict[str, Any]]] = {}
        for name, args, r in results:
            if name == "get_signal_evidence" and isinstance(r, dict) and "data" in r:
                evidence.setdefault(args["signal_id"], []).extend(r["data"]["items"])
        security = [s for s in signals if not s["context_only"]] or signals[:1]
        if mode == "answer":
            pick = [s for s in signals if s["signal_id"] == focus]
            if not pick:
                for sid, pattern in KEYWORDS:
                    if re.search(pattern, question, re.I):
                        pick = [s for s in signals if s["signal_id"] == sid]
                        break
            pick = pick[:1] or security[:1]
        else:
            lens = [s for s in security if s["in_lens"]]
            pick = (lens + [s for s in security if not s["in_lens"]])[:2]
        if account["status"]["code"] == "not_a_prospect":
            pick = []
        wanted = [s for s in pick if s["signal_id"] not in evidence]
        if wanted:
            return [self._use("get_signal_evidence", {"signal_id": s["signal_id"], "limit": 3}) for s in wanted]
        if account["status"]["code"] == "verify_ownership" and "explain_priority" not in data:
            return [self._use("explain_priority")]
        snapshot = next((r.get("snapshot_id") for _, _, r in results if isinstance(r, dict) and "snapshot_id" in r), None)
        if mode == "answer":
            return [self._use("submit_answer", {**self._answer(account, pick, evidence, question),
                                                "snapshot_id": snapshot})]
        draft = {**self._brief(account, pick, evidence, playbook), "snapshot_id": snapshot}
        if submit_errors:  # repair: drop the cards the server rejected, keep the rest
            bad = {int(i) for i in re.findall(r"cards\[(\d)\]", submit_errors[0])}
            draft["cards"] = [c for i, c in enumerate(draft["cards"]) if i not in bad] or draft["cards"][:1]
        return [self._use("submit_brief", draft)]

    @staticmethod
    def _products(sig: dict[str, Any], items: list[dict[str, Any]]) -> list[str]:
        if sig["signal_id"] == "S06":
            return sig["defects"][:3] or sig["products"][:3]
        seen = [i["service"]["product"] for i in items if i["service"].get("product")]
        return list(dict.fromkeys(seen + sig["products"]))[:3]

    def _brief(self, account: dict[str, Any], pick: list[dict[str, Any]], evidence: dict[str, list[dict[str, Any]]],
               playbook: dict[str, Any]) -> dict[str, Any]:
        code, offering = account["status"]["code"], playbook["offering"]
        lead = pick[0] if pick else None
        lens_lead = lead is not None and lead["signal_id"] in playbook["lens_signals"]
        gap = f"; no {offering} finding here" if playbook["lens_signals"] and not lens_lead else ""
        if code == "not_a_prospect":
            decision = "Do not pursue: the backend excludes this record as not an organisation."
        elif code == "verify_ownership":
            decision = (f"Verify who operates these {lead['name'].lower()} before outreach{gap}." if lead
                        else f"Verify who operates these services before outreach{gap}.")
        elif code == "context_only":
            decision = f"Monitor this account: nothing here is strong enough to open a conversation{gap}."
        elif lead is None:
            decision = "Monitor this account: no security finding is linked to it."
        elif playbook["lens_signals"] and not lens_lead:
            decision = f"No {offering} finding here; lead with the {lead['name'].lower()}."
        elif not playbook["lens_signals"]:
            decision = f"Lead with the {lead['name'].lower()}: the strongest finding on this account."
        else:
            decision = (f"Lead with {offering}: {_n(lead['n_services'], 'exposed service')} "
                        f"{'gives' if lead['n_services'] == 1 else 'give'} you the opening.")
        cards = []
        buyer = "the " + (playbook["buyers"][0] if playbook["buyers"] else "CISO")
        for i, s in enumerate(pick):
            items = evidence.get(s["signal_id"], [])
            products = self._products(s, items)
            seen = f"{', '.join(products)} on " if products else ""
            if code == "verify_ownership":
                action = ("Verify ownership: match these addresses to the company's DNS records or ask its IT team."
                          if i == 0 else f"Include the {s['name'].lower()} in the same check.")
            elif code in ("context_only", "not_a_prospect"):
                action = "Keep this as context; recheck after the next scan." if i == 0 else \
                    f"Note the {s['name'].lower()} as context only."
            else:
                action = ACTIONS.get(s["signal_id"], "Ask {buyer} who owns these services.").format(buyer=buyer)
            questions = [q for q in playbook["discovery_questions"] if q] or ["Who owns these services?"]
            cards.append({
                "signal_id": s["signal_id"],
                "headline": f"{s['name']} on {_n(s['n_services'], 'service')}",
                "finding": f"The scan saw {seen}{_n(s['n_services'], 'service')} across {_n(s['n_ips'], 'IP address')}.",
                "relevance": playbook["signal_angles"].get(s["signal_id"], "This is a concrete security opening."),
                "action": action,
                "evidence_refs": [x["observation_id"] for x in items[:3]],
                "discovery_question": questions[i % len(questions)],
            })
        return {"snapshot_id": None, "decision": decision, "cards": cards,
                "follow_up_questions": FOLLOW_UPS.get(playbook.get("use_case") or "",
                                                      ["What ties these services to the organisation?"])}

    def _answer(self, account: dict[str, Any], pick: list[dict[str, Any]], evidence: dict[str, list[dict[str, Any]]],
                question: str) -> dict[str, Any]:
        s = pick[0] if pick else None
        items = evidence.get(s["signal_id"], []) if s else []
        if re.search(r"\b(own|tie|link|belong|whose)\w*", question, re.I):
            text = account["ownership"]["summary"]
        elif re.search(r"\brank|priorit", question, re.I):
            text = account["priority_summary"]
        elif s is not None:
            products = self._products(s, items)
            text = (f"The scan saw {', '.join(products) + ' on ' if products else ''}{_n(s['n_services'], 'service')} "
                    f"across {_n(s['n_ips'], 'IP address')}.")
        else:
            text = account["status"]["summary"]
        return {"snapshot_id": None, "answer": text, "evidence_refs": [x["observation_id"] for x in items[:3]],
                "follow_up_questions": ["What ties these services to the organisation?"]}
