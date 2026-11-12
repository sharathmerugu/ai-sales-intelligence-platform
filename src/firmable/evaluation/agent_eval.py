"""Repeatable evaluation: agent briefs vs the deterministic briefs (docs/agentic-briefs.md §7).

Cases are chosen by rule from the serving DB, so the same snapshot always gives the same set (account
ids are written to the work directory, never to Git). Per lens (remote access, certificate
management) the set covers: the top research candidates, an ownership-unresolved account, a
context-only account, sparse evidence (one lens service), correlated findings (a suppressed
duplicate), and an account opened under a lens it has no finding for.

Each case is scored three ways on the same automated measures:
- `v4`: the serving-v4 template report (`api.brief.build_brief`), what the page showed before;
- `fallback`: the deterministic brief in card form (`agent.fallback`);
- `agent`: the agent run with the configured provider (`mock` = harness check only).

Automated measures: factual support (publication checks pass, unsupported-claim patterns), signal
emphasis (lens finding leads when one exists), seller relevance (lead relevance names the offering),
next action (present, imperative, consistent with the backend status), conciseness (words, hedges).
Usefulness needs people: `review.csv` has blank columns for reviewer judgments. Operating cost is
taken from the recorded runs (tokens, model calls, latency, retries, cache status, USD at configured
rates). Nothing here is estimated: a mock run reports zero cost because it made no billed call.
"""

from __future__ import annotations

import csv
import json
import statistics
import time
from pathlib import Path
from typing import Any

from ..agent.checks import GO, HEDGE, STOP, UNSUPPORTED, VERIFY, CheckContext, check_brief, words
from ..agent.config import PRICES_SOURCE
from ..agent.fallback import fallback_draft
from ..agent.service import BriefService
from ..agent.tools import EvidenceIndex
from ..api.store import Store
from ..semantic.layer import SemanticLayer

LENSES = ("remote_access", "certificate_management")
EVAL_VERSION = 1
SCOPE = "eval:agent-eval"


def select_cases(store: Store, top: int = 3) -> list[dict[str, Any]]:
    """Deterministic case list (module docstring)."""
    cases: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(lens: str, kind: str, rows: list[dict[str, Any]], n: int = 1) -> None:
        for r in rows:
            if n <= 0:
                break
            key = (lens, r["account_id"])
            if key in seen:
                continue
            seen.add(key)
            cases.append({"case_id": f"{lens}:{kind}:{len(cases) + 1:02d}", "use_case": lens, "kind": kind,
                          "account_id": r["account_id"]})
            n -= 1

    for lens in LENSES:
        add(lens, "top", store.search_accounts(view="research", use_case=lens, limit=top)[1], top)
        add(lens, "verify_ownership", store.search_accounts(view="verify", use_case=lens, limit=5)[1])
        context = store.search_accounts(view="context", use_case=lens, limit=5)[1]
        add(lens, "context_only", context or store.search_accounts(view="context", limit=5)[1])
        research = store.search_accounts(view="research", use_case=lens, limit=5000)[1]
        add(lens, "sparse", [r for r in research if r["uc_n_services"] == 1])
        lens_ids = {r["account_id"] for r in research}
        correlated = store._query(
            "SELECT DISTINCT account_id FROM account_evidence WHERE NOT counted AND suppressed_by IS NOT NULL "
            "AND list_contains(?::VARCHAR[], account_id) ORDER BY account_id", [sorted(lens_ids)])
        add(lens, "correlated", correlated)
        other = "certificate_management" if lens == "remote_access" else "remote_access"
        outside = [r for r in store.search_accounts(view="research", use_case=other, limit=50)[1]
                   if not set(r["signal_ids"] or []) & set(_lens_signals(lens))
                   and r["account_id"] not in lens_ids]
        add(lens, "no_lens_finding", outside)
    return cases


def _lens_signals(lens: str) -> tuple[str, ...]:
    from ..accounts.use_cases import USE_CASES_BY_ID
    return USE_CASES_BY_ID[lens].signals


# -- measures --------------------------------------------------------------------------


def _unsupported(text: str) -> list[str]:
    return [label for label, pattern in UNSUPPORTED if pattern.search(text)]


def _status_ok(status: str, decision: str, actions: list[str]) -> bool:
    if status == "verify_ownership":
        return bool(VERIFY.search(decision)) and not any(GO.search(a) and not VERIFY.search(a) for a in actions)
    if status in ("context_only", "not_a_prospect"):
        return not GO.search(decision) and not any(GO.search(a) for a in actions)
    return not STOP.search(decision)


def measure_cards(brief: dict[str, Any], semantic: SemanticLayer, case: dict[str, Any]) -> dict[str, Any]:
    """Measures for a card-format brief (agent or fallback)."""
    lens = case["use_case"]
    pb = semantic.get_seller_playbook(lens)
    account = semantic.get_account(case["account_id"], lens)
    signals = semantic.signal_occurrences(case["account_id"], lens)
    lens_present = any(s.in_lens and not s.context_only for s in signals)
    cards = brief.get("cards") or []
    lead = cards[0] if cards else None
    ids = [e["observation_id"] for c in cards for e in c.get("evidence", [])]
    evidence = EvidenceIndex(semantic.evidence_by_ids(case["account_id"], ids))
    draft = {"snapshot_id": brief["snapshot_id"], "decision": brief["decision"],
             "cards": [{k: c[k] for k in ("signal_id", "headline", "finding", "relevance", "action",
                                          "discovery_question")} | {"evidence_refs": [e["observation_id"] for e in
                                                                                     c["evidence"]]} for c in cards],
             "follow_up_questions": brief.get("follow_up_questions") or []}
    issues = check_brief(draft, CheckContext(account, signals, evidence, pb, semantic.vocabulary,
                                             semantic.snapshot.snapshot_id, lens))
    text = " ".join([brief["decision"]] + [c[k] for c in cards for k in ("headline", "finding", "relevance", "action")])
    first_card = " ".join(lead[k] for k in ("finding", "relevance", "action")) if lead else ""
    return {
        "checks_pass": not issues,
        "issues": [str(i) for i in issues],
        "unsupported_claims": _unsupported(text),
        "lens_finding_present": lens_present,
        "lead_signal": lead["signal_id"] if lead else None,
        "emphasis_ok": (lead is not None and lead["signal_id"] in pb.lens_signals) if lens_present else True,
        "relevance_ok": bool(lead) and any(k in lead["relevance"].lower() for k in pb.relevance_keywords)
                        if lens_present else True,
        "action_present": bool(lead and lead["action"].strip()) or account.status.code == "not_a_prospect",
        "status_coherent": _status_ok(account.status.code, brief["decision"], [c["action"] for c in cards]),
        "decision_words": words(brief["decision"]),
        "first_card_words": words(first_card),
        "total_words": words(text),
        "hedges": len(HEDGE.findall(text)),
        "cards": len(cards),
        "evidence_links": len(ids),
    }


def measure_v4(v4: dict[str, Any], semantic: SemanticLayer, case: dict[str, Any]) -> dict[str, Any]:
    """The same measures on the serving-v4 template report (its main sections as shown on the page)."""
    lens = case["use_case"]
    pb = semantic.get_seller_playbook(lens)
    account = semantic.get_account(case["account_id"], lens)
    lens_present = any(s.in_lens and not s.context_only for s in semantic.signal_occurrences(case["account_id"], lens))
    lead = (v4.get("findings") or [None])[0]
    lead = next((f for f in v4.get("findings") or [] if not f["context_only"]), lead)
    pitch = v4.get("pitch") or {}
    # "Key threats" is the registry's device-class text ("One unpatched gateway is a direct path…"), a general
    # statement rather than a claim about this account, so it is left out of the claim and length measures.
    sections = [v4.get("summary") or "", *(v4.get("why_target") or []), pitch.get("opener") or "",
                *(pitch.get("talking_points") or []), *(v4.get("action_plan") or [])]
    text = " ".join(sections)
    decision = v4["research_state"]["label"] + ". " + v4["research_state"]["summary"]
    relevance = " ".join([pitch.get("lead_offering") or "", *(pitch.get("talking_points") or [])[:1]]).lower()
    return {
        "checks_pass": None,
        "issues": [],
        "unsupported_claims": _unsupported(text),
        "lens_finding_present": lens_present,
        "lead_signal": lead["signal_id"] if lead else None,
        "emphasis_ok": (lead is not None and lead["signal_id"] in pb.lens_signals) if lens_present else True,
        "relevance_ok": any(k in relevance for k in pb.relevance_keywords) if lens_present else True,
        "action_present": bool(v4.get("action_plan")),
        "status_coherent": _status_ok(account.status.code, decision, v4.get("action_plan") or []),
        "decision_words": words(decision),
        "first_card_words": words(" ".join([v4.get("summary") or "", (v4.get("action_plan") or [""])[0]])),
        "total_words": words(text),
        "hedges": len(HEDGE.findall(text)),
        "cards": len(v4.get("threats") or []),
        "evidence_links": 0,
    }


def _rate(rows: list[dict[str, Any]], key: str) -> str:
    vals = [r[key] for r in rows if r.get(key) is not None]
    return f"{sum(bool(v) for v in vals)}/{len(vals)}" if vals else "n/a"


def _median(rows: list[dict[str, Any]], key: str) -> float | None:
    vals = [r[key] for r in rows if r.get(key) is not None]
    return round(statistics.median(vals), 1) if vals else None


def run_eval(semantic: SemanticLayer, service: BriefService, out_dir: Path, cases: list[dict[str, Any]] | None = None,
             max_cost_usd: float | None = None, scope: str | None = None) -> dict[str, Any]:
    scope = scope or SCOPE
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = cases or select_cases(semantic.store)
    (out_dir / "cases.json").write_text(json.dumps(cases, indent=1))
    results: list[dict[str, Any]] = []
    spent = 0.0
    started = time.time()
    for case in cases:
        if max_cost_usd is not None and spent >= max_cost_usd:
            results.append({"case": case, "skipped": f"cost cap {max_cost_usd} reached"})
            continue
        v4 = semantic.deterministic_brief(case["account_id"], case["use_case"])
        account = semantic.get_account(case["account_id"], case["use_case"])
        pb = semantic.get_seller_playbook(case["use_case"])
        resp = service.run_now(kind="brief", account_id=case["account_id"], use_case=case["use_case"], scope=scope)
        run = resp.get("run") or {}
        metrics = run.get("metrics") or {}
        spent += metrics.get("cost_usd") or 0.0
        draft, _, _ = fallback_draft(semantic, account, case["use_case"], pb)
        fb = service.agent.fallback(service._ctx(case["account_id"], case["use_case"], scope), "eval", {})
        results.append({
            "case": case,
            "status": account.status.code,
            "agent": {"state": resp["state"], "cache": resp.get("cache"), "disposition": run.get("disposition"),
                      "kind": (resp.get("output") or {}).get("kind"), "metrics": metrics,
                      "measures": measure_cards(resp["output"], semantic, case) if resp.get("output") else None,
                      "decision": (resp.get("output") or {}).get("decision"),
                      "lead": ((resp.get("output") or {}).get("cards") or [{}])[0]},
            "fallback": {"measures": measure_cards(fb, semantic, case), "decision": fb["decision"],
                         "lead": (fb["cards"] or [{}])[0]},
            "v4": {"measures": measure_v4(v4, semantic, case), "decision": v4["research_state"]["label"],
                   "summary": v4["summary"]},
            "draft_cards": len(draft["cards"]),
        })
    summary = summarize(results, service, time.time() - started)
    (out_dir / "results.json").write_text(json.dumps({"summary": summary, "results": results}, indent=1, default=str))
    (out_dir / "report.md").write_text(report_md(summary, results))
    write_review_csv(out_dir / "review.csv", results)
    return summary


def summarize(results: list[dict[str, Any]], service: BriefService, seconds: float) -> dict[str, Any]:
    done = [r for r in results if "skipped" not in r]
    out: dict[str, Any] = {
        "eval_version": EVAL_VERSION, "snapshot_id": service.semantic.snapshot.snapshot_id,
        "provider": service.config.provider, "model": service.config.model_label, "cases": len(results),
        "skipped": len(results) - len(done), "wall_seconds": round(seconds, 1),
        "mocked": service.config.provider == "mock",
    }
    for arm in ("agent", "fallback", "v4"):
        rows = [r[arm]["measures"] for r in done if r[arm].get("measures")]
        out[arm] = {k: _rate(rows, k) for k in ("checks_pass", "emphasis_ok", "relevance_ok", "action_present",
                                                "status_coherent")}
        out[arm]["unsupported_claim_cases"] = sum(bool(r["unsupported_claims"]) for r in rows)
        out[arm].update({f"median_{k}": _median(rows, k) for k in ("decision_words", "first_card_words",
                                                                   "total_words", "hedges")})
    runs = [r["agent"]["metrics"] for r in done if r["agent"].get("metrics")]
    published = [r for r in done if r["agent"]["kind"] == "agent"]
    cost = sum(m.get("cost_usd") or 0 for m in runs)
    out["operations"] = {
        "runs_recorded": len(runs),
        "published_by_agent": len(published),
        "fell_back": len(done) - len(published),
        "dispositions": {d: sum(1 for r in done if r["agent"]["disposition"] == d)
                         for d in sorted({str(r["agent"]["disposition"]) for r in done})},
        "cache": {c: sum(1 for r in done if r["agent"]["cache"] == c) for c in sorted({str(r["agent"]["cache"])
                                                                                         for r in done})},
        "model_calls_total": sum(m.get("model_calls", 0) for m in runs),
        "tool_calls_total": sum(m.get("tool_calls", 0) for m in runs),
        "input_tokens_total": sum(m.get("input_tokens", 0) for m in runs),
        "output_tokens_total": sum(m.get("output_tokens", 0) for m in runs),
        "cache_read_tokens_total": sum(m.get("cache_read_tokens", 0) for m in runs),
        "cache_write_tokens_total": sum(m.get("cache_write_tokens", 0) for m in runs),
        "retries_total": sum(m.get("retries", 0) for m in runs),
        "repairs_total": sum(m.get("repairs", 0) for m in runs),
        "unpriced_calls": sum(m.get("unpriced_calls", 0) for m in runs),
        "cost_usd_total": round(cost, 4),
        "cost_usd_per_published_brief": round(cost / len(published), 4) if published else None,
        "latency_ms_median": _median(runs, "latency_ms"),
        "latency_ms_max": max((m.get("latency_ms") or 0 for m in runs), default=None),
        "prices_source": PRICES_SOURCE,
    }
    return out


def report_md(summary: dict[str, Any], results: list[dict[str, Any]]) -> str:
    mock = summary["mocked"]
    lines = [f"# Agent evaluation — snapshot {summary['snapshot_id']}", ""]
    if mock:
        lines += ["> **Mock model (`mock-heuristic`).** This run checks the harness (tools, budgets, checks, "
                  "persistence, cost accounting). It says nothing about language-model quality and its cost is zero "
                  "because no billed call was made.", ""]
    lines += [f"Provider `{summary['provider']}`, model `{summary['model']}`, {summary['cases']} cases, "
              f"{summary['wall_seconds']} s.", "", "| Measure | agent | fallback cards | v4 template |",
              "|---|---|---|---|"]
    for k in ("checks_pass", "emphasis_ok", "relevance_ok", "action_present", "status_coherent",
              "unsupported_claim_cases", "median_decision_words", "median_first_card_words", "median_total_words",
              "median_hedges"):
        lines.append(f"| {k} | {summary['agent'].get(k)} | {summary['fallback'].get(k)} | {summary['v4'].get(k)} |")
    ops = summary["operations"]
    lines += ["", "## Operations (recorded)", ""] + [f"- {k}: {v}" for k, v in ops.items()]
    lines += ["", "## Cases", "", "| case | status | agent decision | agent lead | v4 status |", "|---|---|---|---|---|"]
    for r in results:
        if "skipped" in r:
            lines.append(f"| {r['case']['case_id']} | skipped | {r['skipped']} | | |")
            continue
        lead = r["agent"]["lead"] or {}
        lines.append(f"| {r['case']['case_id']} | {r['status']} | {r['agent']['decision']} | "
                     f"{lead.get('signal_id', '—')}: {lead.get('headline', '—')} | {r['v4']['decision']} |")
    return "\n".join(lines) + "\n"


REVIEW_COLUMNS = ("case_id", "account_id", "use_case", "status", "arm", "decision", "lead_headline", "lead_finding",
                  "lead_relevance", "lead_action", "factual_support_ok", "emphasis_ok", "seller_relevance_ok",
                  "next_action_clear", "usefulness_1to5", "reviewer", "notes")


def write_review_csv(path: Path, results: list[dict[str, Any]]) -> None:
    """Blind-able review sheet: one row per case and arm; judgment columns left empty for reviewers."""
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=REVIEW_COLUMNS)
        w.writeheader()
        for r in results:
            if "skipped" in r:
                continue
            for arm in ("agent", "fallback"):
                lead = r[arm]["lead"] or {}
                w.writerow({"case_id": r["case"]["case_id"], "account_id": r["case"]["account_id"],
                            "use_case": r["case"]["use_case"], "status": r["status"], "arm": arm,
                            "decision": r[arm]["decision"], "lead_headline": lead.get("headline"),
                            "lead_finding": lead.get("finding"), "lead_relevance": lead.get("relevance"),
                            "lead_action": lead.get("action")})
            w.writerow({"case_id": r["case"]["case_id"], "account_id": r["case"]["account_id"],
                        "use_case": r["case"]["use_case"], "status": r["status"], "arm": "v4",
                        "decision": r["v4"]["decision"], "lead_finding": r["v4"]["summary"]})
