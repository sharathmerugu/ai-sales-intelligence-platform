"""Semantic layer: query functions over the serving DB that return typed business objects.

The API, the UI and the agent's tools all read through this class, so they see the same facts.
It reuses `Store` queries and the serving-v4 brief helpers; it adds no score, rank or confidence.
Access control stays where it was: the app's authentication guards every route, and the store is the
sanitized serving DB of the deployment (`profile`), so this layer exposes nothing the API did not.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from ..accounts.use_cases import USE_CASES_BY_ID
from ..api.brief import (OWNERSHIP_LABEL, POPULATION_NOUN, SUB_FLAG_TEXT, _scan_date, build_brief, order_findings,
                         ownership_sentence, priority_sentence, research_state_ref)
from ..api.store import Store
from ..api.wording import render_fact
from .models import (SEMANTIC_VERSION, AccountView, EvidenceItem, EvidencePage, LensPriority, Ownership,
                     PriorityExplanation, SellerPlaybook, ServiceRef, SignalOccurrence, SignalPage, SnapshotRef,
                     Status)
from .playbooks import PLAYBOOK_VERSION, playbook_for

POPULATION = {"enterprise": "eligible enterprise accounts", "network_provider": "network-provider accounts"}
PRIORITY_NOTE = ("relative priority in this snapshot; not a purchase probability, confirmed vulnerability or "
                 "loss estimate")
MAX_EVIDENCE_PAGE = 50


def iso(value: datetime | None) -> str | None:
    return None if value is None else value.strftime("%Y-%m-%dT%H:%M:%SZ")


class SemanticLayer:
    def __init__(self, store: Store):
        self.store = store
        meta = store.meta_full()
        self.snapshot = SnapshotRef(
            snapshot_id=meta.get("snapshot_id"), scan_date=_scan_date(meta.get("snapshot_id")),
            serving_version=meta["serving_version"], wording_version=meta.get("wording_version"),
            use_cases_version=meta.get("use_cases_version"), profile=meta.get("profile") or "internal",
        )
        self.registry = {r["id"]: r for r in store.registry()}
        self.sizes = store.population_sizes()
        self.vocabulary = store.product_vocabulary()

    # -- identity ------------------------------------------------------------------

    def resolve(self, account_id: str) -> tuple[dict[str, Any], str | None] | None:
        """(account row, the older id it was resolved from or None); None when unknown."""
        row = self.store.get_account(account_id)
        if row is not None:
            return row, None
        successor = self.store.resolve_account_id(account_id)
        if successor is None or successor == account_id:
            return None
        row = self.store.get_account(successor)
        return (row, account_id) if row is not None else None

    def _population(self, row: dict[str, Any]) -> str:
        size = self.sizes.get(row["segment"], {}).get("eligible")
        if size:
            return f"{size:,} {POPULATION_NOUN.get(row['segment'], 'accounts')}"
        return POPULATION.get(row["segment"], "accounts")

    def _lens(self, row: dict[str, Any], use_case: str | None) -> tuple[LensPriority | None, dict[str, Any] | None]:
        if not use_case or use_case not in USE_CASES_BY_ID:
            return None, None
        lenses = {x["uc_id"]: x for x in self.store.account_use_cases(row["account_id"])}
        x = lenses.get(use_case)
        if x is None:
            return None, None
        of = self.sizes.get(row["segment"], {}).get("lenses", {}).get(use_case)
        pct = x["uc_percentile"]
        return LensPriority(
            use_case=use_case, name=USE_CASES_BY_ID[use_case].name, rank=x["uc_rank"], of=of,
            percentile=None if pct is None else int(pct), priority=x["uc_priority"],
            signal_ids=list(x["uc_signal_ids"] or []), n_services=x["uc_n_services"], n_ips=x["uc_n_ips"],
        ), x

    # -- objects -------------------------------------------------------------------

    def get_account(self, account_id: str, use_case: str | None = None) -> AccountView | None:
        found = self.resolve(account_id)
        if found is None:
            return None
        row, resolved_from = found
        lens, lens_row = self._lens(row, use_case)
        state = research_state_ref(row, use_case)
        level = row.get("ownership_confidence")
        return AccountView(
            account_id=row["account_id"], resolved_from=resolved_from,
            name=row.get("account_name") or row["account_id"], kind=row["account_kind"], segment=row["segment"],
            status=Status(**state), eligibility=row["eligibility"],
            ownership=Ownership(level=level, label=OWNERSHIP_LABEL.get(level or "", "Unknown"),
                                summary=ownership_sentence(row), reasons=list(row.get("ownership_reasons") or []),
                                review_flags=list(row.get("review_flags") or []), best_tier=row.get("best_tier")),
            rank=row.get("rank"), priority_band=row.get("priority_band"),
            priority_summary=priority_sentence(row, self._population(row), lens_row),
            lens=lens, n_services=row["n_services"], n_ips=row["n_ips"], countries=list(row.get("countries") or []),
            signal_ids=list(row.get("signal_ids") or []), scoring_version=row.get("scoring_version"),
            snapshot=self.snapshot,
        )

    def signal_occurrences(self, account_id: str, use_case: str | None = None) -> list[SignalOccurrence]:
        """Every signal of the account, lens signals first (same order as the deterministic brief)."""
        lens = set(USE_CASES_BY_ID[use_case].signals) if use_case in USE_CASES_BY_ID else set()
        coverage = self.store.signal_coverage(account_id)
        breakdown = self.store.signal_breakdown(account_id)
        out = []
        for s in order_findings(self.store.account_signals(account_id), use_case):
            reg = self.registry.get(s["signal_id"], {})
            cov = coverage.get(s["signal_id"], {})
            family = s.get("family") or reg.get("family")
            out.append(SignalOccurrence(
                occurrence_id=f"{account_id}|{s['signal_id']}|{self.snapshot.snapshot_id}",
                signal_id=s["signal_id"], name=reg.get("short_name") or reg.get("name") or s["signal_id"],
                family=family, in_lens=s["signal_id"] in lens, context_only=family == "technographic",
                n_services=s["n_services"], n_ips=s["n_ips"], n_counted_services=s.get("n_counted_services") or 0,
                products=list(s.get("details") or []),
                defects=[SUB_FLAG_TEXT.get(f, f) for f in (s.get("sub_flags") or [])],
                threat=reg.get("inferred_risk"),
                first_observed=iso(cov.get("first_observed")), last_observed=iso(cov.get("last_observed")),
                defect_counts={SUB_FLAG_TEXT.get(k, k): v for k, v in
                               breakdown.get(s["signal_id"], {}).get("defects", {}).items()},
                product_counts=dict(list(breakdown.get(s["signal_id"], {}).get("products", {}).items())[:10]),
                evidence_rows=cov.get("n_rows") or 0, counted_rows=cov.get("n_counted") or 0,
                suppressed_rows=cov.get("n_suppressed") or 0,
            ))
        return out

    def list_signals(self, account_id: str, use_case: str | None = None, limit: int = 20,
                     offset: int = 0) -> SignalPage | None:
        found = self.resolve(account_id)
        if found is None:
            return None
        aid = found[0]["account_id"]
        items = self.signal_occurrences(aid, use_case)
        return SignalPage(account_id=aid, snapshot_id=self.snapshot.snapshot_id, use_case=use_case,
                          total=len(items), offset=offset, limit=limit, items=items[offset:offset + limit])

    def _evidence_item(self, r: dict[str, Any]) -> EvidenceItem:
        return EvidenceItem(
            observation_id=r["observation_id"], signal_id=r["signal_id"], signal_name=r.get("signal_name"),
            observed_at=iso(r.get("observed_at")), observed_fact=render_fact(r.get("observed_fact_template"), r),
            service=ServiceRef(service_id=r.get("service_id"), ip=r.get("ip"), port=r.get("port"),
                               transport=r.get("transport"), sni=r.get("sni"), product=r.get("product"),
                               version=r.get("version"), http_title=r.get("http_title"), module=r.get("module"),
                               country_code=r.get("country_code"), is_cdn=r.get("is_cdn")),
            match_basis=r.get("match_basis"), detail=r.get("detail"), sub_flags=list(r.get("sub_flags") or []),
            counted=bool(r.get("counted")), suppressed_by=r.get("suppressed_by"), attribution_tier=r.get("tier"),
            attribution_confidence=r.get("attribution_confidence"),
            attribution_reasons=list(r.get("attribution_reasons") or []),
            attribution_domains=list(r.get("attribution_domains") or []),
            record_sha256=r.get("record_sha256"), file_id=r.get("file_id"),
        )

    def get_signal_evidence(self, account_id: str, signal_id: str | None, limit: int = 5,
                            offset: int = 0) -> EvidencePage | None:
        found = self.resolve(account_id)
        if found is None:
            return None
        aid = found[0]["account_id"]
        limit = max(1, min(limit, MAX_EVIDENCE_PAGE))
        total, rows = self.store.account_evidence(aid, signal=signal_id, limit=limit, offset=offset)
        coverage = self.store.signal_coverage(aid)
        covs = [coverage[signal_id]] if signal_id in coverage else ([] if signal_id else list(coverage.values()))
        return EvidencePage(
            account_id=aid, signal_id=signal_id, snapshot_id=self.snapshot.snapshot_id, total=total,
            counted_total=sum(c["n_counted"] for c in covs), suppressed_total=sum(c["n_suppressed"] for c in covs),
            offset=offset, limit=limit, complete=offset == 0 and len(rows) >= total,
            items=[self._evidence_item(r) for r in rows],
        )

    def evidence_by_ids(self, account_id: str, observation_ids: list[str]) -> list[EvidenceItem]:
        found = self.resolve(account_id)
        if found is None:
            return []
        return [self._evidence_item(r) for r in self.store.evidence_by_ids(found[0]["account_id"], observation_ids)]

    def explain_priority(self, account_id: str, use_case: str | None = None) -> PriorityExplanation | None:
        found = self.resolve(account_id)
        if found is None:
            return None
        row = found[0]
        lens, lens_row = self._lens(row, use_case)
        pct = row.get("priority_percentile")
        return PriorityExplanation(
            account_id=row["account_id"], snapshot_id=self.snapshot.snapshot_id, rank=row.get("rank"),
            band=row.get("priority_band"), percentile=None if pct is None else int(pct),
            population=POPULATION.get(row["segment"]),
            summary=priority_sentence(row, self._population(row), lens_row),
            value=row.get("opportunity_priority"), product_relevance=row.get("product_relevance"),
            signal_strength=row.get("signal_strength"),
            formula="priority = 100 x product relevance x signal breadth (scoring v3); ownership confidence and "
                    "evidence quality are separate fields, not multiplied in",
            lens=lens, explanation=list(row.get("explanation") or []), actionable=bool(row.get("actionable")),
            blockers=list(row.get("actionable_blockers") or []), scoring_version=row.get("scoring_version"),
            note=PRIORITY_NOTE,
        )

    def get_seller_playbook(self, use_case: str | None) -> SellerPlaybook:
        return playbook_for(use_case)

    # -- deterministic brief and cache identity -----------------------------------

    def deterministic_brief(self, account_id: str, use_case: str | None = None) -> dict[str, Any] | None:
        """The serving-v4 template brief (`api.brief.build_brief`), unchanged."""
        found = self.resolve(account_id)
        if found is None:
            return None
        row = found[0]
        sigs = [{**s, "details": list(s["details"] or []), "sub_flags": list(s["sub_flags"] or [])}
                for s in self.store.account_signals(row["account_id"])]
        size = self.sizes.get(row["segment"], {})
        return build_brief(row, sigs, self.registry, self.store.account_use_cases(row["account_id"]),
                           self.snapshot.snapshot_id, POPULATION.get(row["segment"]), use_case,
                           lens_sizes=size.get("lenses"), population_size=size.get("eligible"))

    def context_digest(self, account_id: str) -> str:
        """Content hash of everything a brief about this account can read: the account row, its signals,
        lenses and evidence coverage (observation-id digest per signal), the snapshot and the versions.
        Any change to the evidence, scores or wording changes the digest."""
        found = self.resolve(account_id)
        if found is None:
            return "missing"
        row = found[0]
        aid = row["account_id"]
        payload = {
            "account": row, "signals": self.store.account_signals(aid), "lenses": self.store.account_use_cases(aid),
            "coverage": self.store.signal_coverage(aid), "snapshot": self.snapshot.model_dump(),
            "population": self.sizes.get(row["segment"]),
            "playbook_version": PLAYBOOK_VERSION, "semantic_version": SEMANTIC_VERSION,
        }
        blob = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()[:32]
