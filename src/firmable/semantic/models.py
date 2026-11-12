"""Typed business objects of the semantic layer (docs/agentic-briefs.md §2).

Thin, read-only views over the serving DB. Every value is copied from the analytical layers
(accounts, signals, evidence, scoring v3, use-case lenses); nothing here computes a score, a rank or
a confidence. Each object carries the snapshot it came from.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

SEMANTIC_VERSION = 1


class SnapshotRef(BaseModel):
    snapshot_id: str | None
    scan_date: str = Field(description="human-readable scan date, e.g. '7 Nov 2026'")
    serving_version: int
    wording_version: int | None = None
    use_cases_version: int | None = None
    profile: str = Field(description="serving DB profile: 'public' (sanitized) or 'internal'")
    semantic_version: int = SEMANTIC_VERSION


class Status(BaseModel):
    code: str
    label: str
    summary: str


class Ownership(BaseModel):
    level: str | None = Field(description="backend ownership confidence: high | medium | low")
    label: str = Field(description="Strong | Probable | Unconfirmed")
    summary: str
    reasons: list[str]
    review_flags: list[str]
    best_tier: str | None


class LensPriority(BaseModel):
    use_case: str
    name: str
    rank: int | None
    of: int | None = Field(description="ranked accounts in this lens and segment")
    percentile: int | None
    priority: float | None
    signal_ids: list[str]
    n_services: int
    n_ips: int


class AccountView(BaseModel):
    account_id: str
    resolved_from: str | None = Field(None, description="older account id this request was redirected from")
    name: str
    kind: str
    segment: str
    status: Status
    eligibility: str
    ownership: Ownership
    rank: int | None
    priority_band: str | None
    priority_summary: str
    lens: LensPriority | None
    n_services: int
    n_ips: int
    countries: list[str]
    signal_ids: list[str]
    scoring_version: int | None
    snapshot: SnapshotRef


class SignalOccurrence(BaseModel):
    """One signal on one account in one snapshot."""
    occurrence_id: str
    signal_id: str
    name: str
    family: str | None
    in_lens: bool
    context_only: bool
    n_services: int
    n_ips: int
    n_counted_services: int
    products: list[str]
    defects: list[str]
    threat: str | None
    first_observed: str | None
    last_observed: str | None
    evidence_rows: int
    counted_rows: int
    suppressed_rows: int


class SignalPage(BaseModel):
    account_id: str
    snapshot_id: str | None
    use_case: str | None
    total: int
    offset: int
    limit: int
    items: list[SignalOccurrence]


class ServiceRef(BaseModel):
    service_id: str | None
    ip: str | None
    port: int | None
    transport: str | None
    sni: str | None
    product: str | None
    version: str | None
    http_title: str | None
    module: str | None
    country_code: str | None
    is_cdn: bool | None


class EvidenceItem(BaseModel):
    observation_id: str
    signal_id: str
    signal_name: str | None
    observed_at: str | None
    observed_fact: str
    service: ServiceRef
    match_basis: str | None
    detail: str | None
    sub_flags: list[str]
    counted: bool
    suppressed_by: str | None
    attribution_tier: str | None
    attribution_confidence: float | None
    attribution_reasons: list[str]
    attribution_domains: list[str]
    record_sha256: str | None
    file_id: str | None = Field(None, description="null in the public profile")


class EvidencePage(BaseModel):
    account_id: str
    signal_id: str | None
    snapshot_id: str | None
    total: int = Field(description="all evidence rows for this account and signal")
    counted_total: int
    suppressed_total: int
    offset: int
    limit: int
    complete: bool = Field(description="true when this page holds every row; false means more rows exist")
    items: list[EvidenceItem]


class PriorityExplanation(BaseModel):
    account_id: str
    snapshot_id: str | None
    rank: int | None
    band: str | None
    percentile: int | None
    population: str | None
    summary: str
    value: float | None
    product_relevance: float | None
    signal_strength: float | None
    formula: str
    lens: LensPriority | None
    explanation: list[str]
    actionable: bool
    blockers: list[str]
    scoring_version: int | None
    note: str


class SellerPlaybook(BaseModel):
    id: str
    version: int
    use_case: str | None
    offering: str
    lens_signals: list[str]
    buyers: list[str]
    value_angle: str
    positioning: list[str]
    signal_angles: dict[str, str] = Field(description="signal id -> why that finding matters for this offering")
    discovery_questions: list[str]
    relevance_keywords: list[str]
    avoid_claims: list[str]


def dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
