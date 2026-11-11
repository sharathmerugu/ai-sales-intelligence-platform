"""Account scoring: scoring v3 (opportunity priority, kept apart from confidence) and the legacy
v2 composite score, kept for reproducible before/after comparisons (docs/ranking-v3.md, ADR 0009).

Scoring v3 reports three separate axes and never multiplies one into another:

- opportunity_priority = 100 x product_relevance x signal_strength: why to act (signal relevance
  and distinct exposure breadth). Ranked within the eligible population of a segment, shown as a
  percentile and a High / Medium / Low band.
- ownership confidence: why to trust that the services are the account's (`eligibility.assess`).
- evidence quality: how strong the matched observations are (`evidence_quality_band`).
An account is actionable for outreach only when it is eligible, its ownership is medium or high, it
has no open review flag, and at least one counted security observation (exposure or hygiene) matched
on a product, protocol, TLS or title basis (`actionability`).

Legacy v2 (scoring v1 formula, ADR 0006):

score = 100 x product_relevance x signal_strength x attribution_confidence x evidence_quality

- product_relevance: noisy-OR of per-signal relevance weights over the distinct
  *counted* signals. Saturates, so correlated breadth adds less and less.
- signal_strength: breadth of evidence, from distinct IPs carrying counted
  signals: 0.5 + 0.5 * min(1, log2(n_ips) / 4)  (1 IP 0.5, 4 IPs 0.75, 16+ IPs 1.0).
- attribution_confidence: mean attribution confidence over services with counted evidence.
- evidence_quality: mean over those services of their best match-basis quality.

The weights are hypotheses for a general cybersecurity seller, not fitted to
outcomes (no labels exist). The score is not a purchase probability.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

SCORING_VERSION = 3         # v3: priority apart from ownership and evidence; eligibility; bands
LEGACY_SCORING_VERSION = 2  # the composite score below, kept as `legacy_score` / `legacy_rank`

# Commercial relevance of each signal to a general cybersecurity seller (hypothesis).
RELEVANCE: dict[str, float] = {
    "S01": 0.80,  # remote-access gateway: ZTNA/SASE/VPN replacement
    "S03": 0.70,  # remote administration: PAM/ZTNA/MFA
    "S04": 0.65,  # database / object store: DSPM/CSPM
    "S05": 0.55,  # management plane: ASM/CSPM
    # Hygiene and technographics are kept low enough that, at equal attribution, no amount of
    # them alone outranks one product-identified exposure: 1 - 0.8 * 0.75 = 0.40 < 0.80 * 0.50.
    "S06": 0.20,  # TLS hygiene: CLM, amplifier
    "S16": 0.25,  # technographics: competitive intelligence, no security claim
}

# Quality of the clause that matched (hypothesis): a protocol answer or product
# fingerprint beats a page title, which beats a scanner tag.
BASIS_QUALITY: dict[str, float] = {
    "product": 1.0,
    "protocol": 1.0,
    "tls": 0.9,
    "waf": 0.9,
    "title": 0.7,
    "tag": 0.5,
}


@dataclass(frozen=True)
class AccountInput:
    signal_ids: frozenset[str]  # distinct counted signals
    n_ips: int  # distinct IPs carrying counted evidence
    attribution_confidence: float
    evidence_quality: float


@dataclass(frozen=True)
class ScoreBreakdown:
    product_relevance: float
    signal_strength: float
    attribution_confidence: float
    evidence_quality: float
    score: float


def product_relevance(signal_ids: frozenset[str]) -> float:
    miss = 1.0
    for sid in sorted(signal_ids):
        miss *= 1.0 - RELEVANCE.get(sid, 0.0)
    return 1.0 - miss


def signal_strength(n_ips: int) -> float:
    if n_ips <= 0:
        return 0.0
    return 0.5 + 0.5 * min(1.0, math.log2(n_ips) / 4.0)


def score_account(a: AccountInput) -> ScoreBreakdown:
    r = product_relevance(a.signal_ids)
    s = signal_strength(a.n_ips)
    score = 100.0 * r * s * a.attribution_confidence * a.evidence_quality
    return ScoreBreakdown(r, s, a.attribution_confidence, a.evidence_quality, round(score, 4))


# ----------------------------------------------------------------------------- scoring v3
EXPOSURE_SIGNALS = frozenset({"S01", "S03", "S04", "S05"})
SECURITY_SIGNALS = EXPOSURE_SIGNALS | {"S06"}      # S16 is technographic and makes no security claim
MIN_SECURITY_BASIS_QUALITY = 0.7                   # a title match or better; a scanner tag alone is not enough
HIGH_BAND_PERCENTILE = 99.0                        # top 1% of the eligible population ...
MEDIUM_BAND_PERCENTILE = 90.0                      # ... and the next 9% (cut points of docs/experiments/06)
PRIORITY_DECIMALS = 4                              # ties are decided on the rounded value
OWNERSHIP_ACTIONABLE = frozenset({"high", "medium"})


def opportunity_priority(signal_ids: frozenset[str], n_ips: int) -> float:
    """100 x relevance x breadth over counted evidence. No attribution or evidence-quality term."""
    return round(100.0 * product_relevance(signal_ids) * signal_strength(n_ips), PRIORITY_DECIMALS)


def percentile_ranks(values: list[float]) -> list[float]:
    """Per value: 100 x share of values strictly below it. Ties share a percentile; deterministic."""
    keyed = [round(v, PRIORITY_DECIMALS) for v in values]
    order = sorted(keyed)
    out, below = {}, 0
    for i, v in enumerate(order):
        if i == 0 or v != order[i - 1]:
            below = i
            out[v] = 100.0 * below / len(order)
    return [out[v] for v in keyed]


def priority_band(percentile: float, has_exposure: bool) -> str:
    """High needs both the top 1% and a counted exposure signal, so hygiene or technographics alone
    never read as High (the v2 design rule, kept as an explicit anchor)."""
    if percentile >= HIGH_BAND_PERCENTILE and has_exposure:
        return "High"
    if percentile >= MEDIUM_BAND_PERCENTILE:
        return "Medium"
    return "Low"


def evidence_quality_band(quality: float) -> str:
    """Mean best basis quality over counted services: product/protocol/TLS/WAF high, title medium."""
    return "high" if quality >= 0.9 else "medium" if quality >= MIN_SECURITY_BASIS_QUALITY else "low"


def actionability(eligibility: str, ownership: str, review_flags: tuple[str, ...],
                  has_security_observation: bool) -> tuple[bool, tuple[str, ...]]:
    """(actionable, blockers). Blockers are listed in a fixed order."""
    blockers = []
    if eligibility != "eligible":
        blockers.append("excluded")
    if ownership not in OWNERSHIP_ACTIONABLE:
        blockers.append("ownership_low")
    if review_flags:
        blockers.append("review_flags")
    if not has_security_observation:
        blockers.append("no_security_observation")
    return not blockers, tuple(blockers)
