# 0006 — Scoring v1: product of four separate, explainable components

Status: accepted (2026-11-10)

## Context
No outcome labels exist, so a fitted model is impossible. Sellers and
reviewers must see why an account ranks, and attribution doubt must lower a
rank rather than hide inside one number.

## Decision
`score = 100 x product_relevance x signal_strength x attribution_confidence x evidence_quality`
over counted evidence (correlated hits on one service counted once):
- product_relevance: noisy-OR of per-signal weights (saturates).
- signal_strength: breadth, `0.5 + 0.5 * min(1, log2(distinct IPs) / 4)`.
- attribution_confidence and evidence_quality: means per counted service.
Weights keep hygiene and technographics alone below one product-identified
exposure at equal attribution. Ties break on distinct IPs, then account id.
Each account stores the four components and a written explanation. The score
is a relative priority, not a purchase probability.

## Consequences
- Deterministic and reproducible; a zero in any component zeroes the score.
- Weights are hypotheses for a general security seller; product-specific
  lenses (ZTNA, CLM, competitive) would be alternative weight sets.
- Breadth saturates at 16 IPs, so very large accounts rank on relevance,
  attribution and evidence quality, not on size.
