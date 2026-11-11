# 0009 — Scoring v3: priority apart from ownership and evidence; account eligibility

Status: accepted (2026-11-11). Supersedes the ranking part of ADR 0006, which stays as the legacy
score.

## Context

The scoring v2 score multiplied relevance, breadth, attribution confidence and evidence quality.

- Attribution was the largest driver of rank: rank correlation 0.755 with attribution confidence.
- Registry placeholders and ISP pool labels reached the enterprise top 100: 12 accounts.
- The decimals implied precision that does not exist.

No outcome labels exist, so no weight can be fitted (`docs/experiments/`).

## Decision

1. **Three separate axes, never multiplied together.**
   - Opportunity priority = `100 × relevance × breadth`, with unchanged weights.
   - Ownership confidence comes from records that name the account: high, medium or low.
   - Evidence quality is the match-basis band.
2. **Account eligibility (v1).**
   - Exclude only when three things agree: a placeholder or pool label, no naming record, and a
     structural sign (A2, ≥ 3 operators, ≥ 20% subscriber reverse DNS).
   - Weaker indications are review flags. They never exclude.
3. **Rank** only eligible accounts, per segment, by priority. Ties: an exposure first, then counted
   IPs, then id.
   - Show a percentile: share strictly below, floored.
   - Show a band: High ≥ 99th percentile with an exposure; Medium ≥ 90th.
   - No peer groups without firmographics.
4. **Outreach is gated explicitly.** `actionable` needs eligibility, medium or high ownership, no
   review flag, and one counted security observation on a title-or-better basis.
5. **Keep the v2 score** as `legacy_score`/`legacy_rank`, and keep the v2 tables, for before/after
   comparison.
6. **Round per-account means to 9 decimals** before any score, band or tie. Parallel float sums
   otherwise cross cut points.

## Consequences

- Attribution no longer reorders the list; it decides who can be contacted. Tier-B accounts in the
  top 1,000 rose from 34 to 195. Rank correlation with attribution fell to 0.121.
- No registry-label account remains in the outreach list (47 sat in the legacy top 1,000).
  282 accounts are excluded, and no likely-enterprise name was excluded.
- The outreach list holds 60,633 accounts. 118,754 eligible accounts wait in review, mostly S16-only
  or registry-only ownership.
- **API change:** `score`, `components` and `min_score` are gone. Clients read `priority`,
  `ownership`, `evidence`, `eligibility`, `actionable` and `legacy`, and filter with `view`, `band`,
  `ownership` and `min_priority`.
- Thresholds are hypotheses chosen on development data without labels. Precision is still unknown
  until the review set is labelled. Details: `docs/ranking-v3.md`.
