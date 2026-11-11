# 05 — Separate the reason to trust from the reason to act

**Proposal.** The score multiplies the reason to act (signals, breadth) by the reason to trust
(attribution, evidence quality). A high score is therefore ambiguous. Rank on exposure, and show
confidence as a separate axis or gate.

**Scripts:** `scripts/accounts_base.sql`, then `scripts/05_score_decomposition.sql`.
**Output:** `results/05_score_decomposition.txt`.

## Method

Because the score is a product, `ln(score)` is a sum of the logs of its four components. Compare the
variance each component contributes, overall and in the top 1,000. Then:

- compute rank correlations of the score with each component;
- profile one score band (25–30);
- show the account kind and tier mix of the top 1,000.

## Results

| Set | var ln(relevance) | var ln(strength) | var ln(attribution) | var ln(evidence) | var ln(score) |
|---|---|---|---|---|---|
| All 179,669 enterprise | 0.071 | 0.027 | **0.101** | 0.001 | 0.267 |
| Top 1,000 | 0.006 | 0.011 | 0.002 | 0.002 | 0.015 |

The component variances add up to 0.200. The remaining 0.067 comes from positive covariance between
components.

Rank correlation of the score with each component: relevance 0.59, strength 0.58, **attribution
0.75**, evidence 0.20.

Accounts scoring 25–30:

| Profile | Accounts | Mean relevance | Mean attribution |
|---|---|---|---|
| Weak signal, strong attribution (R < 0.5, A ≥ 0.85) | 292 | 0.40 | 0.89 |
| Strong exposure, weak attribution (R ≥ 0.7, A < 0.6) | 2 | 0.84 | 0.42 |
| Other | 969 | 0.62 | 0.85 |

Top 1,000 by kind: 665 org A1, 301 org A2, 34 domain (tier B).

## Conclusions

- **Attribution confidence is the largest single driver of rank.** Across all accounts it has the
  highest log-variance and the highest rank correlation. The list is ordered more by how sure we are
  of the owner than by what we saw.
- **The top of the list is decided by tier.** Within the top 1,000, attribution barely varies (0.002)
  because 97% are org accounts at 0.85–0.9. Domain (tier B) accounts, most of them cloud-hosted, are
  effectively locked out. This is the cloud penalty from 01, seen in the ranking.
- **The ambiguity is real but one-sided.** At equal score, hygiene or technographic accounts with
  strong attribution sit next to exposure accounts. The opposite case is rare, because exposure on weak
  tier-B attribution is already blocked (`allows_infra_signals`).
- **Recommendation:**
  - rank on relevance × strength (× evidence quality);
  - show attribution as a separate confidence band (high / medium / low; the cut points already exist
    in `service_attribution.confidence_band`);
  - add a minimum-confidence gate for outreach;
  - keep the signals that fired visible in the list row.

  The API already returns all four components and an explanation (`src/firmable/api/app.py`), so
  this is mainly a change to scoring and presentation.

## Limitations

- The variance split describes this population. It does not say which weighting is right.
- The profile thresholds (0.5, 0.6, 0.7, 0.85) are illustrative.
