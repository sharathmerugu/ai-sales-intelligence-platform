# 02 — Feature weights without ground truth

**Proposal.** Without labels, the score can still be improved in four ways:

- weight signals by information content (entropy, CRITIC or inverse frequency);
- remove double counting by studying how signals correlate (PCA or factor analysis), which also
  tests the noisy-OR independence assumption;
- show the ranking is robust to weight changes and bootstrap resampling;
- plant known negatives and known positives and check where they land.

**Scripts:**

- `scripts/accounts_base.sql`, then `scripts/02_signal_structure.sql`;
- `scripts/02_sensitivity.py`.

**Outputs:** `results/02_signal_structure.txt`, `results/02_sensitivity.txt`.

## Results

**Prevalence** of counted signals across 179,669 enterprise accounts, with self-information
`-ln(share)`:

| Signal | Accounts | Share | Self-info | Current weight | Self-info weight (max 0.80) |
|---|---|---|---|---|---|
| S01 | 2,408 | 1.34% | 4.31 | 0.80 | 0.577 |
| S03 | 1,371 | 0.76% | 4.88 | 0.70 | 0.652 |
| S04 | 454 | 0.25% | 5.98 | 0.65 | **0.800** |
| S05 | 2,026 | 1.13% | 4.49 | 0.55 | 0.600 |
| S06 | 76,157 | 42.39% | 0.86 | 0.20 | 0.115 |
| S16 | 116,200 | 64.67% | 0.44 | 0.25 | 0.058 |

**Correlation** (phi, account level):

- Exposure signals with each other: 0.04–0.14.
- S01 with S06: 0.03. S01 with S16: −0.03.
- **S06 with S16: −0.81.**
- Among the 17,226 accounts with two or more signals, S06 with S16 is 0.01.

S06 and S16 split by account kind: domain accounts have 67,435 with S06 and 109,522 with S16, but
only 12,827 with both.

**Stability.** Overlap with the current enterprise top k:

| Perturbation | Top 40 | Top 100 | Top 1,000 |
|---|---|---|---|
| Random weights × U(0.5, 1.5), 30 runs | mean 0.61, min 0.40 | 0.67, min 0.48 | 0.85, min 0.69 |
| Bootstrap of services within each account, 20 runs | mean 0.68, min 0.57 | 0.72, min 0.66 | 0.81, min 0.79 |
| Self-information weights | 0.57 | 0.68 | 0.78 |
| Equal weights 0.5 | 0.85 | 0.87 | 0.78 |
| S01 and S03 weights swapped | 0.82 | 0.87 | 0.91 |

**Known-class placement.** Classes come from name regexes, not labels.

| Class | Accounts | Median rank | In top 100 | In top 1,000 |
|---|---|---|---|---|
| Pool or customer label (known negative) | 642 | 64,960 | **4** | 37 |
| Bank or health (likely enterprise) | 2,051 | 64,423 | 0 | 47 |
| University (likely enterprise) | 1,698 | 54,130 | 28 | 119 |
| Other | 175,278 | 90,726 | 68 | 797 |

## Conclusions

- **Rarity weights get the order wrong.** They would make S04 the strongest signal and S01 the
  weakest exposure. Rarity measures surprise, not commercial value. They agree only on what the
  current weights already encode: S06 and S16 stay low. Do not adopt them.
- **Correlation analysis adds little.** Exposure signals are nearly independent at account level, so
  noisy-OR is a fair approximation. Double counting on one device is already removed per service
  (suppression in `rollup.py`).
  - The −0.81 between S06 and S16 is not double counting. It is a side effect of the CDN gate: S06
    excludes CDN endpoints, while S16 is mostly CDN/WAF evidence, so the two replace each other.
  - With six binary features, PCA would not reveal more than this table.
- **The top of the list is fragile; the tail is stable.** Weight changes of ±50% or a bootstrap keep
  only 57–68% of the top 40 on average, but about 80–85% of the top 1,000. The exact order inside the
  top 40 carries little information. Present bands, and report stability in evaluation.
- **The placebo check found a real failure.** Pool and customer labels have the same median rank as
  banks and health organisations, and 4 reach the top 100. The scorer cannot tell them apart; the
  attribution layer must (see also 06).

## Limitations

- Bootstrap resamples services inside each account. It does not model a different crawl.
- The ±50% range for weights is arbitrary. It is meant to show sensitivity, not to estimate
  uncertainty.
- The name classes are crude. Some "customer" names are real companies, and some banks are missed.
