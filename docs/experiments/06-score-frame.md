# 06 — A reference frame for the score

**Proposal.** A bare score such as "53.9" gives a rep no frame, and the decimal suggests precision the
heuristic does not have. Instead:

- convert it to a percentile within a peer group;
- bucket it into Hot/Warm/Cold bands;
- anchor the bands with reference cases (one confirmed exposure scores 36.0) and a junk floor;
- label the result as relative priority.

**Scripts:** `scripts/accounts_base.sql`, then `scripts/06_score_distribution.sql`.
**Output:** `results/06_score_distribution.txt`.

## Results

**Distribution** (enterprise, 179,669 accounts):

- 7,378 distinct scores;
- median 7.2, p90 13.4, p99 44.6, p99.9 75.1, max 86.4;
- 1.55% of accounts score 36.0 or more.

**Ties:**

| Score | Accounts |
|---|---|
| 5.85 | 23,353 |
| 5.625 | 16,235 |
| 10.6875 | 9,982 |
| 5.4 | 9,127 |

**Peer groups.** The same score lands at very different percentiles:

| Kind / tier | Accounts | Below 30 | Below 36 | p50 | p90 | p99 |
|---|---|---|---|---|---|---|
| Domain / B | 164,595 | 99.6% | 99.8% | 7.0 | 13.0 | 21.3 |
| Org / A2 | 7,694 | 80.2% | 87.7% | 10.6 | 38.4 | 70.8 |
| Org / A1 | 7,380 | 73.4% | 78.8% | 13.8 | 52.5 | 78.2 |

**Illustrative bands** cut at the whole-population p99 and p90. These cut points are not calibrated.

| Band | Accounts | Score range | Org accounts | Domain accounts |
|---|---|---|---|---|
| Hot (top 1%) | 1,804 | 44.6–86.4 | 1,675 | 129 |
| Warm (top 10%) | 21,035 | 13.4–44.6 | 5,172 | 15,863 |
| Cold | 156,830 | 2.2–13.4 | 8,227 | 148,603 |

**Known-negative floor check.** The 642 accounts with pool or customer labels split 56 hot, 119 warm
and 467 cold. **8.7% of them are hot, against 1% of all accounts.**

## Conclusions

- **The decimals are false precision.** Large blocks of accounts tie exactly, and the top 40 is
  unstable (02). Show whole-number percentiles or bands, not `fmt(score, 1)` as the list does now
  (`src/firmable/api/static/index.html`).
- **Percentiles need peer groups.** A 30 is exceptional for a domain account (99.6th percentile) and
  ordinary for an A1 org (73rd). Population-wide bands give the hot band almost entirely to org
  accounts.
  - The right peer groups are industry and size, but those are not available.
  - Grouping by tier groups by attribution, which is close to circular (05). Use it only as a stopgap,
    and say so.
- **Anchors work; the floor does not yet.** "One product-identified exposure on one owned IP = 36.0"
  falls at about the top 1.5%, a usable reference case. The junk floor fails: known negatives are
  over-represented in the hot band (8.7% against 1%). Bands set now would advertise pool labels as
  hot. Fix the leak first (attribution layer and pool-label rules), then cut the bands.
- **Calibration needs outcomes.** A calibration curve (outcome rate per band) needs a proxy outcome.
  Until then, label bands as "relative priority in this snapshot, not a probability of sale".

## Limitations

- Band cut points are illustrative quantiles, not chosen at stable breaks in the distribution.
- The pool-label class is a name regex, not reviewed labels.
