# 03 — Grounding weights in public breach data and dollar value

**Proposal.**

- Set signal weights from public exploitation and breach data (CISA KEV, EPSS, Verizon DBIR,
  ransomware incident reports).
- Turn the score into expected dollar risk using breach-cost and cyber-insurance data.
- Add firmographic and industry-spend data as a buying-propensity layer.

**Script:** `scripts/03_kev_by_signal.sql`. **Output:** `results/03_kev_by_signal.txt`.

No external data was fetched, so this experiment only tests the one part that can be checked inside
the dataset: what a per-service CVE/KEV basis would do.

## Method

For each signal, measure the share of hit services with a scanner-inferred KEV flag (`any_kev`), any
CVE (`vulns`), and a visible version.

## Results

| Signal | Hits | KEV-flagged | Any CVE | Version visible |
|---|---|---|---|---|
| S01 remote-access gateway | 26,847 | **0.63%** | 2.81% | 4.5% |
| S03 remote administration | 24,983 | 0.71% | 0.71% | 47.8% |
| S04 database | 9,863 | 1.18% | 4.86% | 28.5% |
| S05 management plane | 34,822 | 3.18% | 8.00% | 22.1% |
| S06 TLS hygiene | 217,167 | **11.81%** | 16.46% | 26.8% |
| S16 technographics | 1,522,410 | 0.60% | 0.98% | 8.3% |

## Conclusions

- **Per-service CVE/KEV/EPSS weighting inverts the order.** It would rank TLS hygiene (S06) about 19
  times above VPN gateways (S01). The cause is how the data is collected, not attacker behaviour:
  - CVEs are inferred from version strings;
  - edge devices hide their version (4.5% visible for S01);
  - web servers with TLS defects expose theirs.

  Any weight learned from these fields would encode version visibility.
- **Grounding at the level of a device class is reasonable.** Use cited public statistics on initial
  access vectors and exploited-product classes. That is a defensible replacement for analyst
  judgement. The current order (S01 > S03 > S04 > S05 ≫ S06, S16) already follows that direction.
  Record the source and date of any external figure, and keep the weights labelled as hypotheses.
- **Reject the "~$X of breach exposure" framing.**
  - It multiplies a population-average loss by an uncalibrated score, which gives false precision.
  - It implies the company is vulnerable or will be breached, which `docs/research-findings.md` §3
    forbids.
  - It invites the rep to quote a number that cannot be defended.
- **A firmographic and industry fit layer is the right idea, but it is blocked.** It needs Firmable's
  company index (size, industry), which this project does not have. The same data would also allow
  normalizing by size (see 02 and 06).

## Limitations

- KEV and CVE here are the scanner's inferences: 99.99% are `verified:false`.
- No external feed was retrieved, so no class-level weight was computed or checked.
