# Data-science experiments on scoring v2 (2026-11-11)

Six quick experiments that test review proposals against the built data. They are read-only. They
change no application logic, no build and no published artifact.

- **Inputs:** snapshot `2026-11-07`, full data (not the sample files). Everything comes from Parquet
  that already exists in `~/firmable-work/lake/`:
  - `services` v1;
  - `signal_hits` signals v1;
  - `service_attribution` attribution v4;
  - `accounts` scoring v2 over attribution v4.
- **Scope:** enterprise segment only (179,669 accounts) wherever accounts are used.
- **Privacy:** outputs contain no IPs, hostnames, account names or NTLM values. The script in
  experiment 02 reads account names only to classify them with a regex, and prints only counts.

| # | Proposal tested | Verdict | Doc |
|---|---|---|---|
| 01 | Missing values are non-random; fill attribution from outside data | Pattern **confirmed**. Outside data can reach only a small share of the gap; LLM fill rejected | [01-missingness.md](01-missingness.md) |
| 02 | Information-content weights, correlation analysis, sensitivity, placebos | Sensitivity and placebo checks **useful**: they found a fragile top 40 and leaking pool labels. Rarity weights and PCA **not useful** | [02-feature-weights.md](02-feature-weights.md) |
| 03 | Ground weights in breach and exploitation data; express risk in dollars | Class-level grounding **reasonable**. Per-service CVE weights **invert** the order. Dollar framing **rejected** | [03-external-grounding.md](03-external-grounding.md) |
| 04 | Ground truth from WHOIS, CT and passive DNS, without human labels | WHOIS and CT are **largely circular**. Forward DNS and a company index are not. Human labels still needed | [04-ground-truth.md](04-ground-truth.md) |
| 05 | Separate confidence from the priority score | **Supported**: attribution is the largest driver of rank | [05-decouple-confidence.md](05-decouple-confidence.md) |
| 06 | Percentiles, peer groups and Hot/Warm/Cold bands instead of a raw score | **Supported**, but known negatives reach the top band, so fix them first | [06-score-frame.md](06-score-frame.md) |

## Reproduce

From the repo root, after `uv sync` (about 2 minutes in total, peak memory under 5 GB).
Frozen v4 reproduction: the paths below read the attribution v4 / scoring v2 tables, which stay on disk unchanged; the results were computed on them. Attribution v5 (`attribution=v5`, `docs/attribution-implementation.md` §7) changes org classes and accented account ids, so repointing these paths means rerunning the experiments.

```bash
LAKE="$HOME/firmable-work/lake"
ACC="$LAKE/accounts/scoring=v2/attribution=v4/normalizer=v1/snapshot=2026-11-07"
D=docs/experiments
for n in 01_missingness 03_kev_by_signal 04_attribution_evidence; do
  duckdb -no-agent -csv -c "SET VARIABLE lake='$LAKE';" -c ".read $D/scripts/$n.sql" > $D/results/$n.txt
done
for n in 02_signal_structure 05_score_decomposition 06_score_distribution; do
  duckdb -no-agent -csv -c "SET VARIABLE accounts='$ACC';" -c ".read $D/scripts/accounts_base.sql" \
    -c ".read $D/scripts/$n.sql" > $D/results/$n.txt
done
uv run python $D/scripts/02_sensitivity.py "$ACC" > $D/results/02_sensitivity.txt
```

- `scripts/`: the SQL and Python behind every number.
- `results/`: raw output of the run on 2026-11-11.
- `02_sensitivity.py` imports the weights and functions from `firmable.accounts.scoring`, so it
  tracks the current implementation. Its recomputed baseline matches the stored rank for 994 of the
  top 1,000 enterprise accounts. The other 6 differ because the stored score is rounded to 4
  decimals before ties are broken.

## Recommended changes (summary)

Each doc gives the evidence behind its recommendation. The consolidated list, with file paths, is in
`docs/PHASE3_HANDOFF.md` §18.

1. Label the 104-case review set by hand, and add a random stratum from below the top k (04).
2. Turn pool and customer labels into a regression test, and fix them before any banding (02, 06).
3. Rank on the reason to act. Show attribution as a separate confidence band or gate, not a hidden
   multiplier (05).
4. Show a percentile within a peer group and a band instead of a raw score with decimals. Label it
   as relative priority (06).
5. Report top-k stability (weight sensitivity and bootstrap) as part of evaluation. Treat the order
   within the top 40 as unstable (02).
6. Do not adopt rarity weights, per-service CVE/EPSS weights or dollar figures (02, 03).
7. Fill attribution from a forward-DNS check and a company/domain index, not from WHOIS, CT or an
   LLM. Consider login-page hashes as a version proxy for edge devices (01, 04).

## Limitations that apply to all six

- **No human labels, no outcomes.** These experiments test internal coherence, stability and known
  failure modes. None of them shows that a high rank means a good lead.
- **One snapshot.** The data cannot show stability over time.
- **Regex classes are crude.** The "pool label", "university" and "bank or health" classes in 02
  and 06 come from name patterns. They are not reviewed labels.
- **Enterprise segment only.** The network-provider segment (775 accounts) was not analysed.
