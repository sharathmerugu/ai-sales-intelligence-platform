# Evaluation — stratified account review

Goal: measure whether the ranking puts qualified enterprise prospects at the top, whether
attribution names the right company, and whether the evidence supports each signal. Compare the
**baseline** ranking (scoring v1 over attribution v2, before network classification) with the
**enriched** ranking (scoring v2 over attribution v4: OpenASN rules, network-provider segment).

No metric is reported without reviewed labels. Model output is never a label.

## Review set

```bash
uv run firmable review-set 2026-11-07          # -> ~/firmable-work/eval/2026-11-07-review.csv
uv run firmable review-metrics ~/firmable-work/eval/2026-11-07-review.csv                     # manual labels
uv run firmable review-metrics ~/firmable-work/eval/2026-11-07-review.csv --source suggested  # provisional
```

The CSV holds real company names, domains and IPs, so it stays in `~/firmable-work/eval/`, out of
Git. It is deterministic for its seed (`20261110`). One row per case; an account in several
strata appears once with all its strata listed.

| Stratum | Cases | Measures |
|---|---|---|
| `top40_baseline` | baseline rank 1–40 | Precision@20/40 before |
| `top40_enriched` | enriched enterprise rank 1–40 | Precision@20/40 after |
| `top_network_provider` | network-provider rank 1–10 | the separate segment holds providers |
| `tier_b_sample` | 10 random tier-B domain accounts with an exposure signal | tenant attribution precision |
| `asn_reclassified` | 10 random baseline org accounts that OpenASN rules moved out of the enterprise list | precision of the ASN rule (are they really providers?) |
| `abstain_sample` | 10 random tier-C services with an exposure signal | abstention: was no company identifiable? |

## Label columns

Reviewers fill only the `manual_*` columns, plus `manual_reviewer` and `manual_notes`. Use the
deployed app (account detail and evidence) and public sources such as the company website. Do not
use the `suggested_*` columns as a source.

| Column | Values | Question |
|---|---|---|
| `manual_entity_type` | `enterprise`, `network_provider`, `unclear` | Is the named entity an end organisation (company, university, government body) or a network provider (ISP, telco, hoster, data centre, CDN, IP lessor) whose IPs mostly carry other parties' systems? |
| `manual_qualified` | `yes`, `no`, `unclear` | Would a general cybersecurity seller reasonably prospect this account in the **enterprise** segment on this evidence? `no` for network providers, pool or placeholder names, and misattributed tenants. |
| `manual_attribution_correct` | `yes`, `no`, `unclear` | For attributed cases: does the evidence (org, domains, certificate, SNI) support that these services belong to the named entity? For `abstain_sample` cases: `yes` when abstaining was right (no single company is identifiable from the record), `no` when one clearly is. |
| `manual_evidence_supported` | `yes`, `no`, `unclear` | Does at least one evidence row show what the signal claims (e.g. a product-identified VPN portal for S01, an RDP handshake for S03)? |

Empty means unlabeled and is excluded from every denominator. `unclear` is labeled and counts as a
negative, so precision is never inflated by skipping hard cases. Every metric reports its
numerator and denominator.

## Metrics

- **Precision@k** (k = 20, 40), per ranking: share of labeled top-k cases with
  `qualified = yes`. Enriched precision uses the enterprise segment only.
- **Segment agreement**: system segment (`enterprise` or `network_provider`) equals the
  reviewed `entity_type`.
- **ASN-rule precision**: share of `asn_reclassified` cases reviewed as `network_provider`.
- **Attribution precision**: share of attributed cases (tiers A1, A2, P, B) with
  `attribution_correct = yes`.
- **Abstention correctness**: share of `abstain_sample` cases where abstaining was right.
- **Evidence support**: share of labeled cases with `evidence_supported = yes`.

## Source-observation inspection (reviewer aid)

```bash
uv run firmable inspect-accounts 2026-11-07 --top 40                         # enterprise top 40
uv run firmable inspect-accounts 2026-11-07 --segment network_provider --top 10
uv run firmable inspect-accounts 2026-11-07 --account dom:example.com --n 20  # any account
```

For each account, up to `--n` evidence rows are sampled: counted rows first, one per service,
exposures first. For each sampled row the command:

- re-reads the exact source bytes by provenance (file, offset, length; SHA-256 verified; one seek,
  no rescan of the 137 GB file);
- parses them with the ingestion normalizer;
- writes `~/firmable-work/eval/SNAPSHOT-inspect-*.{md,json}` (IPs masked to /24, NTLM values never
  printed).

Each record shows:

- **names account**: certificate O, CN or SAN, SNI, HTTP Host, hostnames or Shodan domains that
  name the account. Matching is looser than attribution's: it adds initials (`mit.edu`), a label
  equal to the first token (`sap.com`) and distinctive words (`ucdavis.edu`). The `org` registry
  field never counts, because attribution already used it.
- **third parties**: other registrable domains in the same record.
- **shown in record**: whether the raw record shows what the signal claims. For S06 that is the
  named TLS fact; for other signals, the detail's vendor or protocol in the product, title, banner,
  probe, WAF or components. Both sides are accent- and case-folded (`fold_name`) before matching.

Per-account verdict (heuristic, never a label):

| Verdict | Meaning |
|---|---|
| `corroborated` | a certificate, SNI or Host names the account |
| `reverse_dns_only` | only PTR names do, i.e. the IP owner's own zone |
| `registry_only` | the records carry no names at all |
| `contradicted` | no record names the account, and at least half name third parties |
| `weak` | anything else |

Reviewers use it to fill `manual_attribution_correct` and `manual_evidence_supported`.

## Ranking comparison (offline, scoring v2 vs v3)

```bash
uv run firmable compare-rankings 2026-11-07   # -> ~/firmable-work/eval/2026-11-07-ranking-compare{,-detail}.json
```

`firmable.evaluation.ranking_compare` compares the legacy list (all enterprise accounts by v2 rank)
with the candidate outreach list (actionable enterprise accounts by v3 rank):

- top-20/40/100/1,000 membership;
- known-negative and likely-enterprise name classes (regexes, not labels);
- the `inspect-accounts` checker verdicts (heuristic, not labels);
- eligibility coverage, and the ownership distribution by tier and band;
- rank correlation of each list's ranking value with attribution confidence;
- stability under one weight at a time and joint random weights at ±10/20/50%, and a bootstrap of
  counted services;
- the number of manual labels in the review CSV.

The JSON report holds counts only. The `-detail` file holds account ids and stays here, outside Git.
The review set remains the final holdout: comparisons never read its `suggested_*` columns. Results:
`docs/ranking-v3.md` §5.

## Scoring-v3 holdout

The review set above was built for scoring v2 and its top strata were read while the scoring-v3
rules were developed (`docs/ranking-v3.md` §4), so it cannot test scoring v3 cleanly. The holdout is
a fresh, deterministic sample of the scoring-v3 tables that leaves out every account already seen
during development, plus metrics computed from human labels only. Code:
`src/firmable/evaluation/holdout.py`; tests: `tests/test_holdout.py`.

```bash
uv run firmable holdout-set 2026-11-07                       # -> ~/firmable-work/eval/2026-11-07-holdout-v3{.csv,.blind.csv,.dev-registry.json,.manifest.json}
uv run firmable holdout-set 2026-11-07 --attribution-version 4 --out PATH   # an older attribution build (default name gets -attr4)
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv \
    --labels ~/firmable-work/eval/2026-11-07-holdout-v3.blind.csv  # labels filled in the blind file
```

- **Seed** `20261112` (`HOLDOUT_SEED`). Each stratum draws with its own `Random("SEED:stratum")` from
  its frame sorted by account id, so the same tables and seed give a byte-identical CSV, whatever
  the row order of the input tables. The manifest records the CSV's SHA-256.
- **Paths** follow the version constants: the frame is `accounts_dir()` / `attribution_dir()` of the
  current `ATTRIBUTION_VERSION` unless `--attribution-version` is given.
- **Overwrite**: the command refuses to replace an existing CSV or `.blind.csv` (either may hold
  labels) unless `--overwrite`, also under `--no-blind`. With `--overwrite --no-blind` a stale blind
  file is deleted, so it can never sit beside a different case list.
- **Out of Git**: it refuses an output path inside a Git repository. `.gitignore` also excludes
  `*-holdout*.csv`, `*.blind.csv` and `*-review*.csv`.
- **Drafts**: a draft drawn on attribution v4 (2026-11-11) was deleted unlabelled once the
  attribution-v5 rebuild was scheduled. The canonical holdout is generated once, on the final
  attribution-v5 build, and then kept.

### Development-case registry

An account is a development case (`dev_case = yes`) when any of the sources below saw it. `dev_sources`
lists the sources.

**Name matching.** A source suffixed `@name` matched by normalized name only, which catches accounts
whose id changed in an attribution rebuild. Normalization is `fold_name` (the attribution-v5 accent
fold), punctuation to spaces, then `norm_org` (legal suffixes stripped). Names shorter than 4
characters after normalization never match by name alone.

| Source | What |
|---|---|
| `review_set` | Accounts in `SNAPSHOT-review*.csv` (their `suggested_*` labels were seen) |
| `legacy_top100` | Enterprise rank ≤ 100 of every scoring-v2 build of the snapshot (eligibility-rule development) |
| `v3_actionable_top400` | Actionable enterprise top 400 of every scoring-v3 build (provider-flag development) |
| `v3_excluded`, `registry_label_name` | Every excluded account and every name `is_registry_label` accepts (label-rule development) |
| `inspect_worksheet` | Accounts in every `SNAPSHOT-inspect-*.json` |
| `ranking_compare_detail` | Every account id in `SNAPSHOT-ranking-compare-detail*.json` |
| `provider_flag_all` | Every `possible_network_provider` account. The §4 spot-check (DuckDB `setseed(0.20261111)`) cannot be redrawn from the rebuilt tables, so all flagged accounts count as seen |
| `provider_flag_spotcheck` | The 30 spot-check names, recovered from the session log of the drawing query, in the local file `SNAPSHOT-dev-provider-spotcheck.json` |
| `doc_reference` | `org:`/`dom:`/`net:` ids written in `docs/`; a missing `docs/` is recorded as absent |
| any `SNAPSHOT-dev-*.json` | Optional extra lists (`account_ids`, `orgs`, `names`, optional `source`), e.g. accounts read during attribution-v5 development. Read if present at generation time |

"Every build" covers every attribution and normalizer version. It is deliberately conservative: it
includes the build being sampled, so the current actionable top 400 is always development data.

The `.dev-registry.json` file holds:

- the inputs found or missing;
- the ids and names per source;
- how many accounts of the sampled build each source marks.

### Strata

Enterprise segment unless stated. "Outreach position" is the position in the actionable list a
seller sees (`view=actionable`); `rank` counts all eligible accounts.

| Stratum | Cases | Frame | Draw |
|---|---|---|---|
| `top_enterprise` | 40 | outreach positions 1–40 | all; development cases kept and marked |
| `rank_41_200` | 25 | outreach positions 41–200 | non-development first, then filled from development cases (marked) |
| `rank_401_2000` | 15 | outreach positions 401–2,000 | non-development only |
| `random_eligible` | 25 | eligible accounts, any rank, actionable or not | non-development only |
| `network_provider/top5` | 5 | network-provider ranks 1–5 | all |
| `network_provider/random` | 10 | network-provider ranks 6+ | non-development only |
| `low_confidence_review/ownership_low` | 10 | eligible, not actionable, ownership `low`, no review flag | non-development only |
| `low_confidence_review/review_flag` | 10 | eligible, not actionable, any review flag | non-development only |
| `technographic_only` | 15 | eligible, S16 present and no S01/S03/S04/S05/S06 signal | non-development only |

Positions 41–200 lie inside the actionable top 400, so in practice `rank_41_200` holds only
development cases. `rank_401_2000` was added as the nearest clean stratum below the top.

An account drawn into several strata appears once with all of them listed. The manifest records
`cases`, `unique_accounts` and `stratum_memberships`. Case ids (`H001`, …) follow a seeded shuffle,
so ranks are not grouped. For each stratum the manifest also records:

- the frame size `frame_n`;
- the non-development frame `frame_non_dev_n`;
- the cases drawn, and how many of them are development cases.

**Canonical holdout** (generated once, 2026-11-11, on scoring v3 / eligibility v2 / attribution v5,
seed `20261112`; `~/firmable-work/eval/2026-11-07-holdout-v3*`, out of Git). 155 cases, 155 unique
accounts: **67 development, 88 held out**. CSV SHA-256 `d41948b6…743b847c`; a second run to another
path was byte-identical (CSV and blind file). **0 manual labels.**

| Stratum | Frame | Non-dev frame | Drawn | Dev drawn |
|---|---|---|---|---|
| `top_enterprise` | 40 | 0 | 40 | 40 |
| `rank_41_200` | 160 | 0 | 25 | 25 |
| `rank_401_2000` | 1,600 | 1,584 | 15 | 0 |
| `random_eligible` | 179,450 | 177,498 | 25 | 0 |
| `network_provider/top5` | 5 | 3 | 5 | 2 |
| `network_provider/random` | 775 | 733 | 10 | 0 |
| `low_confidence_review/ownership_low` | 32,265 | 31,676 | 10 | 0 |
| `low_confidence_review/review_flag` | 1,976 | 1,364 | 10 | 0 |
| `technographic_only` | 100,480 | 99,937 | 15 | 0 |

2,277 of the build's 180,511 accounts are development cases. The attribution-v5 contamination log
(`2026-11-07-dev-attribution-v5.json`: the actionable top 170 read during the provider
investigation, every org whose class or tier changed, and the accent-merged ids) is one of the
inputs. An earlier draft on attribution v4 was deleted unlabelled.

### Columns

- **Case:** `case_id`, `strata`, `dev_case`, `dev_sources`, `account_id`, `account_ref` (a seeded
  hash of the account id), `account_name`, `segment`, `best_tier`, `account_kind`.
- **System output** (`system_*`): v3 rank, outreach position, percentile, band, opportunity
  priority, ownership confidence and reasons, evidence-quality band, eligibility and reasons,
  actionable and blockers, review flags, legacy rank and score.
- **Signals:** `signal_ids`, `signal_services` (services, counted services and IPs per signal),
  `details`, `countries`, `n_services`, `n_ips`.
- **Ownership evidence:** the ownership feature counts from scoring v3, plus:
  - `sample_naming_domains` and `sample_third_party_domains`: registrable domains on the records,
    with service counts;
  - the modal `org`, `isp`, `asn` and OpenASN category, and the attribution reasons.
- **Source references:** up to 3 observation and service ids (counted first, exposures first), with
  `ip:port`. Also:
  - the app path `/accounts/{id}`;
  - a `firmable evidence OBS_ID` command;
  - a `firmable inspect-accounts --account ID` command. It writes under `eval/holdout-inspect/`,
    outside the registry's inputs, and its verdict is a heuristic, not a label.
- **Manual:** `manual_entity_type`, `manual_qualified`, `manual_attribution_correct`,
  `manual_evidence_supported`, `manual_reviewer`, `manual_notes`. Same values and rubric as the
  review set ([Label columns](#label-columns)).

**What the CSV never holds:**

- no `suggested_*` column and no checker verdict;
- no NTLM value (only rule names such as `dom_ntlm_corroborated`). `firmable evidence` prints the
  raw record, which can hold NTLM values: treat its output as restricted (ADR 0007);
- no live formula: a cell starting with `=`, `+`, `-`, `@`, tab or CR is written with a leading `'`.

**Blind file.** `.blind.csv` drops everything that shows what the system decided or reveals the
segment or tier:

- `strata`, `dev_case`, `dev_sources`, `segment` and every `system_*` column;
- `account_id` (its `org:`/`dom:`/`net:` prefix is the segment and tier), `best_tier`,
  `account_kind` and `attribution_reasons`;
- `app_path` and `inspect_command`, which embed the id.

It keeps:

- `case_id` and `account_ref`;
- the account name, the signal summary and the ownership evidence;
- the observation and service ids, and the `firmable evidence` command.

**Labelling order.** The deployed app shows system outputs (band, priority, ownership, flags) on
every account page. Label from the evidence in the file, the `firmable evidence` records and public
sources first. Use the app only to read evidence rows, not its verdicts.

Label one file only. `holdout-metrics --labels BLIND` joins the blind file's labels strictly by
`case_id`:

- both files must hold the same case ids with no duplicates;
- `account_ref` must match on every case;
- the full CSV must hold no labels of its own.

**Reviewer guide:** `docs/labelling-guide.md` (how to apply each label, sources, edge cases, two-reviewer
protocol).

### Metrics

`holdout-metrics` reads `manual_*` only:

- Blank is unlabeled and excluded from the denominator. `unclear` counts as a negative.
- It refuses:
  - a CSV with any `suggested_*` column;
  - a duplicate `case_id`;
  - a `dev_case` other than `yes`/`no`;
  - a label outside the rubric values;
  - a non-UTF-8 file (UTF-8 with a BOM, as Excel writes it, is accepted);
  - a `manual_reviewer` that names a model family or "AI"/"model" as a whole word. This is a guard,
    not proof.
- Every rate reports `num`, `den`, `unlabeled`, `rate` and a Wilson 95% interval, separately for
  `all`, `held_out` (`dev_case = no`) and `dev`. A subgroup with no labels reports `den = 0` and
  `"no labels in this subgroup"` instead of a rate.

| Metric | Population | Positive |
|---|---|---|
| `precision_at_k` (20, 40) | `top_enterprise` cases with outreach position ≤ k | `qualified = yes` |
| `attribution_correct` | all cases, and per stratum | `attribution_correct = yes` |
| `evidence_supported` | all cases, and per stratum | `evidence_supported = yes` |
| `entity_type_agreement.by_segment` | per system segment | `entity_type` equals the segment |
| `entity_type_agreement.by_stratum` | network-provider strata | `entity_type = network_provider` |
| `qualified.by_stratum` | enterprise cases per stratum (sub-strata also rolled up to their parent) | `qualified = yes` |
| `qualified.by_actionable` | enterprise cases, actionable vs not | `qualified = yes` |
| `qualified.by_signal_group` | enterprise cases: `exposure` (S01/S03/S04/S05), `hygiene_no_exposure` (S06, no exposure), `technographic_only` (S16 only) | `qualified = yes` |

**Precision@k has no clean value.** It is a census of the top k, and `top_enterprise` is development
data. So `precision_at_k` reports:

- `contamination`, e.g. "top_enterprise is entirely development data";
- per k, the `census` rate and `dev_cases`;
- `clean: null`, with a `clean_reason`.

There is deliberately no all / held-out headline next to it. Uncontaminated rates come from
`rank_401_2000` and the random strata.

`qualified` is an enterprise question, so network-provider strata report entity-type agreement
instead. Per-stratum rates describe that stratum. They are not weighted to the frame, so they do not
combine into a population rate.

### Limitations

- **The top 40 is contaminated.** Every `top_enterprise` case was inspected during development, so
  Precision@20/40 is a census of development data, not a clean test of scoring v3. `rank_41_200` is
  all development cases too.
- **Small n.** With 10–25 cases per stratum, a Wilson interval is often ±20 points or wider. Read
  differences between strata as indications, not findings.
- **One labeler.** No inter-rater agreement can be measured unless a second reviewer labels at least
  part of the set independently.
- **Registry coverage.** Account names mentioned in docs prose are not matched; only ids are.
  Development reading that left no file (ad-hoc queries) is covered only through the conservative
  table-wide sources.
- **Snapshot-specific.** The frames are one snapshot's scoring-v3 tables. A rebuild changes ids,
  ranks and frames, so the holdout is generated once on the final build and then kept.

## Model suggestions

`suggested_*` columns may hold suggestions from a model (`suggested_by` names it). They are
there to speed review, never to replace it. `review-metrics --source suggested` reports them
separately and labels the output `"source": "suggested"`; such figures are provisional and
are not results.

## Results

See `docs/phase3-hardening-results.md`.
