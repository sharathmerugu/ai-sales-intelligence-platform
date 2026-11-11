# Ranking v3: priority, ownership and evidence as separate axes (2026-11-11)

Scoring v3 and eligibility v1 replace the scoring v2 composite as the ranking the app serves. The v2
score is kept next to it (`legacy_score`, `legacy_rank`) and the v2 tables stay on disk, so before/after
comparisons can be reproduced. ADR: `docs/decisions/0009-scoring-v3-priority-apart-from-confidence.md`.

**[F]** measured on the full snapshot `2026-11-07`. **[H]** heuristic or judgement. No result below is
a precision figure: the review set has **0 human labels**.

## 1. Why

The data-science experiments (`docs/experiments/`) found three problems with scoring v2:

- **Known negatives ranked high** (exp 02, 06). The v2 enterprise top 100 held 12 IP-registry
  placeholders and ISP pool labels, among them "Leased Line Customer LAN", "leased=false" and
  "ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE" [F].
- **Attribution drove the rank** (exp 05). The score multiplied attribution confidence into the
  priority. Rank correlation of score with attribution confidence: 0.755 [F]. A high score could mean
  "strong exposure" or only "sure of the owner".
- **False precision** (exp 06). Decimal scores, large exact ties, and a fragile top 40.

## 2. Old behaviour (scoring v2, now "legacy")

```
score = 100 × R × S × A × Q          ranked per segment: score desc, counted IPs desc, account_id
R = noisy-OR of signal weights        S = 0.5 + 0.5·min(1, log2(IPs)/4)
A = mean attribution confidence       Q = mean match-basis quality   (ADR 0006)
```

Every account with counted evidence was ranked, whoever the registry named. The page showed `score`
with one decimal and four component bars.

## 3. New behaviour

Code: `src/firmable/accounts/eligibility.py` (eligibility, ownership, review flags),
`scoring.py` (priority, percentile, bands, actionability, legacy score), `rollup.py` (features and
assembly). `SCORING_VERSION = 3`, `ELIGIBILITY_VERSION = 1`, `LEGACY_SCORING_VERSION = 2`. Tables land
in `accounts/scoring=v3/attribution=v4/...` (a frozen v4 reproduction: the measurements in this document were taken
there). Attribution v5 (`docs/attribution-implementation.md` §7) writes `scoring=v3/attribution=v5` with
`ELIGIBILITY_VERSION = 2`. `account_evidence` and `account_signals` are unchanged.

### 3.1 Three axes, never multiplied together

| Axis | Field | Definition |
|---|---|---|
| Why act | `opportunity_priority` | `100 × R × S` over counted evidence. Same weights and breadth as v2. **No attribution or evidence-quality term.** |
| Who owns it | `ownership_confidence` | `high` / `medium` / `low` from records that name the account (§3.3). |
| How good the observations are | `evidence_quality_band` | Mean best match basis per counted service: ≥ 0.9 `high` (product, protocol, TLS, WAF), ≥ 0.7 `medium` (title), else `low` (scanner tag). |

Attribution still gates which exposures count: exposures on weak tier-B services are blocked by
`allows_infra_signals`, as in v2.

### 3.2 Eligibility: who is in the prospect population

An org account (tier A1/A2) is **excluded** only when all three hold:

1. **The name is a registry placeholder or pool label** (`is_registry_label`). Examples: subscriber,
   customer, leased line, pool, DHCP, BRAS, PPPoE, GPON, FTTx, WiMAX, GGSN, "non-portable",
   "transferred from … whois", "local registry", bare "Entreprise" or "Core Infrastructure". Bare
   words that also occur in company names ("home", "dynamic", "assigned") count only inside pool
   phrases.
   - A name that identifies one organisation is never a label. That covers a legal form (Ltd,
     GmbH, a.s., Kommune, …), "Customer - Name" and "Customers (Name)". So "Home Credit a.s.",
     "Address block assigned to … Ltd" and "Get AS Customers (… Kommune)" stay eligible.
2. **No scanned record names the account** (§3.3).
3. **At least one structural sign:**
   - tier A2, a sub-allocation inside a provider network;
   - the same label registered under ≥ 3 network operators;
   - ≥ 20% of its services carrying subscriber reverse DNS (an access label, or the operator's own zone).

A label alone never excludes an account. Structural signs alone never exclude a real name. Excluded
accounts get no rank, percentile or band, but keep all their evidence. The API serves them under
`view=excluded`.

### 3.3 Ownership confidence

Features per org account are computed over **all** its attributed services, not only those with
signals. They come from the attribution `evidence.parquet` and the services `cert_subject_o`.

| Field | Meaning |
|---|---|
| `named_public_services` | Certificate subject O (`org_names_match`), or a non-wildcard certificate CN/SAN, SNI or HTTP Host with an outcome attribution trusts (`accepted`, `infra_domain`; never `provider_cert` or `non_company`) whose registrable domain names the account (`ownership_names_org`, §3.3.1). |
| `named_rdns_services` | A reverse-DNS hostname (`accepted`, `ptr_like`, `infra_domain`) names the account, and is not in the network operator's own zone unless the account is the operator. |
| `third_party_domains` | Distinct accepted certificate/SNI/Host domains that do not name it. |
| `network_operators` | Distinct ISP names its services sit under. |
| `subscriber_rdns_services` | Reverse DNS with an access label, or in the operator's zone, that does not name the account. |

- **Org accounts:** `high` if `named_public_services > 0`; `medium` if only reverse DNS names it;
  `low` if only the IP registry does (`registry_only`).
- **Domain accounts (tier B):** the record's own name is the account, so the band comes from the
  attribution confidence. The existing `confidence_band` cut points apply: ≥ 0.75 `high`,
  ≥ 0.5 `medium`.
- **Tier P:** `high`, because the provider's own domain is on the record.
- **NTLM is never read** for ownership (ADR 0007).

#### 3.3.1 Name matching for ownership

`ownership_names_org` (`attribution/providers.py`) is stricter than the reviewer aid
`plausibly_names_org`. It accepts:

- the org's tokens joined as the label (`skywaywest.net`), or a label that starts with its first
  distinctive token;
- the org's initials (`mit.edu`), or the first significant token as the whole label (`sap.com`);
- a distinctive word (≥ 5 letters, not a common organisation word) that is the whole label, or its
  prefix or suffix with at most 3 other letters (`berkeley.edu`, `ucdavis.edu`).

A word buried in a longer label does not count, so "… Italia SpA" is not named by
`telecomitalia.it`.

Reverse DNS in the network operator's zone (a domain that names the ISP) names the operator. It
names the account only when the account is the operator. "Assigned to Liquid Zimbabwe" in Liquid
Telecom's zone therefore counts as subscriber reverse DNS, not as ownership.

### 3.4 Review flags

Review flags keep an account eligible but out of the outreach list until a person clears them:

- **`possible_network_provider`:** records name ≥ 10 other organisations' domains, and more than 10×
  the services whose certificate, SNI or Host names the account. Typical case: a hoster's own portal
  certificate among its tenants' certificates.
- **`registry_label_name`:** the name reads as a label, but the exclusion conditions do not all hold.
- **`label_spans_network_operators` and `subscriber_reverse_dns`:** raised only when no record names
  the account.

### 3.5 Rank, percentile and band

- **Rank:** eligible accounts of a segment only. Order: priority desc (rounded to 4 decimals), an
  exposure signal first, counted IPs desc, `account_id`. Deterministic: two full builds were
  identical row for row [F].
- **Percentile:** 100 × the share of eligible accounts in the segment with strictly lower priority.
  Ties share a percentile. It is floored to 2 decimals, so the top account shows "higher than 99%",
  never 100%.
- **Bands:** cut points from exp 06.

  | Band | Rule |
  |---|---|
  | **High** | percentile ≥ 99 **and** at least one counted exposure signal (S01/S03/S04/S05) |
  | **Medium** | percentile ≥ 90, or ≥ 99 without an exposure |
  | **Low** | everything else |

  The exposure condition keeps the v2 design rule that hygiene or technographics alone never read
  as top priority.
- **Peer groups:** none. Industry and size groups need firmographic data the project does not have.
  Tier-based groups would be circular (exp 05).

### 3.6 Actionable outreach

`actionable` is true only when all of these hold:

- the account is eligible;
- ownership is `medium` or `high`;
- it has no review flag;
- at least one counted security observation (S01, S03, S04, S05 or S06) matched on a product,
  protocol, TLS or title basis (quality ≥ 0.7).

S16 alone is technographic and makes no security claim. `actionable_blockers` lists the reasons in a
fixed order: `excluded`, `ownership_low`, `review_flags`, `no_security_observation`.

### 3.7 API and page

- **Listing:** `GET /accounts` defaults to `view=actionable`. Other views: `review` (eligible, not
  actionable), `excluded` and `all`.
- **Filters:** `band` and `ownership`. `min_priority` replaces `min_score`.
- **Account items:** separate `priority`, `ownership`, `evidence`, `eligibility`, `actionable`,
  `actionable_blockers`, `top_signals` and `legacy` blocks. There is no bare `score` field.
- **Page:** shows rank, band and percentile, ownership, evidence and top signals. The legacy score sits
  in a collapsed "comparison only" section.
- **Explanations:** one plain-English line per axis. Example on real data, an A1 hosting company:

  > High relative priority: higher than 99% of eligible enterprise accounts in this snapshot
  > (priority 99.4 = 100 x relevance 0.99 x breadth 1.00). Not a purchase probability, a confirmed
  > vulnerability or a loss estimate. · Ownership confidence high (tier A1): a certificate, SNI or
  > HTTP Host on 2 of 185 attributed services names this account. Inferred from scan records, not
  > verified. · Evidence quality high … · Review: records name 62 other organisations' domains, more
  > than 10 times the 2 service(s) whose certificate, SNI or Host names this account (possible hosting
  > or ISP). · Outreach: not actionable until reviewed: open review flags.

## 4. How the rules were set, and what was not tuned

- **Weights:** no signal weight, basis quality or breadth constant changed.
- **Holdout:** the review set (`docs/evaluation.md`) is the final holdout. Its labels (none) and its
  model suggestions were not used.
- **Development set for the eligibility and flag rules:** the v2 enterprise top 100, all 266 names
  the first label draft excluded, and the actionable top 400 for the provider flag. This overlaps the
  review set's `top40_*` strata, so those strata are not a clean test of eligibility. The
  `tier_b_sample`, `asn_reclassified` and `abstain_sample` strata were not looked at.
- **False exclusions found during development, and fixed:**
  - The first label regex excluded real companies: Home Credit a.s., "… Dynamics LLC", customer
    blocks named after a company. Hence the legal-form exemption.
  - A "multi-tenant ⇒ exclude" rule would have excluded the Irish Government and the universities of
    Cambridge, Linköping and Umeå, because the matcher missed their domains. Multi-tenancy is
    therefore a review flag, never an exclusion.
- **Independent code review** (a separate reviewer agent, before deployment) found two
  ownership defects, both fixed with tests:
  - Operator-zone reverse DNS counted as naming a customer label that contained the ISP's name.
  - The loose substring matcher, for example "… Italia SpA" read as named by `telecomitalia.it`.

  It also found that shared, default and wildcard certificates could name an account. Measured impact
  of all fixes: ownership `high` 33,743 → 33,498, `low` 34,026 → 34,372, actionable
  60,891 → 60,633, excluded 276 → 282.
- **Spot-check after freezing the rules** [H]: 30 randomly drawn (seed 0.20261111)
  `possible_network_provider` accounts not seen during development. By the author's reading: about
  20 hosting, colocation, ISP or registrar businesses; 3 enterprises (a software company, a
  university, a public-sector body); about 7 unclear. This is an author judgement, not a label.

## 5. Measured results (offline, full snapshot) [F]

Commands in §8. Build of accounts and the serving DB: 36 s.

### 5.1 No regression in attribution, evidence or provenance

- **Attribution:** the attribution layer (v4) was not rebuilt.
- **Account evidence:** `account_evidence` (676,127 rows, every provenance and attribution column) and
  `account_signals` are identical between v2 and v3, `EXCEPT ALL` in both directions.
- **Accounts:** all 180,444 keep the same tier, segment, name, signals and IP count.
- **Legacy score:** equals the stored v2 score for 179,474 of 179,669 enterprise accounts. The other
  195 differ by exactly 0.0001.
  - Cause: v3 rounds per-account means to 9 decimals before scoring.
  - Why: DuckDB's parallel `avg` returned 0.6999999999999998 for three 0.7 values, so an unrounded
    mean could cross a band cut point and v2 rounding was not reproducible run to run. 45 scores
    already differed between the stored v2 table and a rebuild with the same, unrounded scoring code.
  - Comparisons below use the stored v2 tables, not the recomputed legacy score.
- **Public DB:** `publish-public` checks are unchanged: no NTLM or `evidence_json` columns, raw file
  coordinates nulled. Ownership features never read NTLM.

### 5.2 Eligibility coverage (enterprise segment, 179,669 accounts)

| | Accounts |
|---|---|
| Excluded (registry label, no naming record, structural sign) | 282 |
| … of which A2 sub-allocation / ≥ 3 operators / subscriber reverse DNS | 272 / 9 / 90 (several can apply) |
| Eligible | 179,387 |
| Actionable | 60,633 |
| Review (eligible, not actionable) | 118,754 |
| Blocker: no counted security observation (mostly S16-only) | 100,525 |
| Blocker: ownership low (no record names the account) | 34,372 |
| Blocker: review flags | 1,995 |
| Flags: `possible_network_provider` / `subscriber_reverse_dns` / `label_spans_network_operators` / `registry_label_name` | 527 / 1,309 / 234 / 42 |

**Bands:**

| Population | High | Medium | Low |
|---|---|---|---|
| Eligible | 1,729 | 13,058 | 164,600 |
| Actionable | 872 | 6,062 | 53,699 |

The network-provider segment (775 accounts) is all `high` ownership, and 697 of its accounts are
actionable.

### 5.3 Top-k membership: legacy list vs candidate outreach list

- **Legacy list:** all enterprise accounts by v2 rank.
- **Candidate list:** actionable enterprise accounts by v3 rank.

| | Top 20 | Top 40 | Top 100 | Top 1,000 |
|---|---|---|---|---|
| Overlap | 10 | 22 | 53 | 494 |
| Legacy top-k now actionable / review / excluded | 16 / 3 / 1 | 27 / 9 / 4 | 54 / 34 / 12 | 494 / 462 / 44 |
| Candidate top-k ownership high / medium | 20 / 0 | 38 / 2 | 91 / 9 | 788 / 212 |
| Candidate top-k tier A1 / A2 / B | 17 / 3 / 0 | 32 / 4 / 4 | 76 / 14 / 10 | 625 / 180 / 195 |
| Legacy top-k tier A1 / A2 / B | 19 / 1 / 0 | 36 / 4 / 0 | 82 / 18 / 0 | 665 / 301 / 34 |

- In the candidate list every top-100 account has corroborated ownership and is in the High band.
- Tier-B (mostly cloud-hosted) accounts in the top 1,000 rose from 34 to 195, because attribution is
  no longer multiplied into the rank.

### 5.4 Known negatives and likely enterprises (name classes, not labels)

| Class | Accounts | Legacy top 20 / 40 / 100 / 1,000 | Candidate top 20 / 40 / 100 / 1,000 | Candidate excluded / actionable |
|---|---|---|---|---|
| Registry label (`is_registry_label`, org accounts) | 324 | 1 / 4 / 12 / 47 | 0 / 0 / 0 / 0 | 282 / 0 |
| Experiment-02 pool regex (crude) | 642 | 1 / 4 / 4 / 37 | 0 / 0 / 0 / 1 | 221 / 115 |
| Likely enterprise (university, hospital, bank, government …) | 1,581 | 12 / 21 / 34 / 203 | 15 / 22 / 47 / 243 | **0** / 748 |

- The one experiment-02 match left in the candidate top 1,000 is a registered company whose name
  contains "B2B".
- No likely-enterprise account is excluded. 833 are not actionable, mostly for low ownership or no
  security observation. The stricter matcher moved some real ones to review; for example, a
  university whose own domain is not matched.

### 5.5 Deterministic source-record checker [H]

These are `inspect-accounts` verdicts on 8 sampled records per account. They are heuristic and are
not ground truth.

| Top 40 | corroborated | reverse DNS only | registry only | weak | contradicted | records showing the claimed signal |
|---|---|---|---|---|---|---|
| Legacy (v2) | 23 | 2 | 4 | 6 | 5 | 320 / 320 |
| Candidate (v3 actionable) | 32 | 2 | 2 | 2 | 2 | 318 / 318 (2 records had no check) |

All 23 legacy "corroborated" accounts stay actionable. Of the 5 legacy "contradicted", 1 is excluded,
3 are in review and 1 is still actionable.

The candidate's 2 "contradicted" are:

- a government IT agency whose records carry the government's reverse-DNS zone;
- a software company whose records carry its product brand domain, which the matcher does not tie to
  the company.

The 2 "weak" are a telco and a university whose own domain (its initials) the matcher missed. One
"reverse DNS only" account is a telco.

Two consortium networks (a state college board and a school cooperative, whose records name member
institutions) were in the candidate top 40 before the review fixes. They are now in review.

### 5.6 Priority and ownership stay distinguishable

**Rank correlation with mean attribution confidence:**

| Measure | Correlation |
|---|---|
| Opportunity priority (eligible accounts) | **0.121** |
| Legacy score | 0.755 |

**Band × ownership (eligible accounts):**

| Band | high | medium | low |
|---|---|---|---|
| High | 719 | 218 | 792 |
| Medium | 2,866 | 5,695 | 4,497 |
| Low | 29,913 | 105,886 | 28,801 |

792 High-priority accounts have low ownership. They sit in the review queue, not the outreach list.

**Checked through the HTTP API on the real serving DB:**

- No item carries a bare `score`.
- Two accounts with the same priority (99.433, both High, percentile 99) return different `actionable`
  values and blockers. One is actionable. The other is held for `review_flags`
  (`possible_network_provider`).
- Each detail explanation has separate priority, ownership, evidence and outreach lines.

### 5.7 Stability (overlap with each list's own unperturbed ranking; 30 joint draws per level, seed 20261111)

| Perturbation | Candidate top 20 / 40 / 100 (mean, min) | Legacy top 20 / 40 / 100 (mean, min) |
|---|---|---|
| One weight ±10% | 1.00, 0.95 / 0.99, 0.98 / 0.95, 0.75 | 0.96, 0.85 / 0.95, 0.83 / 0.95, 0.74 |
| All weights × U(0.9, 1.1) | 0.98, 0.75 / 0.98, 0.83 / 0.93, 0.81 | 0.91, 0.85 / 0.92, 0.83 / 0.90, 0.82 |
| One weight ±20% | 0.96, 0.75 / 0.94, 0.83 / 0.91, 0.71 | 0.86, 0.40 / 0.88, 0.48 / 0.89, 0.49 |
| All weights × U(0.8, 1.2) | 0.91, 0.75 / 0.91, 0.75 / 0.86, 0.71 | 0.80, 0.40 / 0.80, 0.50 / 0.82, 0.53 |
| One weight ±50% | 0.90, 0.50 / 0.86, 0.63 / 0.86, 0.71 | 0.78, 0.40 / 0.80, 0.48 / 0.83, 0.49 |
| All weights × U(0.5, 1.5) | 0.81, 0.45 / 0.80, 0.65 / 0.74, 0.50 | 0.57, 0.35 / 0.59, 0.38 / 0.67, 0.46 |
| Bootstrap of counted services within accounts (20 runs) | 0.66, 0.55 / 0.78, 0.70 / 0.71, 0.65 | 0.65, 0.45 / 0.66, 0.55 / 0.71, 0.65 |

- The candidate list is more stable under weight changes, because attribution and evidence quality no
  longer jitter the order.
- It is about as sensitive as legacy to which services were observed (bootstrap).
- Order inside the top 40 still carries little information. The band and the percentile are the
  message, not the rank number.
- The top priority value saturates: 10 enterprise accounts tie at 99.43 (all six signals, ≥ 16
  IPs) and are ordered by counted IPs.

### 5.8 Verification before and after deployment

| Check | Result |
|---|---|
| Unit and integration tests | 653 passed, slow test included |
| e2e on the local public DB, Basic auth on | 22 / 22 passed (desktop and Pixel 7) |
| Independent review | 2 medium and 7 low findings; all 9 fixed, with tests for the ownership, certificate-outcome, label-regex and serving-version fixes |
| Deployed | Railway, commit `5be744f`, 2026-11-11; previous deployment `2a02391` |
| e2e on production | 22 / 22 passed |
| Live API | `/health` reports 180,444 accounts; `view=actionable` returns 60,633 and `view=excluded` 282; no item has a bare `score` |

### 5.9 Labels

The review CSV holds 104 cases with **0 manual labels**. The scoring-v3 holdout
(`docs/evaluation.md`, 155 cases, 88 held out) also holds **0 manual labels**. No precision, recall
or calibration figure exists for either ranking.

### 5.10 After attribution v5 (2026-11-11) [F]

Attribution v5 (`docs/attribution-implementation.md` §7) changed attribution, not scoring: the
accent fold, 12 corroborated provider entries and key-level org profiling. Accounts and serving
were rebuilt on it; the scoring algorithm is unchanged. §5.1–5.8 stay measured on attribution v4.

| Enterprise segment | Attribution v4 | Attribution v5 |
|---|---|---|
| Accounts (all segments) | 180,444 | 180,511 |
| Network-provider accounts | 775 | 780 |
| Excluded | 282 | 281 |
| Actionable | 60,633 | 60,722 |
| Review (eligible, not actionable) | 118,754 | 118,728 |
| High band (eligible / actionable) | 1,729 / 872 | 1,708 / 869 |

Overlap of the actionable outreach list, v4 vs v5, by position: top 20: 18, top 40: 37,
top 100: 93, top 200: 189, top 1,000: 981. The three accounts that left the v4 top 40 (a
Lithuanian and a Mexican operator, and a Dutch ISP) are provider-classified in v5. The Lithuanian and Dutch
ones now sit in the network-provider segment; the Mexican operator's registry block abstains, and
its own domain account stays in the enterprise segment, not actionable (telco domain accounts are a
known limitation, attribution-implementation §7.4).

Account ids of 654 accented orgs changed (`org:telefónica chile` → `org:telefonica chile`). Old links
now redirect by rule (`docs/api.md`, "Ids from an older build"; deployed in `aa78567`): of the 250 public ids
that disappeared, 198 resolve by accent fold and 7 by an org↔net prefix swap; 45 have no successor and
return 404. The v2-vs-v3 comparison needs both lists on one attribution
version, so it stays measured on v4; a rerun with `--legacy …/scoring=v2/attribution=v4/…
--candidate …/scoring=v3/attribution=v4/…` reproduced the recorded report exactly.

**Verification of the v5 deployment:**

| Check | Result |
|---|---|
| Tests | 805 passed, slow test included |
| e2e, local public DB, Basic auth on | 22 / 22 |
| Independent reviews (attribution v5; holdout tooling) | 0 critical. Attribution: 9 medium, 7 low, 1 question; holdout: 12 medium, 8 low, 1 question. All medium findings fixed with tests; low findings fixed or documented |
| Deployed | Railway, commit `fd7c671`, 2026-11-11 (`serving_version` 3); previous deployment `5be744f` |
| Production = local build | 8 endpoints (page, three views, network-provider list, folded search, signals, one detail) byte-identical to the local public DB |
| e2e on production | 22 / 22 |
| Live API | `/health` 180,511 accounts; `view=actionable` 60,722, `view=excluded` 281; no bare `score`; unauthenticated `/accounts` → 401 |

## 6. Unresolved scientific limitations

1. **No ground truth.** Every improvement above is internal: placebo classes, a heuristic checker and
   stability. None shows that a High band means a better lead.
2. **Size bias is unchanged.** The candidate top 40 is still mostly universities and large public
   bodies. Breadth saturates at 16 IPs, and nothing normalises for footprint (exp 02, 06).
3. **Provider leakage remains, reduced by attribution v5** (`docs/attribution-implementation.md` §7, §5.10 below).
   - Fixed in v5: the accent bug ("Telefónica" read as a business), and 12 named operators and
     hosters corroborated by ASN, OpenASN or `isp` evidence, among them the Mexican and Lithuanian
     operators that sat at actionable ranks 24 and 26 under v4.
   - Not fixed (named in §7.4 with the reason): hosters whose own ASNs OpenASN files as `business`,
     sub-allocated resellers with no evidence naming them, IT outsourcers with mixed evidence, and
     telco domain accounts in the enterprise segment. The "Turkish cloud host at rank 116" in the v4
     draft of this note did not reproduce; the Turkish hosts found sit at ranks 69 (fixed) and 180
     (not fixed).
   - Consortium networks (state college boards, school cooperatives, research networks) look like
     enterprises but carry members' services. Documented only; no rule.
   - Key-level profiling in v5 moved one actionable enterprise (an IT distributor, v4 rank 301) to
     `saas_platform` through the multi-tenant backstop. That needs a human check.
4. **The ownership matcher is loose and incomplete.**
   - `plausibly_names_org` misses brand and product domains, and initials with possessives
     ("King Mongkut's …").
   - It can also accept a domain that merely contains a distinctive word.
   - `high` needs only one naming record. 127 actionable org accounts have naming records on fewer
     than 5% of their services.
5. **The flag and exclusion thresholds are hypotheses:** 10 domains and 10×, 3 operators, 20%,
   bands at the 99th and 90th percentiles. They were chosen on development data with no labels.
6. **Bootstrap stability of the top 20 is about 0.66** for both rankings. The single snapshot cannot
   show stability across crawls.
7. **Missing-not-at-random abstention (exp 01) is untouched.** Tier C is still 69.7% of services.
   Cloud-hosted firms rank better than before, but only when they reach tier B.
8. **The "no security observation" blocker** keeps 100,525 S16-only accounts out of outreach. This is
   a product decision for a general security seller. A competitive-displacement seller would want a
   different rule.

## 7. Manual review still required

1. **Label the review set.** Fill the `manual_*` columns (`docs/evaluation.md`). Add the candidate
   top 40 and a random stratum from below the top k, so the two rankings can be compared on precision.
   The scoring-v3 holdout (`firmable holdout-set`, `docs/evaluation.md` "Scoring-v3 holdout") does
   this: it adds the top 40 and random strata, and leaves out every development case.
2. **Check the 282 exclusions.** The list is written by `compare-rankings` to
   `~/firmable-work/eval/2026-11-07-ranking-compare-detail.json`. Do this especially for the 90 with
   subscriber reverse DNS.
3. **Clear or confirm review flags** before outreach, starting with the 857 High-band accounts in
   `view=review`.
4. **Check the 833 likely-enterprise accounts that are not actionable.** Most have registry-only
   ownership. A human can often find the owner's domain where the matcher could not.
5. **Feed provider misclassifications into attribution v5:** the telcos, hosters and consortium
   networks found in §6.3 and in the inspect worksheet
   `~/firmable-work/eval/2026-11-07-inspect-enterprise-v3.md`.
6. **Keep sensitive details behind review, unchanged:** NTLM values, compromise indicators and OT
   exposure.

## 8. Reproduce

```bash
uv run pytest                                                     # 653 tests, ~60 s
uv run firmable build-phase3 2026-11-07 --steps accounts serving  # ~40 s; scoring=v3 tables + serving DB
uv run firmable compare-rankings 2026-11-07                       # ~2 min; ~/firmable-work/eval/2026-11-07-ranking-compare{,-detail}.json
uv run firmable inspect-accounts 2026-11-07 --top 40 --out ~/firmable-work/eval/2026-11-07-inspect-enterprise-v3
```

- **Legacy tables:** `~/firmable-work/lake/accounts/scoring=v2/attribution=v4/...` (unchanged; a frozen v4
  reproduction. Account ids change across attribution versions, so after v5 run `compare-rankings`
  with `--legacy` pointing here and `--candidate .../scoring=v3/attribution=v4/...`; it refuses a missing
  legacy path.)
- **Legacy serving DBs:** backed up as `~/firmable-work/serving/2026-11-07{,.public}.scoring-v2.duckdb`.
- **Report contents:** the comparison report holds counts only. The detail file holds account ids and
  stays outside Git.
