# Exposure-led vs technographic prospecting (2026-11-11)

Question: should the product separate **exposure-led** prospecting (an account shows an exposed
remote-access edge, remote admin, database or management plane: S01/S03/S04/S05) from
**technographic** prospecting (an account runs a named security vendor: S16), and from TLS hygiene
(S06)?

**Decision: not as a new workflow now.** Document the split, measure it in the holdout, and use the
existing filters. Reasons and measurements below. **[F]** = measured on snapshot `2026-11-07`
(scoring v3, eligibility v2, attribution v5). **[H]** = judgement.

## 1. What the eligible enterprise population looks like [F]

Eligible enterprise accounts, 179,450, grouped by which signal families they carry:

| Signal mix | Accounts | Actionable | High band | Medium band | Tier B | Max priority |
|---|---|---|---|---|---|---|
| Exposure (S01/S03/S04/S05) + S16 | 2,189 | 1,143 | 1,303 | 886 | 261 | 99.4 |
| Exposure, no S16 | 3,295 | 1,128 | 405 | 2,890 | 552 | 96.2 |
| S06 + S16, no exposure | 13,845 | 10,149 | 0 | 6,249 | 12,704 | 40.0 |
| S06 only | 59,641 | 48,302 | 0 | 0 | 54,600 | 20.0 |
| S16 only | 100,480 | 0 | 0 | 3,024 | 96,592 | 25.0 |

- The outreach list (`view=actionable`, 60,722 accounts) is 3.7% exposure-led (2,271 accounts).
  The remaining 58,451 are TLS-hygiene accounts (S06), most of them tier-B domain accounts.
- Ordering already separates the modes at the top: every actionable account above eligible rank
  3,707 has an exposure signal. Below that, exposure and hygiene accounts interleave (the last
  exposure-led actionable account is at eligible rank 9,435).
- No account without an exposure reaches the High band (band rule, ADR 0009).
- S16-only accounts (100,480) are never actionable: the `no_security_observation` blocker holds
  them in `view=review`. 84,484 of them have medium or high ownership, no review flag and
  title-or-better evidence, so for a technographic seller they would be usable leads.

## 2. Why the two modes differ [H]

| | Exposure-led | Technographic |
|---|---|---|
| Buyer | security team; message about an observed exposure | vendor or competitive-displacement seller; message about installed footprint |
| Claim | an observed exposure (allowed wording, research-findings §3) | no security claim: "runs Cloudflare / FortiGate" |
| Risk of the claim | higher; needs evidence review | low |
| Attribution risk | owned space (A1/A2) dominates the top | mostly tier B (CDN/WAF fronting a named domain) |
| Ranking signal | priority (relevance × breadth) | vendor identity; priority is uninformative (max 25) |

Ranking S16-only accounts by the same priority as exposures is not meaningful: their priority sits
in a narrow band (12.5–25) and differences reflect breadth only.

## 3. Why not build a separate workflow now

1. **No evidence it improves precision.** No reviewed labels exist for either mode. The holdout
   (`docs/evaluation.md`, "Scoring-v3 holdout") has a `technographic_only` stratum and splits the
   qualified rate by exposure-led vs technographic, so the question can be answered from labels
   before any product change.
2. **The existing API already serves both modes**, with one gap:
   - Exposure-led: `GET /accounts?view=actionable&band=High` (all High accounts have an exposure),
     or `signal=S01` / `S03` / `S04` / `S05` one at a time.
   - Technographic: `GET /accounts?view=review&signal=S16&ownership=high&ownership=medium`.
   - Gap: `signal` is ALL-of, so "any exposure signal" needs one request per signal.
3. **Assignment priority** is signal correctness, attribution and explainable ranking. A second
   ranking for technographics would need its own scoring rule, with no labels to set it.

## 4. If labels support it later

Smallest change, in this order:

1. A derived, read-only `lead_type` field (`exposure`, `hygiene`, `technographic`) on each account,
   and a `lead_type` filter. No scoring change.
2. For technographic leads, order by vendor and ownership, not by priority.
3. Keep the `no_security_observation` blocker for the default (security-seller) outreach list.

## 5. Does the default list tell the three lead types apart? (review, 2026-11-11)

Checked on the deployed page and the public serving DB (`view=actionable`, enterprise, 60,722
accounts, ordered as the page orders them). Lead type is derived here for measurement only, from
the signal families in the registry: `exposure` (any of S01/S03/S04/S05), `hygiene` (S06, no
exposure), `technographic` (S16 only). It is not a field the product serves.

**Composition by outreach position [F]:**

| Lead type | Accounts | First position | Last position | High / Medium / Low band |
|---|---|---|---|---|
| Exposure-led | 2,271 | 1 | 5,292 | 869 / 1,402 / 0 |
| TLS hygiene | 58,451 | 1,630 | 60,722 | 0 / 4,668 / 53,783 |
| Technographic only | 0 | — | — | — |

- Pages 1–32 of the default list (positions 1–1,629, 50 per page) are all exposure-led.
- From position 1,630, the remaining 642 exposure-led accounts are mixed in with hygiene accounts,
  up to position 5,292.
- Technographic-only accounts never reach the default list. They appear under "Needs review", with
  the status "review: no security observation".

**What the page shows [F]:**

- **Band.** High always means an exposure (band rule). Medium mixes both types: 1,402 exposure-led
  and 4,668 hygiene accounts carry the same blue "Medium" label. Low is all hygiene.
- **List rows.** A row shows its top signals only as bare codes ("S06", "S16"), with no name, no
  tooltip and no family. Every row in the default view has the same status, "actionable". For
  hygiene accounts that also carry S16, the chips can put "S16" first.
- **Detail panel.** It names each signal ("S06 TLS hygiene defect (non-CDN endpoint)"), shows its
  details and gives the labelled inferred risk and hypothesis. Here the type is clear.
- **Filters.** A seller can isolate exposure-led accounts only through `band=High` (869 of 2,271)
  or one exposure signal at a time (`signal` is ALL-of). There is no "any exposure" or "hygiene
  only" filter.

**Assessment [H]:**

- **In the list, the three lead types are not clearly differentiated.** Telling them apart means
  knowing the signal codes or opening each account. This matters from page 33 on, and inside the
  Medium band.
- **This is not a defect.** Ranking, filters and claim wording behave as specified (ADR 0009, §1),
  each claim is labelled correctly in the detail panel, and technographic-only accounts are
  correctly held out of outreach. So product behaviour was not changed.
- **Smallest fix, if wanted:** the §4 step 1 plan. Add a read-only `lead_type` field, show it as a
  row tag, add a `lead_type` filter, and give the chips their names as tooltips. No scoring change.
