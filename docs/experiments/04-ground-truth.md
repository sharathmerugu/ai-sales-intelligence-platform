# 04 — Automated ground truth for attribution

**Proposal.** With no human labels and no sales outcomes, take ground truth from sources that are not
circular and can be automated:

- for attribution, WHOIS/RDAP, Certificate Transparency and passive DNS;
- for lead quality, real-world proxy outcomes: CRM conversions, breach or advisory feeds, and a second
  scan.

**Script:** `scripts/04_attribution_evidence.sql`. **Output:** `results/04_attribution_evidence.txt`.

## Method

For attributed services that carry a signal, list the evidence that decided the attribution: reason
codes in `service_attribution` v4.

## Results

| Tier | Deciding evidence | Services |
|---|---|---|
| A1 | registry `org` is a business (`org_not_provider`) | 56,966 |
| A2 | registry `org` is a business inside a provider ASN | 27,377 |
| B | certificate names the domain (CN, SAN or wildcard; with or without SNI agreement) | 334,511 (59.9% of B) |
| B | SNI or HTTP Host only | 199,382 (35.7%) |
| B | reverse-DNS hostname only | 23,699 (4.2%) |
| B | NTLM corroborating a public name | 552 (0.1%) |

## Conclusions

- **WHOIS/RDAP cannot validate A1 or A2.** These tiers rest only on the registry org. RDAP returns
  the same registrant, so a match is guaranteed and proves nothing.
- **Certificate Transparency mostly cannot validate tier B either.** About 60% of tier B rests on a
  certificate that CT also logs. A CT match confirms the certificate exists, not who runs the server.
  The scanner probably chose its SNI values from CT or DNS too, so the SNI-only 36% is not independent
  either.
- **Non-circular checks exist:**
  - forward DNS at scan time (the company's domain resolves to the IP);
  - the organisation field of OV/EV certificates (a vetted subject, unlike DV);
  - Firmable's company/domain index;
  - the company's own published IP ranges or ASN (for A1/A2).
- **Proxy outcomes are the right target for lead quality.** CRM conversion is the only direct one.
  Breach or advisory feeds and a second snapshot measure risk and change, not buying intent.
- **"No humans to label" should not stand.** The 104-case review set (`docs/evaluation.md`) needs
  a few hours of review. It is the only source of attribution precision and Precision@k that is
  neither circular nor model-made. Automated checks can add to it but cannot replace it.
  - Add a random stratum from below the top k so recall-type errors become visible.

## Limitations

- Reason codes describe the winning rule. Some B services also have weaker evidence of other kinds.
- Whether the scanner really took SNI from CT is an inference, not verified.
