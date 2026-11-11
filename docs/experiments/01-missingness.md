# 01 — Missing values: pattern and what outside data could fill

**Proposal.** The missing values are not random: cloud-hosted companies and edge devices have the
gaps. Fill attribution gaps from WHOIS, passive DNS, certificate logs, a company index or an LLM.
Observation gaps, such as an unseen version, cannot be recovered.

**Script:** `scripts/01_missingness.sql`. **Output:** `results/01_missingness.txt`.

## Method

Take the 94,162 services that carry an exposure signal (S01, S03, S04 or S05). Then:

- measure abstention (tier C) by registrant class and by the scanner's cloud tag;
- classify the names that abstained services do carry;
- measure version visibility per signal, and for S01 per vendor, against other fingerprint fields.

## Results

**Abstention by network context.** Overall, 71.4% of exposure services are tier C.

| Registrant class | Cloud tag | Services | Tier C |
|---|---|---|---|
| isp_telco | no | 40,337 | 82.6% |
| cloud_hosting | no | 27,153 | 70.9% |
| cloud_hosting | yes | 15,794 | 87.4% |
| business | no | 9,612 | 0.0% (by construction: business orgs are A1/A2) |
| saas_platform | no | 795 | 56.2% |

**Names on the 67,248 abstained exposure services.** 67,055 abstain with
`abstain_no_customer_evidence`.

| What the record carries | Services | Share |
|---|---|---|
| No certificate, SNI or Host at all | 18,346 | 27.3% |
| Certificate CN is an IP | 7,484 | 11.1% |
| Vendor or default certificate | 5,250 | 7.8% |
| CN is not a domain | 29,686 | 44.1% |
| Domain-like name present | 6,482 | **9.6%** |

**Version visibility** (observation gap): S01 4.5%, S03 47.8%, S04 28.5%, S05 22.1%.

| S01 vendor | Services | Version | Favicon | JARM | HTML hash | Distinct HTML hashes |
|---|---|---|---|---|---|---|
| SonicWall | 6,991 | 0.0% | 94.0% | 67.6% | 99.6% | 3,483 |
| Citrix NetScaler | 4,583 | 5.5% | 29.3% | 44.3% | 100% | 2,438 |
| FortiGate | 3,948 | 0.4% | 56.8% | 86.5% | 95.3% | **179** |
| Check Point | 1,733 | 0.0% | 5.7% | 90.8% | 98.9% | 423 |

## Conclusions

- **The non-random pattern is confirmed.** Abstention concentrates on cloud and ISP address space.
  Self-hosted business ranges are always attributed. The gap is missing-not-at-random, so cloud-hosted
  firms are under-represented in every ranked list.
- **Outside data could reach only a small part of the gap.** Only 9.6% of abstained exposure services
  carry a domain-like name to look up.
  - WHOIS/RDAP returns the same registrant (the cloud or ISP) that we already have.
  - Passive DNS on cloud IPs risks naming an earlier tenant, because cloud IPs change hands.
  - A forward-DNS check (the company's domain resolves to this IP at scan time) is the useful source.
- **Reject LLM fill.** An LLM is not evidence, can invent owners, and sending IPs to an outside model
  breaks the data-handling rules.
- **"Observation gaps cannot be recovered" is too strong.** Edge devices rarely show a version, but
  login-page HTML hashes cluster tightly. FortiGate has 179 distinct hashes over 3,948 services. With
  a public reference table that maps hashes to firmware builds, these could serve as a version proxy.

## Limitations

- The certificate classes come from regex heuristics. "CN is not a domain" includes internal
  hostnames that a company index might still match.
- The cloud tag is the scanner's own field (32.5% coverage) and misses smaller hosters.
- The firmware-proxy idea is untested. No reference table was built.
