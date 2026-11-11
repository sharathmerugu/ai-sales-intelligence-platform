# 0008 — Network type from pinned OpenASN data; enterprise and network-provider segments

Status: accepted (2026-11-10). Amends ADR 0005 (org classification, tiers) and ADR 0006
(ranking is now per segment). Evaluation and vetting: `docs/network-classification.md`.

## Context
After attribution v2 about half of the top 40 org accounts were ISPs, hosters and data centres.
Curated name regexes and reverse-DNS backstops had stopped converging. PeeringDB is excluded
(acceptable-use policy); CAIDA's AS classification download is unavailable.

## Decision
- Vendor OpenASN `asn-categories.csv` release v2026.10.18 (CC0) under
  `reference/openasn/v2026.10.18/`, verified by SHA-256 on every load. Updating it is a
  deliberate change: new directory, new checksum, rebuild, re-review.
- Attribution v4 (`ATTRIBUTION_VERSION = 4`):
  - An org is a network provider when it **operates** an ASN that OpenASN files as `isp`, or as
    `hosting` with a hosting/CDN/VPN flag or a role other than `access_provider` /
    `content_network`. It operates the ASN when it is named like the `isp` field or holds a
    majority of the ASN's services. Unknown categories change nothing.
  - Other orgs on provider ASNs stay enterprise accounts (A2): customer-owned exposures are never
    moved to the provider.
  - Tier **P** (`net:<org>`): a provider's service whose own non-wildcard certificate, SNI or
    Host names the provider's own domain with a non-per-host name. Reverse DNS and
    machine-specific names (`vps-5f3a2b1c…`) are customer naming, not provider evidence.
  - NTLM corroboration counts only with a certificate, SNI or Host (ADR 0007 tightened).
- Scoring v2: same formula; accounts carry `segment` (`enterprise`, `network_provider`), ranks
  restart per segment, and the API serves `enterprise` unless `segment=network_provider` is given.

## Consequences
- Regex expansion is frozen; the name table and backstops remain for orgs OpenASN leaves unknown
  or files as business.
- Known misses: telcos that OpenASN files as `business` (e.g. AMERICATEL PERU), and ISP
  customer-pool labels on ISP blocks ("Leased Line Customer LAN") that stay enterprise A2.
- OpenASN categories come from ipverse's undisclosed "multiple signals"; precision is measured
  by the reviewed sample (`docs/evaluation.md`), not assumed.
