# Network classification (attribution v4) — OpenASN evaluation and rules

Problem: after attribution v2 about half of the top 40 org accounts were ISPs, hosters and data
centres. Curated provider-name regexes and reverse-DNS features had stopped converging
(`docs/phase3-results.md`). This change adds a reference table of network types per ASN and
a separate network-provider segment. Regex expansion is frozen.

## Source vetting

| Check | Result |
|---|---|
| Dataset | OpenASN `asn-categories.csv`, release `v2026.10.18` (build 2026-10-18T08:03:28Z), the last weekly release before snapshot 2026-11-07. Pinned in `reference/openasn/v2026.10.18/` |
| Integrity | SHA-256 `28c49e43…e5419` matches the release's `SHA256SUMS` and `manifest.json`; `firmable.attribution.asn` refuses any other file |
| License | Compiled artifacts and overrides are CC0 1.0 (`LICENSE-DATA`); code MIT |
| Provenance | Categories and roles come from ipverse `as-metadata` (CC0); `bad_asn` / `hosting_extra` flags come from X4BNet `lists_vpn` and brianhama `bad-asn-list` (both MIT, attribution in `ATTRIBUTION.md`); org names come from Wikidata (CC0, not used here). RIR WHOIS names are not redistributed |
| PeeringDB | Excluded by OpenASN's own "Legal design" rules (acceptable-use policy). No PeeringDB data is used here |
| Residual risk | ipverse documents its category method only as "multiple signals"; it says categories reflect an AS's primary function and "won't always be correct". OpenASN has 2 GitHub stars and one main contributor |

## Coverage against our data

Snapshot 2026-11-07, 5,233,493 services on 39,049 distinct ASNs:

- 5,233,172 services carry an ASN; 5,232,655 (99.99%) map to an OpenASN category; 38,979 ASNs
  are covered.
- OpenASN categories over the whole file (119,322 ASNs): business 62,550, isp 27,282, hosting
  11,724, education_research 7,060, government_admin 6,039, empty 4,667.
- Disagreement with the v2 rules (services): of the services v2 called `business`, 171,321
  sit on `isp` ASNs and 124,770 on `hosting` ASNs; this is where the ISP/hoster residue lived.

## Known-example validation

Checked against public, well-known networks (the expected class is public fact; the table
records what OpenASN says):

| ASN | Network | OpenASN | Expected | Used as |
|---|---|---|---|---|
| 7922 / 7018 / 3320 / 9808 | Comcast / AT&T / Deutsche Telekom / China Mobile | isp | ISP | provider |
| 174 / 3356 / 1299 / 2914 | Cogent / Lumen / Arelion / NTT | isp, tier1 | transit ISP | provider |
| 24940 / 14061 / 16509 / 36351 | Hetzner / DigitalOcean / Amazon / IBM Cloud | hosting + `bad_asn` | hoster | provider |
| 13335 / 20940 / 54113 | Cloudflare / Akamai / Fastly | hosting + `cdn` | CDN | provider (cdn) |
| 10794 | Bank of America | business | enterprise | enterprise |
| 8068 / 6185 | Microsoft (corp) / Apple (corp) | business | enterprise | enterprise |
| 714 / 32934 | Apple / Meta | **hosting**, access_provider, no flag | enterprise | enterprise (rule below) |
| 2906 / 14340 | Netflix / Salesforce | **hosting**, content_network | content / SaaS | not a network provider (rule below) |
| 37963 | Alibaba Cloud | **business** | hoster | missed by OpenASN; curated name rule still applies |

Top-60 org accounts before the change (v2), by OpenASN category of their own ASN: universities
`education_research` (McGill, UC Davis, Utah, Clemson, USP, NTU, Keio, …), SAP / Cerner /
Baidu `business`, and the residue `isp` or `hosting` (Skyway West, Devoli, Grupohost, Telx,
Claranet, Dialog Axiata, RailTel, EastLink, TekSavvy, Euskaltel, kabelplus, …). Two telcos
are filed as `business` and stay as false positives: AMERICATEL PERU and (arguably) Blue Ridge
Mountain EMC, an electric co-operative that also sells broadband.

## Rules (attribution v4)

1. `network_provider_class(row)`: `isp` → `isp_telco`; `hosting` with a `cdn` flag → `cdn`;
   `hosting` with `bad_asn`, `hosting_extra` or `vpn_provider`, or with a role other than
   `access_provider` / `content_network` → `cloud_hosting`; anything else, including an empty
   category, → not a provider (unknown is preserved and the existing name rules decide).
2. The ASN class applies to an org only when the org **operates** that ASN: its normalised name
   equals the `isp` name, shares its first significant token, or the org holds a majority (≥ 50%)
   of that ASN's services. A different org on a provider ASN is a customer allocation and stays an
   enterprise account (tier A2, `byoip_in_provider`). Customer-owned exposures are never moved to
   the provider.
3. The curated name table still runs first; ASN evidence replaces the data-driven backstops
   for business-named orgs (reason `org_asn_isp` / `org_asn_hosting` / `org_asn_cdn`).
4. **Tier P (network-provider segment)**: a service of a network provider (`isp_telco`,
   `cloud_hosting`, `cdn`) whose own certificate CN/SAN, SNI or HTTP Host names the provider's
   own domain (`domain_matches_org`: label equals the org tokens concatenated, or starts with its
   first token of at least four characters that is not a generic word such as `cloud` or `data`).
   The name must be non-wildcard and not machine-specific (`vps-5f3a2b1c`, `ns3012345`): hosters
   name customer VPSes in their own zone. Reverse DNS alone is not enough: subscriber lines
   are named in the ISP's zone. Account id `net:<org>`, confidence 0.8, infrastructure signals
   allowed.
5. Accounts carry `segment`: `network_provider` for `net:` accounts, `enterprise` otherwise.
   Ranks restart per segment. The API and page serve `enterprise` by default; network providers
   appear only when `segment=network_provider` is selected.

## Measurements

See `docs/phase3-hardening-results.md` for full-data counts and the reviewed before/after
precision.
