# Company Attribution — resolving scan observations to sales accounts

Status: research draft. All counts come from `sql/exploration.sql` §4–§5 on
the full file, using signal-eligible observations and services unless stated
otherwise.

## 1. The core problem

`org` names the **registrant of the IP block**, not the operator of the
service. In this dataset that is usually the infrastructure provider.

- **Concentration in a few providers:** `Incapsula Inc` (28.9% of rows),
  `Google LLC` (26.9%), `Cloudflare` (7.3%), Amazon (4.1%) and Alibaba (3.1%)
  together exceed 70% of rows.
- **The two fields usually agree:** `org == isp` on 78.0% of rows.
- **Hosted-tenant evidence is elsewhere:** for a service run by a company on
  AWS, Azure, GCP, a CDN or a hosting provider, `org` gives no information
  about the company. The company identity has to come from names in the
  record.

**The account is therefore never inferred from `org` alone unless the org is
known not to be an infrastructure provider.**

## 2. Attribution sources found in the data

| Source | Field | What it is | Coverage (eligible services) | Strength | Failure modes |
|---|---|---|---|---|---|
| Registrant org | `org` | RIR/WHOIS org of the netblock | 100% | Strong *only* for non-provider orgs | Provider/ISP/SaaS platforms; subsidiaries registered under a parent (Optum under UnitedHealth); legacy names (`Wal-Mart Stores, Inc.`, `Avago Technologies` → Broadcom); ISP subscriber CPE |
| Network operator | `isp` | Operating network | 100% | Context only | `org ≠ isp` with a provider `isp` signals BYOIP or a sub-allocation (2.76% of rows) |
| Reverse/forward DNS | `hostnames[]` (and the redundant `domains[]`) | PTR and forward names | 58.9% of eligible observations have any; 29.1% have a non-PTR name | Medium | Mostly provider PTRs: `googleusercontent.com`, `amazonaws.com`, `incapdns.net`, `your-server.de`. A shared-hosting IP lists many unrelated tenants |
| SNI / vhost probed | `_shodan.options.hostname` | Name the scanner put in SNI/Host | 13.1% of eligible observations | Strong | The name came from DNS/CT discovery, so a CNAME to a SaaS platform names the brand while the service is the platform's |
| HTTP Host | `http.host` (non-IP) | Host header used | 12.9% | Medium–strong | Mirrors SNI; equals the IP on most rows |
| TLS certificate | `ssl.cert.subject.CN` (SAN in raw DER) | Name the server asserts | 16.3% (CN) | Strong if the certificate is trusted and specific | Vendor default CNs (`draytek.com`, `unifi.local`, Alibaba WAF `notexist.com`); hosting-brand certs (`hstgr.cloud`, `cloudflaressl.com`); 26% of CNs are wildcards; self-signed device certs |
| NTLM AD domain | `ntlm.dns_domain_name`, `.fqdn` | Internal Active Directory domain | 15,701 raw rows; ~1,284 eligible with a public-looking dotted domain | **Strongest**: organization-chosen and internal | VPS defaults (`WIN-…`, `vultr-guest`); `.local` / `.corp` names that do not map to a public domain |
| Page content | `http.title`, `http.html`, `http.components`, `http.favicon.hash` | Brand text and tech stack | 50% of HTTP rows have a title | Weak–medium | Generic titles, default pages, multilingual text; needs entity matching |
| Tracking IDs | `http.identifiers.google_analytics / google_tag_manager` | Analytics IDs | <1% of HTTP rows (sample) | Strong link across sites | Agencies reuse IDs across clients |

### Evidence source counts

Signal-eligible observations, after removing PTR names, non-company names
and infrastructure domains (Q5.2):

| Source | Observations | Distinct domains |
|---|---|---|
| hostname | 1,587,812 | 648,337 |
| cert_cn | 831,219 | 284,299 |
| sni_scan | 777,634 | 195,047 |
| http_host | 761,862 | 205,318 |
| ntlm | 1,284 | 772 |

## 3. Name filtering rules (implemented in SQL §4)

1. **Provider PTR detector `is_ptr_like`.**
   - The name embeds four IP octets (`a-b-c-d`, `a.b.c.d`, reversed or
     hex-ish).
   - Or it carries an access-network token followed by digits: `static`,
     `dsl`, `pool`, `cust`, `ppp`, `dhcp`, `ftth`, ...
   - Validation on 1,000-IP-plus domains:
     - `googleusercontent.com` 99.9% IP-embedded
     - `akamaitechnologies.com` 100%
     - `incapdns.net` 99.4%
   - Some ISP PTR schemes are opaque and are not caught: `ocn.ne.jp`,
     `nuro.jp`, `t-ipconnect.de` (0%). Rule 3 handles those.
2. **Non-company names `is_non_company_name`.**
   - Non-public TLDs: `.local`, `.lan`, `.internal`, `.corp`, `.home`,
     `.arpa`, `.adsl`, ...
   - Vendor default certificate names: `draytek.com`, `fortinet.com`,
     `ubnt.com`, `traefik.default`, `kubernetes`, ...
   - Consumer dynamic-DNS zones: `synology.me`, `myqnapcloud.com`,
     `asuscomm.com`, `no-ip.*`, `duckdns.org`, ...
3. **Infrastructure domains, data-driven.**
   - Any registrable domain seen in `hostnames` on ≥1,000 distinct IPs:
     203 domains.
   - This removes provider namespaces regardless of naming scheme.
   - Cost: big self-hosters such as `amazon.com` and `cisco.com` are dropped
     as customer evidence. They are vendors, not prospects, so the cost is
     acceptable.
4. **Registrable domain `reg_domain`.**
   - eTLD+1 by regex with common two-level suffixes (`co.uk`, `com.au`,
     `ac.jp`, ...).
   - **Known gap:** without the Public Suffix List, some private suffixes
     resolve wrongly, e.g. `*.github.io` or `*.herokuapp.com`, where each
     subdomain is a different owner.
   - Production must use the PSL.

### Still unhandled

These were found in the final examples:

- `hstgr.cloud` (Hostinger). Hosting brands show up in cert CNs on
  fewer than 1,000 IPs.
- `.gateway`, a pseudo-TLD used by ISP CPE.
- `notexist.com`, the Alibaba WAF default certificate CN.
- `cloudflaressl.com`, an old Cloudflare shared certificate. Added to the
  list.

## 4. Provider / platform classification of `org`

`org_profile.is_platform` is true when any of the following holds:

- **(a) name heuristic `is_provider_org`:** cloud, CDN, hosting, telco/ISP
  or SaaS keywords plus a list of named providers. This catches 19,897 orgs.
- **(b) multi-tenant:** more than 100 distinct customer domains appear on
  the org's IPs. This adds 314 orgs, e.g. Automattic (6,738 domains),
  Unified Layer (5,281), A100 ROW / AWS (3,646), Namecheap, netcup, Strato,
  Liquid Web, ZOHO, Wix, WPEngine, Shopify, Vercel, HubSpot, Pantheon.
- **(c) CDN/cloud-tagged majority:** more than 50% of the org's rows carry
  the `cdn` or `cloud` tag. This adds 72 orgs.

### Precision problems observed

**False negatives:** ISPs read as companies. The top tier-A1 orgs still
include ISPs and access networks:

- BIGLOBE
- Asahi Net
- Yettel Hungary
- XFone 018
- SingNet
- BSNL
- OPTAGE
- Internexa
- `IP pools`
- `Dynamic pools`
- `Static IP Services`
- `Company 64d3451…` (synthetic registrant names)
- MTN Nigeria
- Puerto Rico Telephone
- Fatbeam
- EDPNET

Their subscriber devices (cameras, SOHO VPNs, RDP boxes) would be attributed
to the ISP.

**False positives:** large enterprises read as platforms.

- UnitedHealth Group (343 own brand domains: optum.com, uhc.com, ...) is
  misclassified by the >100-domain rule.
- Apple (1,451 domains) is ambiguous: iCloud custom-domain hosting makes it
  genuinely multi-tenant.

Better tenancy features than a raw count:

- share of the top domain;
- similarity of the domains to the org name;
- WHOIS/registrant overlap.

**Recommendation:** replace (a) with a curated ASN/org type table (hosting,
ISP, education, government, business), built once and reviewed. This is
reference data about networks, not prospect data. Keep (b) and (c) as
data-driven backstops, with (b) reworked as described above.

## 5. Attribution tiers and recommended account keys

| Tier | Rule | Eligible services | Share | Account key | Confidence |
|---|---|---|---|---|---|
| **A1** owned / direct | `org` not a platform | 621,208 | 11.9% | normalized `org` (`norm_org`: lower-case, strip punctuation and legal suffixes) → org→company mapping | High for real enterprises; **wrong for ISP ranges** until classification improves |
| **A2** owned in provider space | `org` not a platform, `org ≠ isp`, `isp` is a provider | 147,808 | 2.8% | normalized `org` | High for scanned services. Many A2 ranges are BYOIP that only answer with empty banners (Wal-Mart, Fiserv, Equifax, KeyBank, NYMEX, TGS on Google: 99–100% empty) and are therefore not signal-bearing |
| **B** tenant on provider IP | platform IP with ≥1 customer domain after filtering | 1,164,553 | 22.3% | registrable domain → company (Firmable domain index) | Medium. 65% of tier-B services have one domain confirmed by ≥2 sources (e.g. cert CN and SNI agree). 17% name more than one domain (shared hosting; ambiguous). 18% rest on a hostname alone (weakest) |
| **C** unattributable | platform IP, no customer name | 3,299,100 | 63.0% | none | Do not use for account-level signals |

### Tier-B evidence weighting

Recommended for the scoring engine. This is a hypothesis to calibrate, not
measured.

1. `ntlm` dotted domain → highest.
2. `sni_scan` and `cert_cn` agree, and the certificate is not a wildcard or
   a provider certificate → high.
3. `cert_cn` alone (non-wildcard) → medium-high.
4. `http_host` / `sni_scan` alone → medium. The service may be the SaaS
   platform behind a brand CNAME.
5. `hostname` alone → low. Forward DNS can point at shared hosting.
6. Records naming more than 3 unrelated domains → treat as shared hosting.
   Attribute the *website* to each domain, but never infrastructure
   exposures (RDP, DB, management planes).

### Which signals each tier may carry

| Signal family | A1/A2 | B | C |
|---|---|---|---|
| Exposure of infrastructure (S01, S03, S04, S05, S10, S11) | yes | only with high-confidence evidence (ntlm, or cert+SNI agreement) and a single domain | no |
| Web/TLS hygiene (S06, S07, S08, S09, S13) | yes | yes (domain owner controls the site, but may not control the runtime on managed hosting) | no |
| Technographics (S16) | yes | yes (CDN/WAF customers are visible only here) | no |
| CDN-edge rows | — | technographics only | — |

## 6. Mapping account keys to companies (Firmable side)

The dataset alone cannot finish attribution. Two joins are needed, both
against Firmable's own company records. No external API is involved.

1. **`org` name → company.**
   - Normalize with `norm_org`.
   - Then fuzzy-match against company legal names and known aliases,
     including historical names: `Wal-Mart Stores, Inc.` → Walmart,
     `Avago Technologies U.S. Inc.` → Broadcom,
     `Bayerische Motoren Werke Aktiengesellschaft` / `BMW Manufacturing Co.,
     LLC` → BMW Group.
   - Variant spellings for one entity must merge: `Incapsula Inc` /
     `Incapsula Inc.`, `Aliyun Computing Co., LTD` / `Aliyun Computing
     Co.LTD`. `norm_org` does this for punctuation and legal-suffix
     variants.
2. **Registrable domain → company** via Firmable's website/domain field.
   Include secondary and brand domains. Optum is UnitedHealth, and
   `bmwgroup.com` is BMW.
3. **Subsidiary roll-up.** Signals should attach to the operating entity
   (Optum) and roll up to the parent for enterprise selling.

## 7. Attribution risks that must reach the scoring design

- **Tenant ≠ operator.** HubSpot, WPEngine, Shopify, Squarespace and
  Pantheon serve customer brands. A KEV-flagged nginx on a WPEngine IP is
  WPEngine's runtime, not the brand's.
- **Default identities.** Vendor default certificates and hostnames would
  attribute thousands of devices to the vendor (`draytek.com`) or to
  nobody (`unifi.local`).
- **Geolocation.** `location` describes the IP, not the company. Anycast
  and CDN space puts 27% of rows in Singapore.
- **Residential and SMB space.** Cameras, SOHO VPNs and consumer IoT
  dominate ISP ranges. They are not B2B accounts unless a business domain
  is present.
- **Time.** IP→tenant mappings on cloud change within hours. Attribution
  should be recomputed per snapshot and never cached across snapshots for
  tier B/C.
- **Ethics and legal.** Internal AD names (NTLM) and compromise indicators
  (S12) are sensitive. Using them in outreach needs policy review.
