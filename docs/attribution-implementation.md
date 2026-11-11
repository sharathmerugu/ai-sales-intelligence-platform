# Attribution v1 — implementation, full-data run, limitations

Milestone M2 of `docs/phase3-plan.md`. Status 2026-11-09: built, tested, run on
snapshot `2026-11-07` (committed as a2e35f2). Fix round 2026-11-10: §6. Attribution v5
(2026-11-11, accent folding and named provider additions): §7, which holds the current numbers. Contract: `phase3-plan.md` "Contract: attribution".
Research basis: `company-attribution.md`, `sql/exploration.sql` §4–§5.

Every score, multiplier and threshold below is a **hypothesis chosen from the
data profile**. None is measured against labels: no labels exist, so the
precision and recall of the tiers are unmeasured.

## 1. Files

| File | Holds |
|---|---|
| `src/firmable/attribution/names.py` | `normalize_name`, `registrable_domain` (PSL), `classify_name`, `name_outcome`, ported `is_ptr_like` / `is_non_company_name`, curated vendor-default zones and provider certificate namespaces |
| `src/firmable/attribution/text.py` | `fold_name` (v5): accent and case folding for org / ISP names |
| `src/firmable/attribution/providers.py` | `norm_org` (port), `classify_org` (curated name table), `org_names_match`, `is_access_network_name`, `org_backstop` / `org_backstop_class` (data-driven backstops) |
| `src/firmable/attribution/build.py` | `build_attribution`, `compute_infra_domains`, `attribution_dir`, `build_attribution_for_snapshot` |
| `tests/test_attribution_names.py`, `tests/test_attribution_providers.py`, `tests/test_attribution_build.py` | 277 tests (after the fix round), hand-written expected literals |

Outputs go to `~/firmable-work/lake/attribution/attribution=v1/normalizer=v1/snapshot=S/`:

- `evidence.parquet` and `service_attribution.parquet`, with exactly the contract columns. Both are written to `*.tmp` and published with `os.replace`.
- `infra_domains.parquet` (`domain, ips`): the cached infrastructure-domain set.

## 2. Method

### 2.1 Evidence: a service's own record only

Each service yields one evidence row per `(service, source, name)`:

| source | field | extraction |
|---|---|---|
| `ntlm` | `ntlm_dns_domain` | dotted values only |
| `cert_cn` | `cert_subject_cn` | non-empty |
| `cert_san` | `cert_san_dns[]` | each entry |
| `sni` | `sni` | non-empty |
| `http_host` | `http_host` | non-empty and not an IP literal (IPv4, IPv6 or bracketed, optional `:port`) |
| `hostname` | `hostnames[]` | each entry |

Rules:

- **No cross-service evidence.** Nothing joins on IP, so two vhosts on one IP never share names, and a service without SNI never inherits another vhost's domain (see the test `test_vhosts_on_one_ip_never_share_evidence`).
- **Normalization.** Names are lower-cased and trimmed. A trailing dot, a leading `*.` and a `:port` are removed, and IDN names are converted to punycode.
- **Wildcards.** Wildcard status can be read from `raw_name`. When the same name arrives as both wildcard and bare, the non-wildcard raw name is kept.

### 2.2 Name outcome (first match wins)

`classify_name` runs once per distinct raw string, in Python. That is 15.3M evidence rows and a few million distinct strings, using `publicsuffixlist` (offline, `accept_unknown=False`). The snapshot rules are then applied in SQL by the same logic as `names.contextual_outcome`.

| # | Outcome | Rule |
|---|---|---|
| 1 | `invalid` | empty, or not a syntactically valid DNS name (spaces, `@`, commas, labels longer than 63 characters) |
| 2 | `ip_literal` | the name parses as an IPv4 or IPv6 address |
| 3 | `non_company` | **Ported regexes:** non-public TLDs, plus `.gateway`, `.localhost`, `.router`, `.domain`, ... **Vendor-default zones and names**, matched as a name suffix (many dynamic-DNS zones are PSL private suffixes): `draytek.com`, `synology.com`, `tplinkwifi.net`, `router.asus.com`, `captive-portal.peplink.com`, `notexist.com`, RFC 2606 `example.*`, `fritz.box`, ... **Dynamic-DNS / device-cloud / tunnel parents** (fix round): `softether.net`, `vpnazure.net`, `fortiddns.com`, `hanwha-security.com`, `ngrok.*`, `dynv6.net`, `mynetname.net`, the 3CX hosted-PBX zones (`(my\|on)3cx.<tld>`, which also rejects the vendor's own `3cx.com`), ... **Per-device serial certificates** under `huawei.com` (a label containing ≥ 8 digits) |
| 4 | `ptr_like` | ported `is_ptr_like`: four embedded octets, or an access token followed by digits |
| 5 | `provider_cert` | curated hosting-brand or provider certificate namespaces, matched as a suffix: `hstgr.cloud`, `cloudflaressl.com`, `certfallback.com`, `cloudwaysapps.com`, `cloudhub.io`, `ctcdn.cn`, ... |
| 6 | `no_registrable_domain` | the PSL gives no registrable domain (`github.io` itself, unknown TLDs, `*.compute-1.amazonaws.com`) |
| 7 | `provider_cert` | **Shared certificate name** (snapshot data, cert sources only): the same certificate name is served by ≥ 20 distinct registrant orgs. Examples: vendor defaults, ISP-embedded CDN caches (`*.cdnhwc3.com`, Huawei cloud), copycat certificates. 730 names on the full data. |
| 8 | `infra_domain` | The registrable domain is in the infra set: seen in `hostnames` on ≥ 1,000 distinct IPs across **all** observations of the snapshot (the committed observation files, projecting `ip, hostnames`). There are 200 such domains (research: 203). |
| 9 | `accepted` | none of the above |

The PSL makes each private-suffix tenant its own owner: `alice.github.io` and `bob.github.io` are different accounts, as are `x.herokuapp.com` tenants. The cost is that the curated provider zones must be matched as suffixes, because `srv1.hstgr.cloud` is itself a registrable domain under the PSL.

### 2.3 Org class

`classify_org(org, isp)` returns one of `business`, `cloud_hosting`, `cdn`, `isp_telco`, `saas_platform` or `unknown`. It checks, in order:

1. **Unknown orgs.** An org with no usable name is `unknown`. This covers:
   - an empty `norm_org`;
   - synthetic registrant names (`Company 64d3451…`);
   - postal addresses used as the org (`21/F, Ciputra World 1 …`, `1 Raffles Place,`);
   - phone numbers used as the org.
2. **Pool labels** (`IP pools`, `Dynamic pools`, `Static IP Services`, `... Static Pool`, `Customers`, `Private Customer`) take the network operator's class. If the operator itself reads as a business, the class is `isp_telco`.
3. **Curated tables,** in the order business override → CDN → SaaS/site platform → cloud/hosting → ISP/telco:
   - The tables port `is_provider_org` and add every ISP listed in `company-attribution.md` §4: BIGLOBE, Asahi Net, Yettel, XFone, SingNet, BSNL, OPTAGE, Internexa, MTN, Puerto Rico Telephone, Fatbeam, EDPNET.
   - They also add the ISPs and hosters found among the top owned orgs of the first full run (Free Pro, CANTV, AAPT, FreeBit, EOLO, Optimum, Fidium, JCOM, Polkomtel, …).
   - National research networks (SUNET, SURF, RENATER, …) are classed as ISPs, because their customers are member institutions.
4. **Generic keywords.** These are the ported keyword list, split by class, plus access-network labels (`xDSL`, `IP range`, `statically assigned`, `address pool`, …).
5. **Otherwise** the org is `business`.

Patterns that would hit enterprises were narrowed. Examples: `orange` but not Orange County, `liberty global` but not Liberty Mutual, `charter communications`, `tpg telecom`.

**Data-driven backstops** run per org over the snapshot's services. They apply only to orgs that the name table reads as `business`. The first that matches wins:

- **Access network** (fix round, reason `org_access_network_ptr`):
  - Rule: the org has ≥ 20 services, and ≥ 0.30 of them have a hostname carrying a subscriber/access label. That is an access token (`a?dsl`, `dhcp`, `dyn`, `pool`, `cust`, `cpe`, `ftth`, `res`, `static`, `lte`, `gpon`, `home`, `dial`, …) followed by digits; see `ACCESS_PTR_PATTERN`. The class becomes `isp_telco`.
  - Plain IP-embedded PTRs are deliberately not used: enterprise and SaaS ranges have them too (Adobe 0.75, ServiceNow 0.99, ICE 0.87).
  - Coordinator's measurement: ISPs score 0.4–1.0, enterprises and universities ~0, and Columbia University 0.27 stays a business.
  - The same rule runs per `isp` string, so a business inside an access network becomes A2.
- **CDN/cloud-tag majority** (ported rule (c)): more than 0.5 of the org's services carry the `cdn` or `cloud` tag. The class becomes `cdn` when cdn rows are at least as many as cloud-only rows, otherwise `cloud_hosting`. Reason `org_cdn_cloud_tagged`.
- **Multi-tenant** (rule (b), reworked): more than 100 distinct accepted customer domains on the org's services. Reason `org_multi_tenant`. The org is **exempt** when it presents certificates in its own name: the certificate subject O matches the org on its first significant token (`org_names_match`), on either
  - ≥ 0.25 of its services, or
  - ≥ 50 services that make up ≥ 0.8 of its certificates that carry an O.

  Profile behind the exemption:

  | Org | Services with own-name O | Result |
  |---|---|---|
  | UnitedHealth | 46% | business |
  | CIGNA | 20%, but 61/61 of its O-bearing certificates are its own | business |
  | Apple | 1,308 of 1,308 O-bearing certificates are its own | business |
  | WPEngine, Automattic, Unified Layer, Strato, Pantheon | ~0% | multi-tenant |

  After the fix round: 137 orgs are classed as access networks (plus 245 isp strings), 104 multi-tenant and 71 CDN/cloud-tagged. Thales DIS, which is Imperva's space, is correctly caught as a CDN.

### 2.4 Domain choice, tiers, confidence

For each `(service, registrable domain)` with accepted evidence, the domain score is the first matching row below. Then add `0.05 × (evidence families − 1)`, where the families are ntlm, cert, vhost (`sni` or `http_host`) and hostname. The score is capped at 1.0.

| Condition | Base | Reason |
|---|---|---|
| ntlm | 1.0 | `dom_ntlm` |
| non-wildcard cert CN/SAN **and** SNI on the same registrable domain | 0.85 | `dom_cert_sni_agree` |
| wildcard cert and SNI | 0.7 | `dom_cert_wildcard_sni_agree` |
| non-wildcard cert CN | 0.6 | `dom_cert` |
| non-wildcard cert SAN | 0.55 | `dom_cert_san` |
| SNI | 0.45 | `dom_sni` |
| HTTP Host | 0.45 | `dom_http_host` |
| wildcard cert only | 0.4 | `dom_cert_wildcard` |
| hostname only | 0.25 | `dom_hostname_only` |

| Tier | Rule | account_id | Confidence |
|---|---|---|---|
| A1 | org class `business`, and either `norm_org(org) == norm_org(isp)` or the isp is not a provider | `org:<norm_org>` | 0.9 |
| A2 | org class `business`, a different org, and the isp is a provider (its name class, or the backstop when the isp string is itself a backstop org) | `org:<norm_org>` | 0.85 |
| B | any other org class, and the best domain **strictly** beats the runner-up | `dom:<registrable domain>` | domain score × 1 (one candidate), × 0.85 (2–3), × 0.6 (> 3, `shared_hosting`) |
| C | no accepted domain (`abstain_no_customer_evidence`) or a tie (`abstain_ambiguous_domains`) | NULL | 0 |

Additional rules:

- **Confidence bands:** `high` ≥ 0.75, `medium` ≥ 0.5, `low` > 0, `none` = 0.
- **`allows_infra_signals`:** true for A1 and A2. For B it is true only when there is exactly one candidate domain and the evidence is strong (NTLM, or a non-wildcard cert agreeing with SNI). It is false for C and for any record with more than 3 candidate domains.
- **`reasons`:**
  - The org class comes first: `org_cloud_hosting`, `org_cdn`, `org_isp`, `org_saas_platform`, `org_unknown`.
  - Then the backstop reason, if any.
  - Then the winning domain reason or the abstention reason.
  - Then `multiple_candidate_domains` (2–3 candidates) or `shared_hosting` (> 3).
  - A1 carries `org_not_provider` and `org_eq_isp` or `isp_not_provider`. A2 carries `org_not_provider` and `byoip_in_provider`.
- **`customer_domains[1]` is not ported.** No positional domain choice exists anywhere.

## 3. Commands

```bash
uv run pytest tests/test_attribution_names.py tests/test_attribution_providers.py tests/test_attribution_build.py
```

```python
from firmable.ingest.pipeline import Pipeline
from firmable.attribution.build import build_attribution_for_snapshot

build_attribution_for_snapshot(Pipeline("~/firmable-work"), "2026-11-07", memory_limit="4GB", threads=4,
                               temp_directory="/Users/sharath/firmable-work/duckdb_tmp",
                               refresh_infra=False)   # True recomputes infra_domains.parquet from observations
```

`firmable.phase3` (M5) calls the same function.

## 4. Verification

### 4.1 Tests

`uv run pytest tests/test_attribution_*.py` passes 181 tests in 3.5 s. The whole suite, `uv run pytest -m "not slow"`, passes 348 tests with 1 deselected.

Every slice was written red first:

- the PSL cases (`github.io` tenants, `co.uk`, `com.au`);
- PTR and vendor-default rejection;
- ISP orgs are not A1; BYOIP gives A2;
- a CDN tenant with cert and SNI agreeing gives B with infra signals allowed;
- a hostname-only service gives low-confidence B with infra signals blocked;
- tied domains give C;
- more than 3 domains gives `shared_hosting`;
- vhost isolation;
- shared certificate names;
- a UnitedHealth-like org stays A1 while a 101-tenant host becomes `saas_platform`;
- infra-domain computation, caching and the missing-input error;
- exact output schemas.

### 4.2 Full data, snapshot 2026-11-07 (M2 commit; superseded by §6)

The input is 5,233,493 services. The machine is an i7-9750H with 16 GB, with another DuckDB job running concurrently.

| Run | Wall | Infra step | Peak RSS |
|---|---|---|---|
| Infra computed from the 511 observation files | 228 s | 58–65 s | 4.7 GB |
| Infra from cache (final run) | 177 s | — | 4.7 GB |

Peak RSS exceeds the 4 GB DuckDB `memory_limit` because the Python-side name map lives in Arrow.

**Tiers vs research (Q5.1):**

| Tier | v1 services | v1 share | Research | Research share | Delta | v1 accounts |
|---|---|---|---|---|---|---|
| A1 | 424,766 | 8.1% | 621,208 | 11.9% | −196,442 | 32,461 orgs |
| A2 | 149,848 | 2.9% | 147,808 | 2.8% | +2,040 | 24,634 |
| B | 1,106,669 | 21.1% | 1,164,553 | 22.3% | −57,884 | 410,871 domains |
| C | 3,552,210 | 67.9% | 3,299,100 | 63.0% | +253,110 | — |

**Delta explanations:**

- **A1 falls by 32%.** The research called A1 an upper bound polluted by ISPs. v1 moves the following out of A1, mostly into C because ISP subscriber IPs rarely carry names:
  - the §4 missed ISPs;
  - about 150 further named ISPs, hosters and NRENs;
  - access-network labels, pool labels, postal-address orgs and synthetic orgs.
- **B is slightly lower.**
  - Downward:
    - 72,949 services that the research counted as B now abstain on tied domains (`abstain_ambiguous_domains`);
    - shared certificate names reject 670k cert evidence rows;
    - the new vendor-default zones reject more names.
  - Upward:
    - orgs moved out of A1 that do carry names;
    - the new `cert_san` source (751k services have an accepted SAN).
- **C rises** by the same ISP moves and abstentions.
- **A2 is about the same.** Address-string orgs inside Alibaba moved out (−1.7k); orgs whose isp is now recognized as a provider moved in.

**Top 40 A1 orgs** (final run), checked by hand:

- Apple 12,516 and West Virginia University 11,617.
- UnitedHealth 5,606, kept by the own-certificate exemption. CIGNA is also kept.
- VK, UNAM, Medidata, RIT, Baidu, Meta, UKG/Ultimate Software, BNY Mellon, Netflix, Fortinet, Index Exchange, MIT, Berkeley, Anthropic, SpaceX, Meraki, American Express, Refinitiv, Government of Alberta, and other universities.

Remaining doubtful entries in the top 40:

- `Office of Info.Tech. Admin. for Educational Development` (the Thai education network).
- `ChangZhou Bitcomm Software`, `PT Abhinawa Sumberdaya Asia`, `T.E.I.S.A` and `Entidad Publica Empresarial Red.es` (the Spanish research network operator): likely hosters or networks.

None of the §4 ISPs remain. `Quality Technology Services` and `Dimension Data` were in the second run's top 40 and are now classed as hosting.

**Evidence sources vs `company-attribution.md` §2.** The research counted eligible *observations* (7.1M); v1 counts *services* (5.23M) with an accepted name.

| Source | Research obs | Research domains | v1 services | v1 accepted domains |
|---|---|---|---|---|
| hostname | 1,587,812 | 648,337 | 1,335,657 | 671,425 |
| cert_cn | 831,219 | 284,299 | 668,979 | 290,758 |
| sni | 777,634 | 195,047 | 669,930 | 200,821 |
| http_host | 761,862 | 205,318 | 653,965 | 211,315 |
| ntlm | 1,284 | 772 | 944 | 679 |
| cert_san | — | — | 750,968 | 472,309 |

- **Fewer rows** follow from the observation-to-service grain, plus the shared-certificate and vendor-zone rejections.
- **More distinct domains** come from the PSL, which splits private-suffix tenants such as `*.github.io` into separate domains.
- **NTLM is lower** because names under non-public TLDs and PTR-like names are rejected, and the PSL is stricter.

**Evidence outcomes** (15,257,632 rows):

| Outcome | Rows |
|---|---|
| accepted | 9,615,626 |
| infra_domain | 2,340,978 |
| ptr_like | 2,182,663 |
| provider_cert | 670,271 |
| no_registrable_domain | 210,066 |
| non_company | 173,507 |
| invalid | 33,714 |
| ip_literal | 30,807 |

**Tier B composition.** Research: 65% have one domain confirmed by ≥ 2 sources, 17% name more than one domain, 18% rest on a hostname alone.

| Winning evidence | B services | Share |
|---|---|---|
| sni | 352,261 | 31.8% |
| cert + sni agree | 242,250 | 21.9% |
| cert CN | 219,783 | 19.9% |
| hostname only | 156,867 | 14.2% |
| cert SAN | 91,483 | 8.3% |
| wildcard cert | 30,776 | 2.8% |
| wildcard cert + sni | 11,143 | 1.0% |
| http_host | 1,452 | 0.1% |
| ntlm | 654 | 0.1% |

By candidate count, B services have 1 candidate domain in 952,530 cases (86%), 2–3 in 132,042 (12%) and more than 3 (`shared_hosting`) in 22,097 (2%). Another 55,323 services with more than 3 domains abstain.

Confidence bands in B are high 242,802, medium 609,284 and low 254,583.

**B services allowed to carry infrastructure signals:** 204,105, which is 18.4% of B, across 63,584 domain accounts. Of these, 203,540 rest on cert and SNI agreeing and 565 on NTLM.

**Spot checks** (3 per tier, deterministic hash sample; IPs masked to /24):

| Tier | Service | Result | Verdict |
|---|---|---|---|
| A1 | 130.102.0.0/24:110, Citrix NetScaler | University of Queensland, `org_eq_isp` | Correct |
| A1 | 140.113.195.0/24:80, nginx | National Yang Ming Chiao Tung University | Correct |
| A1 | 103.11.76.0/24:22, OpenSSH | `UberGlobal UBRCBR` | **Wrong:** an Australian hosting provider missing from the table |
| A2 | 69.48.218.0/24:2086 | Uber Technologies | Correct BYOIP |
| A2 | 162.251.205.0/24:2082 | Contentstack | Correct BYOIP |
| A2 | 122.8.38.0/24 | `Beijing CNISP Technology` | Likely an ISP or hoster: **wrong** |
| B | 69.72.136.0/24:443 on WHG Hosting, SNI `ferretdesigns.com`, cert `cpcontacts.ferretdesigns.com` | `dom:ferretdesigns.com`, 0.95, infra allowed | Correct |
| B | 43.254.194.0/24:9928, cert `wave-api-secure.zijieapi.com` | `dom:zijieapi.com`, 0.65 | ByteDance API edge; plausible |
| B | 110.4.45.0/24:2086, hostname `satay.mschosting.com` only | `dom:mschosting.com`, 0.25 | Names the hoster's own server, not a tenant; low confidence, infra blocked, so acceptable |
| B | 46.167.151.0/24, 118.163.82.0/24, 76.210.252.0/24 on port 3389 | `dom_ntlm` → `sirgroup.ir`, `e-f.com.tw`, `cmdelectric.com`, 1.0, infra allowed | Correct (this is sensitive NTLM evidence; see the limitations) |
| C | 94.57.253.0/24 (Etisalat) | no name | Correct |
| C | 107.154.145.0/24 (Incapsula) | only an `incapdns.net` PTR | Correct |
| C | 121.43.237.0/24 (Aliyun), VNC | no name | Correct |

Earlier runs found further false positives, all now fixed: the address-string org on Alibaba (1.7k A2 services), YouStable, and `cloudhub.io` (a MuleSoft tenant namespace).

## 5. Known limitations

1. **The curated org table is incomplete.** A1 and A2 still contain some ISPs and hosters, e.g. UberGlobal, Beijing CNISP and PT Abhinawa. Treat owned counts as upper bounds. The research recommendation still stands: replace the regex table with a reviewed ASN/org-type table.
2. **The ported CDN/cloud-tag rule misreads CDN BYOIP.** For example, Trans Union on Cloudflare Magic Transit (1,123 services) becomes `cdn` instead of A2.
3. **The multi-tenant rule misreads brand-heavy enterprises without OV certificates.** For example, InnoGames (413 services) has many game domains and no O in its certificates.
4. **Apple is now `business` (A1).** iCloud custom-domain hosting makes part of it genuinely multi-tenant. Apple operates those services, but the custom domains' owners are not Apple's accounts.
5. **Tenant ≠ operator.** A B account names the domain owner. On SaaS and site platforms the runtime belongs to the platform, yet a cert+SNI agreement still sets `allows_infra_signals`. The M1 exposure signals exclude `is_cdn` rows, which limits the effect. Platform namespaces on fewer than 1,000 IPs and absent from the PSL still produce accounts named after the platform; `cloudhub.io` was added by hand.
6. **The ported PTR regex rejects some legitimate names**, e.g. `host1.company.com` or `mobile2.bank.com`.
7. **Domain accounts are not mapped to companies.** Brand domains of one company (`optum.com`, `uhc.com`) are separate `dom:` accounts. The org→company and domain→company joins (`company-attribution.md` §6) are Firmable-side work.
8. **Org backstops and shared-certificate names are computed over eligible services, not all observations.** Only infra domains use all observations.
9. **NTLM-derived accounts expose internal AD names.** Per CLAUDE.md, using them in outreach needs human review.
10. **All thresholds are unvalidated hypotheses:**

    | Threshold | Value |
    |---|---|
    | Infra domains | 1,000 IPs |
    | Shared certificate names | 20 orgs |
    | Multi-tenant | 100 domains |
    | Own-cert exemption | 0.25 share, or 50 services at 0.8 |
    | Domain scores | see §2.4 |
    | Candidate multipliers | 1 / 0.85 / 0.6 |
    | A1 / A2 confidence | 0.9 / 0.85 |

## 6. Fix round 2026-11-10

**Trigger.** The full ranked build showed ISP subscriber CPE dominating the top accounts.

### 6.1 Changes

All changes were made test-first (277 tests, 4 s).

1. **Access-network backstop** on both the org and the isp side (§2.3).
2. **Curated additions**, each org string confirmed in the 2026-11-07 data first:

   | Group | Orgs |
   |---|---|
   | ISPs | Eircom, VF Ukraine, Hutchison Drei, HERABIT, BRASIL TECPAR, LEW TelNet, PUNTONET, Núcleo S.A. (exact match; NIC.BR stays a business), Saba Abr Mizban, Globalways, TELY, Wana Corporate, New Century InfoComm, Logix (anchored; GreyLogix stays), Conterra, C.C.S. (Leeds), Pioneer Elabs, Operbes, Bharat Sanchar Nigam (1,929 services, was A2), Magticom, HAIonNet, Iran Information Technology |
   | Hosting | Register.com (2,513), xTom, Voxility, Beijing CNISP, UberGlobal, Nucleo Brasil Servidores |
   | Pool labels | `... Static Pool` now takes the operator's class |

3. **Dynamic-DNS / device-cloud parents** are now `non_company` (§2.2). The scan looked for tier-B accounts whose names have many distinct numeric or random leftmost labels across ≥ 15 orgs.
   - Rejected: `softether.net` (194 services, 100 orgs), the 3CX zones (≈ 900 services in total), `fortiddns.com` (85 services, 59 orgs), `hanwha-security.com` (54 services, 32 orgs), `secomddns.jp`, `ngrok.io`, and Huawei device-serial certificates.
   - Kept as operator attribution:
     - `fbinfra.net` (Meta caches);
     - `nic.br` (SIMET probes) and `ripe.net` (Atlas anchors);
     - `nordvpn.com`;
     - Huawei's own hosts;
     - big enterprises with many subdomains: `ondemand.com` (SAP), `deloitte.com`, `autodesk.com`.
4. **One iteration on the top owned orgs by exposure-signal services.**
   - Added as hosting: Binary Racks, Nexeon, Dynu, PacketStream, Rapid Infocare, Tecpoint, KALANDA, PT Industri Kreatif Digital, Part Payam Paya, Optimus Technologies, PetroSky, Grupo Interdominios, Liasail, InterLIR, ScaleMatrix.
   - Added as ISPs: Enreach, Integratel Perú, Global Connectivity Solutions, and the Thai educational network office (UniNet).
   - Phone-number orgs (`+27 (82) …`) become `unknown`.
   - Also extended the Huawei serial pattern (`2s2470002537.huawei.com`).

### 6.2 Results

Final run: 183 s wall with infra from cache, peak RSS 4.6 GB, 15,257,632 evidence rows.

| Tier | Services | Share | Accounts | M2 commit | Research |
|---|---|---|---|---|---|
| A1 | 405,742 | 7.8% | 31,759 | 424,766 | 621,208 |
| A2 | 139,700 | 2.7% | 25,036 | 149,848 | 147,808 |
| B | 1,108,975 | 21.2% | 411,904 | 1,106,669 | 1,164,553 |
| C | 3,579,076 | 68.4% | — | 3,552,210 | 3,299,100 |

- **B services allowed to carry infrastructure signals:** 204,305.
- **Exposure-signal services by tier** (`signal_hits`, family `exposure`):

  | Tier | Exposure services | Of which may carry infra signals |
  |---|---|---|
  | A1 | 10,008 | all |
  | A2 | 3,941 | all |
  | B | 15,795 | 1,169 |
  | C | 64,418 | none |

- **Spot checks.** Spot-checked orgs land as expected:
  - Conterra and BSNL are now `isp_telco` (B/C), and Register.com is `cloud_hosting`.
  - MIT, Columbia, UnitedHealth, ICE, Apple and Adobe stay `business`.
  - ServiceNow stays `saas_platform` (curated).
  - `dom:huawei.com` falls from 288 to 182 services, which are Huawei's own hosts plus the bare `huawei.com`.

**Top 40 owned (A1/A2) orgs by services carrying exposure signals**, after the iteration:

| Verdict | Orgs |
|---|---|
| Real organizations | named organisations withheld in the public copy (universities, state and provincial agencies, banks, a rail operator, technology companies) |
| Remaining ISPs / telcos | Dialog Axiata, S-NET, Omnia Connect, Dstny BE, VoiceHost, Maxindo Mitra Solusi, `Urban Wimax Assigned IP Address`, Asia Pacific On-Line Service |
| Remaining hosters / datacenters | WebNX, Netuv Bilisim, Web2Objects, Telx, Claranet, End of Reality (on Dedicated.com), Megacore |
| Junk org strings | `leased=false` |
| Unclear: one IP answering on many ports, possibly honeypot-like | three orgs (names withheld): 77 MySQL on 1 IP, 49 ScreenConnect on 1 IP, 25 MongoDB on 4 IPs |
| Unclear | DONG HUNG PHU, Aviation RE LLC (an IP lessee on Charter) |

The long tail is the curated table's known limit (§5.1). The next cheap steps:

- an org-string junk filter (`leased=…`, `… Assigned IP Address`);
- a per-org "many ports on few IPs" flag for the honeypot-like single hosts;
- the reviewed ASN/org-type table the research recommends.

## 7. Attribution v5 (2026-11-11)

**Trigger.** `classify_org` read "Telefónica" (acute ó) as a business, while "Telefonica" and
"Telefônica" were ISPs (`ranking-v3.md` §6.3). Org names were lower-cased but not accent-folded, so
the ASCII curated tables missed accented spellings, and `first_significant_token` dropped accented
letters ("telefnica", "socit"). Scoring v3 also showed telcos and hosters in the actionable
enterprise list.

### 7.1 Accent folding

`text.fold_name` is the single fold for org and ISP names. One pass does four things:

1. maps letters that Unicode does not decompose: ı İ → i, ø → o, æ → ae, œ → oe, ß → ss, ł → l,
   đ ð → d, þ → th, ħ → h;
2. applies NFKD, which also turns full-width forms, ligatures and ordinal indicators (ª º) into
   plain letters;
3. drops combining *diacritical* marks only (U+0300–U+036F plus the extended, supplement, symbol and
   half-mark blocks). Latin, Greek and Cyrillic lose their accents. Thai, Devanagari and Arabic
   vowel signs, viramas and harakat are kept;
4. casefolds, then recomposes with NFC. Hangul syllables and kana with (han)dakuten therefore keep
   their precomposed form.

Passes repeat until the string stops changing, at most 5 times (`ǿ` needs two). Tests check the
following:

- idempotence on every BMP letter and mark;
- idempotence on 20,000 deterministic mixed strings drawn from Latin Extended, Greek, Cyrillic,
  kana, Hangul, Thai, Devanagari and Arabic;
- that Thai (`กิ่ง`), Devanagari (`हिन्दी`), Arabic with harakat, Hangul and kana names come out
  unchanged.

Where the fold is applied:

- **`providers.py`:** `norm_org` (and therefore the org account key), `classify_org` (pool-label,
  address and phone checks, the curated tables, and the isp side), `first_significant_token`,
  `org_names_match`, `domain_matches_org`, `plausibly_names_org` and `ownership_names_org`.
- **Eligibility:** `accounts.eligibility.is_registry_label`.
- **Accounts roll-up:** `network_operators` is counted over folded ISP names, so one operator
  spelled two ways counts once. `ELIGIBILITY_VERSION` is now 2.
- **Serving DB:** search is accent-insensitive in both directions. `search_text` is folded at build
  time and the query `q` is folded in Python before matching, so "telefonica" finds "Telefónica"
  and the reverse also works. `SERVING_VERSION` is now 3, and the app refuses an older DB.

The curated table had non-ASCII literals (`telefônica`, `tel[eé]fonos`, `n[uú]cleo`) and the stop
word `für`. They are now ASCII, and a test asserts that every curated pattern is ASCII.

**DNS names are not folded.** `names.py` keeps IDNA for internationalised domains, because
`münchen.de` and `munchen.de` are different names. `is_access_network_name` only lower-cases a
hostname, as its SQL mirrors (`lower(h)`) do.

**Profiles are keyed by the account key.** These rules now group raw org and isp strings by
`norm_org`, the account key, instead of by the raw string:

- the data-driven backstops (access network, CDN/cloud tags, multi-tenant);
- the isp-side access rule;
- the ASN-majority operator rule.

So spelling variants of one account get one class. Examples: "Jazztel Triple Play Services" and
"Jazztel triple play services"; "NhanHoa Software Company" and "... company". The build
statistics `backstop_orgs` and `access_network_isps` now count keys, not raw strings.

`ATTRIBUTION_VERSION` is 5, and output goes to `lake/attribution/attribution=v5/...`. These were
left untouched, with size and mtime checked before and after every build:

- the v4 tables;
- the accounts built on v4 (`accounts/scoring=v2|v3/attribution=v4/...`).

The infra-domain cache was copied from v4. It depends only on hostnames and the PSL, which v5 does
not change.

**Account keys change for accented orgs** [F]:

- **Renamed:** 654 v4 `org:` / `net:` account ids are renamed with the same tier (291 A1, 343 A2,
  23 P; 2,351 services). Every one is a Latin-script name:
  - 653 ids lose Latin diacritics or non-decomposing letters, e.g.
    `org:brb - banco de brasília s/a` → `org:brb - banco de brasilia s/a`;
  - 4 also hold an ordinal indicator (`4ª região` → `4a regiao`).
- **Other scripts are unchanged:** in v4 the A1/A2/P tiers hold one CJK id and no Hangul, kana or
  Cyrillic ids, and that CJK id is unchanged in v5.
- **No alias:** there is no v4 → v5 id alias. An old link to an accented id (e.g.
  `/accounts/org:telefónica chile`) returns 404, so reviewers should search by name, which is now
  accent-insensitive. Labels and review rows keyed on accented v4 ids need remapping with
  `norm_org`.

**Decision: accent variants merge into one account** [F]. One registrant written with and without
accents ("Müller GmbH" / "Muller GmbH") is the common case, so both spellings share one key.
Measured over A1/A2/P:

- 816 v5 ids carry ≥ 2 distinct raw org spellings. v4 had 822; those merges come from case,
  punctuation and legal-suffix differences.
- 11 of the 816 merge spellings that differ only by accents, i.e. equal after `fold_name` but not
  after `lower()`. Examples: "Enköping CityNet" / "Enkoping CityNet", "Rechenzentrum Haßfurt" /
  "Rechenzentrum Hassfurt", "AJUNTAMENT DE MATARÓ" / "... MATARO", "VIRO Osnabrück" /
  "VIRO Osnabruck".

None of the 11 looked like two different organisations. A false merge would need two registrants
whose names differ only by accents. This has not been measured beyond these 11.

### 7.2 Named provider additions

Each org string below was seen in the 2026-11-07 data. Each entry is backed by OpenASN v2026.10.18,
by the snapshot's own `isp` field, or by both, and the evidence is repeated in a comment next to the
entry in `providers.py`. No generic keyword was added, and ADR 0008's freeze on regex expansion
still holds for anything that lacks this evidence. Negative tests cover the riskier entries: Tigo Energy,
TIGO-ENERGY, Tigo Solar and Tigo Security; Maxtel and Axtell; Batelcom and Abatelco; Orbit B.V.;
Netlife Robotics; a customer on Cheops' network; and TEKNET VERI MERKEZI.

| Entry (class) | Org strings | Evidence | Why v4 missed it |
|---|---|---|---|
| `bite lietuva` (isp) | Bite Lietuva; UAB "Bite Lietuva" | `isp` = UAB "Bite Lietuva"; AS13194 OpenASN "Bitė Lietuva", hosting / midsize_transit | The legal-form prefix "UAB" in the isp field defeated the operator name match, and the org held no majority of the ASN, so it stayed A2 inside its own network |
| `\baxtel\b` (isp) | Axtel, S.A.B. de C.V. and its pool labels | OpenASN AS6503 "Axtel", isp; 71 services sit on AS11172 (Alestra, already curated; OpenASN hosting) | Not in the table; its other ASN (AS28502) is filed `business` |
| `^bit b\.?v\.?$` (isp) | BIT BV, BIT B.V. | `isp` = "NL-BIT BIT BV"; AS12859 OpenASN "BIT internetprovider", isp | The RIPE netname prefix in the isp field defeated the operator match |
| Tigo, exact observed strings (isp): `^tigo guatemala\b`, `^tigo-corporativo$`, `^corporativos tigo gt$`, `^for tigo b2b clients$`, `^tigo public ip$`, `^tigo$` | The six strings themselves | OpenASN files six Tigo ASNs as isp (AS13489, AS23201, AS27773, AS27831, AS27882, AS262197); the services sit on AS23243 (OpenASN hosting), AS23383 (isp), AS37649 (isp), AS26617 (hosting) and AS23201 (isp) | Sub-allocations named differently from the isp field. Anchored, because "Tigo" is also a solar brand |
| `\bbatelco\b` (isp) | Batelco Jordan, Batelco MPLS service | AS9038 OpenASN "Umniah", isp; AS5416 OpenASN "Beyon (Batelco)", isp | The isp field is the Arabic legal name |
| `\bvodien\b` (hosting) | VODIEN AUSTRALIA PTY LTD, Vodien Indonesia, Vodien Malaysia, Vodien Internet Solutions | A web-hosting and domain brand; its services sit on Dreamscape AS38719 (OpenASN hosting) and Oracle AS31898 (hosting) | Sub-allocation; AS38719's role `content_network` is not a provider under ADR 0008. OpenASN files Vodien's own AS58621 as `isp`; the hosting class follows the brand's business and the networks its services sit on. "Vodien Internet Solutions" moves from isp_telco (name keyword) to cloud_hosting |
| `^clientes netlife\b` (isp) | Clientes NETLIFE Quito / Guayaquil ... (≈ 250 services) | `isp` = Telconet S.A; AS27947 OpenASN "Telconet (Ecuador)", isp. The label means "NETLIFE customers" | A Spanish pool label; the pool patterns are English |
| `china netcom` (isp) | shanghai branch, china netcom; Fujian ... branch of China Netcom; ... | `isp` = China Unicom networks; AS17621 OpenASN "China Unicom (Shanghai)", isp | `chinanet` needs no space |
| `\bjazztel\b` (isp) | Jazztel Triple Play Services, Jazztel triple play services | `isp` = Orange Espagne SA; AS12479 OpenASN "Orange España", isp / access_provider | v4 caught only the 44-service spelling, through the access-PTR backstop. Under key-level profiling the two spellings together fall below the 0.30 share, so the named entry is needed |
| `\bazion\b` (cdn) | Azion Technologies Ltda. | Own AS52580 (`isp` = itself) carries the OpenASN flag `cdn` (category business) | `network_provider_class` reads flags only under category hosting |
| `^eg veri merkezi\b` (hosting) | EG VERI MERKEZI TEKNOLOJI LTD. STI. ("veri merkezi" = data centre) | Own AS212249 OpenASN hosting / access_provider | The role `access_provider` is not a provider under ADR 0008 |
| `^cheops technology\b` (hosting) | CHEOPS TECHNOLOGY FRANCE S.A., Cheops Technology Switzerland SA | Own AS58011 OpenASN hosting / content_network | The role `content_network` is not a provider under ADR 0008. Customers on its network (e.g. "GPM informatique Transverse") stay A2 |

### 7.3 Measured impact (v4 → v5, snapshot 2026-11-07) [F]

Final build (after the review fixes): 249 s wall, peak RSS 4.7 GB, 5,233,493 services, 15,257,632
evidence rows.

| Tier | v4 services | v5 services |
|---|---|---|
| A1 | 258,258 | 256,710 |
| A2 | 154,569 | 153,010 |
| P | 45,690 | 45,845 |
| B | 1,126,121 | 1,127,428 |
| C | 3,648,855 | 3,650,500 |

Org-class changes, counted per distinct raw org string over (org, isp, asn) rows (123 distinct orgs):

| Change | Orgs | Services |
|---|---|---|
| business → isp_telco | 76 | 1,513 |
| business → saas_platform | 25 | 1,104 |
| isp_telco → cloud_hosting | 1 | 395 |
| business → cloud_hosting | 13 | 358 |
| cloud_hosting → isp_telco | 2 | 234 |
| business → cdn | 2 | 137 |
| saas_platform → isp_telco | 1 | 49 |
| isp_telco → saas_platform | 1 | 20 |
| cdn → isp_telco | 1 | 4 |
| isp_telco → business | 4 | 4 |
| cloud_hosting → business | 1 | 1 |

Tier transitions (3,358 services in total):

| Transition | Services |
|---|---|
| A2 → C | 1,215 |
| A1 → B | 802 |
| A2 → B | 510 |
| A1 → C | 432 |
| A1 → A2 | 237 |
| A1 → P | 77 |
| A2 → P | 76 |
| B → P | 3 |
| B → A2 | 3 |
| C → A2 | 2 |
| P → B | 1 |

**By cause.** For each changed row, the v4 and v5 name classifiers were run on the same (org, isp):

| Cause | Orgs that change class | Services that change class | Services that change tier |
|---|---|---|---|
| Accent fold in the name table | 11 | 223 | 145 |
| Named entries (§7.2) | 41 | 2,001 | 1,450 |
| Key-level profiling (backstops, ASN majority, operator match on the account key) | 71 | 1,595 | 1,742 |
| isp-side name class only | 0 | 0 | 21 |

- **Accent fold** examples: TELEFÓNICA CHILE S.A., the Argentine "Cooperativa Telefónica ..."
  cooperatives, "Signal Bredbånd AS", "CapRock Comunicações".
- **Key-level profiling** is the largest new effect. The multi-tenant backstop now sees all spellings
  of one account together, which moves 25 orgs to `saas_platform`:
  - NhanHoa Software Company / company: 281 + 97 services;
  - Otsuka Corporation / OTSUKA CORPORATION: 165 + 72 (an actionable enterprise at v3 rank 301);
  - NovaTrend Services 99;
  - domainfactory / DOMAINFACTORY: 92 + 44;
  - Netsec / NETSEC: 77 + 33;
  - GMO DigiRock: 58 + 31.

  Most of these are hosting or domain companies by name. Otsuka is a systems integrator that also
  hosts, and whether it is a prospect needs review. Other effects:
  - A shifted ASN majority moved four 1-service orgs from isp_telco to business.
  - Webhost LLC moved from isp_telco to saas_platform.
  - M1 LIMITED (122 services) and several small ISPs became isp_telco.
- **A1 → A2** (237 services) covers businesses whose isp is now read as a provider.

**Top changed orgs by services:**

- Vodien Internet Solutions 395 (isp_telco → cloud_hosting; still a provider);
- NhanHoa 281; Otsuka 165; Bite Lietuva 161; UAB "Bite Lietuva" 156;
- BIT BV 151; Clientes NETLIFE Quito - gepon 141; Azion 132; EG VERI MERKEZI 127; VODIEN AUSTRALIA 124;
- M1 LIMITED 122; Jazztel triple play services 119; NovaTrend 99; TELEFÓNICA CHILE S.A. 97 + 78; Axtel 81.

These are attribution counts only. No precision is claimed: the changes move named operators out of
the owned tiers, but no labelled sample measures the tier precision.

### 7.4 Investigated and not fixed

These cases are from the scoring v3 actionable enterprise list (attribution v4). Each is a
limitation, with its root cause and the reason no rule was added.

| Account (v3 rank) | Root cause | Why not fixed |
|---|---|---|
| KGEx.com (139, A2) | Sub-allocations under 6 Taiwanese ISPs (Meteverse, TINP, New Kaohsiung Broadband, Taiwan Mobile, two cable TV operators) | No OpenASN row or isp field names KGEx itself; the nature of the org is inference |
| VEONE TECHNOLOGIES (141, A2) | Sub-allocation on OVH (AS16276) | A customer on a hoster looks the same; there is no corroboration that it resells |
| Waycom International (149, A2) | Sub-allocation on INHERENT ADISTA (AS16347, hosting) | Waycom has no OpenASN row; the isp field names Adista |
| VERO S.A (154, A1) | 19 own ASNs, all filed by OpenASN as `business` / stub; reverse DNS names the account on 120 services | OpenASN contradicts an ISP reading; no access-network PTR share triggers the backstop |
| JSC Kazteleport (155, A1) | Own ASNs filed `business` / access_provider | No corroboration |
| Xelon AG (177), Kuroit (179), TURKTICARET.NET (180), Civo (270), Grupo Loading Systems (271) — all A1 | Hosting companies whose own ASNs OpenASN files as `business` | Contradicted by the reference data. Adding them would be an unverified heuristic. They remain the "curated table is incomplete" limitation (§5.1) |
| T-Systems International (224), Cegeka (287), SIGMA INFORMATIQUE (275), Engineering D.HUB (136) | IT outsourcers: some services may be their clients' | Mixed evidence (T-Systems: AS34086 hosting / content_network, AS6878 business); a real prospect is plausible |
| `dom:vodafone.com` (83), `dom:jio.com` (86) | Tier-B domain accounts of telcos stay in the enterprise segment; only org accounts reach tier P | Segment rule, not a name-table issue; left for the scoring layer |
| Generic Turkish "veri merkezi" (data centre) orgs, e.g. TEKNET, meohost, NGN | Turkish for "data centre" is not a keyword | A keyword would be a broad rule; only EG VERI MERKEZI (OpenASN hosting) was added |

**Consortium networks (document only, no rule).** These look like enterprises but carry member
institutions' services: IUCC – Israel InterUniversity Computation Center (194; AS378 OpenASN
education_research), Red de Interconexion Universitaria (272; AS4270 education_research, members'
ASNs in its isp field), the WA State Board for Community & Technical Colleges, school cooperatives,
and shared-service IT agencies such as SITA (54), KDO (93) and CITEC (192). Some NRENs are
already curated as ISPs (§2.3). Deciding whether a consortium is a prospect is a product decision,
not an attribution rule.

**The "Turkish cloud host at rank 116"** in `ranking-v3.md` §6.3 does not reproduce in the current
v3 table. Rank 116 is "Nodisto IT, LLC", which is not actionable. The Turkish hosting accounts found
were TURKTICARET.NET (rank 180, actionable; not fixed, see above) and EG VERI MERKEZI (rank 69, in
review; fixed).

All accounts inspected for this section are development cases and must be excluded from any
evaluation holdout. They are listed in `~/firmable-work/eval/2026-11-07-dev-attribution-v5.json`:

- 315 account ids: the original inspection set, the v5 forms of renamed ids, the org and net ids of
  every org whose class or tier changed, and the accent-merge examples;
- 356 raw org strings.

### 7.5 Reproduce

```bash
uv run pytest -q -o addopts="" tests/test_attribution_providers.py tests/test_attribution_build.py \
  tests/test_eligibility.py tests/test_accounts.py tests/test_api.py
uv run firmable build-phase3 2026-11-07 --steps attribution    # ~250 s; writes attribution=v5 only
```

Follow-ups for the lead:

- Rebuild `accounts` and `serving` on v5. They write `accounts/scoring=v3/attribution=v5/...` with
  `eligibility_version` 2 and `serving_version` 3. Deploy the app and the DB together: an app at
  serving v3 refuses a v2 DB, and the reverse.
- `compare-rankings` derives its default legacy path from the current attribution version
  (`scoring=v2/<attribution>`). After the bump, pass
  `--legacy ~/firmable-work/lake/accounts/scoring=v2/attribution=v4/normalizer=v1/snapshot=2026-11-07`
  or pin that default to v4.
