# Data Profile — Firmable internet scan dataset

Status: research only. Every number below came from a DuckDB query in
`sql/exploration.sql` (section noted as §n / Qn.n). Nothing here comes from
external enrichment.

## 1. What the dataset is

- **Format:** newline-delimited JSON, one *banner* per line: one scanner
  response from one `ip:port/transport`. The schema is the Shodan banner format
  (`_shodan`, `data`, `http`, `ssl`, `vulns`, `cpe23`, `tags`, ...).
- **File:** `~/Downloads/firmable_dataset`, 137,113,095,904 bytes,
  **16,988,823 lines**.
- **Parse failures:** 451 lines (0.003%). They contain invalid UTF-16
  surrogate escapes. Python's `json` module accepts them; DuckDB's parser
  rejects them. They are kept as all-NULL rows with `ignore_errors=true` and
  dropped in §4.
- **Time window:** a single crawl, not a time series.
  - Bounds are 2026-11-07 10:24 to 15:06 UTC.
  - 99.2% of rows fall between 13:45 and 15:00, and 94.3% between 14:00 and
    15:00 (Q3.3 histogram).
- **Volume:**
  - 4,187,088 distinct IPv4 addresses and 70,922 IPv6 addresses.
  - 83,167 distinct `org` values, 38,527 `isp` values and 40,138 ASNs.
  - 13,967,293 distinct `ip:port:transport` keys.
- **Record size:**
  - Mean 8.1 KB across the file. Median about 0.9 KB in the samples.
  - The largest record in the samples is 2.1 MB. Size comes from HTML, favicon
    base64 and the `vulns` map.

### 1.1 Samples and representativeness

| Sample | How it was drawn | Rows | Window (UTC) | Representative? |
|---|---|---|---|---|
| `sample.jsonl` | First 5,000 lines of the file (verified byte-identical to line 1) | 5,000 | 12:49–14:00 | **No.** It is skewed to HTTP: 52% HTTP and 35% empty banners, against 28% and 57% in the full file. Port 9200 is over-represented 120x. |
| `distributed_sample.jsonl` | 250 evenly spaced byte offsets, then 8 consecutive lines at each | 2,000 | 13:02–14:59 | Mostly yes on marginals. It is clustered, though: runs of 8 consecutive lines share a scan module, e.g. 52 rows of port 2082/2086. |
| research offset sample (scratch only, not in the repo) | 20,000 seeded random byte offsets, then the next full line | 19,606 | 12:49–15:05 | Yes. Its marginals match the full file within about 1 point. |
| full file (streamed, §2) | every line | 16,988,823 | 10:24–15:06 | Ground truth |

The file is ordered by time: row position and timestamp correlate at 0.935.
A head sample is therefore also a time-biased sample. For later research, use
the full slim Parquet (§2) or a random-offset sample. Do not use `head`.

Coverage comparison (% of records):

| Field | sample | dist | offset | **full** |
|---|---|---|---|---|
| empty banner (`data` blank) | 35.3 | 56.4 | 55.1 | **56.9** |
| `http` present | 52.3 | 28.6 | 29.9 | **28.2** |
| `product` present | 27.9 | 15.8 | 15.6 | **13.4** |
| `ssl` present | 6.9 | 8.6 | 9.3 | **7.7** |
| `vulns` present | 4.6 | 3.5 | 4.6 | **2.5** |
| `cpe23` present | 38.4 | 24.6 | 24.6 | **22.8** |
| `cloud` present | 27.6 | 33.5 | 33.0 | **32.5** |
| any `tags` | 69.2 | 79.2 | 79.0 | **80.0** |
| ≥1 hostname | 72.2 | 74.7 | 76.0 | **75.8** |
| UDP | 9.2 | 7.9 | 7.5 | **7.5** |

## 2. Field dictionary

Coverage is the share of records in the full file where the field is
non-null or non-empty, unless a sample is named.

### 2.1 Identity and network

| Path | Type | Coverage | Notes |
|---|---|---|---|
| `ip_str` / `ip` | VARCHAR / UBIGINT | 98.7% | Missing on IPv6-only records |
| `ipv6` | VARCHAR | 1.3% | |
| `port` | INT | 100% | |
| `transport` | `tcp` \| `udp` | 100% | 92.5% tcp / 7.5% udp |
| `timestamp` | ISO string, no TZ | 100% | Scanner observation time (UTC assumed) |
| `hash` | BIGINT | 100% | Hash of `data`; the same banner gives the same hash |
| `org` | VARCHAR | 99.993% | **The IP-block registrant**, usually the provider |
| `isp` | VARCHAR | 99.993% | Network operator. `org == isp` on 77% of records (offset sample) |
| `asn` | VARCHAR (`AS123`) | 100% | |
| `hostnames[]` | VARCHAR[] | 75.8% | Reverse plus forward DNS names. About 80% of records with hostnames carry only provider-style PTR names (offset sample; see company-attribution.md) |
| `domains[]` | VARCHAR[] | 75.8% | Registrable domains derived from `hostnames`. Always present together with `hostnames`; adds no new information |
| `location.{city,country_code,country_name,region_code,latitude,longitude}` | mixed | >99.9% | `area_code` is always null. Geolocation of anycast/CDN ranges is unreliable: SG holds 27% of rows, driven by Incapsula/Google ranges |
| `cloud.{provider,region,service}` | VARCHAR | 32.5% | Google 4.39M, Amazon 0.77M, Alibaba 0.11M, Azure 0.09M, ... |
| `os` | VARCHAR | 3.7% | Fingerprint guess (`Windows 7 or 8`, `Fortigate v5`, `PIX OS 7.0.x`) |
| `devicetype` | VARCHAR | 0.2% | router, firewall, webcam, printer ... |
| `link`, `tcp.fp`, `uptime` | VARCHAR / OBJECT / INT | dist: 83% / 92% / 38% | Passive TCP/IP fingerprint (p0f style). Not used for signals |
| `opts.raw` | hex string | ~10% (sample) | Raw probe response bytes. Not used |

### 2.2 Scan metadata

| Path | Notes |
|---|---|
| `_shodan.module` | **The probe that was run, not what was found.** For example, `remcos-pro-rat` (19,843 rows) and `darktrack-rat` (20,398 rows) are 70% or more empty banners. The rest are mostly ordinary nginx 400 pages (Q1.5). `auto` makes up 55% of rows, and 90.8% of those are empty |
| `_shodan.options.hostname` | SNI/vhost the scanner requested. Present on 5.6% of rows. **A strong attribution field** |
| `_shodan.options.referrer`, `.scan` | Rare (≤1%). Not used |
| `_shodan.ptr`, `.crawler`, `.id`, `.region` | Crawler bookkeeping |

### 2.3 Service content

| Path | Coverage | Notes |
|---|---|---|
| `data` | 100% present, **43.1% non-empty** | Raw banner. Blank means the TCP port answered and the probe got no payload |
| `product`, `version` | 13.4% / 4.6% | Fingerprint. Can be wrong; see §4 |
| `cpe` / `cpe23[]` | 22.8% | Product identifiers. Usually 1–3 per record. Lists of 14–20 unrelated CPEs mark a decoy |
| `info` | ~4% (sample) | Free text such as `protocol 2.0` or `(Ubuntu)` |
| `tags[]` | 80.0% | Scanner classifications (§3.2) |
| `http.{status,title,server,host,location,html,html_hash,headers{...},waf,favicon{hash,data,location},robots,sitemap,securitytxt,components{name:{categories,versions}},redirects[],dom_hash,title_hash,headers_hash}` | 28.2% | `headers` is an open map (100+ distinct keys in samples). `components` is a Wappalyzer-style tech list with categories (CDN, CMS, Security, ...). `waf` is set on 52% of HTTP rows |
| `ssl.{versions[],cipher,ciphers[],cert{expired,expires,issued,subject{},issuer{},sig_alg,pubkey{type,bits},serial,fingerprint,extensions[]},chain[],chain_sha256[],dhparams,ja3s,jarm,alpn,tlsext,ocsp,trust{browser{mozilla,apple,microsoft},revoked},handshake_states,kex_groups,unstable}` | 7.7% | `versions` entries prefixed `-` mean *not supported*. `pubkey.type='dsa'` is used for ECDSA keys. `trust.browser` is null on 89% of TLS rows, meaning not evaluated rather than untrusted. Dates are `YYYYMMDDHHMMSSZ`. SAN data is raw DER bytes inside `extensions[].data` |
| `ssh.{type,key,fingerprint,hassh,cipher,mac,kex{...}}` | 0.8% | Full KEX algorithm lists available |
| `ntlm.{dns_domain_name,netbios_domain_name,fqdn,netbios_computer_name,os[],os_build,target_realm,timestamp}` | 15,701 rows | From RDP (87%), MS-SQL, IIS, WinRM and Exchange. **Discloses internal AD names** |
| `isakmp.{version,flags,exchange_type,vendor_ids[],aggressive{...}}` | 7.3% (UDP 500/4500) | IKE responder details; `aggressive` mode response |
| Protocol objects: `rdp_encryption`, `snmp`, `vnc`, `ftp`, `telnet`, `mysql`, `dns`, `ntp`, `sip`, `pptp`, `hikvision`, `dahua`, `mikrotik_routeros`, `mikrotik_winbox`, `hp_ilo`, `fortinet`, `kubernetes`, `plex`, `rsync`, `openflow`, `upnp`, `l2tp`, `mpls_ldp`, `dav`, `open_dir`, `hermes_agent`, `mac`, `vendor` | each <0.2% | Parsed protocol detail. Worth targeted extraction later (e.g. `hp_ilo`, `fortinet`, `mikrotik_routeros.version`) |

### 2.4 `vulns` (inferred CVEs)

`vulns` is a map from CVE ID to `{cvss, cvss_version, cvss_v2, epss,
ranking_epss, summary, references[], verified, kev?, ransomware_campaign?}`
(Q1.4).

| Metric | Value |
|---|---|
| records with `vulns` | 428,367 (2.5%) |
| CVEs per record | mean 51.9, p50 17, p99 367 |
| records with ≥1 CVE `verified:true` | **3,199 (0.75%)** |
| individual CVE entries `verified:false` in samples | 76,708 of 76,717 (99.99%) |
| records with any `kev:true` | 238,391 |
| … of which on fingerprint-soup decoys | 28,938 |
| … of which honeypot-tagged | 32,887 |
| … of which have no `version` | 73,616 |
| records with `ransomware_campaign:"Known"` | 67,655 |

**Interpretation:** `vulns` comes from matching product and version against
CPE ranges. It is not the result of exploit testing. Treat it as
*"possibly affected, per version string"*, never as *"vulnerable"*.

## 3. Value distributions (full file)

### 3.1 Ports and modules

- **Top ports:**
  - 80/tcp: 1.72M
  - 443/tcp: 1.22M
  - 500/udp (IKE): 1.18M
  - 2086/tcp: 0.48M
  - 2082/tcp: 0.45M
  - 22/tcp: 0.16M
  - 2000/tcp: 0.16M
  - 554/tcp: 0.12M
  - 110/tcp: 0.09M
- **Long tail of high ports:** ports such as 9166, 5915, 49767, 5231 and
  51002 have 40k–90k rows each and are **91–99.8% empty**. They come from a
  few provider orgs answering on every port.
- **Ports per IP:**
  - 3.14M IPs show 1 port.
  - 108,610 IPs show 11–100 ports. They hold 8.2M rows, 48% of the file.
  - 3,401 IPs show more than 100 ports.

### 3.2 Tags (% of records)

| Tag | % of records |
|---|---|
| cdn | 40.04 |
| cloud | 32.50 |
| vpn | 6.60 |
| pqc | 2.69 |
| honeypot | 1.16 |
| eol-product | 0.93 |
| self-signed | 0.76 |
| proxy | 0.31 |
| starttls | 0.30 |
| mptcp | 0.10 |
| database | 0.028 |
| iot | 0.026 |
| devops | 0.026 |
| open-dir | 0.025 |
| eol-os | 0.012 |
| ai | 0.010 |
| ics | 0.008 |
| videogame | 0.004 |
| medical | 0.003 |
| cryptocurrency | 0.003 |
| mcp | 0.003 |
| scanner | 0.001 |
| ssh-bad-key | 0.001 |
| c2 | 0.001 |
| malware | 0.001 |
| tor | 0.0003 |
| compromised | 0.0002 |
| alpr | 0.0001 |
| onion | <0.0001 |
| doublepulsar | <0.0001 |

### 3.3 Org concentration

| org | share of records | empty banner |
|---|---|---|
| Incapsula Inc | 28.9% | 83.6% |
| Google LLC | 26.9% | 98.3% |
| Cloudflare, Inc. | 7.3% | 0.5% |
| Amazon (3 org spellings) | 4.1% | ~1% |
| Aliyun / Alibaba (4 spellings) | 3.1% | <1.3% |

**Two orgs, Incapsula and Google, account for 56% of all records, and almost
all of those rows are empty or CDN-edge responses.**

### 3.4 Products (top)

| Product | Records |
|---|---|
| nginx | 559k |
| CloudFront httpd | 311k |
| Apache httpd | 216k |
| OpenSSH | 175k |
| AWS ELB | 104k |
| AkamaiGHost | 102k |
| MikroTik bandwidth-test | 66k |
| Microsoft IIS | 65k |
| OpenResty | 54k |
| Cisco (IKE) | 50k |
| BigIP | 44k |
| Ncat proxy | 44k |
| SonicWall | 38k |
| Fortinet FortiGate | 30k |
| Checkpoint | 17k |
| RDP | 16k |
| ZyXEL | 15k |

Full list: Q3.3.

### 3.5 TLS (1,305,753 TLS records)

| Measure | Records |
|---|---|
| expired certificate | 77,149 |
| TLS 1.0 enabled | 197,964 |
| TLS 1.1 enabled | 214,158 |
| SSLv3 enabled | 7,838 |
| SSLv2 enabled | 814 |
| versions not enumerated (`[]`) | 284,077 |
| RSA key < 2048 bits | 11,498 |
| SHA-1/MD5 signature | 22,402 |
| Mozilla trust evaluated | 139,101 (10.7%) |

### 3.6 HTTP (4,795,353 HTTP records)

| Measure | Value |
|---|---|
| status 403 | 32% of HTTP records |
| status 200 | 19% |
| status 503 | 10% |
| WAF fingerprinted | 52% |
| HSTS | 8.1% |
| CSP | 6.0% |
| `security.txt` | 0.4% |
| `X-Powered-By` disclosed | 3.3% |

### 3.7 Repeated observations (Q3.6)

- **Repeat counts:** 1,074,682 `(ip, port, transport, SNI)` keys occur more
  than once, for 3.43M rows in total. The median gap between repeats is 8
  minutes and the p99 is 53 minutes.
- **Changes between repeats:**
  - title: 0.65% of repeated keys
  - product: 0.46%
  - status: 0.46%
  - certificate: 0.36%
  - version: 0.08%
- **Keying without SNI is misleading.** On the bare `(ip, port, transport)`
  key, single CloudFront IPs show up to 4,562 rows, one per probed vhost.

## 4. Noise and data-quality findings

These are the main reasons a naive "port X is open" approach fails on this
data.

1. **Empty banners: 56.9% (9.66M rows).**
   - These rows mean the port completed a TCP handshake and returned nothing.
   - They concentrate on Google (98% empty), Incapsula (84%), Fly.io and
     Internet Rimon.
   - Enterprise BYOIP ranges on Google behave the same way. All 20,533
     `Wal-Mart Stores, Inc.` rows with isp `Google LLC` are empty, spread
     across random ports.
   - **Excluded from all signals.**
2. **Honeypots: 196,309 tagged rows (1.16%).** Some products are almost all
   honeypot. For example:
   - `Java Debug Wire Protocol`: 714 of 714
   - `Legalis Intranet`: 696 of 696
   - `MCP Server`: 1,446 of 1,887
   - `ASUS AiCloud`: 1,171 of 1,666
   - `LiteLLM`: 1,067 of 1,480
   - `Socks4A`: 8,165 of 27,606

   Excluded.
3. **"Fingerprint soup" decoys: 65,706 rows on 1,259 IPs, mostly
   Linode/Huawei/Alibaba/Akamai.**
   - Each is a ~147 KB HTTP page with a random `Server:` header.
   - Each matches 14–20 unrelated CPEs (ColdFusion, WordPress, Bugzilla,
     Django, Rails, FortiWeb ...).
   - Only 51% carry the `honeypot` tag.
   - They produce bogus `product` values such as "Sophos SSL VPN User Portal"
     on pages titled "Teltonika-RUT955" or "Budibase".
   - They account for **28,938 KEV-flagged records**.
   - Detected by: `len(cpe23) ≥ 8 AND cpe23 ∋ coldfusion AND cpe23 ∋ wordpress`.
     Excluded.
4. **Module ≠ detection.**
   - OT and RAT probe names are often answered by ordinary web servers or CDN
     edges.
   - Of `dicom` hits, 36,946 of 39,103 are on CDN edges.
   - `melsec-q-tcp` hits on port 9600 return nginx.
5. **CDN edge responses describe the CDN's configuration, not the
   customer's.**
   - Their TLS settings, open ports and WAF are the CDN's.
   - CDN rows are excluded from exposure and TLS signals.
6. **Product misfingerprints exist outside decoys too.** Example: `product =
   nginx` with title "UniFi OS". Prefer title, CPE and product agreement over
   any single field.
7. **The provider org dominates `org`.** See company-attribution.md.

After removing empty, honeypot and fingerprint-soup rows, **7,099,796 rows
(41.8%) are signal-eligible.** Deduplicating to the latest observation per
`(ip, port, transport, SNI)` gives the service table used for signals (§5).
