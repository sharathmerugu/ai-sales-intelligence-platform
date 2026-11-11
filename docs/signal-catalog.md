# Signal Catalog — cybersecurity buying signals from scan observations

Status: research draft for review. Nothing here has been scored or validated
against sales outcomes yet.

## How to read this catalog

Every signal separates three layers of evidence:

| Layer | Meaning | Example |
|---|---|---|
| **Observed fact** | Something the scanner recorded at time `ts` | "port 3389 returned an RDP handshake whose NTLM block names `<internal-domain>`" |
| **Inferred risk** | A security interpretation commonly drawn from that fact | "an interactive login surface is internet-reachable and leaks AD naming" |
| **Unverified hypothesis** | What would need outside confirmation before we act on it commercially | "the account may be evaluating ZTNA / PAM" |

Three rules apply throughout:

- **No vulnerabilities from ports alone.** No signal claims a vulnerability,
  a missing authentication control or buying intent from a port number. Ports
  only decide which probe ran; every signal below needs a protocol-level
  response or a product fingerprint.
- **The `vulns` field is version inference.** 99.99% of its CVE entries are
  `verified:false`.
- **Login pages prove nothing about access control.** A login page or admin
  title proves a management surface is reachable. It does not prove the
  surface is unauthenticated.

### Global eligibility filter

Applied before any signal (§4 of `sql/exploration.sql`). Excluded rows:

- empty banner: 9.66M
- `honeypot` tag: 196k
- fingerprint-soup decoys: 65.7k

That leaves 7.10M eligible observations. These are deduplicated to the latest
observation per `(ip, port, transport, SNI)`, giving 5.23M services.

### Attribution tiers

Counts are of signal-eligible services. Details in `company-attribution.md`.

| Tier | Meaning | Services | Share |
|---|---|---|---|
| A1 | `org` is not a provider or platform (direct allocation) | 621k | 11.9% |
| A2 | non-provider `org` inside a provider's network (sub-allocation / BYOIP) | 148k | 2.8% |
| B | provider IP, but the record names a customer domain (hostname, cert CN, SNI, HTTP Host, NTLM) | 1.16M | 22.3% |
| C | provider IP with no customer evidence: **unattributable** | 3.30M | 63.0% |

A1 still includes ISP and residential ranges that the provider heuristic
misses (e.g. BIGLOBE, Asahi Net, MTN Nigeria, Yettel). Treat A1 counts as
upper bounds until a curated ASN classification replaces the regex.

### Prevalence summary

Full dataset, deduplicated services. "Owned" = tiers A1 + A2.

| ID | Signal | Services | Owned services | Owned orgs | Tier-B domains | Tier C (unattributable) |
|---|---|---|---|---|---|---|
| S01 | Remote-access gateway / SSL-VPN portal identified | 26,700 | 8,285 | 3,393 | 2,417 | 14,234 |
| S02 | IPsec/IKE VPN responder | 791,246 | 218,900 | 30,993 | 12,775 | 545,259 |
| S03 | Interactive remote-admin protocol reachable (RDP/VNC/Telnet/WinRM/ScreenConnect) | 26,114 | 5,745 | 1,905 | 1,141 | 18,435 |
| S04 | Database / object store reachable | 9,930 | 1,628 | 834 | 594 | 7,408 |
| S05 | Infra / DevOps / hosting management plane reachable | 35,678 | 7,680 | 3,491 | 5,657 | 19,549 |
| S06 | TLS hygiene defect (non-CDN) | 217,036 | 48,898 | 12,810 | 61,916 | 57,680 |
| S07 | End-of-life product/OS (scanner tag) | 137,683 | 27,101 | 6,821 | 40,398 | 54,882 |
| S08 | Version-inferred CVE with KEV flag (unverified) | 140,816 | 34,077 | 8,145 | 39,235 | 53,520 |
| S09 | Owned web app without WAF/CDN fingerprint and without HSTS | 92,067 | 92,067 | 16,623 | — | — |
| S10 | NTLM leaks internal AD domain / host | 13,098 | 3,256 | 1,229 | 1,050 | 8,316 |
| S11 | OT / ICS / medical / camera exposure | 21,207 | 6,283 | 1,970 | 210 | 14,415 |
| S12 | Compromise / offensive-tooling tag | 220 | 34 | 32 | 40 | 145 |
| S13 | Open directory listing | 3,355 | 876 | 592 | 1,310 | 956 |
| S14 | Self-hosted email / collaboration server | 4,768 | 1,603 | 913 | 1,537 | 1,238 |
| S15 | Self-hosted AI / LLM / agent / automation tooling | 2,732 | 459 | 166 | 571 | 1,292 |
| S16 | Security-vendor technographics (WAF / appliance) | 1,522,317 | 72,701 | 9,789 | 107,588 | 919,133 |
| S17 | `security.txt` published (positive maturity) | 14,733 | 2,302 | 713 | 1,951 | 7,934 |

All examples below are real rows from the dataset. IPs are masked to /24.
Counterexamples are real rows that a naive rule would have matched.

---

## S01 — Remote-access gateway / SSL-VPN / firewall portal identified

- **Observed fact:** A TCP service returns a fingerprinted remote-access or
  firewall product, or a portal title naming one. Products seen include
  SonicWall, Citrix NetScaler/Gateway, FortiGate, Check Point Connectra,
  GlobalProtect, BIG-IP APM logout page, DrayTek, Sophos and Pulse/Ivanti.
- **Inferred risk:** The perimeter remote-access appliance is internet-facing.
  This class of device is heavily targeted. Whether a specific box is
  vulnerable depends on a version, which is rarely available: S01 rarely has
  `version`, and only 30 S01 services also carry S07 or S08 on the same port.
- **Hypothesis:** The account runs a legacy VPN and is a ZTNA/SASE
  replacement candidate. This needs firmographic and timing confirmation.
- **Detection:**
  - `transport='tcp' AND NOT cdn`
  - AND `product` regex (`fortigate|sonicwall|check ?point|connectra|netscaler|citrix|globalprotect|pulse secure|ivanti connect|sophos|zyxel|barracuda|watchguard|draytek|…`)
  - OR `http.title` regex (`GlobalProtect|FortiGate|SSL VPN|VPN Portal|NetScaler|Citrix Gateway|BIG-IP logout page|SonicWall …`)
- **Evidence to show:** product, title, port, certificate CN, `ts`.
- **Top hits:**

  | Product | Services |
  |---|---|
  | SonicWall | 6,578 |
  | Citrix NetScaler | 4,566 |
  | untyped HTTPS with a matching title | 3,954 |
  | DrayTek | 1,659 |
  | Check Point Connectra | 1,264 |
  | BIG-IP APM | 717 |

- **Examples:**
  - An organisation (A1): 54 IPs, e.g.
    x.x.x.x:443, "BIG-IP logout page".
  - An organisation (A1): two IPs, "Citrix Gateway".
  - An organisation (A1): three NetScaler IPs.
  - An organisation (A1): BIG-IP APM logout page.
- **Counterexamples:**
  - Fingerprint-soup decoys assign `product = "Sophos SSL VPN User Portal"`
    to pages titled "Teltonika-RUT955" or "Budibase" (removed by the decoy
    filter).
  - DrayTek devices present the vendor default certificate CN `draytek.com`.
    That is the vendor's domain, not the customer's (handled by
    `is_non_company_name`).
  - "Puerto Rico Telephone Company" and "Fatbeam, LLC" appear in tier A1, but
    these are ISPs whose subscriber CPE gets attributed to the ISP.
  - A large healthcare group's NetScaler AAA hosts land in tier B/C, not A1.
    Its own brand domains exceed the >100-domain
    multi-tenant threshold, so the org is misclassified as a platform. See
    company-attribution.md §5.
- **False positives:**
  - Shared VPN concentrators run by MSPs or telcos.
  - SOHO routers with a VPN feature (DrayTek, ZyXEL).
  - Vendor demo or test units: `Fortinet Inc.` itself is a top A1 org.
- **Attribution risk:** Medium. Usually on owned space (31% of hits). Cloud
  instances (Alibaba, AWS) host virtual appliances for many customers.
- **Freshness:** Appliance firmware changes in weeks. Advisories land at any
  time. Suggested TTL: 7–14 days. This is a hypothesis; it needs repeated
  snapshots to measure.
- **Commercial relevance:** ZTNA/SASE, VPN replacement, MFA, firewall
  refresh, exposure management. **Very high** when combined with a fresh
  vendor advisory (C1).

## S02 — IPsec / IKE VPN responder

- **Observed fact:** UDP 500 or 4500 answers an IKE probe (`isakmp` object,
  `vpn` tag). Vendor identification comes from vendor IDs or the product
  field, e.g. Cisco, SonicWall, FortiGate, strongSwan, ZyXEL, Check Point.
- **Inferred risk:** None by itself. IPsec responders are normal. The
  `isakmp.aggressive` response, present on 37% of IKE rows in the sample, is
  a known weak-configuration indicator but is still *configuration*, not a
  vulnerability.
- **Hypothesis:** The site uses site-to-site or legacy remote-access VPN.
- **Detection:** `module IN ('ike','ike-nat-t')`.
- **Prevalence:** 791k services. That is ubiquitous, so treat it as a
  footprint and technographic attribute, not a trigger.
- **False positives:** Telco CPE fleets. A2/A1 ISP ranges dominate.
- **Attribution risk:** High in tier C (69%).
- **Freshness:** Slow-changing; 30–90 days.
- **Commercial relevance:** Low alone. Useful for vendor install base
  (S16-style) and as a component of C1/C6.

## S03 — Interactive remote-administration protocol reachable

- **Observed fact:** A protocol-level response was received from RDP (with
  `ntlm` / `rdp_encryption`), VNC, Telnet, WinRM, ScreenConnect,
  TeamViewer, X11, rlogin or NoMachine.
- **Inferred risk:** A login surface is directly reachable. Brute-force and
  credential-stuffing exposure is a commonly cited ransomware initial-access
  pattern. **No authentication weakness is observed.**
- **Hypothesis:** The account lacks a remote-access broker, PAM or ZTNA
  control.
- **Detection:** `NOT cdn AND (module IN ('rdp','telnet','x11','rlogin','nomachine') OR product ~ 'remote desktop|vnc|winrm|screenconnect|teamviewer|telnetd')`.
- **Top hits:**

  | Product | Services |
  |---|---|
  | RDP | 12,912 |
  | VNC | 4,805 |
  | Telnet | 3,679 |
  | Crestron telnetd | 711 |
  | WinRM | ~500 |
  | ScreenConnect | ~460 |

- **Examples:**
  - An organisation (A1): 16 RDP hosts, NTLM domain
    `<internal-domain>`.
  - An organisation (A1): RDP at x.x.x.x:3389, NTLM `<internal-domain>`.
- **Counterexamples:**
  - 3,058 `[rdp]` module hits sat on CDN edges, i.e. Incapsula answering the
    probe. These are excluded by `NOT cdn`.
  - 20,936 RDP-module rows had empty banners. They are already removed.
- **False positives:**
  - Cloud VPS jump boxes with default hostnames (`WIN-XXXX`,
    `vultr-guest`).
  - Lab and university machines.
  - Crestron AV controllers, which are telnet but not IT admin.
- **Attribution risk:** High. 71% of hits are tier C, mostly hosting VPS
  rented by individuals.
- **Freshness:** RDP exposure is often short-lived (cloud instances).
  Suggested TTL: 7 days.
- **Commercial relevance:** PAM, ZTNA, MFA, EDR/MDR, attack surface
  management. High when the host is tier A1/A2 and S10 names the corporate
  AD domain (C2).

## S04 — Database / object store reachable

- **Observed fact:** A data-store protocol answered, or its console was
  identified. Seen: MinIO, MySQL/MariaDB, MS-SQL and SQL Server Browser,
  PostgreSQL, ClickHouse, Redis, Elastic, Mongo, Riak, the `database` tag.
- **Inferred risk:** Data infrastructure is reachable from the internet.
  Whether authentication is enforced is **not observed**.
- **Hypothesis:** Cloud or DB security posture gap.
- **Detection:**
  - `NOT cdn AND (product ~ db-regex OR (db module AND banner not HTTP) OR tag 'database')`
  - Module-only hits whose banner starts `HTTP/` are excluded.
- **Top hits:**

  | Product | Services |
  |---|---|
  | MinIO | 2,912 |
  | MySQL | 2,377 |
  | ClickHouse native | 1,581 |
  | SQL Server Browser | 1,531 |
  | MariaDB | 729 |
  | Redis | 436 |
  | PostgreSQL | 386 |

- **Examples:**
  - An organisation (A2): MS-SQL 2012 RTM on 3306, NTLM host `<internal-host>`.
  - An organisation (A1): MS-SQL 2014 SP3 on 52014 plus SQL
    Browser on 1434.
- **Counterexamples:**
  - `nginx` matched the db rule on 404 services through the `database` tag
    on HTTP fronts.
  - `[clickhouse-native]` produced 115 hits on CDN edges.
- **False positives:** Intentionally public object stores (MinIO behind a
  CDN for assets). SQL Browser responses without an exposed SQL port.
- **Attribution risk:** High (75% tier C).
- **Freshness:** 7 days.
- **Commercial relevance:** CSPM/DSPM, database security, backup and
  ransomware resilience. Strong when tier A1 and combined with S10.

## S05 — Infrastructure / DevOps / hosting management plane reachable

- **Observed fact:** A management UI or API was identified by product or
  title. Seen: UniFi OS, WHM, cPanel, Plesk, RouterOS, MinIO Console, GitLab,
  Portainer, Grafana, Kubernetes, Keycloak admin console, Proxmox,
  phpMyAdmin, HP iLO, Jenkins, Airflow, Argo CD.
- **Inferred risk:** Control-plane exposure. Login pages are usually present.
  **Authentication bypass is not observed.**
- **Hypothesis:** DevOps or security tooling gaps, shadow IT.
- **Detection:** product/title regex (see SQL §6), `NOT cdn`.
- **Top titles:**

  | Title | Services |
  |---|---|
  | UniFi OS | 4,375 |
  | WHM Login | 4,050 |
  | RouterOS config | 3,154 |
  | MinIO Console | 2,726 |
  | cPanel Login | 2,457 |
  | GitLab | 1,475 |
  | Portainer | 830 |
  | Grafana | 742 |

- **Examples:**
  - An organisation (A1): "Keycloak Administration Console" on 5 IPs.
  - An organisation (A1): Proxmox VE
    on 443.
  - An organisation (A1): Grafana.
- **Counterexamples:**
  - UniFi OS on DigitalOcean with cert CN `unifi.local`. That is a default
    self-signed certificate on an MSP-hosted controller, not a company
    domain.
  - WHM/cPanel on hosting providers: this is the hoster's panel, so the
    record describes the provider, not a prospect.
- **False positives:** Hosting control panels on shared hosting; vendor demo
  instances; `routeros` titles on ISP CPE.
- **Attribution risk:** High (55% tier C). Hosting panels must be scoped to
  the hoster.
- **Freshness:** 14 days.
- **Commercial relevance:** Exposure management/ASM, CSPM/KSPM, PAM, secrets
  management.

## S06 — TLS hygiene defect (non-CDN endpoint)

- **Observed fact:** On a non-CDN TLS service, one or more of the following.
  Sub-flag counts (Q6.3):

  | Sub-flag | Services |
  |---|---|
  | certificate `expired` | 53,985 |
  | TLS 1.0 or 1.1 accepted | 112,841 |
  | SSLv2/v3 accepted | 6,456 |
  | RSA key < 2048 bits | 9,614 |
  | SHA-1/MD5 signature | 17,023 |
  | self-signed certificate on an HTTP(S) service (RDP excluded) | — |
  | expiring within 30 days (predictive; not part of the S06 trigger) | 7,462 |

- **Inferred risk:** Weak cryptographic hygiene. Expired or self-signed
  certificates on user-facing services suggest absent certificate lifecycle
  management.
- **Hypothesis:** No certificate lifecycle management (CLM) or PKI tooling.
- **Detection:** see SQL §6.
  - `ssl.versions` must match exactly, because `-TLSv1` means *disabled*.
  - `cert.expired` agrees with `expires < ts` on 100% of rows.
- **Examples:**
  - An organisation (A1): 64 IPs with a TLS hygiene defect.
  - An organisation (A1): 79 IPs.
  - An organisation (A1): 143 services on 444/tcp, title "Server Login".
- **Counterexamples:**
  - RDP certificates are self-signed by design (14k RDP services). They are
    excluded from the self-signed criterion.
  - CDN edges (Cloudflare/Akamai/CloudFront) are excluded because their TLS
    is the CDN's configuration.
  - Alibaba WAF default cert CN `notexist.com`.
  - Hosting-brand certificates (`hstgr.cloud`): the cert belongs to the
    hoster, not the site owner.
- **False positives:**
  - Device-management ports where self-signed is standard (firewalls, iLO).
  - Legacy TLS left enabled for compatibility but never negotiated by
    clients.
- **Attribution risk:** Medium. 51% of hits are tier B, where attribution
  relies on the certificate CN or SAN.
- **Freshness:** Expiry is deterministic, so the "expiring in N days" flag
  can be computed for any future date. Protocol support changes rarely: 30
  days.
- **Commercial relevance:** CLM/PKI (machine identity), web/app security
  posture, compliance (PCI DSS requires TLS ≥ 1.2). Medium. Best as a
  "hygiene debt" amplifier (C3).

## S07 — End-of-life product / OS

- **Observed fact:** The scanner tagged the service `eol-product` or `eol-os`.
- **Inferred risk:** The software no longer receives security fixes, per the
  scanner's EOL mapping. That mapping is not documented in the data.
- **Hypothesis:** The account carries a patch or upgrade backlog.
- **Detection:** `tags && ['eol-product','eol-os']`.
- **Top hits:**

  | Product | Services |
  |---|---|
  | nginx | 132k (the tag fires on nginx versions outside supported branches) |
  | Apache | 13k |
  | RDP | 1.4k |
  | MySQL | 0.9k |
  | Kubernetes | 0.7k |

- **Examples:**
  - An organisation (A1): nginx "403 Forbidden" on 8 IPs, internal
    NTLM domain `<internal-domain>` elsewhere.
  - An organisation (A1): nginx default page on 30 IPs.
- **Counterexamples:**
  - The EOL tag lands on nginx `1.24.0`/`1.28.3` behind managed platforms
    (`Amazon Data Services India` hosting a portfolio site). The website
    owner may not control the runtime.
  - Distribution backports (Ubuntu/Debian builds) can keep an old version
    string while carrying security patches.
- **False positives:** Backported distro packages; reverse proxies reporting
  an upstream version.
- **Attribution risk:** Medium.
- **Freshness:** 30 days.
- **Commercial relevance:** Vulnerability and patch management, virtual
  patching/WAF, modernization services. Medium.

## S08 — Version-inferred CVE with CISA KEV flag (UNVERIFIED)

- **Observed fact:** `vulns` lists at least one CVE with `kev:true` for the
  fingerprinted product and version. `verified` is false for 99.99% of CVE
  entries.
- **Inferred risk:** *If* the version string is accurate and unpatched, a
  known-exploited vulnerability may apply.
- **Hypothesis:** Vulnerability management gap. **Never present this to a
  prospect as "you are vulnerable."**
- **Detection:** `any_kev AND product IS NOT NULL AND version IS NOT NULL`,
  after excluding honeypots and decoys.
- **Population context:**
  - 238,391 raw rows have `kev:true`.
  - 28,938 of them sit on fingerprint-soup decoys and 32,887 on honeypots.
  - 73,616 have no version at all.
  - After filtering and deduplication, 140,816 services remain.
- **Top hits:**

  | Product | Services |
  |---|---|
  | nginx | 98.8k (pre-dedup) |
  | Apache httpd | 56.6k |
  | IIS | 3.8k |
  | Jetty | 0.9k |

- **Examples:**
  - An organisation (A1): Apache/nginx on 166 IPs.
  - An organisation (A1): IIS on 13 IPs.
  - An organisation (A1): Apache
    2.4.18.
  - (named example withheld in the public copy)
- **Counterexamples:**
  - KEV on decoys whose CPE lists include ColdFusion, WordPress, Bugzilla
    and 12 more.
  - KEV on `Confluence` titles that are honeypot-tagged.
  - KEV on nginx where the CVE list was matched by version range alone.
- **False positives:** Backports; CPE over-matching; the version string of a
  front proxy rather than the app.
- **Attribution risk:** Medium.
- **Freshness:** KEV status and advisories change daily. Re-evaluate within
  7 days of a KEV addition.
- **Commercial relevance:** Vulnerability management, exposure management,
  MDR. Medium. Strongest as a timing trigger: "a KEV entry added this week
  affects a product family this account exposes."

## S09 — Owned web application without WAF/CDN fingerprint and without HSTS

- **Observed fact:** On tier A1/A2 space, an HTTP 200 page with a title has
  no `http.waf` fingerprint, no `cdn` tag and no HSTS header, and is not a
  block page.
- **Inferred risk:** Origin web apps are directly exposed without an edge
  protection layer. **The absence of a fingerprint is weak evidence.** WAFs
  can be transparent.
- **Hypothesis:** WAF/WAAP or CDN opportunity.
- **Detection:** see SQL §6. Titles such as "Request Rejected", "Rejected
  Request", 403/50x pages and BigIP/NetScaler/FortiWeb products are excluded.
  Those are WAF block pages that the fingerprinter missed. BNY Mellon and the
  Government of Alberta both returned them.
- **Examples:**
  - An organisation (A1): a ministry's
    citizen-request portal title on Apache.
  - (named example withheld in the public copy)
  - An organisation (A1): a placeholder title naming the company on
    12–13 IPs each.
- **Counterexamples:**
  - Hikvision camera web UIs (3,242 S09 services). These are devices, not
    web apps; route them to S11. A later rule revision should exclude them
    from S09.
  - Default "Welcome to OpenResty!" or "IIS Windows Server" pages, which are
    unconfigured hosts.
- **False positives:** Intranet-style apps intentionally public; WAFs that do
  not modify responses.
- **Attribution risk:** Low (owned space only), but the A1 ISP contamination
  noted above still applies.
- **Freshness:** 30 days.
- **Commercial relevance:** WAF/WAAP, CDN, bot management. **Low–medium.**
  This signal is noisy and should be combined with S08 or S07 before use.

## S10 — NTLM discloses internal Active Directory domain / host

- **Observed fact:** RDP, MS-SQL, IIS, WinRM or Exchange returned an NTLM
  challenge. It contains `dns_domain_name`, `netbios_domain_name`, `fqdn`
  and `os_build`. For example, `ETC-SQL-DW1.src.riverside.stockton.ac.uk` on
  port 53337.
- **Inferred risk:** Information disclosure of internal naming, useful for
  targeted attacks. `os_build` gives the Windows build: 6.3.9600 is Windows
  Server 2012 R2 (EOL), 10.0.14393 is Server 2016.
- **Hypothesis:** Identity attack surface; the account may need identity
  threat detection or PAM.
- **Detection:** `ntlm.dns_domain_name IS NOT NULL`.
  - 15,701 raw rows; 13,098 services.
  - Only ~1,284 eligible observations carry a dotted, public-looking domain.
    The rest are workgroup or VPS defaults such as `WIN-…` and
    `DESKTOP-…`.
- **Examples:**
  - (named example withheld in the public copy)
  - (named example withheld in the public copy)
  - (named example withheld in the public copy)
  - (named example withheld in the public copy)
- **Counterexamples:** `WIN-3ACDK6GS5TF`, `vultr-guest`, `DESKTOP-4KDQHD0` on
  Vultr/Hetzner/OVH. These are default names on rented servers and carry no
  company identity.
- **False positives:** None for the fact itself. Risk depends on context.
- **Attribution risk:** **Lowest of all signals when the domain is dotted.**
  The internal AD name is chosen by the organization.
- **Freshness:** 14 days.
- **Commercial relevance:** Identity security (ITDR), PAM, ASM. Also a
  first-class **attribution feature** (company-attribution.md).

## S11 — OT / ICS / medical / camera exposure

- **Observed fact:** One of the following:
  - An industrial or medical protocol answered with a non-HTTP payload
    (Modbus, DNP3, IEC-104, EtherNet/IP, MELSEC, Omron FINS, PCWorx,
    ProConOS, GE-SRTP, DICOM, BACnet, Fox).
  - `ics` or `medical` tags.
  - Camera/NVR/building-automation products: Hikvision 10.7k, Dahua, Axis,
    Crestron.
- **Inferred risk:** Operational technology is reachable from the internet.
- **Hypothesis:** The account lacks OT network segmentation and monitoring.
- **Detection:** see SQL §6.
  - Module-only matches require a non-HTTP banner and a non-web-server
    product.
  - `NOT cdn`.
- **Counterexamples (raw rule before filters):**
  - `dicom`: 39,103 hits, of which **36,946 were on CDN edges**.
  - `melsec-q-tcp`: 6,531 hits, 4,811 on CDN edges.
  - `omron-tcp` hits on port 9600 returned `nginx` (Kcell JSC, China Unicom
    Henan).
  - Chromecast devices tagged `iot` are consumer devices (2,999).
- **Examples:**
  - An organisation (A1): DICOM `medical` on port 104.
  - An organisation (A2): Hikvision on 80. Note FreeBit is an ISP, so the camera
    belongs to a subscriber.
- **False positives:** Research honeypots not tagged as such; ISP subscriber
  devices.
- **Attribution risk:** **Very high.** 68% of hits are tier C, and cameras
  sit mostly on residential/SMB ISP space.
- **Freshness:** 30 days.
- **Commercial relevance:** OT security (asset visibility and monitoring),
  IoT security, physical security. **High for manufacturing, utilities and
  healthcare**, but only when attribution is A1/A2 with a non-ISP org.

## S12 — Compromise / offensive-tooling indicators

- **Observed fact:** Scanner tags `c2`, `malware`, `compromised` or
  `doublepulsar`. Products seen: XtremeRAT, Metasploit, Sliver C2, Panda C2,
  GoPhish, XMRig, BurpSuite.
- **Inferred risk:** The host runs attack or C2 tooling, or is itself
  compromised (`compromised`, `doublepulsar`).
- **Hypothesis:** On a company's *owned* space this may indicate an incident
  or red-team activity. On rented VPS it is almost always attacker or
  pentester infrastructure.
- **Prevalence:** 220 services, of which only 34 are on owned space.
- **Examples:** an organisation (A1, port 3790): "Metasploit – Setup and
  Configuration", tag `c2`.
- **Counterexamples:** BurpSuite tagged `malware` on Tencent Cloud. This is
  a security tester's tool, not a compromise.
- **Attribution risk:** Extreme. Tooling on a VPS belongs to whoever rents
  it.
- **Freshness:** Hours to days.
- **Commercial relevance:** IR/MDR. **Do not use for outreach without
  analyst review.** Mentioning a suspected compromise to a prospect carries
  legal and reputational risk.

## S13 — Open directory listing

- **Observed fact:** `open-dir` tag; the title is usually "Index of /".
- **Inferred risk:** Possible unintended file exposure. File contents are not
  observed.
- **Examples:**
  - (named example withheld in the public copy)
  - (named example withheld in the public copy)
- **Counterexamples:** Intentional mirrors and download servers, e.g. Linux
  mirrors at universities.
- **Attribution risk:** Medium. 45% of hits are tier B via the HTTP Host or
  cert.
- **Freshness:** 7 days.
- **Commercial relevance:** DLP/DSPM, ASM. Low–medium.

## S14 — Self-hosted email / collaboration server

- **Observed fact:** Outlook Web App (`Outlook` title: 1,014), Exchange SMTP,
  Zimbra (520), MDaemon, MailEnable, Lotus Domino, GroupWise, Kerio Connect.
- **Inferred risk:** On-prem mail is a frequent target class. Version is
  usually unknown.
- **Hypothesis:** The account is a candidate for an email security gateway
  or a cloud-mail migration.
- **Examples:**
  - An organisation (A1): Lotus Domino.
  - An organisation (A1): Outlook Web App.
  - An organisation (B): OWA.
  - An organisation (B): Kerio Connect 10.0.9.
- **Counterexamples:**
  - `Novell GroupWise imapd`: 690 services, 1 owned. A probe-response pattern
    that clusters on a few tier-C hosts.
  - MailEnable on shared hosting (`serverpars.net`), which belongs to the
    hosting provider.
- **Attribution risk:** Medium.
- **Freshness:** 30 days.
- **Commercial relevance:** Email security, M365/Google migration, MDR.
  Medium–high when combined with S07 or S08 (C5).

## S15 — Self-hosted AI / LLM / agent / automation tooling

- **Observed fact:** n8n (801), Open WebUI (209), Streamlit, JupyterHub,
  LiteLLM, MCP Server, Hermes Agent, Dify, LibreChat; `ai`/`mcp` tags.
- **Inferred risk:** AI or automation infrastructure is reachable. These
  tools hold API keys and data connectors.
- **Hypothesis:** Shadow AI; the account may be a buyer for AI security or
  governance tooling.
- **Counterexamples:** This class is **honeypot-saturated**.
  - `MCP Server`: 1,446 of 1,887 raw rows are honeypot-tagged.
  - `LiteLLM`: 1,067 of 1,480 raw rows are honeypot-tagged.
  - Post-filter, `MCP Server` still has 426 services, 1 of them owned.
    Assume residual decoys remain.
- **Examples:**
  - An organisation (A1): JupyterHub 1.4.0.
  - An organisation (B): Open WebUI.
- **Attribution risk:** High (47% tier C).
- **Freshness:** 7 days. This class churns fast.
- **Commercial relevance:** AI security posture, secrets management, SaaS
  security. Emerging. Treat as exploratory.

## S16 — Security-vendor technographics

- **Observed fact:** One of the following:
  - An `http.waf` fingerprint (Cloudflare, CloudFront, Incapsula/Imperva,
    Akamai Kona, AWS ELB, FortiWeb, F5 BIG-IP LTM/ASM, NetScaler AppFW,
    Azure Front Door, Zscaler, Barracuda, ...).
  - A security appliance product (FortiGate, SonicWall, Check Point,
    Zscaler, BIG-IP, ...).
- **Inferred:** Not a risk. This is the installed vendor footprint.
- **Hypothesis:** A competitive-displacement or renewal opportunity, given
  external renewal-timing data.
- **Examples:**
  - (named example withheld in the public copy)
  - An organisation (A1): BIG-IP.
  - An organisation (A1): Cloudflare-fronted.
- **Counterexamples:** A CDN edge serving a domain that only CNAMEs to a
  marketing platform (HubSpot, WPEngine). The vendor relationship belongs to
  the platform, not the brand.
- **Attribution risk:** Low for tier-B domain evidence on CDNs; the SNI/cert
  names the customer.
- **Freshness:** 90 days.
- **Commercial relevance:** Competitive intelligence for WAF, CDN, firewall
  and SASE vendors. High value, low risk. No security claim is made.

## S17 — `security.txt` published (positive maturity signal)

- **Observed fact:** `http.securitytxt` is present: 19,492 HTTP rows, 14,733
  services.
- **Inferred:** The account has a vulnerability-disclosure process. This
  points to a more mature security function.
- **Use:** As a **dampener or segmentation feature**, not a trigger. Mature
  programs buy differently: platform consolidation rather than first tools.
- **Freshness:** 90 days.

---

## Compound signals

Same-account co-occurrence is weaker than same-service co-occurrence. Counts
are accounts (owned = org key; tier B = first customer domain); Q7.1/Q7.2.

| ID | Definition | Owned-space accounts | Tier-B accounts | Why it matters |
|---|---|---|---|---|
| C1 | S01 remote-access edge + (S07 EOL or S08 KEV) on same account | 1,131 | 213 | Aging perimeter; strongest ZTNA/VPN-refresh narrative. **Only 30 IPs** have both on the same `ip:port`, because edge appliances rarely expose versions |
| C2 | S03 remote admin + S10 identity leak | 1,050 | 883 | Identity-exposed remote access. On the same `ip:port`: 4,171 IPs |
| C3 | (S04 database or S05 mgmt plane) + S06 TLS debt | 2,180 | 1,612 | Hygiene debt across control planes |
| C4 | ≥3 distinct exposure signals among S01, S03, S04, S05, S10, S11, S13, S14, S15 | 1,146 | 212 | Attack-surface sprawl; ASM/CTEM narrative |
| C5 | S14 on-prem mail + (S07 or S08) | 479 | 145 | Email security / migration |
| C6 | S11 OT + (S01 or S03) remote access | 727 | 60 | OT reachable alongside remote access; OT security |

Owned-space accounts include ISP orgs. Expect substantial shrinkage once ISPs
are filtered.

Additional compounds worth testing once firmographics are joined:

- **Regulated-industry exposure.** Healthcare plus S11 DICOM or S04. Finance
  plus S08. Government plus S06.
- **Vendor-advisory timing.** S01/S16 vendor footprint joined to an external
  advisory feed (e.g. a new FortiGate or NetScaler KEV entry). Outreach would
  lead with the advisory, not with a claim about the prospect.
- **Multi-cloud sprawl.** Distinct `cloud.provider` count per tier-B domain
  ≥ 3. CSPM/CNAPP.

## Change over time

**Status in this dataset:** one ~5-hour crawl. Repeated observations of the
same `(ip, port, transport, SNI)` are minutes apart (median 8 minutes) and
changed in under 1% of cases: product 0.46%, title 0.65%, certificate 0.36%,
version 0.08%. Those changes are mostly load-balancer variation. **No real
change signal can be derived from this file.**

With periodic snapshots, the SQL §7 Q7.3 template diffs on
`(ip, port, transport, SNI)` and yields the following.

| Change event | What it suggests (hypothesis) |
|---|---|
| `new_exposure` of S01/S03/S04/S05 on an account | New project, M&A integration, misconfiguration. Fast-decay trigger |
| `closed` | Remediation, possibly after an incident; a post-incident buying window |
| `version_change` on an S01 product | Patching cadence. A fast patch is a mature buyer; a stale version after an advisory is an urgent need |
| `cert_rotated` / cert issuer change | CLM adoption, CA migration (S06 resolves) |
| Vendor change in S16 (e.g. WAF Imperva to Cloudflare, firewall SonicWall to FortiGate) | A competitive switch just happened. Renewal timing becomes estimable |
| Footprint growth (count of services per account) | Expansion; budget event |

Recommended snapshot cadence for testing: weekly. Key on SNI. Exclude empty
banners from both sides, otherwise CDN all-port behavior produces spurious
new and closed events.
