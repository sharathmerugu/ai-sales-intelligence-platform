# Data Scientist Handoff — Firmable cybersecurity sales intelligence

Code at `22e22b2`. **[F]** measured fact, **[H]** heuristic, **[U]** untested hypothesis.

## 1. Project and dataset

Goal: rank companies for B2B cybersecurity sellers, every claim traceable to scan observations. Input: 137 GB Shodan-format NDJSON, **16,988,823 records from one crawl** (2026-11-07 10:24–15:06 UTC) [F]. Limits: one snapshot (no change or intent); 56.9% empty banners; two CDN orgs hold 56% of rows; 99.99% of `vulns` CVEs are `verified:false` [F]. Details: `docs/research-findings.md`, `docs/data-profile.md`.

## 2. Entities

**In the raw dataset** (one Shodan banner per line; coverage is % of records, from `docs/data-profile.md` §2) [F]:

| Entity | Raw fields | Coverage / volume |
|---|---|---|
| Banner (scanner response) | `_shodan.id`, `timestamp`, `hash`, `data` | 16,988,823; 43.1% non-empty |
| IP address | `ip_str`, `ipv6` | 4,187,088 IPv4 + 70,922 IPv6 |
| Port endpoint | `port`, `transport` | 13,967,293 `ip:port:transport` keys; 92.5% tcp |
| Scan probe | `_shodan.module`, `_shodan.options.hostname` (requested SNI) | 100% / 5.6% |
| Network registrant | `org`, `isp`, `asn` | 83,167 orgs, 38,527 ISPs, 40,138 ASNs |
| DNS names | `hostnames[]`, `domains[]` | 75.8%; ~80% of those are provider PTR names |
| Location / cloud | `location.*`, `cloud.{provider,region,service}` | >99.9% / 32.5%; CDN geolocation unreliable |
| Product fingerprint | `product`, `version`, `cpe23[]`, `os`, `devicetype` | 13.4%, 4.6%, 22.8%, 3.7%, 0.2% |
| Scanner tags | `tags[]` (cdn, honeypot, self-signed, database, devops, …) | 80.0% |
| HTTP response | `http.{status,title,host,server,waf,headers,components,securitytxt}` | 28.2%; `waf` on 52% of HTTP |
| TLS certificate | `ssl.{versions,cipher,cert{subject,issuer,expired,sig_alg,pubkey},trust}` | 7.7%; `trust` null on 89% |
| SSH / IKE | `ssh.*`, `isakmp.*` | 0.8% / 7.3% |
| NTLM identity | `ntlm.{dns_domain_name,fqdn,netbios_*}` | 15,701 rows; restricted (ADR 0007) |
| Protocol objects | `fortinet`, `hp_ilo`, `mysql`, `vnc`, `snmp`, … | each <0.2% |
| Inferred CVEs | `vulns{CVE:{verified,cvss,kev}}` | 2.5% of records; 99.99% unverified |

**Derived by us**:

| Entity | Definition |
|---|---|
| Observation | Normalized banner, with provenance (`file_id`, `byte_offset`, `byte_length`, `record_sha256`) |
| Service | `(ip, port, transport, sni)`; latest eligible observation wins |
| Network type | ASN typed with pinned OpenASN `v2026.10.18` (ADR 0008) |
| Domain | Registrable domain from cert CN/SAN, SNI, HTTP Host, hostnames, NTLM |
| Attribution | Service to owner: tier A1/A2 (business org), P (network provider's own), B (customer domain), C (abstain) |
| Signal | A rule matched on a service (`signal_hits`) |
| Account | `org:` (A1/A2), `net:` (P), `dom:` (B). Org and domain accounts are **not merged** |

Relationships: an IP has many endpoints; an endpoint has one service per SNI; a service has many observations and one attribution; an account has many services; a service has 0–6 signals.

## 3. Pipeline and counts [F]

16,988,823 rows (0 quarantined, 451 repaired) → flags: 9,668,102 empty, 196,309 honeypot, 65,706 fingerprint-soup decoys (flagged, never deleted) → 7,100,193 eligible → **5,233,493 services** (1,648,005 `is_cdn`) → 1,836,092 signal hits → attribution v4: A1 258,258 · A2 154,569 · P 45,690 · B 1,126,121 · **C 3,648,855 (69.7%)** → **180,444 accounts** (179,669 enterprise, 775 network-provider). Code: `src/firmable/{ingest,transform,signals,attribution,accounts}/`.

## 4. Feature lineage

| Raw fields (normalized name) | Signal / feature | Account aggregation | Score contribution |
|---|---|---|---|
| `product`, `http.title`, `protocol_json.fortinet.model`, `transport`, `tags:cdn` | **S01** VPN/firewall portal: vendor regex on product or title, or protocol object; TCP, non-CDN, parked titles excluded | distinct counted signal; IPs | w=0.80; basis product/protocol 1.0, title 0.7 |
| `_shodan.module`, `data` head (`banner_head`), `product` | **S03** RDP/VNC/Telnet/WinRM: module in set AND not answered by HTTP/SSH/other daemon (`foreign_answer`) | same | w=0.70; protocol 1.0 |
| `product`, `module`, `protocol_json` keys, `tags:database` | **S04** DB/object store; tag ignored on generic web servers | same | w=0.65; tag 0.5 |
| `product` + `http_title`, `tags:devops` | **S05** management plane (word-bounded regex) | same | w=0.55 |
| `ssl.versions` (exact membership), `cert_expired`, `cert_key_type/bits`, `cert_sig_alg`, `tags:self-signed` | **S06** TLS hygiene; `sub_flags` list; RDP self-signed excluded; `dsa`+256/384 = ECDSA | same | w=0.20; tls 0.9 |
| `http.waf`, `product` | **S16** WAF/appliance vendor (CDN rows allowed) | same | w=0.25; waf 0.9 |
| `org`, `isp`, `asn`+OpenASN, cert, SNI, Host, hostnames, NTLM | tier + confidence (A1 0.9, A2 0.85, P 0.8, B = domain-rule score 0.25–1.0 × 0.85 if 2–3 domains, × 0.6 if ≥4) | mean per counted service | multiplier A |
| `ip` | distinct IPs with counted evidence | count | breadth S |

**Correlated signals** [H]: per service only the highest-weight exposure counts. Appliance-only S16 is suppressed when the service is also S01. Noisy-OR saturates, and means are per service, not per row. **Missing values**: NULLs coalesce to false or empty and never trigger a rule. A missing fingerprint never implies a missing control. Tier C contributes nothing, and exposures on weak tier B are blocked (`allows_infra_signals`).

## 5. Signals

S01, S03, S04 and S05 are exposures. S06 is hygiene. S16 is technographic and makes no security claim. Hits: S01 26,847; S03 24,983; S04 9,863; S05 34,822; S06 217,167; S16 1,522,410, all within 5% of research counts [F]. Fixed false positives: module-only hits, "Consulting" matching consul, parked pages, `-TLSv1` (disabled) and decoy products. Not implemented: S02, S07–S15 (incl. EOL, KEV-inferred, NTLM, OT), S17 and compounds C1–C6 (`docs/signal-catalog.md`).

## 6. Scoring (`src/firmable/accounts/scoring.py`, v2, ADR 0006)

```
score = 100 × R × S × A × Q
R = 1 − Π_s (1 − w_s)              over distinct counted signals
S = 0.5 + 0.5·min(1, log2(n_ips)/4) (1 IP 0.5, 16+ IPs 1.0)
A = mean attribution confidence; Q = mean best basis quality (per counted service)
```

Ranking is per segment: score desc, counted IPs desc, `account_id`. By design, S06+S16 alone max 35.9, below one product-matched S01 on one A1 IP (36.0) [F]. **All weights, qualities, tier confidences, the 16-IP saturation and multiplicative independence are [U]**, unfitted because no outcomes exist. The score is a relative priority, not a probability.

## 7. Bias and confounding

| Bias | Status |
|---|---|
| Scanner: fixed probe/port set, one crawl, module ≠ product | Partly mitigated (foreign-answer guard); coverage unknown |
| CDN/ISP: edges dominate; ISPs and hosters look like businesses | Mitigated: `is_cdn` gate, OpenASN, P segment. Residue in top 40 (telcos, pool labels, data centres) |
| Company size: breadth rewards large owned IP space; universities and governments over-represented | **Unresolved**; no normalization by footprint |
| Attribution: own-ASN orgs reach A1 (0.9); cloud-hosted firms only reach B (≤0.85, often 0.25–0.6) | **Unresolved**; cloud-native firms are systematically down-ranked |
| Missing-not-at-random: 69.7% abstain; versions rarely visible on edge devices | Abstention is explicit; impact on ranking unmeasured |
| Correlation: one device, several signals | Mitigated (suppression, noisy-OR); cross-service correlation unmodeled |
| Selection: review strata mostly top-k | **Unresolved**; recall unmeasurable |
| Duplicate entities: `org:` / `dom:` for one company | **Unresolved** |

## 8. Ground truth

| Level | What we have | Missing |
|---|---|---|
| Service detected | Raw bytes re-read by offset, SHA-256 matched; 421/421 sampled records show the claimed fact (automated checker) [F] | Human check |
| Vulnerability confirmed | Nothing; no active testing; CVEs inferred | All |
| Correct company | Heuristic ownership verdicts on the top 40: 23 corroborated, 2 reverse-DNS only, 4 registry only, 6 weak, 5 contradicted [H] | Human labels; Firmable company/domain index |
| Buying intent | Nothing | Outcomes, CRM conversion, firmographics |

## 9. Evaluation and open questions

- Tests: 554 non-slow tests passed; 18 Playwright tests passed on the deployed app [F].
- Review set: 104 stratified cases, seed 20261110 (`docs/evaluation.md`, `src/firmable/evaluation/`). **Human labels: 0/104**, so no precision figure exists.
- AI-suggested P@20 of 0.35 to 0.80 (baseline to enriched) is **not validation**. Results: `docs/phase3-hardening-results.md`.

**Top five questions**

1. What sampling and sample size should the labeling use (strata beyond top-k, inter-rater agreement, CIs on P@k) to estimate precision and recall honestly?
2. Is a product of means the right functional form? Or should attribution gate rather than multiply, and how should weights be set before outcomes exist (expert pairwise elicitation, then learning-to-rank)?
3. Should exposure be normalized by observed footprint (rate vs count) to remove size bias?
4. How should we correct the cloud-hosted attribution penalty and the 69.7% missing-not-at-random abstention?
5. Which proxy outcomes (CRM conversions, breach or advisory feeds, a second snapshot) would best link signals to buying intent?
