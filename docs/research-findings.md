# Research Findings — cybersecurity buying signals in Firmable scan data

Status: research complete for review. No scoring engine and no UI.
Companion docs:

- `data-profile.md` — fields, coverage, distributions
- `signal-catalog.md` — 17 signals and 6 compounds
- `company-attribution.md` — resolving observations to accounts
- `../sql/exploration.sql` — every query behind every number

## 1. What was done

1. **Inspected both repo samples with DuckDB.**
   - Inventoried keys and nested paths with their JSON types.
   - Found that `sample.jsonl` is the first 5,000 lines of the file and is
     not representative.
2. **Built a seeded 20k random-offset sample** in scratch space to check
   representativeness. It matched the distributed sample and, later, the
   full file within about 1 point.
3. **Streamed the full 137 GB file once** with typed `read_json` into a
   selected-fields Parquet.
   - About 2 minutes on a laptop, with memory capped at 6–8 GB.
   - Kept outside the repo.
   - Contains no raw banners, HTML, favicons or CVE text. It is a derived
     index for research.
4. **Profiled the population** (§3) and identified the noise classes that
   dominate the data (§4).
5. **Defined 17 signals** grounded in fields that exist, plus 6 compounds.
   Measured prevalence by attribution tier and pulled real examples and
   counterexamples.
6. **Ran `sql/exploration.sql` end-to-end** on the full file: 6.5 minutes,
   exit 0. Numbers in the docs come from that run.

Nothing was sent to external APIs. No records were invented. Example IPs in
the docs are masked to /24.

## 2. Headline findings

1. **The file is one crawl, not a history.**
   - 16,988,823 records from 2026-11-07 10:24–15:06 UTC; 99.2% fall in
     75 minutes.
   - Repeated `(ip, port, SNI)` probes are minutes apart and change <1% of
     the time.
   - **No change-over-time signal can be derived yet.** It needs periodic
     snapshots; a diff template is in SQL Q7.3.
2. **Most rows are not evidence of anything.**
   - 56.9% have an empty banner: a port answered but nothing was
     identified.
   - Two orgs, Incapsula and Google, hold 56% of rows, 84–98% of them empty.
   - Some enterprise BYOIP ranges on Google behave the same way. Wal-Mart's
     20,533 rows are 100% empty across random ports.
   - **A "port open" signal would mostly be measuring CDN behavior.**
3. **The scanner's own labels need guarding.**
   - `_shodan.module` names the probe, not the finding. "RAT" probes mostly
     return nginx 400 pages, and 36,946 of 39,103 DICOM probes hit CDN
     edges.
   - Honeypots (196k rows) and a newly identified **fingerprint-soup decoy**
     class (65,706 rows; ~147 KB pages matching 14–20 unrelated CPEs; only
     half honeypot-tagged) generate fake products and **28,938 fake KEV
     hits**.
4. **`vulns` is inference, not verification.**
   - 99.99% of CVE entries are `verified:false`.
   - KEV flags often appear without a version (73,616 rows).
   - Mean 52 CVEs per flagged record.
   - Usable only as "the version string falls in an affected range," and
     best as a timing trigger alongside external advisories.
5. **Attribution is the binding constraint, more than detection.**
   - Of 5.23M signal-eligible services:
     - 11.9% sit on non-provider orgs (A1)
     - 2.8% are owned ranges inside providers (A2)
     - 22.3% are provider IPs naming a customer domain (B)
     - **63.0% are unattributable (C)**
   - Tier A1 is further polluted by ISPs that the name heuristic misses.
6. **High-value, well-grounded signals exist but are small:**
   - S01 remote-access gateways: 8,285 owned services across 3,393 orgs.
   - S03 RDP/VNC/Telnet/WinRM: 5,745 owned.
   - S10 NTLM AD-domain disclosure: the strongest attribution and identity
     signal, 1,284 observations with real dotted domains.
   - S11 OT/ICS/medical: 6,283 owned, but heavy ISP contamination.
   - S05 management planes: 7,680 owned.
7. **Hygiene signals are plentiful but weak alone:**
   - S06 TLS: 217k
   - S07 EOL: 138k, mostly nginx branch EOL
   - S08 KEV-inferred: 141k
   - S09 no-WAF: 92k

   They work as amplifiers in compounds, e.g. C3: management plane plus TLS
   debt, 2,180 owned accounts.
8. **Technographics (S16) is the safest commercial use.**
   - 1.52M services expose a WAF/CDN/appliance vendor.
   - Tier-B domain evidence makes CDN customers visible: 107,588 domains.
   - No security claim is made, so the risk of misleading outreach is
     lowest.
9. **Compound edges are rarer than account co-occurrence suggests.**
   - 1,131 owned accounts have S01 plus an EOL/KEV signal somewhere.
   - Only **30 IPs** have both on the same port, because edge appliances
     rarely expose a version.
   - The aging-perimeter story therefore needs an external advisory feed
     joined to vendor footprint, not CVE inference.

## 3. Facts vs inferences vs hypotheses

| Statement type | Allowed wording | Examples from this research |
|---|---|---|
| **Directly observed fact** | "On 2026-11-07 14:52 UTC, x.x.x.x:3389 returned RDP with NTLM domain `<internal-domain>`." | Banner/protocol response, product fingerprint, HTTP title, TLS version list, certificate dates, tags, NTLM fields, `org`/`isp` strings |
| **Inferred security risk** | "An interactive login surface is internet-reachable; this exposure class is commonly targeted." | Exposure of remote access, management planes, databases, OT; TLS/EOL hygiene debt; version-range CVE applicability |
| **Unverified hypothesis** | "This account *may* be evaluating ZTNA." Never presented as fact. | Buying intent, budget, vendor dissatisfaction, missing controls (MFA, PAM, segmentation), actual exploitability, compromise |
| **Not claimable from this data** | — | "Vulnerable to CVE-X", "authentication bypass", "unauthenticated", "breached", "intends to buy", anything from a port number alone |

## 4. Data-quality and method findings worth keeping

| Finding | Impact | Handling |
|---|---|---|
| 451 malformed lines (bad surrogates) | negligible | `ignore_errors`, drop `ts IS NULL` |
| `head`-style samples are time- and protocol-biased | wrong priors | use random offsets or a full pass |
| `(ip,port)` repeats are SNI vhost probes | inflated counts | key services on `(ip, port, transport, SNI)` |
| `ssl.versions` uses `-TLSv1` for *disabled* | false TLS 1.0 hits if substring-matched | exact list membership |
| `pubkey.type='dsa'` for ECDSA | wrong weak-crypto hits | treat `dsa`+256/384 as ECDSA |
| `trust.browser` null on 89% of TLS rows | "untrusted" over-claimed | treat null as unknown |
| RDP certificates are self-signed by design | noise in S06 | exclude RDP from self-signed rule |
| WAF block pages ("Request Rejected") lack `http.waf` | false "no WAF" (S09) | exclude block-page titles |
| `list_contains(NULL, …)` is NULL in DuckDB | silently dropped 20% of rows in a draft run | `coalesce(..., false)` everywhere |
| `->` vs `IS NOT NULL` precedence, new lambda syntax | query errors | documented in SQL header |

## 5. Implications for the scoring-engine design

Recommendations for review, not decisions.

1. **Score at the service level, then roll up.**
   - Key is `(ip, port, transport, SNI)`, latest observation.
   - Roll up to the account with tier-aware weights.
   - Never let tier-C services contribute to an account.
2. **Gate before scoring.**
   - Require a non-empty banner, no honeypot tag, no decoy, and no CDN edge
     for exposure signals.
   - Treat module-only matches as non-evidence.
3. **Make attribution a first-class confidence term.**
   - Combine evidence source, source agreement and tenancy.
   - Keep it separate from security severity so reviewers can see why an
     account ranked.
4. **Use KEV and EOL as amplifiers and timing triggers, not as headlines.**
   - Pair vendor footprint (S01, S16) with an advisory feed.
   - Outreach language must stay at "the product family you expose had an
     advisory".
5. **Gate high-risk signals behind human review:** S12 (compromise), S10
   (internal names) and S11 (OT).
6. **Treat freshness as a property of each signal.**
   - The suggested TTLs (7–90 days) are hypotheses.
   - Measure them once two or more snapshots exist.

## 6. Open questions for review

1. **Labels.** Can Firmable provide labeled accounts (won/lost/no-op) or a
   curated ASN-type table? Precision and recall of tiers and signals are
   currently **unmeasured**.
2. **Snapshots.** Will periodic snapshots be available? Cadence matters for
   change signals and for validating TTLs.
3. **Domain index.** Is Firmable's company domain/brand index available for
   joining? Tier-B attribution depends on it.
4. **Policy.** What is the policy on using NTLM-derived names and compromise
   tags in sales workflows?
5. **Scope.** Should hosting/MSP/telco orgs be modeled as accounts
   themselves (they buy security too), or always excluded as infrastructure?
6. **Extraction.** Should the extraction add `http.components`
   (Wappalyzer-style tech list with categories), `ssl` SAN names (raw DER
   today), `isakmp.aggressive` and protocol objects (`hp_ilo`, `fortinet`,
   `mikrotik_routeros.version`)? Each would sharpen existing signals.

## 7. Reproduce

```bash
mkdir -p ~/firmable-work
duckdb ~/firmable-work/research.duckdb \
  -c "SET VARIABLE sample='sample.jsonl';" \
  -c "SET VARIABLE dist='distributed_sample.jsonl';" \
  -c "SET VARIABLE dataset='$HOME/Downloads/firmable_dataset';" \
  -c "SET VARIABLE slim='$HOME/firmable-work/full_slim.parquet';" \
  -c ".read sql/exploration.sql"
```

- DuckDB v2.0.0.
- About 6.5 minutes wall time, 12 cores, <8 GB RAM.
- About 0.9 GB Parquet plus a work DB, both outside the repo.
- To iterate cheaply, point `dataset` at `distributed_sample.jsonl`.
