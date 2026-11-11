# Reviewer guide: labelling the scoring-v3 holdout

For people filling the `manual_*` columns of the scoring-v3 holdout. The rubric is defined in
`docs/evaluation.md` ("Label columns"). This guide says how to apply it. Allow 5–10 minutes per
case, so 155 cases take about two working days.

**Labels come from people only.** Do not paste a case into a chat model, accept model suggestions,
or copy a verdict from `inspect-accounts`, the app's band, ownership or flags. `holdout-metrics`
rejects a `manual_reviewer` that names a model, but that check can be bypassed: whether the labels
are honest is up to the reviewer.

## 1. Files and setup

| File | Use |
|---|---|
| `~/firmable-work/eval/2026-11-07-holdout-v3.blind.csv` | **Label this file.** It hides rank, band, segment, tier, development status and every other system output |
| `~/firmable-work/eval/2026-11-07-holdout-v3.csv` | Don't open it while labelling: it shows the system's decisions. Leave its `manual_*` columns blank |

Both files hold real company names, domains and IPs. Keep them in `~/firmable-work/eval/`, never in
Git, chat tools or shared drives.

- Fill only these columns: `manual_entity_type`, `manual_qualified`, `manual_attribution_correct`,
  `manual_evidence_supported`, `manual_reviewer` (your name or initials) and `manual_notes`.
- Edit the CSV in a spreadsheet tool, then export it as CSV. UTF-8 with or without a BOM is accepted.
  Don't reorder or delete rows, and don't edit any other column.
- Values are lower case, exactly as given: `enterprise`, `network_provider`, `yes`, `no`, `unclear`.
  Leave a cell blank if you didn't judge it. `unclear` counts against the system; a blank cell is
  left out of the denominator.

## 2. Sources, in order

1. The row itself: `account_name`, `signal_ids`, `details`, `signal_services`, `org`, `isp`, `asn`,
   `openasn_category`, `sample_naming_domains`, `sample_third_party_domains` and `sample_services`.
2. The raw records: run the row's `evidence_command` (`uv run firmable evidence OBS_ID`). It prints
   the exact source banner. **This output is restricted** because it can contain NTLM internal names
   (ADR 0007). Read it, but don't copy NTLM values into notes. The command needs the raw dataset
   and the ingestion manifest on the machine, so run it on the build machine.
3. Public sources: the organisation's website, Wikipedia, the registry (RDAP/whois), and the ASN's
   PeeringDB entry.
4. The deployed app's evidence rows, only if you need them. Each account page also shows a band,
   ownership and flags. **Don't let those decide your label.** To find the account, search for
   `account_name`.

## 3. The four labels

### `manual_entity_type`: what kind of organisation this is

| Value | When |
|---|---|
| `enterprise` | An end organisation that runs its own systems: company, university, hospital, government body, NGO |
| `network_provider` | An organisation whose IPs mostly carry other parties' systems: ISP, telco, hoster, VPS or cloud provider, data centre, CDN, IP lessor, registrar, managed-hosting reseller |
| `unclear` | You can't decide even after checking public sources, **or** the name is not a real organisation: a pool label, "Customer LAN", "Static IP block", a placeholder |

Edge cases:

- A telco or ISP is `network_provider`, even when its own corporate domain is the account.
- An IT outsourcer or managed-service provider that mostly hosts clients' systems is
  `network_provider`. If it runs mainly its own business systems, it is `enterprise`.
- A consortium or research network (a school cooperative, a state college board, a national
  research and education network) is `network_provider` when the records name member
  institutions, and `enterprise` when they name only the consortium.
- A SaaS company is `enterprise`, even if its customers' names show up on its hosts.

### `manual_qualified`: would a general cybersecurity seller prospect this?

Answer for the **enterprise segment**, from this evidence, as a seller of general security products
and services.

- `yes`: a real end organisation that you can identify, with at least one observation a seller
  could honestly raise in a first conversation, using the allowed wording (research-findings §3:
  observed fact, inferred risk, hypothesis).
- `no`: any one of these:
  - a network provider;
  - a pool or placeholder name;
  - the services don't belong to this organisation (a misattributed tenant);
  - the only evidence is technographic (S16 alone: "runs a WAF") with no security observation;
  - the organisation could not plausibly be a buyer (for example, it has closed down).
- `unclear`: a real organisation, but you can't tell whether these services are its own.

**Size, sector and country don't matter.** A small firm with a real exposure is `yes`.

Don't rate how serious the finding is. A scan observation is not a confirmed vulnerability, and
CVEs inferred from version strings are unverified. Qualification asks only whether the account is a
legitimate prospect on this evidence.

### `manual_attribution_correct`: do these services belong to the named entity?

Check the sample services (`sample_services`, `evidence_command`).

- `yes`: the evidence ties the services to the named entity. Examples:
  - a certificate, SNI, HTTP Host or hostname on the organisation's own domain;
  - an IP block registered to the organisation itself, not to its ISP;
  - the organisation's own reverse-DNS zone.
- `no`:
  - the services belong to someone else, such as a hoster's tenants, an ISP's subscribers, or
    another company's domain;
  - the "entity" is the ISP's label for a customer block.
- `unclear`: registry-only evidence with nothing to corroborate it, or mixed evidence.

Typical traps:

- reverse DNS in the ISP's zone (`…dynamic.isp.net`) names the ISP, not the customer;
- a wildcard or shared certificate, or a default appliance certificate, names nobody;
- `org` comes from the IP registry. It may name the ISP or a sub-allocation label, not the user.

For network-provider cases, ask whether the services belong to that provider's infrastructure.

### `manual_evidence_supported`: does a record show what the signal claims?

`yes` if **at least one** raw record (`evidence_command`) shows the claimed fact for at least one
listed signal:

| Signal | The record must show |
|---|---|
| S01 | a remote-access, SSL-VPN or firewall portal identified by product, title or certificate (for example a FortiGate, GlobalProtect or Pulse login page). A scanner module name alone is not enough |
| S03 | a remote-admin protocol handshake or banner: RDP, VNC, Telnet, WinRM or ScreenConnect |
| S04 | a database or object-store protocol response (for example MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, S3-compatible storage) |
| S05 | an infrastructure or DevOps management interface (for example a hypervisor, a container or CI console, a hosting control panel) |
| S06 | the named TLS fact in the certificate or handshake: expired, self-signed, key under 2048 bits, TLS 1.0 or 1.1 accepted |
| S16 | a security vendor (WAF, CDN security or appliance) named in headers, a product field or a certificate |

- `no`: the record shows something else. Examples: a generic web page tagged by the scanner module,
  a CDN edge rather than the organisation's server, or a TLS fact that doesn't match.
- `unclear`: the record is truncated or ambiguous.

An open port alone is not a vulnerability, and a missing fingerprint doesn't prove a control is
missing. Label only what the record shows.

## 4. Notes

Write one short sentence per case, saying what decided it. For example: "Own cert CN on
vpn.example.edu; FortiGate login page", or "ISP pool label, rDNS in ISP zone".

- Don't include IPs. If you need one, mask it to /24.
- Don't include NTLM names, credentials or compromise details.

## 5. Two reviewers (recommended)

If two people label, each works on **a separate copy** of the blind file, without talking about
cases. Agree on an overlap of at least 30 cases across strata. Compare the copies to measure
agreement (Cohen's kappa) before merging them. Settle disagreements by discussion, and record the
outcome in `manual_notes`. Then write the agreed labels into one blind file.

## 6. When done

```bash
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv \
    --labels ~/firmable-work/eval/2026-11-07-holdout-v3.blind.csv > ~/firmable-work/eval/holdout-metrics-v3.json
```

- Report every rate with its numerator, denominator and Wilson interval.
- Precision@20/40 is a census of development data. Report uncontaminated rates from
  `rank_401_2000` and the random strata (`docs/evaluation.md`, "Metrics").
- No result supports a claim about vulnerability accuracy or purchase probability.
