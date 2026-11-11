# Phase 3 hardening results — NTLM policy, network classification, deployment, evaluation

Measured 2026-11-10 on snapshot `2026-11-07` (sealed; 5,233,493 services; the 137 GB source was
not reread), i7-9750H, 16 GiB. Decisions: ADR 0007 (NTLM, public DB), ADR 0008 (OpenASN,
segments). Details: `docs/network-classification.md`, `docs/deployment.md`, `docs/evaluation.md`.

## Commands

```bash
uv run pytest -m "not slow"                                        # 554 passed, 1 deselected (~40 s)
uv run firmable build-phase3 2026-11-07 --steps attribution accounts serving --memory-limit 6GB --threads 6
uv run firmable publish-public 2026-11-07
scripts/stage_deploy.sh 2026-11-07
uv run firmable review-set 2026-11-07
uv run firmable review-metrics ~/firmable-work/eval/2026-11-07-review.csv [--source suggested]
uv run firmable inspect-accounts 2026-11-07 --top 40                # re-read source records per account
cd e2e && FIRMABLE_URL=https://firmable-api-production.up.railway.app FIRMABLE_USER=reviewer \
  FIRMABLE_PASSWORD=... npx playwright test                         # 18 passed
```

## NTLM policy (attribution v2, kept in v4)

- NTLM-only services now abstain: 87 services in v2, 95 in v4 (`abstain_ntlm_uncorroborated`).
  Accounts went from 180,136 to 180,103 under v2.
- Since the review, NTLM corroborates only a certificate, SNI or Host. Reverse DNS no longer
  counts, and the public DB rewords the reason code (`dom_multi_source_corroborated`).
- Full-data scan of the public DB against all 12,764 distinct NTLM DNS domain, FQDN and NetBIOS
  values: no value copied from an NTLM field. The only equal strings are generic words in HTTP
  titles (`server`, `admin`, …) and public domains that are also AD domains. Every domain account
  has public evidence by construction.
- Live crawl of 80 deployed accounts (5,219 evidence rows): no `ntlm` substring, no raw file
  coordinates.
- Note: RDP certificates often carry the machine's FQDN (`ADSRV-01.corp.<company>`). The API
  does not serve certificate CNs; only the registrable domain appears.

## Network classification (attribution v4, scoring v2)

| | Baseline (attr v2, scoring v1) | Enriched (attr v4, scoring v2) |
|---|---|---|
| A1 / A2 services | 405,742 / 139,700 | 258,258 / 154,569 |
| P services (network providers' own) | — | 45,690 |
| B / C services | 1,108,887 / 3,579,164 | 1,126,121 / 3,648,855 |
| Accounts | 180,103 | 180,444 (enterprise 179,669; network provider 775) |
| Enterprise org accounts A1 / A2 | 18,563 org accounts in total | 7,380 / 7,694 |

- OpenASN covers 39,024 of the snapshot's ASNs (99.99% of services). 17,719 ASNs are network
  providers under the rules; 9,294 business-named orgs were reclassified as operators of
  provider ASNs.
- Build: attribution + accounts + serving 250 s wall, 6.3 GB peak RSS (infra domains
  recomputed for the new layer).
- Top 40 enterprise accounts after: mostly universities, government bodies and named companies
  (names withheld in the public copy). Residue:
  telcos OpenASN files as `business` (AMERICATEL PERU, Completel), pool or customer labels on ISP
  space ("Leased Line- LAN Range", "Leased Line Customer LAN", "Cellucar subscribers for GGSN",
  "B2B"), data centres (Oman Data Park, EG Veri Merkezi) and a co-op/municipal ISP (Blue Ridge
  Mountain EMC, Spanish Fork City).
- Network-provider top 10: Amazon entities, Swisscom, Telia, Vodafone, Colt, Telstra,
  Cegedim.Cloud, CenturyLink. Only served when `segment=network_provider` is selected.

## Evaluation

Review set: 104 cases, seed 20261110:

| Stratum | Cases |
|---|---|
| baseline top 40 | 40 |
| enriched top 40 | 40 |
| network-provider top 10 | 10 |
| tier-B sample | 10 |
| ASN-reclassified sample | 10 |
| abstention sample | 10 |

Strata overlap, so the 120 stratum slots resolve to 104 cases. The CSV is in
`~/firmable-work/eval/`, outside Git, because it holds real names and IPs.

**Manual labels: 0 of 104.** No reviewed metric exists yet. `review-metrics` reports `null`
for every rate until a person fills the `manual_*` columns.

Model suggestions (`suggested_by = claude-opus-5-5`) are below for orientation only. They are
**not labels and not results**. They come from public knowledge of the named networks and the
row context, without checking evidence rows (evidence support is left blank):

| Provisional, model-suggested | Baseline | Enriched |
|---|---|---|
| Precision@20 (qualified enterprise) | 7/20 = 0.35 | 16/20 = 0.80 |
| Precision@40 | 13/40 = 0.33 | 27/40 = 0.68 |
| ASN-reclassified cases suggested as network providers | | 10/10 |
| Attribution suggested correct, enriched accounts | | 43/69 = 0.62 |
| Abstentions suggested correct | | 10/10 |

The decision to integrate OpenASN rests on full-data coverage, the known-example checks
(`docs/network-classification.md`) and these suggestions. The reviewed Precision@k is still
owed.

### Source-observation inspection

`firmable inspect-accounts` re-read every sampled record from the source file by offset; all
SHA-256 hashes matched. Runtime was 4.6 s for 320 records.

| Set | Accounts | Records | Signal shown in the raw record | Ownership verdicts (heuristic) |
|---|---|---|---|---|
| Enterprise top 40 | 40 | 320 | 320 / 320 | corroborated 23, reverse-DNS only 2, registry only 4, weak 6, contradicted 5 |
| Network-provider top 10 | 10 | 80 | 80 / 80 | corroborated 10 |
| Tier-B review sample | 10 | 21 | 21 / 21 | corroborated 10 |

- **Signals hold up at source.** Every sampled record shows the product, protocol or TLS fact its
  signal claims. The first pass flagged 5 records; all 5 were vendor-alias misses in the checker
  (Elastic, Fireware XTM, FortiWiFi, BigIP), not wrong signals.
- **Ownership is the weak point, in the expected places.**
  - *Contradicted*: a medical-area network consortium (records name member hospitals, not the
    consortium); a data-centre operator (hosted customers); a national state IT agency (reverse
    DNS in a shared government zone); two accounts whose records are subscriber lines in ISP
    reverse-DNS zones.
  - *Registry only* (no name in any record, only the IP registry's org): a utility cooperative,
    a large technology company, a university, and an ISP pool label.
  - *Weak*: a telco, ISP pool labels, a data centre, a software company, and a provincial
    government whose domain is an abbreviation the checker does not match.
- Universities named by acronym domains (MIT, RIT, UCSB, NTHU, USP) are corroborated by their
  own certificates and hostnames.
- These verdicts are heuristics for the reviewer, not labels. The worksheets are
  `~/firmable-work/eval/2026-11-07-inspect-*.md`.

## Deployment

- URL: <https://firmable-api-production.up.railway.app> (Basic auth; `/health` open).
- Image built by Railway from a private context (git HEAD + 137.6 MB public DB); runs without
  the dataset. A local container used 98 MB RSS.
- Live server-side latency (app logs, final deploy):

| Route | n | Median | p95 |
|---|---|---|---|
| `/accounts` | 25 | 12.3 ms | 22.9 ms |
| account detail | 4 | 7.2 ms | 7.7 ms |
| evidence | 14 | 14.6 ms | 18.9 ms |

  Round trip from the developer machine is about 0.4–0.5 s (network).
- Access checks, live:
  - without credentials: 401 on `/`, `/accounts`, `/signals`, `/docs`, `/openapi.json`;
  - every response carries `no-store`, `noindex`, `nosniff`, `DENY`;
  - global rate limit: 650 spoofed-header requests gave 600 × 200 and 50 × 429.
- Per-client limiting was tried and measured bypassable on Railway (headers and TCP peer); see
  `docs/deployment.md`.
- Playwright, 18 tests on desktop Chrome and a Pixel 7 profile:
  - ranked list, search, filters, segment switch, account detail with fact / risk / hypothesis,
    deep link, pagination;
  - auth, cache headers, no NTLM or raw offsets in evidence, segment validation.

## Code review

Two-axis review (Standards + Spec) of `25439b0..35a866c`. Fixed in `ffb9360` and later:

- tier P captured customer VPSes that carry the hoster's default certificate, and generic names
  prefix-matched (`Cloud Telecom` claimed `cloudflare.com`);
- the ASN operator rule needed a majority share;
- NTLM plus reverse DNS was decisive, and the public reason code revealed AD-domain equality;
- the rate limiter trusted headers and reset everyone on overflow;
- `review-set` skipped the OpenASN checksum, could overwrite manual labels and leaked its
  connection;
- attribution precision mixed builds;
- the image was not pinned by digest and the DB was writable;
- the e2e NTLM check was wrong;
- ADR 0008 was missing, contracts were stale, and links pointed to a missing results doc.

Not done:

- Railway CPU and memory caps are left at plan defaults (dashboard setting);
- `publish-public` scans column names and versions, not values; the full-data value scan above
  was run once by hand;
- baseline accounts (attribution v2) can only be rebuilt from commit `55d86b9`;
- duplicated SQL fragments and scattered segment strings remain.

## Known limitations

1. **No reviewed labels yet.** Precision@20/40, segment agreement, attribution precision,
   abstention and evidence support all need the `manual_*` columns filled.
2. **Residue in the enterprise top 40**: telcos filed as `business`, ISP pool labels on A2,
   data centres and municipal or co-op ISPs.
3. **Org and domain accounts are still separate** (`org:` / `net:` / `dom:` for one company).
4. **Rate limit is global**, in one process; one heavy client can exhaust it.
5. **One snapshot.** OpenASN is pinned to the release before the crawl; refreshing it is a
   deliberate rebuild.
6. **`railway.json` is deprecated** by Railway from 2026-12-01 (migrate to `.railway/railway.ts`).
