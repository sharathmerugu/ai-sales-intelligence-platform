# Phase 3 Results — signals, attribution, accounts, ranking, API

Measured 2026-11-09/10 on snapshot `2026-11-07` (sealed), i7-9750H 6C/12T,
16 GiB. Input: `services.parquet` (5,233,493 services). The 137 GB source was
not reread. Plan and contracts: `docs/phase3-plan.md`. Decisions: ADR
0004–0006. Per-layer detail: `docs/signals-implementation.md`,
`docs/attribution-implementation.md`, `docs/api.md`.

## Commands

```bash
uv run pytest -m "not slow"                                   # 447 passed, 1 deselected (~35 s)
uv run firmable build-phase3 2026-11-07 --memory-limit 6GB --threads 6
uv run firmable build-phase3 2026-11-07 --steps accounts serving   # after a scoring change
uv run firmable serve 2026-11-07 --port 8000                  # API + page at http://127.0.0.1:8000/
uv run python -m firmable.signals.reconcile --snapshot 2026-11-07  # signal counts vs research
```

`build-phase3` refuses an unsealed snapshot.

## Build measurements

| Step | Wall | Notes |
|---|---|---|
| signals | 7.4 s | 1,836,092 hits, 193 MB |
| attribution | 148–183 s | cached infra domains; 15.3 M evidence rows; peak 4.6 GB |
| accounts | 13.5 s | |
| serving DB | ~4 s | 143 MB DuckDB file |
| full `build-phase3` | 173 s, 6.1 GB peak RSS | first full run, before the attribution fix round |
| accounts + serving only | 17.9 s, 2.3 GB peak RSS | final run |

## Signals (vs research prevalence)

| Signal | Research | v1 | Main causes (all reconciled) |
|---|---|---|---|
| S01 | 26,700 | 26,847 | NULL-org rows the research join dropped; 451 recovered rows; +183 FortiGate via `protocol_json`; −47 parked titles |
| S03 | 26,114 | 24,983 | −1,096 module-only hits answered by HTTP/SSH/SOCKS; −35 whitespace banners |
| S04 | 9,930 | 9,863 | −68 DB-module hits answered by another protocol |
| S05 | 35,678 | 34,822 | −835 substring false positives ("Consulting" for consul) |
| S06 | 217,036 | 217,167 | NULL-org + recovered rows only |
| S16 | 1,522,317 | 1,522,410 | NULL-org + recovered rows; −4 SNI case merges |

## Attribution (final run)

| Tier | Services | Share | Research |
|---|---|---|---|
| A1 | 405,742 | 7.8% | 621,208 (11.9%) |
| A2 | 139,700 | 2.7% | 147,808 (2.8%) |
| B | 1,108,975 | 21.2% | 1,164,553 (22.3%) |
| C (abstain) | 3,579,076 | 68.4% | 3,299,100 (63.0%) |

A1 shrinks because ISPs, hosters and pool labels left owned tiers (curated
table + access-network reverse-DNS backstop). 204,305 tier-B services may
carry infrastructure signals (NTLM or certificate/SNI agreement on one domain).

## Accounts and ranking

- 180,136 accounts: 12,202 org A1, 6,361 org A2, 161,573 domain (B).
- 692,627 attributed signal rows; 14,846 exposure rows blocked by weak tier-B
  attribution; 677,781 evidence rows served (= 692,627 − 14,846).
- Highest score of an account with only S06/S16: 35.9 (one product-identified
  S01 on one IP at confidence 0.9 scores 36.0), as designed.
- Top 40 after the fix round: about half real organisations (McGill, SAP,
  Cerner, UC Davis, Utah, Clemson, USP, RIT, NTU, Baidu, Keio); the rest are
  ISPs, hosters and data centres the curated table still misses (Skyway West,
  Americatel Peru, Devoli, Claranet, Telx, Eastlink, RailTel, Dialog Axiata …).

## API (full serving DB, TestClient, median of 5)

| Request | Latency | Result |
|---|---|---|
| `GET /accounts?limit=50` | 17 ms | total 180,136 |
| `GET /accounts?q=university` | 32 ms | 582 |
| `GET /accounts?signal=S01&signal=S03&tier=A1&country=US` | 23 ms | 41 |
| `GET /accounts/{id}` | 8 ms | |
| `GET /accounts/{id}/evidence?signal=S01` | 20 ms | facts, risk and hypothesis separate; provenance tuple |

## Review

Two-axis review (Standards + Spec) of `22b5267..d972fe0`. Fixed: missing
`hive_partitioning = false`; claims not carrying `attribution_version` or the
accepted domains; per-row instead of per-service averaging; hygiene and
technographic breadth outranking a confirmed exposure; label duplication; no
`temp_directory`; no ADRs; ISPs in A1; dyn-DNS parents as accounts; doubled
"UTC" in facts. Not changed, by decision: platform operator domains
(`jamfcloud.com`, `mktoweb.com`) stay operator accounts, not tenant leaks;
S16 CDN/WAF on a tenant domain is the tenant's vendor choice.

## Known limitations

1. **ISP/hoster residue in A1.** About half of the top 40 is still access or
   hosting networks. Name lists and reverse-DNS features do not converge; a
   curated ASN-type reference table (e.g. CAIDA AS classification, PeeringDB
   network type) is the fix. Until then, treat org-account ranks as upper
   bounds and review before outreach.
2. **Org and domain accounts are not merged** (`org:adobe` and
   `dom:adobe.com`); `norm_org` can merge same-named companies across
   countries. Needs Firmable's company/domain index.
3. **NTLM-derived domains** can become tier-B account names. Only the
   registrable domain is shown, but policy review is pending (CLAUDE.md).
4. **No labels.** Signal precision, tier precision and score weights are
   unmeasured hypotheses. The score is a relative priority, not a purchase
   probability.
5. **One snapshot.** No change-over-time claims; infra-domain cache is reused
   without a fingerprint of the files it came from.
6. **Not hosted yet.** API and page run locally; no auth or rate limiting.

**Update 2026-11-10:** limitations 1, 3 and 6 are addressed by the hardening round (OpenASN
network classification and segments, NTLM policy, Railway deployment with auth and rate
limits). See `docs/phase3-hardening-results.md`.
