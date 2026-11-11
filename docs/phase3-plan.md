# Phase 3 Plan — signals, attribution, accounts, ranking, API

Started 2026-11-09. Amended 2026-11-10 for attribution v2 (NTLM, ADR 0007) and v4 / scoring v2 (network type, segments, ADR 0008). Input: sealed snapshot `2026-11-07`,
`services.parquet` (5,233,493 rows, services v1). The 137 GB source is not
reread. Contracts below are fixed so the workstreams can run in parallel;
change them only by editing this file first.

## Milestones (each one tested and committed)

| # | Milestone | Owner module | Acceptance |
|---|---|---|---|
| M1 | Signal registry + `signal_hits` layer for S01, S03, S04, S05, S06, S16 | `firmable.signals` | Synthetic positives and the catalog counterexamples pass; full-data per-signal counts compared with the research prevalence table and every delta explained |
| M2 | Attribution v1: per-source evidence + service attribution with abstention | `firmable.attribution` | PSL domains; vendor-default / PTR / dyn-DNS / infra names rejected; ISP orgs not A1; multi-domain records abstain or block infra signals; no evidence crosses services; tier counts on full data compared with research |
| M3 | Account roll-up + deterministic score v1 | `firmable.accounts` | Stable account ids; correlated signals on one service counted once; four separate score components; hand-worked scores match |
| M4 | Serving DB + API | `firmable.api` | Ranked list, search, filters, account detail, evidence with provenance and §3 wording; FastAPI TestClient tests |
| M5 | End-to-end full-data run + docs | CLI | `firmable build-phase3 2026-11-07` produces all layers and the serving DB; measured timings and counts recorded in `docs/phase3-results.md` |

Hosted app and evaluation follow M5.

## Seams under test

1. `firmable.signals.evaluate(con, services_relation)` / `build_signal_hits(services_parquet, out_parquet)` — synthetic service rows in, signal rows out.
2. `firmable.attribution.names` pure functions: `registrable_domain`, `name_outcome`; `firmable.attribution.providers.classify_org`.
3. `firmable.attribution.build_attribution(services_parquet, out_dir, ...)` — synthetic services in, evidence + service attribution out.
4. `firmable.accounts.build_accounts(signal_hits, service_attribution, out_dir)` and pure `score_account(...)`.
5. HTTP API via `fastapi.testclient.TestClient` over a serving DB built from fixture tables.

Tests build services rows with `tests/service_rows.py` (`service_row`, `write_services`), which writes the exact production services schema.

## Layer paths

All under `~/firmable-work/lake/`, mirroring the services convention, read with `hive_partitioning = false`:

```
signal_hits/signals=v1/normalizer=v1/snapshot=S/signal_hits.parquet
attribution/attribution=v1/normalizer=v1/snapshot=S/evidence.parquet
attribution/attribution=v1/normalizer=v1/snapshot=S/service_attribution.parquet
accounts/scoring=v1/normalizer=v1/snapshot=S/{accounts,account_signals,account_evidence}.parquet
~/firmable-work/serving/S.duckdb     (read-only DB for the API)
```

Writes go to a temp name and are published by `os.replace`. Layers never write into earlier layers.

## Contract: `signal_hits` (one row per signal_id × service_id)

| Column | Type | Notes |
|---|---|---|
| snapshot_id, signal_id, signal_version, family | VARCHAR, VARCHAR, INTEGER, VARCHAR | family ∈ `exposure` (S01 S03 S04 S05), `hygiene` (S06), `technographic` (S16) |
| service_id, observation_id | VARCHAR | |
| file_id, byte_offset, byte_length, record_sha256 | provenance | copied from services |
| ip, port, transport, sni, observed_at, is_cdn, country_code | | |
| product, version, http_title, module | VARCHAR | scanner-asserted values shown as evidence |
| match_basis | VARCHAR | strongest clause that matched: `product` > `protocol` > `title` > `tag` (S06: `tls`; S16: `waf` or `product`) |
| detail | VARCHAR | short human label: vendor / protocol / datastore / plane, e.g. `SonicWall`, `RDP`, `MySQL`, `Grafana`, `Cloudflare` |
| sub_flags | VARCHAR[] | S06: subset of `cert_expired, legacy_tls, ssl_v2_v3, weak_rsa_key, weak_signature, self_signed_http`; S16: `waf` / `appliance`; others `[]` |
| evidence_json | VARCHAR | JSON of the field values that matched |

The registry entry per signal holds id, version, name, family, SQL predicate, detail expression, `observed_fact_template`, `inferred_risk`, `hypothesis` (wording per `research-findings.md` §3) and `infra_exposure` (True for S01/S03/S04/S05).

## Contract: attribution

`evidence.parquet` — one row per (service, source, name):
`snapshot_id, service_id, source, raw_name, name, reg_domain, outcome, attribution_version`.
source ∈ `ntlm, cert_cn, cert_san, sni, http_host, hostname`. outcome ∈ `accepted, ptr_like, non_company, infra_domain, provider_cert, no_registrable_domain, ip_literal, invalid`.

`service_attribution.parquet` — one row per service:

| Column | Type | Notes |
|---|---|---|
| snapshot_id, service_id, attribution_version | | |
| tier | VARCHAR | `A1` owned / `A2` owned in provider space / `P` network provider's own infrastructure (v4, ADR 0008) / `B` tenant on provider IP named by its own record / `C` abstain |
| account_id | VARCHAR NULL | `org:<norm_org>` (A1/A2), `net:<norm_org>` (P) or `dom:<registrable domain>` (B); NULL for C. Stable across snapshots |
| account_name | VARCHAR NULL | raw org string or registrable domain |
| confidence | DOUBLE | 0–1, 0 for C |
| confidence_band | VARCHAR | `high`, `medium`, `low`, `none` |
| reasons | VARCHAR[] | machine codes, e.g. `org_not_provider`, `org_isp`, `byoip_in_provider`, `dom_ntlm`, `dom_cert_sni_agree`, `dom_hostname_only`, `shared_hosting`, `abstain_no_customer_evidence`, `abstain_ambiguous_domains` |
| candidate_domains | VARCHAR[] | accepted registrable domains from this service's own record, sorted |
| allows_infra_signals | BOOLEAN | A1/A2 true; B only with one candidate domain and strong evidence (NTLM, or cert CN/SAN agreeing with SNI); C false |
| org, isp, org_class | VARCHAR | org_class ∈ `business`, `cloud_hosting`, `cdn`, `isp_telco`, `saas_platform`, `unknown` |

Rules: evidence comes only from the service's own record (never from another vhost on the same IP); a domain is chosen only when it wins on evidence strength, ties abstain; never `customer_domains[1]`.

## Contract: accounts

`accounts.parquet`: `account_id, account_name, account_kind (org|domain), segment (enterprise|network_provider; scoring v2), best_tier, n_services, n_ips, signal_ids VARCHAR[], details VARCHAR[], countries VARCHAR[], product_relevance, signal_strength, attribution_confidence, evidence_quality, score (0–100), rank, explanation VARCHAR[], scoring_version`.

**Scoring v3 (2026-11-11, ADR 0009, `docs/ranking-v3.md`)** replaces `score` with `opportunity_priority, priority_percentile, priority_band, rank` (eligible accounts only), adds `top_signals, eligibility, eligibility_reasons, ownership_confidence, ownership_reasons, review_flags, ownership_services, named_public_services, named_rdns_services, third_party_domains, network_operators, subscriber_rdns_services, evidence_quality_band, actionable, actionable_blockers, legacy_score, legacy_rank, legacy_scoring_version, eligibility_version`. The v1/v2 contract above is kept for the legacy tables.

`account_signals.parquet`: `account_id, signal_id, family, n_services, n_ips, n_counted_services, details VARCHAR[], sub_flags VARCHAR[], max_attribution_confidence, contribution`.

`account_evidence.parquet`: one row per (account, signal, service): service and provenance columns from `signal_hits`, plus `tier, attribution_confidence, attribution_reasons, counted BOOLEAN, suppressed_by VARCHAR, attribution_version INTEGER, attribution_domains VARCHAR[]` (counted is false when suppressed as a correlated duplicate on the same service; suppressed_by names the signal that took precedence).

Score is a relative priority, **not** a purchase probability.

### Roll-up rules v1 (`firmable.accounts.rollup`)

- Tier C (account_id NULL) contributes to no account.
- Exposure-family hits (S01 S03 S04 S05) attach only where `allows_infra_signals`; blocked rows are counted in the build result.
- Correlation on one service: only the highest-relevance exposure signal counts (MinIO = S04, not S04 + S05); an S16 `appliance`-only hit on a service that is also S01 does not count. Suppressed hits stay as evidence.
- Rank: score desc, then distinct counted IPs desc, then account_id asc. Scoring v2 ranks each segment separately (`net:` accounts are `network_provider`, the rest `enterprise`).

### Scoring v1 (`firmable.accounts.scoring`)

`score = 100 x product_relevance x signal_strength x attribution_confidence x evidence_quality`

| Component | Definition (over counted evidence) |
|---|---|
| product_relevance | noisy-OR of signal weights: S01 0.80, S03 0.70, S04 0.65, S05 0.55, S06 0.20, S16 0.25 (hygiene/technographics alone can never outrank one product-identified exposure at equal attribution) |
| signal_strength | `0.5 + 0.5 * min(1, log2(distinct IPs) / 4)` (1 IP 0.5, 4 IPs 0.75, 16+ IPs 1.0) |
| attribution_confidence | mean attribution confidence per counted service |
| evidence_quality | mean per counted service of its best match-basis quality: product/protocol 1.0, tls/waf 0.9, title 0.7, tag 0.5 |

All weights are hypotheses for a general cybersecurity seller; no labels exist to fit them.

## API (FastAPI, embedded DuckDB, read-only)

- `GET /health`
- `GET /signals` — registry with fact / risk / hypothesis wording
- `GET /accounts?segment=&view=&q=&signal=&tier=&band=&ownership=&country=&min_priority=&limit=&offset=` — ranked, searchable; `segment` defaults to `enterprise`, `view` to `actionable` (scoring v3; `min_score` before v3)
- `GET /accounts/{account_id}` — components, explanation, per-signal summary
- `GET /accounts/{account_id}/evidence?signal=&limit=&offset=` — evidence rows with provenance
