# API and salesperson page (Phase 3, M4)

`firmable.api` serves the accounts layer (`docs/phase3-plan.md`, "Contract: accounts") from one read-only DuckDB file, through a FastAPI app and a single static HTML page.

```
accounts/scoring=v1/.../{accounts,account_signals,account_evidence}.parquet
        + signal registry (firmable.signals)
            │  build_serving_db
            ▼
~/firmable-work/serving/<snapshot>.duckdb   (read-only)
            │  Store (one cursor per request)
            ▼
FastAPI: /health /signals /accounts /accounts/{id} /accounts/{id}/evidence  +  GET / (UI)
```

## Build the serving DB

```python
from firmable.api.store import build_serving_db
from firmable.signals.registry import SIGNALS  # the M1 registry

stats = build_serving_db(
    accounts_dir,          # directory holding the three accounts parquet files
    list(SIGNALS),         # registry entries: dicts or objects with id, version, name, family,
                           # observed_fact_template, inferred_risk, hypothesis, infra_exposure
    out_path,              # e.g. ~/firmable-work/serving/2026-11-07.duckdb
    snapshot_id=None,      # optional; inferred from account_evidence.snapshot_id when unique
)
# -> {"accounts": n, "account_signals": n, "account_evidence": n, "signal_registry": n,
#     "snapshot_id": ..., "path": ...}
```

- The three files are read with `hive_partitioning = false`. Only the contract columns are loaded. `evidence_json` is not loaded (see limitations).
- Tables: `accounts` (sorted by segment, rank with unranked last, priority, plus a lowercased `search_text` of name, id and details), `account_signals`, `account_evidence` (sorted by account and signal), `signal_registry`, `meta` (snapshot id, serving version, build time). ART indexes on `account_id`.
- The DB is written to `.<name>.tmp-<pid>` beside the output and published with `os.replace`. A failed build leaves no partial file.

## Run the server

```bash
FIRMABLE_SERVING_DB=~/firmable-work/serving/2026-11-07.duckdb uv run python -m firmable.api --host 0.0.0.0 --port 8000
# or
FIRMABLE_SERVING_DB=... uv run uvicorn firmable.api.app:app --host 0.0.0.0 --port 8000
```

`python -m firmable.api` also accepts `--db PATH`, and reads `HOST` and `PORT` from the environment. For tests or embedding, call `create_app(db_path)`. If no DB is given, the app raises `RuntimeError`; if the file is missing, it raises `FileNotFoundError`.

## Endpoints

All responses are JSON except `GET /`. `limit` defaults to 50; values outside 1–200, or a negative `offset`, return 422.

| Endpoint | Returns |
|---|---|
| `GET /` | The salesperson page (`src/firmable/api/static/index.html`) |
| `GET /health` | `{status, snapshot_id, n_accounts}` |
| `GET /signals` | `{labels, signals:[{id, version, name, family, observed_fact_template, inferred_risk, hypothesis, infra_exposure}]}` |
| `GET /accounts` | `{total, limit, offset, view, items:[account]}` in priority-rank order (scoring v3, `docs/ranking-v3.md`) |
| `GET /accounts/{account_id}` | account + `explanation`, `scoring_version`, `eligibility_version`, `signals` (per-signal summary with registry name, inferred risk, hypothesis), `labels`, `disclaimer`; 307 to the current id for an id from an older build (see below), else 404 |
| `GET /accounts/{account_id}/evidence` | `{account_id, total, limit, offset, labels, disclaimer, items:[evidence]}`; 307 for an older id, else 404 |

### `/accounts` filters

| Param | Meaning |
|---|---|
| `segment` | `enterprise` (default) or `network_provider` (a provider's own infrastructure, tier P). Ranks restart per segment; any other value is a 422. |
| `view` | `actionable` (default: the outreach list), `review` (eligible, not actionable), `excluded` (not a prospect: registry placeholders and pool labels), `all`. Excluded accounts have no rank and sort last. |
| `band` (repeatable) | `priority_band` is **any** of `High`, `Medium`, `Low` |
| `ownership` (repeatable) | `ownership_confidence` is **any** of `high`, `medium`, `low` |
| `q` | Case-insensitive literal substring of `account_name`, `account_id` or any `details` entry (max 200 characters). `%` and `_` are literal, not wildcards. |
| `signal` (repeatable) | The account has **all** the given signals |
| `tier` (repeatable) | `best_tier` is **any** of the given tiers |
| `country` (repeatable) | The account has **any** of the given countries (case-insensitive) |
| `min_priority` | `opportunity_priority >= min_priority` (0–100). Replaces `min_score` (scoring v3). |

Every request value is a bound SQL parameter, so no request text is interpolated into SQL.

Account item (scoring v3; priority, ownership and evidence are separate fields, and there is no bare `score`):

```json
{"account_id": "org:example corp", "account_name": "Example Corp", "account_kind": "org",
 "segment": "enterprise", "rank": 1,
 "priority": {"band": "High", "percentile": 99, "population": "eligible enterprise accounts",
              "value": 82.5, "product_relevance": 0.9, "signal_strength": 0.8,
              "note": "relative priority in this snapshot; not a purchase probability, confirmed vulnerability or loss estimate"},
 "ownership": {"confidence": "high", "reasons": ["record_names_account"], "review_flags": [],
               "best_tier": "A1", "mean_attribution_confidence": 0.95, "services": 3,
               "named_public_services": 1, "named_rdns_services": 0, "third_party_domains": 0,
               "network_operators": 1},
 "evidence": {"quality": "high", "mean_basis_quality": 0.7},
 "eligibility": {"status": "eligible", "reasons": []},
 "actionable": true, "actionable_blockers": [],
 "top_signals": [{"signal_id": "S01", "name": "Remote access exposed"}],
 "signal_ids": ["S01", "S03"], "best_tier": "A1", "n_services": 3, "n_ips": 2,
 "countries": ["AU"], "details": ["RDP", "SonicWall"],
 "legacy": {"scoring_version": 2, "score": 54.8625, "rank": 1,
            "note": "scoring v2 composite (attribution and evidence quality multiplied in); comparison only"}}
```

`percentile` is the floored share of eligible accounts in the segment with strictly lower priority;
`band`, `percentile` and `rank` are null for excluded accounts. Definitions and thresholds:
`docs/ranking-v3.md` §3.

### Account ids in paths

Ids look like `org:example corp`, `net:skyway west` (network provider) or `dom:example.com`. Percent-encode them (the UI uses `encodeURIComponent`), for example `/accounts/org%3Aexample%20corp/evidence`. Colons can also be left unencoded. The evidence route is matched first, so an id that itself ends in `/evidence` cannot be addressed.

**Ids from an older build.** Ids come from names, so an attribution rebuild can change them. When an id
is not found, the API tries `successor_ids` (`api/store.py`) in order and answers `307` with the first
one that exists, keeping the query string:

1. the accent-folded id (attribution v5: `org:telefónica x` → `org:telefonica x`);
2. for `org:`/`net:` only, the same org key under the other prefix (an org reclassified as a network
   provider, or back). It is the same registry organisation, and the target page shows its segment.

Domain ids never change prefix. An existing id is always served as is, never redirected. Measured on
the deployed v4 → v5 change: 250 public ids disappeared; 198 resolve by folding, 7 by the prefix swap,
and 45 have no successor (the org now abstains or merged into another key) and still return 404.
The redirect is temporary (307), so a later build can reuse an id. An evidence request is never
redirected when the full path is itself an existing id ending in `/evidence`.

### Evidence item

```json
{"signal_id": "S03", "signal_name": "Network security appliance exposed", "family": "exposure",
 "observed_fact": "On 2026-11-07 14:52 UTC, 192.0.2.3:443 (SNI —) served a SonicWall page titled '—' via —.",
 "inferred_risk": "…", "hypothesis": "…",
 "service": {"service_id": "…", "ip": "192.0.2.3", "port": 443, "transport": "tcp", "sni": null,
             "observed_at": "2026-11-07T14:52:01Z", "country_code": "AU", "is_cdn": false,
             "product": null, "version": null, "http_title": null, "module": null},
 "match_basis": "title", "detail": "SonicWall", "sub_flags": [],
 "tier": "A1", "attribution_confidence": 0.95, "attribution_reasons": ["org_not_provider"],
 "counted": false, "suppressed_by": "S01",
 "observation_id": "obs3",
 "provenance": {"observation_id": "obs3", "file_id": "…", "byte_offset": 3000, "byte_length": 900,
                "record_sha256": "…"}}
```

Rows are ordered by signal, then counted before suppressed, then service. `counted: false` with `suppressed_by` marks a correlated duplicate on the same service. The UI shows it as "Not counted twice: correlated with S01 … on the same service." `firmable evidence OBS_ID` resolves `provenance` back to the raw record.

## Wording (research-findings §3)

- Each response that carries claims includes `labels`: *observed fact* (what the scanner recorded), *inferred risk* (a risk class, not a verified vulnerability) and *unverified hypothesis* (a conversation starter, not evidence of intent, budget, missing controls or compromise). The UI shows the three in separate, colour-coded lines.
- `observed_fact` is the registry's `observed_fact_template` rendered by `firmable.api.wording.render_fact`. Missing, empty or unknown values render as `—` and never as `None`. Positional, attribute, index and conversion fields are refused. A malformed template falls back to `On {observed_at}, {ip}:{port}/{transport} matched signal {signal_id} ({detail}).` Timestamps render as `YYYY-MM-DD HH:MM UTC`.
- The account detail and evidence responses carry a `disclaimer`. It says bands and percentiles are a relative priority among eligible accounts in the snapshot, not a purchase probability, a confirmed vulnerability or an expected loss; that ownership confidence is separate, inferred and may be wrong, and is not multiplied into the priority; and that one snapshot says nothing about change over time. The page header repeats it. Each detail `explanation` has one line per axis (priority, signals, ownership, evidence, review flags, outreach status) and ends with the legacy score, labelled comparison only.

## Tests

```bash
uv run pytest tests/test_api*.py
```

- `tests/test_api.py`: fixture parquet files written column for column from the contract (the evidence column order matches `firmable.accounts.rollup`), served over `TestClient`. Covers ranking, pagination totals, `q` (name, id, details, literal `%`/`_`, injection-like strings), signal AND, tier and country filters, `view`, `band`, `ownership`, `min_priority`, the v3 item shape (no bare `score`), limit caps, account detail for ids with a space and colons, 404s, successor redirects for older ids (accent fold, `org`/`net` swap, URL-special characters, query kept, `/evidence` shadowing), evidence rendering with `None` fields, provenance, `suppressed_by`, registry wording, the page, and the env-var entry point.
- `tests/test_api_wording.py`: safe template rendering.
- `tests/test_api_rollup.py`: runs the real `build_accounts` on synthetic hits and serves its output, so column drift between M3 and M4 fails a test. It also loads the real `firmable.signals.registry.SIGNALS` into the serving DB and checks the wording fields are present.

## Known limitations

- `evidence_json` is not served. It can hold raw fields, such as NTLM internal names, that `CLAUDE.md` puts behind human review. There is no reviewed path to it yet.
- Full IPs are shown to the salesperson. Masking to /24 applies to docs, not to the product view.
- `q` is a substring scan over all accounts (two scans per request: count, then page), and `/accounts` totals are exact. This is fine for hundreds of thousands of accounts on one machine but has not been benchmarked on the full layer. There is no full-text ranking.
- Access: when `FIRMABLE_BASIC_AUTH=user:password` is set, every route except `/health` needs HTTP Basic auth (the container image refuses to start without it). `FIRMABLE_RATE_LIMIT_PER_MIN` limits requests in memory (one process) per key: `FIRMABLE_RATE_LIMIT_KEY=peer` (TCP peer, default), `forwarded` (right-most `X-Forwarded-For` hop, only behind a proxy that appends it) or `global` (one budget, used on Railway). Responses are `no-store` and `noindex`. Deployment: `docs/deployment.md`.
- The app reads a single snapshot DB. To switch snapshots, rebuild the DB and restart the process.
- Deployed DBs are made by `firmable publish-public` (ADR 0007): raw file coordinates are null and NTLM-derived reason codes are reworded.
- The page has been checked in a desktop browser against the fixture DB. Phone-width layout (stacked panels below 900 px, the evidence column hidden below 600 px) is CSS-only and has not been checked on a real device.
- Signals without a registry entry still serve their evidence, using the generic fact sentence and null risk and hypothesis.
