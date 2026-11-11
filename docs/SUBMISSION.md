# Submission summary (2026-11-11)

This is a hosted cybersecurity sales-intelligence app. It ranks companies by evidence-backed signals
found in one internet-scan snapshot (2026-11-07, 16,988,823 banners), and every claim it makes
traces back to its source observations.

**[F]** measured. **[H]** judgement.

**No precision figure exists yet.** The evaluation holdout has 0 human labels (§5). Without labels,
nothing in this submission supports a claim about precision, vulnerability accuracy or purchase
probability.

## 1. What to open

| What | Where |
|---|---|
| Live app | <https://firmable-api-production.up.railway.app>. `/health` is open; every other route needs HTTP Basic auth, with the credential supplied separately |
| Research | `docs/research-findings.md` (start here), `docs/signal-catalog.md`, `docs/company-attribution.md` |
| Pipeline | `docs/ingestion-architecture.md`, `docs/ingestion-benchmark.md`, `docs/phase3-plan.md`, `docs/signals-implementation.md` |
| Attribution | `docs/attribution-implementation.md` (v5 is §7); ADRs 0005, 0007, 0008 |
| Ranking | `docs/ranking-v3.md`, ADR 0009. The legacy v2 score is kept as `legacy_score` |
| Evaluation | `docs/evaluation.md` (rubric, holdout, metrics); **`docs/labelling-guide.md`** (for human reviewers) |
| Prospecting modes, outreach-list review | `docs/prospecting-modes.md` (§5 covers the UI review) |
| API, deployment | `docs/api.md`, `docs/deployment.md` |

## 2. Architecture

```
137 GB NDJSON ─► normalized observations (normalizer v1, Parquet, provenance per row)
             ─► classification + services (services v1; key = ip, port, transport, SNI)
             ─► signals v1 (S01, S03, S04, S05, S06, S16)
             ─► attribution v5 (tiers A1/A2/P/B, abstain = C; OpenASN network classes)
             ─► accounts: eligibility v2 + scoring v3 (priority | ownership | evidence quality)
             ─► serving DB v3 ─► publish-public (sanitized) ─► FastAPI + static page on Railway
```

- **One machine.** The batch work uses Python, DuckDB, PyArrow and Parquet, streams with bounded
  memory, and writes to `~/firmable-work/`, outside Git.
- **Versioned layers.** Each layer writes to its own versioned path. The attribution-v4 and
  scoring-v2 tables stay on disk, so comparisons can be reproduced.
- **Provenance.** Each observation carries its source file, byte offset, length, observation id
  and SHA-256. `firmable evidence OBS_ID` re-reads the exact source bytes.
- **Ranking: three separate axes, never multiplied together.**
  - `opportunity_priority`: why act.
  - `ownership_confidence`: who owns the services.
  - `evidence_quality`: how good the observations are.
  - An `actionable` gate builds the outreach list.
- **Production serves only the sanitized public DB.** Raw file coordinates are null, and NTLM
  values are never served (ADR 0007).
- **Git tags.**
  - `scoring-v2-baseline`: the last commit that served scoring v2.
  - `scoring-v3-deployed`: the first scoring-v3 deployment.
  - Both are unchanged. `main` was fast-forwarded to `feat/scoring-v3` (no merge commit).

## 3. Verified [F] (2026-11-11)

| Check | Result |
|---|---|
| Unit and integration tests | **813 passed** in 62 s, slow memory test included (`uv run pytest`) |
| e2e (Playwright, desktop + Pixel 7) | **22 / 22** locally (public DB, Basic auth on) and **22 / 22 on production** |
| Deployed commit | **`aa78567`** (Railway; `deploy/GIT_COMMIT` in the build context). Previous: `fd7c671` |
| Production matches the code | 10 live endpoints byte-identical to a local server on the same commit and public DB: page, health, signals, three views, the network-provider list, folded search, one detail, one evidence page. Old-id redirect `Location` also identical |
| Old account ids | 250 public ids from the attribution-v4 deployment are gone in v5. On production, **205 now redirect** (307: 198 by accent fold, 7 org↔net) and 45 return 404 (no successor). A browser deep link to an old id opens the current account |
| Deterministic builds | Accounts rebuild identical row for row (ranking-v3 §3.5). The holdout CSV is byte-identical on regeneration |
| Privacy | The public DB has no NTLM values and no raw file coordinates. Unauthenticated `/accounts` → 401 |
| Live counts | 180,511 accounts; 60,722 actionable enterprise accounts; 281 excluded; no bare `score` field |
| Credentials | Rotated 2026-11-11; old credential rejected (401); e2e 22 / 22 with the new one (§8) |

## 4. Performance [F]

| Stage | Measured | Source |
|---|---|---|
| Ingestion, `run --workers 6` | 516 s for 137 GB (254 MiB/s, 32,955 rows/s); 249 MiB peak RSS per worker | `docs/ingestion-benchmark.md` |
| `build-services` | 108 s; 5.7 GiB peak (DuckDB capped at 6 GB) | same |
| Raw file → services table | about 15.6 min end to end on one 16 GiB laptop | same |
| Full `build-phase3` (signals → serving) | 173 s; 6.1 GB peak RSS | `docs/phase3-results.md` |
| Accounts + serving rebuild after a scoring change | about 36–40 s | `docs/ranking-v3.md` §5 |
| Live API, server side (app logs, current deployment, 143 requests including e2e) | `/accounts` list and search: median 15.6 ms, p95 24.2 ms. Detail: 8.0 / 11.2 ms. Evidence: 17.6 / 25.4 ms | Railway logs, 2026-11-11 |
| Live API, client round trip from the author's network | median 504 ms, p95 765 ms (80 requests); network-dominated | same session |

## 5. Evaluation status

- **Holdout.** 155 cases in `~/firmable-work/eval/2026-11-07-holdout-v3.csv`, kept out of Git
  because it holds real names and IPs. Seed `20261112`; CSV SHA-256 `d41948b6…743b847c`.
- **Development vs held out.** 67 cases are development data (`dev_case = yes`, with their sources)
  and 88 were never seen during development.
- **Integrity re-checked on 2026-11-11 [F]:**
  - both files read as UTF-8; same 155 case ids in the same order;
  - `account_ref` matches its seeded hash in both files;
  - the SHA-256 matches the manifest;
  - `dev_case` re-derived from the development registry agrees on all 155 cases;
  - per-stratum development counts match the manifest; every `non_dev` stratum holds 0 development
    cases;
  - the blind file hides every system, stratum and id column;
  - `read_holdout(full, labels=blind)` accepts the pair;
  - regenerating the holdout to a scratch path after this submission's doc changes gave a
    byte-identical CSV and blind file (9.5 s).
- **Labels: 0.** Every `manual_*` cell is blank in both files. No model-suggested labels and no
  checker verdicts are in either file. No labels were created during this submission.
- **Metrics.** `holdout-metrics` reports `cases_labeled: 0` and no rates.
- **Precision@20/40 cannot be clean.** The top 40 was read while the rules were developed, so it
  is reported as a census of development data. Uncontaminated rates come from `rank_401_2000` and
  the random strata.

Exact commands:

```bash
# integrity and metrics (read-only)
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv
uv run firmable holdout-metrics ~/firmable-work/eval/2026-11-07-holdout-v3.csv \
    --labels ~/firmable-work/eval/2026-11-07-holdout-v3.blind.csv   # after labelling the blind file
# regenerate to a scratch path and compare (never over the canonical file)
uv run firmable holdout-set 2026-11-07 --out /tmp/holdout-check.csv
shasum -a 256 /tmp/holdout-check.csv ~/firmable-work/eval/2026-11-07-holdout-v3.csv
# reviewer aids (heuristic, never labels)
uv run firmable evidence OBS_ID
uv run firmable inspect-accounts 2026-11-07 --account ID --n 20
uv run firmable compare-rankings 2026-11-07 \
    --legacy ~/firmable-work/lake/accounts/scoring=v2/attribution=v4/... \
    --candidate ~/firmable-work/lake/accounts/scoring=v3/attribution=v4/...
```

How to label: `docs/labelling-guide.md`. Label the blind file only. Labels must come from people,
not from a model, a checker or the app's verdicts.

## 6. Reproduce

```bash
uv sync && uv run pytest                                             # 813 tests, ~62 s
uv run firmable register ~/Downloads/firmable_dataset --snapshot 2026-11-07
uv run firmable run --workers 6 && uv run firmable build-services 2026-11-07 && uv run firmable seal 2026-11-07
uv run firmable build-phase3 2026-11-07 --memory-limit 6GB --threads 6
uv run firmable publish-public 2026-11-07
scripts/stage_deploy.sh 2026-11-07                                   # Railway; needs a clean tracked tree
cd e2e && FIRMABLE_URL=... FIRMABLE_USER=reviewer FIRMABLE_PASSWORD=... npx playwright test
```

The image is pinned by digest and dependencies come from `uv.lock`. A commit plus the public DB
reproduces the deployment (`docs/deployment.md`).

## 7. Unresolved limitations

1. **No ground truth.** Every quality statement so far is internal: name-class placebos, a
   heuristic source-record checker and stability tests (ranking-v3 §5). Nothing supports a claim
   about precision, vulnerability accuracy or purchase probability.
2. **Provider leakage remains after attribution v5.** It comes from:
   - hosters whose own ASNs OpenASN files as `business`;
   - sub-allocated resellers;
   - IT outsourcers;
   - telco domain accounts in the enterprise segment;
   - consortium networks.

   See attribution-implementation §7.4. One IT distributor was moved to `saas_platform` and needs a
   human check.
3. **Attribution abstains on 69.7% of services** (tier C), and not at random: cloud-hosted firms are
   visible only when a certificate, SNI or HTTP Host names them.
4. **Outreach list composition.** 96% of actionable accounts are TLS-hygiene (S06) leads; 2,271 are
   exposure-led.
   - **In the list view the lead types are not labelled.** Positions 1–1,629 are all exposure-led.
     Past that, the remaining 642 exposure-led accounts are mixed in with hygiene accounts, and rows
     show only signal codes. The Medium band holds both types.
   - The detail panel names each signal and labels its claims, and technographic-only accounts
     never reach the list. So this was documented, not changed (`docs/prospecting-modes.md` §5).
5. **Size bias.** Breadth saturates at 16 IPs, and nothing normalises for footprint, so the top is
   mostly universities and large public bodies.
6. **Thresholds are hypotheses.** The bands, flags and exclusion rules were set on unlabelled
   development data.
7. **One snapshot.** No claim of change over time, activity or purchase intent is possible.
8. **Old account ids.** 45 of the 250 ids lost in the v4→v5 rebuild have no successor, because
   their org now abstains or merged into another key. They return 404. Redirects are rule-based
   (accent fold, org↔net), not a stored alias table, so a future rename of another kind would
   break links again (`docs/api.md`).
9. **Deployment.**
   - One shared Basic-auth credential and an in-memory global rate limit suit a private review, not
     multi-user production.
   - Request logs record account ids in paths, and those ids are organisation names.
   - Railway's `railway.json` config-as-code format is deprecated from 2026-12-01
     (`docs/deployment.md`).

## 8. Credentials and exposure check (2026-11-11)

No secret values were printed during this check.

- The local credential file `~/firmable-work/deploy-credentials.txt` has mode 600. The Railway
  service has one non-system variable, `FIRMABLE_BASIC_AUTH`, and it matches the local file. The
  image refuses to start without it.
- The credential, raw and as a Basic-auth header, was searched for in these places and found in
  none of them:
  - tracked files and all Git history;
  - the untracked `session1.txt`;
  - `~/firmable-work/logs`, the build logs, `eval/` and `deploy-context/`;
  - `e2e/` (including `test-results`);
  - the last 312 lines of Railway logs.
- A pattern scan of tracked files for API keys, tokens and private keys found nothing.
- **Found:** the password appears in **one local Claude Code session transcript**
  (`~/.claude/projects/…`), from the session that created it. That means it also passed through
  the AI tool's context in that session.
- **Rotated on 2026-11-11 [F].** A new 24-character password was generated locally and set with
  `railway variable set FIRMABLE_BASIC_AUTH --stdin`, so it never appeared on a command line or in
  output. Railway redeployed the same image. Checks after the redeploy:
  - the new credential gets 200;
  - the old credential and no credential both get 401;
  - an old account id still redirects (307), and live counts are unchanged;
  - production e2e passes **22 / 22** with the new credential.

  The new value was then searched for and found in none of: tracked files, `e2e/`, the last 500
  lines of Railway logs, or any Claude Code transcript. The local file was replaced, with mode 600.
  The old password, which still sits in the one transcript, no longer works.
- **Procedure for the next rotation:**

  ```bash
  python3 -c "import secrets; print('reviewer:' + secrets.token_urlsafe(18), end='')" \
    | railway variable set FIRMABLE_BASIC_AUTH --stdin --service firmable-api
  ```

  Write the same value to the local file before piping it, then rerun e2e. Never pass the
  credential as a command argument, and never paste it into an AI session.
- Playwright keeps traces on failure (`trace: retain-on-failure`), and a trace can contain the
  Authorization header. `e2e/test-results/` is gitignored and was empty after the passing runs.

## 9. AI-assisted development methodology

The project was built with Claude Code (an AI coding agent) working under the author's direction.

- **The human decided.** The author set the priorities (CLAUDE.md), chose between options, and
  approved outward-facing actions such as Railway deployments.
- **The agent proposed, implemented and measured.**
- **Research before code.** Every number in the research documents comes from
  `sql/exploration.sql` runs on the full file. The implementation ports that logic and keeps its
  versions and citations.
- **Specs and tests first.** Specs have testable acceptance criteria. Parsers, attribution rules,
  eligibility, scoring, holdout sampling, metrics and the id redirect were built test-first, and the
  full suite runs after every change.
- **Independent review.** Every important change was reviewed by a separate reviewer agent before
  deployment:

  | Change | Medium findings | Low findings | Outcome |
  |---|---|---|---|
  | Scoring v3 | 2 | 7 | all fixed |
  | Attribution v5 | 9 | 7 | medium fixed with tests; low fixed or documented |
  | Holdout tooling | 12 | 8 | medium fixed with tests; low fixed or documented |
  | Id redirect | 3 | — | two fixed with tests; one kept, with the reason in `docs/api.md` |

- **Results only from real runs.** Every [F] figure comes from a command run on the real data or
  the live service, and test counts are copied from pytest and Playwright output. [H] marks
  judgement.
- **Model output is never a label.**
  - The older review set has model-written `suggested_*` columns. `review-metrics --source
    suggested` reports them separately as provisional, and they are not results.
  - The scoring-v3 holdout has no suggestion columns at all. `holdout-metrics` rejects files that
    carry them, and rejects a reviewer name that names a model.
  - No labels were generated for this submission.
- **Guardrails in the instructions.** Allowed claim wording (research-findings §3), NTLM and other
  sensitive details behind review, IPs masked to /24 in docs, and real-data artifacts kept out of
  Git.
- **Known weakness of the method.** The same agent that wrote the rules also read the development
  data. The holdout's development registry and blind file exist to keep that from leaking into the
  evaluation, but only human labels can show whether it did.

## 10. Next step that matters most

Have one or two people label the blind holdout (`docs/labelling-guide.md`), then run
`holdout-metrics`. If two people label, an overlap of 30 or more cases also gives inter-rater
agreement.
