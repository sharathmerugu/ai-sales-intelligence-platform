# Deployment — Railway, private build context, sanitized DB

Live: <https://firmable-api-production.up.railway.app> (project `firmable-intel`, service
`firmable-api`, environment `production`). `/health` is open; every other route needs HTTP
Basic auth. The reviewer credential is set as a Railway variable and kept locally in
`~/firmable-work/deploy-credentials.txt` (mode 600). It is never in Git.

## What is deployed

- The existing FastAPI app and static page (no new framework).
- A read-only DuckDB file made by `firmable publish-public SNAPSHOT` (ADR 0007): accounts,
  signals, evidence and the signal registry. Raw file coordinates are null; NTLM fields were
  never in the serving DB; NTLM reason codes are reworded. 137.6 MB for snapshot 2026-11-07.
- Nothing else: no raw dataset, lake, observations or internal serving DB. The app needs only
  that one file and runs without the 137 GB dataset.

## How

```bash
uv run firmable publish-public 2026-11-07
scripts/stage_deploy.sh 2026-11-07      # needs a clean tree; `--no-up` stages without deploying
```

`stage_deploy.sh` copies `git archive HEAD` (tracked files only) plus the public DB into
`~/firmable-work/deploy-context/` and runs `railway up --ci --service firmable-api` from there.
Railway builds the `Dockerfile` in its private builder and keeps the image in the project's
private registry. The DB never enters Git or a public registry. `.dockerignore` limits the
image to `pyproject.toml`, `uv.lock`, `README.md`, `src/` and `deploy/`.

## Image

- `python:3.12.11-slim-bookworm` and `uv 0.11.28`, both pinned by digest; dependencies
  from `uv.lock` (`uv sync --frozen --no-dev`). Reproducible from a commit plus the DB file.
- Runs as an unprivileged user that cannot modify the code or the DB.
- Environment (set in the image): `FIRMABLE_SERVING_DB=/app/deploy/serving.duckdb`,
  `FIRMABLE_REQUIRE_AUTH=1` (refuses to start without `FIRMABLE_BASIC_AUTH`),
  `FIRMABLE_RATE_LIMIT_PER_MIN=600`, `FIRMABLE_RATE_LIMIT_KEY=global`, `FIRMABLE_DUCKDB_MEMORY_LIMIT=512MB`, `FIRMABLE_DUCKDB_THREADS=2`,
  `FIRMABLE_LOG_STREAM=stdout`. Railway sets `PORT`.
- Set on Railway: `FIRMABLE_BASIC_AUTH=reviewer:<secret>`. Set it from stdin
  (`railway variable set FIRMABLE_BASIC_AUTH --stdin --service firmable-api`) so the value never sits
  on a command line. Changing it redeploys the same image. Last rotated 2026-11-11 (`docs/SUBMISSION.md` §8).
- Health: Docker `HEALTHCHECK` and Railway `healthcheckPath: /health` (`railway.json`); restart
  on failure, up to 5 retries; one replica.
- Logs: one JSON line per request (`event=http.request`, method, path without query, status,
  ms) on stdout; uvicorn access logs are off. `railway logs --service firmable-api`.
- Resources: DuckDB is capped at 512 MB and 2 threads. Measured locally the container uses
  98 MB RSS after start. Railway's per-service CPU and memory caps are set in the dashboard,
  not in `railway.json`; this project uses the plan defaults.

## Verify

```bash
cd e2e && npm ci && npx playwright install chromium
FIRMABLE_URL=https://firmable-api-production.up.railway.app FIRMABLE_USER=reviewer \
FIRMABLE_PASSWORD=... npx playwright test
```

Results and live latencies: `docs/phase3-hardening-results.md`. Scoring v3 deployment (commit
`5be744f`, 2026-11-11, e2e 22/22): `docs/ranking-v3.md` §5.8. Attribution v5 deployment (commit
`fd7c671`, 2026-11-11, e2e 22/22, live responses byte-identical to the local public DB):
`docs/ranking-v3.md` §5.10. The app refuses a serving DB whose `serving_version` differs from its own
(now 3: accent-folded search), so the image and the public DB must be deployed together.
Old-account-id redirects (`docs/api.md`) deployed in commit `aa78567`, 2026-11-11, with the same public
DB (SHA-256 unchanged): e2e 22 / 22 on production; 10 endpoints and the redirect `Location`
byte-identical to a local server; 205 of 250 old ids redirect, 45 return 404.

Serving v4 (salesperson report, statuses, use-case lenses; ADR 0010, `docs/sales-brief.md`) deployed
in commit `cf8e58a`, 2026-11-12, with public DB SHA-256 `4a901c139f31…`: e2e 21 / 21 on production; 7
endpoints byte-identical to a local server. Rollback to serving v3: check out `aa78567` and copy
`~/firmable-work/serving/2026-11-07.public.serving-v3.duckdb` over the public DB, then run
`scripts/stage_deploy.sh 2026-11-07` (image and DB must match: the app refuses another serving version).

Rollback to the previous deployment: check out `fd7c671` and run `scripts/stage_deploy.sh 2026-11-07` (same
public DB). Rollback to attribution v4: tag `scoring-v3-deployed` (`5be744f`) with the backed-up
`~/firmable-work/serving/2026-11-07.public.scoring-v3-attr-v4.duckdb` copied over the public DB.

## Limits

- The rate limiter lives in process memory: it resets on restart and does not span replicas.
- The rate limit is one global budget (600 requests/minute across all clients). Measured on
  Railway (2026-11-10): with spoofed `X-Real-IP` / `X-Forwarded-For`, 250 of 250 requests passed
  when the app keyed on `X-Real-IP` and 260 of 260 when it keyed on the right-most
  `X-Forwarded-For` hop; keyed on the TCP peer, 650 of 650 passed in one minute because the edge
  connects from changing addresses. No per-client key is trustworthy there, so the image uses
  `FIRMABLE_RATE_LIMIT_KEY=global`. One heavy client can exhaust the shared budget; per-client
  limits belong in Railway's WAF or another edge.
- Basic auth with one shared credential suits a private review deployment, not production
  multi-user access.
- `railway.json` (config as code) is deprecated by Railway in favour of `.railway/railway.ts`
  from 2026-12-01; migrate with `railway config migrate`.
