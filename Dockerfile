# Firmable sales-intelligence API: FastAPI + read-only DuckDB serving DB.
#
# The image needs only the sanitized public serving DB (`firmable publish-public`), never the
# raw dataset or the lake. The DB is not in Git: `scripts/stage_deploy.sh` assembles a build
# context outside the repo (git HEAD + deploy/serving.duckdb) and `railway up` builds it in
# Railway's private builder. For a local run, mount the DB instead:
#   docker run -p 8000:8000 -e FIRMABLE_BASIC_AUTH=user:pass \
#     -v ~/firmable-work/serving/2026-11-07.public.duckdb:/app/deploy/serving.duckdb:ro firmable-api
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev

# deploy/ holds only a README in Git; the staged build context adds serving.duckdb.
COPY deploy ./deploy

# The runtime user can read but not modify the code or the serving DB (owned by root).
RUN useradd --system --uid 10001 app
USER app

ENV PATH=/app/.venv/bin:$PATH \
    FIRMABLE_SERVING_DB=/app/deploy/serving.duckdb \
    FIRMABLE_REQUIRE_AUTH=1 \
    FIRMABLE_RATE_LIMIT_PER_MIN=600 \
    FIRMABLE_RATE_LIMIT_KEY=global \
    FIRMABLE_DUCKDB_MEMORY_LIMIT=512MB \
    FIRMABLE_DUCKDB_THREADS=2 \
    FIRMABLE_LOG_STREAM=stdout \
    HOST=0.0.0.0 PORT=8000

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health', timeout=4)"

CMD ["python", "-m", "firmable.api"]
