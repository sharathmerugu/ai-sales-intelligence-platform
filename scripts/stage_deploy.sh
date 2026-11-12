#!/usr/bin/env bash
# Assemble a private build context outside the repo and deploy it to Railway.
#   scripts/stage_deploy.sh 2026-11-07 [--no-up]
# Context = `git archive HEAD` (tracked files only) + the sanitized public serving DB.
# Raw data, the lake and the internal serving DB never enter the context.
set -euo pipefail
snap=${1:?usage: stage_deploy.sh SNAPSHOT [--no-up]}
work=${FIRMABLE_WORK:-$HOME/firmable-work}
db="$work/serving/$snap.public.duckdb"
ctx="$work/deploy-context"
[[ -f "$db" ]] || { echo "missing $db: run 'uv run firmable publish-public $snap'" >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo "commit tracked changes first" >&2; exit 1; }
rm -rf "$ctx" && mkdir -p "$ctx"
git archive HEAD | tar -x -C "$ctx"
cp "$db" "$ctx/deploy/serving.duckdb"
# Briefs generated once from the public DB (`firmable agent-pregenerate`); optional, served read-only.
briefs="$work/app/$snap.briefs.sqlite"
if [[ -f "$briefs" ]]; then
  sqlite3 "$briefs" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
  cp "$briefs" "$ctx/deploy/briefs.sqlite"
fi
git rev-parse HEAD > "$ctx/deploy/GIT_COMMIT"
( cd "$ctx" && find . -type f | sort | grep -v '^./src/' | head -50 && du -sh . )
if [[ "${2:-}" != "--no-up" ]]; then
  ( cd "$ctx" && railway up --ci --service "${RAILWAY_SERVICE:-firmable-api}" )
fi
