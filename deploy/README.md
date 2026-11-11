# deploy/

Build context slot for the sanitized public serving DB. Only this README is in Git.

`scripts/stage_deploy.sh SNAPSHOT` copies `git HEAD` plus
`~/firmable-work/serving/SNAPSHOT.public.duckdb` (made by `firmable publish-public SNAPSHOT`)
to `~/firmable-work/deploy-context/`, with the DB at `deploy/serving.duckdb`, and runs
`railway up` from there. The DB is never committed and never pushed to a public registry.
