-- Experiment 03: would per-service CVE / KEV data be a sound basis for signal weights?
-- Read-only. `any_kev` and `vulns` are the scanner's version-inferred CVEs (99.99% unverified).
--   duckdb -no-agent -csv -c "SET VARIABLE lake='$HOME/firmable-work/lake';" -c ".read docs/experiments/scripts/03_kev_by_signal.sql"
SET memory_limit = '5GB';
SET threads = 6;

.print '== 3a scanner-inferred KEV / CVE presence and version visibility by signal'
SELECT h.signal_id, count(*) AS n,
       round(100 * avg(coalesce(s.any_kev, false)::INT), 2) AS pct_kev,
       round(100 * avg((len(coalesce(s.vulns, [])) > 0)::INT), 2) AS pct_any_cve,
       round(100 * avg((s.version IS NOT NULL)::INT), 1) AS pct_version
FROM read_parquet(getvariable('lake') || '/signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet', hive_partitioning = false) h
JOIN read_parquet(getvariable('lake') || '/services/services=v1/normalizer=v1/snapshot=2026-11-07/services.parquet', hive_partitioning = false) s
  USING (service_id)
GROUP BY ALL ORDER BY signal_id;
