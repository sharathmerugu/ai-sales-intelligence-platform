-- Experiment 01: is missing attribution / missing version non-random, and how much could outside data fill?
-- Frozen v4 reproduction: reads attribution v4 (kept unchanged on disk); see docs/attribution-implementation.md §7.
-- Read-only. Run from the repo root (see docs/experiments/README.md):
--   duckdb -no-agent -csv -c "SET VARIABLE lake='$HOME/firmable-work/lake';" -c ".read docs/experiments/scripts/01_missingness.sql"
SET memory_limit = '5GB';
SET threads = 6;

CREATE TEMP TABLE s AS SELECT * FROM read_parquet(getvariable('lake') || '/services/services=v1/normalizer=v1/snapshot=2026-11-07/services.parquet', hive_partitioning = false);
CREATE TEMP TABLE a AS SELECT * FROM read_parquet(getvariable('lake') || '/attribution/attribution=v4/normalizer=v1/snapshot=2026-11-07/service_attribution.parquet', hive_partitioning = false);
CREATE TEMP TABLE h AS SELECT * FROM read_parquet(getvariable('lake') || '/signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet', hive_partitioning = false);

-- Services carrying at least one exposure signal (S01/S03/S04/S05).
CREATE TEMP TABLE x AS
SELECT s.service_id, s.cloud_provider IS NOT NULL AS cloud, a.org_class, a.tier, a.reasons,
       s.cert_subject_cn, s.sni, s.http_host
FROM s JOIN a USING (service_id)
WHERE service_id IN (SELECT service_id FROM h WHERE family = 'exposure');

.print '== 1a abstention (tier C) share of exposure services'
SELECT count(*) AS n, round(100 * avg((tier = 'C')::INT), 1) AS pct_c FROM x;

.print '== 1b abstention by registrant class and cloud tag'
SELECT org_class, cloud, count(*) AS n,
       round(100 * avg((tier = 'C')::INT), 1) AS pct_c,
       round(100 * avg((tier IN ('A1', 'A2'))::INT), 1) AS pct_a
FROM x GROUP BY ALL ORDER BY n DESC;

.print '== 1c abstention reasons (tier C exposure services)'
SELECT r AS reason, count(*) AS n
FROM (SELECT unnest(reasons) AS r FROM x WHERE tier = 'C')
WHERE r LIKE 'abstain%' OR r = 'shared_hosting'
GROUP BY r ORDER BY n DESC;

.print '== 1d what name evidence abstained exposure services carry (upper bound for external fill)'
SELECT CASE
         WHEN cert_subject_cn IS NULL AND coalesce(sni, '') = '' AND http_host IS NULL THEN '0 no name at all'
         WHEN regexp_matches(coalesce(cert_subject_cn, ''), '^[0-9.:]+$') THEN '1 certificate CN is an IP'
         WHEN regexp_matches(lower(coalesce(cert_subject_cn, '')),
              'localhost|fortigate|fgt|sonicwall|default|self|router|device|^[a-f0-9]{12,}$|synology|mikrotik|ubnt|plesk|cpanel|vmware|idrac|ilo')
              THEN '2 vendor or default certificate'
         WHEN coalesce(cert_subject_cn, '') NOT LIKE '%.%' AND coalesce(sni, '') = '' THEN '3 CN is not a domain'
         ELSE '4 domain-like name present' END AS kind,
       count(*) AS n
FROM x WHERE tier = 'C' GROUP BY ALL ORDER BY kind;

.print '== 1e observation gap: version visible on exposure-signal hits'
SELECT signal_id, count(*) AS n, round(100 * avg((version IS NOT NULL)::INT), 1) AS pct_version_seen
FROM h WHERE family = 'exposure' GROUP BY ALL ORDER BY signal_id;

.print '== 1f S01 by vendor: version vs other fingerprints that could stand in for it'
SELECT h.detail, count(*) AS n,
       round(100 * avg((s.version IS NOT NULL)::INT), 1) AS pct_version,
       round(100 * avg((s.favicon_hash IS NOT NULL)::INT), 1) AS pct_favicon,
       round(100 * avg((s.jarm IS NOT NULL AND s.jarm NOT LIKE '0000%')::INT), 1) AS pct_jarm,
       round(100 * avg((s.http_html_hash IS NOT NULL)::INT), 1) AS pct_html_hash,
       count(DISTINCT s.http_html_hash) AS distinct_html_hashes
FROM h JOIN s USING (service_id)
WHERE h.signal_id = 'S01'
GROUP BY ALL ORDER BY n DESC LIMIT 6;
