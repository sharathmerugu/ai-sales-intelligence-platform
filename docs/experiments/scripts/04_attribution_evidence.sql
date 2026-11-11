-- Experiment 04: which evidence does current attribution rest on? (Is WHOIS / CT validation circular?)
-- Frozen v4 reproduction: reads attribution v4 (kept unchanged on disk); see docs/attribution-implementation.md §7.
-- Read-only.
--   duckdb -no-agent -csv -c "SET VARIABLE lake='$HOME/firmable-work/lake';" -c ".read docs/experiments/scripts/04_attribution_evidence.sql"
SET memory_limit = '5GB';
SET threads = 6;

CREATE TEMP TABLE a AS
SELECT * FROM read_parquet(getvariable('lake') || '/attribution/attribution=v4/normalizer=v1/snapshot=2026-11-07/service_attribution.parquet', hive_partitioning = false)
WHERE tier IN ('A1', 'A2', 'B')
  AND service_id IN (SELECT service_id FROM read_parquet(getvariable('lake') || '/signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet', hive_partitioning = false));

.print '== 4a attributed services with a signal, by tier and deciding reason code'
SELECT tier, r AS reason, count(*) AS n
FROM (SELECT tier, unnest(reasons) AS r FROM a)
WHERE r LIKE 'dom_%' OR r = 'org_not_provider'
GROUP BY ALL ORDER BY tier, n DESC;

.print '== 4b tier-B services by evidence family behind the winning domain'
SELECT CASE WHEN list_contains(reasons, 'dom_ntlm_corroborated') THEN 'NTLM + public name'
            WHEN list_has_any(reasons, ['dom_cert_sni_agree', 'dom_cert_wildcard_sni_agree', 'dom_cert', 'dom_cert_san', 'dom_cert_wildcard'])
                 THEN 'certificate (CT-visible)'
            WHEN list_has_any(reasons, ['dom_sni', 'dom_http_host']) THEN 'SNI / Host only'
            WHEN list_contains(reasons, 'dom_hostname_only') THEN 'reverse DNS hostname only'
            ELSE 'other' END AS family,
       count(*) AS n, round(100.0 * count(*) / sum(count(*)) OVER (), 1) AS pct
FROM a WHERE tier = 'B' GROUP BY ALL ORDER BY n DESC;
