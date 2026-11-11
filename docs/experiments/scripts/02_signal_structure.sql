-- Experiment 02 (part 1): signal prevalence, information content, correlation, known-class placement.
-- Frozen v4 reproduction: reads attribution v4 (kept unchanged on disk); see docs/attribution-implementation.md §7.
-- Read-only. Part 2 (weight sensitivity, bootstrap) is 02_sensitivity.py.
--   duckdb -no-agent -csv -c "SET VARIABLE accounts='$HOME/firmable-work/lake/accounts/scoring=v2/attribution=v4/normalizer=v1/snapshot=2026-11-07';" \
--     -c ".read docs/experiments/scripts/accounts_base.sql" -c ".read docs/experiments/scripts/02_signal_structure.sql"

.print '== 2a prevalence of counted signals across enterprise accounts; self_info = -ln(share)'
SELECT sid AS signal_id, count(*) AS n, round(100.0 * count(*) / (SELECT count(*) FROM e), 2) AS pct,
       round(-ln(count(*) / (SELECT count(*) FROM e)), 2) AS self_info
FROM (SELECT unnest(cs) AS sid FROM e) GROUP BY sid ORDER BY sid;

CREATE TEMP TABLE ind AS
SELECT account_id,
       list_contains(cs, 'S01')::INT AS s01, list_contains(cs, 'S03')::INT AS s03, list_contains(cs, 'S04')::INT AS s04,
       list_contains(cs, 'S05')::INT AS s05, list_contains(cs, 'S06')::INT AS s06, list_contains(cs, 'S16')::INT AS s16
FROM e;

.print '== 2b phi correlation between counted-signal indicators, all enterprise accounts'
SELECT round(corr(s01, s03), 3) AS s01_s03, round(corr(s01, s04), 3) AS s01_s04, round(corr(s01, s05), 3) AS s01_s05,
       round(corr(s03, s04), 3) AS s03_s04, round(corr(s03, s05), 3) AS s03_s05, round(corr(s04, s05), 3) AS s04_s05,
       round(corr(s01, s06), 3) AS s01_s06, round(corr(s05, s06), 3) AS s05_s06, round(corr(s01, s16), 3) AS s01_s16,
       round(corr(s06, s16), 3) AS s06_s16
FROM ind;

.print '== 2c same, accounts with >= 2 counted signals'
SELECT count(*) AS n, round(corr(s01, s03), 3) AS s01_s03, round(corr(s01, s16), 3) AS s01_s16,
       round(corr(s05, s06), 3) AS s05_s06, round(corr(s06, s16), 3) AS s06_s16
FROM ind WHERE s01 + s03 + s04 + s05 + s06 + s16 >= 2;

.print '== 2d S06 / S16 overlap by account kind'
SELECT e.account_kind, count(*) AS n, sum(s06) AS with_s06, sum(s16) AS with_s16, sum(s06 * s16) AS with_both
FROM ind JOIN e USING (account_id) GROUP BY ALL ORDER BY n DESC;

.print '== 2e known-class placement by account-name pattern (crude regex classes, not labels)'
SELECT CASE WHEN regexp_matches(lower(account_name), 'subscriber|customer|leased line|pool|dynamic|broadband|dsl|dhcp|residential|b2b')
                 THEN 'pool or customer label (known-negative)'
            WHEN regexp_matches(lower(account_name), 'universit|college|\.edu$|\.ac\.[a-z]+$') THEN 'university (likely enterprise)'
            WHEN regexp_matches(lower(account_name), 'bank|hospital|health') THEN 'bank or health (likely enterprise)'
            ELSE 'other' END AS name_class,
       count(*) AS n, round(median(rank)) AS median_rank,
       count(*) FILTER (WHERE rank <= 100) AS in_top100, count(*) FILTER (WHERE rank <= 1000) AS in_top1000
FROM e GROUP BY ALL ORDER BY name_class;
