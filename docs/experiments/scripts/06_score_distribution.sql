-- Experiment 06: what reference frame does a raw score have (ties, percentiles, peer groups, anchors)?
-- Read-only. Needs accounts_base.sql first (see 02_signal_structure.sql header for the command).

.print '== 6a score distribution, enterprise'
SELECT count(*) AS n, count(DISTINCT score) AS distinct_scores,
       round(quantile_cont(score, 0.5), 1) AS p50, round(quantile_cont(score, 0.9), 1) AS p90,
       round(quantile_cont(score, 0.99), 1) AS p99, round(quantile_cont(score, 0.999), 1) AS p999,
       round(max(score), 1) AS max,
       round(100 * avg((score >= 36.0)::INT), 2) AS pct_ge_36
FROM e;

.print '== 6b most common score values (ties)'
SELECT score, count(*) AS n FROM e GROUP BY score ORDER BY n DESC LIMIT 6;

.print '== 6c peer groups: same score, different percentile'
SELECT account_kind, best_tier, count(*) AS n,
       round(100 * avg((score < 30)::INT), 1) AS pct_below_30,
       round(100 * avg((score < 36)::INT), 1) AS pct_below_36,
       round(quantile_cont(score, 0.5), 1) AS p50, round(quantile_cont(score, 0.9), 1) AS p90,
       round(quantile_cont(score, 0.99), 1) AS p99
FROM e GROUP BY ALL ORDER BY n DESC;

.print '== 6d illustrative bands cut at whole-population percentiles (not calibrated)'
WITH cut AS (SELECT quantile_cont(score, 0.99) AS hot, quantile_cont(score, 0.90) AS warm FROM e)
SELECT CASE WHEN score >= hot THEN '1 hot (top 1%)' WHEN score >= warm THEN '2 warm (top 10%)' ELSE '3 cold' END AS band,
       count(*) AS n, round(min(score), 1) AS min_score, round(max(score), 1) AS max_score,
       count(*) FILTER (WHERE best_tier IN ('A1', 'A2')) AS org_accounts,
       count(*) FILTER (WHERE best_tier = 'B') AS domain_accounts
FROM e, cut GROUP BY ALL ORDER BY band;

.print '== 6e where pool / customer labels land in those bands (known-negative floor check)'
WITH cut AS (SELECT quantile_cont(score, 0.99) AS hot, quantile_cont(score, 0.90) AS warm FROM e)
SELECT CASE WHEN score >= hot THEN '1 hot' WHEN score >= warm THEN '2 warm' ELSE '3 cold' END AS band, count(*) AS n
FROM e, cut
WHERE regexp_matches(lower(account_name), 'subscriber|customer|leased line|pool|dynamic|broadband|dsl|dhcp|residential|b2b')
GROUP BY ALL ORDER BY band;
