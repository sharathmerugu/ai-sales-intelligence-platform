-- Shared setup for experiments 02, 05 and 06: enterprise accounts (scoring v2, attribution v4) with their
-- counted signal set. Read by the experiment scripts; needs `SET VARIABLE accounts='<dir>'`.
SET memory_limit = '5GB';
SET threads = 6;

CREATE TEMP TABLE e AS
SELECT a.account_id, a.account_name, a.account_kind, a.best_tier, a.rank, a.score,
       a.product_relevance AS r, a.signal_strength AS s, a.attribution_confidence AS ac, a.evidence_quality AS q,
       list_sort(list(g.signal_id) FILTER (WHERE g.contribution > 0)) AS cs
FROM read_parquet(getvariable('accounts') || '/accounts.parquet', hive_partitioning = false) a
JOIN read_parquet(getvariable('accounts') || '/account_signals.parquet', hive_partitioning = false) g USING (account_id)
WHERE a.segment = 'enterprise'
GROUP BY ALL;
