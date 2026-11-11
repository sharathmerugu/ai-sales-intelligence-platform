-- Experiment 05: which score component drives the ranking, and does one number hide different stories?
-- Read-only. Needs accounts_base.sql first (see 02_signal_structure.sql header for the command).

.print '== 5a variance of ln(component), enterprise accounts with score > 0'
SELECT count(*) AS n, round(var_pop(ln(r)), 3) AS v_relevance, round(var_pop(ln(s)), 3) AS v_strength,
       round(var_pop(ln(ac)), 3) AS v_attribution, round(var_pop(ln(q)), 3) AS v_evidence,
       round(var_pop(ln(score)), 3) AS v_score
FROM e WHERE score > 0;

.print '== 5b same, enterprise top 1000'
SELECT count(*) AS n, round(var_pop(ln(r)), 3) AS v_relevance, round(var_pop(ln(s)), 3) AS v_strength,
       round(var_pop(ln(ac)), 3) AS v_attribution, round(var_pop(ln(q)), 3) AS v_evidence,
       round(var_pop(ln(score)), 3) AS v_score
FROM e WHERE rank <= 1000;

.print '== 5c Spearman-style rank correlation of score with each component (all enterprise)'
WITH rk AS (
  SELECT rank() OVER (ORDER BY score) AS r_score, rank() OVER (ORDER BY r) AS r_r, rank() OVER (ORDER BY s) AS r_s,
         rank() OVER (ORDER BY ac) AS r_a, rank() OVER (ORDER BY q) AS r_q FROM e)
SELECT round(corr(r_score, r_r), 3) AS relevance, round(corr(r_score, r_s), 3) AS strength,
       round(corr(r_score, r_a), 3) AS attribution, round(corr(r_score, r_q), 3) AS evidence FROM rk;

.print '== 5d accounts scoring 25-30, by what drives the score'
SELECT CASE WHEN r >= 0.7 AND ac < 0.6 THEN 'strong exposure, weak attribution'
            WHEN r < 0.5 AND ac >= 0.85 THEN 'weak signal, strong attribution'
            ELSE 'other' END AS profile,
       count(*) AS n, round(avg(r), 2) AS mean_relevance, round(avg(ac), 2) AS mean_attribution
FROM e WHERE score BETWEEN 25 AND 30 GROUP BY ALL ORDER BY n DESC;

.print '== 5e kind and tier mix of the enterprise top 1000'
SELECT account_kind, best_tier, count(*) AS n FROM e WHERE rank <= 1000 GROUP BY ALL ORDER BY n DESC;
