"""Scoring v1: pure, deterministic, explainable account score.

Expected values are worked by hand from the formula in docs/phase3-plan.md
("Scoring v1"), not recomputed with the code under test.
"""

import pytest

from firmable.accounts.scoring import AccountInput, score_account


def test_single_remote_access_gateway_on_one_owned_ip():
    # relevance: S01 weight 0.80
    # strength: 1 IP -> 0.50
    # score = 100 * 0.80 * 0.50 * 0.90 * 1.00 = 36.0
    s = score_account(AccountInput(signal_ids=frozenset({"S01"}), n_ips=1,
                                   attribution_confidence=0.9, evidence_quality=1.0))
    assert s.product_relevance == pytest.approx(0.80)
    assert s.signal_strength == pytest.approx(0.50)
    assert s.attribution_confidence == pytest.approx(0.90)
    assert s.evidence_quality == pytest.approx(1.00)
    assert s.score == pytest.approx(36.0)


def test_correlated_breadth_saturates_instead_of_adding():
    # relevance: 1 - (1-0.80)(1-0.70)(1-0.20) = 1 - 0.2*0.3*0.8 = 0.952
    # strength: 4 IPs -> 0.5 + 0.5 * log2(4)/4 = 0.75
    # score = 100 * 0.952 * 0.75 * 0.75 * 0.80 = 42.84
    s = score_account(AccountInput(signal_ids=frozenset({"S01", "S03", "S06"}), n_ips=4,
                                   attribution_confidence=0.75, evidence_quality=0.8))
    assert s.product_relevance == pytest.approx(0.952)
    assert s.signal_strength == pytest.approx(0.75)
    assert s.score == pytest.approx(42.84)


@pytest.mark.parametrize("n_ips, expected", [(0, 0.0), (1, 0.5), (2, 0.625), (16, 1.0), (500, 1.0)])
def test_strength_grows_with_distinct_ips_and_caps(n_ips, expected):
    s = score_account(AccountInput(frozenset({"S16"}), n_ips, 1.0, 1.0))
    assert s.signal_strength == pytest.approx(expected)


def test_abstained_or_zero_confidence_attribution_scores_zero():
    s = score_account(AccountInput(frozenset({"S01", "S03"}), 10, 0.0, 1.0))
    assert s.score == 0.0


def test_hygiene_and_technographics_alone_never_outrank_one_confirmed_exposure():
    # Review finding: S06 + S16 on 16+ IPs scored ~44, above one product-identified S01 gateway (36).
    broad_low_relevance = score_account(AccountInput(frozenset({"S06", "S16"}), 10_000, 0.9, 0.9))
    single_gateway = score_account(AccountInput(frozenset({"S01"}), 1, 0.9, 1.0))
    assert broad_low_relevance.score < single_gateway.score


# ----------------------------------------------------------------------------- scoring v3
# Opportunity priority, percentile, bands and actionability. The legacy v2 score above is kept
# unchanged so before/after comparisons stay reproducible.

from firmable.accounts.scoring import (actionability, evidence_quality_band, opportunity_priority,
                                       percentile_ranks, priority_band)


def test_priority_is_relevance_times_breadth_with_no_attribution_term():
    # 100 * 0.80 * 0.50 = 40.0, whatever the attribution confidence
    assert opportunity_priority(frozenset({"S01"}), 1) == pytest.approx(40.0)
    # 100 * 0.952 * 0.75 = 71.4
    assert opportunity_priority(frozenset({"S01", "S03", "S06"}), 4) == pytest.approx(71.4)
    assert opportunity_priority(frozenset(), 3) == 0.0


def test_same_evidence_under_different_attribution_gets_the_same_priority_but_not_the_same_legacy_score():
    strong = score_account(AccountInput(frozenset({"S01"}), 1, 0.9, 1.0))
    weak = score_account(AccountInput(frozenset({"S01"}), 1, 0.3, 1.0))
    assert strong.score != weak.score
    assert opportunity_priority(frozenset({"S01"}), 1) == opportunity_priority(frozenset({"S01"}), 1)


def test_percentile_is_share_strictly_below_and_ties_share_a_percentile():
    # values: 10, 10, 20, 40 -> below counts 0, 0, 2, 3 of 4
    assert percentile_ranks([20.0, 10.0, 40.0, 10.0]) == [50.0, 0.0, 75.0, 0.0]
    assert percentile_ranks([]) == []


def test_percentile_ignores_float_noise_below_four_decimals():
    assert percentile_ranks([40.00000001, 40.0, 10.0]) == [pytest.approx(100 / 3)] * 2 + [0.0]


@pytest.mark.parametrize("pct, exposure, band", [
    (99.0, True, "High"), (99.5, False, "Medium"), (98.99, True, "Medium"), (90.0, True, "Medium"),
    (89.99, True, "Low"), (0.0, False, "Low"),
])
def test_bands_cut_at_the_99th_and_90th_percentile_and_high_needs_an_exposure(pct, exposure, band):
    assert priority_band(pct, exposure) == band


@pytest.mark.parametrize("q, band", [(1.0, "high"), (0.9, "high"), (0.8, "medium"), (0.7, "medium"), (0.5, "low")])
def test_evidence_quality_band(q, band):
    assert evidence_quality_band(q) == band


def test_actionable_needs_eligibility_owned_evidence_no_flags_and_a_security_observation():
    assert actionability("eligible", "high", (), True) == (True, ())
    assert actionability("eligible", "medium", (), True) == (True, ())
    assert actionability("excluded", "low", (), True) == (False, ("excluded", "ownership_low"))
    assert actionability("eligible", "low", (), True) == (False, ("ownership_low",))
    assert actionability("eligible", "high", ("possible_network_provider",), True) == (
        False, ("review_flags",))
    assert actionability("eligible", "high", (), False) == (False, ("no_security_observation",))
