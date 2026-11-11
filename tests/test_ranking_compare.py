"""Offline ranking comparison helpers (evaluation only; no ground truth is implied)."""

import random

import pytest

from firmable.evaluation.ranking_compare import overlap, rank_candidate, rank_legacy, weight_variants


def test_overlap_is_share_of_the_first_k():
    assert overlap(["a", "b", "c"], ["c", "x", "a"], 2) == 0.0
    assert overlap(["a", "b", "c"], ["c", "x", "a"], 3) == pytest.approx(2 / 3)
    assert overlap([], [], 0) == 0.0


def test_weight_variants_move_one_weight_each_way_then_draw_joint_changes_deterministically():
    base = {"S01": 0.8, "S06": 0.2}
    v = weight_variants(base, 0.5, random.Random(1), n_random=3)
    labels = [label for label, _ in v]
    assert labels[:4] == ["S01+50%", "S01-50%", "S06+50%", "S06-50%"]
    assert dict(v)["S01+50%"] == {"S01": 0.95, "S06": 0.2}  # capped below 1
    assert dict(v)["S06-50%"] == {"S01": 0.8, "S06": 0.1}
    assert v == weight_variants(base, 0.5, random.Random(1), n_random=3)
    assert all(0.4 <= w["S01"] <= 0.95 and 0.1 <= w["S06"] <= 0.3 for _, w in v[4:])


def test_candidate_ranking_ignores_attribution_and_legacy_does_not():
    # account: (signals, n_ips, mean attribution, mean quality)
    summ = {"org:a": (frozenset({"S01"}), 1, 0.3, 1.0), "org:b": (frozenset({"S03"}), 1, 0.9, 1.0)}
    w = {"S01": 0.8, "S03": 0.7}
    assert rank_candidate(summ, summ, w) == ["org:a", "org:b"]   # 40 > 35
    assert rank_legacy(summ, summ, w) == ["org:b", "org:a"]      # 31.5 > 12
