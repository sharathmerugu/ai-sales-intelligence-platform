"""Review metrics: computed from manual labels only; model suggestions are reported separately.

Expected values are worked by hand from the rows below.
"""

from __future__ import annotations

import pytest

from firmable.evaluation.review import LABEL_COLUMNS, review_metrics


def case(case_id, strata, baseline_rank=None, enriched_rank=None, segment="enterprise", tier="A1", **labels):
    row = {"case_id": case_id, "strata": strata, "baseline_rank": baseline_rank, "enriched_rank": enriched_rank,
           "segment": segment, "best_tier": tier}
    for c in LABEL_COLUMNS:
        row[f"manual_{c}"] = labels.get(c, "")
        row[f"suggested_{c}"] = labels.get(f"s_{c}", "")
    return row


ROWS = [
    # top of both lists
    case("a", "top40_baseline;top40_enriched", 1, 1, qualified="yes", entity_type="enterprise",
         attribution_correct="yes", evidence_supported="yes", s_qualified="yes"),
    # an ISP the baseline ranked 2nd; enrichment moved it out of the enterprise list
    case("b", "top40_baseline;asn_reclassified", 2, None, segment="network_provider", tier="P",
         qualified="no", entity_type="network_provider", attribution_correct="yes", evidence_supported="yes",
         s_qualified="no"),
    case("c", "top40_enriched", 30, 2, qualified="yes", entity_type="enterprise", s_qualified="no"),
    case("d", "top40_enriched", None, 3, qualified="unclear", entity_type="enterprise"),
    case("e", "top40_baseline", 3, 50),                                  # not yet reviewed
    case("f", "tier_b_sample", None, 900, tier="B", attribution_correct="no", evidence_supported="yes"),
    case("g", "abstain_sample", tier="C", attribution_correct="yes"),    # abstaining was right
    case("h", "abstain_sample", tier="C", attribution_correct="no"),     # a company was identifiable
]


def test_precision_at_k_uses_manual_labels_and_reports_coverage():
    m = review_metrics(ROWS, source="manual", ks=(3,))
    assert m["source"] == "manual"
    # baseline top-3 = a, b, e: a yes, b no, e unlabeled -> 1 of 2 labeled
    assert m["precision_at_k"]["baseline"][3] == {"qualified": 1, "labeled": 2, "k": 3, "precision": 0.5}
    # enriched top-3 = a, c, d: yes, yes, unclear (unclear counts as not qualified) -> 2 of 3
    assert m["precision_at_k"]["enriched"][3] == {"qualified": 2, "labeled": 3, "k": 3, "precision": 0.6667}


def test_suggestions_never_mix_with_manual_labels():
    m = review_metrics(ROWS, source="suggested", ks=(3,))
    assert m["source"] == "suggested"
    assert m["precision_at_k"]["baseline"][3] == {"qualified": 1, "labeled": 2, "k": 3, "precision": 0.5}
    assert m["precision_at_k"]["enriched"][3] == {"qualified": 1, "labeled": 2, "k": 3, "precision": 0.5}


def test_segment_attribution_abstention_and_evidence_rates():
    m = review_metrics(ROWS, source="manual", ks=(3,))
    # system segment vs reviewed entity type over labeled cases: a, b, c, d all agree
    assert m["segment_agreement"] == {"agree": 4, "labeled": 4, "rate": 1.0}
    assert m["asn_reclassified_provider_rate"] == {"provider": 1, "labeled": 1, "rate": 1.0}
    # attributed cases (tiers A1/A2/P/B), split by build: a, b (now tier P) and f are enriched accounts
    assert m["attribution_precision"] == {"enriched": {"correct": 2, "labeled": 3, "rate": 0.6667},
                                          "baseline_only": {"correct": 0, "labeled": 0, "rate": None}}
    # abstentions: g right, h missed a company
    assert m["abstention_correct"] == {"correct": 1, "labeled": 2, "rate": 0.5}
    assert m["evidence_support"] == {"supported": 3, "labeled": 3, "rate": 1.0}
    assert m["cases"] == 8 and m["cases_labeled"] == 7


def test_unknown_source_is_refused():
    with pytest.raises(ValueError):
        review_metrics(ROWS, source="model")
