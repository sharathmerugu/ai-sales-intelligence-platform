"""Use-case lenses: membership, counting and ranking (firmable.accounts.use_cases)."""

from __future__ import annotations

from firmable.accounts.scoring import opportunity_priority
from firmable.accounts.use_cases import USE_CASES, USE_CASES_BY_ID, lens_rows, rank_lenses, row_counts_in


def ev(account, signal, service, ip, basis="product", counted=True, suppressed_by=None):
    return dict(account_id=account, signal_id=signal, service_id=service, ip=ip, match_basis=basis,
                counted=counted, suppressed_by=suppressed_by)


def by(rows, account, lens):
    return next((r for r in rows if r["account_id"] == account and r["use_case"] == lens), None)


def test_every_lens_uses_only_implemented_signals():
    from firmable.signals import SIGNALS_BY_ID
    for u in USE_CASES:
        assert u.signals and set(u.signals) <= set(SIGNALS_BY_ID), u.id


def test_row_suppressed_by_a_signal_outside_the_lens_counts_inside_it():
    data = USE_CASES_BY_ID["data_security"]
    exposure = USE_CASES_BY_ID["exposure_management"]
    # S04 on a service that is also an S01 gateway: the roll-up counts S01 only.
    assert row_counts_in(data, "S04", counted=False, suppressed_by="S01")
    assert not row_counts_in(exposure, "S04", counted=False, suppressed_by="S01")  # S01 is in the lens
    assert not row_counts_in(data, "S01", counted=True, suppressed_by=None)


def test_lens_priority_uses_lens_signals_and_lens_ips_only():
    rows = lens_rows([
        ev("a", "S01", "s1", "10.0.0.1"),
        ev("a", "S06", "s2", "10.0.0.2", basis="tls"),
        ev("a", "S06", "s3", "10.0.0.3", basis="tls"),
    ])
    remote = by(rows, "a", "remote_access")
    assert remote["signal_ids"] == ["S01"] and remote["n_ips"] == 1 and remote["n_services"] == 1
    assert remote["priority"] == opportunity_priority(frozenset({"S01"}), 1)
    cert = by(rows, "a", "certificate_management")
    assert cert["n_ips"] == 2 and cert["priority"] == opportunity_priority(frozenset({"S06"}), 2)
    assert by(rows, "a", "data_security") is None


def test_one_service_is_counted_once_per_lens():
    rows = lens_rows([
        ev("a", "S04", "s1", "10.0.0.1"),
        ev("a", "S05", "s1", "10.0.0.1", counted=False, suppressed_by="S04"),
    ])
    exposure = by(rows, "a", "exposure_management")
    assert exposure["signal_ids"] == ["S04"] and exposure["n_services"] == 1
    # the S05 row was suppressed by S04, which is outside the console lens: it counts there
    assert by(rows, "a", "admin_consoles")["signal_ids"] == ["S05"]


def test_security_lens_needs_a_match_above_a_scanner_tag():
    rows = lens_rows([ev("a", "S04", "s1", "10.0.0.1", basis="tag"),
                      ev("b", "S04", "s2", "10.0.0.2", basis="tag"), ev("b", "S04", "s3", "10.0.0.3")])
    assert by(rows, "a", "data_security") is None
    b = by(rows, "b", "data_security")
    assert b["n_services"] == 2 and b["evidence_quality"] == 0.75


def test_vendor_lens_takes_technographics_without_a_quality_bar():
    rows = lens_rows([ev("a", "S16", "s1", "10.0.0.1", basis="waf")])
    assert by(rows, "a", "vendor_footprint")["signal_ids"] == ["S16"]
    assert USE_CASES_BY_ID["vendor_footprint"].context_only


def test_ranking_is_per_lens_and_segment_over_eligible_accounts_with_quality_before_size():
    rows = lens_rows([
        ev("big", "S01", "b1", "10.0.1.1", basis="title"), ev("big", "S01", "b2", "10.0.1.2", basis="title"),
        ev("good", "S01", "g1", "10.0.2.1"), ev("good", "S01", "g2", "10.0.2.2"),
        ev("small", "S01", "m1", "10.0.3.1"),
        ev("gone", "S01", "x1", "10.0.4.1"), ev("gone", "S01", "x2", "10.0.4.2"),
        ev("net", "S01", "n1", "10.0.5.1"),
    ])
    accounts = {"big": dict(segment="enterprise", eligibility="eligible"),
                "good": dict(segment="enterprise", eligibility="eligible"),
                "small": dict(segment="enterprise", eligibility="eligible"),
                "gone": dict(segment="enterprise", eligibility="excluded"),
                "net": dict(segment="network_provider", eligibility="eligible")}
    ranked = [r for r in rank_lenses(rows, accounts) if r["use_case"] == "remote_access"]
    ent = [(r["account_id"], r["rank"]) for r in ranked if r["segment"] == "enterprise"]
    # equal priority (2 IPs each): stronger match basis first; excluded accounts are unranked, last
    assert ent == [("good", 1), ("big", 2), ("small", 3), ("gone", None)]
    assert by(ranked, "small", "remote_access")["percentile"] == 0.0
    assert by(ranked, "good", "remote_access")["percentile"] == by(ranked, "big", "remote_access")["percentile"]
    assert by(ranked, "net", "remote_access")["rank"] == 1  # own segment
