"""Account report and status (firmable.api.brief), from hand-written account rows."""

from __future__ import annotations

import re

import pytest

from firmable.api.brief import (build_brief, finding, main_finding, priority_sentence, research_state,
                                research_state_ref)
from firmable.signals import SIGNALS

FIELDS = ("name", "short_name", "family", "inferred_risk", "noun_one", "noun_many", "offering", "pitch", "opener")
REGISTRY = {s.id: {**{f: getattr(s, f) for f in FIELDS}, "discovery_questions": list(s.discovery_questions),
                   "confirm_on_call": list(s.confirm_on_call), "detail_notes": dict(s.detail_notes)}
            for s in SIGNALS}

# Report language is direct: no hedging, and no claim one scan cannot support about the account.
HEDGES = re.compile(r"\b(may|might|possibly|perhaps|usually not|not observed|not a weakness|depends on|"
                    r"not verified|inferred)\b", re.I)
ACCOUNT_CLAIMS = re.compile(r"\b(is|are) vulnerable\b|\bbreached\b|\bcompromised\b|\blegacy\b|\bintends? to\b|"
                            r"\bbudget\b", re.I)


def account(**over):
    row = dict(
        account_id="org:example", account_name="Example", account_kind="org", segment="enterprise",
        eligibility="eligible", eligibility_reasons=[], actionable=True, actionable_blockers=[],
        ownership_confidence="high", ownership_reasons=["record_names_account"], review_flags=[],
        named_public_services=4, ownership_services=40, named_rdns_services=0, third_party_domains=0,
        network_operators=1, subscriber_rdns_services=0, attribution_confidence=0.9,
        priority_percentile=99.43, n_services=7, n_ips=5, countries=["US", "CA"], top_signals=["S01", "S06"],
    )
    row.update(over)
    return row


def sig(signal_id, n_services=1, n_ips=1, details=(), sub_flags=(), counted=None, family=None):
    return dict(signal_id=signal_id, n_services=n_services, n_ips=n_ips,
                n_counted_services=n_services if counted is None else counted,
                details=list(details), sub_flags=list(sub_flags),
                family=family or next(s.family for s in SIGNALS if s.id == signal_id))


def _text(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [t for k, v in obj.items() if k not in ("signal_id", "code", "id", "level") for t in _text(v)]
    if isinstance(obj, list):
        return [t for v in obj for t in _text(v)]
    return []


@pytest.mark.parametrize("over, state", [
    ({}, "research_candidate"),
    ({"top_signals": ["S06", "S16"]}, "hygiene_only"),
    ({"actionable": False, "actionable_blockers": ["ownership_low"]}, "verify_ownership"),
    ({"actionable": False, "actionable_blockers": ["review_flags", "no_security_observation"]}, "verify_ownership"),
    ({"actionable": False, "actionable_blockers": ["no_security_observation"]}, "context_only"),
    ({"eligibility": "excluded", "actionable": False, "actionable_blockers": ["excluded"]}, "not_a_prospect"),
])
def test_status_follows_the_gate(over, state):
    assert research_state(account(**over)) == state


def test_status_labels_are_decisions():
    assert [research_state_ref(account(**o))["label"] for o in (
        {}, {"top_signals": ["S06"]}, {"actionable": False, "actionable_blockers": ["ownership_low"]},
        {"actionable": False, "actionable_blockers": ["no_security_observation"]},
        {"eligibility": "excluded", "actionable": False})] == [
        "Pursue", "Pursue for certificate management", "Confirm ownership first", "Monitor", "Do not pursue"]


def test_sql_server_browser_finding_states_exactly_what_it_is():
    f = finding(sig("S04", 2, 2, ["SQL Server Browser"]), REGISTRY["S04"])
    assert f["name"] == "Exposed data stores"
    assert f["what_we_saw"] == "2 services on 2 IP addresses: SQL Server Browser"
    assert any("lists SQL Server instance names and ports" in n for n in f["notes"])


def test_finding_aggregates_products_and_explains_counting():
    f = finding(sig("S06", 3, 2, ["Expired certificate"], ["cert_expired", "legacy_tls"], counted=1), REGISTRY["S06"])
    assert f["products"] == ["Expired certificate", "TLS 1.0/1.1 accepted"]
    assert f["phrase"] == "3 endpoints with certificate or TLS defects (Expired certificate and TLS 1.0/1.1 accepted)"
    assert f["counting_note"] == "2 of these services also carry a higher-priority finding and are counted there."
    many = finding(sig("S01", 6, 6, ["A", "B", "C", "D", "E", "F"]), REGISTRY["S01"])
    assert many["what_we_saw"].endswith("A, B, C, D and 2 more")
    assert many["opener"].startswith("Your remote access runs through internet-facing A, B, C and 3 more gateways")


def test_main_finding_prefers_the_use_case_then_security_then_relevance():
    sigs = [sig("S16", 9, 9, ["Cloudflare"]), sig("S06", 1, 1, ["Expired certificate"]), sig("S01", 1, 1, ["FortiGate"])]
    assert main_finding(sigs, REGISTRY)["signal_id"] == "S01"
    assert main_finding(sigs, REGISTRY, "certificate_management")["signal_id"] == "S06"
    assert main_finding([sig("S16", 1, 1, ["Cloudflare"])], REGISTRY)["context_only"] is True
    assert main_finding([sig("S16", 9, 9, ["Akamai"]), sig("S06")], REGISTRY)["signal_id"] == "S06"
    assert main_finding([sig("S16", 9, 9, ["Akamai"]), sig("S06")], REGISTRY, "vendor_footprint")["signal_id"] == "S16"
    assert main_finding([], REGISTRY) is None


def test_priority_sentence_names_its_population():
    assert priority_sentence(account(), "179,450 organisations") == "Top 1% of 179,450 organisations by exposure."
    assert priority_sentence(account(priority_percentile=90.0), "x") == "Top 10% of x by exposure."
    assert priority_sentence(account(priority_percentile=42.7), "x") == "Ranks above 42% of x by exposure."
    lens = {"uc_id": "remote_access", "uc_percentile": 95.2}
    assert priority_sentence(account(), "x", lens) == "Top 5% of x in Remote access security by exposure."
    assert priority_sentence(account(eligibility="excluded"), "x") == "Not ranked."


def test_report_leads_with_findings_threats_reasons_pitch_and_plan():
    sigs = [sig("S01", 3, 1, ["SonicWall"]), sig("S03", 47, 47, ["RDP", "VNC"]),
            sig("S04", 1, 1, ["SQL Server Browser"]), sig("S06", 9, 9, ["Expired certificate"]),
            sig("S16", 3, 3, ["Cloudflare"])]
    lenses = [{"uc_id": "remote_access", "uc_rank": 3, "uc_percentile": 99.1, "uc_signal_ids": ["S01", "S03"]}]
    b = build_brief(account(account_name="Example U", n_ips=60), sigs, REGISTRY, lenses, "2026-11-07",
                    "eligible enterprise accounts", "remote_access", lens_sizes={"remote_access": 1628},
                    population_size=179450)
    assert b["summary"] == (
        "Example U exposes 3 remote-access gateway services (SonicWall), 47 remote-administration logins "
        "(RDP and VNC) and 1 data-store service (SQL Server Browser) to the internet, and has 9 endpoints with "
        "certificate or TLS defects (Expired certificate), across 60 IP addresses. Lead with remote access "
        "security (ZTNA, MFA, gateway hardening).")
    assert [t["name"] for t in b["threats"]] == ["Remote-access gateways", "Remote-administration logins",
                                                 "Exposed data stores", "Certificate and TLS defects"]
    assert "most exploited entry point" in b["threats"][0]["threat"]
    assert b["why_target"][0] == "Top 1% of 179,450 organisations by exposure."
    assert b["why_target"][1] == "#3 of 1,628 in Remote access security."
    assert "Exposure in 3 categories" in b["why_target"][2]
    assert b["why_target"][3].startswith("Certificates, TLS names or web hostnames name this organisation on 4")
    assert b["pitch"]["lead_offering"].startswith("Remote access security")
    assert b["pitch"]["opener"].startswith("Your remote access runs through internet-facing SonicWall gateways")
    assert len(b["pitch"]["talking_points"]) == 3 and b["pitch"]["discovery_questions"][0].endswith("?")
    assert b["action_plan"][0].startswith("Qualify fit")
    assert b["action_plan"][1].startswith("Find the owner: head of IT infrastructure")
    assert b["action_plan"][-1] == "Evidence is from the 7 Nov 2026 scan; recheck an endpoint before quoting its address."
    assert "Gateway firmware version and patch level" in b["confirm_on_call"]
    assert b["competitive_context"]["vendors"] == ["Cloudflare"]
    assert b["ownership"]["label"] == "Strong"
    assert b["counts"]["services_with_findings"] == 7 and b["counts"]["all_attributed_services"] == 40
    for text in _text({k: v for k, v in b.items() if k not in ("findings", "counts", "source")}):
        assert not HEDGES.search(text), text
        assert not ACCOUNT_CLAIMS.search(text), text
        assert not re.search(r"\bS\d\d\b", text), text
        assert not re.search(r"\b(A1|A2|tier)\b", text), text
        assert "relevance" not in text.lower() and "actionable" not in text.lower(), text


def test_confirm_ownership_report_says_how():
    a = account(actionable=False, actionable_blockers=["ownership_low", "review_flags"], ownership_confidence="low",
                ownership_reasons=["registry_only"], review_flags=["possible_network_provider"],
                third_party_domains=30, named_public_services=1)
    b = build_brief(a, [sig("S03", 1, 1, ["RDP"])], REGISTRY, [], "2026-11-07", "x")
    assert b["research_state"]["label"] == "Confirm ownership first"
    assert b["action_plan"][0].startswith("Confirm ownership: only the IP registry ties these services")
    assert any("possible hosting or ISP" in s for s in b["action_plan"])
    assert b["ownership"]["label"] == "Unconfirmed"


def test_review_flags_alone_do_not_claim_ownership_is_missing():
    ref = research_state_ref(account(actionable=False, actionable_blockers=["review_flags"],
                                     ownership_confidence="medium"))
    assert ref["code"] == "verify_ownership" and "No certificate" not in ref["summary"]
    assert "review flags" in ref["summary"]


def test_certificate_only_and_monitor_plans():
    b = build_brief(account(top_signals=["S06"]), [sig("S06", 2, 2, ["Expired certificate"])], REGISTRY, [], None, "x")
    assert b["action_plan"][0] == "Pursue only if you sell certificate or TLS management."
    m = build_brief(account(actionable=False, actionable_blockers=["no_security_observation"], top_signals=["S16"]),
                    [sig("S16", 2, 2, ["Akamai"])], REGISTRY, [], None, "x")
    assert m["action_plan"][0].startswith("Do not open outreach") and m["pitch"] is None
    assert m["summary"] == "Example runs Akamai in front of its services. No exposure was found."


def test_tls_only_account_is_pursued_in_the_certificate_lens():
    a = account(top_signals=["S06"])
    assert research_state(a) == "hygiene_only"
    assert research_state(a, "certificate_management") == "research_candidate"
    assert research_state(a, "remote_access") == "hygiene_only"


def test_domain_accounts_do_not_report_an_attributed_service_total():
    b = build_brief(account(account_kind="domain", ownership_services=0), [], REGISTRY, [], None, None)
    assert b["counts"]["all_attributed_services"] is None and b["headline"] is None


def test_do_not_pursue_report():
    a = account(eligibility="excluded", eligibility_reasons=["registry_label_not_an_organisation"], actionable=False,
                actionable_blockers=["excluded"])
    lenses = [{"uc_id": "remote_access", "uc_rank": None, "uc_percentile": None, "uc_signal_ids": ["S01"]}]
    b = build_brief(a, [sig("S01")], REGISTRY, lenses, "2026-11-07", None)
    assert b["action_plan"] == ["Do not contact: the name is an IP-registry placeholder or pool label."]
    assert b["fit"]["use_cases"] == [] and b["why_target"] == []
