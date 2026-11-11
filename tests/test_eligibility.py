"""Account eligibility and ownership confidence (accounts layer, eligibility v1).

Cases are real registrant-label shapes from the 2026-11-07 profile (docs/ranking-v3.md), written
by hand. Exclusion needs a placeholder label AND no record naming the account AND a structural
sign; a name pattern alone never excludes.
"""

import pytest

from firmable.accounts.eligibility import OwnershipEvidence, assess, is_registry_label


def org(name, tier="A1", n=100, public=0, rdns=0, third=0, operators=1, subscriber=0, conf=0.9):
    return OwnershipEvidence(account_kind="org", best_tier=tier, account_name=name, n_services=n,
                             named_public_services=public, named_rdns_services=rdns, third_party_domains=third,
                             network_operators=operators, subscriber_rdns_services=subscriber,
                             mean_attribution_confidence=conf)


@pytest.mark.parametrize("name", [
    "Leased Line- LAN Range", "Leased Line Customer LAN", "Cellucar subscribers for GGSN", "B2B",
    "Urban Wimax Assigned IP Address", "UNIFI-HOME", "ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE",
    "data has been transferred from RIPE Whois Database 20050221", "leased=false", "Entreprise",
    "PROVIDER Local Registry", "Core Infrastructure", "NAS DHCP Pool Brescia", "Kabel Deutschland Breitband Customer 21",
    "customers1", "CustomerLAN", "BRAS Pools - Jaipur", "IP addresses are assigned statically", "PPPoE RS 12",
])
def test_placeholder_and_pool_labels_are_recognised(name):
    assert is_registry_label(name)


@pytest.mark.parametrize("name", [
    # real organisations whose names contain pool-like words
    "Home Credit a.s.", "NeuroSync Dynamics LLC", "Address block assigned to Foster Clarks Ltd",
    "TeleCity Group Customer - Core Technology Systems", "Get AS Customers (Meldal Kommune)",
    "BOL Customer - Badsha Textiles", "Splash-Pool UG (haftungsbeschraenkt)", "Springfield Home Care Services/Baylea",
    "Home&Garden", "Customer Care Solutions Ltd", "B2B TS a.s Frýdek-Místek", "GGSNET",
    # ordinary enterprises
    "McGill University", "SAP SE", "Government of Alberta", "Blue Ridge Mountain Electric Membership Corporation",
    "San Jose",
])
def test_names_of_specific_organisations_are_not_labels(name):
    assert not is_registry_label(name)


def test_pool_label_inside_a_provider_network_with_no_naming_record_is_excluded():
    a = assess(org("Leased Line Customer LAN", tier="A2"))
    assert a.eligibility == "excluded"
    assert "registry_label_not_an_organisation" in a.eligibility_reasons
    assert "sub_allocation_in_provider_network" in a.eligibility_reasons


def test_placeholder_registered_under_many_operators_is_excluded_even_when_tier_a1():
    a = assess(org("leased=false", tier="A1", operators=30))
    assert a.eligibility == "excluded"
    assert "label_spans_network_operators" in a.eligibility_reasons


def test_placeholder_with_subscriber_reverse_dns_is_excluded():
    a = assess(org("B2B", tier="A1", n=100, subscriber=20))
    assert a.eligibility == "excluded"
    assert "subscriber_reverse_dns" in a.eligibility_reasons


def test_label_alone_never_excludes_without_a_structural_sign():
    # A1 on its own network, one operator, no subscriber rDNS: kept, but ownership is registry only.
    a = assess(org("Entreprise", tier="A1"))
    assert a.eligibility == "eligible"
    assert a.ownership_confidence == "low"
    assert "registry_label_name" in a.review_flags


def test_a_record_naming_the_account_keeps_a_label_like_name_eligible():
    a = assess(org("B2B", tier="A2", public=3))
    assert a.eligibility == "eligible"
    assert a.ownership_confidence == "high"


def test_structural_signs_alone_never_exclude_a_real_name():
    # A real organisation inside a provider network, under several operators, nothing names it:
    # it stays eligible for review, it is not removed.
    a = assess(org("Pemerintah Daerah Provinsi Kalimantan Timur", tier="A2", operators=4, subscriber=50))
    assert a.eligibility == "eligible"
    assert a.ownership_confidence == "low"
    assert {"label_spans_network_operators", "subscriber_reverse_dns"} <= set(a.review_flags)


@pytest.mark.parametrize("public, rdns, expected, reason", [
    (5, 0, "high", "record_names_account"),
    (0, 7, "medium", "reverse_dns_names_account"),
    (0, 0, "low", "registry_only"),
])
def test_org_ownership_confidence_comes_from_naming_records(public, rdns, expected, reason):
    a = assess(org("University of Example", public=public, rdns=rdns))
    assert a.ownership_confidence == expected
    assert reason in a.ownership_reasons


def test_many_third_party_domains_and_no_public_name_flags_a_possible_provider_but_keeps_it():
    # Universities and governments that host others are real prospects; this is a review flag only.
    a = assess(org("Irish Government", rdns=3, third=11))
    assert a.eligibility == "eligible"
    assert a.ownership_confidence == "medium"
    assert "possible_network_provider" in a.review_flags


def test_third_party_domains_do_not_flag_an_account_that_records_name():
    a = assess(org("SAP SE", public=67, third=60, operators=5))
    assert a.review_flags == ()
    # a university naming itself on 1 of 423 services among 10 other domains: not 10x, not flagged
    assert assess(org("Chulalongkorn University", n=423, public=1, third=10)).review_flags == ()


def test_a_hoster_named_on_a_couple_of_services_among_dozens_of_tenant_domains_is_flagged():
    # its own portal certificate names it twice; 62 customer domains: more than 10x
    a = assess(org("Acens Technologies S.L.", n=185, public=2, rdns=65, third=62))
    assert (a.eligibility, a.ownership_confidence) == ("eligible", "high")
    assert a.review_flags == ("possible_network_provider",)


@pytest.mark.parametrize("conf, expected", [(0.85, "high"), (0.75, "high"), (0.6, "medium"), (0.5, "medium"),
                                            (0.45, "low"), (0.25, "low")])
def test_domain_account_ownership_uses_the_existing_confidence_band_cut_points(conf, expected):
    a = assess(OwnershipEvidence(account_kind="domain", best_tier="B", account_name="example.com", n_services=3,
                                 named_public_services=0, named_rdns_services=0, third_party_domains=0,
                                 network_operators=1, subscriber_rdns_services=0, mean_attribution_confidence=conf))
    assert (a.eligibility, a.ownership_confidence) == ("eligible", expected)
    assert "tenant_domain_named_by_record" in a.ownership_reasons


def test_network_provider_own_infrastructure_is_high_ownership():
    a = assess(org("Skyway West", tier="P", conf=0.8))
    assert (a.eligibility, a.ownership_confidence) == ("eligible", "high")
    assert "provider_own_domain" in a.ownership_reasons


@pytest.mark.parametrize("name, label", [
    ("RESİDENTİAL", True),                          # Turkish dotted capital I: lower() gives i + U+0307
    ("WİMAX ABONELERİ", True),
    ("Frýdek-Místek B2B", True),
    ("B2B TS a.s Frýdek-Místek", False),            # names an organisation (legal form)
    ("Société Générale", False),
])
def test_is_registry_label_folds_accents(name, label):
    assert is_registry_label(name) is label
