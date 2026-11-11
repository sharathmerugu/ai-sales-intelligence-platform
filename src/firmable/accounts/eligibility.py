"""Account eligibility and ownership confidence (eligibility v2, part of scoring v3).

Two questions the opportunity priority must not answer by itself:

- **Eligibility**: does this account belong in the prospect population at all? The enterprise top 100
  of scoring v2 held IP-registry placeholders and ISP subscriber-pool labels ("Leased Line Customer
  LAN", "leased=false", "ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE"). An account is excluded only
  when three independent things agree:
    1. its name is a registry placeholder or pool label (`is_registry_label`);
    2. no scanned record names it (no certificate, SNI, Host or reverse-DNS name matches it);
    3. a structural sign: a sub-allocation inside a provider network (tier A2), the same label
       registered under >= 3 network operators, or >= 20% of its services carrying subscriber
       reverse DNS (an access label or the operator's own zone).
  A name pattern alone never excludes, and structural signs alone never exclude a real name: those
  accounts stay eligible with review flags.

- **Ownership confidence**: how strongly the records tie the services to the account. For org
  accounts (tiers A1/A2) it comes from records that name the account: `high` when a certificate
  (subject O, CN, SAN), SNI or HTTP Host does, `medium` when only reverse DNS does, `low` when only
  the IP registry does. Domain accounts (tier B) keep the existing attribution cut points
  (`confidence_band`: >= 0.75 high, >= 0.5 medium). Network providers' own infrastructure (tier P)
  is high by construction (their own domain is on the record).

- **Review flags** keep an account eligible but out of the outreach list until a person clears them:
  `possible_network_provider` (records name >= 10 other organisations' domains, more than 10x the
  services whose certificate, SNI or Host names the account: a hoster's own portal among its
  tenants), `registry_label_name`, and, when no record names the account, `label_spans_network_operators`
  and `subscriber_reverse_dns`.

NTLM never contributes here (ADR 0007). All thresholds are documented hypotheses chosen from the
2026-11-07 profile (docs/ranking-v3.md), not fitted to labels; none exist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..attribution.text import fold_name

ELIGIBILITY_VERSION = 2  # v2: names accent-folded (is_registry_label, network_operators), attribution v5

MIN_LABEL_OPERATORS = 3        # one label registered under this many network operators is not one network
SUBSCRIBER_RDNS_SHARE = 0.2    # share of services with subscriber / operator-zone reverse DNS
MULTI_TENANT_MIN_DOMAINS = 10  # third-party domains on the records ...
MULTI_TENANT_RATIO = 10        # ... and more than this many per service whose record names the account
DOMAIN_HIGH, DOMAIN_MEDIUM = 0.75, 0.5   # = service_attribution.confidence_band cut points

# Registry placeholders and access-network pool labels. Searched in the folded name (`fold_name`: ASCII
# literals only). Bare words
# that also occur in company names ("home", "dynamic", "assigned") only count in pool phrases.
_REGISTRY_LABEL = re.compile("|".join([
    r"subscriber", r"customer", r"leased[ _-]?lines?", r"leased=", r"lease line", r"\bpools?\b", r"-pool\b",
    r"pool-", r"dynamic[ _-]?(pool|ip|address|assignment|links?|cgn)", r"dhcp", r"\b[avx]?dsl\b", r"\bbras\b",
    r"residential", r"\bb2[bc]\b", r"\bhsi\b", r"\bggsn\b", r"wimax", r"pppoe", r"\bftt[hxbc]\b", r"\bgpon\b",
    r"\bcgn(at)?\b", r"dial[ _-]?up", r"\bnas\b", r"\b[lw]an[ _-]range\b", r"static[ _-]?(ip|pool|subscriber|address)",
    r"assigned[ _-](ip|pa\b|by\b|statically)", r"ip[ _-]addresses[ _-](are|assigned)", r"addresses within this",
    r"non-portable", r"transferred from", r"whois database", r"local registry", r"^entreprise$",
    r"^(core )?infrastructure$", r"end[ _-]users?\b", r"\w-home\b", r"home[ _-](subscribers|users|static|clients)",
]))
# A label that names one specific organisation is that organisation's block, never a placeholder:
# a legal form, or "Customer - <name>" / "Customers (<name>)".
_NAMES_ORGANISATION = re.compile("|".join([
    r"\b(ltd|limited|llc|inc|gmbh|ug|bvba|corp|corporation|plc|pty|kommune|kft|oy|ab)\b",
    r"\ba\.s\.?(\s|$)", r"\bs\.a\.", r"\bs\.p\.a\.", r"\bb\.v\.", r"\bco\.", r"sdn\.? ?bhd",
    r"customers?\s+-\s+\w", r"customers?\s*\((?!\s*/)[^)]*[a-z]{3}",
]))


def is_registry_label(name: str | None) -> bool:
    """True when `name` reads as a registry placeholder or pool label and names no organisation."""
    o = fold_name(name).strip()
    return bool(o) and bool(_REGISTRY_LABEL.search(o)) and not _NAMES_ORGANISATION.search(o)


@dataclass(frozen=True)
class OwnershipEvidence:
    """What the records say about who owns an account's services (all attributed services, not
    only those with signals)."""

    account_kind: str                 # "org" or "domain"
    best_tier: str                    # A1, A2, P or B
    account_name: str
    n_services: int
    named_public_services: int        # certificate O/CN/SAN, SNI or HTTP Host names the account
    named_rdns_services: int          # reverse-DNS hostname names the account
    third_party_domains: int          # distinct accepted domains in certificate/SNI/Host naming others
    network_operators: int            # distinct ISP names the services sit under
    subscriber_rdns_services: int     # reverse DNS with an access label or in the operator's own zone
    mean_attribution_confidence: float


@dataclass(frozen=True)
class Assessment:
    eligibility: str                  # "eligible" or "excluded"
    eligibility_reasons: tuple[str, ...]
    ownership_confidence: str         # "high", "medium" or "low"
    ownership_reasons: tuple[str, ...]
    review_flags: tuple[str, ...]


def _domain_band(conf: float) -> str:
    return "high" if conf >= DOMAIN_HIGH else "medium" if conf >= DOMAIN_MEDIUM else "low"


def assess(e: OwnershipEvidence) -> Assessment:
    if e.account_kind == "domain":
        return Assessment("eligible", (), _domain_band(e.mean_attribution_confidence),
                          ("tenant_domain_named_by_record",), ())
    if e.best_tier == "P":
        return Assessment("eligible", (), "high", ("provider_own_domain",), ())

    if e.named_public_services > 0:
        ownership, why = "high", "record_names_account"
    elif e.named_rdns_services > 0:
        ownership, why = "medium", "reverse_dns_names_account"
    else:
        ownership, why = "low", "registry_only"
    named = ownership != "low"

    structural = []
    if not named:
        if e.best_tier == "A2":
            structural.append("sub_allocation_in_provider_network")
        if e.network_operators >= MIN_LABEL_OPERATORS:
            structural.append("label_spans_network_operators")
        if e.n_services and e.subscriber_rdns_services >= SUBSCRIBER_RDNS_SHARE * e.n_services:
            structural.append("subscriber_reverse_dns")
    label = is_registry_label(e.account_name)
    if label and not named and structural:
        return Assessment("excluded", ("registry_label_not_an_organisation", *structural), ownership, (why,), ())

    flags = []
    if label:
        flags.append("registry_label_name")
    if (e.third_party_domains >= MULTI_TENANT_MIN_DOMAINS
            and e.third_party_domains > MULTI_TENANT_RATIO * e.named_public_services):
        flags.append("possible_network_provider")
    flags += [s for s in structural if s != "sub_allocation_in_provider_network"]
    return Assessment("eligible", (), ownership, (why,), tuple(flags))
