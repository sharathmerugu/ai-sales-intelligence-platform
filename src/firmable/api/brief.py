"""Salesperson account report (docs/sales-brief.md §5).

A direct report in the order a salesperson acts on it: status, summary of what we found, the threat
each finding represents, why to target the account, the pitch, the action plan, then supporting
evidence. It is built only from fields the accounts layer computed and from the signal registry's
wording, and adds no score. Threats are stated at the device-class level; the report never says the
account is vulnerable, breached or buying (one scan cannot show that). Codes, tiers and formulas
stay in the technical fields.
"""

from __future__ import annotations

import math
from datetime import date
from typing import Any

from ..accounts.rollup import EXCLUSION_TEXT, FLAG_TEXT
from ..accounts.scoring import EXPOSURE_SIGNALS, RELEVANCE
from ..accounts.use_cases import USE_CASES, USE_CASES_BY_ID

# Status replaces the pre-v4 "actionable outreach". Codes are stable API values; labels are copy.
RESEARCH_STATES: dict[str, dict[str, str]] = {
    "research_candidate": {
        "label": "Pursue",
        "summary": "Strong ownership link and exposed infrastructure. Qualify fit and reach out.",
    },
    "hygiene_only": {
        "label": "Pursue for certificate management",
        "summary": "Owned by this organisation; its findings are certificate and TLS defects. Pursue for "
                   "certificate and TLS products only.",
    },
    "verify_ownership": {
        "label": "Confirm ownership first",
        "summary": "No certificate or hostname ties these services to this organisation yet. Confirm ownership "
                   "before outreach.",
    },
    "context_only": {
        "label": "Monitor",
        "summary": "Linked to this organisation, with no exposure strong enough to open a conversation. Keep as "
                   "account context.",
    },
    "not_a_prospect": {
        "label": "Do not pursue",
        "summary": "Not an organisation: a registry placeholder, pool label or provider sub-allocation.",
    },
}
VERIFY_FLAGS_ONLY = "Records name this organisation, but review flags are open. Clear them before outreach."
OWNERSHIP_LABEL = {"high": "Strong", "medium": "Probable", "low": "Unconfirmed"}
# Who to reach, by the finding that leads the pitch.
BUYER = {
    "S01": "head of IT infrastructure or network security",
    "S03": "head of IT infrastructure or the identity and access lead",
    "S04": "the data platform owner and the CISO",
    "S05": "head of platform engineering or DevOps, and the CISO",
    "S06": "the PKI or infrastructure owner",
    "S16": "the CISO or security architecture lead",
}
# Same text as the S06 detail labels (registry `detail_sql`), so a flag already named as a detail is not repeated.
SUB_FLAG_TEXT = {
    "cert_expired": "Expired certificate",
    "legacy_tls": "TLS 1.0/1.1 accepted",
    "ssl_v2_v3": "SSLv2/SSLv3 accepted",
    "weak_rsa_key": "RSA key < 2048 bits",
    "weak_signature": "SHA-1/MD5 signature",
    "self_signed_http": "Self-signed certificate",
    "waf": "web application firewall",
    "appliance": "security appliance",
}
POPULATION_NOUN = {"enterprise": "organisations", "network_provider": "network providers"}
MAX_DETAILS = 4
MAX_CONFIRM = 6
MAX_QUESTIONS = 5
MAX_TALKING_POINTS = 3


def has_exposure(account: dict[str, Any]) -> bool:
    """A counted exposure signal (gateway, remote administration, data store, console); `top_signals`
    holds the counted signals."""
    return bool(set(account.get("top_signals") or []) & EXPOSURE_SIGNALS)


def research_state(account: dict[str, Any], use_case: str | None = None) -> str:
    """Status from the scoring-v3 gate (`actionable`, `actionable_blockers`, eligibility) plus whether
    the gate passed on an exposure or on certificate / TLS findings alone. In the certificate lens TLS
    findings are the reason to pursue."""
    if account["eligibility"] == "excluded":
        return "not_a_prospect"
    if account["actionable"]:
        lens = USE_CASES_BY_ID.get(use_case or "")
        if has_exposure(account) or (lens is not None and lens.hygiene_is_the_finding):
            return "research_candidate"
        return "hygiene_only"
    blockers = set(account.get("actionable_blockers") or [])
    if blockers & {"ownership_low", "review_flags"}:
        return "verify_ownership"
    return "context_only"


def research_state_ref(account: dict[str, Any], use_case: str | None = None) -> dict[str, str]:
    code = research_state(account, use_case)
    ref = {"code": code, **RESEARCH_STATES[code]}
    if code == "verify_ownership" and "ownership_low" not in (account.get("actionable_blockers") or []):
        ref["summary"] = VERIFY_FLAGS_ONLY
    return ref


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _join(items: list[str], limit: int = MAX_DETAILS) -> str:
    shown = items[:limit]
    more = len(items) - len(shown)
    if more > 0:
        return ", ".join(shown) + f" and {more} more"
    return shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " and " + shown[-1] if shown else ""


def _scan_date(snapshot_id: str | None) -> str:
    try:
        d = date.fromisoformat(snapshot_id or "")
    except ValueError:
        return snapshot_id or "the scan date"
    return f"{d.day} {d.strftime('%b %Y')}"


def ownership_sentence(account: dict[str, Any]) -> str:
    """What ties the services to the organisation, stated as the evidence."""
    reasons = account.get("ownership_reasons") or []
    n_named, n_all = account.get("named_public_services") or 0, account.get("ownership_services") or 0
    if "record_names_account" in reasons:
        return (f"Certificates, TLS names or web hostnames name this organisation on {n_named:,} of its "
                f"{n_all:,} services.")
    if "reverse_dns_names_account" in reasons:
        return (f"Reverse-DNS names on {account.get('named_rdns_services') or 0:,} of its {n_all:,} services name "
                "this organisation; no certificate does yet.")
    if "tenant_domain_named_by_record" in reasons:
        return "The services' own certificates and hostnames name this domain."
    if "provider_own_domain" in reasons:
        return "The provider's own domain is on its services' records."
    if "registry_only" in reasons:
        return "Only the IP registry names this organisation; no certificate or hostname confirms it."
    return "No record ties these services to the organisation."


def _fill(template: str, details: list[str], sig: dict[str, Any]) -> str:
    return (template.replace("{details}", _join(details, 3) or "these")
            .replace("{n_ips}", f"{sig['n_ips']:,}").replace("{n_services}", f"{sig['n_services']:,}"))


def _counting_note(n: int) -> str | None:
    if n <= 0:
        return None
    if n == 1:
        return "1 of these services also carries a higher-priority finding and is counted there."
    return f"{n:,} of these services also carry a higher-priority finding and are counted there."


def finding(sig: dict[str, Any], reg: dict[str, Any]) -> dict[str, Any]:
    """One signal on one account, aggregated over its services."""
    details = list(sig.get("details") or [])
    flags = [SUB_FLAG_TEXT.get(f, f) for f in (sig.get("sub_flags") or [])]
    if sig["signal_id"] == "S06":
        details += [f for f in flags if f not in details]
    n_services, n_ips = sig["n_services"], sig["n_ips"]
    counted = sig.get("n_counted_services") or 0
    notes = reg.get("detail_notes") or {}
    noun = reg.get("noun_one") if n_services == 1 else reg.get("noun_many")
    family = sig.get("family") or reg.get("family")
    return {
        "signal_id": sig["signal_id"],
        "name": reg.get("short_name") or reg.get("name") or sig["signal_id"],
        "family": family,
        "count": f"{_plural(n_services, 'service')} on {_plural(n_ips, 'IP address', 'IP addresses')}",
        "phrase": f"{n_services:,} {noun or 'services'}" + (f" ({_join(details, 3)})" if details else ""),
        "products": details,
        "what_we_saw": (f"{_plural(n_services, 'service')} on {_plural(n_ips, 'IP address', 'IP addresses')}"
                        + (f": {_join(details)}" if details else "")),
        "notes": [notes[d] for d in details if d in notes],
        "threat": reg.get("inferred_risk"),
        "offering": reg.get("offering"),
        "pitch": reg.get("pitch"),
        "opener": _fill(reg.get("opener") or "", details, sig) or None,
        "discovery_questions": list(reg.get("discovery_questions") or []),
        "confirm_on_call": list(reg.get("confirm_on_call") or []),
        "n_services": n_services,
        "n_ips": n_ips,
        "n_counted_services": counted,
        "counting_note": _counting_note(n_services - counted),
        "context_only": family == "technographic",
    }


def order_findings(sigs: list[dict[str, Any]], use_case: str | None = None) -> list[dict[str, Any]]:
    """Lens signals first, then security before technographics, then commercial relevance, then breadth."""
    lens = set(USE_CASES_BY_ID[use_case].signals) if use_case in USE_CASES_BY_ID else set()
    return sorted(sigs, key=lambda s: (s["signal_id"] not in lens, s.get("family") == "technographic",
                                       -RELEVANCE.get(s["signal_id"], 0.0), -s["n_ips"], s["signal_id"]))


def main_finding(sigs: list[dict[str, Any]], registry: dict[str, dict[str, Any]],
                 use_case: str | None = None) -> dict[str, Any] | None:
    """The strongest relevant finding, for a list row."""
    ordered = order_findings(sigs, use_case)
    if not ordered:
        return None
    f = finding(ordered[0], registry.get(ordered[0]["signal_id"], {}))
    return {"signal_id": f["signal_id"], "name": f["name"], "what_we_saw": f["what_we_saw"],
            "context_only": f["context_only"]}


def priority_sentence(account: dict[str, Any], population: str | None, lens: dict[str, Any] | None = None) -> str:
    """Where the account ranks, against a named population."""
    if account["eligibility"] == "excluded":
        return "Not ranked."
    pct, scope = account.get("priority_percentile"), population or "accounts"
    if lens is not None:
        pct = lens.get("uc_percentile")
        scope = f"{population or 'accounts'} in {USE_CASES_BY_ID[lens['uc_id']].name}"
        if pct is None:
            return "Not ranked in this use case."
    if pct is None:
        return "Not ranked."
    top = max(1, math.ceil(100 - pct))
    if top <= 10:
        return f"Top {top}% of {scope} by exposure."
    if int(pct) == 0:
        return f"Lowest exposure tier of {scope}."
    return f"Ranks above {int(pct)}% of {scope} by exposure."


def _summary(account: dict[str, Any], security: list[dict[str, Any]], vendors: dict[str, Any] | None,
             lead: dict[str, Any] | None) -> str:
    name = account.get("account_name") or account["account_id"]
    if not security:
        if vendors:
            return f"{name} runs {_join(vendors['products'], 3)} in front of its services. No exposure was found."
        return f"No security finding is linked to {name}."
    exposures = [f for f in security if f["signal_id"] != "S06"]
    tls = next((f for f in security if f["signal_id"] == "S06"), None)
    parts = [f["phrase"] for f in exposures]
    text = f"{name} exposes {_join(parts, 5)} to the internet" if parts else f"{name} has {tls['phrase']}"
    if parts and tls:
        text += f", and has {tls['phrase']}"
    text += f", across {_plural(account['n_ips'], 'IP address', 'IP addresses')}."
    if lead and lead.get("offering"):
        text += f" Lead with {lead['offering'][0].lower() + lead['offering'][1:]}."
    return text


def _action_plan(state: dict[str, str], account: dict[str, Any], lead: dict[str, Any] | None,
                 scan_date: str) -> list[str]:
    code = state["code"]
    if code == "not_a_prospect":
        reasons = [EXCLUSION_TEXT[r].format(**account) for r in account.get("eligibility_reasons") or []
                   if r in EXCLUSION_TEXT]
        return ["Do not contact: " + ("; ".join(reasons) or "not an organisation") + "."]
    if code == "context_only":
        return ["Do not open outreach on this data. Keep the account for context and recheck it after the next "
                "scan."]
    steps: list[str] = []
    if code == "verify_ownership":
        if "ownership_low" in (account.get("actionable_blockers") or []):
            steps.append("Confirm ownership: only the IP registry ties these services to this organisation. "
                         "Check the addresses against its website, DNS records or IT team before outreach.")
        for flag in account.get("review_flags") or []:
            if flag in FLAG_TEXT:
                steps.append(f"Clear the review flag: {FLAG_TEXT[flag].format(**account)}.")
    if code == "hygiene_only":
        steps.append("Pursue only if you sell certificate or TLS management.")
    steps.append("Qualify fit: check industry, size and territory against your target profile.")
    if lead is not None:
        steps.append(f"Find the owner: {BUYER.get(lead['signal_id'], 'the CISO')}.")
        steps.append(f"Open with the opening line above and cite the {lead['name'].lower()} evidence.")
    steps.append("Use the discovery questions to settle the points under “Confirm on the call”.")
    steps.append(f"Evidence is from the {scan_date} scan; recheck an endpoint before quoting its address.")
    return steps


def build_brief(account: dict[str, Any], sigs: list[dict[str, Any]], registry: dict[str, dict[str, Any]],
                lenses: list[dict[str, Any]], snapshot_id: str | None, population: str | None,
                use_case: str | None = None, lens_sizes: dict[str, int] | None = None,
                population_size: int | None = None) -> dict[str, Any]:
    state = research_state_ref(account, use_case)
    ordered = order_findings(sigs, use_case)
    findings = [finding(s, registry.get(s["signal_id"], {})) for s in ordered]
    security = [f for f in findings if not f["context_only"]]
    vendors = next((f for f in findings if f["context_only"]), None)
    lead = security[0] if security else None
    lens_by_id = {row["uc_id"]: row for row in lenses}
    selected = lens_by_id.get(use_case) if use_case else None
    scan_date = _scan_date(snapshot_id)
    pop = population or "accounts"
    if population_size:
        pop = f"{population_size:,} {POPULATION_NOUN.get(account.get('segment') or '', 'accounts')}"
    lens_sizes = lens_sizes or {}

    why: list[str] = []
    if state["code"] != "not_a_prospect":
        why.append(priority_sentence(account, pop))
        if selected and selected.get("uc_rank"):
            size = lens_sizes.get(selected["uc_id"])
            why.append(f"#{selected['uc_rank']:,}" + (f" of {size:,}" if size else "")
                       + f" in {USE_CASES_BY_ID[selected['uc_id']].name}.")
    exposure_kinds = len([f for f in security if f["signal_id"] in EXPOSURE_SIGNALS])
    if exposure_kinds > 1:
        why.append(f"Exposure in {exposure_kinds} categories, a broad attack surface for one organisation.")
    if state["code"] != "not_a_prospect":
        why.append(ownership_sentence(account))
    if vendors and state["code"] != "not_a_prospect":
        why.append(f"Already runs {_join(vendors['products'], 3)} in front of its services: security tooling is "
                   "in place to position against or alongside.")

    talking_points = [f["pitch"] for f in security[:MAX_TALKING_POINTS] if f["pitch"]]
    questions: list[str] = []
    confirm: list[str] = []
    for f in (security or findings)[:2]:
        questions += [q for q in f["discovery_questions"] if q not in questions]
        confirm += [c for c in f["confirm_on_call"] if c not in confirm]

    is_org = account.get("account_kind") == "org"
    return {
        "research_state": state,
        "priority": {"summary": priority_sentence(account, pop, selected) if selected
                     else priority_sentence(account, pop)},
        "summary": _summary(account, security, vendors, lead),
        "headline": None if lead is None else f"{lead['name']}: {lead['what_we_saw']}",
        "threats": [{"signal_id": f["signal_id"], "name": f["name"], "count": f["count"],
                     "products": f["products"], "threat": f["threat"]} for f in security],
        "why_target": why,
        "pitch": None if lead is None else {
            "lead_offering": lead["offering"],
            "buyer": BUYER.get(lead["signal_id"]),
            "opener": lead["opener"],
            "talking_points": talking_points,
            "discovery_questions": questions[:MAX_QUESTIONS],
        },
        "action_plan": _action_plan(state, account, lead, scan_date),
        "confirm_on_call": confirm[:MAX_CONFIRM],
        "competitive_context": None if vendors is None else {
            "vendors": vendors["products"], "count": vendors["count"], "pitch": vendors["pitch"]},
        "findings": findings,
        "fit": {
            "use_cases": [
                {"id": u.id, "name": u.name, "rank": lens_by_id[u.id]["uc_rank"], "of": lens_sizes.get(u.id),
                 "percentile": lens_by_id[u.id]["uc_percentile"], "context_only": u.context_only,
                 "matched_by": [registry.get(s, {}).get("short_name") or s
                                for s in lens_by_id[u.id]["uc_signal_ids"]]}
                for u in USE_CASES if u.id in lens_by_id and state["code"] != "not_a_prospect"],
            "infrastructure_location": list(account.get("countries") or []),
            "location_note": "Country of the IP addresses (geolocation), not the organisation's headquarters.",
        },
        "ownership": {
            "level": account.get("ownership_confidence"),
            "label": OWNERSHIP_LABEL.get(account.get("ownership_confidence") or "", "Unknown"),
            "summary": ownership_sentence(account),
        },
        "counts": {
            "services_with_findings": account["n_services"],
            "ips_with_findings": account["n_ips"],
            "all_attributed_services": account.get("ownership_services") if is_org else None,
            "definitions": {
                "services_with_findings": "Distinct services (IP, port, protocol, TLS name) linked to this "
                                          "account with at least one finding.",
                "ips_with_findings": "Distinct IP addresses among those services.",
                "all_attributed_services": "Every scanned service linked to this organisation, with or without a "
                                           "finding; the base for the ownership check. Not counted for domain "
                                           "accounts.",
            },
        },
        "source": (f"Internet-wide scan of {scan_date}. Rankings compare {pop} in that scan; software versions "
                   "and internal controls are not captured by an external scan."),
    }
