"""Seller context: versioned, approved positioning per prospecting use case.

A playbook says what the seller offers, who buys it, why each finding matters for that offering and
which claims are off limits. Without it the agent can only give a general security reading. Wording
follows `docs/research-findings.md` §3 and the communication contract in docs/agentic-briefs.md §4:
direct about what the scan shows, silent on what it cannot show (intent, missing controls, compromise,
change over time).
"""

from __future__ import annotations

from ..accounts.use_cases import USE_CASES_BY_ID
from .models import SellerPlaybook

PLAYBOOK_VERSION = 1

AVOID_ALWAYS = [
    "Do not say the account is breached, compromised, vulnerable or unpatched: one scan cannot show it.",
    "Do not say a control (MFA, patching, monitoring) is missing: ask about it instead.",
    "Do not claim buying intent, budget, a project or a recent change: the data is one snapshot.",
    "Do not invent confidence percentages; the backend's ownership and priority fields are the confidence.",
]

PLAYBOOKS: dict[str, SellerPlaybook] = {
    "remote_access": SellerPlaybook(
        id="remote_access", version=PLAYBOOK_VERSION, use_case="remote_access",
        offering="remote-access security",
        lens_signals=["S01", "S03"],
        buyers=["head of network security", "head of IT infrastructure", "identity and access lead"],
        value_angle=("Internet-facing VPN gateways and remote-administration logins are the first systems "
                     "attackers probe. The offering takes that edge off the internet (zero-trust access) or "
                     "hardens it: MFA on every login, patch visibility, monitoring."),
        positioning=[
            "Zero-trust access removes the internet-facing VPN portal.",
            "MFA on every remote login, including contractors.",
            "Patch visibility and monitoring for every gateway.",
        ],
        signal_angles={
            "S01": "Internet-facing remote-access gateways are the concrete opening for remote-access security.",
            "S03": "Remote-administration logins on the internet are the case for privileged, zero-trust admin access.",
            "S04": "Exposed data stores widen the conversation from access to what sits behind it.",
            "S05": "Exposed management consoles are another remote-access path to cover.",
            "S06": "Certificate defects are secondary for a remote-access conversation.",
            "S16": "The security vendors already in front of the services are the incumbents to position against.",
        },
        discovery_questions=[
            "How do you enforce MFA across these gateways, including contractors?",
            "Who owns the remote-access gateways, and who patches them?",
            "How fast do you apply gateway firmware advisories today?",
            "Is a move to zero-trust access on your roadmap?",
        ],
        relevance_keywords=["remote", "access", "vpn", "gateway", "zero-trust", "zero trust", "mfa", "login",
                            "admin", "rdp", "ssh", "edge", "perimeter"],
        avoid_claims=AVOID_ALWAYS,
    ),
    "certificate_management": SellerPlaybook(
        id="certificate_management", version=PLAYBOOK_VERSION, use_case="certificate_management",
        offering="certificate lifecycle management",
        lens_signals=["S06"],
        buyers=["PKI or infrastructure owner", "head of platform or web operations"],
        value_angle=("Expired, self-signed or weak certificates and old TLS on public endpoints are visible "
                     "defects. The offering automates certificate discovery, renewal and policy so expiries "
                     "stop causing outages and audit findings."),
        positioning=[
            "Automated discovery of every public certificate.",
            "Renewal before expiry, with policy on key size and signature.",
            "Retire TLS 1.0/1.1 with an inventory of who still needs it.",
        ],
        signal_angles={
            "S06": "Certificate and TLS defects on public endpoints are the direct case for certificate lifecycle "
                   "management.",
            "S01": "Remote-access gateways also present certificates; they are secondary for this offering.",
            "S03": "Remote-administration services are outside a certificate conversation.",
            "S04": "Exposed data stores are outside a certificate conversation.",
            "S05": "Exposed consoles are outside a certificate conversation.",
            "S16": "The CDN and security vendors in front of the services often terminate TLS; ask who manages "
                   "those certificates.",
        },
        discovery_questions=[
            "How do you track certificate expiry across teams today?",
            "Who owns renewals for these public endpoints?",
            "Do any clients still require TLS 1.0 or 1.1?",
        ],
        relevance_keywords=["certificate", "certificates", "tls", "renewal", "expiry", "expired", "pki", "ssl",
                            "self-signed", "key", "signature"],
        avoid_claims=AVOID_ALWAYS + [
            "Self-signed certificates are normal on some appliances: lead with expired or weak certificates "
            "where present.",
            "Do not claim an outage happened.",
        ],
    ),
}

GENERAL = SellerPlaybook(
    id="general", version=PLAYBOOK_VERSION, use_case=None,
    offering="security",
    lens_signals=[],
    buyers=["CISO", "head of IT infrastructure"],
    value_angle="General security reading: no seller offering was selected, so findings are ranked by the backend.",
    positioning=[],
    signal_angles={
        "S01": "Internet-facing remote-access gateways are a concrete security opening.",
        "S03": "Remote-administration logins on the internet are a concrete security opening.",
        "S04": "Exposed data stores are a concrete security opening.",
        "S05": "Exposed management consoles are a concrete security opening.",
        "S06": "Certificate and TLS defects are a hygiene opening.",
        "S16": "Security vendors already in place are competitive context.",
    },
    discovery_questions=[],
    relevance_keywords=["security", "exposure", "exposed", "internet", "attack", "gateway", "certificate"],
    avoid_claims=AVOID_ALWAYS,
)


def playbook_for(use_case: str | None) -> SellerPlaybook:
    """The approved playbook for a use case; other lenses get a general reading scoped to the lens."""
    if use_case in PLAYBOOKS:
        return PLAYBOOKS[use_case]
    lens = USE_CASES_BY_ID.get(use_case or "")
    if lens is None:
        return GENERAL
    return GENERAL.model_copy(update={
        "id": f"general:{lens.id}", "use_case": lens.id, "offering": lens.name.lower(),
        "lens_signals": list(lens.signals), "value_angle": lens.description,
    })
