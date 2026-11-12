"""Publication checks for agent output (docs/agentic-briefs.md §5).

Code, not a model, decides whether a brief is published. The checks go past "has a citation":

- structure: schema, snapshot id, card count, known and distinct signal ids;
- evidence linkage: every cited observation was retrieved in this run and belongs to the card's signal;
- numbers: every number in a card is a value the backend holds for that card's signal, the account or
  the cited records (counts, ranks, ports, dates); percentages only as the backend's own "top N%";
- named products: a vendor or product named in a factual field appears in this account's records;
- unsupported conclusions: compromise, vulnerability, missing controls, buying intent, recent change
  and invented confidence are rejected unless phrased as a question;
- decision coherence: the move matches the backend research status (ownership, eligibility), and no
  card recommends outreach while another says to hold or verify;
- signal emphasis and seller relevance: a lens finding leads when the account has one, and lens cards
  say why the finding matters for the seller's offering;
- communication: word limits, at most one hedge per card, no filler, no repeated caveats, an
  imperative next action, questions that are questions.

Every failure is an `Issue` the model receives verbatim during repair.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..api.brief import SUB_FLAG_TEXT
from ..semantic.models import AccountView, SellerPlaybook, SignalOccurrence
from .tools import EvidenceIndex

VALIDATOR_VERSION = 1

MAX_CARDS = 3
MAX_REFS_PER_CARD = 5
HEADLINE_WORDS = 12
CARD_WORDS = 80
DECISION_WORDS = 25
QUESTION_WORDS = 25
FOLLOW_UP_WORDS = 15
ANSWER_WORDS = 60
MAX_FOLLOW_UPS = 4

EXTRA_VENDORS = (
    "Palo Alto", "GlobalProtect", "Citrix", "Ivanti", "Pulse Secure", "Fortinet", "Microsoft", "Okta", "Duo",
    "Zscaler", "Netskope", "Cloudflare", "Akamai", "Check Point", "Juniper", "Cisco", "F5", "SonicWall",
    "Let's Encrypt", "DigiCert", "Sectigo", "Entrust", "Venafi", "Keyfactor", "AppViewX", "GlobalSign",
)
GENERIC_FIRST_WORDS = {"open-resty", "secure", "self-signed", "ssl", "tls", "sql", "rsa", "sha-1/md5", "utm",
                       "expired", "minio", "page", "control", "alert", "expression", "shadow", "remote", "data",
                       "cloud", "web", "apple", "generic"}
DEFECT_LABELS = set(SUB_FLAG_TEXT.values()) | {"SSL VPN portal (unbranded)"}

NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
                "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
                "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20}
# Version-like tokens that are product names, not quantities.
NON_QUANTITY = re.compile(
    r"\bTLS\s?1\.[0-3](?:\s?/\s?1\.[0-3])?|\bSSL\s?v?[23](?:\s?/\s?(?:SSL)?v?3)?|\bSSLv[23]\b|\bSHA-?\d+\b|\bMD5\b"
    r"|\bIPv[46]\b|\bS\d\d\b|\bRSA(?: key)?\s?(?:<\s?)?\d{3,4}(?:[- ]bits?)?|\b\d{3,4}[- ]bit\b|\bX11\b|\bMS-SQL\b"
    r"|\b2FA\b|\bP2P\b|\b24/7\b|\bTop\s+\d+%|\b[A-Z][a-z]+\d+\b|(?<![\d.])1\.[0-3](?![\d.])", re.I)
NUMBER = re.compile(r"(?<![\w.\-/])(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)(\s?%)?(?![\w])")
TOP_PCT = re.compile(r"\btop\s+(\d+)%", re.I)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_OR_EMAIL = re.compile(r"\bhttps?://\S+|\bwww\.\S+|\b[\w.+-]+@[\w-]+\.[\w.-]+", re.I)
HOSTNAME = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
OWNERSHIP_ASSERTION = re.compile(r"\b(?:belongs? to|owned by|operated by|run by|confirmed (?:as|to be)|certainly|"
                                 r"definitely)\b", re.I)

HEDGE = re.compile(r"\b(may|might|potentially|possibly|perhaps|could)\b", re.I)
FILLER = re.compile(
    r"in today's|ever[- ]evolving|threat landscape|it is important to note|it's important to note|it is worth noting"
    r"|\brobust\b|\bholistic\b|synerg|\bleverag|cutting[- ]edge|best[- ]in[- ]class|game[- ]changer|as an ai\b"
    r"|peace of mind|comprehensive solution|\bdelve\b", re.I)
CAVEAT = re.compile(r"\b(?:single|one) (?:scan|snapshot)\b|cannot (?:confirm|show|tell|prove)|not (?:verified|confirmed)"
                    r"|external scan", re.I)
UNSUPPORTED = [
    ("compromise", re.compile(r"\b(?:is|are|was|were|be|been|being|likely|already)\s+(?:\w+\s)?(?:breached|compromised|"
                              r"hacked|infected|attacked|exploited)\b|\b(?:breach|compromise|intrusion) (?:has|had) "
                              r"(?:occurred|happened)\b|\bindicators? of compromise\b", re.I)),
    ("vulnerability", re.compile(r"\b(?:is|are|be|been|being|remains?|looks?|seems?)\s+(?:\w+\s)?(?:vulnerable|exploitable|unpatched|"
                                 r"out[- ]of[- ]date|outdated|misconfigured)\b|\bunpatched\b|\bknown[- ]vulnerable\b",
                                 re.I)),
    ("missing control", re.compile(r"\b(?:no|without|lacks?|lacking|missing|absence of|absent|not using|doesn'?t use|"
                                   r"does not use|isn'?t using|not enforc\w*|has not enabled|hasn't enabled)\s+(?:any\s+)?"
                                   r"(?:mfa|multi[- ]factor|2fa|patch\w*|monitoring|zero[- ]trust|encryption|"
                                   r"certificate management|controls?)\b|\b(?:mfa|multi[- ]factor|2fa|patching|"
                                   r"monitoring|encryption|zero[- ]trust)\s+(?:is|are|was|were)\s+(?:not\s+(?:enabled|"
                                   r"enforced|configured|required|in place|used|applied)|disabled|absent|missing|off)\b"
                                   r"|\b(?:isn'?t|aren'?t)\s+(?:enabled|enforced|configured|required)\b", re.I)),
    ("unverified CVE", re.compile(r"\bCVE-\d{4}-\d{3,}\b", re.I)),
    ("buying intent", re.compile(r"\b(?:is|are)\s+(?:actively\s+)?(?:evaluating|looking (?:for|to)|in the market|planning|"
                                 r"budgeting|shopping)\b|\bbuying intent\b|\bready to buy\b|\bha(?:s|ve) budget\b|"
                                 r"\bpurchase intent\b", re.I)),
    ("change over time", re.compile(r"\b(?:recently|newly|just (?:deployed|added|exposed|opened|launched)|this (?:week|"
                                    r"month|quarter)|last (?:week|month|quarter)|has (?:changed|grown|increased|"
                                    r"expanded)|new(?:ly)? (?:exposed|deployed|added))\b", re.I)),
    ("invented confidence", re.compile(r"\d+\s?%\s*(?:confiden|certain|likel|probab|chance|sure)|\b(?:confidence|"
                                       r"probability|likelihood) (?:of|is|at) \d", re.I)),
]
GO = re.compile(r"\b(?:lead with|reach out|open with|pitch|contact (?:them|the|their)|book (?:a|the)|email|call the|"
                r"pursue now|prioriti[sz]e this|engage|schedule|introduce|set up a (?:call|meeting)|meet (?:the|with))\b",
                re.I)
STOP = re.compile(r"\b(?:do not (?:contact|pursue|reach out|open)|don'?t (?:contact|pursue|reach out)|hold off|"
                  r"not a prospect|skip this account|deprioriti[sz]e|no outreach)\b", re.I)
VERIFY = re.compile(r"\b(?:verify|confirm|check)\b[^.]*\b(?:own\w*|operat\w*|runs?|belongs?|whose)\b", re.I)
PARK = re.compile(r"\b(?:monitor|hold|keep|context|recheck|watch|park|revisit)\b", re.I)
LENS_GAP = re.compile(r"\b(?:no|not|outside|none)\b", re.I)
IMPERATIVES = {
    "ask", "confirm", "verify", "lead", "open", "check", "map", "find", "contact", "book", "send", "hold", "recheck",
    "monitor", "reach", "call", "email", "request", "review", "use", "start", "position", "identify", "compare",
    "do", "keep", "skip", "deprioritize", "deprioritise", "propose", "offer", "cite", "qualify", "frame", "bring",
    "walk", "pitch", "prioritize", "prioritise", "focus", "route", "get", "raise", "target", "engage", "show",
    "share", "name", "anchor", "include", "note", "pair", "move", "treat", "park", "add", "hand", "present", "lead,", "pull",
}


@dataclass
class Issue:
    code: str
    where: str
    message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.where}: {self.message}"


@dataclass
class CheckContext:
    account: AccountView
    signals: list[SignalOccurrence]
    evidence: EvidenceIndex                    # the run's ledger: observations actually retrieved
    playbook: SellerPlaybook
    vocabulary: list[str]
    snapshot_id: str | None
    use_case: str | None
    extra_numbers: set[float] = field(default_factory=set)

    @property
    def signals_by_id(self) -> dict[str, SignalOccurrence]:
        return {s.signal_id: s for s in self.signals}


def words(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text or "") if s.strip()]


def statements(text: str) -> str:
    """The text without its questions: a question may ask about what a statement may not assert."""
    return " ".join(s for s in sentences(text) if not s.endswith("?"))


def _num(token: str) -> float:
    return float(token.replace(",", ""))


def numbers_in(text: str) -> list[tuple[float, bool]]:
    """(value, is_percentage) for each quantity in the text; product versions are skipped."""
    cleaned = NON_QUANTITY.sub(" ", text or "")
    out = [(_num(m.group(1)), bool(m.group(2))) for m in NUMBER.finditer(cleaned)]
    for w, v in NUMBER_WORDS.items():
        # "one of", "no one", "any one": not quantities
        out += [(float(v), False) for _ in re.finditer(rf"(?<!\bno )(?<!\bany )\b{w}\b(?! of\b)", cleaned, re.I)]
    return out


def _numbers_from_text(text: str | None) -> set[float]:
    return {v for v, _ in numbers_in(text or "")}


def vendor_names(vocabulary: list[str]) -> list[str]:
    names: set[str] = set(EXTRA_VENDORS)
    for term in vocabulary:
        if term in DEFECT_LABELS:
            continue
        names.add(term)
        for piece in re.split(r"\s*/\s*", term):
            if len(piece) >= 3:
                names.add(piece)
        first = term.split()[0]
        if " " in term and len(first) >= 4 and first.lower() not in GENERIC_FIRST_WORDS:
            names.add(first)
    return sorted(names, key=len, reverse=True)


def mentioned_vendors(text: str, names: list[str]) -> set[str]:
    found: set[str] = set()
    lowered = text.lower()
    for n in names:
        if n.lower() in lowered and re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text, re.I):
            found.add(n)
    return found


class Checker:
    def __init__(self, ctx: CheckContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        a = ctx.account
        self.account_numbers: set[float] = {
            float(x) for x in (a.n_services, a.n_ips, a.rank, a.lens.rank if a.lens else None,
                               a.lens.of if a.lens else None, a.lens.n_services if a.lens else None,
                               a.lens.n_ips if a.lens else None) if x is not None}
        self.account_numbers |= _numbers_from_text(a.ownership.summary) | _numbers_from_text(a.priority_summary)
        snap = ctx.snapshot_id or ""
        self.account_numbers |= {float(p) for p in re.findall(r"\d+", snap)}
        self.account_numbers |= ctx.extra_numbers
        self.allowed_pcts = {float(m) for m in TOP_PCT.findall(a.priority_summary)}
        self.vendors = vendor_names(ctx.vocabulary)
        blob = []
        for s in ctx.signals:
            blob += s.products + s.defects
        for e in ctx.evidence.values():
            blob += [e.service.product or "", e.service.version or "", e.detail or "", e.service.http_title or "",
                     e.service.sni or "", " ".join(e.attribution_domains)]
        self.product_blob = " | ".join(blob).lower()
        # Product and defect labels may contain digits ("Windows Server 2012"); they are names, not quantities.
        self.labels = sorted({x for s in ctx.signals for x in s.products + s.defects if re.search(r"\d", x)},
                             key=len, reverse=True)

    def add(self, code: str, where: str, message: str) -> None:
        self.issues.append(Issue(code, where, message))

    # -- reusable text checks ------------------------------------------------------

    def signal_numbers(self, s: SignalOccurrence) -> set[float]:
        return {float(x) for x in (s.n_services, s.n_ips, s.n_counted_services, s.evidence_rows, s.counted_rows)}

    def ref_numbers(self, refs: list[str], signal_id: str | None = None) -> set[float]:
        items = [e for e in (self.ctx.evidence.get(r, signal_id) for r in refs) if e is not None]
        out = {float(len(items)), float(len({e.service.ip for e in items}))}
        for e in items:
            if e.service.port is not None:
                out.add(float(e.service.port))
        return out

    def check_numbers(self, where: str, text: str, allowed: set[float]) -> None:
        known_ips = {e.service.ip for e in self.ctx.evidence.values()}
        for ip in IPV4.findall(text):
            if ip not in known_ips:
                self.add("unsupported_number", where, f"the address {ip} is not in the retrieved records")
        text = IPV4.sub(" ", text)
        for label in self.labels:
            text = re.sub(re.escape(label), " ", text, flags=re.I)
        for top in TOP_PCT.findall(text):
            if float(top) not in self.allowed_pcts:
                self.add("unsupported_number", where, f"'top {top}%' is not the backend's priority summary")
        for value, pct in numbers_in(text):
            if pct:
                if value not in self.allowed_pcts:
                    self.add("unsupported_number", where, f"'{value:g}%' is not a backend value; only the priority "
                             "summary's 'top N%' may be quoted")
            elif value not in allowed:
                self.add("unsupported_number", where, f"the number {value:g} is not in the retrieved data for this "
                         "finding or account; use the counts the tools returned")

    def check_products(self, where: str, text: str) -> None:
        for name in mentioned_vendors(text, self.vendors):
            if name.lower() not in self.product_blob:
                self.add("unsupported_product", where, f"names '{name}', which no record for this account shows; "
                         "name only products in the retrieved records")

    def check_claims(self, where: str, text: str, question_field: bool = False) -> None:
        stmt = statements(text) if question_field else text
        m = URL_OR_EMAIL.search(text)
        if m:
            self.add("unsupported_claim", where, f"contains a link or address ('{m.group(0)}'); scanner text is data, "
                     "not something to publish")
        for host in HOSTNAME.findall(IPV4.sub(" ", text)):
            if host.lower() not in self.product_blob and "." in host and not re.fullmatch(r"[\d.]+", host):
                self.add("unsupported_claim", where, f"names the host '{host}', which no record for this account shows")
        if self.ctx.account.ownership.level != "high":
            m = OWNERSHIP_ASSERTION.search(stmt)
            if m:
                self.add("status_mismatch", where, f"asserts ownership ('{m.group(0)}') the backend has not "
                         "established; say 'linked to'")
        for label, pattern in UNSUPPORTED:
            m = pattern.search(stmt)
            if m:
                self.add("unsupported_claim", where, f"asserts {label} ('{m.group(0)}'), which one external scan "
                         "cannot establish; state the observation, or turn it into a discovery question")
        m = FILLER.search(text)
        if m:
            self.add("filler", where, f"cut generic wording ('{m.group(0)}')")

    def check_question(self, where: str, text: str, limit: int) -> None:
        if not text.strip().endswith("?"):
            self.add("not_a_question", where, "must be a single question ending with '?'")
        if words(text) > limit:
            self.add("too_long", where, f"{words(text)} words; keep it under {limit}")

    def check_refs(self, where: str, refs: list[str], signal_id: str | None) -> None:
        if len(set(refs)) != len(refs):
            self.add("duplicate_ref", where, "cites the same observation twice")
        for r in refs:
            found = self.ctx.evidence.signals_of(r)
            if not found:
                self.add("unknown_ref", where, f"cites {r!r}, which was not retrieved with get_signal_evidence in "
                         "this investigation")
            elif signal_id and signal_id not in found:
                self.add("ref_signal_mismatch", where, f"cites {r!r}, a {'/'.join(sorted(found))} record, on a "
                         f"{signal_id} card")

    def check_imperative(self, where: str, text: str) -> None:
        first = re.sub(r"[^\w-]", "", (text.split() or [""])[0]).lower()
        if first not in IMPERATIVES:
            self.add("weak_action", where, "start with the action itself (e.g. 'Ask…', 'Lead with…', 'Verify…')")

    # -- decision coherence --------------------------------------------------------

    def check_decision(self, decision: str, actions: list[tuple[str, str]]) -> None:
        status = self.ctx.account.status.code
        own = self.ctx.account.ownership.level
        go, stop, verify = GO.search(decision), STOP.search(decision), VERIFY.search(decision)
        if status == "verify_ownership":
            if not verify:
                self.add("status_mismatch", "decision", "ownership is unresolved: the decision must be to verify "
                         "who owns or operates the services, with the verification step")
            elif go and go.start() < verify.start():
                self.add("status_mismatch", "decision", "puts outreach before ownership is verified")
            for where, act in actions:
                if GO.search(act) and not VERIFY.search(act):
                    self.add("status_mismatch", where, "recommends outreach although ownership is unresolved; make "
                             "the step a verification")
        elif status == "not_a_prospect":
            if not stop:
                self.add("status_mismatch", "decision", "the backend excludes this account: say not to pursue it")
            for where, act in actions:
                if GO.search(act):
                    self.add("status_mismatch", where, "recommends outreach to an excluded account")
        elif status == "context_only":
            if go or not (PARK.search(decision) or stop):
                self.add("status_mismatch", "decision", "no finding is strong enough to open a conversation: the "
                         "decision is to monitor or hold, not to reach out")
            for where, act in actions:
                if GO.search(act):
                    self.add("status_mismatch", where, "recommends outreach on context-only evidence")
        else:  # research_candidate, hygiene_only
            if stop:
                self.add("status_mismatch", "decision", "the backend marks this account to pursue; do not tell the "
                         "seller to hold off")
            if own == "high" and verify and not go:
                self.add("needless_qualification", "decision", "ownership is strong; lead with the move instead of "
                         "an ownership check")
        go_any = bool(go) or any(GO.search(a) and not VERIFY.search(a) for _, a in actions)
        stop_any = bool(stop) or any(STOP.search(a) for _, a in actions)
        if go_any and stop_any:
            self.add("contradiction", "decision", "one part recommends outreach and another says to hold off; pick one")

    def check_caveats(self, texts: list[tuple[str, str]]) -> None:
        hits = [(w, m.group(0)) for w, t in texts for m in CAVEAT.finditer(t)]
        if len(hits) > 1:
            self.add("repeated_caveat", hits[1][0], f"repeats a data caveat ('{hits[1][1]}'); state it once, only "
                     "where it changes the action")
        seen: dict[str, str] = {}
        for w, t in texts:
            for s in sentences(t):
                key = re.sub(r"\W+", " ", s.lower()).strip()
                if len(key) > 20 and key in seen and seen[key] != w:
                    self.add("repetition", w, f"repeats a sentence from {seen[key]}")
                seen.setdefault(key, w)


def check_brief(draft: Any, ctx: CheckContext) -> list[Issue]:
    c = Checker(ctx)
    if not isinstance(draft, dict):
        return [Issue("schema", "brief", "submit_brief input must be an object")]
    for key, kind in (("snapshot_id", str), ("decision", str), ("cards", list), ("follow_up_questions", list)):
        if not isinstance(draft.get(key), kind):
            c.add("schema", key, f"missing or not a {kind.__name__}")
    if c.issues:
        return c.issues
    if draft["snapshot_id"] != ctx.snapshot_id:
        c.add("snapshot_mismatch", "snapshot_id", f"is {draft['snapshot_id']!r}; this investigation reads snapshot "
              f"{ctx.snapshot_id!r}")
    sigs = ctx.signals_by_id
    cards = draft["cards"]
    security = [s for s in ctx.signals if not s.context_only]
    status = ctx.account.status.code
    if len(cards) > MAX_CARDS:
        c.add("card_count", "cards", f"{len(cards)} cards; publish at most {MAX_CARDS}, strongest first")
    if not cards and ctx.signals and status != "not_a_prospect":
        c.add("card_count", "cards", "publish at least one finding")

    decision = draft["decision"]
    if words(decision) > DECISION_WORDS:
        c.add("too_long", "decision", f"{words(decision)} words; keep it under {DECISION_WORDS}")
    if len(HEDGE.findall(decision)) > 0:
        c.add("hedging", "decision", "state the move directly, without 'may', 'might', 'could' or 'potentially'")
    c.check_numbers("decision", decision, c.account_numbers | {n for s in ctx.signals for n in c.signal_numbers(s)})
    c.check_products("decision", decision)
    c.check_claims("decision", decision)

    lens = set(ctx.playbook.lens_signals)
    lens_security = [s for s in security if s.signal_id in lens]
    texts: list[tuple[str, str]] = [("decision", decision)]
    actions: list[tuple[str, str]] = []
    seen_signals: set[str] = set()
    for i, card in enumerate(cards):
        w = f"cards[{i}]"
        if not isinstance(card, dict):
            c.add("schema", w, "must be an object")
            continue
        missing = [k for k in ("signal_id", "headline", "finding", "relevance", "action", "evidence_refs",
                               "discovery_question") if k not in card]
        if missing:
            c.add("schema", w, f"missing {missing}")
            continue
        bad_types = [k for k in ("signal_id", "headline", "finding", "relevance", "action", "discovery_question")
                     if not isinstance(card[k], str)]
        if bad_types or not isinstance(card["evidence_refs"], list):
            c.add("schema", w, f"fields must be strings and evidence_refs a list ({bad_types or ['evidence_refs']})")
            continue
        sid = card["signal_id"]
        s = sigs.get(sid)
        if s is None:
            c.add("unknown_signal", w, f"signal {sid!r} is not on this account; its signals are {sorted(sigs)}")
            continue
        if sid in seen_signals:
            c.add("duplicate_signal", w, f"a second card for {sid}; merge them")
        seen_signals.add(sid)
        refs = [r for r in card["evidence_refs"] if isinstance(r, str)]
        if not refs:
            c.add("no_evidence", w, "cite at least one observation_id from get_signal_evidence for this finding")
        if len(refs) > MAX_REFS_PER_CARD:
            c.add("too_many_refs", w, f"cite at most {MAX_REFS_PER_CARD} observations")
        c.check_refs(w, refs, sid)
        allowed = c.account_numbers | c.signal_numbers(s) | c.ref_numbers(refs, sid)
        core = " ".join(str(card[k]) for k in ("finding", "relevance", "action"))
        if words(card["headline"]) > HEADLINE_WORDS:
            c.add("too_long", f"{w}.headline", f"{words(card['headline'])} words; keep it under {HEADLINE_WORDS}")
        if words(core) > CARD_WORDS:
            c.add("too_long", w, f"finding, relevance and action total {words(core)} words; keep them under {CARD_WORDS}")
        if len(HEDGE.findall(card["headline"] + " " + core)) > 1:
            c.add("hedging", w, "more than one 'may/might/could/potentially': state supported findings directly")
        for k in ("headline", "finding", "relevance", "action", "discovery_question"):
            c.check_numbers(f"{w}.{k}", str(card[k]), allowed)
            c.check_claims(f"{w}.{k}", str(card[k]), question_field=k == "discovery_question")
        for k in ("headline", "finding"):
            c.check_products(f"{w}.{k}", str(card[k]))
        c.check_imperative(f"{w}.action", card["action"])
        c.check_question(f"{w}.discovery_question", card["discovery_question"], QUESTION_WORDS)
        if sid in lens and ctx.playbook.relevance_keywords:
            rel = card["relevance"].lower()
            if not any(k in rel for k in ctx.playbook.relevance_keywords):
                c.add("seller_relevance", f"{w}.relevance", f"say why this matters for {ctx.playbook.offering}")
        if s.context_only and i < len(cards) - 1:
            c.add("emphasis", w, "vendor context goes last, after security findings")
        actions.append((f"{w}.action", card["action"]))
        texts += [(f"{w}.{k}", str(card[k])) for k in ("finding", "relevance", "action")]
    if cards and isinstance(cards[0], dict) and lens_security and cards[0].get("signal_id") not in lens:
        c.add("emphasis", "cards[0]", f"the account has a {ctx.playbook.offering} finding "
              f"({', '.join(s.signal_id for s in lens_security)}); lead with it")
    if lens and not lens_security and status not in ("not_a_prospect",) and not LENS_GAP.search(decision):
        c.add("emphasis", "decision", f"no {ctx.playbook.offering} finding on this account: say so in the decision")
    c.check_decision(decision, actions)
    c.check_caveats(texts)

    fus = draft["follow_up_questions"]
    for i, q in enumerate(fus):
        if isinstance(q, str):
            c.check_claims(f"follow_up_questions[{i}]", q, question_field=True)
    if len(fus) > MAX_FOLLOW_UPS:
        c.add("too_many", "follow_up_questions", f"at most {MAX_FOLLOW_UPS}")
    for i, q in enumerate(fus):
        if not isinstance(q, str):
            c.add("schema", f"follow_up_questions[{i}]", "must be a string")
            continue
        c.check_question(f"follow_up_questions[{i}]", q, FOLLOW_UP_WORDS)
    return c.issues


def check_answer(draft: Any, ctx: CheckContext) -> list[Issue]:
    c = Checker(ctx)
    if not isinstance(draft, dict):
        return [Issue("schema", "answer", "submit_answer input must be an object")]
    for key, kind in (("snapshot_id", str), ("answer", str), ("evidence_refs", list), ("follow_up_questions", list)):
        if not isinstance(draft.get(key), kind):
            c.add("schema", key, f"missing or not a {kind.__name__}")
    if c.issues:
        return c.issues
    if draft["snapshot_id"] != ctx.snapshot_id:
        c.add("snapshot_mismatch", "snapshot_id", f"is {draft['snapshot_id']!r}; expected {ctx.snapshot_id!r}")
    text = draft["answer"]
    if not all(isinstance(r, str) for r in draft["evidence_refs"]):
        c.add("schema", "evidence_refs", "must be a list of observation ids")
    refs = [r for r in draft["evidence_refs"] if isinstance(r, str)]
    c.check_refs("evidence_refs", refs, None)
    if words(text) > ANSWER_WORDS:
        c.add("too_long", "answer", f"{words(text)} words; keep it under {ANSWER_WORDS}")
    if len(HEDGE.findall(text)) > 1:
        c.add("hedging", "answer", "more than one hedge: answer directly")
    allowed = c.account_numbers | {n for s in ctx.signals for n in c.signal_numbers(s)} | c.ref_numbers(refs)
    c.check_numbers("answer", text, allowed)
    c.check_products("answer", text)
    c.check_claims("answer", text)
    status = ctx.account.status.code
    if status in ("verify_ownership", "not_a_prospect", "context_only") and GO.search(text) and not VERIFY.search(text):
        c.add("status_mismatch", "answer", f"recommends outreach, but the account status is {status}")
    for i, q in enumerate(draft["follow_up_questions"][:MAX_FOLLOW_UPS + 1]):
        if isinstance(q, str):
            c.check_question(f"follow_up_questions[{i}]", q, FOLLOW_UP_WORDS)
    return c.issues
