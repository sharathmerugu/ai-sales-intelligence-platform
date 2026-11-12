# 0010 — Research states, use-case lenses and a plain-language brief (serving v4)

Status: accepted (2026-11-12). Builds on ADR 0009; the scoring-v3 accounts layer is unchanged.

## Context

The page read like an internal diagnostic: signal codes, a formula as "why act", tiers, and
"actionable outreach" on accounts whose fit, buyer and timing are unknown. The default list was
50 / 50 High because it sorts by rank. Several hypotheses claimed more than one snapshot shows
(legacy VPN, missing controls, renewal). Audit: `docs/sales-brief.md` §1.

## Decision

1. Replace "actionable" with research states (research candidate, certificate findings only,
   verify ownership first, context only, not a prospect). The gate is unchanged, but a research
   candidate also needs a counted exposure, because 96% of gated accounts passed on TLS findings
   alone; inside the certificate lens those TLS findings are the reason, so they count there.
2. Add use-case lenses over implemented signals only. A lens ranks on its own signals and IPs with
   the existing priority function; ties go to evidence quality before size. Lenses are computed at
   serving-DB build time from `account_evidence`, not in the accounts layer, so no scoring rebuild
   is needed and the accounts contract stays fixed.
3. Sales wording lives in the signal registry (`WORDING_VERSION`), separate from detection
   (`Signal.version`), so a wording change does not invalidate signal hits.
4. The API builds a brief from existing fields; the score, tiers and reason codes move to a
   collapsed technical section rather than being removed.

## Consequences

- Serving DB version 4: the image and the public DB must be deployed together.
- Overall size bias is reduced inside lenses, not removed; changing the score needs labels.
