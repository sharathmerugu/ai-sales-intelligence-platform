# 0005 — Attribution v1: own-record evidence, PSL domains, strict winner or abstain

Status: accepted (2026-11-10), experimental

## Context
`org` names the netblock registrant, usually a provider. The research v0
picked `customer_domains[1]`, used a regex without the Public Suffix List and
left ISPs in tier A1. Tenant names on shared infrastructure must never be
assigned arbitrarily.

## Decision
- Evidence comes only from the service's own record (NTLM, certificate CN and
  SAN, SNI, HTTP Host, hostnames), one row per (service, source, name) with a
  filter outcome. Nothing propagates between services or vhosts.
- Registrable domains use the bundled PSL (`publicsuffixlist`, offline,
  private suffixes included, so `a.github.io` and `b.github.io` differ).
- Org classification: curated name table plus data-driven backstops
  (CDN/cloud-tag share, multi-tenant domains with an own-name certificate
  exemption, access-network reverse-DNS share). ISP, hosting, CDN and SaaS
  orgs never become owned (A1/A2) accounts.
- Tier B chooses a domain only when it strictly beats the runner-up on
  evidence strength; ties abstain (tier C). More than three domains is shared
  hosting. Infrastructure-exposure signals attach to tier B only with one
  candidate and strong evidence (NTLM, or certificate agreeing with SNI).
- Certificate names served by 20+ orgs are provider certificates.

## Consequences
- Tier C grows (63% to about 68% of services); recall is traded for precision.
- All thresholds are hypotheses; precision is unmeasured without labels.
- Org (`org:`) and domain (`dom:`) accounts for one company are not merged;
  that needs Firmable's company/domain index.
- The curated table needs ongoing review; a curated ASN-type table is the
  intended replacement.
