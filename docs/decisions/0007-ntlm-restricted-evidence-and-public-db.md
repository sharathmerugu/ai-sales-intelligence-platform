# 0007 — NTLM is restricted evidence; deploy only a sanitized public serving DB

Status: accepted (2026-11-10)

## Context
NTLM handshakes (RDP, SMB, HTTP NTLM auth) reveal internal Active Directory names: the AD DNS
domain, the NetBIOS domain and the host FQDN. Attribution v1 let an NTLM domain alone win a
service (`dom_ntlm`, score 1.0) and allow infrastructure-exposure signals, so an internal name
could become a public prospect account. CLAUDE.md puts NTLM internal names behind human review.

## Decision
- Attribution v2 (`ATTRIBUTION_VERSION = 2`): an NTLM domain never names a candidate on its own.
  It only corroborates a registrable domain that a public source on the same record also names
  (certificate CN/SAN, SNI, HTTP Host or reverse-DNS hostname); that pair scores 1.0
  (`dom_ntlm_corroborated`). NTLM-only services abstain (tier C,
  `abstain_ntlm_uncorroborated`). NTLM-only domains are not listed in `candidate_domains`.
- NTLM rows stay in internal `evidence.parquet` (provenance preserved); no NTLM field is ever
  copied into the accounts layer or the serving DB, and no signal wording mentions NTLM.
- Deployments use `firmable publish-public`, which copies the serving DB, nulls raw file
  coordinates (`file_id`, `byte_offset`, `byte_length`; `observation_id` and `record_sha256`
  stay for tracing) and refuses input with `attribution_version < 2`, v1 `dom_ntlm` reasons, or
  any column named like `ntlm` / `evidence_json`.
- The deployed app is behind HTTP Basic auth (`FIRMABLE_BASIC_AUTH`; the image sets
  `FIRMABLE_REQUIRE_AUTH=1`, so it refuses to start without credentials), except `/health`.
  Every response is `no-store`, `noindex`; each client IP is rate limited in memory.

## Consequences
- Full snapshot: 87 services abstain that v1 attributed; accounts 180,136 to 180,103.
- `tests/test_privacy.py` runs the whole slice on banners with NTLM names and crawls every
  route; no internal name may appear. A full-data scan of the public DB found no NTLM-only
  value; the only equal strings are generic words (`server`, `admin`) in HTTP titles and public
  domains that are also AD domains (e.g. a company whose AD domain is its web domain).
- Exposure details (IP, port, product) are still visible to authenticated reviewers: the
  deployment is a private review tool, not a public site.
