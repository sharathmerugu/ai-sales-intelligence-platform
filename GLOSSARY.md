# Glossary

**Delivery** — one arrival of a source file at a path. Two deliveries with the same bytes are the same Source File.

**Source File** — an immutable NDJSON file identified by the SHA-256 of its full content.

**Chunk** — a byte range of one Source File; the unit of work, retry and output. Every line belongs to exactly one Chunk.

**Observation** — one scanner banner: what the scanner saw on one Service at one moment. Carries the scanner's own claims (tags, product, inferred CVEs) labelled as scanner-asserted.

**Quarantined Line** — a line that could not become an Observation; counted and kept with its location and error class.

**Service** — a network endpoint: (IP, port, transport, SNI). Two virtual hosts on one IP are two Services.

**Snapshot** — a declared batch of Observations treated as one view of the internet. Open while files arrive; Sealed when complete.

**Repeat Observation** — the same Service observed again (same or another Snapshot). Not a duplicate.

**Duplicate Observation** — the same Observation delivered more than once (same scanner banner ID).

**Eligible Observation** — an Observation that can carry signal evidence: non-empty banner, not honeypot-tagged, not a fingerprint-soup decoy.

**Signal Hit** — a Service matching one versioned signal rule, with the evidence that matched. A fact match, not a risk claim.

**Attribution** — the inference linking a Service to an Account, with per-source evidence and a tier; may abstain.

**Account** — a company a salesperson can target. Never an infrastructure provider by default.
