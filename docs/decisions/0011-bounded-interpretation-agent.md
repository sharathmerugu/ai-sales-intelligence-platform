# 0011 — One bounded interpretation agent behind code-enforced publication checks

Status: accepted (2026-11-13). Builds on ADR 0009 and 0010; the analytical layers are unchanged.

## Context

Serving v4 gives a template report per account. The proposed target design asks for account-specific
interpretation for the seller's offering, with evidence-linked claims, while keeping the backend as the
system of record and avoiding a platform build (multiple agents, graph DB, workflow engine).

## Decision

1. A thin semantic layer (`firmable.semantic`): pydantic objects and query functions over the existing
   read-only serving DB. No new store, no ontology platform.
2. One agent with five retrieval tools and one submit tool, bound server-side to account, snapshot,
   lens and scope; budgets on model calls, tool calls, tokens and time. A manual loop (not the SDK tool
   runner) because the loop owns budgets, repair and fallback.
3. Code decides publication (`firmable.agent.checks`): evidence linkage, numbers, product names,
   unsupported conclusions, status coherence, emphasis and communication rules. Status, ranks,
   confidence and dates on the card come from the backend, never from the model.
4. A deterministic brief in the same card shape is the fallback and the no-model default; it must pass
   the same checks.
5. Application state in SQLite inside the API process (thread pool, partial unique index for one active
   run per cache key). Postgres and a separate worker are the documented next step, not built.
6. Provider: Anthropic SDK behind a provider-neutral `LLMClient`; `mock` for tests and demos.

## Consequences

- No analytical value can change through this path; the agent can only choose emphasis and words.
- Pattern checks reject known failure classes but do not prove entailment; reviewer cases remain needed.
- Without durable storage on Railway, runs are lost on restart; acceptable until a volume or Postgres is
  added. A real-model evaluation is required before any quality or cost claim.
