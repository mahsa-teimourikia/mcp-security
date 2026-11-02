# Roadmap

## Current program state

- All 30 vertical slices are published with a chapter, reusable lab, canonical
  notebook, focused tests, checkpoint coverage, and Learning Hub entry.
- Course 30 integrates the tenant-scoped support scenario from signed release
  through runtime authorization, uncertain effects, containment, recovery, and
  reauthorization.
- Future work deepens existing proof and production transfer rather than adding
  disconnected topics.

## Quality improvements

- Deepen advanced lessons with property-based and protocol-level tests.
- Add tested approval receipts and idempotent side-effect examples.
- Execute every credential-free notebook in CI within bounded time.
- Add more cross-tenant, replay, stale-state, and unknown-outcome cases.
- Expand the quiz with at least one architecture-judgment checkpoint per topic.
- Add durable database and queue adapters for approval, idempotency, event
  ordering, and recovery while preserving the credential-free default path.
- Validate real OPA/Cedar, Sigstore/SLSA, SPIFFE, and SIEM integrations in
  optional test profiles that reuse the deterministic policy contracts.

## Contribution ideas

- Add sanitized MCP JSON-RPC traces to an existing lesson.
- Turn a prose-only production control into a deterministic invariant test.
- Add a failure injection and explain the observable evidence it should emit.
- Improve accessible diagrams without embedding secrets or private data.
