# Roadmap

## Current program state

- All 30 vertical slices are published with a chapter, reusable lab, canonical
  notebook, focused tests, checkpoint coverage, and Learning Hub entry.
- Course 30 integrates the tenant-scoped support scenario from signed release
  through runtime authorization, uncertain effects, containment, recovery, and
  reauthorization.
- Future work deepens existing proof and production transfer rather than adding
  disconnected topics.

## Maintenance baseline (verified 2026-10-31)

- The curriculum targets MCP `2026-07-28`, MCP Python SDK 2.3.x, A2A 1.0,
  and A2A Python SDK 1.3.x.
- The primary toolchain is Python 3.15 and Node.js 26 LTS; CI also proves the
  declared Python 3.11 floor.
- Python and npm dependencies are locked, audited, and monitored by weekly
  Dependabot updates. Third-party GitHub Actions are pinned to immutable
  commits.
- All 30 labs and notebooks execute in CI, and all 30 courses have a dedicated
  checkpoint inside the comprehensive 219-question assessment bank.

## Next quality improvements

- Deepen remaining lessons with property-based and protocol-level tests.
- Add more cross-tenant, replay, stale-state, and unknown-outcome cases where
  a lesson still demonstrates only a narrower invariant.
- Add durable database and queue adapters for approval, idempotency, event
  ordering, and recovery while preserving the credential-free default path.
- Validate real OPA/Cedar, Sigstore/SLSA, SPIFFE, and SIEM integrations in
  optional test profiles that reuse the deterministic policy contracts.
- Add scheduled external-reference validation with redirect and rate-limit
  handling, without turning transient documentation outages into release
  blockers.
- Add automated browser accessibility checks for the Hub and quiz.

## Contribution ideas

- Add sanitized MCP JSON-RPC traces to an existing lesson.
- Turn a prose-only production control into a deterministic invariant test.
- Add a failure injection and explain the observable evidence it should emit.
- Improve accessible diagrams without embedding secrets or private data.
