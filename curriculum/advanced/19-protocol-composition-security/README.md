# Protocol Composition Security: MCP + A2A + Agent Runtimes

## Learning objectives

Identify security-context loss at protocol adapters; preserve authenticated
subject, tenant, action, resource/purpose, audience, expiry, approval, trace,
and error semantics; and reject an adapter that broadens authority or silently
converts a denial into a retry/allow.

## Composition risk

Each protocol can be secure in isolation while their adapter is unsafe. A task
handoff may lose audience; an MCP tool call may lose user/tenant context; a
runtime retry may repeat a side effect; an error mapper may turn deny into
fallback; and a trace break may prevent containment across systems. Treat an
adapter as a security-critical policy enforcement and translation boundary.

## Lab and production controls

Run `python3 lab.py`. It accepts an A2A-to-MCP handoff only when the bounded
security envelope is complete and its audience matches the receiving MCP
resource; it rejects audience loss and action broadening. Production adapters
need typed versioned contracts, schema validation, explicit identity mapping,
audience/token exchange, action/resource intersection, approval carry-forward
only when bound to the exact action, idempotency keys, bounded retries, error
taxonomy, trace propagation, telemetry, and revocation propagation.

## Evaluation

Test missing/forged context, mismatched identity or tenant, scope/audience
expansion, stale approval, protocol-version skew, denied-action remapping,
retry duplication, trace loss, and partial cancellation. Measure cross-protocol
invariant completeness and the time to trace an incident end-to-end.

## References

- [MCP architecture](https://modelcontextprotocol.io/specification/latest/architecture)
- [A2A protocol](https://a2a-protocol.org/latest/)
