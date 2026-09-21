# MCP Server Registry, Discovery, Trust, and Enterprise Gateways

## Learning objectives

Design a server onboarding record; separate discovery from enablement; bind
identity, owner, endpoint/launch specification, artifact digest, capabilities,
review, and revocation; and use an enterprise gateway as a policy/observability
point without assuming it removes server-side controls.

## Control-plane model

Discovery answers what servers exist. A registry trust record answers which
server a host may use under which version, owner, capability, and policy.
Gateways can centralize transport controls, identity, routing, rate limits,
observability, and revocation, but must not silently expand user/server
authority or become an unreviewed universal credential broker.

## Lab and operations

Run `python3 lab.py`. An entry needs an owner, immutable digest, review, and
approved capability set; an unreviewed rogue entry and a revoked entry deny.
Production onboarding verifies provenance, identity, policy compatibility,
transport, data classification, sandbox profile, incident owner, and test
evidence. Re-review changes; invalidate host caches; revoke active connections
and credentials; retain affected trace/digest evidence.

## Evaluation

Test rogue registration, owner loss, digest/capability drift, endpoint swap,
stale review, revocation propagation, gateway outage, bypass attempt, and
multi-tenant routing mistake. Measure onboarding time, unreviewed discovery
block rate, revocation propagation, and registry-to-host consistency.

## References

- [MCP architecture](https://modelcontextprotocol.io/specification/latest/architecture)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
