# Agent-to-Agent / A2A Security and Delegation

## Learning objectives

Authenticate agent peers, authorize a bounded task rather than a broad agent,
preserve tenant/purpose/trace linkage, limit lifetime and hops, and prevent a
downstream agent from treating a peer request as unrestricted authority.

## Security model

Agent-to-agent handoff adds another principal and another opportunity for scope,
context, and identity confusion. A task must name an authenticated sender and
recipient, tenant, purpose, allowed action/resource, expiry, delegation depth,
and correlation/parent trace. The recipient independently validates it and uses
its own narrow downstream authorization. Never forward broad user/host tokens
or make an agent identity synonymous with every user it assists.

## Lab and evaluation

Run `python3 lab.py`. The fixture accepts a known peer with a short-lived,
allow-listed task and parent trace; it rejects rogue peer identity and an
undelegated write action. Production adds signed/validated peer credentials,
audience binding, task schemas, replay protection/idempotency, queue durability,
revocation, human approval for high-impact tasks, and redacted cross-agent
traces. Test impersonation, expiry, replay, tenant mismatch, context poisoning,
task escalation, loop/depth overflow, and partial failure.

## References

- [A2A protocol](https://a2a-protocol.org/latest/)
- [OAuth Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)
