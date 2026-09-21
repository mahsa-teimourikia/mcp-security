# MCP Identity and Non-Human Identity Governance

## Learning objectives

Govern hosts, clients, servers, agents, gateways, CI jobs, and service accounts
as non-human identities; assign ownership; bind each identity to audience and
least privilege; automate short-lived issuance/rotation/revocation; and detect
orphaned or overprivileged identities.

## Governance model

Every workload identity needs a stable ID, owner/team, purpose, environment,
audience/resource, allowed actions, credential type, issuance path, expiry,
rotation, last use, review cadence, and revocation control. Prefer workload
identity and short-lived credentials over shared static secrets. Separate host,
server, pipeline, and downstream API identities; do not reuse a broad platform
credential across all MCP integrations.

## Lab and evaluation

Run `python3 lab.py`. The fixture permits only an owned, non-revoked,
unexpired, audience-bound, narrowly scoped workload identity. It rejects an
orphaned identity and an `admin` scope. Production adds attested workload
identity, secret-manager integration, JIT access, inventory reconciliation,
break-glass controls, access reviews, anomaly monitoring, and incident rotation.
Test expiry, owner departure, stale environment, audience mismatch, scope
creep, credential replay, and revocation propagation.

## References

- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-4/)
- [SPIFFE](https://spiffe.io/docs/latest/)
