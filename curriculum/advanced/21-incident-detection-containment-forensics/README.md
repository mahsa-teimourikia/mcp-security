# MCP Incident Detection, Containment, and Forensics

## Learning objectives

Detect suspicious server behavior; contain it through server, session,
credential, and network controls; preserve redacted, integrity-protected
evidence; scope affected users/artifacts; and coordinate recovery without
destroying the forensic record.

## Incident sequence

Detect an evidence-backed signal, validate and classify it, contain the minimum
necessary boundary quickly, preserve traces and artifact identity, scope impact,
eradicate root cause, recover through known-good deployment, and learn through
tests/runbooks. Do not delete logs or rotate away the only evidence before
capturing it. Do not wait for a model decision to revoke a known malicious
server.

## Lab

Run `python3 lab.py`. A suspicious server is added to revocation and only its
events are preserved as the affected evidence set. In production, contain host
launch/connect, registry enablement, active sessions, delegated credentials,
egress, and downstream API access as appropriate. Preserve trace ID, timestamp,
server ID, digest/version, capability/tool, destination, policy decision,
principal/tenant identifiers, approval/action fingerprint, and redacted result
class; protect access and integrity.

## Evaluation and exercises

Exercise a malicious egress alert, dependency compromise, poisoned output, and
cross-tenant access event. Measure time-to-detect, time-to-contain, scoped-user
accuracy, evidence completeness, and time-to-recover. Write a runbook for
revoke/disable, token invalidation, network isolation, evidence export, owner
notification, and escalation. Course 22 covers rollback and resilience.

## References

- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
