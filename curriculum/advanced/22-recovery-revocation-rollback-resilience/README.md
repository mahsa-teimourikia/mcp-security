# Recovery, Revocation, Rollback, and Resilience

## Learning objectives

Recover an MCP service to verified known-good bytes; propagate revocation across
registry, host cache, sessions, credentials, and network; distinguish rollback
from root-cause eradication; and test resilience under partial failure.

## Recovery model

Disable the compromised server, invalidate cached capabilities, close sessions,
revoke or rotate delegated credentials, restrict egress, preserve evidence, and
deploy a verified known-good digest. Validate security regression tests before
re-enabling. A rollback to unverified bytes is not recovery.

## Lab and evaluation

Run `python3 lab.py`. Recovery needs registry revocation, session closure, grant
revocation, and a verified immutable rollback digest. It rejects partial
revocation. Production exercises include gateway/cache propagation, in-flight
requests, downstream token invalidation, policy/config rollback, dependency
compromise, and failover. Measure time-to-revoke, time-to-safe-service,
residual session count, rollback success, and regression result.

## Resilience controls

Use immutable deployments, versioned policy/configuration, trusted artifact
history, narrow credentials, idempotency, graceful degradation, and practiced
runbooks. Do not rely on mutable tags or revocation signals hosts do not consume.

## References

- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [SLSA](https://slsa.dev/)
