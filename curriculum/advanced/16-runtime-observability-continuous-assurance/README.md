# MCP Runtime Observability and Continuous Assurance

## Learning objectives

Define security-relevant MCP traces; correlate artifact identity, session,
principal/tenant, capability, tool/resource, destination, policy decision, and
result; detect behavioral drift; and route signals to bounded controls without
granting new authority.

## Telemetry model

Record trace ID, server identity/digest/version, host-client session,
principal/tenant (pseudonymized as needed), capability, tool/resource/prompt,
argument class rather than raw sensitive payload, destination, policy version
and decision, error class, approval fingerprint, and revocation state. Never
record bearer tokens, unbounded private content, or hidden model reasoning.
Observability is evidence, not authorization.

## Lab: observe → detect → control

Run `python3 lab.py`. A reviewed artifact and approved destination allow.
Artifact drift quarantines, unapproved egress blocks, and injected content or
repeated denials trigger review. The fixture is a deterministic risk gate, not
anomaly ML. Production assurance combines rules, baselines, sampled traces,
policy/version-change events, and operator review.

## Evaluation and operations

Measure precision/recall on labeled fixtures, false review rate, time-to-detect,
time-to-revoke, time-to-rollback, trace completeness, and safe completion.
Test missing telemetry, artifact drift, capability change, unknown destination,
injection, log loss, and control-plane compromise. Preserve redaction,
integrity, retention, access controls, and a runbook that links an alert to
affected sessions and artifact digests.

## References

- [OpenTelemetry specification](https://opentelemetry.io/docs/specs/otel/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
