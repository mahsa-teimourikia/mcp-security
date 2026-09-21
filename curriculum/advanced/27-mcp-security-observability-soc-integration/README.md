# MCP Security Observability and SOC Integration

## Learning objectives

Normalize MCP telemetry for SOC workflows; retain server digest, trace,
tenant/principal scope, capability/action, destination, policy decision, and
severity; enrich/dedupe alerts; and preserve a path from alert to containment
and recovery evidence.

## SOC model

Security operations needs structured events, not prose. Normalize timestamps,
trace/session IDs, server identity/digest/version, principal/tenant,
host/gateway, tool/resource/prompt, destination, policy/approval decision,
error, risk signal, and revocation state. Apply redaction/classification before
export. Map detections to owners and playbooks; correlate artifact, identity,
network, and incident records without storing raw tokens or full customer text.

## Lab and evaluation

Run `python3 lab.py`. It turns an MCP event into a triage record and elevates an
unapproved destination. Production integrations use a defined schema, reliable
delivery, access control, retention, integrity, alert deduplication, enrichment
from registry/identity/provenance, and tested case-to-containment automation.
Test missing fields, duplicate alerts, clock skew, poisoned telemetry, log loss,
false positives, and an alert whose server/digest is already revoked. Measure
coverage, alert fidelity, MTTD, MTTR, and case completeness.

## References

- [OpenTelemetry](https://opentelemetry.io/)
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
