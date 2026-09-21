# MCP Threat Hunting and Runtime Anomaly Detection

## Learning objectives

Form evidence-based MCP hunt hypotheses; query normalized traces for unexpected
artifact, capability, identity, tenant, destination, approval, and denial
patterns; distinguish a signal from a verdict; and route findings to triage,
containment, and regression tests.

## Hunting model

Start from a hypothesis, such as “a server artifact changed without review,”
“a tool reached an unapproved destination,” “denials indicate probing,” or “a
delegation chain exceeded normal depth.” Define expected baseline, query fields,
time window, exclusions, validation steps, and containment threshold. Anomaly
detection creates a risk signal; policy and operators decide action.

## Lab and evaluation

Run `python3 lab.py`. The offline hunt finds events with unapproved destinations
or unknown digests. Production hunts add statistical baselines carefully,
identity/registry enrichment, data-quality checks, peer review, and false-
positive analysis. Test low-and-slow egress, capability drift, token/audience
mismatch, cross-tenant denials, repeated injection signals, missing telemetry,
and attacker-forged benign fields. Measure precision, recall on labeled fixtures,
time-to-triage, and detection-to-containment completeness.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [OpenTelemetry](https://opentelemetry.io/)
