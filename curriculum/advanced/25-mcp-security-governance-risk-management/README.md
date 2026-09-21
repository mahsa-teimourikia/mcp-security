# MCP Security Governance and Risk Management

## Learning objectives

Translate MCP threats into owned risks; connect controls to tests, telemetry,
incidents, and evidence; operate exceptions and residual-risk decisions; and
establish review triggers for system, vendor, model, capability, identity, and
deployment changes.

## Governance model

Governance does not replace engineering. It makes decisions accountable:
inventory integrations and owners; classify data and impact; set control
baselines; require evidence; track residual risk; approve time-bounded
exceptions; review material changes; and audit revocation/incident readiness.
Use the Course 02 threat model and Courses 12–22 evidence as inputs, not as
independent paperwork.

## Lab and operations

Run `python3 lab.py`. A decision needs an owner and tested-control evidence;
high residual risk also needs an active exception. Production records include
risk ID, scenario, asset/tenant, likelihood/impact rationale, controls, test
and telemetry links, owner, decision authority, exception compensating controls,
expiry, review date, and incident linkage. Test expired exception, owner change,
unverified control, material capability change, and stale risk assessment.

## References

- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
