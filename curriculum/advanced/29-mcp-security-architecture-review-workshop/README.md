# MCP Security Architecture Review Workshop

## Learning objectives

Conduct a structured review of an MCP platform or integration; trace design
claims to threat model, identity, policy, provenance, isolation, telemetry,
recovery, owner, and test evidence; and produce prioritized remediation with
explicit residual risk.

## Workshop flow

1. State scenario, users/tenants, data classification, side effects, and
success/non-goals.
2. Draw architecture/data/control flows and identify every trust boundary.
3. Review server onboarding, artifact provenance, identity/delegation, policy,
tool/resource/prompt contracts, isolation/egress, telemetry/SOC, and recovery.
4. Run abuse cases and inspect tests/traces/runbooks rather than accepting
claims. Record gaps, severity/rationale, owner, compensating control, due date,
and residual-risk decision.

## Lab and deliverables

Run `python3 lab.py`. The rubric requires evidence across the control planes
and a named owner; missing recovery fails the review. The workshop deliverables
are a versioned DFD/threat model, architecture decision record, control-to-test
matrix, adversarial results, observability fields, incident/recovery drill, and
remediation register. It is not a compliance checkbox: material changes trigger
review.

## References

- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST SP 800-154](https://csrc.nist.gov/pubs/sp/800/154/final)
