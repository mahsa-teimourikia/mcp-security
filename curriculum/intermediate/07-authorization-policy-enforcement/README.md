# Authorization and Policy Enforcement

## Learning objectives

Evaluate a decision over principal, action, resource, tenant, purpose, risk,
and approval; compare RBAC, ABAC, and relationship-based authorization; and
enforce denial at a tool/API boundary outside the model.

## Why authentication is not enough

Course 06 establishes that a support token is authentic and intended for a
resource. It does not answer whether its principal may read `acme-7`, draft a
reply, or use a ticket for a different purpose. “The model chose this tool” is
a proposal, never a permission decision.

```text
principal + action + resource + tenant + purpose + risk + approval → ALLOW / DENY
```

## Policy patterns

| Pattern | Strength | Limitation |
| --- | --- | --- |
| RBAC | Simple role administration | Weak resource/tenant context |
| ABAC | Claims and request context | Policy complexity |
| ReBAC | Ownership/relationship rules | Relationship data dependency |

Production systems commonly combine them: a role grants a candidate action;
tenant and purpose narrow it; relationships validate ownership; and an approval
record gates high-impact activity. Deny by default and evaluate at the server
tool boundary and, where applicable, the downstream resource server.

## Lab: normal → negative case → approval → retest

Run `python3 lab.py`. A tenant-matching support read is allowed. The same
authenticated principal is denied for another tenant's ticket. A reply draft is
denied until risk and explicit approval satisfy policy. This offline model
teaches decision semantics; it is not a replacement for Cedar, OPA/Rego, or
OpenFGA in a production deployment.

## Failure modes and production upgrade

Reject model/client-supplied tenant as the sole identity source, stale policy,
permissive default, and authorization performed only in the UI. Log a redacted
decision with policy version, principal ID, action, resource ID, result, and
reason. Test allow, deny, cross-tenant, missing-purpose, stale-approval, and
policy-rollback cases. A policy engine does not remove application ownership of
safe distribution, testing, explainability, and failure behavior.

## Exercises

1. Add a relationship rule for a user assigned to a ticket.
2. Add an expiry-bound approval and test replay.
3. Explain why host capability filtering cannot replace server-side policy.

## References

- [MCP authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [OPA policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Cedar policy language](https://docs.cedarpolicy.com/)
