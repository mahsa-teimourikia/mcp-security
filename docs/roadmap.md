# Learning roadmap

Each step links to its training document and runnable implementation. Read the theory, run the lab, then use the Learning Hub checkpoint.

## Beginner — understand the boundary

[MCP architecture and threat model](01-mcp-architecture-and-threat-model.md) plus [runtime isolation and tool safety](04-runtime-isolation-and-tool-safety.md). Outcome: inventory a server and reject unsafe tool arguments.

## Intermediate — verify and authorize the supply chain

[Provenance and dependencies](03-supply-chain-provenance-and-dependencies.md) plus [protocol authentication and authorization](02-protocol-authentication-and-authorization.md). Outcome: release a pinned, authorized server with measurable gates.

## Advanced — operate protocols at scale

[Delegation and protocol composition](02-protocol-authentication-and-authorization.md) plus [incident response and operations](05-incident-response-and-operations.md). Outcome: contain a malicious server and prove recovery.

## Technology decision checkpoint

Before the capstone, read the [MCP development and security technology review](06-tools-and-technologies.md). Choose an SDK, transport, identity method, policy engine, provenance workflow, sandbox, testing strategy, and observability stack; record why each choice fits your threat model.

## Runtime assurance and observability

9. [Runtime security, observability, and continuous assurance](11-runtime-assurance-and-observability.md) · [runtime policy lab](../labs/intermediate/03_runtime_policy.py) · [containment runbook](../labs/advanced/03_containment_runbook.py) · [notebook](../labs/notebooks/03_runtime_assurance.ipynb)

Outcome: detect anomalous MCP behavior, apply a risk gate, and contain a compromised server using trace evidence.

## Capstone and operations

7. [Secure support server capstone](07-mcp-capstone.md) · [threat-model worksheet](08-threat-model-worksheet.md)
8. [Operator checklist](09-operator-checklist.md) · [protocol comparison](10-protocol-comparison.md)

Run `python3 labs/capstone_secure_server.py`, inspect `tests/adversarial_cases.json`, and complete the operator checklist before calling the course complete.
