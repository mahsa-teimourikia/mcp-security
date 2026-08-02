# MCP security learning roadmap

Each step links directly to its training document, runnable lab, and (where available) notebook. Complete the reading before opening the Hub checkpoint.

## Beginner — understand the boundary

1. [MCP architecture and threat model](01-mcp-architecture-and-threat-model.md) · [manifest inventory lab](../labs/beginner/01_manifest_inventory.py)
2. [Tool schemas and safe boundaries](04-runtime-isolation-and-tool-safety.md) · [tool boundary lab](../labs/beginner/02_tool_boundary.py)

Outcome: identify every trust boundary and reject unsafe tools, schemas, paths, and destinations.

## Intermediate — verify and authorize the supply chain

3. [Provenance, SBOMs, and dependencies](03-supply-chain-provenance-and-dependencies.md) · [provenance lab](../labs/intermediate/01_provenance_gate.py) · [notebook](../labs/notebooks/02_provenance_gate.ipynb)
4. [Protocol authentication and authorization](02-protocol-authentication-and-authorization.md) · [egress lab](../labs/intermediate/02_egress_policy.py)

Outcome: release a pinned, signed server with explicit identity, policy, and egress gates.

## Advanced — operate protocols at scale

5. [Delegation across MCP and A2A](02-protocol-authentication-and-authorization.md) · [delegation lab](../labs/advanced/01_delegation_contract.py)
6. [Incident response and operations](05-incident-response-and-operations.md) · [containment lab](../labs/advanced/02_incident_response.py)

Outcome: contain a malicious server, preserve evidence, and recover from a known-good digest.

## Capstone sequence

Inventory a real or sample server → threat-model its tools → generate an SBOM → verify a signature → run it in an isolated environment → exercise a denied call → simulate compromise → revoke and roll back. Record evidence for each release gate.
