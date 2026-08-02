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
