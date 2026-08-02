# 6. MCP development and security technology review

Technology choices determine the size of an MCP server's attack surface. Start with a narrow, typed server and add infrastructure only when its control is measurable. The table below focuses on maintained, widely adopted options; always verify current releases and security advisories before production use.

## Build an MCP server

| Area | Options | Good fit | Security considerations |
| --- | --- | --- | --- |
| Official SDK | [TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk), [Python SDK](https://github.com/modelcontextprotocol/python-sdk), Java/Kotlin/C# SDKs | Standards-compliant tools/resources/prompts | Pin SDK versions; validate schemas and capabilities; review transport defaults |
| Transport | stdio, Streamable HTTP, SSE (legacy) | stdio for local sandboxed tools; HTTP for remote services | TLS, origin validation, session binding, CSRF/replay protection, bounded message sizes |
| Validation | JSON Schema, Pydantic, Zod, TypeScript types | Runtime input and output validation | Schema validation is necessary but not sufficient; enforce semantic tenant/path/amount rules |
| Agent host | Custom host, LangGraph, OpenAI Agents SDK, Semantic Kernel | Explicit state, routing, approvals, and retries | Keep authorization outside prompts; cap loops, retries, tokens, and spend |

Use the official SDK when protocol compatibility matters. A thin adapter around business APIs is safer than exposing arbitrary HTTP, SQL, shell, or filesystem tools. Give each tool one clear purpose and document side effects, data classification, idempotency, and approval requirements.

## Identity, authorization, and policy

| Control | Options | Choose it when | Important guardrail |
| --- | --- | --- | --- |
| Authentication | OAuth 2.0/OIDC, mTLS, SPIFFE/SPIRE | Remote users/services or workload identity | Bind tokens to the MCP resource/audience and rotate short-lived credentials |
| Authorization | OPA/Rego, OpenFGA, Cedar, application policy module | Central policy, relationship checks, or small deterministic systems | Deny by default; test negative cases and fail closed |
| Delegation | OAuth Token Exchange, signed capability envelopes | Agent-to-agent or user-to-agent authority | Intersect scopes; limit audience, lifetime, resources, and delegation depth |
| Secrets | Vault, cloud secret manager, workload identity | Runtime credentials | Never inject the host environment wholesale or log tokens |

The model must not be the policy engine. Evaluate principal, audience, tenant, action, resource, risk, and approval in application code before every side effect. See [MCP authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization), [OAuth Security BCP](https://datatracker.ietf.org/doc/html/rfc9700), and [OAuth Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).

## Supply-chain and build security

- [Syft](https://github.com/anchore/syft) generates SBOMs; [OSV-Scanner](https://google.github.io/osv-scanner/) checks known vulnerabilities.
- [Sigstore/cosign](https://www.sigstore.dev/) signs artifacts and verifies provenance; [SLSA](https://slsa.dev/) defines increasing build assurance.
- Dependabot/Renovate keep lockfiles current, but updates still require tests and review.
- Use lockfiles and hash-pinned dependencies; reject unreviewed install scripts and mutable `latest` images.
- Scan source with Semgrep and containers with Trivy or an equivalent scanner, then record exceptions with expiry dates.

Signatures establish origin and integrity; they do not prove that a tool is safe. Combine provenance with threat modeling, code review, sandboxing, and adversarial tests.

## Runtime isolation and network controls

| Runtime | Fit | Security trade-off |
| --- | --- | --- |
| Dedicated process + stdio | Trusted local, low-risk utilities | Host privileges and filesystem must be explicitly restricted |
| Rootless container | Reproducible services and CI | Container is not a complete VM boundary; drop capabilities and use read-only mounts |
| gVisor/Firecracker/VM sandbox | Untrusted code or high-value data | More operational cost, stronger isolation |
| Cloud worker with egress policy | Stateless remote tools | Provider boundary and network policy become critical |

Allow-list HTTPS destinations; block metadata, localhost, private ranges, and unexpected DNS resolution. Limit CPU, memory, execution time, output size, retries, and concurrency. Separate server credentials from host credentials and use a temporary workspace.

## Testing and evaluation

- Unit-test schemas, policy decisions, path/URL canonicalization, and error handling.
- Contract-test initialize/capability negotiation and every tool's success and denial cases.
- Fuzz JSON inputs and URLs; add regression tests for SSRF, path traversal, confused deputy, token replay, and output injection.
- Use [AgentDojo](https://arxiv.org/abs/2406.13352), [ToolEmu](https://arxiv.org/abs/2309.15817), [garak](https://arxiv.org/abs/2406.11036), and [PyRIT](https://arxiv.org/abs/2410.02828) as research-informed evaluation references.
- Stage a canary server with synthetic data before enabling production tools; define release gates for exploit severity, denial correctness, latency, and cost.

## Observability and operations

Use OpenTelemetry to trace `user → host → client → server → tool → resource`. Capture correlation ID, principal, audience, tool/version, policy version, decision, artifact digest, latency, and outcome. Redact tokens and sensitive arguments. Keep a kill switch, credential revocation path, known-good digest, and tested rollback runbook.

## Recommended default stack

For a new Python server: official Python MCP SDK + Pydantic schemas + stdio in a rootless sandbox for local tools; OAuth/mTLS and an explicit egress proxy for remote tools; OPA or a small tested policy module; Syft/OSV-Scanner/Sigstore in CI; OpenTelemetry for traces; and a Hub lab that demonstrates both allowed and denied calls. Choose a more complex platform only when its added control outweighs its operational and supply-chain cost.
