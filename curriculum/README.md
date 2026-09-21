# MCP Security Engineering curriculum

This is the canonical learning sequence for the MCP Security Engineering,
Agent Protocol Security, and AI Supply-Chain Security program. Start with the
[Learning Hub](../README.md#start-with-the-learning-hub); the Hub tracks
progress and opens each topic's chapter, lab, and checkpoint.

The support-platform scenario evolves through the curriculum: a host connects
to a tenant-scoped ticketing MCP server, then adds identity, policy, delegation,
release controls, observability, and enterprise operations. Each course must
teach a normal path, a deliberately vulnerable variant, an attack trace, a
control, and a retest. Offline labs are the default; integrations that need
credentials are explicitly optional.

The systematic quality review is tracked in the repository's
[course-by-course review plan](../COURSE_REVIEW_PLAN.md).

## Progression

| Level | Topics |
| --- | --- |
| Beginner | 01 Architecture, lifecycle, and trust boundaries · 02 Threat modeling · 03 Secure interfaces · 04 Minimal secure server · 05 Client/host security |
| Intermediate | 06 Authentication and OAuth · 07 Authorization and policy · 08 Delegation and confused deputy · 09 Isolation · 10 Filesystem/network/SSRF · 11 Injection and untrusted content · 12 Provenance/SBOM/signing · 13 CI/CD release gates |
| Advanced | 14 Testing and fuzzing · 15 Red teaming · 16 Observability and assurance · 17 Registry and gateway · 18 A2A security · 19 Protocol composition · 20 Cross-server attack paths · 21 Detection and forensics · 22 Recovery and resilience · 23 Enterprise architecture · 24 Non-human identity · 25 Governance and risk · 26 Supply-chain risk · 27 SOC integration · 28 Threat hunting · 29 Architecture review workshop |

## Available now

1. [MCP Architecture, Lifecycle, and Trust Boundaries](beginner/01-mcp-architecture-lifecycle-trust-boundaries/README.md) — chapter · [lab](beginner/01-mcp-architecture-lifecycle-trust-boundaries/lab.py) · [notebook](beginner/01-mcp-architecture-lifecycle-trust-boundaries/mcp_architecture_lifecycle.ipynb)
2. [Threat Modeling MCP and Agent Protocol Systems](beginner/02-threat-modeling-mcp-agent-protocols/README.md) — chapter · [lab](beginner/02-threat-modeling-mcp-agent-protocols/lab.py) · [notebook](beginner/02-threat-modeling-mcp-agent-protocols/mcp_threat_modeling.ipynb)
3. [Secure Tool, Resource, and Prompt Interface Design](beginner/03-secure-tool-resource-prompt-interfaces/README.md) — chapter · [lab](beginner/03-secure-tool-resource-prompt-interfaces/lab.py) · [notebook](beginner/03-secure-tool-resource-prompt-interfaces/secure_interfaces.ipynb)
4. [Building a Minimal Secure MCP Server](beginner/04-minimal-secure-mcp-server/README.md) — chapter · [lab](beginner/04-minimal-secure-mcp-server/lab.py) · [notebook](beginner/04-minimal-secure-mcp-server/minimal_secure_server.ipynb)
5. [MCP Client/Host Security and Capability Negotiation](beginner/05-client-host-security-capability-negotiation/README.md) — chapter · [lab](beginner/05-client-host-security-capability-negotiation/lab.py) · [notebook](beginner/05-client-host-security-capability-negotiation/capability_negotiation.ipynb)
6. [MCP Authentication and OAuth Security](intermediate/06-mcp-authentication-oauth-security/README.md) — chapter · [lab](intermediate/06-mcp-authentication-oauth-security/lab.py) · [notebook](intermediate/06-mcp-authentication-oauth-security/oauth_security.ipynb)
7. [Authorization and Policy Enforcement](intermediate/07-authorization-policy-enforcement/README.md) — chapter · [lab](intermediate/07-authorization-policy-enforcement/lab.py) · [notebook](intermediate/07-authorization-policy-enforcement/policy_enforcement.ipynb)
8. [Delegation, Token Exchange, and Confused Deputy](intermediate/08-delegation-token-exchange-confused-deputy/README.md) — chapter · [lab](intermediate/08-delegation-token-exchange-confused-deputy/lab.py) · [notebook](intermediate/08-delegation-token-exchange-confused-deputy/delegation_security.ipynb)
9. [Runtime Isolation and Sandboxing](intermediate/09-runtime-isolation-sandboxing/README.md) — chapter · [lab](intermediate/09-runtime-isolation-sandboxing/lab.py) · [notebook](intermediate/09-runtime-isolation-sandboxing/runtime_isolation.ipynb)
10. [Filesystem, Network, SSRF, and Egress Security](intermediate/10-filesystem-network-ssrf-egress-security/README.md) — chapter · [lab](intermediate/10-filesystem-network-ssrf-egress-security/lab.py) · [notebook](intermediate/10-filesystem-network-ssrf-egress-security/egress_security.ipynb)
11. [Prompt Injection, Tool Poisoning, and Untrusted MCP Content](intermediate/11-prompt-injection-tool-poisoning-untrusted-content/README.md) — chapter · [lab](intermediate/11-prompt-injection-tool-poisoning-untrusted-content/lab.py) · [notebook](intermediate/11-prompt-injection-tool-poisoning-untrusted-content/untrusted_content.ipynb)
12. [Supply-Chain Provenance, SBOMs, Signing, and Dependencies](intermediate/12-supply-chain-provenance-sbom-signing-dependencies/README.md) — chapter · [lab](intermediate/12-supply-chain-provenance-sbom-signing-dependencies/lab.py) · [notebook](intermediate/12-supply-chain-provenance-sbom-signing-dependencies/provenance_gate.ipynb)
13. [Secure MCP CI/CD and Release Gates](intermediate/13-secure-mcp-cicd-release-gates/README.md) — chapter · [lab](intermediate/13-secure-mcp-cicd-release-gates/lab.py) · [notebook](intermediate/13-secure-mcp-cicd-release-gates/release_gates.ipynb)
14. [MCP Security Testing and Fuzzing](advanced/14-mcp-security-testing-fuzzing/README.md) — chapter · [lab](advanced/14-mcp-security-testing-fuzzing/lab.py) · [notebook](advanced/14-mcp-security-testing-fuzzing/security_testing.ipynb)
15. [MCP Red Teaming and Adversarial Evaluation](advanced/15-mcp-red-teaming-adversarial-evaluation/README.md) — chapter · [lab](advanced/15-mcp-red-teaming-adversarial-evaluation/lab.py) · [notebook](advanced/15-mcp-red-teaming-adversarial-evaluation/red_team_evaluation.ipynb)
16. [MCP Runtime Observability and Continuous Assurance](advanced/16-runtime-observability-continuous-assurance/README.md) — chapter · [lab](advanced/16-runtime-observability-continuous-assurance/lab.py) · [notebook](advanced/16-runtime-observability-continuous-assurance/runtime_assurance.ipynb)
17. [MCP Server Registry, Discovery, Trust, and Enterprise Gateways](advanced/17-server-registry-discovery-trust-enterprise-gateways/README.md) — chapter · [lab](advanced/17-server-registry-discovery-trust-enterprise-gateways/lab.py) · [notebook](advanced/17-server-registry-discovery-trust-enterprise-gateways/registry_trust.ipynb)
18. [Agent-to-Agent / A2A Security and Delegation](advanced/18-agent-to-agent-a2a-security-delegation/README.md) — chapter · [lab](advanced/18-agent-to-agent-a2a-security-delegation/lab.py) · [notebook](advanced/18-agent-to-agent-a2a-security-delegation/a2a_security.ipynb)
19. [Protocol Composition Security](advanced/19-protocol-composition-security/README.md) — chapter · [lab](advanced/19-protocol-composition-security/lab.py) · [notebook](advanced/19-protocol-composition-security/protocol_composition.ipynb)
20. [Multi-Agent and Cross-Server Attack Paths](advanced/20-multi-agent-cross-server-attack-paths/README.md) — chapter · [lab](advanced/20-multi-agent-cross-server-attack-paths/lab.py) · [notebook](advanced/20-multi-agent-cross-server-attack-paths/attack_paths.ipynb)
21. [MCP Incident Detection, Containment, and Forensics](advanced/21-incident-detection-containment-forensics/README.md) — chapter · [lab](advanced/21-incident-detection-containment-forensics/lab.py) · [notebook](advanced/21-incident-detection-containment-forensics/incident_forensics.ipynb)
22. [Recovery, Revocation, Rollback, and Resilience](advanced/22-recovery-revocation-rollback-resilience/README.md) — chapter · [lab](advanced/22-recovery-revocation-rollback-resilience/lab.py) · [notebook](advanced/22-recovery-revocation-rollback-resilience/recovery_resilience.ipynb)
23. [Enterprise MCP Security Architecture](advanced/23-enterprise-mcp-security-architecture/README.md) — chapter · [lab](advanced/23-enterprise-mcp-security-architecture/lab.py) · [notebook](advanced/23-enterprise-mcp-security-architecture/enterprise_architecture.ipynb)
24. [MCP Identity and Non-Human Identity Governance](advanced/24-mcp-identity-non-human-identity-governance/README.md) — chapter · [lab](advanced/24-mcp-identity-non-human-identity-governance/lab.py) · [notebook](advanced/24-mcp-identity-non-human-identity-governance/nonhuman_identity.ipynb)
25. [MCP Security Governance and Risk Management](advanced/25-mcp-security-governance-risk-management/README.md) — chapter · [lab](advanced/25-mcp-security-governance-risk-management/lab.py) · [notebook](advanced/25-mcp-security-governance-risk-management/governance_risk.ipynb)
26. [MCP Supply-Chain Risk Management](advanced/26-mcp-supply-chain-risk-management/README.md) — chapter · [lab](advanced/26-mcp-supply-chain-risk-management/lab.py) · [notebook](advanced/26-mcp-supply-chain-risk-management/supply_chain_risk.ipynb)
27. [MCP Security Observability and SOC Integration](advanced/27-mcp-security-observability-soc-integration/README.md) — chapter · [lab](advanced/27-mcp-security-observability-soc-integration/lab.py) · [notebook](advanced/27-mcp-security-observability-soc-integration/soc_integration.ipynb)
28. [MCP Threat Hunting and Runtime Anomaly Detection](advanced/28-mcp-threat-hunting-runtime-anomaly-detection/README.md) — chapter · [lab](advanced/28-mcp-threat-hunting-runtime-anomaly-detection/lab.py) · [notebook](advanced/28-mcp-threat-hunting-runtime-anomaly-detection/threat_hunting.ipynb)
29. [MCP Security Architecture Review Workshop](advanced/29-mcp-security-architecture-review-workshop/README.md) — chapter · [lab](advanced/29-mcp-security-architecture-review-workshop/lab.py) · [notebook](advanced/29-mcp-security-architecture-review-workshop/architecture_review.ipynb)

Course 30 remains planned until its integrated capstone meets the same artifact
and validation gates. See the repository [roadmap](../ROADMAP.md).
