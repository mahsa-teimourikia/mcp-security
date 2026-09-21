# MCP Security Engineering — Curriculum Evolution Plan

> Historical migration record: the original `docs/`, `labs/`, and `hub/`
> paths below describe the pre-restructure repository. Their preserved source
> material now lives under `curriculum/shared/`; the canonical learner path is
> the numbered curriculum and the Vite application in `app/`.

## Audit scope and decision

This plan audits the repository as it exists on 2026-08-10: root documentation,
all `docs/` chapters and reference aids, every lab and notebook, the capstone,
the Learning Hub, quiz, validators, adversarial fixtures, image assets, and
repository automation/configuration. The repository has a strong, accurate
seed: its tenant-boundary, provenance, egress, delegation, runtime-policy, and
containment examples are useful because they run without credentials and assert
their security decisions. They should be preserved as concepts and test cases,
but are too small to be the primary labs for a full engineering program.

The canonical course will be rebuilt *around* this material, not from scratch.
Each numbered topic will own a chapter, one notebook, `lab.py`, assets where
needed, and a focused checkpoint. Reference aids remain available outside the
progression. The shared scenario is a multi-tenant support platform whose host
connects to a ticketing MCP server and selected downstream services; its
evolution makes the security consequences of each new capability visible.

## Audit findings

### Existing artifacts and disposition

| Existing material | Classification | Rationale and target |
| --- | --- | --- |
| `README.md` | EXPAND | Keep the Hub-first entry point and reference links; add outcomes by level, full 30-topic roadmap, setup, validation, scenario, and curated appendix. |
| `docs/01-mcp-architecture-and-threat-model.md` | SPLIT | The architecture material becomes Course 01; the threat-model material becomes Course 02. Both need protocol mechanics, diagrams, worked scenario, attack/defense/evaluation sections, and authoritative references. |
| `docs/02-protocol-authentication-and-authorization.md` | SPLIT | Separate Courses 06 (authentication/OAuth), 07 (authorization/policy), and 08 (delegation/confused deputy). Preserve its decision-flow framing. |
| `docs/03-supply-chain-provenance-and-dependencies.md` | SPLIT | Become Courses 12 (provenance/SBOM/signing) and 13 (CI/CD/release gates); retain release-gate content. |
| `docs/04-runtime-isolation-and-tool-safety.md` | SPLIT | Become Courses 03 (interface design), 09 (isolation), 10 (filesystem/network/SSRF), and 11 (injection/untrusted content). Preserve the tool-safety checklist as a reference aid. |
| `docs/05-incident-response-and-operations.md` | SPLIT | Become Courses 21 (detection, containment, forensics) and 22 (recovery, revocation, rollback). |
| `docs/06-tools-and-technologies.md` | REFERENCE | Preserve and update as a curated technology landscape; link into relevant lessons rather than presenting it as a course. |
| `docs/07-mcp-capstone.md` | EXPAND | Evolve into Course 30, including architecture, implementation, adversarial tests, evidence, release and rollback requirements. |
| `docs/08-threat-model-worksheet.md` | MOVE | Preserve as `reference/threat-model-worksheet.md` and make it an editable asset used by Course 02 and Course 29. |
| `docs/09-operator-checklist.md` | MOVE | Preserve as `reference/operator-checklist.md`; expand only as an operational companion to Courses 16, 21, 22, and 27. |
| `docs/10-protocol-comparison.md` | MOVE | Preserve as `reference/protocol-comparison.md`; update its evidence and use it in Courses 18–20. |
| `docs/11-runtime-assurance-and-observability.md` | SPLIT | Becomes Courses 16 (continuous assurance), 27 (SOC integration), and 28 (threat hunting). |
| `docs/mcp-supply-chain-security.md` | MERGE | Consolidate its useful introduction and references into the root README and topic chapters; avoid maintaining two competing course narratives. |
| `docs/roadmap.md` | MOVE | Replace with the canonical map in `curriculum/README.md`; retain a short redirect/reference page if external links need continuity. |
| `labs/beginner/01_manifest_inventory.py` | SPECIALIST LAB | Rework as Course 05's host capability-risk gate; retain its allow-list and schema assertions. |
| `labs/beginner/02_tool_boundary.py` | SPECIALIST LAB | Rework as Course 03's narrow-interface refactor; retain tenant-boundary tests. |
| `labs/intermediate/01_provenance_gate.py` | SPECIALIST LAB | Rework as Course 12's verification gate, with signed provenance/SBOM fixture parsing. |
| `labs/intermediate/02_egress_policy.py` | SPECIALIST LAB | Rework as Course 10's SSRF and egress lab; add DNS/IP/private-range and redirect cases. |
| `labs/intermediate/03_runtime_policy.py` | SPECIALIST LAB | Rework as Course 16's trace-to-policy lab; retain quarantine semantics. |
| `labs/advanced/01_delegation_contract.py` | SPECIALIST LAB | Rework as Course 08's flagship delegation/token-exchange lab; retain scope, expiry, and depth assertions. |
| `labs/advanced/02_incident_response.py` | MERGE | Merge into Course 21 with the containment runbook. |
| `labs/advanced/03_containment_runbook.py` | MERGE | Merge into Course 21; retain trace preservation and revocation behavior. |
| `labs/capstone_secure_server.py` | EXPAND | Reuse as the policy core of Course 30; replace toy-only coverage with a real MCP secure-server implementation and integration tests. |
| `labs/notebooks/01_manifest_review.ipynb` | SPLIT | Its host review narrative supports Course 05; redesign it as a cohesive notebook. |
| `labs/notebooks/02_provenance_gate.ipynb` | MOVE | Rebuild beside Course 12's `lab.py` under canonical curriculum structure. |
| `labs/notebooks/03_runtime_assurance.ipynb` | MOVE | Rebuild beside Course 16's `lab.py` under canonical curriculum structure. |
| `tests/adversarial_cases.json` | EXPAND | Keep as shared deterministic fixture; add source, expected decision, policy rule, trace fields, and topic ownership. |
| `hub/index.html`, `hub/app.js`, `hub/styles.css`, `hub/lessons.js` | EXPAND | Preserve design and progress behavior; replace the 9-item registry with all canonical topics, explicit Learn/Lab/Checkpoint links, reference route, and schema validation. |
| `quiz/index.html`, `quiz/questions.js`, `quiz/assets/*` | EXPAND | Preserve the quiz; add a scoring/test module and focused checkpoints. Repair the sparse-array entry caused by the double comma after the recovery question. |
| `scripts/validate_notebooks.py` | EXPAND | Validate topic ownership, one primary notebook per topic, notebook JSON, `lab.py` import/run, required instructional sections, and credential-free execution. |
| `scripts/check_links.py` | EXPAND | Validate Markdown, Hub registry, quiz, notebook asset paths, and canonical curriculum targets. |
| `assets/one-plus-i.png`, `assets/one-plus-i-light.png`, duplicated Hub/quiz assets | REFERENCE | Keep accessible brand assets; deduplicate via documented shared paths or retain required Pages copies after validating build behavior. |
| `LICENSE` | KEEP | No curriculum change required. |
| `requirements.txt`, `pyproject.toml`, CI workflows | NEW | No project dependency manifest or CI workflow exists. Add a pinned teaching dependency set and CI checks only when the first real SDK lab is introduced. |

## Target structure

```text
curriculum/
  beginner/01-mcp-architecture-lifecycle-trust-boundaries/
  beginner/02-threat-modeling-mcp-agent-protocols/
  beginner/03-secure-tool-resource-prompt-interfaces/
  beginner/04-minimal-secure-mcp-server/
  beginner/05-client-host-security-capability-negotiation/
  intermediate/06-mcp-authentication-oauth-security/ ... 13-secure-mcp-cicd-release-gates/
  advanced/14-mcp-security-testing-fuzzing/ ... 29-mcp-security-architecture-review-workshop/
  shared/fixtures/
app/
quiz/
tests/
```

Every topic will contain `README.md`, exactly one notebook, `lab.py`, and
topic-local assets if needed. Notebooks import their colocated/reusable lab
implementation and use deterministic mocks by default. Real MCP SDK examples
will be explicitly version-pinned and separated from mock mode; no secrets or
live side effects will be required.

## Canonical course map

| Target Course | Existing Material | Action | Scenario | Main Technology | Attack/Fault Lab | Evaluation |
| --- | --- | --- | --- | --- | --- | --- |
| 01. MCP Architecture, Lifecycle, and Trust Boundaries | 01 architecture | EXPAND | Support host connects to ticket server | Official MCP SDK | Trace lifecycle/capability confusion | Boundary inventory and trace assertions |
| 02. Threat Modeling MCP and Agent Protocol Systems | 01, 08 worksheet | EXPAND/MOVE | Ticketing integration review | STRIDE + DFD | Abuse-case attack tree | Threat-to-control/test/telemetry map |
| 03. Secure Tool, Resource, and Prompt Interface Design | 04, tool boundary | NEW/SPECIALIST LAB | Support operations APIs | JSON Schema/Pydantic | Broad shell/URL/path contracts | Allow/deny contract suite |
| 04. Building a Minimal Secure MCP Server | Capstone seed | NEW/EXPAND | Tenant support server | Official MCP Python SDK | Unsafe broad tool | Integration tests and structured traces |
| 05. MCP Client/Host Security and Capability Negotiation | Manifest notebook/lab | NEW/SPECIALIST LAB | Host approves server manifest | MCP client + policy gate | Malicious capability metadata | Capability risk score and revocation test |
| 06. MCP Authentication and OAuth Security | 02 | EXPAND | User reaches tenant server | OAuth/OIDC simulation | Passthrough/wrong-audience tokens | JWT validation matrix |
| 07. Authorization and Policy Enforcement | 02, runtime policy | NEW | Tenant ticket access | Cedar/OPA comparison + Python | Model-selected but unauthorized call | RBAC/ABAC/ReBAC negative suite |
| 08. Delegation, Token Exchange, and Confused Deputy | 02, delegation lab | EXPAND | Agent calls downstream ticket API | Token-exchange simulation | Cross-tenant deputy | Scope/audience/depth tests |
| 09. Runtime Isolation and Sandboxing | 04 | NEW | Local server execution | Containers/sandbox policy | Process escape attempt | Isolation-policy verification |
| 10. Filesystem, Network, SSRF, and Egress Security | 04, egress lab | EXPAND | Remote retrieval tool | URL/IP policy | Metadata/redirect/DNS rebinding cases | Egress decision metrics |
| 11. Prompt Injection, Tool Poisoning, and Untrusted MCP Content | 04, adversarial fixture | NEW | Untrusted ticket/resource content | Structured content handling | Poisoned prompt/tool output | Attack success and safe-completion rate |
| 12. Supply-Chain Provenance, SBOMs, Signing, and Dependencies | 03, provenance lab/notebook | EXPAND | Server release artifact | SLSA/Sigstore/SBOM tools | Tampered/missing-dependency artifact | Release evidence gate |
| 13. Secure MCP CI/CD and Release Gates | 03 | NEW | Promotion pipeline | GitHub Actions + policy gate | Bypassed/failed gate | CI evidence and rollback readiness |
| 14. MCP Security Testing and Fuzzing | adversarial cases | NEW | Server contract test suite | pytest/property tests | Schema/parser fuzz cases | Coverage and invariant failures |
| 15. MCP Red Teaming and Adversarial Evaluation | adversarial cases | NEW | Attack campaign | Evaluation harness | Prompt/tool/SSRF/delegation chain | Attack success, detection, containment |
| 16. MCP Runtime Observability and Continuous Assurance | 11, runtime notebook/lab | EXPAND | Production support server | OpenTelemetry-shaped traces | Behavior drift/untrusted output | Detection precision and MTTD/MTTR |
| 17. Server Registry, Discovery, Trust, and Enterprise Gateways | Manifest inventory | NEW | Enterprise server onboarding | Registry/gateway policy | Rogue server registration | Trust decision audit |
| 18. Agent-to-Agent / A2A Security and Delegation | 02, 10 comparison | NEW | Cross-agent support escalation | A2A/MCP concepts | Peer impersonation/task scope abuse | Peer and task authorization matrix |
| 19. Protocol Composition Security | 10 comparison | NEW | MCP + A2A runtime | Protocol adapters | Context/authority mismatch | Cross-protocol invariant tests |
| 20. Multi-Agent and Cross-Server Attack Paths | 01, adversarial cases | NEW | Multi-server ticket workflow | Attack graph | Lateral movement chain | Reachability and blast-radius score |
| 21. MCP Incident Detection, Containment, and Forensics | 05, advanced incident labs | EXPAND/MERGE | Compromised server event | Trace/evidence model | Malicious egress event | Revoke, preserve, scope affected traces |
| 22. Recovery, Revocation, Rollback, and Resilience | 05, containment | EXPAND | Restore known-good server | Registry + release rollback | Failed revocation/rollback | Recovery time and evidence checklist |
| 23. Enterprise MCP Security Architecture | roadmap, tool review | NEW | Enterprise platform design | Reference architecture | Boundary bypass | Architecture review rubric |
| 24. MCP Identity and Non-Human Identity Governance | 02 | NEW | Workload identities | SPIFFE/OIDC concepts | Orphaned credential | Identity lifecycle review |
| 25. MCP Security Governance and Risk Management | 09, roadmap | NEW | Risk committee | NIST/OWASP mapping | Unaccepted residual risk | Control ownership and exception test |
| 26. MCP Supply-Chain Risk Management | 03, 06 | NEW | Vendor/server portfolio | SLSA/SBOM risk model | Compromised upstream | Supplier risk decision record |
| 27. MCP Security Observability and SOC Integration | 11, 09 | NEW | SOC triage | SIEM-normalized events | Alert routing gap | Detection-to-case completeness |
| 28. MCP Threat Hunting and Runtime Anomaly Detection | 11 | NEW | Hunt across traces | Query/rule-based analytics | Low-and-slow exfiltration | Precision/recall on fixture set |
| 29. MCP Security Architecture Review Workshop | 08, 09, 10 | NEW | Design review | Threat-model worksheet | Architecture flaws | Review rubric and remediation plan |
| 30. Secure MCP Platform Capstone | 07, capstone lab, all prior labs | EXPAND | Full tenant support platform | Official MCP SDK + policy/testing | End-to-end adversarial campaign | Release gates, incident drill, architecture defense |

## Implementation sequence and quality gates

1. Create the canonical skeleton, migration index, shared fixtures, and a
   schema-driven Hub registry; do not delete legacy files until all inbound links
   have replacement targets.
2. Build and validate Courses 01–05 first. Course 04 establishes the real SDK
   server/client fixture; Course 05 consumes it through a host-side risk gate.
3. Build Courses 06–13 around the same server, preserving existing deterministic
   labs while adding typed, failure-driven implementations.
4. Build Courses 14–22 as an adversarial and operations layer over the same
   fixture and trace model.
5. Build Courses 23–30 as production architecture/governance workshops and the
   integrated capstone. Keep reference aids out of the required sequence.
6. At each topic gate: confirm README chapter progression; execute credential-free
   notebook and `lab.py`; check attack → trace → control → retest; add a focused
   checkpoint; verify local links/assets; add only authoritative current sources.
7. At repository gate: run lint/tests, all lab modules, notebook execution and
   JSON validation, Hub registry/link validation, quiz behavior tests, and Pages
   smoke checks. Validate deployed URLs separately before claiming publication.

## Known defects and constraints to repair during migration

- The current Hub has only nine lessons and does not represent the requested
  progression or individual Learn/Lab/Checkpoint artifacts.
- Most chapters (11–45 lines) and labs (4–16 lines) are intentionally compact;
  they require coherent rewrites, not appended checklists.
- The quiz contains a sparse array entry from `},,` after the recovery question.
  JavaScript parses it, but iteration must be tested so the empty item cannot
  break quiz behavior.
- Current notebook validation checks only for the strings `Reflection` and
  `runpy`; it does not execute notebooks or verify topic structure.
- No `requirements.txt`, `pyproject.toml`, or CI workflow is present in this
  repository. Add pinned dependencies and automation with the first SDK course.

## Research and safety policy

Protocol and security claims will be refreshed against MCP specification and
official SDK documentation, OAuth/OIDC and JWT standards, SLSA/Sigstore/SBOM
standards, OWASP/NIST guidance, and primary research for adversarial evaluation.
Labs will use offline fixtures, redacted trace fields, local-only endpoints, no
hard-coded credentials, narrow typed tools, explicit approvals for side effects,
and bounded retries. Educational vulnerable variants will be isolated and never
be the default runnable server.
