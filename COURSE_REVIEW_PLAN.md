# Course-by-course review and improvement plan

This tracker governs the systematic review of all 29 published courses. Work is
performed one vertical slice at a time so a course is not marked complete when
only its prose, lab, notebook, quiz, or tests have improved.

## Definition of complete

A course moves to **complete** only when it passes every gate below:

1. **Coverage:** objectives, prerequisites, concepts, architecture, normal path,
   failure paths, mitigations, evaluation, operations, and limitations are all
   explicit; neighboring courses do not hide a prerequisite.
2. **State of practice:** established approaches, current official SDK/tooling,
   emerging techniques, and unresolved limitations are clearly separated.
3. **Sources:** important factual and security claims cite current primary or
   authoritative sources; version-sensitive claims use dated specifications.
4. **Realistic lab:** the recurring tenant support scenario uses common SDKs or
   libraries, deterministic fixtures, bounded execution, and no hidden services
   or credentials.
5. **Adversarial proof:** the lab has a normal path, vulnerable/hostile input,
   visible failure, implemented control, and regression test.
6. **Notebook:** the notebook is runnable in order and adds guided analysis,
   failure injection, metrics, exercises, and production transfer—not merely a
   wrapper around the lab.
7. **Assessment:** checkpoint questions test decisions and invariants rather
   than term recall; quiz coverage matches the lesson objectives.
8. **Enterprise invariant:** the agent proposes; trusted application code
   validates, authorizes, executes, verifies, records, and owns revocation.
9. **Reproducibility:** focused tests, the lesson lab, notebook execution, link
   checks, and repository-wide quality gates pass.

## Review sequence

The order preserves prerequisites and evolves one realistic support-platform
system instead of introducing disconnected toy examples.

| # | Course | Primary implementation and ecosystem emphasis | Status |
| ---: | --- | --- | --- |
| 01 | Architecture, protocol eras, trust boundaries | MCP spec 2026-07-28, Python SDK v2, Inspector v2, modern/legacy interoperability | Complete (2026-09-20) |
| 02 | Threat modeling | STRIDE, attack trees, data-flow diagrams, MITRE ATLAS/OWASP mappings | Next |
| 03 | Secure tools/resources/prompts | JSON Schema, typed validation, annotations, output validation, contract tests | Queued |
| 04 | Minimal secure server | Official Python SDK server, stdio, structured outputs, errors, Inspector | Queued |
| 05 | Client/host security | Official client, capability risk gates, origin/redirect controls, caches | Queued |
| 06 | Authentication and OAuth | MCP authorization spec, OAuth 2.1, protected-resource metadata, PKCE | Queued |
| 07 | Authorization and policy | RBAC/ABAC/ReBAC, OPA/Cedar comparison, deny-by-default enforcement | Queued |
| 08 | Delegation/confused deputy | RFC 8693 token exchange, audience/scope narrowing, delegation chains | Queued |
| 09 | Isolation and sandboxing | Containers, seccomp, namespaces, gVisor/Firecracker trade-offs | Queued |
| 10 | Filesystem/network/SSRF | Path containment, DNS/IP validation, egress proxies, metadata blocking | Queued |
| 11 | Injection and tool poisoning | OWASP guidance, taint/provenance, instruction/data separation, evals | Queued |
| 12 | Provenance/SBOM/signing | SLSA, SPDX/CycloneDX, Sigstore, dependency/vulnerability scanners | Queued |
| 13 | Secure CI/CD | GitHub Actions, pinned actions, attestations, policy gates, rollback | Queued |
| 14 | Testing and fuzzing | pytest, Hypothesis, schema/property tests, protocol conformance | Queued |
| 15 | Red teaming/evaluation | Threat-led test design, reproducible attack cases, scoring and gates | Queued |
| 16 | Runtime assurance | OpenTelemetry, traces/metrics/logs, SLOs, drift and behavioral controls | Queued |
| 17 | Registry/gateway trust | Official Registry, manifests, onboarding, policy proxies, revocation | Queued |
| 18 | A2A security | Current A2A specification/SDKs, agent cards, identity and delegation | Queued |
| 19 | Protocol composition | MCP+A2A trust translation, identity/context loss, end-to-end invariants | Queued |
| 20 | Multi-agent attack paths | Graph analysis, cross-server propagation, least-authority orchestration | Queued |
| 21 | Detection/containment/forensics | Evidence schema, kill switches, timelines, preservation and scoping | Queued |
| 22 | Recovery/revocation/resilience | Credential/artifact revocation, rollback, replay, chaos exercises | Queued |
| 23 | Enterprise architecture | Zones, gateways, identity, data controls, deployment reference design | Queued |
| 24 | Non-human identity | Workload identity, SPIFFE/SPIRE, secretless auth, lifecycle governance | Queued |
| 25 | Governance/risk | NIST AI RMF/CSF, ISO mappings, risk acceptance, ownership and metrics | Queued |
| 26 | Supply-chain risk management | Portfolio inventory, VEX, continuous assurance, supplier response | Queued |
| 27 | SOC integration | OTel/SIEM normalization, detection engineering, runbooks, case evidence | Queued |
| 28 | Threat hunting/anomaly detection | Hypothesis-led hunts, baselines, graph/sequence signals, false positives | Queued |
| 29 | Architecture review workshop | Evidence-backed design review, abuse cases, findings, remediation plan | Queued |

## Delivery waves

- **Wave 1 — foundation (01–05):** protocol correctness, trust boundaries,
  secure interfaces, real server/client SDKs, and host controls.
- **Wave 2 — enforcement (06–13):** identity, authorization, delegation,
  isolation, content security, provenance, and release controls.
- **Wave 3 — assurance (14–22):** testing, red teaming, runtime evidence,
  registry/A2A composition, incident response, and recovery.
- **Wave 4 — enterprise practice (23–29):** architecture, identity governance,
  risk, supply chain, SOC, hunting, and the integrated review workshop.

## Per-course review record

For each course, the implementation change should record:

- protocol/library versions and the date current sources were checked;
- claims added, corrected, qualified, or removed;
- lab dependencies and offline/credential requirements;
- positive, negative, boundary, and failure-injection tests;
- notebook execution result and measurable learner output;
- unresolved limitations intentionally deferred to a named later course; and
- the focused and full validation commands that passed.

Course 01 establishes the reference shape and passed its focused tests, all 29
credential-free labs, all 29 notebooks, link checks, quiz tests, and Learning
Hub production build on 2026-09-20. Course 02 is the next review target.
