# MCP Security Architecture Review Workshop

A security architecture review is a versioned engineering decision about a
specific system, environment, and change. It must connect representations of
components, trust zones, data, identities, authority, and effects to current
evidence and executable abuse cases. A diagram, checklist percentage, model
opinion, signed artifact, or passing happy-path test is not enough.

The governing boundary for this capstone is:

> People and models may propose threats, controls, findings, and remediation.
> Trusted application code validates the exact review package, evidence scope
> and freshness, protected paths, test outcomes, reviewer authority, recording,
> and reassessment. A review outcome never authorizes production deployment.

Course 23 taught enterprise MCP architecture patterns and compared gateway-only
and hybrid enforcement. This final workshop asks a different question: given a
real proposed system and change, can a review team prove which claims are true,
identify unproved or unsafe paths, create accountable remediation, and preserve
an immutable record that becomes invalid when material assumptions change?

## Learning objectives

By the end of this course, you should be able to:

1. define review purpose, exact subject/version, tenants, environments, data,
   effects, owners, assumptions, non-goals, and decision authority;
2. create complementary context, container, component, deployment, data-flow,
   identity/authority-flow, and sequence views without confusing a drawing with
   runtime truth;
3. enumerate every entrypoint-to-protected-resource path and identify trust,
   tenant, privilege, protocol, data-classification, and side-effect boundaries;
4. express security statements as falsifiable owned control claims with explicit
   evidence contracts rather than checklist booleans;
5. verify evidence identity, producer, source locator, exact subject version,
   artifact digest, tests, result, time, expiry, and integrity;
6. model realistic MCP and agent threats using STRIDE-style prompts, abuse cases,
   attack trees, MITRE ATT&CK v20, and MITRE ATLAS without treating framework
   mapping as proof of exposure or coverage;
7. execute positive, negative, bypass, cross-tenant, failure, recovery, and
   independent-outcome tests for critical paths;
8. produce prioritized findings with rationale, affected evidence, owner,
   remediation, due date, compensating controls, and residual-risk handoff;
9. require independent exact attestation to record a review outcome while
   keeping deployment and residual-risk authorization separate; and
10. measure evidence, threat-test, and protected-path coverage with disclosed
    populations and trigger reassessment after material change.

## Prerequisites and execution

Complete the preceding architecture, governance, supply-chain, observability,
incident, recovery, and threat-hunting courses, or bring equivalent experience.
From the repository root:

```bash
uv sync --locked --extra contributor
uv run --frozen python curriculum/advanced/29-mcp-security-architecture-review-workshop/lab.py
uv run --frozen pytest -q tests/test_course_29_architecture_review.py
```

The lab is offline and credential-free. It uses dataclasses for explicit
contracts, SHA-256 for content identity, Ed25519 for peer-review attestations,
NetworkX for real path enumeration, locks for atomic recording, and pytest for
105 architecture invariants. It does not approve or modify production.

## State of practice reviewed 31 October 2026

### MCP protocol and SDK lifecycle

The current MCP protocol era matters to a review. The `2026-07-28` revision
removes protocol-level sessions and the `Mcp-Session-Id` header, uses
`server/discover`, and carries protocol version information per request. Modern
v2 SDKs can support that era while retaining earlier handshake compatibility.
Older `2025-11-25` and earlier peers use the initialization lifecycle. Review
the negotiated behavior and exact SDK/version; do not copy session, capability,
task, or authorization assumptions between eras.

MCP defines protocol behavior, not an enterprise authorization system. Review
token audience/resource binding, confused-deputy defenses, token passthrough,
least privilege, client installation, SSRF, local-server launch, and per-request
task/resource authorization at the implementation boundaries that enforce them.
Trace context, server descriptions, tool annotations, task IDs, and `_meta`
fields remain data—not identity or authority.

### Systems security engineering and AI risk

NIST SP 800-160 Volume 1 Revision 1 treats security as a systems-engineering
concern across the life cycle. Its architecture concept emphasizes security
domains, security-relevant elements, interconnections, trust relationships, and
behavior. That is a better foundation than a single network diagram.

NIST AI RMF organizes AI risk work around Govern, Map, Measure, and Manage. The
NIST Generative AI Profile adds GenAI-specific risks and actions. These sources
support governance and risk framing; they do not supply a pass/fail certificate
for one MCP deployment. Record which profile outcomes and local policies the
review actually applies.

### Verification, threat modeling, and adversary knowledge

OWASP ASVS 5.0.0, published 30 May 2025, provides testable security
requirements for applications and services. Use versioned requirement IDs as
one input to local control objectives and verification—not as an automatic
compliance claim. The OWASP Threat Modeling Cheat Sheet recommends integrating
threat modeling into the SDLC and beginning early enough to influence design.
The OWASP Agentic Security Initiative adds useful agentic-system abuse patterns.

MITRE ATT&CK v20 is current as of this review and includes AI-focused and
AI-enabled Enterprise techniques such as direct and indirect prompt injection,
AI-result poisoning, AI-enabled exfiltration, and impairment of autonomous
defenses. MITRE ATLAS complements ATT&CK for AI-system threats. Framework IDs
help structure scenarios and detection plans; only system-specific evidence
shows reachability, exploitability, defense behavior, and coverage.

## The workshop scenario

You are reviewing a multi-tenant support agent before a capability expansion.
The proposed system contains:

- an MCP host that receives user intent and renders untrusted ticket content;
- an enterprise MCP gateway that authenticates workloads, constrains protocol
  versions, routes tenants, and applies coarse policy;
- a support MCP server that reads and may update tickets;
- an OAuth-protected ticket system that owns ticket and tenant authorization;
- an evidence pipeline and SOC store; and
- build, registry, identity, policy, secret, network, incident, and recovery
  control planes not all visible on the request path.

The change adds a write-capable tool and adopts the modern MCP protocol era.
The review must determine whether the proposal is eligible for a separate risk
and deployment decision. It must not make either decision itself.

## Entry criteria: what the review team needs

Do not start the meeting with an empty whiteboard. Require a review package:

| Artifact | Minimum content |
| --- | --- |
| change request | stable ID, purpose, exact versions/digests, environments, rollout, rollback |
| ownership | business, technical, security, data, incident, and recovery accountability |
| scope | tenants, users, workloads, data classes, side effects, dependencies, non-goals |
| architecture views | context, component, deployment, DFD, identity/authority, sequence, recovery |
| inventory | components, SDKs, models, servers, tools, resources, prompts, stores, external services |
| trust model | zones, principals, credentials, issuers, audiences, delegation, policy points |
| threat model | assumptions, assets, properties, threats, abuse cases, ATT&CK/ATLAS references |
| evidence matrix | claims, evidence kinds, producers, exact subjects/versions, results, freshness |
| operations | telemetry, detections, runbooks, kill switches, recovery objectives and drills |
| tests | positive, negative, tenant, bypass, failure, concurrency, rollback, recovery outcomes |

An unavailable artifact is not automatically a failed control, but it is a
review gap. Mark it missing or inconclusive; never silently assume the design.

## Make the subject immutable

The lab's `ArchitecturePackage` binds:

- package, system, and version identity;
- exact protocol revisions;
- business, technical, and security owners;
- tenant model and data classifications;
- component kinds, zones, tenant scopes, versions, artifact digests, owners,
  and capabilities;
- flow endpoints, protocols, data classes, authentication, encryption, target
  authorization, tenant binding, telemetry, and side-effect semantics;
- entrypoints and protected resources;
- assumptions, non-goals, and change IDs; and
- preparation time and a canonical package digest.

Any material field change creates a new subject. A review of `support-8.1.0`
does not transfer to `support-8.2.0`; a diagram for the read-only tool does not
cover the new write tool; a successful test against a legacy handshake does not
prove the modern era.

## Use multiple architecture views

One diagram cannot answer every question.

### Context and ownership view

Show users, organizations, systems of record, external providers, environments,
owners, and decision authorities. Ask what outcome matters, which losses are
material, and who may accept residual risk.

### Component and deployment view

Show processes, containers, SDKs, plugins, models, MCP clients and servers,
gateways, queues, databases, collectors, policy engines, secret stores, identity
providers, nodes, namespaces, accounts, and regions. Logical separation is not
proof of runtime isolation; name the kernel, network, identity, storage, and
control-plane mechanisms that enforce it.

### Data-flow diagram

For every flow, record direction, protocol/version, authentication, encryption,
data classification, tenant binding, retention, logging, and whether an external
effect can occur. Include discovery, installation, initialization, list calls,
tool/resource/prompt invocation, callbacks, redirects, task polling, telemetry,
updates, and recovery—not only the happy-path tool call.

### Identity and authority-flow view

Trace user, client, workload, server, downstream resource, operator, and CI
identities. For each hop record issuer, subject, audience/resource, scopes,
tenant, purpose, proof-of-possession where relevant, delegation depth, expiry,
revocation, and the target that independently authorizes the action.

### Sequence and state view

Show normal, denied, retry, timeout-after-commit, cancellation, duplicate,
restart, partial failure, rollback, incident, and recovery sequences. A static
DFD cannot reveal unsafe retries, stale decisions, replayed approvals, or
unknown outcomes.

### Evidence and control-plane view

Show build/signing, registry, policy distribution, identity lifecycle, telemetry,
case management, kill switches, backups, recovery, and change detection. These
planes decide whether the runtime graph can be trusted and operated.

## Enumerate paths, not just boxes

The executable review uses NetworkX to enumerate each simple path from every
declared entrypoint to every protected resource. For each path it checks:

1. every crossing is authenticated and encrypted;
2. every relevant hop binds an authenticated tenant;
3. target authorization exists rather than only gateway admission;
4. telemetry can reconstruct the request, decision, effect, and outcome;
5. the path has independent enforcement at more than one boundary; and
6. the final protected resource enforces resource authorization.

A gateway is useful defense in depth, but a path is not secure merely because
it crosses a gateway. The MCP server and final resource must resist bypass,
misrouting, stale policy, confused-deputy behavior, and gateway compromise.

Parallel flows between the same two nodes are ambiguous in a simple directed
graph. The lab rejects them and asks the learner to model an explicit protocol,
broker, adapter, or enforcement component. Production graph tooling may use a
multigraph, but every distinct edge still needs its own contract and evidence.

## Turn claims into proof obligations

Avoid statements such as “OAuth is enabled,” “the sandbox is secure,” or “we
log everything.” Use a control-claim matrix:

| Claim field | Example |
| --- | --- |
| claim ID | `claim:authorization` |
| exact subject | `component:tickets@1.0.0` |
| falsifiable statement | every ticket read/write rechecks authenticated tenant ownership |
| owner | `owner:authorization` |
| required proof | negative cross-tenant test plus same-tenant integration test |
| failure meaning | possible disclosure or modification outside tenant scope |
| review cadence | on artifact, policy, identity, tenant, or tool-contract change |

Course 29 requires claims in ten control planes:

1. identity;
2. authorization;
3. provenance;
4. isolation;
5. egress;
6. data protection;
7. telemetry;
8. incident response;
9. recovery; and
10. change management.

Local systems may add privacy, safety, availability, legal, model, physical,
fraud, or sector-specific planes. Missing a required plane is a finding, not a
zero silently averaged into a score.

## Admit evidence, not assertions

`EvidenceItem` records:

- stable evidence and claim IDs;
- exact subject ID and version;
- evidence kind, producer, and source locator;
- executable test IDs;
- pass, fail, or inconclusive result;
- collection and expiry times;
- artifact digest; and
- evidence-record digest.

Passing evidence counts only if it is current, unexpired, no older than policy,
integrity-valid, complete, and bound to the reviewed subject version. A signed
statement about a different version is authentic but irrelevant. A screenshot
with no reproducible source or test ID may be useful context, but it does not
satisfy an executable proof obligation.

Use evidence diversity deliberately:

- configuration and policy-as-code review;
- unit, integration, property, fuzz, and adversarial tests;
- deployment/runtime isolation and egress probes;
- SLSA provenance, signatures, SBOMs, vulnerability and VEX evidence;
- trace replay and independent effect-state checks;
- access reviews and lifecycle/revocation exercises;
- incident tabletops and containment drills; and
- backup restore, recovery, rollback, and return-to-service drills.

Two views generated from one source are not independent corroboration. Record
the causal producer and exact subject.

## Build threat scenarios that can be tested

A useful threat scenario names:

- entrypoint and target;
- attacker preconditions and capabilities;
- protected properties;
- path and trust boundaries;
- concrete abuse steps;
- expected control behavior;
- independent outcome oracle;
- ATT&CK/ATLAS references where supported; and
- one executable abuse-test ID.

The lab exercises three capstone threats:

1. cross-tenant ticket disclosure;
2. indirect prompt injection driving a write-capable tool; and
3. replay of a stolen delegated token.

Expand these with malicious local-server installation, tool-description
poisoning, capability/version downgrade, SSRF and redirects, token passthrough,
task/callback enumeration, dependency compromise, policy outage, telemetry
suppression, unknown execution outcome, approval replay, and recovery rollback.

## Verify outcomes independently

An abuse test passes only when the expected defense acts and an independent
oracle verifies that the forbidden effect did not occur. A denial response is
not sufficient if the ticket was updated, data left the egress boundary, or a
task was already committed.

`AbuseResult` therefore binds the test and threat IDs to the exact architecture
package digest, authorized tenant, admitted evidence IDs, execution time, result,
and observed effect. The lab accepts `pass + blocked_and_verified`. Failed,
inconclusive, future, wrong-tenant, wrong-digest, missing-evidence, or unverified
results cannot satisfy threat coverage.

## Review each control plane

### Identity and delegation

- Which authenticated state defines user, workload, tenant, actor, audience,
  resource, purpose, and delegated scope?
- Does every child authority remain a subset of parent and current target
  policy?
- Are client, workload, server, CI, operator, and break-glass identities
  separate and lifecycle-managed?
- Can a prompt, tool argument, trace field, or server description spoof scope?

### Authorization and effects

- Does authorization happen at the MCP boundary and final resource?
- Are exact action, target, arguments, tenant, policy version, and current
  resource state checked?
- Do consequential effects require exact expiring single-use approval?
- Are retries idempotent and unknown outcomes reconciled before another effect?

### Protocol and interface contracts

- Which MCP era and revisions are supported, rejected, or translated?
- Are initialization/discovery, capabilities, extensions, tasks, notifications,
  pagination, cancellation, and errors validated for the negotiated era?
- Are tools/resources/prompts schema-bounded and outputs treated as untrusted?
- Can a protocol adapter widen capability or lose caller/tenant context?

### Provenance and supply chain

- Are exact source, revision, builder, workflow, artifact, signature, SBOM,
  dependencies, SDK, server, model, plugin, and deployment identities bound?
- Does admission policy distinguish cryptographic validity from authorization
  and safety?
- Can compromised signing identity, registry rollback, or runtime drift trigger
  quarantine and reassessment?

### Isolation, egress, and data protection

- What kernel/runtime enforces filesystem, network, process, secret, CPU,
  memory, and time limits?
- Are destinations, redirects, DNS answers, connect addresses, methods, headers,
  payloads, and response sizes controlled per hop?
- Are tenant stores, caches, vector indexes, task state, logs, and backups
  partitioned and deletion-aware?
- Are prompt, credential, personal, ticket, and regulated data minimized before
  export and assigned explicit retention?

### Telemetry, detection, and privacy

- Can admitted evidence reconstruct authority requested, decided, exercised,
  and independently observed?
- Are event, observed, and ingest time preserved with clock/delay semantics?
- Are secrets/raw tokens/prompts excluded or governed at the producer?
- Are detections and anomalies evidence-linked proposals rather than response
  authority?

### Incident response, recovery, and change

- Are kill switches, revocation, containment, evidence preservation, and
  reconciliation independently testable?
- Do backups restore security state as well as availability?
- Does return to service verify identities, policies, credentials, caches,
  routes, data, tasks, and post-cut effects?
- Which changes invalidate review evidence and trigger a new package?

## Findings and remediation

Every lab finding contains stable identity, severity, reason code, title,
rationale, affected components/flows/evidence, accountable owner, smallest
credible remediation, and due date. Severity follows impact:

- **critical**: credible cross-tenant disclosure, unauthorized effect, exposed
  secret, unprotected trust boundary, or complete bypass path;
- **high**: missing proof for a material control, failed abuse case, incomplete
  protected path, or unavailable recovery evidence;
- **medium/low**: bounded weaknesses or hardening opportunities that do not
  currently form a material unsafe path.

Do not convert severity labels into arithmetic and average away a critical
finding. A package is `needs_remediation` when any high or critical finding is
open. Otherwise it is only `eligible_for_risk_decision`.

Eligibility means the review found no blocker under its exact scope and policy.
It does not mean risk accepted, compliant, safe for every use, or authorized to
deploy.

## Independent attestation and immutable recording

The `ReviewRegistry` requires an independent `security_architect` or
`architecture_review_board` role. Package owners cannot attest their own work.
An Ed25519 attestation binds:

- purpose;
- exact package and report digests;
- reviewer identity and role; and
- issuance and expiry.

Recording verifies signature, scope, time, package, and report integrity. The
attestation is atomically single-use across operations. A stable operation ID
makes an exact retry idempotent; conflicting content is rejected. The resulting
record still says `production_authorized: false`.

Deployment approval, risk acceptance, exception approval, and change execution
remain separate governed decisions with their own authority and evidence.

## Material change and continuous review

Calendar review is not enough. Reassess when any of these change:

- artifact or dependency;
- capability/tool/resource/prompt contract;
- protocol era, SDK, transport, extension, or adapter;
- identity, issuer, audience, credential, delegation, or authorization policy;
- tenant model, data class, retention, trust boundary, or region;
- egress destination or external service;
- side effect, approval, retry, or task behavior;
- telemetry, detection, incident, recovery, or rollback mechanism; or
- a threat, vulnerability, signer compromise, incident, or failed control.

`MaterialChange` binds the change ID, package ID, prior package digest, changed
dimensions, and observation time to an existing record. A matching event moves
the record to `invalidated`; it cannot silently inherit eligibility.

## Metrics without false precision

The lab reports separate populations:

| Metric | Numerator | Denominator | Interpretation |
| --- | --- | --- | --- |
| evidence coverage | satisfied required evidence kinds | all required evidence slots | proof obligations currently met |
| threat-test coverage | threats with exact valid test results | in-scope threats | scenarios actually exercised |
| abuse-defense pass rate | blocked-and-independently-verified results | tested threats | observed defense result, not absence of unknown threats |
| critical-path coverage | fully secured protected paths | enumerated entrypoint-to-resource paths | modeled paths meeting every invariant |
| eligible packages | eligible review reports | reviewed package population | review workflow state, not deployment rate |

Always disclose time, environment, package versions, exclusions, and missing
paths. Track review lead time, remediation age, overdue critical findings,
reopened findings, change-to-invalidation latency, and architecture escapes
found after review. A high coverage percentage cannot override a critical
finding or a missing path from the denominator.

## Lab walkthrough

The executable scenario performs this vertical slice:

1. construct and seal an exact architecture package;
2. define ten owned control categories and evidence-kind contracts;
3. produce current integrity-bound evidence;
4. define three ATT&CK/ATLAS-linked abuse scenarios;
5. analyze trust-boundary flows and every protected graph path;
6. verify exact abuse-test outcomes and evidence IDs;
7. show an unsafe target-authorization/tenant-binding design fails with critical
   findings;
8. show the repaired design becomes eligible for a separate risk decision;
9. independently attest and idempotently record that exact review; and
10. invalidate the record after a capability change.

Expected output includes:

```json
{"after_material_change":"invalidated","critical_path_coverage":1.0,"evidence_coverage":1.0,"flawed_state":"needs_remediation","production_authorized":false,"recorded_state":"eligible_for_risk_decision","review_state":"eligible_for_risk_decision"}
```

## Workshop plan

### Phase 1: scope and representations

1. Write the decision question and what the review cannot authorize.
2. Pin exact versions, digests, tenants, environments, data, and side effects.
3. Name owners and independent decision authorities.
4. Draw context, component/deployment, DFD, identity/authority, sequence,
   evidence, incident, and recovery views.
5. List assumptions and actively design tests that could falsify each one.

### Phase 2: threats, claims, and evidence

1. Enumerate entrypoints, assets, protected properties, trust boundaries, and
   attack paths.
2. Use STRIDE-style prompts, privacy/safety prompts where relevant, ATT&CK v20,
   ATLAS, incident history, and architecture-specific misuse.
3. Convert proposed controls into falsifiable claims and required evidence.
4. Reject stale, wrong-version, unsigned/untraceable, failed, or inconclusive
   evidence for control satisfaction.
5. Execute abuse cases with independent outcome oracles.

### Phase 3: decision package

1. Prioritize findings by impact and reachability, not checklist count.
2. Assign owners, remediation, due dates, compensating controls, and verification.
3. Produce an architecture decision record and residual-risk handoff.
4. Obtain independent exact attestation.
5. Record the review without granting deployment authority.
6. Define continuous triggers and evidence refresh cadence.

## Deliverables

A complete workshop submission contains:

- immutable review manifest/package;
- versioned architecture views and legend;
- component, flow, identity, authority, data, and dependency inventories;
- trust-boundary and protected-path analysis;
- threat model and abuse-case catalog;
- control-claim-to-evidence matrix;
- executable test results and independent outcome evidence;
- findings/remediation register;
- architecture decision record;
- residual-risk and exception handoff where needed;
- incident, containment, recovery, and rollback evidence;
- metrics with populations and denominators; and
- change/reassessment triggers.

## Common review failures

| Failure | Why it misleads | Corrective pattern |
| --- | --- | --- |
| one diagram for everything | hides identity, deployment, state, and control planes | use complementary versioned views |
| gateway shown as the security boundary | misses bypass and final-resource authorization | enumerate every path and independent enforcer |
| identity copied from prompt/argument/trace | attacker-controlled data becomes authority | derive identity and tenant from authenticated state |
| checklist boolean | names a control without proof | falsifiable claim plus exact evidence contract |
| signature accepted as safety | proves relationship, not authorization or quality | validate signer, subject, context, policy, tests, and current state |
| passing happy path | says nothing about denial, tenant, bypass, or failure | negative and independent-outcome abuse cases |
| denial response treated as success | effect may already have committed | inspect downstream state and reconcile unknown outcomes |
| framework ID treated as exposure proof | mapping is contextual, not system evidence | bind threat to reachable reviewed path and test |
| average security score | can hide a critical path or missing denominator | deterministic blockers plus separate coverage metrics |
| review equals approval | widens reviewer authority | separate review, risk, exception, deployment, and execution decisions |
| annual review only | evidence silently becomes stale | event-driven invalidation and scheduled refresh |
| remediation without owner/due date | gap becomes durable ambiguity | named accountability and verification criterion |

## Tooling choices

The process is tool-independent. Common options include:

- C4-style diagrams and DFDs in Mermaid, PlantUML, Structurizr, or diagram tools;
- OWASP Threat Dragon, pytm, or managed threat-modeling platforms;
- NetworkX, graph databases, or architecture-query engines for path analysis;
- OPA/Rego, Cedar, cloud policy engines, and native IAM analyzers for policy
  experiments—while preserving final-resource authorization;
- MCP Inspector and official SDK test utilities for protocol behavior;
- pytest, Hypothesis, Schemathesis, fuzzers, and integration harnesses;
- OpenTelemetry plus governed logs/traces/metrics and SIEM evidence;
- Cosign/Sigstore, SLSA provenance, CycloneDX/SPDX, VEX, and vulnerability tools;
- CI/CD policy gates, artifact stores, issue trackers, and evidence registries.

Tool output remains evidence to validate. A graph engine does not know business
validity, a policy analyzer does not prove runtime enforcement, and a threat
model generator cannot expand review or execution authority.

## Exercises

1. Add a malicious local stdio server and model exact executable, filesystem,
   environment, egress, update, and user-consent evidence.
2. Add a legacy MCP peer behind a modern adapter. Test lifecycle downgrade,
   capability loss, caller/tenant propagation, tasks, and cancellation.
3. Add a second tenant and a shared cache. Prove cache-key, storage, task, search,
   telemetry, and backup isolation.
4. Add an asynchronous write tool. Model idempotency, timeout-after-commit,
   cancellation, duplicate delivery, and independent reconciliation.
5. Add a signed but vulnerable server artifact. Separate provenance, admission,
   exploitability, compensating controls, exception, and offboarding decisions.
6. Remove the SOC source for one boundary. Recalculate evidence and threat-test
   coverage without calling the path clean.
7. Run the flawed package, repair it, and explain which exact evidence converts
   each finding from open to verified.
8. Attempt concurrent attestation reuse and conflicting operation-ID retries;
   explain the atomicity and idempotency requirements.
9. Create a material protocol or capability change and demonstrate invalidation,
   scoped evidence reuse, and required retesting.
10. Write a final board brief that distinguishes facts, assumptions, findings,
    residual risks, exceptions, eligibility, and production authority.

## Exit checklist

### Scope and integrity

- [ ] Exact package, system, version, artifact, protocol, environment, tenants,
      data, effects, owners, assumptions, non-goals, and change are sealed.
- [ ] Every component and flow has stable identity and accountable ownership.
- [ ] Views agree or discrepancies are explicit findings.

### Paths and controls

- [ ] Every entrypoint-to-resource path is enumerated.
- [ ] Trust-zone crossings authenticate and encrypt both endpoints.
- [ ] Tenant binding and authorization occur at the MCP/tool and final resource.
- [ ] Side-effect paths have approval, idempotency, reconciliation, telemetry,
      and independent outcome evidence.
- [ ] Required control categories have falsifiable claims.

### Evidence and testing

- [ ] Evidence binds exact current subject/version, producer, locator, tests,
      result, digest, collection, and expiry.
- [ ] Missing, failed, stale, inconclusive, or wrong-scope evidence cannot pass.
- [ ] Threats have current ATT&CK/ATLAS mapping only where behavior supports it.
- [ ] Abuse tests cover tenant, bypass, failure, retry, recovery, and outcome.

### Decision and operations

- [ ] Findings have severity, rationale, evidence, owner, remediation, due date,
      compensating control, and verification criterion.
- [ ] Independent attestation binds the exact package/report and is single-use.
- [ ] Review outcome does not authorize risk acceptance, exception, deployment,
      or production effects.
- [ ] Material changes invalidate the record and trigger scoped reassessment.
- [ ] Metrics name population, numerator, denominator, time, and exclusions.

## Authoritative and official references

- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)
- [MCP draft/current changelog](https://modelcontextprotocol.io/specification/draft/changelog)
- [MCP security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [MCP TypeScript SDK v2 protocol versions](https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions)
- [NIST SP 800-160 Vol. 1 Rev. 1: Engineering Trustworthy Secure Systems](https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1: Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [OWASP ASVS 5.0](https://asvs.owasp.org/)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [MITRE ATT&CK v20 release](https://attack.mitre.org/resources/updates/updates-october-2026/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/)
- [SLSA specification](https://slsa.dev/spec/)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [Sigstore documentation](https://docs.sigstore.dev/)
- [NetworkX documentation](https://networkx.org/documentation/stable/)

## Final perspective

A strong architecture review does not ask whether a system contains familiar
security boxes. It asks which exact system and change are being decided, which
losses and adversaries matter, which paths can reach protected resources, which
components independently enforce policy, which claims have current exact proof,
what happens under abuse and failure, who owns every gap, and what change would
invalidate the conclusion.

The final boundary remains constant: models and participants propose; trusted
applications validate, authorize, persist, execute, and verify. A review can
make a later decision better informed. It cannot make that decision by itself.
