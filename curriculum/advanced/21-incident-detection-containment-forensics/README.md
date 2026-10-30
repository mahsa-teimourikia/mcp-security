# MCP Incident Detection, Containment, and Forensics

An MCP incident is not resolved because an agent says it is safe or a registry row says `disabled`. A defensible response admits trustworthy telemetry, separates observed facts from hypotheses, correlates independent effect evidence, scopes only within explicit investigator authority, preserves a verifiable redacted record, executes the minimum authorized containment exactly once, and proves the controls took effect.

## Course thesis

By the end of this course, you will investigate a realistic cross-tenant MCP incident from signal to a verified containment handoff. You will build and challenge an offline reference implementation that:

- validates signed, hash-chained security events before persistence;
- detects artifact drift, unexpected egress, cross-tenant effects, and policy/effect disagreement;
- keeps observations, findings, hypotheses, and incident declarations distinct;
- scopes affected identities, workloads, credentials, sessions, artifacts, and destinations with an authorization-aware graph;
- preserves a redacted, integrity-protected evidence package with retention and custody history;
- binds approval to one exact containment plan and rejects stale, modified, expired, or cross-tenant requests;
- reconciles an unknown control-plane outcome without repeating the business effect; and
- proves containment from both control state and the absence of forbidden post-cut effects.

Course 22 begins at the recovery handoff. Eradication, rollback, restoration, resilience testing, and return-to-service authorization belong there; this course does not treat containment as recovery.

## Learning objectives

After completing the chapter, lab, and notebook, you should be able to:

1. Map MCP incident work to NIST SP 800-61r3's Detect, Respond, and Recover outcomes without importing an obsolete linear lifecycle.
2. Design forensic readiness before an incident, including source identity, clocks, immutable artifact identity, redaction, retention, access control, and an independent outcome oracle.
3. Explain why a valid schema, signature, trace, or model judgment is insufficient on its own.
4. Write rule-versioned detections whose findings cite admitted evidence and whose alerts have explicit thresholds.
5. Scope a multi-server incident without using trace context, graph reachability, or model-generated tenant fields as authorization.
6. Choose containment actions that balance mission availability, evidence preservation, blast radius, and propagation delay.
7. Preserve and transfer evidence while detecting tampering and minimizing sensitive data exposure.
8. Execute a signed, exact, idempotent containment plan and reconcile a transport timeout safely.
9. Measure detection, scope, evidence, containment, disruption, and uncertainty with declared denominators.
10. Produce a clear handoff to recovery with unresolved questions and control proof attached.

## Standards and version snapshot

This course snapshot is current to **2026-10-30**.

| Area | Course baseline | Why it matters |
| --- | --- | --- |
| Incident response | NIST SP 800-61r3, April 2025 | Integrates incident response into CSF 2.0 and organizes incident activity around Detect, Respond, Recover, and continuous Improvement. |
| Digital forensics | NIST SP 800-86 | Connects forensic techniques to incident response and stresses management and legal coordination. |
| Cloud readiness | NIST SP 800-201, July 2024 | Provides a cloud forensic reference architecture and readiness perspective. |
| MCP | protocol revision `2026-07-28` | Modern MCP is stateless per request; protocol logging is deprecated, so new implementations should use `stderr` or OpenTelemetry. |
| Telemetry | OpenTelemetry Logs Data Model, stable | Standardizes timestamps, observed timestamps, severity, resource, attributes, and trace/span correlation. |
| Detection content | Sigma correlation rules specification 2.1.0 | Makes event selection and correlation portable, while requiring backends to disclose unsupported semantics. |
| Security event normalization | OCSF | Supplies a vendor-neutral, extensible event schema for a multi-tool SOC. |
| Threat intelligence | STIX 2.1 | Distinguishes observed facts from intelligence assertions and supports exchange through TAXII. |
| Agent runtime control | OWASP Agentic Security Initiative Agent Control Standard, September 2026 | Emphasizes inspectable, traceable, instrumentable agents and runtime control hooks. |

Versions are evidence, not decoration. Revisit this course when the MCP revision, SDK behavior, telemetry contract, detection backend, or response policy changes materially.

## 1. The incident-response boundary

NIST SP 800-61r3 does not prescribe a one-way sequence in which preparation ends before detection. Preparation is supplied continuously by the CSF 2.0 Govern, Identify, and Protect functions; incident work occurs through Detect, Respond, and Recover; lessons feed Improvement.

For this course, the operational boundary is:

```text
trusted signal -> admitted evidence -> finding -> alert -> declared incident
       -> authorized scope -> preserved package -> approved containment
       -> reconciled execution -> containment proof -> recovery handoff
```

The arrows are not automatic trust upgrades. Each transition has a different proof obligation.

| Object | Meaning | What it must not claim |
| --- | --- | --- |
| Event | An admitted statement from a known source | That an incident occurred |
| Finding | A versioned rule matched cited events | Intent, root cause, or total impact |
| Hypothesis | A testable analyst or model explanation | Fact or authorization |
| Alert | Findings crossed a declared threshold | That containment is approved |
| Incident | An authorized responder declared a managed case | That the case is contained or recovered |
| Containment proof | Required controls are active and forbidden post-cut effects are absent | Eradication or safe return to service |

### Case states

The lab uses `OPEN -> DECLARED -> CONTAINMENT_PENDING -> CONTAINED`. State changes are optimistic-versioned so two responders cannot silently overwrite each other. A model may attach a hypothesis, but `accepted_as_fact` is always false. Only an authorized responder can declare the incident, and only verified execution evidence can mark it contained.

## 2. Threat model and scenario

The exercise models a support MCP server deployment named `support-v2`. Its artifact differs from the reviewed digest. It uses an Acme workload and credential to access a Beta resource, sends traffic to an unapproved collection endpoint, and completes a protected-resource effect despite a deny decision.

The environment also includes:

- a reviewed `support-v1` path that must continue to work;
- a denied export that demonstrates a policy decision without a completed protected-resource effect;
- registry, MCP call, network, policy, and protected-resource emitters;
- Acme and Beta evidence that requires explicit cross-tenant investigative authority; and
- a control plane whose network response can time out after the state change commits.

The adversary can modify ordinary event content, replay an event ID, create a conflicting copy, exploit a stale control view, and try to widen a containment plan. The adversary cannot forge the configured HMAC keys in this teaching lab. In production, use managed asymmetric workload identity, protected keys, authenticated transport, append-only storage, and independently administered outcome sources.

### Assets and trust boundaries

Protect at least these assets:

- tenant data and protected-resource effects;
- MCP server artifact and registry binding;
- workload, user, service, and responder identity;
- delegated credentials and active sessions;
- policy and approval state;
- telemetry source identity and clocks;
- forensic packages, encryption keys, retention policy, and custody records; and
- response controls and their propagation state.

Crossing a gateway, A2A peer, MCP server, SIEM, SOAR, case platform, or model boundary never carries implicit authority. Re-establish authenticated identity, tenant, purpose, action, resource, and current policy at every effect boundary.

## 3. Forensic readiness before detection

An investigation cannot reconstruct facts the system never recorded. Readiness is an architecture property, not an emergency export command.

### Minimum security event contract

The lab event includes:

- `event_id`, `schema_version`, `emitter_id`, and per-emitter `sequence`;
- `occurred_at` and `observed_at` as timezone-aware timestamps;
- authenticated tenant and protected-resource tenant;
- principal, server, immutable artifact digest, and workload identity;
- trace, logical operation, session, and credential identifiers;
- event kind, action, resource, destination, policy decision, and observed outcome;
- a restricted source locator rather than raw payload content;
- previous event hash, current event hash, and signature.

OpenTelemetry's `Timestamp` and `ObservedTimestamp` distinction helps expose ingestion delay. Trace and span identifiers support correlation, but they are neither identity nor permission. OCSF can normalize events across vendors; preserve original fields and source provenance so normalization does not erase material details.

### Admission order

The store rejects evidence before persistence in this order:

1. event-ID conflict or exact duplicate handling;
2. schema and identifier validation;
3. known emitter and emitter-to-tenant authorization;
4. timestamp and clock-skew checks;
5. content digest and signature verification; and
6. contiguous sequence and previous-hash verification.

Exact duplicates are idempotent. A repeated ID with different content is a conflict. A gap in an otherwise authentic chain is not silently repaired: it means evidence may be missing and must be investigated.

The teaching implementation uses one process and HMAC keys for deterministic offline execution. It demonstrates invariants, not production key custody or durable storage.

### Data minimization

Do not copy raw access tokens, prompt bodies, tool outputs, customer records, or secrets into a general-purpose log. Record stable identifiers and classifications, store sensitive source material in a restricted evidence vault, and preserve a governed locator. Redaction must happen before export; encryption does not remove the need for access control and minimization.

### Independent outcome oracles

The component accused of misbehavior cannot be the only source of truth about its effect. Pair an MCP call event with, for example:

- protected-resource audit or transaction ledger;
- egress flow or proxy record;
- registry/control-plane revision;
- credential issuer or revocation state; or
- immutable object-store evidence.

If the server says a call was blocked but the resource ledger records the read, the effect occurred.

## 4. Detection engineering

The lab's `IncidentDetector` emits four evidence-backed rule types:

1. **Artifact drift** — a server runs bytes different from the reviewed digest.
2. **Unexpected egress** — a network event names a destination outside the allowlist.
3. **Cross-tenant effect** — authenticated tenant and protected-resource tenant differ.
4. **Policy/effect mismatch** — policy says deny while an independent resource event proves completion.

It also emits a correlated intrusion finding only when independent network and protected-resource evidence share the operation context. Every finding includes a rule ID, rule version, severity, and exact evidence IDs.

### Portable content and backend truth

Sigma and OCSF make detection content more portable; they do not make every backend equivalent. Sigma correlation capabilities vary. A converter must report unsupported correlation semantics instead of silently weakening a rule. Store the source rule, generated query, backend/version, test fixtures, and deployment status together.

Useful engineering tests include:

- positive attack fixtures;
- legitimate positive controls;
- missing or delayed source data;
- duplicate, reordered, and conflicting events;
- field-normalization drift;
- time-window boundary conditions;
- rule-version migrations; and
- independent outcome disagreement.

### Alert threshold

One suspicious egress record should not necessarily page an incident commander. The lab requires a combination of high-confidence findings and independent effect evidence before creating a critical alert. Thresholds must be explicit, testable, and tuned against labelled valid activity.

## 5. Triage without converting guesses into facts

Start with three separate columns:

| Known observation | Inference to test | Missing evidence |
| --- | --- | --- |
| `support-v2` digest differs from the reviewed digest | Deployment was replaced maliciously | Build provenance and deployment change record |
| Egress to `collect.invalid` was observed | Data was exfiltrated | Egress bytes, destination ownership, protected-resource event |
| Beta resource recorded a read by an Acme workload | Tenant boundary failed | Credential issuance and downstream authorization decision |

Model output can help suggest queries, summarize admitted facts, or propose hypotheses. It must not:

- declare the incident;
- choose tenant authority;
- approve containment;
- change case facts;
- decide that a completed effect did not occur; or
- close the case.

All model-generated text remains untrusted case content and must cite evidence available to the analyst.

## 6. Authorization-aware impact scoping

The scope engine builds a NetworkX graph from admitted events. Nodes represent events and security identifiers; edges join exact trace, operation, artifact, workload, session, credential, server, and destination values.

Graph reachability is a query technique, not authority or proof of compromise. The safe sequence is:

1. authorize the investigator for every tenant requested;
2. query only admitted evidence within the approved time range and tenant set;
3. seed the graph from the case evidence;
4. traverse exact joins;
5. classify included identities and assets; and
6. report unauthorized or unavailable evidence as an explicit exclusion.

Never retrieve another tenant's evidence and filter it after the fact. That leaks existence, metadata, and potentially content. The lab checks authority before retrieval and before graph expansion.

### Scope is not ground truth

Report scope with uncertainty:

- confirmed affected objects, backed by independent effect evidence;
- potentially affected objects, connected by admitted evidence;
- checked but unaffected objects;
- excluded tenants, sources, and time ranges;
- missing or delayed emitters; and
- assumptions that could change the result.

The exercise has labelled ground truth so you can compute precision and recall. Production investigations rarely do; use sampling, later-confirmed cases, simulations, and purple-team exercises to calibrate scope quality.

## 7. Evidence preservation and forensic handling

Preserve before destructive containment when doing so does not create unacceptable ongoing harm. CISA's playbook explicitly treats containment as a strategy decision balancing mission availability, evidence preservation, and full versus partial or unknown containment.

The lab's forensic vault:

- requires a `forensic_collector` role;
- checks tenant authority before collecting evidence;
- redacts principal, session, and credential identifiers;
- stores event hashes and restricted source locators;
- creates a canonical manifest digest and HMAC;
- binds the package to the case, scope report, retention date, and legal-hold state; and
- appends signed custody transfers without rewriting the original manifest.

### Chain of custody

A useful custody record answers:

- What package or item moved?
- From whom and to whom?
- When and for what purpose?
- Which integrity value was verified?
- Which tool and version created the package?
- Where is the authoritative original?

Chain of custody does not make evidence true. It makes handling changes reviewable. Source authenticity, completeness, clock quality, tool validation, and interpretation remain separate questions.

### Legal and privacy coordination

Retention, legal hold, notification, employee monitoring, data residency, and law-enforcement contact requirements vary by jurisdiction and organization. NIST SP 800-86 advises coordination with management and legal counsel. The lab models policy mechanics; it is not legal advice.

## 8. Designing minimum necessary containment

Containment reduces ongoing harm while preserving options. Possible controls include:

- disable exact registry bindings and server artifacts;
- quarantine affected workloads;
- revoke specific credentials and delegated grants;
- terminate affected sessions and in-flight tasks;
- block malicious or unapproved egress destinations;
- isolate a namespace, node, or environment;
- suspend callbacks, queues, or downstream API access; and
- raise review or approval requirements for related operations.

Choose the smallest control set that blocks every currently executable path. A graph cut can suggest choke points, but business criticality, valid dependencies, propagation, and actual enforcement require human review.

### Evidence before mutation

The lab will not execute containment unless the forensic package verifies. This does not mean responders must allow active harm indefinitely. Emergency policy can permit immediate isolation, but it should explicitly record why normal preservation order was overridden and capture the best available volatile evidence.

### Exact signed approval

An approval receipt binds:

- containment-plan digest;
- case ID and tenant;
- policy version;
- approver identity and role;
- issuance and expiry; and
- signature over the canonical receipt.

A Boolean such as `approved=true` is caller-controlled data, not authority. Changing one workload, credential, destination, or artifact invalidates the receipt and requires fresh approval.

### Atomic execution and replay safety

The control plane applies one immutable revision atomically in the lab. The executor derives a stable operation ID from the exact case and plan, persists a request digest in a durable journal, and rejects reuse with different content.

If transport fails after commit, the outcome is **unknown**, not failed. The safe procedure is:

1. retain the same logical operation ID and request digest;
2. query the target control plane or independent state;
3. reconcile whether the revision committed; and
4. retry only the exact request if reconciliation proves no effect occurred.

Creating a new operation ID can repeat revocation, notification, isolation, or other non-idempotent work.

## 9. Proving containment

An execution receipt is necessary but not sufficient. `prove_containment` checks:

- every scoped server binding and artifact is disabled;
- every scoped workload is quarantined;
- every scoped credential is revoked;
- every scoped session is terminated;
- every scoped unapproved destination is blocked;
- the forensic package still verifies; and
- no completed event after the containment cut matches any contained server, workload, credential, session, or destination.

Only then can the case enter `CONTAINED`. A late protected-resource effect invalidates the proof even if the registry and network controls report success.

Containment can still be partial. Record unresolved in-flight work, unreachable enforcement points, unconfirmed credential caches, delayed telemetry, and endpoints outside administrative control.

## 10. Metrics with explicit denominators

Avoid vanity counts. Declare populations, labels, time boundaries, and exclusions.

| Metric | Definition in the lab | Failure it can expose |
| --- | --- | --- |
| Detection precision | true alerts / all generated alerts | Noisy alerting |
| Detection recall | detected labelled incidents / all labelled incidents | Missed attacks |
| Scope precision | correctly scoped objects / all scoped objects | Excessive blast radius |
| Scope recall | correctly scoped objects / all affected labelled objects | Hidden impact |
| Evidence completeness | required present fields / required fields | Uninvestigable incidents |
| Time to detect | alert time - earliest admitted malicious event time | Detection latency |
| Time to contain | verified containment time - declaration time | Response latency |
| Valid-service disruption | blocked labelled valid effects / labelled valid effects | Containment collateral damage |

Also track source coverage, delayed-event rate, chain gaps, rejected events by reason, unknown outcomes, reconciliation latency, stale-control effects, manual overrides, and post-cut violations.

Metrics are not authorizers. Never lower a security boundary solely to improve a dashboard.

## 11. Tools and libraries in a production stack

The lab deliberately uses real `networkx` and OpenTelemetry SDK objects while keeping all execution offline. Common production choices include:

| Need | Common options | Review focus |
| --- | --- | --- |
| Instrumentation | OpenTelemetry SDK/Collector | Resource identity, security-event sampling, redaction, exporter trust |
| Event normalization | OCSF, ECS, vendor schemas | Lossless source mapping, versioning, tenant partition |
| Detection content | Sigma, SIEM-native rules, Falco | Backend semantics, test fixtures, rule provenance |
| Collection and endpoint evidence | osquery, Falco, eBPF sensors, EDR | Sensor identity, coverage, clock and loss characteristics |
| SIEM and analytics | Splunk, Elastic, Microsoft Sentinel, Google SecOps | RBAC, immutable retention, query reproducibility |
| Workflow and cases | TheHive, Jira/ServiceNow security workflows, SOAR platforms | State transitions, approvals, evidence links, audit history |
| Policy | OPA/Rego, Cedar, cloud IAM | Trusted input provenance, decision version, obligations |
| Workload identity | SPIFFE/SPIRE, cloud workload identity, mTLS | Attestation, rotation, audience and tenant binding |
| Artifact provenance | Sigstore, in-toto, SLSA attestations, SBOM tools | Exact digest, signer/issuer, builder and policy |
| Evidence storage | Object Lock/WORM-capable object stores, encrypted vaults | Immutability, legal hold, key separation, access logging |
| Threat intelligence | STIX 2.1, TAXII, MISP | Confidence, markings, source and time semantics |

STIX modeling deserves care: `Observed Data` represents observed facts, while `Sighting` represents an intelligence assertion that a cyber-observable or indicator was seen. The STIX 2.1 Incident object is not a complete incident-case schema; keep operational case state, approvals, evidence custody, and response execution in a purpose-built case system.

## 12. Practical lab

From the repository root:

```bash
uv sync --extra contributor --frozen
uv run python curriculum/advanced/21-incident-detection-containment-forensics/lab.py
uv run pytest -q tests/test_course_21_incident_forensics.py
```

Expected lab output:

```text
PASS: evidence-backed incident was scoped, preserved, contained, and reconciled
```

The code is organized as a vertical slice:

1. `EventEmitter` and `EvidenceStore` — source authenticity, replay, and chain admission.
2. `IncidentDetector` — evidence-backed findings and alert threshold.
3. `IncidentRepository` and `IncidentManager` — case integrity and state transitions.
4. `ScopeEngine` — authorization-first graph analysis.
5. `ForensicVault` — redaction, manifest, retention, and custody.
6. `make_plan` and `approve_plan` — exact containment proposal and receipt.
7. `ControlPlane`, `ContainmentJournal`, and `ContainmentExecutor` — atomic effects, restart safety, and reconciliation.
8. `prove_containment` — distributed state plus independent post-cut evidence.
9. Metric functions and an in-memory OpenTelemetry span — measurable proof without a network exporter.

The tests are part of the course material. Read each adversarial case and explain which invariant it proves before changing the implementation.

## 13. Notebook investigation

Open `incident_forensics.ipynb` and run all cells from a clean kernel. The notebook walks through:

- trusted and rejected event admission;
- rule findings and alert creation;
- model hypothesis versus responder declaration;
- Acme-only scope denial and authorized Acme/Beta scope;
- forensic collection, redaction, tamper detection, and custody transfer;
- plan creation and signed approval;
- unknown outcome, durable restart, and reconciliation;
- late-effect containment failure; and
- exact metrics and OpenTelemetry evidence.

The notebook imports the canonical `lab.py`; it does not maintain a second implementation.

## 14. Exercises

### Exercise A — Missing evidence

Remove the protected-resource audit event. Confirm that correlation and declaration fail. Add an explicit `INCONCLUSIVE` workflow rather than weakening the effect requirement.

### Exercise B — Reordered delivery

Deliver per-emitter sequence 2 before sequence 1. Design a bounded quarantine buffer with an expiry and operational alert. Do not silently accept a broken chain.

### Exercise C — Partial cross-tenant authority

Give the analyst Acme authority only. Confirm the engine produces an Acme-only partial scope, does not retrieve Beta records, and reports that authorized coverage is incomplete without revealing Beta details. Design an escalation request for the missing authority.

### Exercise D — Emergency isolation

Add an emergency policy that permits workload quarantine before package creation. Bind it to a responder role, reason code, short expiry, exact workload, and automatic after-action review.

### Exercise E — Delayed post-cut effect

Ingest a protected-resource completion that occurred before the cut but arrived after it, then one that occurred after the cut. Define which timestamp is authoritative and how clock uncertainty changes the proof.

### Exercise F — Production adapter

Map one local event type to the OpenTelemetry Logs Data Model or OCSF. Document every loss, transformation, and backend query. Add a Sigma-style detection and positive/negative fixtures.

### Exercise G — Recovery handoff

Create a handoff object containing verified containment revision, package digest, affected identities/assets, unresolved uncertainty, owner, and allowed next actions. Do not implement rollback here; carry it into Course 22.

## 15. Runbook and review checklist

Before an incident:

- [ ] Security-critical events have an unsampled durable path.
- [ ] Source identity, tenant binding, schema version, and clocks are monitored.
- [ ] Artifact digests and workload identities are available in every relevant event.
- [ ] Independent protected-resource and egress evidence is retained.
- [ ] Evidence access, redaction, encryption, retention, legal hold, and custody are tested.
- [ ] Detection rules have attack fixtures and legitimate positive controls.
- [ ] Control-plane operations support stable idempotency and state reconciliation.
- [ ] Emergency and normal containment authorities are documented.
- [ ] Cross-tenant investigations require explicit, auditable authority.

During response:

- [ ] Record observations separately from hypotheses.
- [ ] Confirm source admission and missing-data status.
- [ ] Use independent effect evidence before declaration.
- [ ] Preserve evidence before destructive action when risk permits.
- [ ] Bind approval to the canonical containment plan.
- [ ] Treat timeouts as unknown outcomes.
- [ ] Verify propagation and post-cut effects before claiming containment.
- [ ] Report excluded sources and uncertainty.

At the recovery handoff:

- [ ] Case and evidence-package digests are recorded.
- [ ] Control revision and proof time are recorded.
- [ ] Affected and potentially affected scope is separated.
- [ ] Credentials, sessions, artifacts, workloads, and destinations are enumerated.
- [ ] Unresolved sources, in-flight work, and legal constraints are explicit.
- [ ] Recovery actions require new, purpose-bound authorization.

## 16. Claim-to-proof map

| Claim | Artifact | Executable proof |
| --- | --- | --- |
| Evidence is admitted fail closed | `EvidenceStore` | schema, trust, time, integrity, chain, replay tests |
| Findings cite facts | `IncidentDetector` | benign, attack, and independent-correlation tests |
| A model cannot declare or close | `IncidentManager` | role, citation, independent-effect, and state tests |
| Scope does not bypass tenant authority | `ScopeEngine` | unauthorized and authorized cross-tenant tests |
| Evidence export is minimized and tamper evident | `ForensicVault` | redaction, tamper, retention, and custody tests |
| Approval covers one exact action set | `ApprovalReceipt` | expiry, mutation, tenant, policy, and replay tests |
| Unknown outcomes do not duplicate effects | journal + executor | timeout, restart, reconcile, and idempotency tests |
| Containment is proven, not asserted | `prove_containment` | control-state and late-effect tests |
| Metrics have valid denominators | metric functions | labelled exact-value tests |

## References

- [NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [NIST SP 800-201: NIST Cloud Computing Forensic Reference Architecture](https://csrc.nist.gov/pubs/sp/800/201/final)
- [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry Logs specification](https://opentelemetry.io/docs/specs/otel/logs/)
- [Open Cybersecurity Schema Framework](https://ocsf.io/)
- [Sigma correlation rules specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
- [STIX 2.1 OASIS Standard](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.pdf)
- [MCP protocol revision 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [MCP Ruby SDK: protocol logging deprecation](https://ruby.sdk.modelcontextprotocol.io/server/logging/)
- [MCP Go SDK: logging guidance](https://go.sdk.modelcontextprotocol.io/server/)
- [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/)
