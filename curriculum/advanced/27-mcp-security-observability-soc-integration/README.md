# MCP Security Observability and SOC Integration

Security observability for MCP is the ability to reconstruct and evaluate what
authority was requested, decided, exercised, and independently observed across
the host, server, policy, network, and resource boundaries. SOC integration is
the controlled conversion of that evidence into detections, cases, response
proposals, and verified outcomes.

The governing invariant for this course is:

> A model, log, detector, or alert may propose an interpretation. Trusted
> application code authenticates evidence, resolves identity and tenant scope,
> applies policy, authorizes effects, persists state, executes response, and
> verifies the outcome.

This course is deliberately different from Course 16 and Course 21. Course 16
asks whether runtime controls still satisfy reviewed assurance invariants.
Course 21 develops the broader incident, containment, and forensic lifecycle.
Here the focus is the engineering seam between MCP telemetry and a production
SOC: event contracts, privacy, normalization, correlation, detection content,
case routing, automation safety, and measurable operational quality.

## Learning objectives

By the end of the course, you should be able to:

1. define a privacy-minimized MCP security event contract that preserves the
   exact identity, tenant, artifact, capability, policy, trace, and effect
   evidence needed by defenders;
2. authenticate event producers and reject tampered, stale, ambiguous,
   over-scoped, or sensitive telemetry before it enters a detection pipeline;
3. distinguish event time, observed time, and ingest time, then design bounded
   behavior for clock skew, duplicates, late arrival, and out-of-order events;
4. map an internal event contract into OpenTelemetry and a selected security
   schema without pretending that an evolving convention is stable;
5. implement deterministic single-event and multi-event detections with exact
   tenant partitions, rule versions, evidence links, and explicit uncertainty;
6. route candidate alerts to tenant-owned SOC queues and create cases
   idempotently with bounded, severity-aware suppression;
7. keep detection separate from response authority by requiring an exact,
   expiring, single-use approval for a versioned containment proposal;
8. verify response outcomes from an independent control-plane read rather than
   equating an accepted command with successful containment; and
9. evaluate detections using labelled populations, disclosed denominators,
   event-time latency, precision, recall, false positives, routing, and verified
   containment—not alert counts or fabricated timing.

## Prerequisites and lab setup

You should be comfortable with MCP trust boundaries, authorization, structured
events, Python dataclasses, and basic incident-response vocabulary. From the
repository root:

```bash
uv sync --extra contributor --frozen
uv run python curriculum/advanced/27-mcp-security-observability-soc-integration/lab.py
uv run pytest -q tests/test_course_27_soc_integration.py
```

The lab is offline and credential-free. It uses the common `cryptography`
Ed25519 implementation and the OpenTelemetry Python SDK already pinned by this
repository. The in-memory exporter demonstrates real SDK behavior without
sending data to an external collector or SIEM.

## State of practice: what is stable and what is moving

As of 31 October 2026, treat the following as separate layers:

| Layer | Useful standard or tool | Course position |
| --- | --- | --- |
| telemetry transport and signal model | OpenTelemetry SDK, OTLP, Collector, stable Logs Data Model | use its event/observed timestamps, trace context, resource, scope, severity, body, and attributes concepts |
| GenAI/MCP semantic naming | OpenTelemetry GenAI semantic conventions | verify the exact release and stability before adoption; keep security-critical custom fields versioned behind your internal contract |
| vendor-neutral security normalization | OCSF | choose and pin a schema release, validate mappings, preserve unmapped MCP evidence, and regression-test upgrades |
| Elastic ecosystem normalization | ECS | use when it matches the deployed Elastic stack; maintain mapping/version ownership rather than assuming universal portability |
| portable detection content | Sigma rule and correlation specifications, `sigma-cli`, pySigma | useful for reviewable source rules; backend conversion still needs testing against the target schema and engine |
| adversary knowledge | MITRE ATT&CK and MITRE ATLAS | map behavior and coverage; do not treat a technique tag as a working detection or evidence of effectiveness |
| threat-intelligence exchange | STIX 2.1 and TAXII 2.1 | exchange governed CTI; do not use CTI transport as an authorization channel |
| incident-risk lifecycle | NIST SP 800-61 Rev. 3 and CSF 2.0 | integrate detection, response, recovery, and improvement with organization-wide risk management |

OpenTelemetry's Logs Data Model is stable, and distinguishes source event time
(`Timestamp`) from collection observation time (`ObservedTimestamp`). Its trace
and span fields enable request correlation. This does **not** mean every MCP
security field has a stable standardized semantic name. The main semantic
conventions site moved GenAI conventions into a dedicated repository; adopters
must check the stability level and chosen version rather than copying a current
web example into an unversioned production contract.

OCSF provides an extensible, vendor-neutral core security schema. ECS provides
a widely used schema in the Elastic ecosystem. Neither removes the need for a
canonical internal contract: source facts can be lost or change meaning during
mapping, backend versions differ, and MCP-specific artifact, capability,
approval, policy, and effect relationships may not have an exact native field.

Sigma 2.1.0 describes rule structure, while the Sigma ecosystem provides
`sigma-cli` and pySigma for conversion. Portability is source-level, not proof
that every generated query behaves identically. Test field mappings, null and
array semantics, case handling, window behavior, cardinality, and backend
limits using labelled fixtures in each target SIEM.

MITRE ATT&CK deprecated its legacy data-source catalogue in ATT&CK v18 (October
2025). Do not build a new coverage model around a deprecated list. Use current
ATT&CK detection-strategy material and release notes, while retaining local
MCP telemetry requirements that are specific to your system.

## The security boundary

An observability pipeline is a second control plane. It receives privileged
facts, can expose customer data, influences human decisions, may trigger
automation, and is itself an attacker target.

```text
model / tool content                      authenticated runtime state
          |                                          |
          | proposes interpretation                  | supplies identity,
          v                                          | tenant, artifact,
  [untrusted text]                                   | capability and policy
          |                                          v
          +-----> trusted producer adapter ----> signed event envelope
                                                    |
                                                    v
                  schema + signature + time + privacy + producer-scope gate
                                                    |
                                                    v
                         trusted inventory enrichment and tenant partition
                                                    |
                                                    v
                         deterministic detection -> candidate alert
                                                    |
                                                    v
                           trusted route -> idempotent SOC case
                                                    |
                             analyst proposes       | exact approval
                                                    v
                            versioned response -> executor -> independent read
```

The detector is intentionally not in the authorization path. An alert can be
wrong, duplicated, delayed, or adversarially induced. A response workflow must
re-establish tenant, target, current state, permitted action, approval purpose,
expiry, and idempotency at the execution boundary.

## 1. Design the event contract from investigation questions

Start with questions the SOC must answer:

- Which authenticated principal and workload requested the action?
- Which tenant owned the authenticated session and the affected resource?
- Which MCP server, immutable artifact digest, and capability contract ran?
- What exact tool or resource action, destination, and resource were involved?
- Which policy version decided what, and at which enforcing boundary?
- Did the downstream network or resource effect actually occur?
- Which trace, span, and stable operation link the distributed evidence?
- Which producer observed each fact, and is that producer authorized to attest
  that fact for this tenant and workload?
- When did the action happen, when was it observed, and when was it ingested?
- What evidence can a responder cite without revealing raw customer content or
  credentials?

The lab's `EventTemplate` includes:

- stable `event_id` and a positive producer sequence (gaps and regressions are
  pipeline-health signals; the live store still accepts bounded out-of-order
  delivery);
- `occurred_at` and `observed_at`, with `received_at` supplied by the ingress;
- authenticated `tenant_id`, `principal_ref`, `workload_id`, and `server_id`;
- exact `artifact_digest` and reviewed `capability_version`;
- W3C-sized `trace_id`, `span_id`, and stable `operation_id`;
- event kind, action, resource, resource tenant, destination, decision, and
  outcome; and
- a small bounded set of non-sensitive custom attributes.

The signed envelope adds the schema version, emitter identity, and signature.
The signature authenticates exact bytes; it does not prove that the producer is
authorized, current, accurate, or entitled to speak for a tenant. The
`ProducerBinding` separately constrains tenants, workloads, and event kinds.

### Identity is not a log field

Never authorize from a tenant, role, user, or server name supplied by a model,
tool argument, trace baggage item, log body, or self-described metadata. The
producer adapter derives those values from authenticated application and
transport state. The normalizer checks them against a trusted producer binding
and inventory. A disagreement is a fail-closed security signal, not a field to
merge heuristically.

### Minimize before export

OWASP's logging guidance advises removing, masking, sanitizing, hashing, or
encrypting values such as session identifiers, access tokens, passwords,
connection strings, encryption keys, sensitive PII, and other secrets. This
course takes a strict approach:

- store a stable pseudonymous principal reference, not raw identity claims;
- store resource identifiers only when investigation requires them and access
  controls permit them;
- never put access tokens, cookies, passwords, secrets, or raw prompts in the
  event;
- use decision codes and content digests rather than full model/tool content;
- reject CR/LF in attribute values to prevent log-injection ambiguity;
- bound the number and length of custom attributes; and
- enforce retention, regional, tenant, and analyst access policies downstream.

Redaction after a secret has crossed multiple queues and stores is too late.
Minimize at the trusted producer boundary and test that forbidden fields cannot
be emitted.

## 2. Authenticate and normalize before detection

The `EventNormalizer` performs these ordered checks:

1. require the supported schema version;
2. resolve the registered emitter;
3. verify the Ed25519 signature over canonicalized exact content;
4. validate bounded identifiers, trace context, digest syntax, and sequence;
5. check UTC-aware time relationships, clock skew, and ingestion delay;
6. enforce the emitter's tenant, workload, and event-kind scope;
7. reject excessive, duplicate, sensitive, long, or delimiter-bearing custom
   attributes;
8. resolve the server from trusted inventory and require active tenant scope;
9. compare observed artifact, capability, action, and destination with reviewed
   inventory; and
10. produce a typed immutable `NormalizedEvent` with an evidence digest.

Order matters. Do not enrich unauthenticated data with sensitive inventory, and
do not let a producer-supplied team or SOC queue override trusted ownership.

### OpenTelemetry mapping

`NormalizedEvent.otel_log_projection()` demonstrates an internal-to-OTel
mapping:

- occurrence time becomes `Timestamp`;
- producer-observed time becomes `ObservedTimestamp`;
- trace and span IDs retain their correlation meaning;
- the event kind becomes a stable `EventName`;
- server/workload facts become resource attributes; and
- MCP security facts become version-owned event attributes.

This projection is a teaching object, not a replacement for the OTel Logs SDK
or OTLP exporter. In production, instrument with the SDK, send OTLP to a
hardened Collector, authenticate and encrypt transport, limit receivers and
exporters, isolate credentials, bound queues, monitor dropped telemetry, and
test Collector configuration. Do not expose a Collector administration or
debug endpoint merely because the data pipeline is internal.

### OCSF or ECS mapping

`NormalizedEvent.ocsf_projection()` intentionally declares its schema version
as `deployment-selected`. A real adapter must:

- pin one release of the target schema;
- select the correct class/category and activity/status identifiers;
- document every transformation and unmapped field;
- distinguish required, optional, null, absent, and repeated values;
- validate generated events with the selected schema tooling;
- run golden mapping fixtures on every schema or adapter upgrade; and
- preserve the original signed event digest and access-controlled source
  locator for defensible investigation.

The same rules apply to ECS. A mapping that passes JSON syntax but silently
drops tenant or artifact identity is not correct.

## 3. Engineer event-time correlation explicitly

Distributed telemetry is neither ordered nor exactly once. A defensible design
names its semantics:

- **Event time:** when the source says the event occurred.
- **Observed time:** when the collection component first observed it.
- **Ingest time:** when the trusted normalization boundary received it.
- **Clock-skew bound:** how far source and observer clocks may disagree.
- **Ingest-delay bound:** when an event is too stale for the live path.
- **Late-event allowance/watermark:** how long correlation waits for an older
  event before finalizing a window.
- **Partition key:** tenant first, then only the exact entities needed by the
  rule—never a global principal or model-generated session name.
- **Deduplication key:** stable event ID plus authenticated content digest.
- **State bound:** maximum events or time retained per tenant/entity.

The lab's `EventStore` is bounded per tenant, returns an idempotent duplicate
for the same event ID and digest, and rejects a conflicting replay while that
identity remains in the retained window. Correlation uses event time with a
five-minute lookback and a two-minute late allowance. A production design that
needs longer replay protection should keep a separately bounded durable replay
index. Stream processors should use their native watermark and state-store
features while preserving the same security invariants.

## 4. Detection content and evidence provenance

The lab implements seven rule families:

| Rule | Evidence | Why it matters |
| --- | --- | --- |
| MCP-SOC-001 | observed vs approved artifact digest | catches unreviewed or replaced server bytes |
| MCP-SOC-002 | capability/action/policy version vs reviewed contract | catches interface or authorization-surface drift |
| MCP-SOC-003 | network effect vs destination allowlist | catches unapproved egress |
| MCP-SOC-004 | authenticated tenant vs resource tenant | catches cross-tenant effect attempts |
| MCP-SOC-005 | policy denial followed by successful effect | catches enforcement disagreement or bypass |
| MCP-SOC-006 | three denied operations by exact principal/server/window | demonstrates bounded behavioral correlation |
| MCP-SOC-007 | allowed high-risk call with no resource outcome after grace | catches missing effect evidence and uncertain completion |

Every `Alert` contains a stable rule ID and version, severity, exact tenant and
entity scope, evidence event IDs, a digest of those event digests, reason codes,
playbook, route, and detection time. The alert builder rejects evidence that is
not present in the same tenant's admitted store.

A rule match is a **candidate alert**, not proof of maliciousness. Artifact
drift may be a deployment race. Repeated denials may be a broken client. A
missing outcome may be telemetry loss. Preserve uncertainty in the playbook,
enrich from trusted state, and measure false positives using labelled cases.

### Sigma workflow

A production team can express portable source detections in Sigma and compile
them with `sigma-cli` or pySigma. Treat this as code:

1. assign stable rule IDs, versions, owners, status, references, severity, and
   expected false positives;
2. pin the taxonomy and backend mapping;
3. lint and validate the source rule;
4. compile for each target SIEM;
5. inspect generated queries;
6. run malicious, benign, boundary, null, duplicate, late, and high-cardinality
   fixtures in the actual backend; and
7. record coverage, latency, cost, false positives, and rollback behavior.

Sigma correlation rules can describe multi-event logic, but time windows,
grouping, ordering, and backend capabilities still require target-specific
verification. Never claim a detection is effective merely because the YAML is
valid or has an ATT&CK tag.

## 5. Route alerts and create cases safely

`CaseRouter` takes tenant-to-SOC routing from trusted configuration, not from
the event or model. It creates a deterministic case ID from the alert and route
and returns the committed case on an identical retry. This handles the common
"request timed out after the SIEM may have accepted it" condition.

Suppression is exact and bounded:

- an identical alert ID returns the same case;
- the same fingerprint within 15 minutes can reuse a non-critical case;
- critical alerts bypass fingerprint suppression; and
- a different tenant, server, rule, or operation produces a different
  fingerprint.

Real integrations should also define retry budgets, dead-letter handling,
backpressure, queue ownership, acknowledgements, schema evolution, case-link
repair, and reconciliation between emitted alerts and created cases. Monitor
the integration itself: exporter failures and case-creation gaps are security
signals.

The case state machine requires explicit expected-state transitions:

```text
open -> acknowledged -> response_pending -> contained -> closed
                       \-> closed (a separately governed disposition path)
```

The lab never closes a case automatically from model prose or an alert
disappearance.

## 6. Keep SOAR automation inside an authorization boundary

An analyst or model may propose a response, but the proposal is data. The lab's
`ResponseProposal` binds:

- case and tenant;
- action and exact target;
- reason and accountable requester;
- expected target-state version; and
- proposal time.

`ApprovalService` signs a digest of that exact proposal for the sole purpose
`mcp_soc_containment`. Only incident-commander or security-duty-manager roles
may approve. Receipts expire within 15 minutes and are consumed atomically once.
Any changed target, tenant, action, reason, version, or case invalidates the
approval.

`ContainmentController` rechecks target ownership and optimistic state version,
then applies only actions that the controller owns. A stable operation ID makes
unknown-outcome retries idempotent and rejects conflicting reuse.

Finally, `IndependentVerifier` reads current control-plane state. Only a
matching verified observation permits the case to transition to `contained`.
An HTTP 200, queued job, audit line, or model summary is execution evidence, not
outcome evidence.

## 7. Evaluate the system, not the alert counter

Use labelled episodes with an explicit observation period and population.
Report at least:

- true positives, false negatives, false positives, and true negatives;
- precision and recall;
- false positives per 1,000 valid operations;
- event-time-to-detection for detected malicious episodes;
- routing/case-creation completeness;
- verified-containment rate;
- duplicate, late, dropped, invalid-signature, and schema-rejection rates;
- telemetry and case-pipeline availability; and
- cost/cardinality by tenant, event kind, and rule.

The lab's `detection_metrics()` returns `None` when a denominator does not
exist. It does not turn zero observations into a perfect score. Its median
detection latency uses the first malicious event time, not a `sleep()` call or
test-run duration.

Precision and recall serve different operational decisions. A high-volume SOC
may need false positives per valid operation and analyst-hours per confirmed
case. A safety-critical containment detector may prioritize recall while using
an approval step to constrain automated effects. Always disclose the threshold,
population, label source, exclusions, observation window, and confidence or
sample limits.

## Lab walkthrough

Open `lab.py` and follow this sequence:

1. `demo_components()` creates a reviewed server inventory, a scoped gateway
   producer, normalizer, bounded store, detector, case router, approval service,
   and versioned control state.
2. `event_fixture()` creates a network-effect event for `ticket.export` to an
   unapproved destination and signs it with Ed25519.
3. `EventNormalizer.normalize()` verifies the envelope and enriches it from
   trusted inventory.
4. `EventStore.ingest()` commits the event idempotently.
5. `DetectionEngine.evaluate()` emits MCP-SOC-003 with the admitted event ID and
   evidence digest.
6. `instrumented_route()` creates a real OpenTelemetry span and an idempotent
   SOC case.
7. explicit case transitions show analyst acknowledgement and response intent.
8. an incident commander approves the exact versioned proposal.
9. the controller disables the server and records the stable operation.
10. an independent read verifies the target is disabled before the case becomes
    contained.

Expected output resembles:

```json
{"alert":"MCP-SOC-003","case_state":"contained","evidence":["EV-EGRESS-001"],"execution":"applied","otel_spans":1,"verified":true}
```

Exact case identifiers are deterministic digests and may be treated as opaque.

## Practical exercises

### Exercise 1: add a detection-quality fixture

Add a labelled benign deployment-race episode and a malicious artifact-drift
episode. State the label source, observation window, and valid-operation
denominator. Recompute precision, recall, and false positives per 1,000 valid
operations. Explain whether suppression changes detection quality or only
analyst workload.

### Exercise 2: model late arrival

Emit a successful resource effect before its policy-denial event arrives.
Evaluate once before and once after the late event. Define whether your target
backend retracts, updates, or creates a new alert, and test the watermark edge.

### Exercise 3: implement a schema adapter

Choose one pinned OCSF or ECS release. Document the target event class, map each
canonical field, preserve unmapped MCP values, validate the result with the
official tooling, and add golden round-trip tests. Record every lossy mapping.

### Exercise 4: author a Sigma rule

Express MCP-SOC-003 as a Sigma source rule over your selected normalized
schema. Compile it for two backends. Run the same labelled fixtures in both and
explain differences in generated query semantics.

### Exercise 5: add delivery reconciliation

Model an unknown result after the SIEM may have created a case. Retry with the
same alert ID and verify one case. Then reuse the ID with conflicting content
and require a hard error plus an audit signal.

### Exercise 6: threat-model the pipeline

Cover producer-key theft, poisoned attributes, cross-tenant correlation,
Collector compromise, queue loss, replay, schema rollback, alert flooding,
suppression abuse, SOC credential theft, approval replay, stale target state,
and forged outcome evidence. Identify the trusted owner of every mitigation.

## Common failure modes

| Failure | Consequence | Required correction |
| --- | --- | --- |
| raw prompts/tokens exported for “context” | secret and customer-data exposure | minimize at the source; use digests and controlled source retrieval |
| tenant taken from trace baggage or tool arguments | cross-tenant correlation and response | derive tenant from authenticated application state |
| signature accepted without producer scope | any valid producer can impersonate any fact | bind producer to tenant, workload, and event kinds |
| logs treated as authorization facts | attacker-controlled telemetry gains authority | enrich from trusted inventory and policy state |
| event, observed, and ingest time collapsed | incorrect latency and correlation | preserve all three and define skew/delay/watermarks |
| global correlation key | tenant leakage and false joins | partition by authenticated tenant first |
| unbounded state/window | memory exhaustion and alert storms | bound state, keys, cardinality, windows, and attributes |
| alert without rule/evidence version | irreproducible investigation | store rule version, evidence IDs, and digest |
| all duplicates suppressed | critical activity hidden | exact bounded suppression; critical bypass |
| Sigma conversion assumed equivalent | backend-specific misses or noise | validate compiled queries in every target SIEM |
| SOAR executes alert text directly | detection becomes authority | exact proposal, policy, approval, state version, and owned executor |
| command accepted equals containment | false closure | independent current-state and forbidden-effect verification |
| alert count called coverage | false confidence | labelled positive/negative populations and disclosed denominators |

## Production review checklist

### Event and privacy contract

- [ ] Schema version, compatibility, ownership, and deprecation policy exist.
- [ ] Identity, tenant, artifact, capability, decision, effect, and operation
      fields come from trusted boundaries.
- [ ] Producer authentication and tenant/workload/event-kind scope are enforced.
- [ ] Raw tokens, secrets, passwords, cookies, prompts, and unnecessary PII are
      rejected before export.
- [ ] Attribute length, count, characters, and cardinality are bounded.
- [ ] Retention, residency, encryption, access, deletion, and legal constraints
      are documented and tested.

### Pipeline and schema

- [ ] Event, observed, and ingest timestamps plus clock/skew behavior are known.
- [ ] Duplicate, conflict, late, out-of-order, loss, backpressure, and replay
      semantics are tested.
- [ ] Collector/agent endpoints, credentials, debug surfaces, queues, and
      exporters are hardened and monitored.
- [ ] OTel, OCSF, ECS, or other mapping versions are pinned.
- [ ] Golden mapping fixtures cover nulls, arrays, unmapped fields, and upgrades.
- [ ] Original evidence digest and governed source locator survive mapping.

### Detection and SOC workflow

- [ ] Each rule has an owner, ID, version, references, playbook, severity,
      expected false positives, status, and rollback plan.
- [ ] Cross-tenant joins are impossible by construction.
- [ ] Correlation windows, watermarks, state limits, and grouping keys are tested.
- [ ] Every alert cites admitted same-tenant evidence.
- [ ] Routing comes from trusted ownership data.
- [ ] Case creation and retries are idempotent and reconciled.
- [ ] Suppression is exact, bounded, observable, and severity-aware.

### Response and assurance

- [ ] Detection cannot directly grant or exercise authority.
- [ ] Proposals bind case, tenant, action, target, state version, requester, and
      reason.
- [ ] Approvals are exact, purpose-bound, short-lived, signed, and single-use.
- [ ] Executors re-authorize and own only named actions.
- [ ] Stable operation IDs reconcile unknown outcomes.
- [ ] Independent current-state evidence gates containment and closure.
- [ ] Labelled tests cover attacks, valid work, boundary cases, loss, lateness,
      duplicates, and pipeline failures.
- [ ] Metrics disclose population, denominator, label source, and time window.

## References and further study

Primary and official sources are preferred. Verify their current release and
stability when implementing; this chapter records its review date rather than
claiming that evolving schemas never change.

- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry logging specification](https://opentelemetry.io/docs/specs/otel/logs/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [OpenTelemetry Collector security guidance](https://opentelemetry.io/docs/security/config-best-practices/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [Open Cybersecurity Schema Framework](https://ocsf.io/)
- [OCSF schema browser](https://schema.ocsf.io/)
- [Elastic Common Schema reference](https://www.elastic.co/docs/reference/ecs)
- [Sigma 2.1.0 rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma getting started and `sigma-cli`](https://sigmahq.io/docs/)
- [MITRE ATT&CK data sources deprecation notice](https://attack.mitre.org/datasources/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST SP 800-61 Rev. 3, final, April 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OASIS STIX 2.1 and TAXII 2.1 resources](https://oasis-open.github.io/cti-documentation/resources.html)
- [OASIS introduction to STIX](https://oasis-open.github.io/cti-documentation/stix/intro)
- [OASIS introduction to TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro.html)
- [CISA joint guidance: Best Practices for Event Logging and Threat Detection](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)

## Final perspective

A useful SOC pipeline is not a large pile of logs. It is a governed evidence
system with authenticated producers, privacy-minimized contracts, explicit time
and delivery semantics, trusted enrichment, bounded tenant-safe correlation,
versioned detections, evidence-linked cases, authorized response, independent
outcome verification, and honest quality metrics.

Keep the authority boundary visible at every step: models propose, sensors
observe, detectors signal, analysts decide, trusted applications enforce, and
independent evidence verifies.
