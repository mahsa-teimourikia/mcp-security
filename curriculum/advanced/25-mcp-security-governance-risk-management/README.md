# MCP Security Governance and Risk Management

## Course thesis

Governance is the system that turns MCP security claims into accountable,
versioned decisions. A defensible program states what may go wrong and why it
matters, assigns owners, verifies controls against current scoped evidence,
applies explicit risk appetite and tolerance, authorizes treatment or a bounded
control exception, triggers reassessment after material change, and reports the
portfolio without converting ordinal judgments into false precision.

Governance does not replace engineering. Compliance does not prove security.
A green test does not accept risk. A signed decision does not grant runtime
tool authority. Each artifact has one purpose and one accountable boundary.

## Learning objectives

By the end of this course, you will be able to:

1. distinguish governance, cybersecurity risk management, AI risk management,
   compliance, assurance, and runtime authorization;
2. write a complete MCP risk scenario linking threat, vulnerable condition,
   event, affected assets, consequence, and business objective;
3. define risk appetite, tolerance, decision roles, escalation, and prohibited
   outcomes before reviewing an individual system;
4. create a versioned risk record with inherent and residual assessments,
   treatment, review state, and material-change triggers;
5. trace each control claim to authenticated, current, scoped test, telemetry,
   drill, audit, or independent-review evidence;
6. use qualitative or ordinal matrices transparently without pretending the
   result is probability, currency, or expected loss;
7. separate risk acceptance from a temporary control exception and require
   compensating controls, expiry, review, and an exit plan;
8. bind consequential decisions to exact records, evidence, policy, approver
   authority, expiry, and atomic single use;
9. handle concurrent decisions, stale versions, retries, and unknown outcomes;
10. invalidate decisions after material model, tool, identity, vendor,
    topology, data, incident, legal, policy, or deployment changes; and
11. aggregate portfolio counts, rates, trends, and concentration without
    averaging incomparable ordinal scores.

## Prerequisites and timebox

Complete Course 2 and Courses 12–24 first. Bring one MCP architecture, threat
model, control inventory, test report, incident/recovery result, and owner map.

Suggested time: 90 minutes reading, 120 minutes lab and notebook, and 60
minutes for the governance design exercise.

## Scenario

Acme's support MCP platform serves multiple tenants. A human analyst uses an
MCP host through an enterprise gateway. A support server reads and updates a
ticket API. The platform depends on an IdP, workload identity, CI/CD, a server
registry, model provider, policy service, telemetry pipeline, and incident
response team.

The governing business objective is:

> Serve support tickets without cross-tenant disclosure or unauthorized side
> effects, while meeting recovery and availability obligations.

The primary course risk scenario is:

> Because caller and resource tenant may not be independently enforced, an
> attacker can steer a valid MCP tool call across a tenant boundary, causing
> confidential customer data disclosure, regulatory exposure, and incident
> response cost.

The lab evaluates tenant-authorization and recovery controls using signed test,
telemetry, and drill evidence. It produces an application-owned decision,
records it exactly once, and invalidates it on material change.

### Safety and authority boundary

The lab is deterministic, local, and credential-free. Ed25519 signatures model
authenticated evidence and approval receipts. In-memory stores model a risk
register, exception workflow, and operation journal. They do not constitute a
legal determination, audit opinion, enterprise risk acceptance, compliance
certification, or production authorization.

## 1. Governance is not a paperwork layer

Governance establishes decision rights, policy, oversight, escalation, and
feedback across the system lifecycle. Engineering implements and operates
controls. Assurance tests whether claims are supported. Compliance evaluates
applicable obligations. Risk management connects uncertainty and potential
consequence to business objectives and chooses a response.

| Artifact | Answers | Does not grant |
|---|---|---|
| architecture review | is the design coherent and evidence-backed? | production deployment or tool calls |
| threat model | what can go wrong under stated assumptions? | probability or risk acceptance |
| test result | what happened in a labelled bounded experiment? | universal control effectiveness |
| audit evidence | what a scoped assessment observed | future runtime authorization |
| policy decision | what outcome current policy recommends | human acceptance unless authority signs |
| risk acceptance | who owns a stated residual exposure | bypass of runtime security controls |
| exception | temporary permission to deviate from one requirement | acceptance of every related risk |
| access token | delegated runtime authority for one resource | enterprise risk approval |

NIST CSF 2.0 elevates **Govern** alongside Identify, Protect, Detect, Respond,
and Recover. Its outcomes cover organizational context, risk strategy, roles,
policy, oversight, and supply-chain risk. NIST AI RMF 1.0 uses Govern, Map,
Measure, and Manage; governance is cross-cutting rather than a final approval
step. As of this course revision, NIST states that AI RMF 1.0 is being revised,
so implementations should record the framework and profile version they use.

## 2. Frameworks are maps, not interchangeable checklists

Use frameworks to structure outcomes and communication. Tailor them to the
system, jurisdiction, business objective, and risk method.

| Framework or method | Best use here | Important limit |
|---|---|---|
| NIST CSF 2.0 | enterprise cybersecurity outcomes and profiles | does not prescribe implementation |
| NIST AI RMF 1.0 | govern, map, measure, manage AI-specific risk | voluntary and currently under revision |
| NIST AI 600-1 | GenAI risk profile and suggested actions | profile, not product certification |
| NIST IR 8286 series | integrate cyber risk registers with ERM | requires organization-specific appetite and methods |
| NIST SP 800-37 | system risk-management lifecycle | federal framing may require tailoring |
| NIST SP 800-30 | risk-assessment concepts and process | estimates still depend on evidence and judgment |
| NIST SP 800-53 | control catalog and assessment context | selecting a control does not prove effectiveness |
| OSCAL | machine-readable catalogs, plans, results, POA&M | structured data is not automatically trustworthy |
| ISO 31000 / 27005 | general and information-security risk process | licensed standards and local implementation choices |
| FAIR | quantitative information-risk analysis | needs calibrated inputs and disciplined uncertainty |
| MITRE ATT&CK/ATLAS | threat and technique knowledge | technique mapping is not risk scoring |

Do not combine identifiers from several frameworks and call that evidence. A
mapping helps navigation; it does not establish that a control is implemented,
operating, current, or sufficient for an MCP scenario.

## 3. Risk vocabulary

### Risk capacity, appetite, and tolerance

- **Capacity**: the maximum exposure the enterprise could absorb.
- **Appetite**: the type and amount of risk it is willing to pursue or retain
  in support of objectives.
- **Tolerance**: acceptable variation or boundary for a specific objective,
  measure, or risk category.
- **Limit**: an operational threshold that triggers escalation or action.

Set these before the system owner seeks approval. If every high-risk review
creates a new meaning for “high,” governance is not consistent.

Example policy for the course lab:

- low residual risk: system owner, risk manager, or CISO may decide;
- moderate: risk manager or CISO;
- high: CISO;
- critical: prohibited for deployment; risk committee may record rejection;
- control exception: CISO, at most 14 days, with evidence-backed compensating
  controls and an earlier review date; and
- decision validity: at most 15 minutes and never longer than cited evidence or
  exception validity.

These thresholds are teaching policy, not a universal standard.

### Inherent and residual risk

**Inherent risk** describes exposure before the selected controls. **Residual
risk** describes the assessed exposure after considering current controls and
evidence. Residual risk is not simply inherent score minus control count.

A residual reduction requires a causal argument:

1. which event path changes;
2. which likelihood or impact dimension changes;
3. what control produces that change;
4. what evidence supports operation and outcome;
5. what uncertainty and failure modes remain; and
6. how quickly monitoring detects loss of effectiveness.

### Treatment versus decision

Common treatment choices are avoid, mitigate, transfer/share, accept, and
monitor. A treatment plan is not a completed treatment. Each action needs an
owner, due date, dependency, completion evidence, and effect on the scenario.

Risk acceptance is a decision to retain specified residual exposure. A control
exception permits temporary deviation from one requirement. An exception may
increase risk; it does not automatically accept that risk or override appetite.

## 4. Write decision-useful risk scenarios

Avoid labels such as “prompt injection risk” or “OAuth risk.” Use a causal
statement:

```text
Because <vulnerable condition or dependency>,
<threat actor/event> may <event>,
affecting <assets, tenants, people, or objectives>,
causing <business, security, privacy, safety, legal, or operational impact>.
```

A complete MCP scenario records:

- risk ID and related parent/child risk IDs;
- business objective and mission/service dependency;
- system, tenant scope, users, subjects, and affected parties;
- threat event and actor/capability assumptions;
- vulnerable condition, trust boundary, and preconditions;
- affected identities, data, tools, servers, models, APIs, and artifacts;
- confidentiality, integrity, availability, privacy, safety, financial,
  operational, legal, and reputational consequences as applicable;
- existing controls and dependencies;
- inherent likelihood/impact with rationale and uncertainty;
- residual likelihood/impact with evidence IDs and assessor;
- treatment, actions, owner, decision authority, review date, and status;
- system, model, tool-contract, artifact, policy, and framework versions; and
- triggers that invalidate the assessment.

### Scenario quality checks

- Can an engineer identify the enforcement point?
- Can a tester create labelled positive and adversarial cases?
- Can an operator identify telemetry and an independent outcome oracle?
- Can an executive connect the consequence to an objective or tolerance?
- Can a reviewer tell what evidence would falsify the assessment?

If not, the scenario is too vague for a defensible decision.

## 5. Assessment methods and uncertainty

### Qualitative and ordinal matrices

The lab uses five ordered likelihood categories, five ordered impact
categories, and a declared matrix that maps each pair to low, moderate, high,
or critical. The multiplication used to construct the teaching table is only a
convenience. A result of 12 is not currency, probability, expected annual loss,
or “twice” a result of 6.

Document category anchors. Example likelihood anchors might refer to observed
frequency, attacker access, preconditions, and control reliability. Impact
anchors should reflect the enterprise's business impact analysis and separate
dimensions where one average would hide a severe outcome.

Never average ordinal bands across a portfolio. Report counts by band, trend,
concentration, and the underlying scenarios.

### Quantitative analysis

Quantitative methods can improve decisions when inputs are calibrated. Record
distributions or ranges for event frequency and loss magnitude, model
dependencies, run sensitivity analysis, and report uncertainty. Do not invent
probabilities from CVSS, model confidence, control count, or a language model's
guess. Compare the cost of treatment with the distribution of avoided loss,
not a single magic number.

### Data quality

For every estimate, record source, period, population, exclusions, units,
freshness, uncertainty, and owner. Distinguish:

- observed events from inferred events;
- blocked attempts from completed forbidden effects;
- component metrics from end-to-end outcomes;
- exposure from realized loss;
- absence of evidence from evidence of absence; and
- one source rendered several ways from independent corroboration.

## 6. Controls and the claim-to-proof chain

A control entry needs an objective, owner, implementation boundary, applicable
scenarios, dependencies, evidence requirements, test cadence, monitoring,
failure behavior, exceptions, and framework references.

```text
risk scenario
  -> control objective
    -> enforcement implementation
      -> labelled test or assessment
        -> authenticated evidence artifact
          -> telemetry and independent outcome
            -> current residual assessment
              -> authorized decision
```

The lab validates signed evidence against:

- evidence and control ID;
- system, tenant, and exact subject version;
- authorized producer;
- evidence kind and claim;
- observation and expiry times;
- outcome;
- artifact digest;
- named population, numerator, denominator, and unit; and
- independence where policy requires it.

A test named `test_tenant_isolation` does not prove isolation. The evidence
must show the labelled population, result, environment/version, and outcome
oracle. Runtime telemetry should confirm the control remains effective, but a
log line is not proof that a protected resource did not change.

### Evidence freshness

Decision validity must be no longer than the shortest-lived material evidence
or exception. A valid signature authenticates a stale statement; it does not
make the statement current. Reassessment should fail closed when required
evidence is missing, expired, inconclusive, scoped to another tenant, or tied to
an older artifact/model/tool contract.

### Independent review

Higher-risk claims should include evidence independent of the implementation
owner. Independence is not merely a Boolean; production records should identify
the assessor, reporting line, conflicts, methods, and scope. The lab exposes
the invariant without claiming organizational independence from a fixture.

## 7. Decision rights and separation of duties

Define a RACI or equivalent for:

- risk identification and ownership;
- technical control ownership;
- evidence production and validation;
- residual assessment;
- risk acceptance or rejection;
- exception approval;
- legal/privacy review;
- deployment authorization;
- incident declaration and containment; and
- control/risk closure.

The same person should not request and approve a consequential exception or
risk decision. The system owner may own the business risk without being the
authorized CISO or risk committee. A risk approver does not gain production
tool credentials through that role.

The lab's approval receipt is:

- Ed25519-signed;
- bound to the complete proposal digest;
- bound to requester, approver, role, kind, and policy version;
- short-lived;
- checked against the residual band's authority table; and
- consumed atomically once under concurrent attempts.

Changing the risk version, evidence set, blockers, recommendation, system
version, exception set, or expiry requires a fresh proposal and approval.

## 8. Control exceptions

An exception record includes:

- exact control and risk;
- system, tenant, subject version, and policy version;
- accountable owner and separate approver;
- business justification;
- compensating controls and their evidence IDs;
- start, expiry, and earlier review dates;
- monitoring and escalation;
- remediation/exit plan and action owner; and
- linkage to incidents and dependent risks.

The exception is invalid when its scope drifts, evidence expires, the subject
changes, the review date passes, or the duration exceeds policy. It should not
silently renew. Expiry should remove the deviation and block the affected
decision unless a new review produces a new receipt.

Avoid “permanent exception.” That phrase usually means the baseline or risk
appetite does not match reality. Revisit the policy openly.

## 9. Material change and continuous governance

An approval is tied to reviewed facts. Trigger reassessment after changes to:

- MCP capability, method, tool, resource, prompt, schema, annotation, or cache
  contract;
- model/provider/version, system prompt, routing, temperature, or tool-use
  policy where behavior can materially change;
- human, workload, agent, client, tenant, audience, or delegated identity;
- data classification, source, retention, residency, or affected population;
- server, gateway, registry, IdP, policy service, vendor, SDK, dependency, or
  supply-chain evidence;
- topology, network path, trust domain, federation, isolation, or egress;
- artifact, build, deployment, configuration, environment, or region;
- control implementation, telemetry, evidence producer, or retention;
- threat intelligence, vulnerability, incident, near miss, or red-team result;
- legal, regulatory, contractual, policy, appetite, or tolerance requirement;
  and
- recovery objective or business impact.

The lab's `material_change` operation uses explicit old/new versions, increments
the risk version, clears the prior decision, marks reassessment required, and
records a stable change operation. A changed version is not safe merely because
the previous version was accepted.

### Cadence is not enough

Periodic review catches gradual drift; event-driven review catches material
change. Use both. The next-review date never overrides an incident or change
trigger.

## 10. Durability, concurrency, and unknown outcomes

Risk decisions are consequential records. Use optimistic version checks so a
stale reviewer cannot overwrite a newer reassessment or rejection. Bind the
approval to that version.

If a client times out after submitting a decision, the outcome is unknown.
Retry with the same logical operation ID and exact request digest, then
reconcile the authoritative register. The lab returns the prior record for an
exact retry and rejects a conflicting retry. Per-attempt IDs remain useful for
transport diagnostics but must not create duplicate decisions.

Production systems also need transactional persistence, restart/replay tests,
queue redelivery handling, immutable audit, retention, access control, and
recovery from partial writes. In-memory success proves none of these.

## 11. Portfolio aggregation and reporting

The portfolio view should answer:

- Which objectives and services carry the most significant open scenarios?
- How many risks are above tolerance, by business unit and owner?
- Which controls or vendors create concentration?
- Which evidence, assessments, actions, decisions, or exceptions are stale?
- Which exceptions expire soon, and what service depends on them?
- Which material changes have no completed reassessment?
- Are incidents or losses contradicting residual assessments?
- Is risk moving, or are teams only changing labels?

The lab reports open record count, counts by residual band, above-tolerance and
overdue-review counts/rates, active exception count, and exceptions expiring
within seven days. It names the population: open risk records.

Do not sum or average ordinal risk scores. Roll up related scenarios with clear
parent/child links and retain underlying records. Report uncertainty and missing
populations so a dashboard cannot hide incomplete inventory.

### Example metrics

- inventory coverage = governed MCP systems / discovered MCP systems;
- control evidence coverage = controls with all required current evidence /
  controls required by open scenarios;
- assessment freshness = current assessments / open risk records;
- above-tolerance rate = above-tolerance open risks / open risk records;
- exception overdue rate = expired unresolved exceptions / all exceptions due;
- treatment completion = evidenced completed actions / actions due;
- decision latency = decision timestamp − complete evidence-ready timestamp;
- change-to-reassessment time = reassessment completion − material change;
- incident contradiction rate = incidents contradicting assessed assumptions /
  incidents mapped to assessed risks; and
- unknown-risk rate = material discovered systems without an assessment /
  discovered in-scope systems.

Counts, medians, percentiles, trend, slice, and denominator should be visible.
Targets require owners and response actions; otherwise they are decoration.

## 12. Common methods and tools

| Need | Common choices | What to verify |
|---|---|---|
| risk/GRC workflow | ServiceNow GRC/IRM, Archer, OneTrust, AuditBoard, Jira-based workflows | versioning, roles, evidence scope, API/audit, exceptions, idempotency |
| control data | OSCAL JSON/YAML/XML, control catalogs, policy-as-code | model version, UUID/version semantics, signatures, source authority |
| policy enforcement | OPA/Rego, Cedar, cloud IAM, application policy | trusted inputs, deny behavior, freshness, obligations, tests |
| evidence automation | CI attestations, test reports, OpenTelemetry, SIEM, cloud/Kubernetes audit | producer identity, subject version, population, retention, redaction |
| threat knowledge | MITRE ATT&CK/ATLAS, CAPEC, vendor advisories | applicability and scenario mapping, not automatic scoring |
| architecture/threat modeling | DFDs, attack trees/graphs, STRIDE, misuse cases | scope, assumptions, trust boundaries, control/evidence linkage |
| quantitative analysis | FAIR methods, Monte Carlo tools, sensitivity analysis | calibrated inputs, dependence, uncertainty, decision usefulness |
| dashboards | GRC analytics, BI tools, notebooks | explicit denominators, drill-down, freshness, missing populations |

A GRC platform can preserve records and workflow while the MCP gateway remains
unsafe. A policy engine can enforce decisions while the policy is wrong. A
dashboard can be precise about incomplete data. Keep enforcement and evidence
at the technical boundary; integrate summaries into governance.

## 13. Lab walkthrough

From the repository root:

```bash
uv sync --locked --extra contributor
uv run --frozen python curriculum/advanced/25-mcp-security-governance-risk-management/lab.py
uv run --frozen pytest -q tests/test_course_25_governance_risk.py
```

The scenario performs these steps:

1. define an authorization and recovery control baseline;
2. register an owned, independently assessed MCP risk record;
3. create signed test, telemetry, and incident-drill evidence;
4. validate producer, subject, tenant, version, freshness, outcome, metric, and
   evidence type;
5. compare evidence against every control and residual-assessment claim;
6. apply explicit appetite, tolerance, and decision roles;
7. create a trusted, short-lived decision proposal;
8. sign and atomically consume an exact approval receipt;
9. record the decision idempotently; and
10. report portfolio counts and rates with explicit populations.

### Adversarial cases

The dedicated tests cover incomplete risk metadata, inactive owner,
unauthorized or non-independent assessor, stale assessment, unknown/duplicate
controls, unsupported residual reduction, tampered or mis-scoped evidence,
untrusted producer, expired/non-passing evidence, invalid metric denominator,
missing evidence kinds, prohibited critical risk, invalid/overlong exception,
exception-versus-acceptance confusion, self-approval, weak approver role,
receipt expiry/replay/concurrency, fabricated proposal, stale record version,
conflicting unknown retry, evidence-limited decision expiry, every material
change type, and portfolio denominator correctness.

### Production extension

Replace the fixtures with durable adapters for:

- system/service inventory and discovery;
- IdP-backed principals and decision authority;
- versioned risk, control, treatment, decision, and exception records;
- authenticated evidence producers and protected artifact storage;
- policy evaluation and workflow that cannot sign arbitrary proposals;
- OSCAL import/export where useful;
- incident, change, vulnerability, vendor, model, and deployment feeds;
- legal/privacy/affected-party review appropriate to context; and
- immutable audit plus business continuity and disaster recovery.

Then chaos-test duplicate events, concurrent decisions, stale caches, expired
evidence, signature/key rotation, producer compromise, missing inventory,
partial persistence, delayed change feeds, and unknown outcomes.

## 14. Production claim boundaries

This lab proves deterministic application invariants in one process. It does
not prove:

- a real control is effective in production;
- the fixture's likelihood or impact is calibrated for your enterprise;
- the signed producer is independent or uncompromised;
- evidence storage is immutable;
- the approver has legal or organizational authority;
- the risk is compliant with applicable law or contract;
- the system is authorized to deploy or execute tools;
- distributed decisions are durable and exactly once;
- OSCAL interoperability with a chosen platform; or
- the portfolio is complete.

Each production claim requires evidence from the actual enforcement and
decision system.

## 15. Governance review checklist

- [ ] Business objectives, in-scope systems, tenants, data, people, and owners are inventoried.
- [ ] Appetite, tolerance, limits, prohibited outcomes, and decision roles are explicit.
- [ ] Risk scenarios connect cause, event, affected assets, and consequence.
- [ ] Inherent and residual assessments include rationale, uncertainty, source, and version.
- [ ] Control objectives map to real enforcement points, owners, tests, telemetry, and failure behavior.
- [ ] Evidence is authenticated, current, scoped, version-bound, and outcome-based.
- [ ] Metric populations, numerators, denominators, units, slices, and direction are defined.
- [ ] Independent evidence is required where risk warrants it.
- [ ] Treatment actions have owners, due dates, dependencies, and completion evidence.
- [ ] Risk acceptance and control exceptions remain distinct.
- [ ] Exceptions are exact, compensated, expiring, reviewed, monitored, and non-renewing by default.
- [ ] Approvals are role-bound, exact, expiring, single-use, and atomically consumed.
- [ ] Records use optimistic version checks and idempotent logical operations.
- [ ] Material changes and incidents trigger reassessment before the calendar date.
- [ ] Evidence or exception expiry cannot outlive a dependent decision.
- [ ] Portfolio reporting preserves counts, concentration, uncertainty, and missing populations.
- [ ] Framework mappings do not substitute for implementation evidence.
- [ ] Runtime access, deployment approval, architecture review, and risk acceptance remain separate authorities.
- [ ] Closure requires verified remediation or an explicitly approved terminal disposition.

## References

### Current NIST risk and governance resources

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [NIST AI 600-1: Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST IR 8286 Rev. 1: Integrating Cybersecurity and ERM](https://csrc.nist.gov/pubs/ir/8286/r1/final)
- [NIST IR 8286A Rev. 1: Identifying and Estimating Cybersecurity Risk](https://csrc.nist.gov/pubs/ir/8286/a/r1/final)
- [NIST IR 8286C Rev. 1: Staging Risk for Governance Oversight](https://csrc.nist.gov/pubs/ir/8286/c/r1/final)
- [NIST IR 8286D Update 1: Business Impact Analysis](https://csrc.nist.gov/pubs/ir/8286/d/upd1/final)
- [NIST SP 800-37 Rev. 2: Risk Management Framework](https://csrc.nist.gov/pubs/sp/800/37/r2/final)
- [NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST OSCAL](https://pages.nist.gov/OSCAL/)
- [OSCAL assessment layer](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/)

### MCP, threat, and engineering evidence

- [MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [SLSA provenance](https://slsa.dev/spec/v1.2/provenance)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)

### Broader risk methods

- [ISO 31000 risk management](https://www.iso.org/iso-31000-risk-management.html)
- [ISO/IEC 27005 information security risk management](https://www.iso.org/standard/80585.html)
- [The Open Group FAIR standard](https://www.opengroup.org/forum/security/riskanalysis)
