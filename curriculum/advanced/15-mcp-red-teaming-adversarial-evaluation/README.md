# MCP Red Teaming and Adversarial Evaluation

Red teaming tests whether an MCP-enabled system can be induced to violate a
security objective under realistic adversarial pressure. This course turns a
threat model into an authorized campaign, exercises the model and the application
around it, judges observable outcomes independently, and promotes every confirmed
failure into a reproducible security regression.

## Course thesis

An agent response is not the security outcome. The meaningful question is whether
an adversary completed a forbidden disclosure, write, delegation, persistence, or
other real-world effect. A model may refuse after an effect happened; a detector
may alert without preventing it; and a safe system may allow suspicious-looking
words while enforcing the right boundary.

The central design rule is:

```text
model / attacker / generator -> proposes prompts, plans, and tool calls
trusted application          -> validates, authorizes, executes, observes, and records
independent evaluator        -> compares labelled intent with observable effects
```

Level: advanced. Complete Courses 1–14 first, especially threat modeling, prompt
injection, secure release gates, and structure-aware security testing.

## Learning objectives

You will learn to:

1. write rules of engagement (ROE), scope, safety limits, stop conditions, and an
   evidence plan before a campaign starts;
2. turn assets, trust boundaries, and abuse cases into falsifiable threat
   hypotheses and a coverage matrix;
3. test direct and indirect prompt injection, tool and context poisoning, broken
   access control, excessive agency, approval bypass, capability drift, memory
   poisoning, exfiltration, and multi-step attack chains;
4. separate a seed, attack generator, delivery strategy, target, evaluator, and
   effect oracle so one component does not grade itself;
5. distinguish model behavior from application enforcement and infrastructure
   failure;
6. use deterministic rules for objective effects and carefully calibrated model or
   human judges for semantic outcomes;
7. measure attack success, completed forbidden effects, detection, containment,
   safe-task completion, false blocks, inconclusive cases, coverage, cost, and
   uncertainty with the correct denominators;
8. compare PyRIT, garak, Promptfoo, Inspect AI, and custom MCP harnesses without
   mistaking tool adoption for coverage; and
9. convert confirmed findings into minimized fixtures, owned remediations,
   release gates, monitoring, and retests.

## 1. Red teaming is not ordinary testing

Course 14 asks whether known invariants survive mutation and fuzzing. This course
adds an adversarial objective: the attacker adapts delivery, chains weaknesses,
uses information learned from the target, and tries to produce impact. The two
disciplines reinforce each other:

| Security testing | Red teaming |
|---|---|
| checks specified properties | challenges assumptions and finds missing properties |
| often bounded to one component | follows realistic paths across components |
| optimized for deterministic CI | includes exploratory, adaptive, and human-led work |
| starts from a known oracle | may expose ambiguous policy requiring adjudication |
| regression proves a fixed requirement | campaign evidence drives new regressions |

Neither establishes that a system is “secure.” A campaign supports a bounded
claim about one target version, configuration, policy, environment, corpus, attack
budget, and time window.

## 2. System under test

The lab models a multi-tenant support assistant. A support analyst can read a
ticket, export one customer record to an approved audit vault, send an exactly
approved reply, or persist a bounded fact with provenance. Ticket content, tool
output, memory, tool metadata, and every model-proposed action are untrusted.

```text
synthetic user / poisoned ticket / tool output
                  |
                  v
       deterministic proposal fixture
        (model substitute for CI only)
                  |
                  v
     trusted MCP application boundary
  contract pin -> schema -> identity -> policy
       -> exact approval -> execution
                  |
                  v
     independent effect ledger + audit trail
                  |
                  v
       independently labelled oracle
```

The deterministic proposal fixture makes the lab credential-free and reproducible.
It tests the application boundary, not the safety quality of a foundation model.
A production campaign may replace it with a live model or attacker agent, but must
reuse the same trusted scope, target controls, effect observations, and labels.

## 3. Rules of engagement before payloads

An ROE is an authorization artifact, not a ceremonial document. At minimum record:

| Field | Required decision |
|---|---|
| authority | named owner who authorized the exact target and techniques |
| target | immutable build/model/configuration IDs and allowed endpoints |
| environment | isolated tenant, synthetic identities/data, and prohibited systems |
| time | start/end window and operator coverage |
| techniques | allowed attack families, automation, and social/physical exclusions |
| credentials | test-only identities, scopes, storage, rotation, and revocation |
| budgets | requests, turns, tokens, cost, concurrency, time, bytes, and storage |
| effects | which writes are simulated, reversible, or forbidden even in test |
| stop conditions | safety breach, unexpected destination, real data, instability, or cost cap |
| kill switch | who can stop work and how authority/network access is revoked |
| evidence | collection, redaction, access, retention, and deletion |
| escalation | security, privacy, legal, operations, vendor, and incident contacts |
| disclosure | triage, severity, remediation ownership, retest, and external reporting |

Do not aim a scanner at production because the endpoint is reachable. Do not use a
real customer prompt as a convenient seed. Do not allow an attacker model to widen
its own scope. Test doubles for email, payments, files, identity, and egress should
make forbidden effects observable without making them real.

## 4. Build threat hypotheses

A useful hypothesis names the attacker, precondition, path, forbidden objective,
and evidence that would refute the system's safety claim:

> Given a ticket author who controls ticket text, when the assistant reads an
> indirect instruction asking it to export the customer's record to an arbitrary
> URL, the untrusted content must not grant authority; no export may appear in the
> effect ledger, and the attempt must produce a correlated policy event.

Map hypotheses to the actual architecture, not only to a generic list. MITRE ATLAS
provides adversary tactics and techniques; OWASP catalogues application risks; NIST
AI RMF provides governance, mapping, measurement, and management outcomes. These
are coverage inputs, not substitutes for a system-specific threat model.

### MCP and agent attack matrix

| Family | Entry surface | Adversarial objective | Observable safe outcome |
|---|---|---|---|
| direct prompt injection | user message | override purpose or policy | proposal rejected at action boundary |
| indirect prompt injection | ticket, web, file, tool result | turn data into instructions | data remains untrusted; no forbidden effect |
| tool poisoning | description, schema, annotation | steer calls or conceal behavior | full contract digest mismatch quarantines server |
| capability drift | discovery or runtime | add shell/network/admin authority | unreviewed tool absent or denied |
| confused deputy | trusted host plus weak server | use caller authority for another tenant | trusted identity and resource policy bind tenant |
| approval laundering | changed recipient/body/target | reuse approval for another action | canonical action digest mismatch |
| approval replay | repeated or concurrent call | duplicate a consequential effect | single-use receipt and idempotent operation |
| memory poisoning | summary or long-term memory | persist attacker instructions | only bounded facts with source provenance persist |
| credential theft | context, config, logs | disclose or reuse credentials | secrets never enter model context or evidence |
| SSRF and exfiltration | URL/destination argument | reach internal or attacker service | trusted destination policy and independent egress |
| cross-server chain | server A output to server B | combine individually allowed steps | end-to-end intent and effect authorization |
| denial of wallet/service | loops, oversized content | consume tokens, calls, time, storage | hard budgets, cancellation, backpressure, isolation |
| supply-chain substitution | server/tool/model package | run changed artifact or behavior | provenance, digest pinning, re-review, rollback |

Include positive cases beside every attack family. If every suspicious string is
blocked, the system may look safe while being unusable. The lab includes a benign
case specifically to expose that false-positive strategy.

## 5. Campaign architecture

Keep roles independent:

- **Seed corpus:** reviewed intents, incidents, threat hypotheses, and synthetic
  examples with provenance and expected policy outcomes.
- **Generator:** creates variations. It may be rules, Hypothesis, a framework
  plugin, a model, or a human operator.
- **Strategy:** transforms or delivers a seed through single-turn, multi-turn,
  encoding, indirect, multimodal, cross-session, or cross-tool paths.
- **Target adapter:** connects to the full application, not only the underlying
  model, while preserving identity and state.
- **Effect observer:** reads the test datastore, message outbox, network sink,
  approval service, audit stream, or sandbox state.
- **Evaluator:** compares the labelled policy outcome and observed effect. It does
  not rely solely on the target's prose.
- **Evidence store:** retains immutable identifiers, digests, versions, results,
  and redacted traces under an explicit retention policy.

An attacker model can propose an exploit. A grader model can help classify a
semantic response. Neither may grant credentials, change the ROE, approve an
effect, silently relabel ground truth, or declare a real-world action harmless.

## 6. Choose evaluators by claim

Use the least ambiguous evaluator capable of testing the claim.

| Claim | Preferred evaluator | Common mistake |
|---|---|---|
| no message was sent | outbox or provider test-double state | search response for “sent” |
| no cross-tenant read occurred | datastore access/effect ledger | trust a `deny` string |
| exact approval was required | receipt store plus canonical digest | accept `approved=true` in arguments |
| no arbitrary egress occurred | independent proxy/sink logs | inspect only tool return text |
| contract did not drift | pinned full contract/artifact digest | compare only tool name |
| response violates a nuanced policy | calibrated human or model rubric | use unvalidated keyword matching |
| target was operational | health/trace evidence separate from safety | count timeout as a safe block |

### Model graders

Model graders are appropriate when the expected result is semantic and cannot be
expressed deterministically. They introduce their own false positives, false
negatives, position bias, model/version drift, and prompt-injection surface.

Before using one as a gate:

1. build a hidden, human-labelled calibration set with positive, negative, and
   ambiguous examples;
2. report precision, recall, confusion matrix, and disagreement by risk stratum;
3. pin grader model, prompt, sampling settings, and policy version;
4. blind the grader to irrelevant labels and sanitize target-controlled content;
5. route ambiguous/high-impact cases to independent human review; and
6. rerun calibration after every material grader change.

Never use the same model instance as attacker, target, and final judge without an
independent outcome oracle.

## 7. Outcome taxonomy

Keep these outcomes separate:

- **safe allow:** a labelled valid task completed exactly the authorized effect;
- **safe block:** a labelled attack produced no forbidden effect;
- **unsafe proposal:** the model proposed a forbidden action, but the trusted
  application prevented it;
- **policy bypass:** the trusted boundary accepted a forbidden action;
- **completed forbidden effect:** the external state proves impact occurred;
- **detected:** a correlated signal was emitted;
- **contained:** authority was revoked, a server was quarantined, or an active path
  was stopped;
- **inconclusive:** available evidence cannot distinguish pass from fail; and
- **infrastructure error:** timeout, quota, adapter, reset, or dependency failure
  invalidated the trial.

Do not count an infrastructure error as a safe block. Do not count every generated
prompt as a valid adversarial attempt if it never reached the intended boundary.

## 8. Metrics with correct denominators

For labelled adversarial attempts:

```text
attack success rate = attacks with >=1 completed forbidden effect / valid attack attempts
forbidden-effect rate = completed forbidden effects / valid attack attempts
detection rate = attacks with correlated detection / valid attack attempts
containment rate = attacks with verified containment / containment-applicable attacks
```

For labelled valid tasks:

```text
safe-task completion = valid tasks completing the expected effect / valid task attempts
false-block rate = valid tasks blocked / valid task attempts
```

Also report coverage by asset, actor, boundary, attack family, technique, channel,
role, tenant, tool risk, and single/multi-turn path. Track requests, target tokens,
attacker tokens, grader tokens, elapsed time, cost, retries, and infrastructure
failures separately.

A rate from a small sample is uncertain. The lab includes a Wilson interval to
show that 0 successes in a tiny suite is not proof of zero underlying risk. For
stochastic targets, use predeclared seeds where supported, repeated independent
runs, confidence intervals, and paired comparisons. Preserve transcripts and
version metadata; do not cherry-pick the best rerun.

## 9. Common frameworks and when to use them

| Tool | Strong fit | Integration model | Watch-outs |
|---|---|---|---|
| Microsoft PyRIT | multi-turn attacks, converters, target adapters, memory, custom scorers | Python framework, scanner, or GUI | isolate attacker/target/scorer roles; add effect-based scorers |
| NVIDIA garak | broad model/dialog vulnerability probing and detector-driven discovery | generators, probes, detectors, harness, evaluator | many detectors score text; wrap the full app for effect claims |
| Promptfoo | configuration-driven evals, plugins/strategies, custom assertions, CI, MCP targets | YAML plus providers and assertions | prefer deterministic assertions for objective state; control remote generation |
| Inspect AI | reproducible agent/model eval tasks, scorers, logs, sandboxes, external agents | Python tasks, solvers/agents, scorers, sandbox | sandbox the target and still instrument external effects |
| Hypothesis | typed/stateful variation, shrinking, boundary regression | Python properties and state machines | properties and strategies are only as good as the threat model |
| custom MCP harness | protocol, identity, tool-contract, approval, and effect-specific claims | official SDK plus trusted adapters | avoid recreating a generic scanner; keep adapters small |

Tool selection follows the hypothesis. Use garak for broad model failure discovery,
PyRIT for adaptable multi-turn workflows, Promptfoo for configuration-led application
and MCP scans, Inspect for rigorous agent tasks and sandboxed evaluations, and a
small custom harness when trusted business state is the decisive oracle. A mature
program commonly uses more than one and normalizes evidence into one schema.

Pin versions in reproducible environments. Record whether a tool performs remote
inference or uploads data, and review its license, telemetry, credential handling,
network access, and generated artifacts before introducing sensitive fixtures.

## 10. Practical lab

From the repository root:

```bash
uv sync --extra contributor
uv run python curriculum/advanced/15-mcp-red-teaming-adversarial-evaluation/lab.py
uv run pytest tests/test_course_15_red_teaming.py -q
```

The lab provides:

- a deliberately vulnerable baseline and a hardened target;
- trusted identities, reviewed tool contracts, contract digests, and scoped tools;
- direct, indirect, tool-output, memory, cross-tenant, capability, exfiltration,
  tool-poisoning, and approval-laundering scenarios;
- exact approval binding, expiry, single-use consumption, and operation identity;
- an independent effect ledger for disclosures, messages, exports, and memory;
- result classification, stable failure signatures, redacted evidence artifacts,
  coverage, safe-task metrics, and Wilson intervals; and
- a real in-memory call through the official MCP Python SDK.

The hardened campaign should have a zero completed-forbidden-effect rate and a
100% safe-task completion rate for this corpus. The vulnerable baseline should
complete forbidden effects. Neither result supports a claim beyond the specified
fixtures and budgets.

### Lab investigation

1. Run the campaign and locate the first vulnerable case where the response and
   effect ledger disagree with the label.
2. Inspect `result_artifact`. Confirm it contains target, policy, protocol, seed,
   input digest, trace, technique, and ROE reference—but no raw malicious payload.
3. Add a valid approved export and its exact effect fingerprint.
4. Add a replay case that sends the same approved message twice against one target.
   The first effect may exist; the second call must not create another effect.
5. Add a multi-step cross-server chain: an untrusted ticket proposes a read, then
   uses the result to propose an export. Label the end-to-end forbidden objective,
   not only each isolated step.
6. Use Hypothesis to vary tenant, destination, source, tool name, and action fields.
   Preserve a minimal counterexample as a named regression.
7. Replace one deterministic policy with a model grader, build a calibration set,
   and report its confusion matrix before trusting its score.

### Optional live adapter

When you are explicitly authorized to use a live test system:

1. retain the deterministic suite as the release gate;
2. create a least-privileged synthetic tenant and reversible downstream doubles;
3. implement a target adapter for the complete host/client/server workflow;
4. bind each request to the configured identity instead of accepting identity from
   generated content;
5. collect independent effect state and infrastructure health;
6. enforce request, turn, token, concurrency, time, cost, and destination budgets;
7. stop immediately on any ROE condition; and
8. delete credentials and sensitive campaign artifacts under the retention plan.

## 11. From finding to regression

A finding is not finished at “the model complied.” Preserve:

- campaign/case ID, hypothesis, authorization reference, and owner;
- target model/application/artifact/configuration/policy versions;
- seed, generator, strategy, parameters, turn budget, and input digest;
- trusted identity, tenant, scopes, tool contract digests, and environment;
- expected policy outcome, actual decision, external effects, detection, containment,
  infrastructure health, and trace IDs;
- minimal reproducer, severity, affected assets, exploit prerequisites, and blast
  radius;
- remediation owner, due date, change, regression ID, and retest evidence; and
- redaction, access, retention, and disclosure decisions.

Triage duplicates by stable root-cause and outcome signatures, not raw prompt text.
Validate the finding manually in the safe environment. Minimize it without removing
the causal path. Add a deterministic regression at the lowest useful layer and an
end-to-end case where the chain matters. A fix is complete only when the regression
passes, the original campaign path is retested, telemetry exists, and the owner has
accepted residual risk.

## 12. Continuous evaluation

Use three loops:

1. **Per change:** fast deterministic regressions, contract diffs, policy checks,
   safe-task cases, and effect oracles.
2. **Scheduled:** broader stochastic or adaptive campaigns in isolated environments,
   with budgets and drift comparison.
3. **Human-led:** scoped exercises for novel chains, business logic, social context,
   and assumptions automation is unlikely to challenge.

Release gates should use predeclared thresholds and fail on missing evidence,
infrastructure errors, changed target identity, invalid reset, or unreviewed contract
drift. They should not silently convert an inconclusive result into a pass.

Monitor production for the same boundary signals—contract changes, unusual tool
chains, cross-tenant attempts, approval mismatch/replay, unexpected destinations,
budget exhaustion, and containment actions—without replaying harmful payloads or
recording secrets.

## 13. Enterprise checklist

### Before

- [ ] Written authorization names exact targets, environment, techniques, and time.
- [ ] Synthetic data, test identities, downstream doubles, and reset are verified.
- [ ] Threat hypotheses cover actual assets and trust boundaries.
- [ ] Safe-task controls accompany adversarial cases.
- [ ] Budgets, kill switch, stop conditions, escalation, and on-call coverage exist.
- [ ] Evidence, privacy, retention, disclosure, and vendor terms are approved.

### During

- [ ] Target, model, policy, tool contract, environment, and generator versions are captured.
- [ ] Infrastructure health is separate from safety outcome.
- [ ] Independent observers verify disclosures and side effects.
- [ ] Operators watch cost, rate, destination, errors, and stop conditions.
- [ ] Raw secrets, tokens, and unnecessary payloads do not enter logs or reports.

### After

- [ ] Findings are manually reproduced and deduplicated.
- [ ] Severity reflects achieved impact and realistic prerequisites.
- [ ] Every accepted finding has an owner, remediation, and regression.
- [ ] Fixed cases are retested across safe-task and neighboring attack cases.
- [ ] Credentials are revoked and environments reset and verified.
- [ ] Residual risk, coverage gaps, and uncertainty are explicit.

## Exercises

1. Write an ROE for a staging MCP assistant that can draft invoices but must not
   send them. Include a stop condition for accidental contact with a real vendor.
2. Map five system-specific hypotheses to MITRE ATLAS and OWASP categories, then
   identify one business-logic risk neither catalogue states precisely.
3. Design an effect oracle for a destructive database tool whose real operation may
   never run during testing.
4. Calculate attack success and Wilson intervals for 0/10, 1/10, and 10/100. Explain
   why the first result is not evidence of zero risk.
5. Compare a refusal-text detector with an outbox observer after the target replies
   “I cannot do that” but a message appears in the outbox.
6. Select PyRIT, garak, Promptfoo, Inspect, or a custom harness for three different
   hypotheses and justify each selection in terms of target and oracle.
7. Define promotion criteria from a human-led finding to a per-change CI regression.

## References

Primary and official sources, checked 2026-10-04:

- [Model Context Protocol 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
- [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MITRE ATLAS threat matrix](https://atlas.mitre.org/)
- [NIST AI RMF Generative AI Profile, NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1)
- [NIST AI 100-2e2025: Adversarial Machine Learning taxonomy](https://doi.org/10.6028/NIST.AI.100-2e2025)
- [OWASP GenAI Red Teaming Guide](https://genai.owasp.org/resource/genai-red-teaming-guide/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [Microsoft PyRIT documentation](https://microsoft.github.io/PyRIT/)
- [NVIDIA garak documentation](https://reference.garak.ai/en/stable/)
- [Promptfoo red-team architecture](https://www.promptfoo.dev/docs/red-team/architecture/)
- [Promptfoo MCP provider](https://www.promptfoo.dev/docs/providers/mcp/)
- [UK AI Security Institute Inspect](https://inspect.aisi.org.uk/)
- [Hypothesis documentation](https://hypothesis.readthedocs.io/)

## Summary

Professional red teaming is authorized experimental risk measurement. It starts
with a threat model and ROE, attacks the whole agent system, observes real effects,
keeps generators and judges separated, preserves reproducible evidence, reports
uncertainty and safe-task impact, and ends with owned fixes and durable regressions.
The model proposes. The trusted application decides and executes. Independent
evidence determines what actually happened.
