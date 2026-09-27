# Prompt Injection, Tool Poisoning, and Untrusted MCP Content

Prompt injection is not solved by finding the phrase “ignore previous
instructions.” A model consumes instructions and data through the same language
channel, so a ticket, webpage, tool result, image, resource, or MCP tool
description can influence its next proposal. The durable security boundary must
therefore live outside the model.

This course builds a multi-tenant support workflow in which:

- MCP tool definitions are reviewed and pinned as complete contracts;
- tool results carry provenance and remain explicitly untrusted;
- a fallible detector raises risk signals but grants no authority;
- model output is a typed proposal, never an authorization decision;
- trusted user intent binds action, resource, target, and evidence;
- sensitive effects require exact, expiring, single-use approval;
- durable memory accepts a bounded structured fact rather than free-form
  instructions; and
- evaluation separates detector quality, safe task completion, blocked attacks,
  and completed forbidden effects.

The course thesis is:

> Untrusted content and tool metadata may influence a proposal or trigger
> review, but only trusted application state may authorize capabilities, bind
> data flow, approve exact effects, persist memory, and verify outcomes.

## Learning objectives

After completing the course, you should be able to:

1. distinguish direct injection, indirect injection, tool poisoning, rug pulls,
   parameter tampering, prompt leakage, and ordinary untrusted data;
2. identify every MCP surface that can introduce content into model context;
3. explain why prompt hierarchy, delimiters, escaping, classifiers, and model
   refusal are useful signals but insufficient authorization controls;
4. pin a complete reviewed MCP tool contract and detect a changed description,
   schema, annotation, or tool set before invocation;
5. validate tool results against schema, tenant, provenance, locator, version,
   digest, and size before use;
6. separate user intent, model proposal, policy authorization, approval, effect,
   and effect verification;
7. stop untrusted evidence from changing action, resource, recipient, scope, or
   credential authority;
8. keep poisoned text from becoming durable instructions through memory,
   summaries, caches, logs, or cross-agent messages;
9. design realistic direct, indirect, obfuscated, multi-turn, cross-tool, and
   tool-metadata adversarial tests; and
10. report meaningful utility and security metrics with explicit denominators.

## Prerequisites and learner path

Complete Courses 03, 07, 09, and 10 first. They establish narrow interfaces,
authorization, runtime isolation, filesystem controls, and egress boundaries.

1. Read this chapter.
2. Run `python3 lab.py` from this directory.
3. Complete `untrusted_content.ipynb` top to bottom.
4. Study `tests/test_course_11_untrusted_content.py`.
5. Extend the threat corpus and complete the exercises.

From the repository root:

```bash
uv sync --extra contributor
uv run python curriculum/intermediate/11-prompt-injection-tool-poisoning-untrusted-content/lab.py
uv run pytest -q tests/test_course_11_untrusted_content.py
```

The lab uses the real MCP Python SDK in memory. It does not call a live model,
external service, or credential. Explicit simulated proposals make the policy
decision reproducible and prevent a model refusal from masquerading as a
security guarantee.

## Scenario: Northstar support assistant

An authenticated Acme analyst asks the assistant to read a support ticket,
draft a response, and—after review—send a message to the customer. A ticket may
contain malicious instructions. An MCP server may also change its tool
description after review.

```text
reviewed MCP snapshot                    authenticated application state
          |                                         |
          v                                         v
MCP discovery -> contract gate        identity + exact user intent
          |                                         |
          v                                         |
tool call -> schema/provenance gateway -> untrusted content
                                                |
                                                v
                                      model-generated proposal
                                                |
                                                v
                                      deterministic action gate
                                                |
                           +--------------------+------------------+
                           |                                       |
                    non-executable draft              exact approval receipt
                                                                   |
                                                                   v
                                                        verified in-memory effect
```

The ticket text, model proposal, server self-description, annotations, tool
result, and detector result are not authority. Authenticated identity, reviewed
contract digest, user intent, application policy, and approval state are trusted
inputs.

## Threat model

### Assets

- customer and tenant data;
- tool and downstream credentials;
- email recipients, payment destinations, files, and other effect targets;
- the integrity of model context and durable memory;
- reviewed MCP capability contracts;
- approval and audit evidence;
- service availability and safe task completion.

### Attacker positions

- a malicious or compromised user;
- an author of a ticket, email, document, webpage, image, or retrieved record;
- a malicious MCP server or compromised server dependency;
- a server that changes metadata after installation or approval;
- an upstream service that returns poisoned tool output;
- a tenant attempting cross-tenant access;
- a compromised memory, cache, or cross-agent communication channel.

### Security invariants

| Boundary | Invariant | Lab evidence |
|---|---|---|
| Discovery | Complete reviewed tool snapshot must match before calls | Description and tool-set change tests |
| MCP input | Caller selects one opaque ticket ID, not tenant or action authority | Schema inspection |
| Tool output | Schema, tenant, source, locator, version, digest, and byte size are validated | Gateway fault tests |
| Trust label | All external text remains `untrusted`, even with no detector signal | Detector-miss test |
| Proposal | Model output cannot widen action, resource, recipient, or evidence | Action-binding matrix |
| Risk signal | Detector result may require review but never authorize | Review and miss tests |
| Approval | Receipt binds exact proposal, principal, tenant, target, policy, expiry, and state | Alteration, expiry, identity, replay tests |
| Execution | Only one atomically consumed receipt produces one effect | Concurrency test |
| Memory | Only bounded status plus provenance persists; free text does not | Memory test |
| Evidence | Audit uses IDs, hashes, reasons, and states without raw content | Redaction test |

## Vocabulary and attack classes

### Direct prompt injection

The user supplies text intended to change the model's instructions or bypass
policy. An authenticated user is still not automatically authorized for every
requested operation. Normal authorization, validation, budgets, and approval
remain necessary.

### Indirect prompt injection

Instructions arrive through external content: a ticket, webpage, email,
document, search result, tool output, resource, image, audio transcript, or
database field. OWASP notes that indirect injection can be intentional or
unintentional and that multimodal content expands the attack surface.

### MCP tool poisoning

A malicious instruction is placed in metadata used during tool discovery—most
obviously the description, but the whole exposed definition is relevant. The
model can be manipulated before the poisoned tool is ever invoked. An attack may
instead redirect a legitimate tool or subtly alter a parameter such as an email
recipient.

The MCP specification says tool annotations from untrusted servers must be
treated as untrusted. The same principle applies operationally to names,
descriptions, schemas, icons, and extension metadata: they describe a capability;
they do not grant permission or prove behavior.

### Rug pull and contract drift

A server presents one definition during review and another later. MCP supports
tool-list change notifications, but a notification is not authorization for the
change. The host must recompute its canonical snapshot, invalidate cached review,
and block changed capabilities until policy accepts a new version.

### Tool shadowing and cross-server influence

One tool's description or output may instruct the model to prefer, avoid, or
change arguments to another tool. Aggregating servers also creates name
collisions. Namespace tools by trusted server identity, pin contracts, and
authorize each proposed call independently.

### Persistent and delayed injection

Poisoned content may be summarized into memory, cached, copied into a ticket,
handed to another agent, or wait for a future capability to become available.
The security label and provenance must survive transformations. A clean current
turn does not make prior content trusted.

## The fundamental confused-data problem

Language models do not provide a general, formal separation between an
instruction and data that happens to look instructional. Delimiters and system
messages can improve behavior, but external text still affects token-level
generation.

This makes the following design unsafe:

```text
ticket text -> model decides action -> model invokes powerful tool
```

The secure design narrows the model's role:

```text
trusted user intent + labelled evidence -> model proposes bounded values
trusted application -> validates, authorizes, approves, executes, verifies
```

The application does not ask “did the model obey?” as its primary security
check. It asks “does this exact proposed effect fit authenticated, current,
application-owned authority?”

## MCP discovery is a security boundary

The lab calls `tools/list` through the real SDK and canonicalizes every field in
each returned tool definition. `ToolCatalogGate` compares:

- exact tool set;
- names and descriptions;
- complete input and output schemas;
- annotations and extension metadata;
- titles, icons, and other serialized fields.

A changed description produces `TOOL_CONTRACT_CHANGED`. An extra export tool
produces `TOOL_SET_CHANGED`. In either case no tool handler runs.

Production registries should bind the reviewed snapshot to server identity,
origin/launch configuration, package or image digest, signer/provenance,
requested scopes, transport, policy version, reviewer, and expiry. Hashes prove
equality to reviewed bytes; they do not prove those bytes are benign.

Do not review only the rendered description. Hidden schema fields, annotations,
icons, and extension metadata may also reach a model or UI. Canonicalization
must be deterministic across pagination, ordering, protocol versions, and SDK
serialization.

## Tool-result containment

`ticket.read` returns a closed structured output containing:

- stable content and ticket IDs;
- tenant;
- a bounded status enum;
- bounded text;
- source ID and version;
- canonical locator;
- retrieval time; and
- SHA-256 of the text.

`ContentGateway` validates all fields before storing an artifact. The digest
binds text to provenance evidence; it does not make the text truthful or safe.
The `trust_label` remains `untrusted` after successful schema validation.

Content should be segmented by source and labelled in model context. Preserve
provenance through summaries and transformations. Do not concatenate multiple
sources into an unlabeled “trusted context” block. Authorize retrieval before
ranking so a poisoned document cannot also become a cross-tenant disclosure.

## Detection is instrumentation, not authority

`RiskDetector` deliberately uses simple markers, invisible-character checks,
and an encoded-blob signal. Its corpus includes a paraphrased attack it misses
and benign quoted security language it flags. The resulting recall and false
positive rate are honest properties of that labelled fixture.

A production detector may use rules, classifiers, a separate model, ensemble
scoring, provenance reputation, or content-disarm tooling. Every option has
evasion, distribution-shift, latency, privacy, and availability tradeoffs.

Safe semantics:

- a positive signal may quarantine, restrict capabilities, or require review;
- a negative signal means “not detected,” never “trusted” or “authorized”;
- detector errors fail according to explicit risk policy; and
- detector telemetry is versioned so regressions can be reproduced.

OWASP explicitly describes prompt injection prevention as an open problem and
recommends layered mitigation: constrained behavior, output validation,
filtering, least privilege, approval, external-content separation, and regular
adversarial testing.

## Bind proposals to trusted intent

`UserIntent` is created by trusted application code from the authenticated
interaction. It binds:

- tenant;
- one ticket;
- one action (`reply.propose` or `message.send`);
- exact recipient for sending;
- purpose; and
- maximum body length.

`ActionProposal` is model-controlled. `ActionGate` compares it field by field to
the trusted intent and admitted evidence. A poisoned ticket cannot change:

- `message.send` into `secret.export`;
- `customer@example.com` into an attacker recipient;
- one ticket into another;
- Acme evidence into another tenant; or
- a draft into an executable operation.

A flagged ticket may still support a non-executable draft marked for review.
It cannot directly drive an external send. This preserves useful work while
holding the effect boundary.

## Approval is a bound state transition

A confirmation boolean or model statement such as “approved” is not approval.
`ApprovalStore` issues a short-lived receipt only for an executable proposal
that has already passed policy. The receipt binds:

- proposal digest;
- principal and tenant;
- action and target fingerprint;
- policy version;
- issuance and expiry; and
- server-side `issued` state.

Consumption is atomic. An altered body fails digest binding, another principal
fails identity binding, an expired receipt fails time binding, a policy change
fails version binding, and concurrent replay yields exactly one effect.

In production, the approval UI must show the real action, target, material
arguments, data disclosure, and provenance—not a model-written summary alone.
The executor must verify downstream outcome and reconcile an unknown result
before retrying.

## Memory and persistence

Writing a whole ticket or model summary into durable memory can turn one indirect
injection into a long-lived policy contaminant. The lab exposes no generic
memory-write tool. `MemoryStore` persists only the validated `ticket.status` enum
with tenant, subject, evidence ID, source version, and digest.

Real memory systems need candidate/write separation, authorization, provenance,
retention, deletion, supersession, stale-state handling, and system-of-record
precedence. If free text must be retained, preserve its untrusted integrity
label and never load it into privileged instructions.

## Rendering and active content

The lab HTML-escapes previews. That prevents one class of browser interpretation
but does not make the text safe for a model. Production renderers must consider
HTML, Markdown images, links, SVG, scripts, office macros, PDF actions, hidden
layers, CSS, Unicode controls, OCR text, audio transcripts, and image content.

Use content-type allowlists, safe rendering sandboxes, URL and egress policy,
download isolation, and user-visible provenance. Do not fetch remote images or
links merely because they appear in a model response.

## State of the art and common tools

No single library establishes end-to-end prompt-injection safety. Use tools for
the layer they actually test:

| Tool or method | Useful for | Does not prove |
|---|---|---|
| MCP Python SDK + in-memory `Client` | Real discovery/call/schema behavior in tests | process, network, or model robustness |
| MCP Inspector | Interactive inspection of tools, resources, prompts, schemas, and calls | trusted provenance or safe production policy |
| AgentDojo | Stateful agent utility/security evaluation with tool-return injections | safety for a different toolset, policy, or threat model |
| MCPTox | MCP-specific tool-description poisoning benchmark | immunity to adaptive, persistent, or deployment-specific attacks |
| NVIDIA garak | Broad model/system vulnerability probes including prompt injection | application authorization or forbidden-effect prevention |
| Microsoft PyRIT | Repeatable automated and human-led red-team campaigns | deterministic enforcement at the tool boundary |
| CaMeL-style data/control-flow separation | Fine-grained provenance and policy over agent data flow | automatic support for every real workflow without integration work |
| OPA, Cedar, or application policy code | Deterministic action/resource/target authorization | whether model output is factually correct |

AgentDojo measures formal user utility and attacker goals against environment
state rather than relying only on another model to judge success. MCPTox focuses
on tool-description poisoning and shows that indirect-output attacks and
metadata attacks require distinct corpora. CaMeL is an important research
direction because it extracts trusted control/data flow and enforces policies
outside the underlying model, while openly reporting a utility tradeoff.

Version-pin tools and datasets, store exact scenarios and scorer logic, and
re-run after model, prompt, tool, policy, retrieval, or infrastructure changes.

## Lab walkthrough

`lab.py` provides a complete vertical slice:

| Component | Responsibility |
|---|---|
| `TicketStore` | tenant-bound source records and generic denials |
| `MCPServer` | real `ticket.read` tool with closed structured output |
| `ToolCatalogGate` | full discovery snapshot pin and drift denial |
| `ContentGateway` | schema, tenant, provenance, locator, digest, and size checks |
| `RiskDetector` | fallible review signals with explicit false positive/negative cases |
| `ActionGate` | intent, action, resource, target, evidence, and review policy |
| `ApprovalStore` | exact, expiring, atomic, single-use receipts |
| `EffectExecutor` | one in-memory message effect after approval consumption |
| `MemoryStore` | bounded structured status with provenance |

The scenario proves:

- a reviewed tool catalog is usable;
- a changed description is blocked before invocation;
- poisoned ticket text remains untrusted and is signalled for review;
- direct capability widening and recipient tampering are denied;
- a draft can be useful without being executable;
- altered and replayed approval receipts fail;
- one reviewed safe message produces one effect;
- poisoned free text does not enter durable memory or audit logs; and
- zero forbidden effects complete.

## Evaluation design

Separate component metrics from end-to-end outcomes:

```text
detector recall = detected labelled attacks / labelled attacks
false-positive rate = flagged benign cases / labelled benign cases
safe completion = completed compliant benign tasks / labelled benign tasks
attack success rate = completed attacker goals / labelled attack attempts
forbidden-effect rate = completed forbidden effects / labelled attack attempts
```

A blocked tool call is not the same as a detector true positive. A model refusal
is not proof that a forbidden effect was impossible. A safe system can also be
useless if it blocks every benign task, so report utility beside security.

Evaluation sets should cover:

- direct and indirect injection;
- obvious, paraphrased, encoded, multilingual, typographic, and split payloads;
- HTML, Markdown, SVG, image, audio, OCR, and file metadata;
- poisoned descriptions, schemas, annotations, icons, and changed tool lists;
- legitimate-tool parameter tampering and cross-tool shadowing;
- multi-turn sleeper instructions, summaries, memory, caches, and handoffs;
- wrong tenant, stale source version, bad digest, and absent provenance;
- approval alteration, expiry, replay, concurrency, and policy change;
- detector outage and latency; and
- benign security discussions, quoted attacks, and unusual Unicode.

Keep a held-out adaptive set. A static public corpus can reward memorization.
Review failures by attack family, data source, tool, model, language, modality,
and effect severity.

## Operations and incident response

Useful redacted evidence includes:

- request, trace, intent, proposal, evidence, approval, and effect IDs;
- authenticated principal and tenant where policy permits;
- server identity and complete tool snapshot digest;
- source ID/version/locator and content fingerprint;
- risk signals and detector version;
- action, target fingerprint, decision, and stable reason code;
- policy and artifact version;
- approval state transition; and
- verified terminal effect state.

Avoid raw tickets, prompts, tool descriptions, secrets, recipients, and response
bodies in ordinary logs. Preserve restricted forensic material separately with
access control and retention policy.

Alert on unexpected tool snapshots, new high-privilege tools, repeated target
tampering, cross-tenant evidence, detector drift, approval replays, unusual
content propagation, and discrepancies between policy decisions and downstream
effects.

Containment may require disabling a server or tool, invalidating contract caches,
revoking credentials, quarantining content and derived memory, isolating affected
workloads, preserving evidence, and replaying the adversarial suite before
re-enable.

## Common mistakes

- Calling delimiter tags a security boundary.
- Treating “no injection detected” as “trusted.”
- Asking the same compromised context to judge whether it is compromised.
- Trusting a typed model output because it matches JSON Schema.
- Reviewing only tool names or rendered descriptions.
- Accepting a tool-list change notification as approval.
- Treating `readOnlyHint` or other annotations as enforced behavior.
- Passing all tool results directly into privileged context.
- Letting content select tools, recipients, destinations, scopes, or credentials.
- Using `approved: true` instead of a bound single-use receipt.
- Persisting model summaries as durable trusted memory.
- Reporting classifier recall as end-to-end attack prevention.
- Using model-as-judge alone for whether an external effect occurred.
- Omitting benign cases and therefore hiding a deny-everything defense.
- Presenting an offline simulation as evidence for a production model or network.

## Exercises

### Beginner — classify trust, not prose

Draw the data path for a web search result returned through MCP. Label every
identity, metadata, content, proposal, policy, approval, and effect field as
trusted, untrusted, or derived. Explain what could legitimately change the label.

### Intermediate — schema poisoning

Create a server whose tool name and description are unchanged but whose input
schema adds an optional `recipient` or `url`. Prove the complete snapshot changes
and no handler executes before re-review.

### Intermediate — detector outage

Add timeout/error behavior to the detector. Define which operations may continue
as non-executable drafts and which fail closed. Measure safe completion and
forbidden effects separately.

### Advanced — labelled data flow

Attach confidentiality and integrity labels to every content value. Deny a send
when sensitive Acme data flows to an unapproved recipient, even if the action and
tool are otherwise allowed. Include transformations, summaries, and joins.

### Advanced — adaptive evaluation

Integrate a version-pinned AgentDojo, garak, or PyRIT campaign with a local test
adapter. Store exact model/deployment configuration, dataset revision, seeds,
scorer, costs, and outcomes. Do not require credentials for the canonical course
path.

### Enterprise — response and recovery drill

Model a tool-description rug pull in production. Specify discovery cache
invalidation, kill switch, credential revocation, derived-memory quarantine,
forensic evidence, rollback, user notification, and re-enable gates.

## Reflection

1. Why can a schema-valid proposal still be unauthorized?
2. Which parts of an MCP tool definition require review and pinning?
3. What does a negative detector result actually establish?
4. How can a system preserve useful drafting when evidence is suspicious?
5. Which exact fields must an approval receipt bind?
6. How would you prevent one poisoned summary from contaminating multiple agents?
7. What outcome evidence distinguishes a blocked attempt from a forbidden effect?
8. Which lab claims are deterministic application proofs rather than model-quality
   or production-deployment claims?

## Authoritative and primary references

- [MCP 2026-07-28 tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — discovery, schemas, untrusted annotations, human confirmation, result validation, and audit guidance.
- [MCP security best practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices) — current protocol security guidance.
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) — direct/indirect injection, multimodal risks, and layered mitigation.
- [NIST AI 100-2 E2025: Adversarial Machine Learning](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) — attack terminology, lifecycle, goals, and mitigations.
- [AgentDojo, NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf) and [project](https://agentdojo.spylab.ai/) — stateful utility/security benchmark.
- [MCPTox, AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/download/40895/44856) — empirical MCP tool-poisoning benchmark.
- [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/abs/2503.18813) and [reference implementation](https://github.com/google-research/camel-prompt-injection) — capability and data/control-flow enforcement.
- [NVIDIA garak](https://github.com/NVIDIA/garak) — open-source generative-AI vulnerability scanner.
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT) — automated and human-led AI red teaming.
- [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) — official interactive server inspection and debugging tool.

## Completion checklist

- [ ] Server identity and the complete tool contract are reviewed and pinned.
- [ ] Changed descriptions, schemas, annotations, icons, and tool sets invalidate review.
- [ ] MCP inputs expose opaque business IDs, not identity or effect authority.
- [ ] Tool results are schema-, tenant-, provenance-, version-, digest-, and size-checked.
- [ ] External content remains labelled untrusted through transformations.
- [ ] Detection raises a signal but cannot grant authorization.
- [ ] Trusted intent binds action, resource, target, purpose, and limits.
- [ ] Every proposed effect is independently authorized.
- [ ] Sensitive effects require exact, expiring, single-use approval.
- [ ] Receipt consumption is atomic and effect outcomes are verified.
- [ ] Memory persists only authorized, provenance-bound state.
- [ ] Active rendering is sandboxed and outbound fetches follow egress policy.
- [ ] Evaluation includes adaptive attacks and representative benign cases.
- [ ] Detector, utility, attack, and forbidden-effect metrics have clear denominators.
- [ ] Logs are correlated and redacted.
- [ ] Kill switch, revocation, quarantine, rollback, and re-enable are rehearsed.
