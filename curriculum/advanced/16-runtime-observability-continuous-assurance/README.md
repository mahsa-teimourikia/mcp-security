# MCP Runtime Observability and Continuous Assurance

Runtime observability makes security decisions, effects, and failures explainable.
Continuous assurance uses that evidence to test whether the deployed MCP system
still satisfies its reviewed security invariants. This course builds both without
turning telemetry into a new source of authority or sensitive-data exposure.

## Course thesis

An alert is not a control and a trace is not authorization. The model, server,
and telemetry payload can report what they claim happened; only trusted
application policy and independently observed effects can establish what was
allowed and what actually happened.

```text
model / MCP server -> proposes actions and emits untrusted observations
trusted host       -> validates, authorizes, executes, and records effects
collector          -> authenticates, validates, redacts, and stores evidence
assurance engine   -> evaluates versioned rules over correlated evidence
control plane      -> applies bounded review, quarantine, or revocation
```

The lab's most important invariant is:

> Observability may reduce authority, request review, or preserve evidence. It
> never grants authority, widens a scope, or substitutes for an inline policy
> decision.

Level: advanced. Complete Courses 1–15 first, especially authentication,
authorization, sandboxing, supply-chain assurance, testing, and red teaming.

## Learning objectives

You will learn to:

1. distinguish logs, metrics, traces, span events, security events, and audit
   records by the claims they can support;
2. propagate W3C trace context through MCP without trusting caller-controlled
   context as identity or authorization;
3. design a bounded, privacy-preserving security-event schema with stable
   correlation, artifact, contract, policy, principal, tenant, and destination
   identifiers;
4. authenticate emitters, verify event integrity and sequence, reject replay and
   stale evidence, and monitor the telemetry pipeline itself;
5. reconstruct a tool-call lifecycle and verify request, policy, effect, and
   result invariants independently of model or server prose;
6. use deterministic rules before anomaly models, then calibrate and monitor any
   statistical detector as a fallible measurement system;
7. connect signals to bounded review, quarantine, and revocation actions through
   a separate trusted control plane;
8. measure precision, recall, false-review rate, trace completeness, event
   rejection, safe-task completion, detection delay, and uncertainty; and
9. select OpenTelemetry, collectors, backends, security schemas, and SIEM tools
   by architectural need rather than brand familiarity.

## 1. What each signal can prove

| Signal | Best use | It does not prove |
|---|---|---|
| log | detailed discrete diagnostic record | end-to-end causality by itself |
| metric | bounded aggregate, rate, latency, saturation, SLO | which exact request caused an effect |
| trace | causal path and timing across components | that reported attributes are truthful |
| span event | significant occurrence inside a span | durable security/audit retention |
| security event | normalized policy, integrity, or effect evidence | prevention unless coupled to a control |
| audit record | durable accountable decision/effect history | real-time detection by itself |

One observation may be exported in several forms, but each representation needs a
declared purpose. High-cardinality identifiers belong in traces or logs, not
unbounded metric labels. Audit evidence normally requires stronger retention,
access, immutability, and review controls than debugging telemetry.

### Evidence is not authority

A `traceparent`, span attribute, log field, alert label, or server-reported
`principal_id` is data. It cannot authenticate the caller. Bind telemetry to the
identity and policy result established by the trusted application. Keep the
authorization path fail-closed even when the collector, backend, or dashboard is
unavailable.

## 2. MCP and trace context

The MCP 2026-07-28 revision reserves `_meta` keys for `traceparent`, `tracestate`,
and `baggage`. W3C Trace Context defines the wire format and propagation model.
The Python MCP SDK can automatically create client and server spans when an
OpenTelemetry SDK is configured.

Propagation is useful, but the boundary remains adversarial:

- validate `traceparent` syntax and reject malformed values;
- create a new trace or link rather than blindly accepting context from an
  untrusted external caller when trust domains change;
- never derive principal, tenant, role, approval, or policy outcome from baggage;
- allowlist baggage keys, lengths, and destinations because baggage propagates
  beyond the service where it entered;
- avoid putting customer content, tokens, prompts, reasoning, or credentials in
  trace state or baggage; and
- record the negotiated protocol and stable method/tool identifiers separately
  from user-controlled display text.

The lab creates a valid W3C `traceparent` from a real in-memory OpenTelemetry
trace. It demonstrates propagation shape, not network transport security.

## 3. Reference architecture

```text
MCP host / trusted policy point             MCP server / effect adapter
  request span + policy event  ---------->  server span + bounded attributes
        |                                              |
        +---------------- OTLP -------------------------+
                               |
                     local or gateway collector
                 authenticate -> validate -> redact
                    route -> batch -> retry -> export
                      /                       \
              trace/metrics backend        security lake / SIEM
                      \                       /
                       assurance evaluation
                              |
                 signed, bounded control request
                              |
                separate trusted control plane
             review | quarantine | revoke | rollback
```

Instrument the trusted host and effect adapter first. Server self-reporting is
useful supporting evidence, but cannot be the sole source for a claim about a
forbidden write, disclosure, approval, or policy decision.

Run an OpenTelemetry Collector close to workloads when practical. It centralizes
authentication, TLS, resource enrichment, redaction, batching, routing, sampling,
and backend credentials. Treat its configuration, extensions, and exporters as
production code. Bind administrative endpoints narrowly, use least-privilege
credentials, patch promptly, and isolate tenants and environments.

Keep the detection-to-control path separate from ordinary telemetry transport.
An alert payload must not directly mutate authorization state. A trusted adapter
validates the rule version, target, requested reduction, freshness, replay status,
and operator requirements before invoking the control plane.

## 4. A security-event contract

The lab uses `mcp.security.event/1.0`. A production schema needs ownership,
compatibility rules, validation, examples, and migration tests.

| Field group | Examples | Security purpose |
|---|---|---|
| envelope | schema version, event ID, timestamp, emitter | validation and provenance |
| correlation | trace ID, span ID, parent span ID, operation ID | causal reconstruction |
| trusted context | pseudonymous principal/tenant, session, environment | scoped investigation |
| reviewed identity | server artifact digest, contract digest, protocol version | drift detection |
| action | phase, method/tool, argument digest, destination digest | exact operation binding |
| policy | policy version, decision, reason code, approval fingerprint | decision accountability |
| outcome | effect/result state, error class, duration, resource use | independent verification |
| integrity | sequence, previous hash, event hash, signature | tamper/gap/replay evidence |

### Stable identifiers and pseudonyms

Use an HMAC or equivalent keyed construction for pseudonymous identifiers when
plain identity is unnecessary. A raw hash of an email or small tenant namespace
is vulnerable to enumeration. Rotate keys under a documented strategy and keep
the re-identification mapping tightly controlled.

Argument and destination digests support equality and exact-binding checks; they
do not make low-entropy values anonymous. Domain separation, keyed digests, and
data classification still matter. Keep raw content in a separately governed
evidence store only when a documented incident or legal requirement justifies it.

### Safe-by-default content policy

Do not export by default:

- bearer tokens, cookies, API keys, authorization headers, or session secrets;
- complete prompts, ticket bodies, files, tool outputs, or customer records;
- hidden model reasoning or chain-of-thought;
- arbitrary exception objects, request headers, URLs, or query strings; or
- unrestricted baggage and high-cardinality metric labels.

Prefer schemas with explicit safe fields over generic `attributes: object` bags.
The lab recursively rejects secret-bearing argument key names, stores only a
canonical argument digest, caps field and event size, and hashes destinations.

## 5. Integrity, authenticity, and availability

TLS protects a connection, not an event after ingestion. For security-relevant
evidence, consider all of the following:

1. authenticate workload or collector identity with workload credentials or
   mutually authenticated transport;
2. validate a strict schema, types, enumerations, sizes, timestamps, and IDs;
3. sign or MAC canonical event bytes with a key bound to the emitter;
4. reject duplicate event IDs and enforce an acceptable time window;
5. chain sequence numbers and prior-event hashes per emitter to expose gaps and
   reordering;
6. use append-oriented, access-controlled storage with retention and deletion
   policy; and
7. monitor queue depth, rejected records, dropped spans, exporter failures,
   clock skew, configuration changes, and ingestion lag.

A hash chain does not prove that an emitter reported every real-world action. It
only exposes missing or altered records within the chain you received. Compare it
with independent effect ledgers, datastore change streams, egress sinks, identity
logs, and infrastructure evidence.

When the pipeline is unavailable, choose behavior by control criticality. An
inline authorization decision should remain locally enforceable. A mandatory
audit event may require a bounded local spool or fail-closed behavior for selected
high-risk effects. Document the capacity, retry, overflow, and recovery semantics.

## 6. Reconstruct the lifecycle

The lab models four phases:

```text
request -> policy -> effect? -> result
```

The verifier checks:

- exactly one request, policy, and result event;
- at most one effect for this simplified operation;
- causal order and correct parent relationships;
- stable trace, operation, identity, server, contract, tool, and argument digest;
- no effect after `DENY`;
- an `ALLOW` with a completed effect must end in a completed result;
- an expected write cannot claim completion with no effect; and
- a denial cannot be reported as successful execution.

Production systems may have fan-out, retries, streaming, compensation, and
asynchronous completion. Extend the state machine explicitly. Use a stable
idempotency or operation ID to correlate retries; do not mistake repeated delivery
for repeated effect. Represent unknown outcomes and reconciliation instead of
guessing that a timeout was safe.

## 7. Deterministic assurance before anomaly detection

Start with invariants that have an objective expected result:

- deployed artifact digest differs from the reviewed digest;
- advertised contract digest differs from the approved snapshot;
- a write targets an unapproved destination;
- an effect follows a policy denial;
- required lifecycle evidence is missing or contradictory;
- an event fails authentication, schema, replay, or chain validation; or
- repeated denials cross a versioned operational threshold.

These rules are explainable, reproducible, and testable. The lab maps them to
bounded actions:

| Signal | Default lab action | Rationale |
|---|---|---|
| artifact or contract drift | quarantine server | reviewed identity changed |
| unapproved egress or effect after deny | revoke operation/session | forbidden effect path |
| trace gap | review; revoke if effect safety is unknown | evidence is insufficient |
| invalid signed/chained event | quarantine emitter | evidence source is untrusted |
| repeated clean denials | review | suspicious pattern, not proof of compromise |

### Statistical and model-based detectors

Use anomaly models only when a deterministic rule cannot express the behavior.
Define a labelled population, feature provenance, training window, tenant and
seasonality handling, update cadence, and rollback. Prevent target-controlled
content from injecting instructions into a model-based detector or grader.

Before an anomaly detector changes production state:

- evaluate precision, recall, false-review/block rate, and safe-task completion;
- stratify by tenant, tool, risk class, workload version, and traffic regime;
- use a shadow period and compare against deterministic baselines;
- calibrate thresholds on held-out and incident-derived cases;
- require human confirmation for ambiguous or high-blast-radius actions;
- monitor data, label, feature, threshold, and model drift; and
- version the detector, features, data snapshot, policy, and action mapping.

Anomaly scores never create permission. The safest automated response is usually
a reversible reduction of authority with a short expiry and a documented appeal
or recovery path.

## 8. Sampling and cardinality

Sampling changes the claim. A 1% trace sample cannot prove that no forbidden
effect occurred in the other 99%.

- retain mandatory policy, approval, denial, revocation, artifact-change, and
  consequential-effect events independently of probabilistic trace sampling;
- use head sampling for predictable cost and tail sampling for complete error,
  high-risk, or anomalous traces;
- remember that tail sampling needs buffering, consistent routing, and enough
  capacity to see the full decision window;
- aggregate metrics over bounded dimensions such as environment, decision, risk
  class, and reason code; and
- keep trace IDs, operation IDs, raw users, and arguments out of metric labels.

Record the sampling policy with the evidence. If a collector drops data due to
capacity, expose that loss as an explicit reliability signal.

## 9. Evaluation and service objectives

Let `TP` be correctly signalled unsafe scenarios, `FP` safe scenarios incorrectly
signalled, `TN` safe scenarios left alone, and `FN` unsafe scenarios missed.

```text
precision         = TP / (TP + FP)
recall            = TP / (TP + FN)
false review rate = FP / (FP + TN)
```

Also measure:

- safe-task completion over labelled valid tasks;
- trace completeness over scenarios requiring a complete lifecycle;
- authenticated-event rejection rate by cause and emitter;
- event time, observed time, decision time, and control-application time;
- mean plus percentile time to detect, contain, revoke, and recover;
- uncorrelated event, orphan span, queue lag, and dropped-record rates; and
- uncertainty intervals and sample counts beside proportions.

Define the unit and denominator before collecting results. A low alert count can
mean safety, missing telemetry, broken labels, sampling, or an outage. The lab
uses Wilson intervals and named SLO comparators so a threshold cannot silently
invert from “at least” to “at most.” Its fixtures are illustrative, not a claim
about production performance.

## 10. Operations and incident response

Every actionable signal needs an owner and runbook. A practical runbook answers:

1. What exact rule, evidence, and version produced the signal?
2. Which sessions, tenants, tools, artifacts, contracts, identities, and
   destinations are in scope?
3. Is there independent evidence of a completed effect?
4. Which reversible containment action is authorized now?
5. How will credentials, approvals, caches, and delegated authority be revoked?
6. What evidence must be preserved, redacted, access-controlled, or placed on
   legal hold?
7. How is an unknown effect reconciled?
8. What known-good digest and tested procedure support rollback?
9. What criteria permit recovery, re-enablement, and post-incident monitoring?
10. Which regression, detector, control, and threat model must change afterward?

Test telemetry-loss, collector compromise, forged and replayed events, clock
skew, queue saturation, backend outage, control-plane outage, credential
revocation, quarantine, rollback, and recovery. A dashboard screenshot is not a
recovery exercise.

## 11. Tools and where they fit

| Tool or standard | Appropriate role | Caveat |
|---|---|---|
| OpenTelemetry API/SDK | vendor-neutral instrumentation and context | semantic conventions evolve; pin and test fields |
| OTLP | transport between instrumented apps, collectors, backends | authenticate, encrypt, bound, and validate |
| OpenTelemetry Collector | process, redact, sample, route, and export | privileged evidence plane requiring hardening |
| Prometheus | aggregate numeric service/security metrics | avoid secrets and unbounded labels |
| Grafana | dashboards and alert presentation | visualization is not source-of-truth enforcement |
| Jaeger / Grafana Tempo | distributed trace storage and exploration | retention and search architecture differ |
| Elastic / OpenSearch / Splunk / cloud SIEM | search, correlation, cases, SOC workflows | normalize fields and govern cost/access |
| OCSF | cross-product security event normalization | map without discarding source semantics |
| OWASP Agent Observability Standard | emerging agent-security event vocabulary | working draft; version and validate mappings |
| MCP Python SDK instrumentation | protocol-aware spans and MCP attributes | SDK telemetry is supporting, not independent evidence |

OpenTelemetry's GenAI and MCP semantic conventions are valuable alignment points,
but some portions may be marked development. Pin the convention version, keep a
stable internal security schema, and test mappings before changing a production
contract.

## 12. Lab: observe → verify → detect → control

From the repository root:

```bash
uv sync --extra contributor
uv run python curriculum/advanced/16-runtime-observability-continuous-assurance/lab.py
uv run pytest -q tests/test_course_16_runtime_assurance.py
```

The lab is credential-free and performs no network export. It includes:

- a realistic multi-tenant support workflow with read and message tools;
- privacy-preserving, size-bounded event emission;
- authenticated ingestion, replay/time/schema checks, and event hash chaining;
- lifecycle reconstruction with effect-after-deny and missing-event detection;
- artifact drift, contract drift, egress, denial, and telemetry integrity rules;
- a bounded control plane that can review, quarantine, or revoke but not grant;
- labelled benign and adversarial scenarios with confusion-matrix metrics;
- explicit SLO direction, safe-task completion, and a Wilson interval; and
- a real in-memory OpenTelemetry SDK trace with valid parent relationships and
  W3C `traceparent` generation.

The keys and identities are deterministic training fixtures. Production systems
must use managed workload identity and keys, rotation, authenticated transport,
durable storage, and an independently administered control plane.

### Guided exercises

1. Run the lab and explain why `clean-denial` is a true negative rather than a
   successful attack or missed signal.
2. Inspect a request event and verify that neither recipient nor body is exported.
   Explain why an unkeyed digest may still leak a low-entropy destination.
3. Change one signed field after emission. Confirm that ingestion rejects it
   before assurance evaluation.
4. Remove the policy event from a write trace. Compare review-only handling with
   the stricter response when an effect's safety becomes unknown.
5. Add an approval fingerprint invariant for `support.message.send` and tests for
   mutation, expiry, cross-tenant reuse, and replay.
6. Add a bounded telemetry spool with overflow behavior. Test collector outage,
   recovery, duplicates, reordering, and chain continuity.
7. Replace one deterministic rule with a toy anomaly score. Build labelled train,
   calibration, and held-out sets; report whether it improves on the rule without
   harming safe-task completion.

### Production upgrade checklist

- instrument the trusted authorization and effect boundaries;
- publish an owned, versioned schema and data-classification register;
- use workload identity, authenticated OTLP, managed keys, and rotation;
- configure collector redaction, field allowlists, quotas, retries, and isolation;
- route durable security events separately from sampled diagnostic traces;
- add independent effect sources and unknown-outcome reconciliation;
- define retention, residency, deletion, legal hold, and role-based access;
- test alerts, bounded actions, expiry, recovery, false positives, and appeals;
- maintain labelled evaluations and SLOs by risk stratum; and
- rehearse pipeline failure, containment, rollback, and evidence preservation.

## 13. Review questions

1. Why can a valid `traceparent` correlate a request but not authenticate it?
2. Which fields should be metrics, trace attributes, durable security events, or
   excluded entirely in your system?
3. What independent source proves each consequential effect?
4. Which events must survive sampling and collector loss?
5. How does the assurance engine know the deployed artifact and contract are the
   reviewed ones?
6. What action follows missing evidence, and when is fail-closed justified?
7. Can an alert payload directly quarantine a server? What trusted checks mediate
   the action?
8. How will you measure detector utility without rewarding a system that blocks
   every valid task?

## References

Checked 2026-10-04. Prefer the linked specifications and official project
documentation over screenshots or vendor blog summaries.

- [MCP specification: basic concepts and metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic)
- [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP Python SDK: OpenTelemetry](https://py.sdk.modelcontextprotocol.io/run/opentelemetry/)
- [W3C Trace Context Recommendation](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry specification](https://opentelemetry.io/docs/specs/otel/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [OpenTelemetry Collector security guidance](https://opentelemetry.io/docs/security/)
- [OpenTelemetry Collector configuration](https://opentelemetry.io/docs/collector/configuration/)
- [OpenTelemetry Collector internal telemetry](https://opentelemetry.io/docs/collector/internal-telemetry/)
- [OpenTelemetry sampling concepts](https://opentelemetry.io/docs/concepts/sampling/)
- [OWASP Agent Observability Standard](https://owasp.org/www-project-agent-observability-standard/)
- [OWASP AOS event reference](https://aos.owasp.org/spec/trace/events/)
- [NIST SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [OCSF schema](https://schema.ocsf.io/)
- [Prometheus instrumentation practices](https://prometheus.io/docs/practices/instrumentation/)
