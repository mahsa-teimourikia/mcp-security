# MCP Threat Hunting and Runtime Anomaly Detection

Threat hunting is a scoped, hypothesis-led investigation of available evidence
to discover behavior that existing controls or detections may have missed.
Runtime anomaly detection ranks observations that differ from a defined
baseline. Neither activity proves maliciousness, grants authority, or permits
containment.

The governing invariant is:

> A model or detector may propose a hypothesis, feature, score, or finding.
> Trusted application code authorizes evidence access, validates provenance and
> data quality, executes bounded queries, preserves cited evidence, records an
> analyst disposition, and separately governs detection promotion or response.

Course 27 built the authenticated telemetry-to-SOC path and production alert
workflow. Course 28 starts from that governed evidence plane and asks a
different question: how can defenders systematically search for unknown,
low-and-slow, sequence, peer, and graph deviations without turning rarity into
guilt or a score into policy?

## Learning objectives

By the end of the course, you should be able to:

1. write a versioned, falsifiable MCP hunt hypothesis with exact scope, data
   requirements, exclusions, validation steps, adversary references, and exit
   or promotion criteria;
2. authorize tenant, time, and event-kind evidence access before filtering or
   analytics, without treating a role name or query text as authority;
3. measure source coverage, required-field completeness, duplicate/conflict
   rates, freshness, ingest delay, and clock quality before interpreting an
   empty result;
4. implement deterministic invariant hunts for artifact, capability, network,
   tenant, and delegation drift;
5. use robust univariate statistics, peer grouping, low-and-slow windows,
   operation sequences, and authority/egress graphs with explicit assumptions;
6. choose among rules, Sigma correlations, SQL/SPL/KQL/PPL/EQL queries,
   scikit-learn, PyOD, streaming detectors, and SIEM-native anomaly tools based
   on the data and operational question;
7. preserve exact evidence IDs, baseline identity/version, score, threshold,
   method, and uncertainty in each candidate finding;
8. keep analyst disposition separate from peer-reviewed detection promotion and
   keep both separate from containment authority; and
9. evaluate hunts on labelled episodes using precision, recall, time to finding,
   findings per event population, and analyst effort with disclosed
   denominators.

## Prerequisites and execution

Complete Course 16, Course 21, and Course 27 or be comfortable with runtime
telemetry, incident evidence, SOC operations, and authorization boundaries.
From the repository root:

```bash
uv sync --locked --extra contributor
uv run --frozen python curriculum/advanced/28-mcp-threat-hunting-runtime-anomaly-detection/lab.py
uv run --frozen pytest -q tests/test_course_28_threat_hunting.py
```

The lab is offline and credential-free. It uses the repository's pinned
`cryptography` implementation for exact hunt and review receipts, Python's
`statistics` module for a transparent median-absolute-deviation baseline, and
NetworkX for real graph construction. It does not query a production SIEM,
train a black-box model, open an incident, or execute containment.

## State of practice reviewed 31 October 2026

### ATT&CK detection strategies and analytics

MITRE ATT&CK v20, released on 13 October 2026, is the current ATT&CK version. It
expands coverage of recent adversary activity and adds AI-focused and
AI-enabled Enterprise techniques, including direct and indirect prompt
injection, AI-result poisoning, AI-enabled exfiltration, and impairment of
autonomous defenses. The earlier v18 defensive-model change replaced
technique-page detections with **Detection Strategies** and platform-specific
**Analytics**, substantially updated Data Components, and deprecated the older
Data Sources catalogue.
Detection strategies organize a high-level defensive method; analytics express
implementation logic for a particular platform. Use current strategy and
analytics objects when mapping hunt coverage. Do not treat an ATT&CK reference
as a runnable query, working sensor, or effectiveness result.

MITRE ATLAS complements ATT&CK with adversary tactics and techniques for AI
systems. MCP hunts often span both: a suspicious tool invocation can involve
ordinary credential, network, persistence, and exfiltration behavior plus
AI-specific prompt, model, data, or agent manipulation. Map only behavior that
the cited evidence supports.

### Portable and backend-native detection content

Sigma 2.1.0 includes correlation-rule forms such as event count, value count,
temporal ordering, and metric correlations. Sigma improves source review and
portability; compiled backend queries still require tests for field mapping,
case behavior, arrays, nulls, ordering, windows, cardinality, and late arrival.

Common production query environments include:

- Splunk SPL and Enterprise Security;
- Microsoft Sentinel KQL;
- Elastic Query DSL, EQL, ES|QL, and Security/ML capabilities;
- OpenSearch Query DSL, PPL, Alerting, and Anomaly Detection;
- Chronicle/Google SecOps YARA-L;
- SQL engines and lakehouse tooling for historical hunts; and
- Sigma source rules compiled through `sigma-cli` or pySigma.

The course keeps its query contract vendor-neutral. A real adapter must
authorize the same scope, pin the target schema and backend, parameterize values
instead of concatenating attacker content, bound time and result size, and
preserve stable evidence identity.

### Statistical and machine-learning libraries

The scikit-learn anomaly-detection guide distinguishes novelty detection from
outlier detection and documents Isolation Forest, Local Outlier Factor,
One-Class SVM, SGD One-Class SVM, and robust covariance approaches. Its own
guidance warns that high-dimensional anomaly detection without distributional
assumptions is difficult and that algorithms have different training and
prediction semantics.

PyOD provides a broad common API across classical, ensemble, deep, time-series,
and graph detectors. Current documentation distinguishes stable and
experimental time-series methods and identifies transductive algorithms that
do not support out-of-sample prediction. Library breadth is not automatic
model selection: benchmark fit, feature validity, labels, leakage, calibration,
operational cost, drift, and explainability remain local responsibilities.

OpenSearch's anomaly detector uses Random Cut Forest on aggregated time-series
features and exposes anomaly grade and confidence. Its documentation calls out
intervals, frequency, window delay, history, shingle size, missing-data
imputation, category cardinality, and the difference between confidence and
accuracy. These are security-relevant choices. A high anomaly grade is still a
signal—not proof and not response authority.

Elastic provides anomaly and outlier detection within its machine-learning
workflow. Other SIEMs and observability platforms offer similar capabilities.
Evaluate the deployed version and licensing, but more importantly validate its
feature/aggregation semantics and operational results on your labelled MCP
population.

### Telemetry semantics

OpenTelemetry's stable Logs Data Model distinguishes source `Timestamp` from
`ObservedTimestamp`, carries trace/span context, and separates resource from
event attributes. Preserve source, observed, and ingest time for hunting. Do
not infer ordering or detection latency from index time alone, and never use
trace baggage as authenticated tenant or principal identity.

## The hunt lifecycle

```text
threat model / incident / intelligence / control gap
                         |
                         v
             versioned falsifiable hypothesis
                         |
                  signed read grant
                         |
                         v
        authorize tenant + time + event kinds first
                         |
                         v
   provenance/schema/coverage/completeness/time-quality gate
                         |
             +-----------+------------+
             |                        |
         not ready                  ready
     report visibility gap      run bounded methods
                                      |
             deterministic / robust / sequence / graph
                                      |
                                      v
                     evidence-linked candidate finding
                                      |
                         analyst validation/disposition
                                      |
                 +--------------------+------------------+
                 |                    |                  |
              benign            inconclusive         supported
                                                        |
                                      peer-reviewed detection proposal
                                                        |
                                             test -> evaluate -> active

Containment is a separate incident-response authorization path.
```

An empty query can mean no adversary activity, missing source coverage, broken
parsing, wrong tenant, wrong window, lagging ingestion, stale schema, or a bad
hypothesis. The readiness gate prevents these from collapsing into “clean.”

## 1. Start with a falsifiable hypothesis

A useful hypothesis is neither “look for weird things” nor a guaranteed
conclusion. It states a behavior that could be supported or falsified by named
evidence.

The lab's `HuntHypothesis` contains:

- stable hypothesis ID and version;
- concise title, falsifiable statement, and rationale;
- accountable owner;
- exact tenant set and half-open event-time window;
- required source IDs and event-contract fields;
- one or more named methods;
- documented exclusions;
- analyst validation steps;
- current ATT&CK/ATLAS references; and
- explicit criteria for proposing a durable detection.

Example:

> A reviewed support server may execute an unapproved artifact, capability,
> destination, delegation, or authority path that is absent from current alert
> logic.

This can be falsified for the scoped period only when the required gateway and
network sources are available, complete enough, authentic, and queryable. It
does not establish that the system has never exhibited the behavior.

### Sources of hypotheses

- threat-model paths and residual risk;
- a new ATT&CK detection strategy or ATLAS technique;
- incident findings and forensic timelines;
- red-team or security-test counterexamples;
- new vulnerability, supplier, artifact, or credential intelligence;
- unexplained policy denials or telemetry gaps;
- control-plane, capability, or deployment change;
- a detection coverage or false-negative review; and
- analyst observations that can be converted into testable behavior.

LLMs can help summarize evidence or draft a query proposal, but their output
remains untrusted. They must not invent event fields, infer missing labels,
expand scope, suppress evidence, decide maliciousness, or activate a rule.

## 2. Authorize evidence access before analytics

Threat hunters often have powerful access to cross-system data. “Hunter” as a
role string does not grant that authority. The lab's `HuntAuthority` issues a
signed grant that binds:

- hunter identity and approved role;
- purpose `mcp_threat_hunt_read`;
- exact tenant and event-kind scope;
- exact query window;
- current hunt-policy version;
- issuance and expiry; and
- an Ed25519 signature over the complete grant.

The `EvidencePreparer` verifies the grant and proves that the hypothesis tenant
and time scope are subsets before examining eligible evidence. The maximum
query window is 30 days and the maximum grant lifetime is eight hours in the
lab. Production values are organization policy, but they must be explicit and
bounded.

Authorization for reading telemetry does **not** authorize case creation,
credential revocation, server disablement, network blocking, or detection
activation.

## 3. Gate on evidence and data readiness

`EvidencePreparer.prepare()` performs this sequence:

1. verify the signed grant, purpose, policy, and current validity;
2. validate the hypothesis contract;
3. prove hypothesis tenant and time are within the grant;
4. discard out-of-grant tenant, event-kind, and time records before analytics;
5. resolve the event source contract and its permitted tenant/kind scope;
6. require the current event schema, artifact digest, and trace syntax;
7. recompute and compare the evidence digest;
8. require every hypothesis field;
9. deduplicate exact event ID/digest pairs and reject conflicting reuse;
10. validate source/observed/ingest clock relationships;
11. record late events rather than silently hiding them; and
12. calculate source coverage, field completeness, invalid evidence, duplicate
    count, late-event rate, and clock-error rate.

The strict lab blocks hunts when there are no usable events, required source
coverage is incomplete, required-field completeness is below threshold,
invalid evidence exists, or clock relationships are implausible. Exact
duplicates and bounded ingest delay are measured but do not automatically block
the hunt.

Production systems should also measure:

- expected versus observed event volume by source/tenant/kind;
- sensor heartbeat and last-seen age;
- parser/schema rejection and unmapped-field rates;
- sampling and tail-loss policy;
- queue lag, index refresh, and searchable-time delay;
- sequence gaps and producer restarts;
- retention and tier availability;
- query errors, timeouts, truncation, and result limits; and
- privacy/access-policy exclusions.

Never impute identity, tenant, artifact, policy outcome, or completed effect.
For statistical features, document whether a missing bucket means zero, unknown,
delayed, or inapplicable. These meanings are not interchangeable.

## 4. Prefer deterministic invariants when policy already knows the answer

Do not use machine learning to rediscover an allowlist. `invariant_hunt()`
compares runtime evidence with trusted reviewed state and flags:

- artifact digest drift;
- capability-contract version drift;
- network effects to destinations outside the server allowlist;
- authenticated tenant versus resource-tenant disagreement; and
- delegation depth beyond the reviewed bound.

These are high-confidence mismatches because the expected value is explicit.
They still require analyst validation: inventory could be stale, an emergency
change might be valid, or a source may be compromised. The finding cites the
exact event and reason rather than emitting a generic anomaly score.

Useful deterministic hunt families include:

- unknown artifact, signing identity, publisher, or provenance subject;
- unreviewed MCP tool/resource/prompt schema or annotation;
- new destination, protocol, port, audience, scope, or resource type;
- policy `deny` followed by observed effect;
- approval, receipt, or operation ID reuse;
- cross-tenant principal/resource/result disagreement;
- revoked or inactive workload/credential use;
- missing outcome for a high-impact allowed call;
- impossible lifecycle transitions; and
- control-plane and runtime-state disagreement.

## 5. Use robust baselines with explicit contracts

An anomaly is a deviation from a model of expected behavior. The model must be
identified and governed. The lab's `BaselineContract` binds:

- baseline ID and version;
- exact tenant, server, action, and feature;
- training window that precedes the hunt window;
- training values and minimum sample count;
- reviewed threshold; and
- confirmation that contamination was considered.

### Median absolute deviation

For a value \(x\), median \(m\), and median absolute deviation
\(MAD = median(|x_i-m|)\), the lab uses the conventional modified score:

```text
score = 0.6745 * |x - median| / MAD
```

The score is explainable and robust to a small number of extreme values. The
lab refuses to score when:

- the feature is unsupported or threshold is non-positive;
- there are fewer than five reviewed samples;
- values are negative, non-finite, or otherwise invalid;
- the baseline overlaps the hunt window;
- baseline contamination was not reviewed; or
- MAD is zero, making the ratio undefined.

It does not add an epsilon and fabricate a huge score. A zero-dispersion
population needs an explicitly chosen alternative, such as an exact invariant,
a policy floor, a count model, or a different feature.

### Peer groups and seasonality

Compare like with like. Useful partitions can include tenant tier, server,
tool/action, workload version, region, hour/day, deployment phase, and request
purpose. Too broad a group hides local anomalies; too narrow a group causes
cold start and unstable estimates. Never create peer groups from untrusted
model labels.

For periodic behavior, use calendar-aware or seasonal baselines and prevent
training/test leakage. For streams, define cold-start, update cadence, drift
monitoring, rollback, and how delayed/out-of-order buckets affect state.

### Choosing a common library

| Need | Candidate | Important caveat |
| --- | --- | --- |
| transparent univariate deviation | quantiles, MAD, robust z-score | zero dispersion, sample size, seasonality |
| efficient multivariate outlier | scikit-learn Isolation Forest | contamination/threshold, reproducibility, explanation |
| local peer anomaly | Local Outlier Factor | outlier vs novelty mode and neighbor sensitivity |
| boundary around mostly clean history | One-Class SVM / SGD variant | scaling and hyperparameter sensitivity |
| broad detector comparison | PyOD | detector assumptions, benchmark relevance, optional dependencies |
| streaming time series | River-style online models, OpenSearch RCF, platform-native detectors | state, drift, cold start, late/missing buckets |
| sequence/subsequence | EQL/Sigma temporal, n-grams, Markov models, matrix profile | order, window, transductive semantics |
| graph deviation | NetworkX rules, graph features, graph anomaly models | graph completeness, direction, identity resolution |

Begin with a deterministic or simple robust baseline. Add complexity only when
it improves a labelled operational objective enough to justify feature,
training, deployment, drift, and explanation cost.

## 6. Hunt low-and-slow behavior

Threshold alerts often focus on a burst within five minutes. An adversary can
stay below that threshold for hours. `low_and_slow_hunt()` groups denied policy
events by authenticated tenant, pseudonymous principal, and server; requires a
minimum total count over a minimum span; and requires that no five-minute bucket
exceeds the ordinary burst threshold.

This produces evidence for a distributed probing hypothesis, not a verdict.
Validate client retry policy, automation bugs, credential rotation, deployment
changes, user support activity, and source duplication. Long windows increase
state, cost, and the chance of unrelated joins, so partition and bound them.

Other low-and-slow patterns include:

- many small exports whose cumulative bytes exceed a policy expectation;
- sparse new destinations across multiple server instances;
- repeated prompt-injection signals separated below an alert window;
- gradual delegation-depth or scope growth;
- use of many resources under one operation purpose; and
- alternating failures and successes designed to blend with baseline noise.

## 7. Hunt operation sequences

Individual steps can be allowed while their order is novel or unsafe. The lab
groups events by authenticated tenant and stable operation ID, sorts by event
time and event ID, and compares typed `kind:action:outcome` sequences with a
reviewed set.

Examples:

- read -> export -> unapproved network effect;
- denial -> retry under different credential -> success;
- approval -> proposal mutation -> effect;
- resource effect before policy decision;
- tool call with no downstream outcome; and
- repeated cross-server handoff followed by privileged action.

Sequence novelty is low-confidence by default. Version changes, source loss,
late events, or a new valid workflow can create novel sequences. Sigma temporal
correlations and EQL-like languages can operationalize reviewed sequences, but
backend order/window semantics need labelled verification.

## 8. Hunt authority and egress graphs

MCP systems compose principals, agents, servers, tools, resources, destinations,
credentials, and approvals. Graphs reveal new edges and reachable paths that
row-by-row queries miss.

The lab uses a real NetworkX directed graph per authenticated tenant:

```text
principal -> MCP server -> destination
```

It compares observed edges with a reviewed graph and emits one finding per
unexpected edge with the exact supporting event IDs. Tenant graphs are never
merged.

Production graph hunts can add:

- host/agent -> server capability edges;
- server -> credential/audience/scope edges;
- delegation parent -> child edges;
- tool -> resource tenant and classification edges;
- server -> artifact/supplier/provenance edges;
- approval -> proposal -> effect edges; and
- registry/gateway/runtime disagreement edges.

Useful graph questions include new edge, shortest path to a protected resource,
unexpected bridge between communities, fan-out growth, credential sharing,
cycles in delegation, and reachability that exceeds reviewed architecture.

Graph completeness is critical. A missing edge can mean no relationship or a
missing sensor. Do not call a path safe when required nodes or source planes are
absent.

## 9. Preserve candidate-finding provenance

Every `HuntFinding` stores:

- stable finding ID;
- hypothesis ID and version;
- method;
- tenant and investigated entity;
- exact evidence event IDs and digest of evidence digests;
- reason codes;
- score and threshold when applicable;
- baseline ID/version when applicable;
- creation time and stated confidence; and
- application-owned disposition state.

`finding()` rejects empty evidence and cross-tenant evidence. A score without a
baseline, threshold, population, method, and evidence is not actionable.
Confidence is an operational category, not a probability of maliciousness.

## 10. Analyst disposition is a governed evidence step

`disposition_finding()` requires a trusted analyst identity, an eligible role,
a terminal disposition, and rationale. It records the original finding digest
and exact evidence IDs.

Supported means the scoped evidence supports the behavioral statement. It does
not prove actor intent or authorize response. Benign means the analyst found a
valid explanation for this case; it should inform exclusions only after review.
Inconclusive preserves uncertainty and should drive evidence improvements or a
revised hunt.

Avoid these shortcuts:

- model-generated “malicious” labels;
- analyst disposition without cited evidence;
- adding a global exclusion from one benign case;
- rewriting the original finding after review;
- treating repeated renderings of one source as independent corroboration; and
- closing an incident because a hunt found no further events.

## 11. Promote supported behavior into a test detection

A successful hunt should improve durable coverage. The lab's
`DetectionCandidate` contains:

- candidate, rule, and version IDs;
- title and source hypothesis;
- supported source-finding IDs;
- query contract;
- required fields;
- window, grouping, and threshold;
- expected false positives;
- labelled validation-dataset ID;
- precision and recall for that dataset; and
- accountable owner.

`DetectionRegistry` requires every cited finding to exist and be analyst-
supported. A peer detection reviewer signs the exact candidate digest for the
purpose `register_detection_test`. The receipt expires, is consumed atomically,
and cannot authorize changed content. The registered state is `test`, not
`active`.

Activation needs a separate lifecycle not implemented by this lab: backend
compilation, target-SIEM labelled replay, performance/cost review, shadow or
test deployment, owner/on-call/runbook confirmation, rollback, monitoring, and
an explicit release decision. Response remains separate again.

## 12. Evaluate hunt value and cost honestly

Use labelled episodes, not isolated rows, when one adversary behavior produces
many events or findings. `hunt_metrics()` reports:

- true positives, false negatives, false positives, and true negatives;
- episode precision and recall;
- median event-time to first finding for detected malicious episodes;
- findings per 1,000 scanned events; and
- analyst minutes per detected malicious episode.

The lab returns `None` when a denominator is absent. It does not turn zero
labels, zero events, or zero supported episodes into a perfect score.

Also measure:

- source/field readiness and query failure rate;
- query runtime, scanned bytes/events, and infrastructure cost;
- candidates per hunt and duplicate-candidate rate;
- benign, supported, and inconclusive disposition rates;
- median and tail time to disposition;
- analyst queue age and minutes per supported finding;
- promoted/test/active detections and post-promotion quality;
- detection overlap and incremental coverage; and
- privacy or access-policy violations.

State the label source, observation window, tenant/product slices, exclusions,
sample size, unit, and aggregation. A hunt that generates hundreds of low-value
findings can have acceptable recall and still be operationally harmful.

## Lab walkthrough

1. `demo_components()` creates source contracts, a signed hunt grant, a complete
   hypothesis, trusted reviewed state, approved sequences, and reviewed graph.
2. Two normalized events represent a valid tool call and successful network
   export to an unapproved destination.
3. `EvidencePreparer` authorizes scope, validates evidence, and proves both
   required sources are present.
4. `invariant_hunt()` finds the destination mismatch.
5. `graph_hunt()` finds the new server-to-destination edge.
6. An analyst dispositions the invariant finding as supported with rationale.
7. A detection candidate cites that supported finding and a labelled fixture.
8. A peer reviewer approves the exact candidate.
9. The registry atomically promotes it only to `test`.
10. Output explicitly reports `containment_authorized: false`.

Expected output resembles:

```json
{"containment_authorized":false,"data_ready":true,"detection_state":"test","disposition":"supported","graph_findings":1,"invariant_findings":1}
```

## Practical exercises

### Exercise 1: falsify the hypothesis

Create a complete, valid dataset with only approved artifact, capability,
destination, tenant, delegation, sequence, and graph edges. Explain what the
empty result establishes—and what it cannot establish about other windows,
tenants, sources, or behaviors.

### Exercise 2: prove a visibility gap

Remove the network source, then tamper with one gateway event. Show that the
readiness gate reports source coverage and invalid evidence instead of a clean
hunt. Design the operational ticket produced by each gap.

### Exercise 3: compare thresholds

Build a labelled bytes-out dataset with seasonal and deployment slices. Compare
MAD with a fixed policy threshold and Isolation Forest. Record training
population, contamination assumption, seed, threshold selection, precision,
recall, workload, and explanations. Do not select the final threshold using the
test labels.

### Exercise 4: model drift and cold start

Simulate a reviewed server release that changes normal export volume. Define
how baselines are versioned, when retraining is permitted, how old/new models
overlap, how a rollback works, and which labels reveal poisoning.

### Exercise 5: compile a temporal rule

Express a denial -> credential change -> success sequence in Sigma correlation
or a target backend temporal language. Compile or deploy it in test, replay
ordered, late, missing, duplicate, and cross-tenant fixtures, and compare the
result with the Python oracle.

### Exercise 6: extend the graph

Add credential/audience/scope and resource-tenant nodes. Hunt for one credential
shared by multiple servers and a path from a low-trust server to a protected
resource. Prove graphs stay tenant-partitioned.

### Exercise 7: threat-model an LLM hunt assistant

Cover query injection, invented fields, scope widening, raw-secret requests,
evidence suppression, hallucinated citations, fabricated confidence, malicious
log content, unbounded queries, and direct response attempts. Put every control
in trusted application code and preserve the assistant output only as a
proposal.

## Common failure modes

| Failure | Consequence | Correction |
| --- | --- | --- |
| “search for anything unusual” | unfalsifiable, irreproducible work | versioned hypothesis with scope, evidence, exclusions, and exit criteria |
| tenant filter taken from query/model text | cross-tenant disclosure | authorize authenticated tenant scope before query construction |
| empty result treated as clean | false assurance under sensor/parser loss | source/field/time readiness gate |
| index time used as event time | wrong order and latency | preserve source, observed, ingest, and searchable times |
| ML used for an allowlist | needless opacity and error | deterministic inventory/policy comparison |
| baseline includes investigation window | leakage hides anomalies | baseline window must precede hunt window |
| contaminated history assumed normal | adversary behavior becomes baseline | review labels/contamination and keep baseline provenance |
| epsilon added to zero MAD | fabricated extreme scores | return indeterminate and choose a justified method |
| global peer group | dominant tenants hide local deviations | authenticated tenant/entity/time partitions |
| anomaly score called probability | false precision | report method, score, threshold, baseline, and assumptions |
| graph built across tenants | false paths and data leakage | separate graph per authorized tenant |
| finding without evidence IDs | irreproducible triage | exact admitted evidence and digest |
| model dispositions finding | inference becomes authority | trusted analyst role, rationale, evidence-preserving record |
| one benign case creates global exclusion | systematic false negatives | bounded reviewed exclusion with regression fixtures |
| supported hunt activates rule directly | untested production noise or misses | peer review, target validation, test/shadow phase, release gate |
| anomaly triggers containment | detector becomes authority | independent incident authorization and outcome verification |
| alert/finding count called effectiveness | activity mistaken for value | labelled episodes, precision/recall, workload, incremental coverage |

## Production review checklist

### Scope and hypothesis

- [ ] Hypothesis has stable ID/version, owner, rationale, falsifiable statement,
      exact tenant/time scope, methods, exclusions, validation, and exit or
      promotion criteria.
- [ ] ATT&CK/ATLAS references match observed behavior and current framework
      objects.
- [ ] Hunt grant is authenticated, purpose-bound, least-privilege, and short-
      lived.
- [ ] Query templates are parameterized, time-bounded, result-bounded, and
      protected from attacker-controlled syntax.

### Evidence and readiness

- [ ] Event sources, schema versions, producer trust, tenant/kind scope, and
      evidence digests are verified.
- [ ] Required source coverage and field completeness thresholds are explicit.
- [ ] Duplicate, conflict, gap, clock, lag, truncation, and query-failure rates
      are measured.
- [ ] Missing values have documented semantics; identity or effects are never
      imputed.
- [ ] Sampling, retention, privacy, regional, and access-policy blind spots are
      reported with the result.

### Methods and baselines

- [ ] Deterministic policy/inventory checks are preferred where possible.
- [ ] Feature meaning, units, transformations, grouping, window, and threshold
      are versioned.
- [ ] Baseline population precedes evaluation and includes contamination review.
- [ ] Cold start, seasonality, drift, retraining, rollback, and late data are
      tested.
- [ ] Randomized methods pin seeds where supported and report reproducibility
      limits.
- [ ] Sequence and graph methods prove ordering and tenant isolation.

### Findings and analyst workflow

- [ ] Every finding cites admitted same-tenant evidence and its hypothesis,
      method, score/threshold, baseline, reasons, time, and uncertainty.
- [ ] Analyst disposition preserves original evidence and records rationale.
- [ ] Exclusions are bounded, reviewed, expiring where appropriate, and tested.
- [ ] Inconclusive findings drive evidence or hypothesis improvements rather
      than fabricated closure.

### Detection promotion and response boundary

- [ ] Candidate cites supported findings, query contract, fields, grouping,
      window, threshold, false positives, validation dataset, metrics, and owner.
- [ ] Peer-review approval is exact, signed, expiring, and single-use.
- [ ] Registration creates a test rule, not an active rule or containment action.
- [ ] Target-backend replay, performance, cost, shadowing, monitoring, rollback,
      and release approval precede activation.
- [ ] Any response follows independent incident authorization and verifies the
      effect.

### Evaluation

- [ ] Labels, populations, windows, denominators, slices, units, and aggregation
      are disclosed.
- [ ] Precision and recall are reported with false positives and misses.
- [ ] Time to finding uses event time and distinguishes ingest/search delay.
- [ ] Analyst minutes, findings per event population, query cost, and queue delay
      are measured.
- [ ] Promoted detection adds incremental coverage rather than duplicating an
      existing noisy rule.

## Authoritative and official references

- [MITRE ATT&CK October 2026/v20 release](https://attack.mitre.org/resources/updates/updates-october-2026/)
- [MITRE ATT&CK October 2025/v18 defensive changes](https://attack.mitre.org/resources/updates/updates-october-2025/)
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/)
- [MITRE ATT&CK Analytics](https://attack.mitre.org/analytics/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Sigma Correlation Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
- [Sigma documentation and `sigma-cli`](https://sigmahq.io/docs/)
- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry logging specification](https://opentelemetry.io/docs/specs/otel/logs/)
- [OpenSearch Anomaly Detection](https://docs.opensearch.org/latest/observing-your-data/ad/index/)
- [scikit-learn novelty and outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html)
- [PyOD documentation](https://pyod.readthedocs.io/en/latest/)
- [Elastic machine learning overview](https://www.elastic.co/docs/explore-analyze/machine-learning)
- [NetworkX documentation](https://networkx.org/documentation/stable/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OCSF](https://ocsf.io/)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)

## Final perspective

Good threat hunting is not a search box plus intuition, and anomaly detection is
not a machine-generated verdict. A defensible program authorizes access first,
states a falsifiable hypothesis, proves evidence readiness, chooses the simplest
method that answers the question, preserves exact provenance and uncertainty,
requires accountable analyst validation, promotes only reproducible supported
behavior through a detection lifecycle, and measures both security value and
analyst cost.

The boundary remains constant: models and detectors propose; trusted
applications authorize, validate, persist, promote, execute, and verify.
