# Protocol Composition Security: MCP + A2A + Agent Runtimes

An A2A peer, an MCP server, and an agent runtime can each be locally secure
while the application connecting them is unsafe. The adapter is not plumbing:
it is a security-critical policy enforcement point, credential broker, state
machine, error translator, and evidence producer.

This course builds one defensible vertical slice: an authenticated A2A peer
asks a trusted application to read or comment on a support ticket; the
application normalizes the request, exchanges its source grant for a narrower
MCP-audience token, verifies the discovered MCP contract, obtains exact
approval for the write, calls a real MCP server, and checks the final effect.
The runtime proposes. Trusted application code authorizes and executes.

> **Version snapshot (reviewed 2026-10-28):** the lab targets A2A protocol
> `1.0`, MCP `2026-07-28`, the draft MCP Tasks extension dated `2026-07-28`,
> `a2a-sdk` 1.x, and MCP Python SDK 2.2.x. Protocol
> version, SDK version, and product version are different facts. Re-review the
> linked specifications and compatibility policy before a production upgrade.

## Learning objectives

After completing the course, you should be able to:

1. distinguish protocol translation from semantic preservation;
2. keep human subject, acting workload, tenant, audience, action, resource,
   purpose, expiry, approval, policy version, and trace context separate;
3. exchange rather than pass through credentials at a protocol boundary;
4. map A2A skills to a reviewed MCP contract without letting a model select an
   arbitrary tool or arguments;
5. preserve denial, validation, transient, unknown-outcome, and cancellation
   semantics across different lifecycle models;
6. prevent duplicate effects with a stable logical operation ID, durable
   request digest, target-side idempotency, and reconciliation;
7. bind approval to the exact effect and consume it at the effect boundary;
8. propagate W3C trace context as correlation—not authority; and
9. evaluate the composed system with labelled positive, negative, boundary,
   failure, and postcondition tests.

**Prerequisites:** Courses 1, 6–8, 16, and 18; Python 3.11+; OAuth resource
server concepts; and basic familiarity with distributed retries. Allow 90–120
minutes for the reading, notebook, and exercises.

## 1. Composition is a new security system

Serialization compatibility is the easy part. A secure composition must retain
the meaning of every security-relevant fact and must not invent meaning the
source protocol never established.

```text
untrusted agent runtime
        │ proposes task, arguments, operation ID
        ▼
trusted host / A2A client ── authenticated A2A peer + source grant
        │
        ▼
protocol adapter (PEP + STS client + durable operation ledger)
        │  normalize → authorize → exchange → discover/verify → invoke
        ▼
MCP client ── target-audience credential ── MCP resource server
        │                                      │ authorize again
        │                                      ▼
        └──────── evidence / reconcile ── ticket system effect ledger
```

The trust boundary contains application code, not the model. A prompt cannot
prove identity, approve a write, exchange a token, choose a retry policy, or
declare that a remote effect did not occur.

### Composition invariants

For every accepted operation, prove all of the following:

- **identity:** authenticated subject and each acting workload remain explicit;
- **authority:** child authority is no broader than the intersection of parent,
  actor, adapter, target, tenant, and current resource policy;
- **audience:** every credential names the resource that will accept it;
- **intent:** action, resource, purpose, arguments, and consequential effect are
  exact and immutable after approval;
- **lifecycle:** source and target states are not collapsed into “done”;
- **outcome:** the final resource state, not an adapter response, decides whether
  an effect occurred;
- **replay:** the same logical operation cannot create a second effect;
- **cancellation:** cancellation is cooperative and never rewrites history;
- **errors:** a denial cannot become a fallback, retry, or allow; and
- **evidence:** policy, protocol, contract, trace, and effect records join on
  governed identifiers without logging credentials.

## 2. Know the protocols you are composing

| Concern | A2A 1.0 | MCP 2026-07-28 | Composition consequence |
|---|---|---|---|
| Primary unit | `Message`, `Task`, `Part`, `Artifact` | request/response methods such as `tools/list` and `tools/call` | An A2A skill is not automatically an MCP tool. Use an explicit reviewed mapping. |
| Discovery | Agent Card and skills | capability and tool discovery | Discovery describes availability; neither surface grants caller authority. |
| Long-running work | Task lifecycle and task events | base requests plus the MCP Tasks extension when negotiated | Do not claim task parity unless the extension and mapping are explicitly supported. |
| Success | terminal task `completed` | successful JSON-RPC result; a tool result can still carry `isError` | Preserve protocol success separately from domain/business success. |
| Failure | `failed`, `rejected`, protocol errors | JSON-RPC error, tool `isError`, extension task `failed` | These categories are not interchangeable. |
| Cancellation | idempotent task cancellation, subject to state | cooperative Tasks cancellation when used | “Cancel requested” is not proof that a side effect was prevented. |
| Idempotency | stable message/task identifiers can support deduplication | application-defined for effects; Tasks identify work | Carry one logical operation ID through to the final resource ledger. |
| Authorization | binding-specific authentication plus resource policy | OAuth is specified for HTTP transports; resource server enforces | Re-establish authority at every trust boundary. |

The current draft MCP Tasks extension has an especially important distinction: a
tool result with `isError: true` is still a protocol-level completed task,
whereas a JSON-RPC error can make a task `failed`. An adapter that maps both to
“retry” can repeat a non-idempotent effect or retry a permanent denial.

## 3. Separate identity, authority, and correlation

The lab keeps these principals distinct:

| Principal | Example | Established by | Must not be inferred from |
|---|---|---|---|
| human subject | `user:acme:42` | authenticated application session / authorization server | model text or A2A metadata |
| A2A sender | `triage-agent` | reviewed peer record plus workload authentication | Agent Card name |
| sender workload | `spiffe://acme.test/a2a/triage` | mTLS/SPIFFE identity | claimed sender field |
| protocol adapter | `protocol-adapter` | its own workload credential | the human subject token |
| target MCP resource | `mcp://support` | configured resource indicator and target identity | endpoint display name |
| tenant/resource owner | `acme` | trusted session and target datastore | tool argument, baggage, or message hint |

A target token in the lab preserves the human `sub`, identifies the current
adapter actor, retains prior actor history, and names only the MCP audience,
exact action, exact ticket resource, tenant, purpose, operation, approval, and
policy version. Production systems should apply the same narrowing in an
authorization server and may sender-constrain tokens with mTLS or DPoP.

### Security-context inventory

| Field | Classification | Source of truth | Translation rule |
|---|---|---|---|
| subject, actor, workload | authenticated identity | session, mTLS, workload identity | preserve identities; never merge them into one `user` string |
| tenant | authorized context | session plus resource ownership | reject mismatch; do not copy a tenant hint |
| audience/resource indicator | authorized context | deployment config and authorization server | exchange for the exact target; never pass through |
| action and resource | authorized context | reviewed skill map plus resource policy | exact match or strict intersection; no wildcard default |
| purpose | policy input | trusted workflow state | preserve exact value and apply at each boundary |
| approval | effect authorization | trusted receipt store | verify exact binding; consume atomically at effect boundary |
| expiry/deadline | safety bound | trusted clock and grant | choose the earliest parent, request, and local maximum |
| protocol/policy/contract versions | assurance evidence | negotiated protocol and reviewed configuration | fail closed on unsupported or unreviewed drift |
| operation ID | idempotency identity | trusted workflow | stable across attempts; bind to request digest |
| attempt ID | diagnostic identity | retry controller | new per attempt; never use as the effect key |
| traceparent | correlation only | validated W3C header | preserve trace ID, create a span per hop; grants no authority |
| A2A content, tool descriptions, baggage | untrusted data | remote peer/model | validate shape and content; never treat as identity or policy |

## 4. A safe translation algorithm

The trusted adapter should perform the following sequence:

1. authenticate its caller and resolve the reviewed A2A peer/workload record;
2. parse one versioned A2A schema with closed, typed fields and bounded sizes;
3. bind the wire message to the application-owned proposal and stable operation;
4. normalize all security fields into an immutable internal contract;
5. authorize the exact action/resource/purpose against current parent policy;
6. exchange the source grant for a shorter-lived, target-audience child grant;
7. verify approval and the current discovered MCP contract before dispatch;
8. let the MCP server authenticate and authorize the target grant again;
9. record the final resource effect under the same logical operation ID; and
10. return a typed outcome, or reconcile when the effect may have occurred.

Unknown fields, missing required extensions, unsupported versions, unmapped
skills, novel errors, and contract drift fail closed. “Let the model choose” is
not a safe compatibility strategy.

## 5. Credential exchange, not token passthrough

OAuth 2.0 Token Exchange (RFC 8693) defines a protocol for exchanging a subject
token. It does not by itself guarantee attenuation. Authorization-server policy
must intersect the requested child with:

```text
parent grant ∩ authenticated actor policy ∩ adapter mapping
∩ target audience/resource policy ∩ tenant ownership ∩ current revocation state
```

The child should have a distinct `aud`, `jti`, lifetime, and presenter; exact
action/resource/purpose bindings; and enough actor history for policy and audit.
RFC 8707 resource indicators make the intended resource explicit. Never send a
credential issued for the adapter or gateway to the downstream MCP server.

The lab uses signed training JWTs so claims are visible. Production should use
the organization’s authorization server, hardened key management, rotation,
revocation/status strategy, and sender constraint. Do not log tokens in traces,
notebooks, exceptions, or approval records.

## 6. Approval is a capability for one effect

An `approved=true` argument or opaque approval ID is caller-controlled data.
The lab uses a trusted, integrity-protected, single-use receipt bound to:

- subject and tenant;
- exact action and resource;
- logical operation ID;
- canonical digest of the final arguments/effect;
- policy version, approver, issue time, and expiry; and
- server-side consumed state.

The adapter checks the receipt before dispatch, but the final MCP resource
consumes it atomically immediately before the write. Reads need no write
approval. Any mutation after approval requires a new receipt.

## 7. Lifecycle and cancellation mapping

Use an internal state machine richer than either external protocol:

| Internal state | External meaning | Retry rule |
|---|---|---|
| `accepted` / `working` | authenticated, authorized work not yet terminal | poll/subscribe within deadline; do not duplicate dispatch |
| `input_required` | progress needs trusted user/application input | pause; do not let model fabricate approval/input |
| `completed` | protocol work completed; inspect domain result and effect evidence | return cached result for the same request digest |
| `denied` / `rejected` | permanent authorization/policy refusal | never retry or route around it |
| `invalid` | schema, version, contract, or semantic failure | fix request/configuration; never blind retry |
| `transient` | known pre-effect temporary failure | bounded backoff with same operation ID |
| `unknown` | effect may have committed but result was lost | reconcile first; retry only the exact idempotent operation |
| `cancelled` | cancellation confirmed before effect | terminal, unless independent evidence shows an effect |
| `failed` | known terminal system/protocol failure | retry only if taxonomy explicitly classifies it safe |

Cancellation is cooperative. A cancel request can race with a commit. If the
resource ledger shows the effect, report the effect and begin compensating
workflow if the business domain supports one; do not relabel it “cancelled.”
Compensation is a new authorized effect, not time travel.

## 8. Errors and retries

| Failure class | Example | Retryable? | Required behavior |
|---|---|---:|---|
| authentication/authorization | wrong audience, tenant denial, expired approval | no | return stable denial; alert on suspicious repetition |
| validation/compatibility | bad schema, unsupported version, contract drift | no | quarantine or request review; do not downgrade |
| domain/tool error | ticket closed, business rule refusal, MCP `isError` | normally no | preserve the domain code; do not call it transport failure |
| known transient pre-effect | unavailable before dispatch, explicit rate limit | bounded | back off with the same logical operation ID |
| transport loss after dispatch | timeout/reset after possible commit | reconcile first | classify `unknown`; query durable state before retry |
| novel/unmapped | new remote code | no by default | fail closed and update the reviewed taxonomy |

Retries need a total budget, deadline, jitter, circuit breaker, and observability.
They must never cross a denial, approval expiry, revocation, contract change, or
tenant boundary. A fallback service requires its own explicit authorization;
it is not a harmless retry destination.

## 9. Idempotency and outcome evidence

Use two identifiers:

- **operation ID:** stable for one logical effect across every hop and retry;
- **attempt ID:** unique diagnostic identifier for one transport attempt.

Bind the operation ID to a canonical request digest. Reuse with different
content is a conflict. Enforce idempotency in the adapter ledger *and* at the
resource that owns the effect. A process-local cache is insufficient: use a
durable, atomic store with retention longer than all retry/redelivery windows.

After a timeout, ask the target ledger or business datastore what happened. A
successful adapter response is not proof of a write, and a denial response is
not proof that no write occurred. Independent postconditions are the oracle.

## 10. Trace and security evidence

Validate W3C `traceparent`, preserve the trace ID, and create a new span ID at
each hop. `baggage` is untrusted correlation metadata and must never supply a
tenant, identity, role, scope, or approval. Apply allowlists, size limits,
redaction, retention, and tenant-aware access to telemetry.

Keep a durable, unsampled security record for:

- authenticated principals and target identity references (not secrets);
- policy decision and version;
- source/target protocol and contract versions;
- operation and attempt IDs;
- action/resource/purpose and approval receipt reference;
- token exchange reference and parent/child credential IDs;
- cancellation, retry, reconciliation, and final effect result; and
- timestamps, trace ID, and independently observed postcondition.

Prometheus labels should stay bounded; raw user, trace, and operation IDs belong
in governed logs/traces, not metric dimensions.

## 11. Threat model

| Threat | Unsafe composition | Control and proof |
|---|---|---|
| confused deputy | forward broad user or gateway token | target-audience exchange; child subset tests; target authorization |
| context loss | drop tenant/purpose/resource on translation | complete normalized contract; missing/mismatch negative tests |
| action widening | model maps “triage” to admin tool | reviewed closed skill→tool map; exact schema/argument pin |
| approval substitution | reuse an approval ID with changed body | signed exact-effect receipt; single-use atomic consumption |
| contract/version downgrade | silently ignore new field/extension | pinned semantic contract and supported version matrix; quarantine drift |
| denial laundering | convert deny into retry/fallback | closed error taxonomy; deny is terminal; tests assert no effect |
| duplicate effect | timeout causes a new operation ID | stable operation ID, canonical digest, target ledger, reconciliation |
| cancellation race | report cancelled after commit | final-state/effect query; compensating action is separately authorized |
| cross-tenant lookup | trust ticket or tenant in message | authenticated tenant plus target ownership check; non-enumerating denial |
| trace spoofing | trust baggage identity | correlation-only classification; identity from authenticated context |
| adapter compromise | universal service credential | least-privilege workload identity, isolation, egress, short child grants |
| evidence forgery | target self-reports “blocked” after write | independent resource/outbox postcondition |

## 12. Common tools and implementation choices

| Need | Common choice | Security review focus |
|---|---|---|
| A2A/MCP protocol | official A2A SDK and official MCP SDK | supported protocol revision, generated types, lifecycle/error behavior |
| authorization/token exchange | standards-based OAuth authorization server / STS | audience/resource indicators, attenuation policy, actor chain, revocation |
| workload identity | SPIFFE/SPIRE and mTLS | trust domain, selectors, rotation, federation, workload-to-policy binding |
| policy | OPA/Rego or Cedar | complete inputs, deny-by-default, obligations, policy version/evidence |
| agent control hooks | OWASP Agent Control Standard-compatible middleware patterns | portable interception does not replace application/resource authorization |
| gateway/service proxy | Envoy or an enterprise API gateway | identity propagation, retries, timeout budgets, header stripping, egress |
| durable orchestration | Temporal, cloud workflows, or a durable queue/outbox | deterministic retries, idempotency, cancellation, retention, reconciliation |
| telemetry | OpenTelemetry SDK/Collector | trace validation, redaction, bounded cardinality, durable security events |
| secrets/keys | managed KMS/HSM and secret manager | no model/tool exposure, rotation, audit, least privilege |

These are components, not security claims. For example, using OPA does not
prove the enforcement point supplied the correct tenant; using Temporal does
not make a non-idempotent API safe; using SPIFFE does not authorize a business
action; and an SDK-generated type does not make message content trusted.

### Topology choices and architecture regret

- **In-process adapter:** fewer hops and simple context propagation, but a
  larger shared blast radius and coupled upgrades.
- **Sidecar/gateway:** centralized identity and policy, but a high-value deputy
  that needs strict tenant partitioning and target-side checks.
- **Durable orchestrator:** strong recovery and reconciliation, but more state,
  retention, operational cost, and deletion/privacy obligations.
- **Direct application integration:** least translation ambiguity for a small
  system, but duplicated controls if every team reimplements the boundary.

Measure coordination tax: trust boundaries, credentials, durable states,
failure domains, policy decisions, and operator dependencies. Prefer the
simplest topology that satisfies the required ownership and recovery model.

## 13. Practical lab

The lab uses no real credentials or network endpoints. From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[contributor]'
python curriculum/advanced/19-protocol-composition-security/lab.py
pytest -q tests/test_course_19_protocol_composition.py
```

What the lab actually proves:

- official A2A `Message`/`Part` wire types carry a structured proposal;
- the official MCP Python SDK performs real in-memory discovery and tool calls;
- transport-authenticated peer/tenant facts override message hints;
- a source grant is exchanged for a distinct target-audience child;
- exact action/resource/purpose/version/operation bindings survive exchange;
- discovered MCP tools are compared with a reviewed semantic contract;
- write approval is bound and consumed at the final effect boundary;
- cancellation before dispatch produces no effect;
- known pre-effect transient failure is separated from unknown outcome;
- response loss after commit is reconciled without a duplicate comment; and
- trace IDs remain continuous while every hop gets a distinct span.

The in-memory MCP transport exercises protocol implementation, not TLS,
reverse-proxy behavior, process isolation, production OAuth middleware, or a
durable database. The JWT keys, peer record, policy, approval store, and ledgers
are intentionally local training fixtures.

## 14. Evaluation campaign

At minimum, label and execute:

- positive read and approved-write controls;
- wrong peer/workload, tenant, audience, action, resource, purpose, and expiry;
- malformed A2A data, unsupported version, missing required extension;
- changed MCP tool set, schema, annotations, and security metadata;
- missing, altered, expired, replayed, or cross-operation approval;
- policy denial, domain `isError`, JSON-RPC failure, rate limit, and novel error;
- cancellation before dispatch, during work, and after commit;
- transient before effect and connection loss after possible effect;
- same operation/same body and same operation/different body;
- trace loss/spoofing and evidence redaction; and
- an independent final-effect query for every consequential case.

Report decision accuracy, unsafe-allow rate, false-block rate, duplicate-effect
rate, trace continuity, reconciliation success/time, unclassified-error rate,
and safe-task completion. Do not call a system secure because it blocks every
request or because no attack succeeded in a small sample.

## 15. Production readiness checklist

- [ ] Every trust boundary authenticates its immediate peer and target.
- [ ] Human subject, actor chain, workload, and tenant remain distinct.
- [ ] Each credential has the exact audience/resource and minimum lifetime.
- [ ] Source authority is exchanged and narrowed; no token passthrough exists.
- [ ] Skill→tool/action/resource mappings are closed, versioned, and reviewed.
- [ ] The final resource independently checks tenant ownership and authority.
- [ ] Approval binds exact effect, expires, and is consumed atomically.
- [ ] Protocol, extension, policy, and discovered contracts are compatibility-gated.
- [ ] Operation IDs bind canonical requests in durable adapter and target ledgers.
- [ ] Error taxonomy makes denials permanent and unknown outcomes reconcilable.
- [ ] Retry, timeout, cancellation, and compensation rules are explicit and tested.
- [ ] Trace/baggage is correlation-only, validated, redacted, and access-controlled.
- [ ] Independent effect evidence decides evaluation and incident scope.
- [ ] Credential, policy, registry, contract, and peer revocation propagate measurably.
- [ ] Runbooks cover adapter isolation, queue draining, reconciliation, and rollback.

## 16. Exercises and assessment

1. Add an `input_required` path. Prove that only trusted user input—not agent
   prose—can resume it and that the deadline/approval is revalidated.
2. Add a second tenant and property-based tests showing no cross-tenant read,
   write, lookup, cache hit, or reconciliation result is observable.
3. Replace the training STS with a local authorization-server test double that
   implements token-exchange request/response fields and negative policy cases.
4. Add a deliberate tool-schema change. Require a reviewed contract update
   before the adapter invokes either the old or new server.
5. Model cancellation after commit and implement a separately approved
   compensating comment deletion. Preserve both effects in evidence.
6. Compare this composition with a direct ticket API integration. Document the
   additional boundaries, states, credentials, tests, and operational owners.

**Assessment standard:** a submission passes only when a labelled valid read
and approved write complete, every authority-widening case is blocked before an
effect, the lost-response scenario produces one effect after reconciliation,
and evidence joins the runtime proposal to the independently observed resource
state without exposing a credential.

## Authoritative references

Protocol and standards links were reviewed on 2026-10-28.

- [A2A Protocol Specification 1.0.1](https://a2a-protocol.org/v1.0.1/specification/)
- [MCP 2026-07-28 architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture)
- [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP 2026-07-28 authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP 2026-07-28 transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [MCP Tasks extension 2026-07-28](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks)
- [OAuth 2.0 Token Exchange — RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [OAuth 2.0 Resource Indicators — RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- [OAuth 2.0 DPoP — RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
- [OAuth 2.0 mTLS — RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/)
- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar policy language documentation](https://docs.cedarpolicy.com/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
