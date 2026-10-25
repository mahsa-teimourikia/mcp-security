# Agent-to-Agent / A2A Security and Delegation

Authenticate A2A peers, attenuate human authority into a task-bound grant, enforce it independently at every hop, and evaluate replay, tenant, lifecycle, retry, notification, and outcome failures without treating an agent identity or protocol field as authorization.

> **Version snapshot (verified 2026-10-25):** this course targets the stable A2A 1.0 specification family and the official Python SDK 1.2.3. A2A is evolving; pin the protocol version, SDK range, bindings, and extensions you test. Re-run compatibility and security tests before upgrading.

## Learning objectives

After completing the chapter and lab, you can:

1. distinguish A2A discovery, transport authentication, task authorization, and downstream resource authorization;
2. validate an Agent Card while recognizing that advertised skills are not grants;
3. model the human subject, calling workload, receiving workload, tenant, task, and final resource as separate security subjects;
4. attenuate parent authority to an exact recipient, action, resource, purpose, protocol/card version, message, context, operation, lifetime, and delegation chain;
5. apply A2A `Message`, `Task`, `contextId`, `taskId`, lifecycle, extension, streaming, and push-notification semantics safely;
6. make retry behavior safe under timeouts and unknown outcomes with stable IDs, atomic deduplication, reconciliation, and an independent effect oracle;
7. test confused-deputy, cross-tenant, replay, drift, loop, SSRF, illegal-transition, and duplicate-effect failures; and
8. decide when a simpler direct service call is safer than a multi-agent architecture.

## Prerequisites and setup

Complete Courses 6–8 for OAuth and delegation, Course 10 for SSRF/egress, and Course 17 for registry trust. From the repository root:

```bash
uv sync --extra contributor
uv run --extra contributor python curriculum/advanced/18-agent-to-agent-a2a-security-delegation/lab.py
uv run --extra contributor pytest -q tests/test_course_18_a2a_security.py
```

The lab is deterministic, offline, and credential-free. It uses the official `a2a-sdk` types and PyJWT. Its HMAC keys, static DNS answers, and in-memory stores are training fixtures—not production controls.

## 1. What A2A standardizes—and what it does not

A2A describes interoperable agent discovery and collaboration. Its core objects are:

| Object | Protocol purpose | Security interpretation |
|---|---|---|
| `AgentCard` | Advertises identity, interfaces, skills, capabilities, security schemes, and modes | Discovery evidence to verify and review; never runtime authority |
| `Message` | One user/agent turn made of typed `Part` values | Untrusted input; metadata and prose cannot select identity, tenant, or privilege |
| `Task` | Server-created, stateful unit of work | Authorization and ownership must be checked on every create/get/list/cancel/subscribe operation |
| `contextId` | Relates messages and tasks in one interaction | Correlation, not access control; bind it to the authorized task and tenant |
| `Artifact` | Output produced by a task | Untrusted content requiring size, media-type, malware, provenance, and destination controls |
| Extension URI | Negotiates additional semantics | Versioned code and policy surface; required extensions must fail closed when unsupported |

The protocol intentionally leaves an agent’s authorization model to the application. A conforming A2A message can still be unauthorized. Transport success, a valid Agent Card, a known peer, or a fluent model explanation does not grant access.

### A2A and MCP are complementary

A2A coordinates work between agents. MCP exposes tools, resources, and prompts between a host/client and a server. An A2A recipient may call an MCP server while executing a task, but the A2A task does not automatically authorize the MCP action. The MCP server remains a final enforcement point and needs its own audience-bound, tenant-bound authority.

## 2. Identity is a tuple, not an agent name

A realistic handoff has at least five identities:

1. the human or service subject on whose behalf work occurs;
2. the calling agent workload authenticated by mTLS, SPIFFE, or a workload credential;
3. the receiving agent workload and exact service endpoint;
4. the tenant, environment, and organization boundary; and
5. the final resource owner that authorizes the effect.

Keep them distinct. The model may propose a peer or tool; a trusted application resolves the reviewed record, authenticates the workload, obtains a narrow grant, executes, and verifies the outcome.

```text
model proposes task
       │
       ▼
coordinator ──mTLS/workload identity──► A2A recipient
       │           + task grant              │
       │                                     ▼
human parent authority              independent policy gate
                                             │
                                             ▼
                                  MCP/API/resource server
                                  re-authorizes final effect
```

Do not accept `sender`, `tenant`, `role`, or `authorization` values from message metadata as authenticated facts. Bind the transport credential to the reviewed peer record and derive tenant policy from server-side state.

## 3. Agent Card discovery and trust

The well-known public Agent Card supports discovery. Sensitive or client-specific capabilities belong in an authenticated extended card. Treat either card as mutable metadata until it passes a trust workflow.

A production admission record should bind:

- canonical agent and provider identity;
- exact card bytes/digest, version, supported interfaces, binding, and protocol version;
- HTTPS endpoint and authenticated workload identity;
- approved tenants, environments, skills, modes, and extensions;
- key/signature evidence, source/provenance, owner, incident contact, review time, expiry, and lifecycle state.

For signed cards, follow the specification’s JWS verification procedure: resolve keys through a trusted path, reject expired/revoked keys, remove the signatures field, canonicalize as required, and verify the signature. Multiple signatures may support key rotation. A valid signature proves control of a key, not that the signer is acceptable for this tenant or action.

Re-evaluate trust on cache refresh, card/key/endpoint drift, SDK or protocol upgrades, owner changes, incidents, and revocation. Fail closed if a cached card and the reviewed digest diverge.

## 4. Delegation as authority attenuation

The child grant must be no more powerful than the parent grant:

```text
child authority = parent authority
                ∩ caller workload policy
                ∩ recipient policy
                ∩ tenant/resource policy
                ∩ task-specific request
```

At minimum, bind the child to:

- `iss`, human/service `sub`, calling agent `act`, and exact recipient `aud`;
- authenticated tenant and environment;
- exact action, resource, and purpose;
- A2A protocol version and reviewed recipient-card digest;
- `messageId`, `contextId`, logical operation ID, and required extensions;
- issue/not-before/expiry times, unique token ID, parent-authority digest;
- delegation chain and maximum depth.

OAuth 2.0 Token Exchange provides standard impersonation/delegation concepts. Resource Indicators help request an audience-specific token. DPoP or OAuth mTLS can sender-constrain tokens so theft of a bearer value alone is insufficient. These mechanisms do not replace the resource server’s scope, tenant, ownership, and lifecycle checks.

Never forward a broad user token to every peer. Exchange or mint a narrow token for the next recipient and keep credentials out of A2A `Message`, `Part`, artifact, model context, logs, and traces.

## 5. Task and message invariants

### IDs and ownership

- The message creator supplies a stable, high-entropy `messageId`.
- The server creates `taskId`; clients must not invent a new server task.
- If both `taskId` and `contextId` appear, they must refer to the same authorized task.
- Get/list/cancel/subscribe/push-config operations must check caller ownership before querying in ways that leak task existence.
- A task ID is an identifier, not a secret and not an authorization token.

### Lifecycle

The lab enforces this reduced state machine:

```text
submitted ──► working ──► completed | failed | canceled
    │             │
    ├──► rejected ├──► input-required ──► working | canceled
    └──► canceled └──► auth-required  ──► working | canceled
```

`completed`, `failed`, `canceled`, and `rejected` are terminal. Reject updates after a terminal state, updates before the initial task in a stream, mismatched task/context IDs, and events not authorized for that caller. Store transitions atomically with a monotonic revision in production.

### Parts, artifacts, and streams

Enforce declared media types, byte limits, schemas, malware/content scanning, URL-fetch policy, and artifact destinations. Apply authorization before opening a stream and during long-lived work when credentials, tenant membership, or policy can change. Backpressure, maximum duration, idle timeouts, and bounded history prevent resource exhaustion.

## 6. Idempotency, retries, and unknown outcomes

A2A send-message operations may be idempotent, but this is an implementation choice. A network timeout means “outcome unknown,” not “nothing happened.”

Use:

1. one stable `messageId` for an exact message retry;
2. one stable logical operation ID for the intended real-world effect;
3. a digest of the canonical authorized request;
4. an atomic `(caller, tenant, messageId) → request digest, taskId` record;
5. a resource-side operation ledger or provider idempotency key; and
6. reconciliation (`GetTask`/effect lookup) before creating new work.

An identical retry returns the stored task/result. Reusing the same message ID for different bytes is a conflict. A new attempt ID can describe delivery attempts, but it must not become a new logical effect ID.

## 7. Push notifications and SSRF

Push configuration turns the A2A server into an HTTP client. The current A2A security guidance requires authenticated webhooks and recommends SSRF defenses. Production controls include:

- HTTPS-only, allow-listed callback hosts and permitted ports/paths;
- no userinfo, fragments, IP literals, localhost, private, link-local, multicast, reserved, or metadata-service addresses;
- DNS resolution and IP policy at connection time, with DNS rebinding protection;
- redirect denial or complete validation of every redirect target;
- outbound proxy/egress policy, small payload/time limits, and no ambient cloud credentials;
- unique task-bound receiver credentials, rotation, rate limiting, replay protection, and idempotent processing;
- receiver validation that the authenticated notification names an expected task.

The lab uses a supplied DNS view so it never performs a network request. `validate_push_url` is only a preflight policy; an actual HTTP client must enforce the resolved destination at connect time.

## 8. Threat model and required tests

| Threat | Failure | Control and evidence |
|---|---|---|
| Peer impersonation | Claimed agent name is trusted | mTLS/workload auth bound to reviewed peer record |
| Discovery poisoning | Attacker publishes a convincing card | card signature/provenance review, exact digest, expiry, lifecycle |
| Confused deputy | Recipient uses its broad privilege for caller | exact action/resource/purpose grant; resource re-authorization |
| Cross-tenant access | message tenant selects another customer | server-derived tenant and ownership checks at every operation |
| Replay/duplicate effect | retry creates a second action | message/request dedupe plus independent operation ledger |
| Card/protocol drift | semantics change after review | version and card-digest binding; compatibility tests |
| Delegation loop | agents recursively amplify work | bounded depth, unique chain, budgets and cycle detection |
| Context poisoning | old task/context is attached to new work | token-message-task-context binding and ownership lookup |
| Illegal task event | terminal task becomes active | explicit state machine and atomic revisions |
| Extension downgrade | required control is ignored | versioned URI negotiation and fail-closed required extensions |
| Webhook SSRF | server calls internal/cloud endpoint | URL/DNS/connect-time validation and egress isolation |
| Artifact attack | output contains malware or hostile instructions | size/type/schema/content/provenance controls; treat as data |
| Unknown outcome | timeout is interpreted as failure | reconcile stable IDs and check external effect oracle |

The test suite includes positive, negative, boundary, tamper, lifecycle, retry, and property-based cases. Its most important metric is unsafe allow rate; ordinary decision accuracy can hide a rare but catastrophic cross-tenant allow.

## 9. Lab walkthrough

Open `a2a_security.ipynb` for the guided path, or inspect `lab.py` directly.

1. `build_agent_card` and `build_message` instantiate official SDK protobuf types.
2. `PeerDirectory` admits a reviewed sender and binds it to a SPIFFE-style workload ID.
3. `DelegationBroker` intersects the parent authority with the proposed task and issues a five-minute recipient-bound training JWT.
4. `SecureA2AServer` authenticates the peer, validates protocol/card/skill/extensions/message/push policy, verifies the grant, and atomically deduplicates the message.
5. `TicketResourceServer` independently checks audience, action, tenant ownership, and operation ID.
6. The server applies a legal A2A task lifecycle and records a minimized audit digest.
7. The demo retries an already-completed message after a simulated lost response and proves the effect count remains one.
8. The adversarial campaign measures unsafe allows and false blocks across independent failure planes.

Expected highlights:

```text
Task state: TASK_STATE_COMPLETED
Retry returned same task: True
Independent effect count: 1
Decision accuracy: 1.0
Unsafe allow rate: 0.0
```

### Exercises

1. Add `ticket.comment` to the parent, but require a human approval receipt before the broker can mint that child action.
2. Add a second recipient hop and prove each child’s actions/resources/lifetime are subsets of its parent.
3. Add task ownership to get/cancel/subscribe methods and test that a wrong tenant sees a generic not-found response.
4. Replace the in-memory dedupe map with a transactional database design. Document the unique key and commit boundary with the external effect.
5. Add a webhook receiver that validates a task-bound signature and deduplicates notification deliveries.
6. Compare the A2A design with the direct baseline. Remove A2A if independent ownership, long-running collaboration, or interoperability does not justify its extra trust and failure domains.

## 10. Common production tools and methods

| Need | Common choices | What to verify |
|---|---|---|
| A2A protocol | Official Python, Java, JavaScript, Go, or .NET SDK | exact spec/SDK versions, binding parity, secure defaults, generated types |
| Workload identity | mTLS, SPIFFE/SPIRE, cloud workload identity | trust domain, selector policy, rotation, revocation, endpoint binding |
| Token service | standards-based OAuth authorization server/STS | token exchange policy, audience/resource, actor chain, sender constraint |
| Policy | Open Policy Agent/Rego or Cedar | server-derived inputs, deny-by-default, versioned policy, decision logs/tests |
| Durable tasks | transactional DB, queue, workflow engine | atomic state transitions, dedupe, leases, retries, poison-message handling |
| Gateway/mesh | Envoy or managed API gateway/service mesh | independent backend auth, mTLS, egress, rate/size/time limits |
| Observability | OpenTelemetry plus SIEM | trace continuity without tokens, prompts, secrets, or sensitive artifacts |
| Security testing | pytest, Hypothesis, schema/contract tests, fault injection | unsafe allow rate, duplicate effects, cross-tenant leaks, partial failure |

Treat these as implementation options, not endorsements. Validate current support, maintenance, licensing, and threat fit.

## 11. Production readiness checklist

- [ ] Pin and inventory A2A spec, SDK, binding, extension, schema, and card versions.
- [ ] Separate public discovery from reviewed admission; protect extended cards.
- [ ] Authenticate both workloads and bind credentials to exact reviewed peer records.
- [ ] Keep human subject, actor workload, recipient workload, tenant, and resource owner distinct.
- [ ] Exchange broad authority for short-lived recipient/action/resource/purpose-bound grants.
- [ ] Sender-constrain valuable tokens; never place credentials in protocol content or model context.
- [ ] Authorize every task operation before revealing resource existence.
- [ ] Enforce server-generated task IDs, context binding, legal lifecycle transitions, and revisions.
- [ ] Make dedupe durable and atomic; reconcile unknown outcomes against an external effect oracle.
- [ ] Validate streams, files, URLs, parts, artifacts, extensions, and push destinations as untrusted input.
- [ ] Enforce SSRF controls at DNS resolution, redirect, and network-connect time.
- [ ] Re-authorize at MCP/API/resource servers; block direct bypass paths.
- [ ] Propagate peer, key, credential, task, and policy revocation to every enforcement point.
- [ ] Record minimized, correlated audit events and test that secrets/content are excluded.
- [ ] Exercise impersonation, escalation, replay, cross-tenant, lifecycle, retry, outage, and containment cases.
- [ ] Compare against a direct-call baseline and document why multi-agent complexity is justified.

## Limitations of the lab

The fixture does not implement network transport, TLS, DNS, JOSE key distribution, card JWS verification, OAuth discovery, durable concurrency, an A2A client/server route, a webhook receiver, streaming, file scanning, or distributed revocation. HMAC simulates integrity and the SPIFFE string simulates an already-authenticated transport identity. Production evidence must demonstrate those controls at their actual enforcement points.

## Authoritative references

- [A2A protocol specification 1.0.1](https://a2a-protocol.org/v1.0.1/specification/)
- [A2A security considerations](https://a2a-protocol.org/v1.0.1/specification/#13-security-considerations)
- [A2A agent discovery and card protection](https://a2a-protocol.org/latest/topics/agent-discovery/)
- [Official A2A Python SDK 1.2.3](https://github.com/a2aproject/a2a-python/releases/tag/v1.2.3)
- [OAuth 2.0 Token Exchange — RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [OAuth 2.0 Resource Indicators — RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- [OAuth 2.0 Mutual TLS — RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
- [OAuth 2.0 DPoP — RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
- [JSON Canonicalization Scheme — RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar policy language documentation](https://docs.cedarpolicy.com/)
- [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
