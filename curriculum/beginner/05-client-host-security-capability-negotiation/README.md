# MCP Client/Host Security and Capability Negotiation

Build a fail-closed MCP host that verifies a server before connection, reviews
its complete discovered contract, exposes only namespaced and authorized tools,
validates results, partitions capability caches, and makes revocation effective
for an already-open client connection.

## Learning objectives

After this course, you should be able to:

1. explain the host, client, and server trust boundaries without treating MCP
   discovery as authentication or authorization;
2. distinguish the modern MCP `2026-07-28` lifecycle from the initialization
   handshake used by older protocol revisions;
3. inspect tools, resources, resource templates, prompts, schemas, annotations,
   instructions, protocol support, and cache hints with the official Python SDK;
4. bind a reviewed capability snapshot to a host-owned server ID, exact launch
   specification, verified artifact digest, owner, policy version, and expiry;
5. deny artifact, schema, metadata, and capability drift before publishing any
   tool to a model;
6. namespace tools across servers and authorize each invocation using identity
   from trusted application state;
7. cap, partition, expire, and revoke cached metadata safely; and
8. test the negative paths that establish those claims.

## Prerequisites and scope

Complete Courses 01–04 first. You should already know the MCP architecture,
threat-model vocabulary, safe interface design, and how to build a bounded MCP
server. This course owns the **host/client admission and invocation boundary**.
Course 06 covers OAuth, Course 07 builds deeper authorization policy, Course 09
covers runtime isolation, and Course 17 develops an enterprise registry and
gateway. Those controls are referenced here but not simulated as already
implemented.

The lab is credential-free and uses `Client(MCPServer)` from the official
Python SDK. It executes real protocol discovery and tool calls in memory. It
does **not** prove package-signature verification, subprocess isolation, TLS,
remote origin controls, OAuth, or production registry durability.

## The central boundary

```text
model / agent       proposes a namespaced tool call and arguments
MCP server          advertises metadata and returns untrusted content
trusted host        verifies, filters, validates, authorizes, invokes, revalidates,
                    audits, caches, revokes, and decides what reaches the model
```

A server can truthfully say it supports `filesystem.read`; that does not make
the tool appropriate for this user or deployment. A model can emit valid JSON;
that does not establish permission, tenant, purpose, or approval. A successful
protocol exchange proves interoperability with the connected peer—not the
peer's provenance or the safety of its behavior.

## Architecture and lifecycle

```mermaid
sequenceDiagram
  actor U as Authenticated user
  participant I as Installer / verifier
  participant R as Host review registry
  participant H as Host policy
  participant C as MCP Client
  participant S as MCP Server

  I-->>H: server ID + exact launch spec + verified digest
  R-->>H: owner + expiry + reviewed capability digest + grants
  H->>H: preflight artifact, launch spec, revocation, review freshness
  H->>C: construct one isolated client for this server
  C->>S: server/discover (modern auto negotiation)
  S-->>C: versions + capabilities + self-reported identity + instructions
  C->>S: tools/list, resources/list, templates/list, prompts/list
  S-->>C: schemas, annotations, metadata, ttlMs, cacheScope
  C-->>H: canonical bounded snapshot
  H->>H: exact diff; default deny on drift
  H-->>U: namespaced, policy-filtered capability view
  U->>H: proposed support.ticket.read call
  H->>H: recheck review/revocation + permission + arguments
  H->>C: tools/call ticket.read
  C->>S: protocol request
  S-->>C: untrusted structured result
  C-->>H: result
  H->>H: validate output + audit
  H-->>U: labelled result
```

One host commonly manages several client instances, with one client connected
to one server. Keep those connections and their credentials, caches,
capabilities, errors, and namespaces isolated. Never concatenate every server's
raw tool list into a single ambiguous model namespace.

## Modern and legacy capability negotiation

MCP currently has two lifecycle eras:

| Era | Establishing protocol behavior | Security consequence |
| --- | --- | --- |
| `2026-07-28` modern | no initialization handshake; protocol version and client capabilities travel on each request; servers implement `server/discover` and clients may call it | discovery is fresh protocol metadata but still not verified identity or authority |
| `2025-11-25` and earlier | `initialize` request/response followed by `notifications/initialized` | session state and negotiated capabilities still do not replace application authorization |

The Python SDK's `Client(..., mode="auto")` probes modern discovery and falls
back for a legacy server. The lab asserts the final `client.protocol_version`
instead of assuming which path ran. A pinned modern version skips discovery; if
the host needs identity and capability metadata, it must retain a reviewed
`DiscoverResult` or perform discovery rather than pretending a version pin
supplies those facts.

In modern MCP, `server/discover` returns supported versions, feature-family
capabilities, optional instructions, and a self-reported `serverInfo`. The
specification explicitly says that `serverInfo` is for display, logging, and
debugging—not a security decision. The lab therefore uses a host-owned
`server_id` and verified artifact record. Its malicious server deliberately
reports the same name and version as the reviewed server.

Feature-family capability negotiation answers questions such as “does this
server support tools?” Detailed list methods answer “which tools and schemas are
currently advertised?” Neither grants a user permission to invoke one.

## What a complete capability contract contains

Review the complete contract, not only a set of names:

| Surface | Include in review | Typical drift or attack |
| --- | --- | --- |
| Protocol | selected and supported versions, extensions | downgrade, unsupported extension, changed fallback behavior |
| Server metadata | self-reported name/version, instructions | impersonation or instruction injection |
| Tools | name, description, input/output schemas, annotations, metadata | new tool, widened argument, removed output constraint, false `readOnlyHint` |
| Resources | URI, name, MIME type, description, annotations | new tenant URI, broad file URI, content-type change |
| Resource templates | full URI template and parameter surface | arbitrary path or network target |
| Prompts | name, description, arguments | injected instructions or a new sensitive parameter |
| Lists and discovery | pagination, item/byte/page budgets, cache hints | metadata exhaustion, cursor loop, unsafe public caching |

Tool annotations are useful user-interface hints. The tool specification says
clients must treat them as untrusted unless the server is trusted. Even for a
reviewed server, `readOnlyHint=true` is not a sandbox, proof of implementation,
or authorization grant. Review implementation and runtime evidence separately.

The lab serializes complete SDK models to canonical JSON, sorts them, and hashes
the snapshot. Any material difference—including description, schema,
annotation, resource, prompt, instruction, cache hint, or protocol metadata—
changes the digest and denies the server until a new review record is approved.
This strict policy is appropriate for a beginner security baseline. Larger
platforms may classify compatible changes, but the classification rules must be
deterministic, versioned, and tested; a model must not decide that widening is
safe.

## Three gates, in order

### 1. Pre-connection admission

Before executing a local command or contacting a remote endpoint, compare the
candidate against a trusted installation record:

- host-owned stable server ID and owner;
- exact command plus arguments, or exact HTTPS origin and path policy;
- immutable artifact digest and verifier result;
- approved configuration and environment exposure;
- current review and revocation state.

This order matters. A malicious local server's startup command can execute
before MCP emits its first frame. The official security guidance requires clear
consent before one-click local configuration executes a command and recommends
sandboxing with restricted filesystem and network access. Showing a friendly
server name after launch is too late.

### 2. Post-discovery capability review

Discovery data is untrusted input from the candidate. Bound pagination, item
count, and encoded bytes; canonicalize complete definitions; compare them with
the reviewed snapshot; and fail closed on drift. Do not automatically approve a
snapshot because parsing and discovery succeeded. The lab's review helper
requires the expected inventory and represents a separate reviewer decision.

### 3. Per-invocation authorization

Admission answers whether the host may connect. It does not authorize every
future call. For each proposed invocation, the host must:

1. resolve a namespaced exposed name to exactly one reviewed server tool;
2. recheck review freshness and revocation;
3. derive subject, tenant, and permissions from authenticated application state;
4. validate exact typed arguments before the protocol call;
5. require any action-specific approval needed for consequential effects;
6. call the server with least privilege;
7. reject `is_error` and validate structured output against a host-owned model;
8. label returned content untrusted; and
9. record a redacted decision with reason code and digests.

The server must independently authenticate and authorize requests. Host
filtering reduces exposure; it cannot compensate for a server that trusts a
caller-supplied tenant or forwards the wrong token.

## Namespaces and multi-server isolation

Two servers may both advertise `search`, `read`, or `create`. Expose a stable
host namespace such as `support.ticket.read` or `crm.customer.search`, then map
it to one reviewed `(server_id, tool_name, schema_digest)` tuple. Reject raw
server tool names at the model boundary. This prevents accidental collisions,
ambiguous routing, and a newly connected server from shadowing an existing
capability.

Maintain separate client objects and authorization contexts per server. Do not
pass one server's result, credential, resource roots, or instructions to another
unless an explicit, independently authorized application workflow requires it.

## Capability caching without stale authority

On modern MCP, discovery and list/read results can carry:

- `ttlMs`: how long the server says a result may be treated as fresh; and
- `cacheScope`: `private` for one authorization context or `public` when the
  response is identical for everyone.

These are server hints. They do not grant data-sharing permission. The SDK's
safe default is immediately stale and private. A production host should apply
the smaller of the server TTL and a host maximum, partition by authorization
context even when uncertain, and bind the key to at least:

```text
server_id + artifact_digest + launch/origin + protocol_version
+ policy_version + authorization_context
```

Invalidate entries on revocation, artifact or configuration change, capability
notification, policy update, credential change, or failed assumptions. The lab
always keeps a private authorization-context partition, caps the server's
10-second hint at five seconds, and removes every entry for a revoked server.

## Worked scenario

Northstar Support has reviewed an MCP server with two read-only tools, one
versioned policy resource, and one summary prompt. An authenticated analyst has
only `ticket:read` permission.

The malicious update:

- self-reports the same server name and version;
- widens `ticket.read` with a caller-controlled tenant;
- adds `filesystem.read`;
- replaces the resource with a file template;
- injects instructions into server and prompt metadata; and
- claims a one-hour public cache lifetime.

The host denies the whole connection because the complete snapshot changed.
For the reviewed server it exposes `support.ticket.read` and
`support.ticket.search`, but an attempt to use search is denied before the
server handler because the principal lacks `ticket:search`. A valid read is
output-validated and audited without raw arguments. Finally, revocation blocks
a second read on the already-open connection and invalidates its cache.

Run the lab:

```bash
python curriculum/beginner/05-client-host-security-capability-negotiation/lab.py
```

Run its focused proofs:

```bash
python -m pytest -q tests/test_course_05_client_host_security.py
```

## Claim-to-proof map

| Claim | Executable proof |
| --- | --- |
| Real current protocol path is exercised | SDK `Client(MCPServer)` reports `2026-07-28` and lists every primitive |
| Self-reported identity is not trusted | malicious fixture uses the same name/version yet has a different snapshot and is denied |
| Launch and artifact drift fail before connection | parameterized preflight tests produce no capability digest because discovery never ran |
| Full capability drift is denied | malicious tool/schema/resource/prompt/instruction/cache changes produce `CAPABILITY_DRIFT` |
| Model sees only reviewed namespace | visible list contains only `support.*`; raw `ticket.read` is rejected |
| Identity and permission remain host-owned | principal permission denial occurs before `ticket.search` handler count changes |
| Arguments are exact and typed | missing, wrong-type, extra-tenant, and path-shaped inputs fail before the handler |
| Server success is not blindly trusted | host applies a separate Pydantic output model and has a negative validation test |
| Cache cannot cross authorization contexts | distinct principal or tenant misses; host TTL caps server TTL |
| Revocation affects active use | revoked open connection denies before handler and removes cache entries |
| Discovery is bounded | item budget failure stops oversized metadata collection |
| Audit is useful without raw sensitive values | event records trace, decision, reason, policy and digests; raw subject and ticket ID are absent |

## Threats and controls

| Threat | Control | Residual risk / next layer |
| --- | --- | --- |
| malicious local launch command | exact reviewed command, consent, verified artifact, sandbox | installer/verifier compromise; Course 12 and 17 |
| remote endpoint substitution | exact HTTPS origin, certificate validation, egress and DNS controls | DNS/CA compromise; Course 10 |
| server-name impersonation | host-owned ID plus artifact/origin binding | registry compromise; Course 17 |
| tool poisoning or schema widening | exact canonical snapshot and review on drift | reviewed implementation may still be malicious; Courses 11 and 14 |
| name collision across servers | host namespace and one-to-one mapping | workflow composition risk; Courses 19 and 20 |
| caller-selected tenant or identity | authenticated host principal; no scope field accepted | server must repeat enforcement; Courses 06 and 07 |
| stale capability cache | bounded TTL, context partition, invalidation | distributed invalidation delay; Courses 16 and 22 |
| metadata exhaustion | page/item/byte budgets and cursor-loop detection | transport resource exhaustion; Course 09 |
| malicious tool output | typed output validation and untrusted label | semantic prompt injection; Course 11 |
| revoked server keeps operating | recheck before every call, close connection, revoke credentials | in-flight side effect; Course 22 |

## Evaluation plan

Use labelled cases for reviewed, unknown, expired, revoked, drifted, malformed,
and unauthorized states. Report the denominator and decision point for every
metric:

| Metric | Numerator | Denominator | Direction / slice |
| --- | --- | --- | --- |
| Unreviewed drift block rate | drift cases denied before publication | all labelled drift cases | 100%; slice by tool/schema/resource/prompt/cache/protocol |
| Valid admission rate | reviewed unchanged candidates admitted | all reviewed unchanged candidates | high; slice by SDK and transport |
| Forbidden invocation outcome rate | forbidden calls that reach a server handler | all labelled forbidden calls | 0%; distinguish host denial from server denial |
| Valid-work denial rate | allowed calls incorrectly denied | all labelled allowed calls | low; slice by policy version and server version |
| Revocation propagation | revoked targets blocked within objective | all revocation drills | 100%; report milliseconds, p50/p95/p99 |
| Capability review latency | elapsed time from detected drift to recorded decision | all completed reviews | lower without bypassing review; report distribution |
| Cache isolation violation rate | entries served to wrong authorization context | all cross-context cache probes | 0% |
| Audit completeness | decisions with required redacted fields | all admission and invocation decisions | 100% |

Blocked attempts are not the same as successful attacks. A high denial count can
mean controls work, clients are misconfigured, or adversaries are active; keep
the categories separate. The in-memory fixture provides deterministic control
evidence, not a security benchmark or model-quality evaluation.

## Common tools, SDKs, and methods

| Need | Common choice | Correct use here |
| --- | --- | --- |
| MCP interoperability | official Python, TypeScript, Go, and C# SDKs | use typed clients, lifecycle helpers, structured results, pagination, and conformance tests |
| Contract validation | JSON Schema plus Pydantic, Zod, or equivalent | validate both proposed arguments and returned structured content; schema validity is not authority |
| Policy decision | application code, Open Policy Agent/Rego, Cedar, or Casbin | feed authenticated identity and reviewed resource facts; deny on unavailable or stale policy |
| Artifact provenance | Sigstore/Cosign, SLSA provenance, package lockfiles/SBOMs | verify before launch and bind the accepted digest to the review record |
| Isolation | containers, OS sandbox profiles, seccomp, AppArmor/SELinux, network policy | minimize filesystem, environment, process, and egress access for local servers |
| Observability | OpenTelemetry plus structured security events | correlate host, client, server, tool, policy, digest, decision, latency, and error without tokens or private content |
| Security testing | pytest, SDK in-memory transport, property/fuzz testing, contract fixtures | preserve every discovered failure as a deterministic regression case |

Do not introduce a policy engine merely to move an `if` statement. It is useful
when organizations need centrally governed rules, decision logs, versioned
bundles, and consistent enforcement across many hosts. The trusted application
still owns input integrity, enforcement, failure behavior, and output checks.

## State of the art and production upgrade path

As of September 2026, the final MCP `2026-07-28` revision uses a stateless core,
`server/discover`, per-request version/capability metadata, cache hints, a common
subscription stream, and an extensions framework. MCP Apps and Tasks are
extensions rather than reasons to grant a server broader core authority. Roots,
Sampling, and Logging are deprecated for new implementations in this revision;
supporting legacy connections requires an explicit compatibility and test
matrix.

For production:

- inventory every server with an owner, purpose, support contact, data classes,
  endpoint/launch spec, digest, provenance, capabilities, review, and expiry;
- verify signed immutable artifacts or controlled remote deployments before use;
- require TLS and exact origin policy for remote servers; constrain OAuth
  discovery and redirects against SSRF;
- obtain tokens per MCP resource and never pass through a token issued for a
  different audience;
- isolate local servers and require explicit consent before executing new
  commands;
- add compatibility suites for every supported protocol revision and SDK;
- subscribe to list-change signals where used, but still refresh and compare;
- make revocation close clients, invalidate caches, revoke credentials, stop
  processes, preserve evidence, and verify containment;
- use OpenTelemetry and security events with retention and access controls; and
- rehearse artifact rollback and unknown-outcome handling.

## Exercises

1. Add a second reviewed server that also exposes `ticket.read`. Prove that its
   host namespace cannot shadow `support.ticket.read`.
2. Classify additive versus breaking schema changes. Write deterministic rules
   and counterexamples showing why “optional field added” can still alter model
   behavior.
3. Replace the in-memory target with a stdio subprocess. Verify the exact command
   before launch, isolate its environment, reserve stdout for protocol frames,
   and test termination on revocation.
4. Add an HTTP transport in a local test environment. Enforce exact origin,
   redirects, timeouts, response size, TLS expectations, and OAuth metadata
   egress policy.
5. Persist review and cache records in a transactional store. Test concurrent
   revocation against an invocation and define which operation wins.
6. Add a side-effecting tool using a single-use approval receipt bound to
   principal, tenant, server ID, exact tool, canonical arguments, policy version,
   expiry, and atomic consumption. A Boolean `approved` argument is forbidden.
7. Design a capability-diff review UI that shows exact launch command, digest,
   owner, added/removed tools, schema paths, resources, prompts, annotations,
   cache changes, and reviewer decision without rendering server HTML.
8. Add property tests for cursor loops, large metadata, Unicode names,
   case-sensitive collisions, and canonicalization stability.

## Checkpoint

A reviewed server changes only three things: `readOnlyHint` from true to false,
one optional string property in a tool schema, and `cacheScope` from private to
public. The tool names and artifact version stay the same.

Explain:

1. why all three changes belong in the capability diff;
2. why neither the old annotation nor the unchanged version grants authority;
3. what must happen before the new snapshot reaches a model;
4. which existing cache entries must be invalidated; and
5. which host- and server-side checks still apply to the next invocation.

An acceptable answer identifies the metadata as untrusted, denies by default,
requires an explicit reviewed update tied to the verified deployment, retains
authorization-context isolation, invalidates the old snapshot, and revalidates
identity, permission, arguments, server authorization, result, and audit state.

## Authoritative references

- [MCP 2026-07-28 versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP server discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Official Python SDK client guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/client/index.md)
- [Official Python SDK protocol-version guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/protocol-versions.md)
- [Official Python SDK caching guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/client/caching.md)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [SLSA provenance](https://slsa.dev/spec/v1.2/provenance)
- [Sigstore documentation](https://docs.sigstore.dev/)
- [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/)
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
