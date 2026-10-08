# MCP Server Registry, Discovery, Trust, and Enterprise Gateways

Server discovery makes an MCP integration findable. It does not make the
integration trustworthy, approved, correctly deployed, or authorized for a
particular user. This course builds the enterprise control plane between those
two states and tests whether its decisions survive drift, multi-tenant routing,
gateway bypass, stale caches, and emergency revocation.

## Course thesis

```text
public catalog / server.json / server discovery -> proposes metadata
enterprise review pipeline                      -> verifies evidence
private trust registry                          -> records bounded approval
host and gateway                                -> enforce the current approval
MCP server / downstream API                     -> authorize independently
observed effect                                 -> establishes the outcome
```

The governing invariant is:

> Discovery is untrusted metadata. Only a current, evidence-backed enterprise
> record may enable a server, and no registry or gateway decision replaces
> authorization at the resource that performs the effect.

Level: advanced. Complete Courses 1–16 first, especially authentication,
authorization, supply-chain provenance, release gates, testing, red teaming,
and continuous assurance.

Standards and product status in this course were checked on **2026-10-07**.
The official MCP Registry and several commercial catalog/gateway features are
still evolving; pin versions and re-check linked product documentation before a
production decision.

## Learning objectives

By the end, you can:

1. distinguish public discovery metadata, package identity, deployed workload
   identity, reviewed capability contracts, and runtime authorization;
2. explain what official MCP Registry publication and namespace verification do
   and do not establish;
3. design a tenant- and environment-scoped trust record that binds an exact
   server version, artifact, endpoint, workload, contract, evidence, owner,
   grants, review window, and lifecycle state;
4. build signed, ordered registry snapshots and reject tampering, rollback,
   equivocation, incomplete replacement, expiry, and stale caches;
5. place an enterprise gateway in the architecture without creating a universal
   credential broker, cross-tenant confused deputy, or single bypassable policy
   point;
6. use MCP 2026-07-28 routing metadata, OAuth protected-resource metadata,
   enterprise-managed authorization, and workload identity safely;
7. test artifact, endpoint, workload, capability-contract, and tenant drift with
   independent outcome oracles;
8. measure decision accuracy, unsafe allows, false blocks, safe-task completion,
   registry consistency, and revocation propagation; and
9. evaluate common registries, SDKs, policy engines, proxies, workload identity,
   provenance, observability, and vendor gateway products by control need.

## 1. Four identities, four different claims

An enterprise deployment usually has at least four related identifiers. Do not
collapse them into one “trusted server” label.

| Object | Example | What it can establish | What it cannot establish alone |
|---|---|---|---|
| discovery entry | `com.acme/support` version `3.4.1` | a publisher advertised metadata | safe code, enterprise approval, current deployment |
| package/artifact | OCI or package digest | exact bytes or package version | who may run it, current runtime identity |
| deployed workload | `spiffe://corp.example/prod/mcp/support` | authenticated running workload under a trust domain | reviewed capabilities or user authorization |
| protected resource | `https://support-mcp.example.test/mcp` | OAuth audience/resource identifier | that a token may access every tenant or tool |

A repository URL is another useful stable reference, but neither repository
ownership nor a namespace login proves that the published package came from a
reviewed source revision. Bind the edges explicitly:

```text
server name + version
    -> package coordinates + immutable artifact digest
    -> source repository + revision + provenance statement
    -> reviewed MCP contract digest
    -> approved endpoint + workload identity
    -> tenant/environment grants
```

Missing edges create substitution opportunities. An attacker may keep a trusted
name while changing a package, keep the package while swapping an endpoint, or
keep the endpoint while deploying an unreviewed workload.

## 2. Discovery is not admission

Discovery answers “what claims to exist?” Admission answers “what exact thing
may this enterprise use, where, for whom, until when, and with which
capabilities?”

| Discovery plane | Enterprise trust plane |
|---|---|
| optimized for findability | optimized for enforceable approval |
| publisher-supplied descriptions and install data | independently verified evidence and policy |
| commonly public and ecosystem-wide | private, tenant/environment scoped |
| mutable listings and version histories | immutable revisions and explicit transitions |
| namespace or publisher authentication | artifact, source, workload, endpoint, contract, owner, risk review |
| may say active/deprecated/deleted | active/deprecated/quarantined/revoked with local meaning |

Treat titles, descriptions, repository URLs, package coordinates, environment
variables, remotes, icons, documentation, and extension fields as untrusted
input. Validate schema and length; prevent stored script injection; restrict
fetching and redirects; and never execute install instructions during catalog
ingestion.

### Official MCP Registry: current role

The official Registry is a preview, public metadata repository. It exposes a
generic Registry-compatible API, uses `server.json`, supports version history
and incremental synchronization, and authenticates publishers into GitHub or
reverse-DNS namespaces. Its docs position downstream aggregators and
subregistries as the normal way to add richer search, curation, or organizational
policy.

Publication authentication establishes control of an allowed namespace at the
time of publication. It does **not** prove:

- that the package bytes are non-malicious;
- that the source repository produced those bytes;
- that declared tools match the running server;
- that a remote endpoint runs the declared artifact;
- that the publisher is approved by your enterprise;
- that the server may process a specific data class or tenant; or
- that a current user may invoke a particular tool.

The official API status values (`active`, `deprecated`, `deleted`) are discovery
signals. An enterprise needs its own `quarantined` and `revoked` states, reason
codes, evidence retention, approval separation, and incident workflow. A public
entry becoming active must never reactivate a locally revoked record.

### `server.json`, package metadata, and the live contract

`server.json` identifies a logical server version and how consumers may obtain
or reach it. Package registries identify package versions. The live MCP
`tools/list`, `resources/list`, and `prompts/list` responses describe the
currently exposed protocol contract. These are related but independent.

For strict admission:

1. validate `server.json` with a pinned schema/tool version;
2. require exact package versions and immutable digest evidence;
3. verify signature identity, issuer, workflow/source, provenance subject,
   materials, and build policy;
4. evaluate the SBOM and vulnerability evidence bound to the same artifact;
5. run the artifact in an isolated review environment;
6. retrieve and canonicalize the complete MCP contract;
7. compare the contract with the requested grants and data classification;
8. test safe tasks and adversarial cases with an independent effect oracle; and
9. issue an enterprise record only after all mandatory evidence passes.

“Latest” may be useful for browsing. It is not a production pin.

## 3. Threat model

| Threat | Boundary crossed | Required control | Lab case |
|---|---|---|---|
| typosquat or misleading publisher | public registry to review | trusted source policy, namespace/repository review | metadata validation |
| valid publisher ships different bytes | build to package | digest, signature, provenance, SBOM, promotion recheck | `artifact-drift` |
| endpoint reassignment or DNS/proxy error | registry to network | exact HTTPS resource, TLS, endpoint binding | `endpoint-swap` |
| wrong runtime behind a valid endpoint | network to workload | authenticated workload identity, deployment evidence | `workload-identity-drift` |
| tool/schema/description changes | server to host | complete contract digest and re-review | `contract-drift` |
| model or caller claims another tenant | model to gateway | tenant from authenticated application context | `wrong-tenant-record` |
| broad incoming token is forwarded | gateway to server/API | audience-bound token exchange and scope narrowing | token tests |
| host cache outlives review | registry to host | signed snapshot, max age, expiry, fail closed | `stale-cache` |
| rollback to an old signed snapshot | control plane to host | monotonic epoch and durable last-seen state | snapshot tests |
| two states share one epoch | distributed registry | state digest, consistency monitoring, stop serving | equivocation test |
| gateway is bypassed | client to server | server-side authentication, authorization, network controls | direct bypass |
| revocation reaches one layer only | control plane to data plane | host, gateway, server, token, connection, credential invalidation | revocation exercise |
| gateway outage | data plane | explicit fail-closed policy and safe degraded mode | denial behavior |
| compromised reviewer | human/control plane | separation of duties, signed audit, bounded approvals | lifecycle tests |

Threat-model the registry itself: publisher auth, metadata parsing, namespace
verification, outbound fetches, UI rendering, storage, administrator actions,
signing keys, snapshot distribution, audit retention, and backup restoration are
all security boundaries.

## 4. Enterprise reference architecture

```text
Official Registry / vendor catalogs / internal submissions
                         |
                 untrusted ingestion
                         v
     schema validation + normalization + duplicate detection
                         |
     source/artifact/provenance/SBOM/vulnerability verification
                         |
       isolated contract inspection + safe/adversarial evaluation
                         |
         risk, privacy, owner, data and incident review
                         v
              private trust registry (authoritative)
                 | signed ordered snapshots
          +------+--------------------+
          |                           |
    host trust cache            resource-server view
          |                           |
authenticated user -> gateway -> authenticated MCP workload -> downstream API
                    |                    |                        |
              policy + exchange    independent authz       independent authz
                    \________________ audit/effect evidence ________________/
```

The control plane may be centralized while enforcement is distributed. Every
enforcement point needs authenticated input, a bounded consistency model, and a
defined action when the registry cannot be reached.

### Private registry record

The lab record binds:

| Field | Why it is security relevant |
|---|---|
| tenant and environment | prevents cross-tenant and dev-to-prod reuse |
| canonical server name and exact version | removes mutable-version ambiguity |
| artifact digest | identifies reviewed executable bytes |
| repository identity and source revision evidence | binds package to source |
| provenance, SBOM, and scan digests | binds review evidence to the artifact |
| endpoint/resource identifier | binds routing and OAuth audience |
| workload identity | authenticates the runtime behind the endpoint |
| complete contract digest | detects tools, descriptions, schemas, and annotations drift |
| grants | maps enterprise capability to server tool, permission, and downstream scope |
| owner, incident contact, data class, sandbox profile | creates operational accountability |
| review and expiry timestamps | bounds trust in time |
| status, revision, reason, actor | supports governed lifecycle and audit |
| previous-record digest | makes record history tamper-evident |
| record digest and signature | protects distribution integrity |

The demonstration uses HMAC signatures so it is deterministic and offline. In
production, use a protected asymmetric signing service, publish verification
keys with rotation metadata, separate signers from storage administrators, and
log signing operations. A signature proves integrity and signer identity, not
that the signer made a correct decision.

### Capability grants

Do not grant a server as one indivisible unit. Bind a human-owned business
capability to all enforcement dimensions:

```text
support.ticket.read
  -> MCP tool: ticket.read
  -> application permission: ticket.read
  -> downstream OAuth scope: ticket:read
  -> reviewed input/output schemas
  -> tenant and environment
```

The intersection matters. A tool advertised by the server but absent from the
record is unavailable. A recorded grant without the caller permission is
unavailable. A valid downstream scope still does not replace resource ownership
and tenant checks.

## 5. Admission and lifecycle

### Evidence-backed admission pipeline

1. **Receive** a candidate without executing it.
2. **Normalize** identifiers, URLs, versions, package coordinates, and extension
   fields. Reject ambiguity rather than guessing.
3. **Verify publisher context** and enterprise supplier policy.
4. **Resolve exact bytes** and calculate an immutable digest.
5. **Verify supply-chain evidence** against expected signer, issuer, source,
   revision, builder, workflow, subject, and materials.
6. **Assess dependencies** with an SBOM and time-bounded vulnerability decision.
7. **Inspect in isolation** using least privilege, synthetic data, egress
   restrictions, resource budgets, and independent effect observers.
8. **Hash the complete MCP contract**, including descriptive and schema fields
   that affect model/client behavior.
9. **Map capabilities** to permissions, scopes, data classes, and required
   approvals. Never import publisher descriptions as policy.
10. **Review operations**: owner, incident contact, telemetry, isolation,
    revocation, credential rotation, recovery, and expiry.
11. **Issue** a signed tenant/environment record under optimistic concurrency.
12. **Distribute** an ordered signed snapshot and require acknowledgement from
    hosts, gateways, and resource servers.

No step should silently fill a missing security field from publisher-controlled
metadata.

### State machine

```text
candidate --reviewed admission--> active
active -------------------------> deprecated
active/deprecated --------------> quarantined
active/deprecated/quarantined --> revoked (terminal for that record)
quarantined --new evidence------> new active record/revision
```

Deprecation is not revocation. Decide whether existing pinned consumers may
continue and for how long. Quarantine reduces authority while facts are being
established. Revocation is terminal for the approved record; recovery creates a
new evidence-backed record rather than editing history or toggling the old one
back to active.

Use compare-and-swap on revisions. Without an expected revision, an older review
or incident action can overwrite a newer one.

## 6. Snapshot consistency and caches

A host cache is an authorization cache, not a convenience cache. A safe snapshot
contains at least an epoch, issue time, expiry, complete record set or explicit
delta semantics, state digest, signature, and key identifier.

Consumers should:

- verify the signature before parsing records into active state;
- verify each record digest, signature, chain, schema, and uniqueness;
- build replacement state off-path and swap it atomically only after all checks;
- persist the highest accepted epoch across restarts;
- reject lower epochs and same-epoch different state;
- allow same-epoch same-state reissuance only under an explicit policy;
- reject snapshots issued unreasonably in the future;
- fail closed when the snapshot or record review expires; and
- expose current epoch, age, refresh failures, and rejected updates as telemetry.

Do not partially apply a snapshot. One malformed record must not leave half the
fleet on a new policy state.

### Availability trade-off

Choose the maximum offline age from risk, not convenience. A read-only,
low-sensitivity capability may tolerate a short last-known-good window. A
financial write or emergency-revoked server may require immediate fail-closed
behavior. Document the policy per capability and test control-plane partitions.

## 7. Revocation is a distributed operation

Changing a database row is not completed revocation. Define and measure:

```text
t0 incident decision
t1 authoritative record changed and signed
t2 host/gateway caches reject new calls
t3 resource servers reject old registry bindings
t4 child tokens, sessions, credentials, and connections invalidated
t5 in-flight effects reconciled and evidence preserved
```

The lab models `t1` through `t3`, propagates the signed epoch in 25 ms, revokes
the record-bound child authority, proves the second call is denied, and checks
that the effect counter remains one. It does not claim to model a real network,
key-management service, connection drain, or external API.

Useful revocation SLOs include p50/p95/p99 decision-to-enforcement latency,
fleet acknowledgement percentage, stale-authority attempts, accepted calls
after `t0`, open connections using revoked authority, and reconciliation age.

## 8. What an enterprise gateway should do

A gateway is useful for consistent transport, routing, rate limits, protocol
validation, identity propagation, token exchange, audit, redaction, policy
enforcement, and revocation. It is not a substitute for workload identity,
server authorization, sandboxing, or downstream API policy.

The lab gateway performs this order:

1. validate request identifiers, method, server name, version, and protocol;
2. use the authenticated principal's tenant, ignoring caller/model tenant claims;
3. resolve a current active record from the signed host cache;
4. authenticate and bind endpoint, workload, artifact, and live contract;
5. require an exposed enterprise capability and caller permission;
6. validate arguments with a typed schema;
7. apply a bounded rate limit;
8. mint a short-lived child token for the exact server audience and narrow scope;
9. call the real MCP SDK server;
10. require the resource server to validate token, record, tenant, and ownership;
11. validate the structured result; and
12. emit a privacy-minimized decision record.

### Do not pass through access tokens

An access token for the gateway or MCP resource must not be forwarded to a
different downstream API merely because its signature is valid. Obtain or
exchange a token for the exact resource audience and narrow it to the required
scope, caller, tenant, purpose, lifetime, and approved registry record. The
downstream API still enforces ownership and policy.

The lab's `TokenBroker` is an offline model of this invariant, not a production
OAuth authorization server. It issues a short-lived audience-bound JWT with
tenant, scope, server, record digest, time, and `jti` claims. Production should
use a standards-compliant authorization server, protected keys, correct token
exchange or workload credential flows, and sender constraints where supported.

### MCP 2026-07-28 at a gateway

The 2026-07-28 protocol core is stateless: the old `initialize`/`initialized`
exchange and MCP session header are not part of this revision. Each request
carries protocol/client metadata. `server/discover` is optional. HTTP routing
metadata such as `Mcp-Method` and `Mcp-Name` lets a gateway route and meter
without parsing a JSON body, but these headers are still request data and do not
authorize a tool.

Validate header/body consistency, normalize paths once, bound request bodies,
reject unsupported revisions, and keep authorization before upstream effects.
Treat `ttlMs` and `cacheScope` on list/read responses as caching hints subject to
stricter enterprise partition and freshness rules.

### Authentication and authorization

- Use OAuth protected-resource metadata and validate that its `resource` exactly
  matches the intended resource identifier.
- Request tokens for the exact resource indicator and validate issuer, audience,
  signature, time, client/actor binding, and scopes.
- Prevent authorization-server mix-up and SSRF when retrieving metadata.
- Enterprise-Managed Authorization can centralize user provisioning through an
  IdP and the ID-JAG exchange. It does not turn the gateway into the final
  application authorization decision.
- Authenticate workloads independently. SPIFFE/SPIRE can issue short-lived SVIDs
  and stream trust bundles; prefer X.509-SVIDs where possible and scope every
  federated bundle to its declared trust domain.
- Authenticate the human/app principal and the workload separately. One does not
  imply the other.

### Bypass and compromise

If the server is reachable around the gateway, it must still reject unauthenticated
or unauthorized requests. Network policy should restrict routes, but the server
must not rely on network location alone. The lab directly calls the MCP tool
without downstream authority and observes a denial.

Assume the gateway can fail or be compromised. Limit its credentials, isolate
tenants, avoid universal service tokens, require downstream checks, preserve
independent audit/effect evidence, and make emergency bypass an explicit,
time-bounded, reviewed path—not a hidden fallback.

## 9. Deployment patterns

| Pattern | Appropriate when | Main risks and controls |
|---|---|---|
| direct remote server | a host can enforce policy and server is independently strong | duplicated controls; require shared registry state and server authz |
| centralized L7 gateway | many clients need common routing, exchange, limits, and audit | concentration/bypass; isolate tenants and keep downstream authz |
| sidecar or node proxy | workload identity and local enforcement matter | config drift; attest deployment and distribute policy safely |
| local stdio gateway | local servers need lifecycle and isolation | host compromise and credential leakage; sandbox processes/containers |
| federated gateways | organizations or trust domains interoperate | issuer/audience/bundle confusion; explicit federation and policy intersection |
| regional gateway fleet | latency and resilience require replicas | consistency and revocation lag; monotonic signed snapshots and SLOs |

Do not force every MCP transport through an HTTP-shaped control if that weakens
the local isolation model. A local server still needs a reviewed launch contract:
exact executable/artifact, minimal environment, explicit mounts, network policy,
resource limits, timeout, credentials, and output validation.

## 10. Common tools and how they fit

| Need | Common tools or standards | Evaluation questions |
|---|---|---|
| public discovery | official MCP Registry, `server.json`, `mcp-publisher`, generic Registry API | preview/compatibility status, namespace policy, sync and deletion semantics |
| private inventory | a generic Registry-compatible service, Azure API Center, internal catalog | auth, metadata extensions, tenancy, evidence links, lifecycle, exportability |
| protocol implementation | official Tier 1 MCP SDKs (Python, TypeScript and current listed SDKs) | supported revision, auth features, schema handling, observability, update policy |
| OAuth | RFC 9728, RFC 8707, authorization-server metadata, MCP auth, EMA | resource binding, issuer mix-up, DCR, client type, scope step-up, token exchange |
| workload identity | SPIFFE/SPIRE, service-mesh or cloud workload identity | attestation source, rotation, trust-domain boundaries, federation, revocation |
| artifact trust | OCI/package digests, Sigstore/Cosign, SLSA provenance, CycloneDX/SPDX | exact subject, signer/issuer, source/build policy, SBOM correlation, promotion recheck |
| policy decision | OPA/Rego, Cedar, cloud/vendor policy engines | typed input, default deny, versioning, obligations, testability, decision logs |
| proxy enforcement | Envoy `ext_authz`, API gateways, service mesh | request normalization, fail-open setting, body limits, identity source, bypass paths |
| MCP gateway/runtime | Docker MCP Gateway/Toolkit, Azure API Management and other products | product maturity, isolation boundary, credential model, tool controls, protocol fidelity |
| telemetry | OpenTelemetry Collector, metrics backend, security lake/SIEM | authenticated emitters, redaction, bounded cardinality, durable audit, effect evidence |

Product presence in this table is not an endorsement. For example, Docker's MCP
Gateway documents container isolation, lifecycle, credentials, profiles, and
tracing, while some governance features are invite-only or early access. Azure
API Center documents registry-compatible organizational discovery and APIM
synchronization. Verify current region, tier, preview, protocol, identity, and
control limitations against your requirements.

Envoy's external authorization filter defaults to denying when its authorization
service fails unless `failure_mode_allow` is enabled. Confirm that configuration
explicitly, place authorization early in the filter chain, normalize the same
path the upstream uses, and test partial-body and header mutation behavior.

## 11. Practical lab

The lab uses the official Python MCP SDK in memory. No network service, cloud
account, production registry, or real credential is contacted.

From the repository root:

```bash
uv sync --extra contributor
uv run python curriculum/advanced/17-server-registry-discovery-trust-enterprise-gateways/lab.py
uv run pytest -q tests/test_course_17_registry_gateway.py
```

The code demonstrates:

- public metadata that has no enablement authority;
- evidence-backed tenant/environment admission;
- signed, chained records and signed complete snapshots;
- atomic host cache replacement and independent resource-server trust state;
- rollback, equivocation, future, stale, inactive, and expired-state denial;
- a real MCP `tools/list` contract digest and `tools/call` execution;
- typed input and output validation;
- authenticated principal context that overrides caller/model claims;
- artifact, endpoint, workload, and live-contract drift denial;
- short-lived audience-bound child authority with no token passthrough;
- independent resource-server token, registry, tenant, and ownership checks;
- direct-gateway-bypass denial;
- rate limiting and privacy-minimized audit records;
- labelled valid and adversarial cases with outcome metrics; and
- evidence-backed revocation with measured propagation and no second effect.

The in-memory transport proves real SDK protocol behavior, not TLS, DNS,
container isolation, a network gateway, an OAuth exchange, SPIFFE attestation, or
distributed consistency. Those boundaries require integration and deployment
tests.

### Core exercises

1. Run the notebook and explain why the public metadata is insufficient for
   admission.
2. Tamper with one signed record field without re-signing. Confirm the host
   rejects the entire snapshot and keeps its prior state.
3. Re-sign a different state at the same epoch. Confirm equivocation is rejected.
4. Execute the approved ticket read, then change the artifact, endpoint,
   workload, and live tool contract one at a time.
5. Send a caller-controlled tenant and bearer token. Confirm neither becomes
   trusted context.
6. Call the server directly without the child token. Confirm the server rejects
   the bypass.
7. Revoke the record, synchronize both enforcement views, and verify that the
   previously usable path performs no additional effect.
8. Inspect the audit event and identify which fields are pseudonymous, digested,
   trusted, and untrusted.

### Advanced extensions

- Replace HMAC record signing with an asymmetric test key and a `kid`-aware
  verification set. Test overlap during rotation and unknown/retired keys.
- Implement an append-only transparency log with inclusion and consistency
  proofs, then compare it with the lab's hash chain.
- Add delta synchronization with a signed base epoch and prove that missed or
  reordered deltas cannot create partial state.
- Put Envoy plus OPA in front of a networked test MCP server. Prove fail-closed
  behavior, path normalization, request-body limits, and bypass prevention.
- Integrate a local SPIRE test environment and bind the accepted X.509-SVID to
  the registry workload ID.
- Use an authorization server to exchange incoming authority for an
  audience-bound child token. Test issuer mix-up, wrong resource, over-broad
  scope, replay, and revocation.
- Ingest a real Registry API fixture into a quarantine namespace. Never install
  or execute packages during ingestion.
- Chaos-test registry partitions, signing-key rotation, clock skew, rolling
  deployment, gateway restart, connection drain, and regional lag.

## 12. Evaluation and metrics

A useful campaign contains labelled safe tasks and labelled unsafe attempts.
The lab reports:

```text
decision accuracy       = correct decisions / all labelled cases
unsafe allow rate       = allowed unsafe cases / all unsafe cases
false block rate        = denied valid cases / all valid cases
safe-task completion    = valid cases with expected effect / all valid cases
```

Also operate:

- public candidates blocked until review;
- admission lead time and reviewer queue age;
- evidence expiry and exception expiry;
- contract/artifact/endpoint/workload drift detections;
- registry epoch convergence and rejected snapshots;
- cache age by host/gateway/server;
- revocation propagation p50/p95/p99 and accepted effects after revocation;
- gateway bypass attempts and direct-server accepts;
- token exchange failures, wrong-audience denials, and replay detections;
- per-tenant rate-limit and routing errors;
- security decision/audit delivery completeness; and
- safe-task completion by capability, tenant, and release.

Zero observed unsafe effects is a bounded result, not proof of zero risk. Report
case coverage, versions, environment, budgets, failures, and uncertainty.

## 13. Production readiness checklist

### Registry and admission

- [ ] Public metadata is treated as untrusted and safely rendered/fetched.
- [ ] Names, versions, package coordinates, repository, and source revision are exact.
- [ ] Artifact digest is recomputed at review and promotion.
- [ ] Signature/provenance policy checks identity, issuer, subject, build, and source.
- [ ] SBOM and findings bind to the same artifact and have governed exceptions.
- [ ] Complete live MCP contract is canonicalized, hashed, reviewed, and tested.
- [ ] Grants map tools to enterprise permissions and downstream scopes.
- [ ] Owner, incident contact, data class, isolation, telemetry, and recovery exist.
- [ ] Review has an expiry and material changes require re-admission.

### Distribution and lifecycle

- [ ] Records and snapshots are versioned, signed, ordered, and independently verified.
- [ ] Consumers persist last accepted epoch and reject rollback/equivocation.
- [ ] Snapshot application is atomic and complete.
- [ ] Cache max age and outage behavior are defined per risk class.
- [ ] Quarantine, deprecation, revocation, and re-admission semantics are distinct.
- [ ] Revocation reaches hosts, gateways, servers, tokens, credentials, and connections.
- [ ] Restore procedures preserve epoch monotonicity and do not resurrect revocations.

### Gateway and resource server

- [ ] Principal and tenant come from authenticated context, not MCP arguments.
- [ ] Endpoint and workload identity are authenticated and registry-bound.
- [ ] Protocol/header/body normalization is consistent and bounded.
- [ ] Policy, rate limit, and audit are tenant/environment partitioned.
- [ ] Incoming tokens are not passed through to another resource.
- [ ] Child authority is audience-, scope-, caller-, tenant-, purpose-, and time-bounded.
- [ ] MCP server and downstream API independently authorize ownership and effects.
- [ ] Network policy limits bypass, while direct requests still fail authentication.
- [ ] Gateway failure and emergency access are explicit, tested, and monitored.

### Assurance and operations

- [ ] Safe and adversarial cases use independent effect oracles.
- [ ] Drift and revocation regressions run on every release.
- [ ] Privacy-minimized audit includes policy, record, artifact, contract, and reason.
- [ ] Signing keys, workload roots, OAuth keys, and credentials rotate safely.
- [ ] Metrics cover both unsafe allows and false blocks.
- [ ] Incident rehearsal proves containment, evidence preservation, and recovery.

## 14. Failure modes to review explicitly

- **Namespace equals safety:** publisher authentication is mistaken for artifact
  or enterprise trust.
- **Name-only allowlist:** version, digest, endpoint, workload, or contract can
  change under a familiar server name.
- **Mutable latest:** production silently consumes an unreviewed release.
- **Signed but semantically wrong:** signatures pass while source, builder,
  subject, or intended environment does not.
- **Partial snapshot:** consumers mix old and new policy after one invalid record.
- **Memory-only epoch:** a restart accepts a replayed older signed snapshot.
- **Stale allow:** an availability-oriented cache survives review expiry or
  emergency revocation.
- **Gateway as identity oracle:** the server trusts forwarded claims without
  authenticating their source.
- **Token passthrough:** one audience's bearer credential is reused at another.
- **Universal service credential:** the gateway's authority exceeds every user
  and tenant it represents.
- **Proxy-only authorization:** a reachable upstream performs effects when the
  gateway is bypassed.
- **Fail-open dependency:** policy or registry outage converts uncertainty into
  new authority.
- **Self-reported outcome:** a denial response is accepted even though an
  independent sink shows the effect completed.

## Authoritative references

### MCP protocol and Registry

- [MCP 2026-07-28 release and protocol changes](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP specification: architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture)
- [MCP specification: authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Enterprise-Managed Authorization](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [Official MCP Registry documentation](https://github.com/modelcontextprotocol/registry/tree/main/docs)
- [Official Registry API](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md)
- [Generic Registry OpenAPI specification](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/openapi.yaml)
- [`server.json` reference](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md)
- [Registry authorization guidance](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/registry-authorization.md)
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

### Identity, authorization, and policy

- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/)
- [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
- [SPIFFE federation](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/)
- [Cedar policy language documentation](https://docs.cedarpolicy.com/)
- [Envoy external authorization](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter)

### Supply chain, gateways, and operations

- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [SLSA specification](https://slsa.dev/spec/)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
- [Azure API Center MCP inventory and registry](https://learn.microsoft.com/en-us/azure/api-center/register-discover-mcp-server)
- [OpenTelemetry specification](https://opentelemetry.io/docs/specs/otel/)

## Knowledge check

1. Why does namespace authentication not prove that an MCP server is safe?
2. Which exact edges must bind a discovery entry to a deployed workload?
3. Why must a host persist the highest accepted registry epoch?
4. What is the difference between deprecation, quarantine, and revocation?
5. Which claims should a gateway-generated downstream token contain, and which
   resource must validate them?
6. Why does an authenticated gateway not remove server-side tenant checks?
7. Which independent observation proves whether a forbidden effect occurred?
8. What would you measure to show that revocation works across a fleet?
