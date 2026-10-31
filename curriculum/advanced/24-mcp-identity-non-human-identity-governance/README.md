# MCP Identity and Non-Human Identity Governance

## Course thesis

Every MCP host, client, server, agent, gateway, CI job, and service account is
an independently governed principal. A trustworthy system derives its runtime
identity from attested workload state, issues only short-lived and narrowly
bound credentials, attenuates delegated authority at every hop, and can prove
ownership, use, rotation, revocation, and decommissioning from independent
evidence.

An identifier is not proof. A signed token is not sufficient authorization.
An MCP client name is not an authenticated principal. A service account is not
an owner. Governance connects these distinct facts and keeps them current.

## Learning objectives

By the end of this course, you will be able to:

1. inventory human and non-human principals across an MCP request path;
2. distinguish workload identity, OAuth client identity, human identity,
   deployment identity, artifact identity, and delegated authority;
3. design an ownership and lifecycle record that supports join, change,
   rotation, suspension, revocation, and decommissioning;
4. bind identity issuance to workload attestation, tenant, environment,
   immutable artifact, and runtime selectors;
5. issue and verify short-lived, audience-, scope-, purpose-, and
   sender-bound credentials with common JOSE libraries;
6. exchange rather than pass through tokens when an MCP server calls a
   downstream API;
7. enforce separation of duties and exact approval binding for identity
   creation or privilege change;
8. reconcile desired inventory, the identity registry, and runtime
   observations to find shadow, orphaned, stale, or drifting identities;
9. design revocation and rotation with measurable convergence; and
10. evaluate governance effectiveness with explicit denominators and
    adversarial cases rather than configuration screenshots.

## Prerequisites and timebox

Complete Courses 6, 7, 8, 17, 18, 21, 22, and 23 first. You should understand
OAuth access tokens, policy enforcement, token exchange, registries,
delegation, incident response, recovery, and enterprise architecture.

Suggested time: 90 minutes reading, 120 minutes lab and notebook, and 45
minutes for the production design exercise.

## Scenario

Acme operates a support MCP service in Kubernetes. A desktop host invokes an
enterprise gateway. The gateway calls an MCP support server, which reads a
ticket API. CI builds and deploys the server. Platform engineering owns the
runtime; security approves production identity boundaries; the application
team owns business authorization.

The identity path is:

```text
human analyst
  │ authenticated session and delegated business authority
  ▼
MCP host ── OAuth client identity ──► enterprise gateway
                                         │ attested gateway workload
                                         ▼
                                   MCP support server
                                         │ exchanged, attenuated token
                                         ▼
                                      ticket API

CI job ── build identity/provenance ──► immutable server artifact
runtime platform ── attestation ──► workload credential issuer
registry/HR/CMDB ── ownership and lifecycle ──► policy + review
telemetry/runtime inventory ── evidence ──► reconciliation + response
```

The lab is deterministic, local, and credential-free. It uses PyJWT and
`cryptography` with ephemeral Ed25519 keys. Its in-memory attestor, registry,
approval service, and revocation state are teaching fixtures—not substitutes
for SPIRE, an enterprise IdP, KMS/HSM-backed signing, a durable policy store,
or a production inventory system.

## 1. Identity is a set of claims, not one string

The phrase “non-human identity” is useful for governance, but too broad for an
enforcement decision. Keep these identity planes separate:

| Plane | Example | What establishes it | What it must not imply |
|---|---|---|---|
| Human | analyst `u-42` | enterprise IdP session | workload integrity |
| MCP OAuth client | desktop app client ID | validated registration and issuer metadata | user consent or server privilege |
| Workload | SPIFFE ID for support server | platform attestation and SVID | business permission by itself |
| Service instance | Kubernetes Pod UID | trusted runtime observation | stable service ownership |
| Service | support MCP server | governed registry record | identity of every replica |
| Artifact | image digest `sha256:…` | verified build provenance | authorization to deploy or run |
| Deployment | production release | delivery system evidence | ongoing runtime health |
| Delegated actor | human plus gateway chain | validated, attenuated grant | the server's full service authority |
| Telemetry source | OTel service instance | authenticated exporter and resource attributes | proof that logged content is true |

A production decision usually needs several planes: authenticated caller,
attested workload, current registry record, tenant, purpose, requested action,
resource ownership, current policy, and sometimes exact human approval.

### Modern MCP consequences

The 2026-07-28 MCP lifecycle is stateless at the protocol layer. Version,
client information, and capabilities travel on each request. Treat
`clientInfo`, `_meta`, `Mcp-Method`, and `Mcp-Name` as protocol or routing
inputs, not authenticated workload identity. Re-establish trusted identity and
authorization for every request. An explicit application state handle also
grants no authority by itself.

For HTTP, a protected MCP server is an OAuth resource server. It validates
tokens issued for its canonical resource. It does not mint tokens merely
because it received a plausible client name. For stdio, the host owns process
launch, environment, credential delivery, and operating-system confinement;
the pipe itself provides no authentication or sandbox.

## 2. Threat model

### Protected assets

- signing keys, trust bundles, JWKS, attestor keys, and issuance policy;
- workload identities, service-account bindings, and OAuth client records;
- human-to-workload delegation and downstream access tokens;
- registry records, ownership, approval receipts, and lifecycle state;
- runtime selectors, artifact digests, release evidence, and tenant binding;
- revocation state, credential caches, audit events, and inventory feeds; and
- the ability to distinguish an expected workload from a shadow instance.

### Adversary capabilities

Assume an attacker can steal a bearer token, replay an attestation, edit an
untrusted workload label, deploy an unregistered replica, request broader
scopes, target another audience or tenant, reuse a shared service account,
race a stale registry writer, replay an approval, compromise one workload, and
delay one inventory or revocation feed.

Do not assume the attacker can forge protected Ed25519 signatures, defeat the
platform root of trust without evidence, or write the authoritative registry.
If those assumptions fail, rotate roots and rebuild trust; a policy expression
cannot compensate for a compromised issuer.

### Primary failure modes

| Failure | Consequence | Required control |
|---|---|---|
| shared static credential | no workload attribution; large blast radius | unique attested identity and short lifetime |
| name accepted as identity | spoofed client/server | authenticated transport or signed credential |
| token accepted for wrong audience | cross-service replay | exact issuer and audience validation |
| MCP token passed downstream | confused deputy and audit loss | token exchange or separate downstream grant |
| orphaned owner | no accountable reviewer | active owner and automated separation event |
| wildcard scope/audience | privilege expansion | bounded registry policy and step-up |
| mutable image tag as identity | runtime drift | immutable artifact digest in attestation |
| stale registry write | revocation or scope rollback lost | optimistic version check |
| rotation without overlap plan | outage or fallback to static secret | dual trust window and bounded retirement |
| revocation only in IdP | cached acceptance continues | end-to-end convergence test |
| runtime not reconciled | shadow identity survives | desired/registered/observed three-way diff |

## 3. The governed identity record

Every principal requires a stable record. At minimum, record:

- stable identity URI and identity kind;
- tenant, environment, trust domain, and business purpose;
- accountable owner and backup/escalation team;
- required attestation selectors and immutable artifact digest;
- allowed audiences, scopes/actions, resources, and maximum credential TTL;
- lifecycle state, monotonic version, and revocation epoch;
- creation, last use, last rotation, and next review timestamps;
- credential mechanism and issuing authority;
- dependencies and downstream identities;
- exception, break-glass, and decommission controls; and
- evidence source, freshness objective, and control owner.

The lab's `IdentityRecord` makes these controls executable. Registration
starts from `candidate`, consumes an exact two-person approval, and becomes
`active`. It rejects wildcards, shared identities, missing owners, mutable
artifact references, empty boundaries, and credential lifetimes outside the
course policy.

### Stable identity versus ephemeral instance

A stable service identity supports policy and ownership. A unique instance ID
supports detection and investigation. Keep both. OpenTelemetry's
`service.namespace`, `service.name`, and `service.instance.id` are useful
telemetry dimensions, but they do not replace authentication. A SPIFFE ID can
name a governed workload class; a platform selector or Pod UID can distinguish
the attested instance.

### Never encode volatile authorization in the name

Do not make a name such as `prod-admin-write-all` the policy. Names become
sticky, are hard to rotate, and are often copied into logs and exceptions.
Keep the identifier stable and make authority explicit, versioned, reviewable,
and enforced by policy.

## 4. Lifecycle and control ownership

### Join

1. Identify a business purpose and accountable human owner.
2. Define the trust domain and workload selectors.
3. Pin the immutable artifact and deployment environment.
4. Select exact audiences, scopes, resource constraints, and TTL.
5. Threat-model the issuer, verifier, delegation, and failure paths.
6. Obtain an exact, short-lived, single-use approval from a separate role.
7. Deploy as a candidate; observe before granting production effects.
8. Activate only after runtime attestation and negative tests pass.

### Change

Owner, selector, artifact, audience, scope, purpose, and TTL changes are
security changes. Bind approval to the complete proposed delta and expected
record version. A successful update increments the version so credentials
from the old contract stop working. Never let a stale writer overwrite a more
recent suspension, revocation, or scope reduction.

### Periodic review

Review current use, not only assigned fields:

- Is the identity observed where expected?
- Is every observed instance registered and attested?
- Do used actions fit the documented purpose?
- Can privileges be narrowed based on evidence?
- Are owner, dependencies, and escalation routes active?
- Are credentials short-lived and automatically rotated?
- Does revocation meet its convergence objective?
- Are exceptions current, bounded, and independently approved?

### Suspend, revoke, decommission

`suspended` is reversible containment; it blocks issuance and use while an
investigation proceeds. `revoked` invalidates the trust relationship and
increments a revocation epoch. `decommissioned` is terminal and requires the
runtime, registry, policies, secrets, credentials, routes, caches, monitoring,
and ownership entries to be removed or archived coherently.

Deletion alone is poor evidence. Preserve the authorized change, execution
result, convergence measurement, and final absence from runtime inventory.

## 5. Workload attestation and SPIFFE/SPIRE

SPIFFE defines a workload identity, SVID formats, the Workload API, trust
bundles, and federation. SPIRE is a common implementation. A workload receives
an identity after node and workload attestation rather than reading a shared
secret baked into an image.

The lab's `WorkloadAttestor` signs evidence containing:

- the workload and tenant identity;
- trust domain;
- required runtime selectors;
- immutable artifact digest;
- observation time; and
- a nonce for freshness and replay defense.

Issuance verifies signature, freshness, nonce, exact identity/tenant/trust
domain, required selector inclusion, and artifact equality. This is a compact
analogue, not a full SPIFFE implementation. In production, protect roots in a
KMS/HSM, harden agent sockets, validate node attestation, rotate trust bundles,
monitor registration entries, constrain federation, and test compromised-node
and stale-bundle behavior.

### Kubernetes service accounts

Kubernetes `ServiceAccount` is a non-human identity, but a default or broadly
reused account is not adequate governance. Prefer one account per workload
boundary and projected TokenRequest credentials with explicit audience and
short lifetime. Disable unnecessary automounting. Where external systems
accept Kubernetes credentials, validate object binding and current state with
TokenReview when its stronger revocation behavior is needed. Map the platform
account to the enterprise workload record; do not confuse namespace membership
with application authorization.

### Cloud workload identity federation

AWS IAM Roles Anywhere/IRSA-style patterns, Microsoft Entra workload identity,
and Google Workload Identity Federation can exchange trusted platform evidence
for cloud credentials. The safe pattern is federation without long-lived cloud
keys. Evidence must still bind the expected issuer, subject/selectors,
audience, tenant/project/account, role, session duration, and current policy.

## 6. Credential issuance and verification

The lab uses PyJWT and `cryptography` to create Ed25519-signed access tokens.
It deliberately avoids a custom token parser. A successful issuance requires:

1. an active registry record and active owner;
2. a review date in the future;
3. valid, fresh, unused attestation;
4. an allowed audience;
5. a non-empty scope subset;
6. exact purpose;
7. TTL no longer than the identity maximum;
8. a sender-key thumbprint; and
9. an idempotency key bound to the complete request.

The token contains issuer, subject, exact audience, issued/not-before/expiry
times, JTI, tenant, scope, purpose, identity kind and version, revocation
epoch, policy version, attestation digest, delegation depth, and a `cnf`
sender-binding claim.

The verifier pins the allowed algorithm, signature key, issuer, audience, time,
sender, tenant, purpose, scopes, current identity version, revocation epoch,
lifecycle state, owner, review state, and current policy. Signature validity is
only one check. Never disable audience verification merely to make integration
easier.

### Bearer versus sender-constrained credentials

Short lifetime reduces but does not eliminate replay. A JTI only names a token.
DPoP or mutual-TLS binding requires the presenter to prove possession of a key.
The lab checks a supplied thumbprint to make the binding invariant visible; it
does not implement DPoP proofs or TLS. Production must validate the proof at
the actual resource boundary and protect the private key.

### Idempotency and unknown outcomes

Issuance and revocation cross distributed boundaries. If a caller times out,
retrying under a new operation identity can produce duplicate credentials or
ambiguous state. Bind a stable operation ID to the full request digest. Return
the prior result for an exact retry and reject a conflicting retry. Keep an
auditable journal and reconcile incomplete operations.

## 7. Delegation without token passthrough

An MCP access token is intended for the MCP resource. Passing it unchanged to
a ticket API violates the audience boundary and loses the MCP server's role in
the call chain. Obtain a separate downstream token or use RFC 8693 token
exchange.

For each child grant, intersect:

```text
requested authority
∩ parent token authority
∩ authenticated actor policy
∩ current workload policy
∩ target resource policy
∩ tenant and purpose constraints
```

The lab requires child scopes to be a subset, child lifetime not to exceed the
parent's remaining lifetime, an allowed target audience, a fresh sender
binding, and a bounded delegation depth. It links the child to the parent JTI.
The child resource verifies the child independently. It does not trust an
upstream “already authorized” header.

Human authority and workload authority are also different. A server may be
allowed to call a ticket API, while the initiating analyst may not read that
ticket. Preserve both and enforce the resource's tenant/ownership policy.

## 8. Inventory, ownership, and reconciliation

No single inventory is complete. Reconcile at least three views:

1. desired identities from service catalog and deployment definitions;
2. registered identities and policy bindings from governance systems; and
3. observed identities from runtime, cloud, cluster, gateway, IdP, and logs.

The lab detects:

- desired but unregistered identity;
- observed shadow identity;
- registered but undeclared identity;
- active identity not observed;
- inactive identity still running;
- orphaned owner or overdue review;
- stale or never-used identity;
- shared identity; and
- tenant, selector, or artifact drift.

Treat feeds as evidence with known coverage, freshness, and failure modes. A
missing observation can mean decommissioning, sensor loss, or an evasion. Do
not automatically delete an identity based on one missing feed.

### Owner departure

Human resource or directory separation events should immediately suspend
owner-dependent approval and create reassignment work. A team alias alone is
not enough; retain accountable roles and escalation. For critical identities,
require primary and backup ownership without permitting either to self-approve
their own privilege expansion.

### Break-glass

Emergency access must be exceptional, not a permanent broad identity. Require
a declared incident, narrow audience/action, strong authentication, separate
approval where feasible, very short expiry, prominent monitoring, automatic
revocation, and retrospective review. Never implement break-glass as an
unlogged wildcard service account.

## 9. Rotation and revocation engineering

Rotation is a state transition, not a date field. A safe key or trust-bundle
rotation normally has:

1. generate new protected key material;
2. publish new verification material;
3. verify consumer refresh and cache behavior;
4. issue new credentials;
5. observe successful use of the new key;
6. stop old issuance;
7. retire old acceptance after a bounded overlap; and
8. prove the old credential is rejected everywhere.

Revocation mechanisms differ: short expiry, token introspection, deny lists,
key removal, registry state, trust-bundle update, Kubernetes object deletion,
policy invalidation, and workload termination. Design the combination for the
threat and measure end-to-end convergence at every accepting boundary.

Recommended service objectives:

- emergency suspension visible to every verifier within 60 seconds;
- compromised token JTI blocked within 30 seconds where introspection exists;
- ordinary artifact rotation complete before overlap expiry;
- orphaned critical owner detected within one directory feed interval; and
- shadow production identity alerted within one runtime inventory interval.

These are example objectives, not universal standards. Set them from risk and
test them under cache delay, partition, stale replica, rollback, and partial
failure.

## 10. Common tools and methods

| Need | Common choices | Verify in production |
|---|---|---|
| workload identity | SPIFFE/SPIRE, service mesh identity, cloud workload identity | selectors, trust domain, root protection, federation, rotation |
| Kubernetes identity | ServiceAccount, TokenRequest, projected tokens, TokenReview | unique account, audience, expiry, object binding, RBAC |
| OAuth/OIDC | Keycloak, Entra ID, Okta/Auth0, cloud STS | issuer discovery, audience, client auth, token exchange, revocation |
| JOSE verification | PyJWT/cryptography, jose, Nimbus JOSE, framework middleware | pinned algorithms, key selection, claims, cache refresh, failure mode |
| policy | OPA/Rego, Cedar, Zanzibar-style relationship systems, cloud IAM | trusted inputs, versioning, freshness, obligations, deny behavior |
| secrets and keys | Vault, cloud secret managers, KMS, HSM | workload auth, export policy, rotation, audit, break-glass |
| inventory/governance | IGA, CMDB/service catalog, cloud/cluster inventory, CSPM/CNAPP | coverage, ownership, joins, lag, reconciliation |
| telemetry | OpenTelemetry, IdP logs, cloud audit, Kubernetes audit | source identity, loss, clocks, redaction, immutable retention |
| admission | Kubernetes admission policy, CI gates, signed provenance | digest binding, exception control, deploy/runtime equivalence |

Tool presence proves nothing by itself. A service mesh can issue identities
while application authorization remains broad. A vault can rotate a shared
secret that should not exist. An IGA campaign can certify stale inventory.
Map each claim to an enforcement point, test, telemetry source, and owner.

## 11. Evidence and metrics

Good metrics name a population and outcome:

- inventory coverage = expected identities registered / expected identities;
- runtime governance coverage = observed identities registered / observed identities;
- active owner coverage = active identities with active owners / active identities;
- short-lived coverage = active identities with TTL at or below policy / active identities;
- orphan rate = orphaned identities / registered identities;
- excessive privilege rate = identities violating scope policy / reviewed identities;
- revocation convergence = last confirmed rejection time − authorized revocation time;
- valid-work success = successful labelled legitimate cases / legitimate cases; and
- adversarial block rate = blocked labelled attacks / adversarial cases.

Do not combine “attempted,” “blocked,” “revoked,” and “effect completed.” A
denial log is not proof that the forbidden effect did not happen. Use an
independent outcome oracle such as the protected API's effect ledger.

Audit events should include identity, tenant, issuer, audience, scope, purpose,
policy and identity versions, JTI, parent linkage, decision, stable reason,
trace/correlation ID, and timestamps. Never log raw tokens, private keys,
attestation signatures, or unnecessary personal data.

## 12. Lab walkthrough

From the repository root:

```bash
uv sync --extra contributor --frozen
uv run python curriculum/advanced/24-mcp-identity-non-human-identity-governance/lab.py
uv run pytest -q tests/test_course_24_nonhuman_identity.py
```

The scenario performs these steps:

1. create a candidate SPIFFE-style MCP server record;
2. issue and consume an exact two-person approval;
3. activate the identity;
4. create fresh signed runtime attestation;
5. issue an Ed25519-signed, sender-bound MCP token;
6. independently verify the token for the MCP resource;
7. exchange it for a narrower ticket-API token;
8. verify parent linkage and attenuation;
9. reconcile desired, registered, and observed identity; and
10. report governance metrics and structured audit-event count.

### Adversarial exercises covered by tests

The 55 dedicated tests reject self-approval, unauthorized approvers, approval
replay or mutation, unsafe identity shape, shared identity, wildcards, stale or
tampered attestation, selector/artifact/tenant drift, broad audience or scope,
long lifetime, weak sender binding, conflicting retries, token tampering,
wrong audience/tenant/purpose/sender, expired tokens, insufficient scope,
specific-token revocation, stale identity version, invalid lifecycle state,
delegation expansion, shadow identity, and incomplete metric coverage.

### Production design extension

Replace the fixtures with:

- SPIRE or a cloud workload identity issuer;
- protected signing keys and published rotation metadata;
- an enterprise IdP/STS supporting resource indicators and token exchange;
- a durable, strongly authorized registry and approval workflow;
- real DPoP or mTLS sender constraints where risk justifies them;
- policy enforcement at MCP and downstream resource boundaries;
- OpenTelemetry plus IdP, Kubernetes, cloud, and API outcome evidence; and
- chaos tests for stale caches, partitioned revocation, issuer outage, root
  rotation, owner departure, and unknown operation outcomes.

Then document which claims are proven at which layer. Do not claim that this
local lab proves TLS, Kubernetes admission, SPIFFE federation, HSM protection,
distributed consistency, cloud IAM, or production revocation convergence.

## 13. Review checklist

- [ ] Every MCP and supporting workload has a unique governed identity.
- [ ] Human, OAuth client, workload, artifact, and delegated identities stay distinct.
- [ ] Every active record has an active owner, purpose, tenant, and review date.
- [ ] Runtime issuance requires fresh platform attestation and immutable artifact binding.
- [ ] Credentials are short-lived, audience/scope/purpose/tenant bound, and preferably sender constrained.
- [ ] Resource servers validate issuer, audience, time, current lifecycle, policy, and business authorization.
- [ ] Downstream calls use a separate or exchanged token; passthrough is forbidden.
- [ ] Privilege changes use complete, expiring, single-use, two-person approval.
- [ ] Registry updates use concurrency/version protection.
- [ ] Desired, registered, and observed inventories are reconciled.
- [ ] Owner departure, inactivity, drift, and shadow identity trigger workflows.
- [ ] Rotation and revocation have tested convergence objectives.
- [ ] Telemetry is authenticated, redacted, correlated, and checked for loss.
- [ ] Metrics have explicit populations, denominators, and independent outcomes.
- [ ] Break-glass is narrow, expiring, monitored, and retrospectively reviewed.
- [ ] Decommissioning removes runtime, credentials, policy, routes, caches, and ownership coherently.

## References

### MCP and OAuth

- [MCP 2026-07-28 authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [MCP 2026-07-28 release overview](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP Enterprise-Managed Authorization](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)

### Workload identity and zero trust

- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/)
- [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
- [SPIFFE federation](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
- [SPIRE documentation](https://spiffe.io/docs/latest/deploying/)
- [NIST SP 800-207A: Zero Trust for Cloud-Native Applications](https://csrc.nist.gov/pubs/sp/800/207/a/final)
- [NIST IR 8587: Protecting Tokens and Assertions](https://csrc.nist.gov/pubs/ir/8587/final)
- [Kubernetes Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes Service Account Administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

### Governance and evidence

- [NIST SP 800-53 Rev. 5, Identification and Authentication](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [CISA Identity and Access Management Best Practices](https://www.cisa.gov/sites/default/files/2023-12/ESF%20IDENTITY%20AND%20ACCESS%20MANAGEMENT%20RECOMMENDED%20BEST%20PRACTICES%20FOR%20ADMINISTRATORS%20PP-23-0248_508C.pdf)
- [OpenTelemetry service semantic conventions](https://opentelemetry.io/docs/specs/semconv/resource/service/)
- [SLSA provenance](https://slsa.dev/spec/v1.2/provenance)
