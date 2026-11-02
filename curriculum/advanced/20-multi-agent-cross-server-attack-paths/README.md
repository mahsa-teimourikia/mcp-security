# Multi-Agent and Cross-Server Attack Paths

A collection of individually reviewed agents, MCP servers, gateways, and APIs
can still create an unsafe system. Authority, credentials, content, and network
reachability compose across boundaries. A compromised analytics server may
reuse a shared credential, bypass a gateway, poison shared memory, or exploit a
stale registry binding to reach data its own interface could never access.

This course builds a defensible vertical slice: ingest provenance-backed graph
evidence, enumerate bounded paths with NetworkX, distinguish topological paths
from currently executable paths, measure sensitive blast radius, select
containment candidates without treating a graph heuristic as authority, and
prove containment against current enforcement and independent resource state.

> **Version snapshot (reviewed 2026-10-31):** the course supports NetworkX
> 3.5–3.7 (the resolver keeps 3.11-compatible releases where required) and
> reviews MCP `2026-07-28`, A2A `1.0.1`, NIST SP 800-207,
> MITRE ATT&CK Enterprise lateral movement, and the OWASP Agentic AI Threats
> and Agent Control Standard resources available on the review date. Protocol,
> SDK, graph database, and product versions are different facts. Re-check the
> linked primary sources before using this design as a production baseline.

## Learning objectives

After completing the course, you should be able to:

1. distinguish connectivity, influence, delegated authority, executable access,
   and an observed security effect;
2. build a typed attack graph from registry, IAM, workload identity, network
   policy, approval, trace, inventory, and resource-classification evidence;
3. preserve tenant, audience, action, resource, presenter, artifact, workload,
   freshness, and provenance on every relevant edge;
4. enumerate bounded simple paths without claiming that graph reachability is
   authorization;
5. evaluate paths against the current credential, registry, gateway, egress,
   approval, quarantine, and revocation state;
6. compare a topology-only baseline with a policy-aware attack-path engine;
7. measure exposure and control quality with explicit denominators;
8. use minimum cuts and centrality only as triage hints, then test candidate
   controls at their actual enforcement points;
9. prove containment only after control-plane propagation, zero residual
   executable paths, and zero forbidden effects after the cut; and
10. explain where NetworkX, Neo4j, BloodHound-style identity graphs, OPA or
    Cedar, SPIFFE/SPIRE, OpenTelemetry, SIEMs, and cloud graph inventories fit.

**Prerequisites:** Courses 1–2, 6–8, 10–12, 16–19; Python 3.11+; graph basics;
OAuth audience and scope concepts; and familiarity with MCP gateways and A2A
delegation. Allow 120–150 minutes for reading, notebook, and exercises.

## 1. One graph, several kinds of “path”

The word *path* is dangerously overloaded.

| Path claim | What it means | What proves it | What it does **not** prove |
|---|---|---|---|
| topological | edges connect a source to a target | graph structure | an edge can execute now |
| observed | telemetry recorded a sequence or relation | trace/log provenance | authority or future reachability |
| authorized | policy permits an exact actor/action/resource context | current PEP/PDP decisions | the call occurred |
| executable | every hop passes current identity, network, registry, credential, approval, and resource gates | policy-aware path evaluation | the final effect occurred |
| effect | protected resource state changed or data left a boundary | independent resource/egress ledger | the adapter described it honestly |

An A2A Agent Card or MCP discovery result is descriptive metadata. It does not
grant caller authority. A valid trace context correlates evidence. It does not
authenticate a tenant. A model response can propose a sequence. It cannot make
the sequence executable. The final resource owns the effect.

### Path stages

Use a staged model instead of one undifferentiated `CAN_REACH` relation:

```text
foothold → discovery → credential access → authenticated hop → authorized hop
          → downstream effect → verified data/resource outcome
```

This prevents two common errors:

- **overstatement:** every network route becomes a compromise path; and
- **understatement:** a shared bearer credential or gateway bypass is absent
  because no trace has yet recorded exploitation.

## 2. The graph is a versioned evidence product

An attack graph is only as trustworthy as its inputs. The lab signs a complete
snapshot with an epoch, digest, observation time, assets, edges, and evidence
references. Consumers reject tampering, rollback, future timestamps, stale
snapshots, duplicate identities, unknown endpoints, and edges without evidence.

### Recommended source inventory

| Source | Useful facts | Failure mode to test |
|---|---|---|
| enterprise MCP registry | canonical server, tenant/environment, artifact and workload binding, status | stale cache, revoked record, same name/different bytes |
| A2A registry / Agent Card store | endpoint, skills, protocol version, authenticated peer record | card content mistaken for authorization |
| IAM / authorization server | subject, actor, audience, action, resource, expiry, presenter binding, revocation | wildcard or wrong-audience credential |
| workload identity | SPIFFE ID, certificate/SVID status, deployment identity | endpoint matches but workload does not |
| network policy / service mesh | source–destination route, port, gateway requirement, egress state | direct bypass or DNS/runtime drift |
| approval store | exact effect receipt, approver, expiry, consumed state | Boolean approval or replay |
| inventory / SBOM / deployment | component, artifact digest, owner, version, dependency | approved name resolves to unreviewed artifact |
| OpenTelemetry / audit trail | observed calls, operation/trace join keys, decisions | sampling gap or telemetry treated as authority |
| resource classifier | owner, tenant, sensitivity, criticality | incomplete denominator hides exposed assets |
| independent outcome source | database row, object version, outbox, egress sink | server says “blocked” after effect occurred |

Record `source`, `kind`, `observed_at`, and a digest or immutable version for
every evidence item. “Found in the graph” is not provenance.

### Snapshot acceptance invariants

Before analysis:

1. verify signature and canonical digest;
2. enforce a monotonic epoch and detect same-epoch equivocation;
3. reject stale and implausibly future evidence;
4. validate unique typed node and edge identifiers;
5. resolve every edge endpoint and evidence reference;
6. preserve tenant and environment partitions;
7. retain source confidence and observation type; and
8. record the accepted graph/policy versions with every result.

For production, sign and distribute snapshots through the organization’s
existing control plane and key management. The HMAC key in `lab.py` is an
inspectable training fixture, not a deployment pattern.

## 3. Typed nodes and edges preserve security meaning

The lab models agents, MCP servers, a gateway, APIs, data, and shared memory.
Useful production graphs may also include hosts, cloud identities, queues,
approval services, authorization servers, registries, model endpoints, plugins,
secrets, datasets, and administrative control planes.

### Node properties

- canonical asset identity and type;
- authenticated tenant and environment;
- zone and owner;
- sensitivity and criticality;
- expected OAuth audience and resource identifier;
- exact artifact digest and workload identity for executable servers;
- active, quarantined, or retired state; and
- evidence/version metadata.

### Edge properties

- stable edge ID and typed relation;
- source, target, tenant, action, and exact resource;
- credential, approval, registry, and policy references;
- whether gateway traversal is required;
- ATT&CK/ATLAS or internal technique mapping where justified;
- current enabled state; and
- evidence IDs and observation time.

Do not collapse `INFLUENCES`, `DISCOVERS`, `DELEGATES`, `CALLS`, `READS`, and
`WRITES`. Shared memory or an indirect prompt injection can influence an agent,
but content must not become an authority channel. The lab keeps the influence
edge visible while denying it as an executable authorization step.

## 4. Policy-aware path evaluation

NetworkX `all_simple_paths` enumerates non-repeating node paths with a cutoff.
The number of simple paths can grow factorially, so a production engine also
needs scope, hop, time, result-count, and query-cost budgets.

For each edge in each candidate path, the lab checks this current state:

```text
edge and endpoints active
∩ neither endpoint quarantined
∩ evidence present and fresh
∩ tenant boundary preserved
∩ network route allowed
∩ required gateway traversed
∩ registry tenant/artifact/workload binding exact and active
∩ credential active, unexpired, audience/action/resource/tenant exact
∩ sender constraint satisfied when required
∩ approval exact, unexpired, and unconsumed when required
∩ untrusted content is never interpreted as authority
```

The path is executable only if every edge allows. The protected API or data
service must still enforce its own decision at execution time. A graph result
is analysis, not a capability token.

### Why “shortest path” is not “most likely attack”

A shortest path optimizes a graph weight chosen by the analyst. It does not
automatically encode exploit reliability, credential availability, monitoring,
attacker cost, time, prerequisites, compensating controls, or business impact.
Likewise, a minimum node cut identifies a topological disconnect set. It may
recommend disabling a critical shared gateway and cause a major outage.

Use graph algorithms to rank questions. Validate the answers against current
policy, ownership, service dependency, and effect state.

## 5. Realistic support-platform scenario

The synthetic lab contains:

- a legitimate `triage-agent` using a short-lived sender-bound credential;
- an `analytics-server` assumed compromised;
- an enterprise `mcp-gateway`;
- a registry-bound `support-server`;
- ticket and secrets APIs;
- confidential customer PII and a restricted production secret;
- a shared-memory coordination surface; and
- a rogue server whose display purpose resembles support but whose artifact,
  workload, and active registry binding do not match.

The deliberately unsafe baseline exposes several classes of path:

1. **shared bearer authority:** the compromised server reuses a wildcard
   operations credential to enter the gateway;
2. **transitive service authority:** the gateway and support server then use
   their own downstream credentials, extending blast radius to customer data;
3. **gateway bypass:** a direct route plus the shared credential reaches the
   secrets API;
4. **cross-agent poisoning:** shared memory can influence triage, but the
   policy-aware engine refuses to turn content into authority; and
5. **registry substitution:** a topological route exists to a rogue server,
   but exact active artifact/workload binding denies it.

The hardened state quarantines the compromised server, revokes the shared
credential, blocks dangerous edges, requires gateway traversal, and denies
wildcard credentials. The legitimate triage flow remains executable through
narrow credentials.

## 6. Containment is a distributed-state claim

Changing one database row is the start of containment, not proof of it. A
real response may need to:

- quarantine the compromised workload and stop new sessions;
- revoke affected credentials and signing material;
- disable or revoke the exact registry binding;
- block direct egress and require the enterprise gateway;
- invalidate host, gateway, sidecar, PDP, and SDK caches;
- reconcile in-flight operations and unknown outcomes;
- rotate downstream authority if it may have been copied;
- protect evidence while reducing active authority; and
- verify independent data and egress state after the cut.

The lab represents containment as monotonic revisioned events. A proof requires:

```text
observed control revision >= required revision
AND residual executable paths to protected targets == 0
AND forbidden effects observed after the cut == 0
```

`time_to_cut` is measured from incident start to the timestamp of the fully
propagated control state. It is not a sleep or a self-reported “contained” log.
Course 21 goes deeper into detection, evidence preservation, investigation,
and incident operations; this course stops at path analysis and containment
verification.

## 7. Metrics with honest denominators

### Sensitive exposure rate

```text
reachable labelled sensitive assets / all labelled sensitive assets in scope
```

Report both counts, the classification coverage, source, hop cutoff, graph
epoch, policy revision, and query time. An unclassified asset must not silently
leave the denominator.

### Unsafe-allow rate

```text
executable labelled forbidden cases / all labelled forbidden cases
```

### False-block rate

```text
blocked labelled valid cases / all labelled valid cases
```

Also report maximum reachable criticality, residual path count, stale evidence
count, unowned asset count, wildcard credential count, gateway-bypass count,
control propagation lag, and post-cut forbidden effects. Avoid one composite
“risk score” unless its weights, calibration, uncertainty, and decision use are
explicit and governed.

The lab includes labelled positive and negative cases. A system that blocks
everything has zero attack reachability and is still a failed system.

## 8. Common tools and where they fit

| Tool or method | Good fit | Security caveat |
|---|---|---|
| NetworkX | local analysis, prototypes, deterministic CI fixtures, custom algorithms | in-memory scale; enumeration needs budgets |
| Neo4j + Graph Data Science | persistent enterprise graph, Cypher queries, larger graph analytics | database reachability still is not runtime authorization |
| BloodHound-style graphs | identity and privilege-path thinking, especially AD/Entra estates | extend the schema carefully for agent/MCP semantics; do not relabel edges without proof |
| OPA / Cedar | policy decisions over typed current context | policy input freshness and enforcement placement remain critical |
| SPIFFE/SPIRE | workload identity and mTLS/SVID evidence | identity establishes who; resource policy decides what |
| OpenTelemetry | joinable observed-path evidence | trace/baggage is correlation, sampling leaves gaps, no credential logging |
| SIEM / security data lake | correlation, alerting, investigation, historical evidence | detections can reduce authority; they cannot grant it |
| service mesh / cloud network policy | gateway and egress enforcement | validate runtime route and DNS behavior, not only desired config |
| SBOM, signing, and registry | artifact and deployment provenance | namespace or signature alone does not prove safety or enterprise approval |
| MITRE ATT&CK / ATLAS and OWASP | shared threat/control vocabulary | map only supported evidence; taxonomy labels are not findings |

Use property graphs when relationships and path queries dominate. Use a policy
engine at enforcement time. Use a telemetry system for observations. Use a
resource ledger for outcomes. One product rarely serves all four roles safely.

## 9. Lab workflow

Install the locked contributor environment from the repository root:

```bash
uv sync --locked --extra contributor
```

Run the canonical lab:

```bash
uv run --frozen python \
  curriculum/advanced/20-multi-agent-cross-server-attack-paths/lab.py
```

Run focused tests:

```bash
uv run --frozen pytest -q tests/test_course_20_attack_paths.py
```

Then execute `attack_paths.ipynb` from its course directory. The notebook loads
the canonical `lab.py`; it does not maintain a second security implementation.
Everything is synthetic and offline: no credentials, remote servers, scanners,
or production systems are contacted.

### What to inspect

1. Verify the graph snapshot and enumerate its evidence sources.
2. Compare topological and executable paths from `analytics-server`.
3. Inspect the first denial on the shared-memory and rogue-registry routes.
4. Measure baseline exposure and labelled unsafe allows.
5. Apply containment controls one at a time and find residual paths.
6. Confirm the legitimate triage flow is not blocked.
7. Compare an adapter claim with the independent resource ledger.
8. Prove containment using revision, residual paths, and post-cut effects.
9. Review a minimum-cut result as a hypothesis, not an automatic action.

## 10. Claim-to-proof matrix

| Claim | Required proof | Lab artifact |
|---|---|---|
| graph input is current and untampered | signature, digest, epoch, freshness, schema | `sign_snapshot`, `verify_snapshot` |
| route is executable now | every edge passes current independent gates | `AttackGraph.assess_path` |
| sensitive blast radius is bounded | complete labelled denominator plus executable reachability | `sensitive_exposure` |
| a control reduces risk | before/after negative cases and valid-case regression | `evaluate_cases` |
| an effect occurred | protected-resource state, not agent prose | `ResourceLedger` |
| containment is complete | revision propagated, no residual paths, no post-cut effect | `prove_containment` |
| choke point should be disabled | operational dependency review and tested enforcement | deliberately **not** automated |

## 11. Adversarial test plan

The focused suite covers:

- snapshot tampering, rollback, staleness, future time, duplicates, and unknown
  endpoints;
- hop-budget and missing-node behavior;
- topology that remains visible but is not executable;
- disabled edge, quarantine, route denial, gateway enforcement, revocation, and
  wildcard rejection;
- absent, stale, and tenant-mismatched evidence;
- inactive or mismatched registry artifact/workload bindings;
- credential expiry, tenant, audience, action, resource, and presenter binding;
- missing, expired, mismatched, replayed, and consumed approval receipts;
- legitimate-path completion and false-block measurement;
- misleading adapter claims versus resource state;
- containment revision gaps, time regression, residual routes, and post-cut
  effects; and
- graph-cut output that does not mutate enforcement.

## 12. Exercises

### Exercise A — remove one control

Starting from the hardened state, remove only quarantine, only credential
revocation, or only direct-edge blocking. Explain which path remains and which
additional enforcement point closes it without blocking the valid flow.

### Exercise B — model a second tenant

Add a second tenant with a similarly named support server and data asset. Write
tests proving that display name, Agent Card content, trace baggage, and caller
arguments cannot select tenant authority.

### Exercise C — approval-bound export

Add a consequential export edge that requires an exact, short-lived,
single-use approval. Test changed target, resource, action, tenant, expiry, and
replay. Observe the effect at an independent egress sink.

### Exercise D — evidence uncertainty

Give each source a freshness SLA and confidence category. Exclude stale facts
from executable-path claims while still surfacing them as investigation leads.
Do not convert confidence into authorization.

### Exercise E — operational cut review

Compare `minimum_node_cut` with service ownership and valid traffic. Propose a
containment plan that minimizes both residual sensitive paths and legitimate
flow loss. State which decisions require a human incident commander.

## 13. Production review checklist

- [ ] Graph scope, owner, epoch, and evidence freshness SLA are explicit.
- [ ] Node and edge types preserve influence, discovery, authority, and effect.
- [ ] Tenant/environment partitions come from authenticated context.
- [ ] Registry records bind exact server, artifact, workload, and state.
- [ ] Credentials are target-audience, action/resource, tenant, expiry, and
      presenter bound; wildcard/shared bearer credentials are eliminated.
- [ ] Every target resource independently authorizes the final action.
- [ ] Direct network and gateway-bypass routes are tested at runtime.
- [ ] Approvals bind and are consumed at the exact effect boundary.
- [ ] Untrusted prompts, memory, cards, descriptions, traces, and baggage never
      become identity or authority.
- [ ] Path queries have hop, scope, time, result, and cost budgets.
- [ ] Sensitive-asset and labelled-case denominators are complete and reported.
- [ ] Valid workflows are present in regression and containment tests.
- [ ] Control updates use monotonic revisions and measured propagation.
- [ ] Independent resource/egress state decides whether effects occurred.
- [ ] Graph algorithms recommend investigations; they do not issue authority or
      autonomously disable critical infrastructure.
- [ ] Raw credentials and sensitive payloads are absent from graphs and traces.
- [ ] Course 21 detection/forensics responsibilities remain separately owned.

## References

### Protocols and identity

- [Model Context Protocol specification (`2026-07-28`)](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [A2A Protocol specification 1.0.1](https://a2a-protocol.org/v1.0.1/specification/)
- [A2A multi-tenancy guidance](https://a2a-protocol.org/v1.0.1/topics/multi-tenancy/)
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/overview/)

### Graph analysis and policy tools

- [NetworkX `all_simple_paths`](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.simple_paths.all_simple_paths.html)
- [NetworkX `minimum_node_cut`](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.connectivity.cuts.minimum_node_cut.html)
- [Neo4j Graph Data Science manual](https://neo4j.com/docs/graph-data-science/current/)
- [BloodHound documentation](https://bloodhound.specterops.io/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar policy language documentation](https://docs.cedarpolicy.com/)

### Threats, controls, and evidence

- [MITRE ATT&CK: Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [OpenTelemetry security guidance](https://opentelemetry.io/docs/security/)
