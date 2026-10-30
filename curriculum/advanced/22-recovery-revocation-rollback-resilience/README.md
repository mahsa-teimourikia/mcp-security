# Recovery, Revocation, Rollback, and Resilience

Recovery is not “deploy the previous version” and it is not complete when an API returns success. A defensible MCP recovery accepts a verified containment handoff, converges revocation across every authority path, selects a provenance-backed and compatible candidate, stages it exactly once, validates security and useful service from independent evidence, separately authorizes return to service, and reopens the incident if residual access or adversary re-entry appears.

## Course thesis

By the end of this course, you will be able to explain, implement, evaluate, and productionize an MCP recovery workflow that:

- verifies the incident and containment evidence it inherits;
- revokes registry bindings, host caches, sessions, credentials, tasks, callbacks, and egress with measurable convergence;
- distinguishes rollback, forward recovery, rebuild, failover, and degraded service;
- verifies immutable artifact bytes, Ed25519 provenance, source, builder, build inputs, SBOM, vulnerabilities, remediation, and compatibility;
- binds staging and return-to-service approvals to exact proposals and evidence;
- reconciles unknown deployment outcomes without repeating effects;
- proves both security regression and valid-task recovery before promotion;
- detects post-recovery forbidden effects and reopens rather than fabricating success; and
- measures RTO, residual authority, security regressions, safe-task success, and forbidden effects with explicit denominators.

Course 21 ended with proven containment and a recovery handoff. Course 22 owns eradication, restoration, validation, return to service, monitoring, and resilience improvement. It does not erase or rewrite Course 21 evidence.

## Learning objectives

After completing the chapter, lab, and notebook, you should be able to:

1. Map recovery work to NIST CSF 2.0 and SP 800-61r3 recovery outcomes.
2. Define recovery initiation, prioritization, completion, reopening, and authorization criteria before an incident.
3. Validate a signed containment handoff without treating its unresolved questions as solved.
4. Inventory all distributed authority that can survive a registry change.
5. Explain token-revocation propagation, introspection, short lifetimes, cache risk, and independent resource enforcement.
6. Choose rollback, forward fix, rebuild, failover, or degraded service based on root cause, compatibility, evidence, and mission needs.
7. Verify restoration artifacts and provenance against policy expectations rather than trusting a tag or signature alone.
8. Handle database, configuration, policy, capability-contract, and downstream compatibility during restoration.
9. Use stable operation IDs, durable journals, and reconciliation for ambiguous staging and promotion outcomes.
10. Validate security and service behavior with independent sources, explicit populations, and positive and negative controls.
11. Require a fresh return-to-service decision after validation.
12. Design recovery exercises and use after-action evidence to improve resilience.

## Standards and version snapshot

This course snapshot is current to **2026-10-30**.

| Area | Course baseline | Recovery implication |
| --- | --- | --- |
| Incident recovery | NIST SP 800-61r3, April 2025 | Select, scope, prioritize, and securely perform recovery; verify restoration assets and restored assets; confirm normal operation; declare completion by criteria. |
| Recovery planning | NIST SP 800-184 | Identify mission dependencies, recovery authority, milestones, playbooks, exercises, metrics, and continuous improvement. |
| Operational playbook | CISA Federal Incident Response Playbook | Account for persistence, preserve evidence, coordinate eradication, rebuild from clean sources, monitor for re-entry, and iterate when activity returns. |
| Safe deployment | CISA/FBI/ACSC safe software deployment guidance | Plan rollback, validation, data-loss safeguards, escalation, graceful degradation, and root-cause learning. |
| OAuth security | RFC 7009, RFC 7662, RFC 9700 | Revocation can have propagation delay; access-token invalidation and related-token policy vary; resource servers need current status and safe token design. |
| Artifact provenance | SLSA Build v1.2 | Verify the artifact subject digest, provenance signature, trusted builder, source, build type, and external parameters against expectations. |
| Signing | Sigstore/cosign and in-toto | Verify identity and signed supply-chain statements; a signature is not a vulnerability or compatibility assessment. |
| Deployment | Kubernetes Deployment documentation | Rollout history covers the workload template, not every external dependency or data migration; rollout completion still requires independent validation. |
| MCP | protocol revision 2026-07-28 | Modern requests are stateless and self-contained, but host caches, tasks, credentials, callbacks, registries, and protected resources still hold distributed state. |

A version label never proves that the deployed artifact, policy, configuration, data schema, and capability contract match the reviewed recovery plan. Bind decisions to immutable digests and observed target state.

## 1. Recovery is a new authorization boundary

Containment stops ongoing harm. Recovery deliberately reintroduces capability and traffic. The safe workflow is:

~~~text
verified containment handoff
  -> recovery case accepted
  -> distributed authority revoked and convergence proven
  -> strategy selected
  -> exact candidate verified
  -> staging approved and executed
  -> security and service validation
  -> return-to-service approved
  -> promotion reconciled
  -> post-return effect proof and monitoring
  -> complete, reopen, or continue degraded
~~~

Each arrow changes a different state and needs a different proof. A containment approval does not authorize deployment. A staging approval does not authorize public traffic. A healthy process does not prove the root cause is removed. A model recommendation does not choose or close recovery.

### Application-owned states

The lab uses:

~~~text
ACCEPTED
  -> REVOCATION_PROVEN
  -> CANDIDATE_STAGED
  -> VALIDATED
  -> RETURNED_TO_SERVICE

Any material residual authority or re-entry -> REOPENED
~~~

State is optimistic-versioned. Model text can attach a cited hypothesis, but accepted_as_fact remains false. Trusted application transitions require typed evidence.

## 2. Accept a containment handoff

Recovery begins with a signed handoff rather than a free-form summary. The lab binds:

- incident, handoff, tenant, and server IDs;
- containment time and cut;
- containment control revision;
- evidence-package and containment-plan digests;
- affected artifacts, workloads, credentials, sessions, tasks, hosts, and destinations;
- required remediation IDs;
- unresolved items;
- explicitly authorized recovery actions; and
- handoff policy version and signature.

The recovery coordinator verifies the signature, time relationships, required digests, tenant authority, role, and allowed actions before creating a recovery case.

### Unresolved does not mean ignored

An unresolved downstream token cache does not block accepting the handoff if policy permits recovery work to begin. It does block claiming revocation convergence until the credential issuer and resource enforcement path provide current evidence.

Preserve Course 21's evidence package and custody history. Recovery actions may change or destroy volatile state; record why and under whose authority.

## 3. Establish recovery objectives and priorities

NIST SP 800-184 treats recovery as mission planning, not just technical rollback. Define:

- **Recovery Time Objective (RTO):** target time to restore a required service level.
- **Recovery Point Objective (RPO):** acceptable data-loss interval.
- **Maximum tolerable downtime:** business limit beyond the technical target.
- **Minimum safe service:** the smallest capability set that can operate without recreating the incident.
- **Dependency order:** identity, policy, registry, credentials, data, server, gateway, and clients.
- **Completion criteria:** exact security, service, evidence, and owner conditions.
- **Reopening criteria:** any residual access, re-entry indicator, post-return forbidden effect, or invalidated evidence.

An MCP server can be stateless while its downstream ticket system, queues, task store, token issuer, or memory service is not. RPO may be zero for the server process and nonzero for those dependencies. State the object and unit whenever reporting RPO.

### Priority is not only criticality

Restore in an order that preserves trust:

1. authoritative time, identity, keys, and policy;
2. evidence and security telemetry;
3. token status and revocation services;
4. protected-resource enforcement;
5. registry, gateway, and host control planes;
6. a private recovery route or canary;
7. safe service functions;
8. consequential or high-risk capabilities.

Restoring business traffic before security dependencies can recreate the original compromise.

## 4. Revoke every surviving authority path

Changing a registry row is one control-plane update. An already connected host, cached capability snapshot, delegated token, task, callback, gateway route, or in-flight protected-resource operation may still work.

The lab constructs an exact revocation plan for:

| Plane | Action | Evidence of convergence |
| --- | --- | --- |
| Registry | Disable server plus compromised artifact binding | Monotonic registry epoch and exact binding absence |
| Host cache | Invalidate affected host snapshots | Host-observed epoch and cache miss or deny |
| Gateway/session | Close affected sessions | Session ledger and denied reuse |
| Credential issuer/resource | Revoke affected credentials or grant lineage | Issuer status plus resource denial or introspection |
| Task system | Cancel affected durable tasks | Task terminal state and no later effect |
| Network | Block affected workload and destination | Enforced policy revision plus flow evidence |

The plan carries a required epoch. Each control point must report that epoch or later. A central database at epoch 42 cannot prove a host still at epoch 41 is safe.

### OAuth revocation caveats

RFC 7009 notes that implementations should minimize propagation delay. It also permits different policies for cascading from a refresh token to access tokens or vice versa. Therefore:

- know whether access tokens are self-contained or reference tokens;
- know the maximum access-token lifetime;
- know whether resource servers introspect or cache status;
- know whether revocation covers derived tokens and delegated grants;
- know how sender-constrained tokens and key rotation interact;
- force resource-side rejection, not only issuer-side state change; and
- measure last forbidden effect, not merely the revocation API response.

RFC 7662 can supply current token status for reference-token designs, but the protected resource still owns the final effect. RFC 9700's short-lived, narrowed, rotated credentials reduce but do not eliminate recovery work.

### Partial and unknown outcomes

The exercise distinguishes:

- **PARTIAL:** a known control point was unavailable or did not apply the action;
- **UNKNOWN:** the request may have committed but its response was lost;
- **RECONCILED:** target state and all required epochs prove the exact plan took effect.

Use one stable operation ID and request digest. Persist the authorized plan and result before a process restart. Retry only missing idempotent actions from the same plan, or reconcile a possibly committed operation. Never generate a fresh identity to make the dashboard look successful.

## 5. Prove revocation convergence

The prove_revocation function requires:

- every exact revocation action is satisfied;
- every required control point observes the required epoch;
- no residual action remains;
- no affected workload, credential, session, task, or destination completed an effect after the containment cut; and
- proof time is consistent with the handoff.

A successful deny is useful evidence. A completed effect from an independent protected-resource audit falsifies the claim.

This proof advances the case to **REVOCATION_PROVEN**. It does not yet authorize staging or public traffic.

## 6. Choose the recovery strategy

### Rollback

Return to a previously deployed immutable artifact when:

- its exact bytes and provenance are available;
- it predates the malicious or defective change;
- it is not vulnerable to the same root cause;
- its policy, configuration, capability contract, dependencies, and data schema are compatible; and
- rollback does not destroy required evidence or data.

A Kubernetes Deployment rollback restores the stored Pod template. It does not automatically roll back databases, external APIs, secrets, authorization state, queues, or policy. A revision number is not an artifact integrity proof.

### Forward fix

Deploy a new artifact that removes the root cause when:

- previous versions are vulnerable or incompatible;
- state migrations cannot safely move backward;
- a key, builder, dependency, or policy must change;
- the current platform needs a security patch; or
- reverting would lose accepted data or violate recovery objectives.

### Rebuild

Recreate the environment from trusted foundations when workload, node, cluster, identity, builder, or administrative control may be compromised. Reusing the same environment can preserve attacker persistence.

### Failover or degraded operation

Move to an independently trusted region, service, or control plane, or expose a restricted read-only/safe capability set. Failover is not safe when it shares compromised identity, secrets, build provenance, registry state, or replication data.

### Strategy decision record

Record candidate digest, root-cause coverage, compatibility, data implications, recovery objective impact, owners, evidence IDs, and reasons. The lab keeps the decision deterministic; model output may summarize tradeoffs but cannot select production state.

## 7. Verify the restoration candidate

The lab uses real Ed25519 verification and SLSA-style expectations. It checks:

1. artifact bytes hash to the claimed SHA-256 digest;
2. image or package reference is digest-pinned, not a mutable tag;
3. provenance subject matches those bytes;
4. provenance signature verifies under a trusted key;
5. builder identity matches the configured root of trust;
6. canonical source repository and commit are expected;
7. build type and external parameters are recognized;
8. SBOM digest is valid;
9. critical and high vulnerability gates pass;
10. required security regressions pass;
11. incident remediation IDs are covered;
12. current data schema is compatible; and
13. candidate time is plausible.

SLSA provenance authenticates build claims under its trust assumptions. It does not prove the source is correct, the package is vulnerability-free, the configuration is safe, or the application is compatible. Sigstore/cosign can verify signing identity and transparency evidence; policy must still say which identity, repository, workflow, digest, and claims are acceptable.

### Supply-chain root cause

If the builder, signer, source repository, package registry, or signing identity was compromised, “rebuild the same commit” may reproduce untrusted output. Rotate trust roots, repair the build path, and verify provenance from an independently trusted environment.

## 8. Bind an exact recovery plan

The plan binds:

- incident and tenant;
- current recovery-case version;
- rollback, forward-fix, or rebuild strategy;
- candidate digest and complete candidate-evidence digest;
- immutable reference;
- configuration, policy, and capability-contract digests;
- private canary percentage;
- recovery objectives;
- policy version; and
- issuance and expiry.

An incident or recovery commander signs a single-use staging receipt for that exact plan. A changed image, configuration, policy, capability contract, canary size, or strategy requires fresh review.

The lab will not stage until revocation proof is complete and candidate verification passes.

## 9. Stage safely and reconcile ambiguity

The offline RecoveryExecutor models a private 10% canary. It keeps public registry exposure disabled during validation.

The stage operation:

- verifies the current case state and optimistic version;
- verifies plan and candidate integrity;
- verifies the exact signed approval and current policy;
- consumes the receipt once;
- writes the complete candidate state as one deployment revision;
- persists operation identity and request digest; and
- returns **UNKNOWN** when a simulated response is lost.

A restarted executor reuses the durable journal and checks the observed deployment. It does not repeat the deployment revision.

### Production rollout patterns

Common patterns include:

- private shadow or internal-only validation;
- canary by tenant or capability;
- blue/green with independent traffic switching;
- progressive delivery with automated pause;
- full rebuild and controlled reconnection; and
- degraded safe mode.

Do not canary a security breach across arbitrary customer tenants. Select a governed, low-risk population and prevent sensitive effects until security gates pass.

## 10. Validate security and useful service

A process being “Ready” is not enough. The lab requires:

- workload-attested artifact digest equals the approved candidate;
- registry view names the same candidate but remains public-disabled during canary;
- configuration, policy, and capability-contract digests match;
- all labelled security regressions pass;
- labelled valid tasks meet the safe-task success threshold;
- labelled forbidden attempts produce zero completed effects;
- no compromise indicators appear; and
- at least two independent evidence sources corroborate the result.

The exercise uses workload attestation, protected-resource audit, and gateway probes. Self-reported server output is not an independent source.

### Compatibility and data checks

Include when applicable:

- forward and backward schema compatibility;
- irreversible migrations and restore points;
- queue and message version compatibility;
- cache serialization and invalidation;
- session and task resume semantics;
- downstream API contracts and audiences;
- policy obligations and redaction;
- MCP capability discovery and complete schema snapshots;
- prompt and resource version changes; and
- data reconciliation after failover.

A rollback that starts but corrupts or misinterprets state is a failed recovery.

## 11. Authorize return to service separately

Validation creates signed RecoveryEvidence with:

- incident, plan, candidate, and deployment revision;
- every named check and Boolean result;
- security-regression numerator and denominator;
- safe-task numerator and denominator;
- forbidden-attempt and completed-effect counts;
- independent sources;
- validation time, digest, and signature.

A service owner or recovery commander then issues a fresh, single-use receipt bound to both the plan digest and evidence digest. This prevents a staging approval from silently becoming permission for public traffic.

Promotion sets the exact staged candidate to 100% and enables the public registry binding. A lost promotion response is outcome unknown; restart reconciliation inspects the deployment state before any retry.

## 12. Prove safe service and monitor for re-entry

The prove_safe_service function requires:

- deployed candidate digest matches the plan;
- traffic is at 100%;
- public registry binding is enabled;
- validation evidence still verifies; and
- no forbidden effect completed after return.

If a post-return exfiltration effect appears, the proof fails. The incident responder moves the case to **REOPENED**, records the reason, and returns to containment and analysis. A model cannot relabel the event or preserve a green status.

Monitor beyond the first promotion window:

- credential and session reuse;
- old artifact execution;
- stale host and cache epochs;
- policy and registry drift;
- unexpected egress;
- new persistence indicators;
- error and latency regressions;
- safe-task success by tenant and capability; and
- customer-impact and data-reconciliation signals.

## 13. Resilience engineering

Recovery succeeds faster when the system was designed to fail safely.

### Design controls

- immutable, digest-pinned deployments;
- independently protected artifact history and provenance;
- reversible or expand-contract data migrations;
- short-lived, narrowed credentials and grant lineage;
- monotonic registry and policy epochs;
- cache invalidation and bounded staleness;
- idempotent target operations and effect ledgers;
- durable task state and cancellation semantics;
- bounded queues and backpressure;
- independently tested degraded modes;
- multi-region or alternate-service dependencies with separate failure domains;
- unsampled security evidence;
- tested backups with integrity and restore drills; and
- owned, versioned recovery playbooks.

### Exercises and game days

Practice more than the happy path:

- credential issuer unavailable;
- one host cache partitioned;
- registry and gateway disagree on epoch;
- canary response lost after deployment commit;
- rollback candidate fails provenance;
- schema migration prevents rollback;
- clean artifact carries vulnerable configuration;
- safe tasks fail while security checks pass;
- forbidden effect appears after promotion;
- primary and failover share a compromised secret;
- telemetry source is delayed or missing; and
- responder process restarts mid-operation.

A tabletop validates coordination assumptions. A technical exercise validates executable controls. A production game day validates the deployed environment within an approved blast radius. Do not equate one with another.

## 14. Metrics and service objectives

| Metric | Definition in the lab | Why it matters |
| --- | --- | --- |
| Time to revoke | revocation proof time minus recovery acceptance time | Distributed authority convergence |
| Time to safe service | verified return time minus containment time | Recovery performance against RTO |
| Residual authority rate | unsatisfied exact revocation actions divided by required actions | Hidden access paths |
| Security regression pass rate | passed labelled security regressions divided by all labelled regressions | Root-cause and control verification |
| Safe-task success rate | successful labelled valid tasks divided by all valid attempts | Useful service restoration |
| Forbidden-effect rate | completed forbidden effects divided by labelled forbidden attempts | Security outcome, not block count |
| RTO met | time to safe service is within declared RTO | Mission objective |

Report RPO separately for each stateful system. Also track recovery attempt count, unknown outcomes, reconciliation time, cache convergence distribution, stale-token effects, canary exposure, data-reconciliation errors, rollback or forward-fix decision changes, and re-open rate.

Do not improve RTO by skipping evidence or allowing unsafe traffic. Track “time to safe service,” not time to first process start.

## 15. Common tools and libraries

The lab uses real cryptography Ed25519 verification and an in-memory OpenTelemetry SDK span. Common production choices include:

| Need | Common options | Review focus |
| --- | --- | --- |
| Progressive delivery | Kubernetes Deployments, Argo Rollouts, Flagger | Exact digest, canary population, pause and abort, independent analysis |
| GitOps and state reconciliation | Argo CD, Flux | Signed desired state, drift, rollback scope, reconciliation evidence |
| Provenance and signing | SLSA, in-toto, Sigstore/cosign | Subject digest, identity, builder, source, workflow, transparency, trust roots |
| SBOM and vulnerability gates | CycloneDX or SPDX, Syft, Grype, Trivy | Exact artifact linkage, database freshness, exception policy |
| Policy | OPA/Rego, Cedar, admission controllers | Trusted inputs, versioned decisions, obligations |
| Identity and credentials | OAuth AS, SPIFFE/SPIRE, cloud workload identity | Revocation, lifetime, audience, lineage, cache behavior |
| Telemetry | OpenTelemetry Collector, SIEM, protected-resource audit | Independent sources, unsampled security events, privacy |
| Backup and restore | Cloud snapshots, database PITR, object-lock storage | Integrity, encryption, RPO, restore rehearsal, destructive-test isolation |
| Chaos and resilience | LitmusChaos, Chaos Mesh, controlled game-day tooling | Approval, blast radius, abort, evidence, no fabricated success |
| Case and workflow | SOAR, TheHive, ServiceNow or Jira security workflows | State authority, exact approvals, evidence links, ownership |

A tool's successful command exit is evidence that the command returned success. It is not proof that target state, security behavior, data integrity, or customer service is correct.

## 16. Practical lab

From the repository root:

~~~bash
uv sync --extra contributor --frozen
uv run python curriculum/advanced/22-recovery-revocation-rollback-resilience/lab.py
uv run pytest -q tests/test_course_22_recovery_resilience.py
~~~

Expected output:

~~~text
PASS: recovery converged revocation, verified a candidate, and proved safe return to service
~~~

The vertical slice is organized as:

1. ContainmentHandoff and RecoveryManager — signed handoff, tenant and role checks, case state, model non-authority.
2. Provenance, ArtifactCandidate, and CandidateVerifier — real Ed25519 and policy expectations.
3. select_strategy — explicit rollback, forward-fix, and rebuild reasoning.
4. RevocationPlan, AuthorityPlane, and RevocationCoordinator — distributed authority, epochs, partial failure, restart.
5. prove_revocation — exact controls plus independent post-cut effects.
6. RecoveryPlan and staging approval — exact immutable candidate and objectives.
7. RecoveryExecutor.stage — private canary, single-use receipt, outcome reconciliation.
8. RecoveryObservations and RecoveryEvidence — security, service, compatibility, and independent sources.
9. Return-to-service approval and promote — fresh authority for public exposure.
10. prove_safe_service, reopen, metrics, and OpenTelemetry — terminal proof and improvement evidence.

The tests are course material. Read each invariant and explain which false recovery claim it prevents.

## 17. Notebook investigation

Run recovery_resilience.ipynb top to bottom from a clean kernel. It walks through:

- handoff verification and tamper rejection;
- recovery case and model hypothesis;
- exact revocation inventory;
- a host-cache outage and later convergence;
- post-cut effect failure;
- candidate provenance and deliberate verification failures;
- rollback versus forward-fix versus rebuild;
- exact recovery plan and staging receipt;
- lost response and restart-safe reconciliation;
- canary observations and failed checks;
- signed validation evidence;
- separate return-to-service approval;
- lost promotion response and reconciliation;
- post-return effect failure and reopening;
- exact metrics and OpenTelemetry evidence.

The notebook imports the canonical lab.py; it does not maintain a second implementation.

## 18. Exercises

### Exercise A — Token propagation window

Model a five-minute self-contained access token cached by two resource servers. Revoke its refresh-token lineage and measure last accepted effect. Compare shorter lifetime, introspection, and sender constraint without claiming any one mechanism is universal.

### Exercise B — Schema rollback trap

Make the previous artifact incompatible with customer-schema-v4. Require a forward fix or tested restore point. Add a data-integrity check and explicit RPO.

### Exercise C — Compromised builder

Change the trusted builder root and demonstrate why the old provenance cannot bootstrap trust in the replacement. Define an independent recovery root and rotation ceremony.

### Exercise D — Degraded service

Expose only ticket.read while write capabilities remain disabled. Measure safe-task success and verify that discovery, policy, and resource enforcement all agree.

### Exercise E — Split-brain control plane

Hold one host at revocation epoch 41 while the registry is at 42. Show that average epoch hides the unsafe host and use minimum or percentile convergence instead.

### Exercise F — Queue redelivery

Let a cancelled task redeliver after restart. Use stable task and operation IDs plus a protected-resource effect ledger to prevent duplicate consequences.

### Exercise G — Re-entry

Admit a post-return effect to exfil.example. Fail safe-service proof, reopen the case, and create a new containment handoff rather than mutating the old proof.

### Exercise H — Game day

Design an approved exercise with scope, roles, abort criteria, synthetic evidence, customer safeguards, RTO and RPO objectives, observers, and an after-action owner.

## 19. Recovery runbook checklist

Before an incident:

- [ ] Mission functions, dependencies, owners, RTOs, RPOs, and minimum safe service are documented.
- [ ] Recovery and return-to-service authorities are separate and current.
- [ ] Immutable artifacts, provenance, SBOMs, configs, policies, and capability contracts are retained.
- [ ] Revocation reaches registries, hosts, gateways, issuers, resources, tasks, callbacks, and network controls.
- [ ] Stable idempotency and target-state reconciliation survive restart.
- [ ] Backups and restoration assets are integrity-checked and exercised.
- [ ] Schema migrations have forward, backward, or restore plans.
- [ ] Degraded modes and failover dependencies are independently tested.
- [ ] Security-critical evidence is durable and unsampled.

During recovery:

- [ ] Verify the containment handoff and tenant authority.
- [ ] Preserve unresolved questions and evidence links.
- [ ] Prove revocation convergence before staging.
- [ ] Select strategy from root cause and compatibility evidence.
- [ ] Verify exact candidate bytes and provenance expectations.
- [ ] Bind staging approval to the complete plan.
- [ ] Reconcile unknown outcomes before retrying.
- [ ] Keep the canary private until independent validation passes.
- [ ] Test valid tasks and forbidden effects.
- [ ] Obtain fresh return-to-service approval.

After return:

- [ ] Verify public target state and effect evidence.
- [ ] Monitor old artifacts, credentials, sessions, tasks, caches, and destinations.
- [ ] Reopen on residual authority, re-entry, or invalidated evidence.
- [ ] Reconcile data and customer impact.
- [ ] Complete after-action documentation and owned improvements.
- [ ] Rehearse the revised playbook.

## 20. Claim-to-proof map

| Claim | Artifact | Executable proof |
| --- | --- | --- |
| Recovery inherits valid containment state | Signed handoff | Tamper, time, tenant, role, and action tests |
| Model text cannot select or close recovery | Case hypothesis and transitions | Non-fact and application-state tests |
| Revocation covers every known authority path | Revocation plan and required epochs | Coverage, partial, restart, replay, and post-cut tests |
| Candidate is exact and provenance-backed | Bytes, Ed25519 provenance, policy expectations | Artifact, subject, signer, source, build, SBOM, vulnerability, remediation, schema tests |
| Strategy is explicit | StrategyDecision | Rollback, forward-fix, and rebuild tests |
| Staging is exact and idempotent | Recovery plan, receipt, journal | Mutation, expiry, replay, unknown-outcome, restart tests |
| Validation measures security and service | Signed recovery evidence | One failure per check and tamper tests |
| Public return has fresh authority | Return-to-service receipt | Role, evidence, policy, replay, and promotion tests |
| Safe service is proven | Deployment plus independent post-return effects | Wrong-state and re-entry tests |
| Metrics mean what they say | Labelled counts and objectives | Exact-value and zero-denominator tests |

## References

- [NIST SP 800-61r3: Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-184: Guide for Cybersecurity Event Recovery](https://csrc.nist.gov/pubs/sp/800/184/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- [CISA, FBI, and ACSC Safe Software Deployment](https://www.cisa.gov/sites/default/files/2024-10/safe-software-deployment-how-software-manufacturers-can-ensure-reliability-for-customers-508c.pdf)
- [RFC 7009: OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html)
- [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [SLSA v1.2: Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [Sigstore and cosign signature verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [in-toto](https://in-toto.io/)
- [Kubernetes: Update a Deployment without downtime and roll back](https://kubernetes.io/docs/tasks/run-application/update-deployment-rolling/)
- [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [MCP specification revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
