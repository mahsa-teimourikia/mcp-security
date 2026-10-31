# MCP Supply-Chain Risk Management

## Course thesis

An enterprise must govern the entire path by which MCP software, services,
models, connectors, registries, build systems, and suppliers acquire authority.
A defensible program inventories every dependency and trust edge, verifies
supplier and artifact claims against exact current evidence, makes a bounded
admission decision, detects material change, and can quarantine or offboard the
dependency without confusing provenance with safety.

Course 12 implements an artifact release gate. This advanced course builds on
that foundation: it governs supplier due diligence, dependency topology,
portfolio concentration, contractual and operational assurance, continuous
monitoring, exceptions, incident response, and exit across many artifacts and
services.

## Learning objectives

By the end of this course, you will be able to:

1. distinguish supplier, product, artifact, composition, vulnerability,
   operational, concentration, and runtime risks;
2. inventory direct, transitive, build-time, hosted, data, model, registry, and
   identity dependencies that can influence MCP behavior;
3. tier suppliers using impact, authority, data reach, substitutability,
   concentration, and recovery needs without inventing a magic score;
4. perform scoped due diligence aligned to current NIST C-SCRM guidance;
5. verify supplier and component evidence against exact identities, versions,
   digests, tenants, producers, validity windows, and policy;
6. correlate signatures, SLSA provenance, SBOMs, vulnerability reports, VEX,
   licenses, and release intent without treating one artifact as proof of safety;
7. design intake, approval, exception, reassessment, quarantine, revocation, and
   offboarding workflows with explicit decision rights;
8. respond to compromised signers, artifact drift, new advisories, supplier
   incidents, registry removal, ownership change, and maintenance lapse; and
9. measure inventory and evidence coverage using explicit populations.

## Prerequisites and timebox

Complete Courses 12, 13, 17, 23, 24, and 25 first. You should understand
immutable digests, signatures, provenance, SBOMs, vulnerability scanning,
registry trust, workload identity, architecture review, and risk governance.

Suggested time: 100 minutes reading, 120 minutes lab and notebook, and 60
minutes for the supplier-exit design exercise.

## Scenario and safety boundary

Acme wants to admit a critical third-party helpdesk MCP server. It reads and
updates confidential tenant tickets and depends on a vendor SDK. It is
published through an MCP registry, built by hosted CI, packaged as an OCI
artifact, signed by a workload identity, deployed behind Acme's gateway, and
supported by vendor response and continuity processes.

The objective is to use the integration without allowing a compromised,
substituted, abandoned, or failed dependency to disclose tenant data, perform
unauthorized effects, or prevent safe recovery.

The lab creates a versioned supplier profile; a rooted server/SDK graph; signed
supplier and artifact evidence; findings and a governed exception path; an
exact committee-authorized decision; reassessment and quarantine signals; and
portfolio metrics that expose a shadow observed supplier.

The lab is deterministic, local, and credential-free. Ed25519 signatures model
authenticated evidence and receipts. In-memory stores model an inventory,
exception register, and journal. They do not validate a legal entity, query a
real registry, scan packages, admit production workloads, revoke credentials,
or execute an exit plan.

## 1. C-SCRM is broader than package security

Cybersecurity supply-chain risk management covers risks introduced by the
supplier, the supplied product or service, and the chain that develops,
integrates, distributes, operates, and supports it.

| Layer | Examples | Material failure |
|---|---|---|
| discovery | MCP registry, enterprise subregistry, catalog mirror | takeover, stale or removed record |
| supplier | publisher, SaaS vendor, model or connector operator | incident concealment, acquisition, abandonment |
| source | repository, maintainers, review policy, manifests | malicious commit, compromised maintainer |
| build | CI runner, workflow, compiler, builder identity | secret theft, false or weak provenance |
| artifact | OCI image, binary, package, prompt or policy bundle | substitution, mutable tag |
| composition | packages, base images, actions, plugins | hidden vulnerable or malicious dependency |
| model/data | model, adapter, dataset, retrieval corpus | unreviewed version, provenance or license gap |
| operation | remote server, API, IdP, telemetry, support | outage, drift, credential compromise |
| update | registry, package index, TUF metadata, updater | rollback, freeze, compromised mirror |
| recovery | revocation, export, replacement adapter | retained authority, lock-in, failed restore |

A signed package solves only part of this system. A supplier questionnaire does
not bind the bytes that run. Keep supplier and artifact assurance distinct.

## 2. Current standards and guidance

Record the exact version and status used by policy.

| Resource | Use | Boundary |
|---|---|---|
| NIST SP 800-161 Rev. 1 Update 1 | enterprise C-SCRM strategy and controls | requires local tailoring and evidence |
| NIST SP 1326 (2026) | ICT supplier due diligence | informs a decision; not certification |
| NIST SP 800-218 SSDF 1.1 | secure software development | current final; SSDF 1.2 remains draft |
| NIST SP 800-218A | GenAI/foundation-model SSDF profile | producer practices, not model certification |
| SLSA 1.2 | approved source/build tracks and attestations | named properties, not all C-SCRM |
| in-toto | subject/predicate attestation model | signed claims still need semantic policy |
| CycloneDX 1.7 | SBOM/xBOM, services, dependencies, VEX | declared inventory needs completeness checks |
| SPDX 3.0 | software, build, AI, dataset, provenance data | structured data is not automatically true |
| Sigstore/Cosign | signature and attestation verification | constrain identity, issuer, subject, roots |
| TUF | resilient update metadata | not a code-quality claim |
| CISA 2025 SBOM Minimum Elements | supplier/consumer SBOM baseline | minimum elements do not prove completeness |
| OpenSSF Scorecard | repository/build practice signals | context, not a universal trust score |
| OSV | ecosystem/version vulnerability data | database and identification coverage are incomplete |
| MCP Registry | public discovery and distribution metadata | listing is not enterprise admission |

At this revision, NIST SP 800-161 Rev. 1 includes updates through November
2024, SP 1326 was finalized in July 2026, SSDF 1.1 is the current final while
1.2 is draft, SLSA 1.2 is approved, CycloneDX 1.7 is the final 1.x release, and
SPDX lists 3.0 as current. Recheck status when policy changes.

## 3. Map the MCP supply chain

Start from the business effect. Trace everything able to influence tool,
resource, and prompt definitions; identity and authorization; tenant selection;
local or remote code; model behavior; updates; evidence; containment; and
recovery.

```text
business objective
  -> MCP capability
    -> root server or remote service
      -> SDK / connector / package / base image
        -> source + build + signer + registry
      -> model + data provider
      -> IdP + policy + gateway + telemetry
    -> incident, continuity, revocation, and exit dependencies
```

Use stable supplier IDs, PURLs, source revisions, artifact digests,
model/provider/version, server versions, SBOM IDs and digests, evidence
producer/version/time, and tenant/environment scope. A display name, URL,
registry namespace, mutable tag, or model nickname is not a safe join key.

The lab requires one root and rejects duplicate components, unknown or self
edges, and unreachable inventory. Production graphs can contain cycles and
shared nodes; still name the population and prove reachability from each
admitted service.

## 4. Threat model and invariants

Threats include compromised maintainers, suppliers, builders, signing
identities, registries, indexes, dependencies, install scripts, models, and
subcontractors; fabricated or stale SBOM/VEX/scan evidence; artifact or hosted
service drift; supplier incident or outage; acquisition and abandonment;
fourth-party concentration; emergency bypass; partial revocation; and an exit
plan that cannot remove access or restore a safe alternative.

The lab enforces these invariants:

1. Every supplier and component has an accountable internal owner.
2. Component identity is immutable and the declared graph is complete.
3. Trust roots and allowed producers come from policy.
4. Supplier evidence and artifact evidence are verified separately.
5. Evidence is authenticated, current, scoped, and version-bound.
6. Critical suppliers require independent evidence and committee authority.
7. Open critical findings cannot use the ordinary exception path.
8. Exceptions are exact, compensated, monitored, reviewed, and expiring.
9. Changed proposals invalidate approval.
10. Receipts are exact, short-lived, and atomically single-use.
11. Material signals invalidate admission; compromise signals quarantine.
12. Metrics retain named populations and denominators.

## 5. Tiering without false precision

Tiering selects assurance depth, decision authority, monitoring, and recovery.
Assess dimensions independently: business impact, data and tenant reach,
side-effect authority, local execution, update/signing power, dependent
services, substitutability, migration time, concentration, incident visibility,
maintainer health, support lifetime, and tested recovery/exit.

| Tier | Example | Decision |
|---|---|---|
| standard | replaceable, non-sensitive read-only helper | manager with baseline evidence |
| elevated | confidential-data connector | manager/CISO plus due diligence and continuity |
| critical | cross-tenant write server or concentrated dependency | committee plus independent assessment |

Do not average tiers, Scorecard values, CVSS, SLSA levels, and questionnaire
answers. Preserve causal scenarios and prohibited outcomes.

## 6. Supplier due diligence

NIST SP 1326 frames ICT due diligence around Foreign Ownership, Control, or
Influence; provenance; resilience; foundational cyber practices; and supply
chain tiers. Apply only lawful, relevant inquiries and involve legal, privacy,
and procurement specialists where required.

Review legal identity and material subcontractors; product provenance; secure
development and disclosure; identity, isolation, logging, encryption, and data
lifecycle; build, signing, release, and dependency controls; incident notice
and investigation support; continuity and recovery; privileged personnel;
maintenance and end-of-life; viability and concentration; and contract, audit,
data return/deletion, and exit terms.

Questionnaires are assertions. Corroborate critical claims with technical
evidence, independent assessments, contract terms, incident history, tests, and
runtime observation. Certifications have exact scope and validity; they do not
approve a different service, region, or MCP deployment.

## 7. Artifact evidence is an exact graph

Course 12 implements detailed artifact verification. At portfolio scale retain:

```text
trusted intake intent
  -> exact component digest
    -> authorized signer identity + issuer
    -> provenance subject + source + builder + materials
    -> SBOM subject + component/dependency graph
    -> scan bound to artifact + SBOM + database revision
    -> VEX bound to product + finding + issuer + evidence
    -> policy result for exact tenant, capability, and version
```

A signature proves that an identity signed a payload. Policy still establishes
trusted roots, certificate identity and issuer, repository, workflow, builder,
source revision, build type, subject digest, time semantics, and current
authorization. SLSA provenance describes build facts; its presence does not
prove source quality or vulnerability absence.

For SBOMs verify schema/version, subject binding, creator/tool and timestamp,
direct and transitive identifiers, graph relationships, completeness claim,
licenses, authentication, and correlation to deployed bytes and scans. Compare
source/lockfile, build, binary/image, and runtime observations where warranted.

CycloneDX 1.7 and SPDX 3.0 cover broader xBOM subjects including services,
builds, AI models, datasets, cryptography, and lifecycle relationships.
Conversion can lose semantics; retain original evidence.

## 8. Vulnerability and VEX semantics

Record component and digest, advisory ID/aliases/source/revision, scanner and
database versions/times, SBOM digest, severity vector/source, exploitability,
reachability, environment, fix/workaround, owner, SLA, and remediation proof.

Severity, exploitability, exposure, and business impact differ. A VEX
not-affected assertion needs an authenticated issuer, exact product/finding
scope, justification, evidence, and freshness. The lab rejects an open finding
that simultaneously claims not affected. A green scan never proves absence of
unknown, omitted, malicious, or newly disclosed components.

## 9. MCP registry and remote-service risk

The official MCP Registry is an open catalog for discovering public servers;
enterprises can build subregistries. Treat listings as discovery metadata.

Independently verify publisher ownership, repository and distribution,
immutable version/digest, artifact signatures/provenance, current contract
snapshot, remote endpoint/service identity, data processors, revocation or
namespace-transfer signals, and local tenant/capability/data policy.

A registry entry does not prove that a remote server behaves as documented,
preserves isolation, remains available, or stays under the same control.
Reconcile catalog, approved inventory, deployed digests, observed endpoints,
and runtime contracts.

## 10. Intake, approval, and exceptions

A mature workflow:

1. discovers suppliers/components from procurement, code, registry, runtime,
   identity, network, and expense data;
2. assigns business, supplier, technical, security, and data owners;
3. maps capabilities, tenants, data, dependencies, and exit scope;
4. tiers using explicit impact and substitutability;
5. gathers authenticated supplier and artifact evidence;
6. validates freshness, exact subjects, graph closure, and coverage;
7. assesses findings, uncertainty, and concentration;
8. chooses avoid, replace, mitigate, conditionally admit, or approve;
9. authorizes an exact proposal with separation of duties;
10. configures technical admission, identity, egress, monitoring, and kill
    switches; and
11. verifies the deployed subject and monitors change.

An exception is a temporary deviation for one finding, component, version,
digest, and tenant—not supplier trust or general risk acceptance. Require
owner, separate CISO approval, rationale, tested compensating controls,
evidence IDs, monitoring, remediation/exit, review, and hard expiry. The lab
prohibits exceptions for open critical findings.

## 11. Continuous monitoring, quarantine, and exit

Trigger reassessment after artifact, model, endpoint, package, tool contract,
capability, advisory, signer, builder, workflow, registry, repository,
assessment, contract, maintainer, ownership, subcontractor, region, data-flow,
support-status, runtime, or internal-use changes.

The lab maps signer compromise, artifact drift, registry removal, and explicit
revocation to quarantine. Other signals require reassessment. Stable signal IDs
make duplicate delivery idempotent.

Prepare kill switches, credential revocation, endpoint and egress denial,
affected-component queries, evidence preservation, known-good replacements,
configuration/data export, continuity fallback, communication, and recovery
verification.

Offboarding must verify credentials and federation removed; artifacts and
endpoints unreachable; catalog and allowlist entries removed; vendor access
disabled; data returned/deleted; replacement operational; and no old effects.
The lab only gates and records this transition; it does not perform it.

## 12. Metrics and common tooling

Example metrics:

- inventory coverage = governed observed suppliers / observed suppliers;
- component evidence coverage = components with required current evidence /
  active in-scope components;
- critical freshness = critical suppliers with current due diligence / critical
  suppliers;
- SBOM coverage = deployed immutable artifacts with authenticated current SBOM /
  deployed immutable artifacts;
- finding SLA compliance = findings remediated by due date / findings due;
- time to impact query = affected-system result − advisory admission;
- quarantine convergence = last required denial − quarantine issue; and
- exit verification = completed verified exit obligations / obligations due.

| Need | Common choices | Verify |
|---|---|---|
| inventory | CMDB, CSPM/CNAPP, service catalog, IdP, runtime discovery | observed versus declared populations |
| MCP discovery | official registry, subregistry, allowlisted catalog | publisher, version, digest, revocation |
| supplier workflow | ServiceNow IRM, Archer, OneTrust, AuditBoard | scope, roles, versioning, expiry |
| SBOM/xBOM | CycloneDX, SPDX; Syft, cdxgen, Trivy | subject, completeness, relationships |
| provenance | in-toto, SLSA, GitHub attestations | subject, source, builder, workflow |
| signing | Cosign/Sigstore, KMS/HSM, Notary Project | roots, identity, issuer, digest |
| vulnerabilities | OSV, Grype, Trivy, commercial SCA | identity, DB age, coverage, aliases |
| VEX | CycloneDX VEX, CSAF, OpenVEX | issuer, scope, status, evidence |
| graph | GUAC, SBOM repositories, lineage systems | ingestion provenance and join quality |
| posture | OpenSSF Scorecard | use individual signals, not score-only admission |
| updates | TUF, immutable registries | rollback/freeze/mix-and-match protection |
| policy | OPA, Cedar, Kyverno, Gatekeeper | trusted inputs and fail-closed behavior |

Tool output is evidence input. The application owns joins, policy, approval,
state transitions, external effects, verification, and audit.

## 13. Lab walkthrough

From the repository root:

```bash
uv sync --extra contributor --frozen
uv run python curriculum/advanced/26-mcp-supply-chain-risk-management/lab.py
uv run pytest -q tests/test_course_26_supply_chain_risk.py
```

The scenario registers a critical supplier and rooted server/SDK graph; creates
authenticated supplier and component evidence; verifies exact bindings;
requires independent assessment; evaluates findings and a component-bound
exception; creates a short-lived proposal; requires committee approval;
records an idempotent admission; invalidates it on every material signal; gates
offboarding; and reports portfolio coverage.

The 95 focused cases cover metadata, ownership, freshness, exit planning,
dependency graph closure, immutable component identity, tampering, producer
trust, stale/failed evidence, every required evidence kind, fake independence,
duplicates, critical findings, exact exceptions, VEX contradictions, overdue
findings, approval role/replay/concurrency, fabricated proposals, unknown
retries, decision expiry, every material signal, quarantine, offboarding,
metric denominators, and audit minimization.

### Exercises

1. Add a remote-model component with model-card, license, data-flow, and
   continuity requirements.
2. Import CycloneDX 1.7 and compare its graph with the normalized inventory.
3. Add a concentration limit without converting tiers into arithmetic scores.
4. Model a compromised reusable build workflow and query every affected artifact.
5. Make the journal restart-safe and prove queue redelivery cannot duplicate a
   decision.
6. Test an exit drill covering credentials, data return, replacement readiness,
   and forbidden-effect absence.

## 14. Production boundaries and checklist

This lab does not prove supplier identity, ownership, viability, contract
performance, questionnaire truth, SBOM completeness, build isolation, SLSA
level, component safety, producer independence, production admission,
distributed atomicity, legal compliance, or complete inventory. Production
claims require actual supplier, build, registry, artifact, runtime, enforcement,
and outcome evidence.

Review checklist:

- [ ] Business objective, tenants, data, capabilities, effects, and owners are explicit.
- [ ] Direct, transitive, hosted, build, model, data, registry, and exit dependencies are inventoried.
- [ ] Stable supplier, component, artifact, and evidence identifiers are used.
- [ ] Graph completeness is measured for a named population.
- [ ] Tier criteria preserve impact dimensions and avoid a magic score.
- [ ] Due diligence is scoped, current, corroborated, and separately owned.
- [ ] Supplier and artifact evidence are distinct but exactly correlated.
- [ ] Signature identity, issuer, subject, and trusted roots are constrained.
- [ ] Provenance matches expected source, builder, workflow, and materials.
- [ ] SBOM completeness and relationships are measured.
- [ ] Vulnerability data records database freshness and exact subject.
- [ ] VEX claims are authenticated, exact, justified, and current.
- [ ] Registry listing does not become admission authority.
- [ ] Contract, response, continuity, data, and exit duties are testable.
- [ ] Critical suppliers require independent evidence and proper authority.
- [ ] Exceptions are exact, compensated, monitored, reviewed, and expiring.
- [ ] Open critical findings cannot use the ordinary exception path.
- [ ] Approval is exact, expiring, single-use, and atomically consumed.
- [ ] Unknown outcomes reuse the logical operation ID and reconcile state.
- [ ] Material signals invalidate admission; compromise signals quarantine.
- [ ] Revocation, continuity, recovery, and exit are outcome-verified.
- [ ] Metrics expose populations, denominators, gaps, and freshness.
- [ ] Runtime calls remain independently authenticated and authorized.

## References

### C-SCRM and secure development

- [NIST SP 800-161 Rev. 1 Update 1](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final)
- [NIST C-SCRM project](https://csrc.nist.gov/Projects/Cyber-Supply-Chain-Risk-Management)
- [NIST SP 1326 due diligence guide](https://csrc.nist.gov/pubs/sp/1326/final)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST SSDF version status](https://csrc.nist.gov/Projects/ssdf/publications)
- [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [CISA 2025 SBOM Minimum Elements](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)

### Provenance, inventory, updates, and discovery

- [SLSA 1.2](https://slsa.dev/spec/v1.2/)
- [in-toto specifications](https://in-toto.io/docs/specs/)
- [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [CycloneDX 1.7](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
- [TUF specification](https://theupdateframework.io/spec/)
- [GUAC documentation](https://docs.guac.sh/guac/)
- [OSV](https://osv.dev/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [CISA VEX minimum requirements](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf)
- [Official MCP Registry documentation](https://registry.modelcontextprotocol.io/docs)
- [MCP Registry and subregistry model](https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/)
