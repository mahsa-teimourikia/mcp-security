"""Course 29: evidence-backed MCP security architecture review workshop.

Diagrams, claims, model suggestions, tests, and review status are evidence
inputs—not production authority. Trusted code validates an immutable package,
checks exact current evidence, analyzes protected paths, evaluates abuse cases,
produces owned findings, and records an independent review outcome. Material
change invalidates that outcome.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import json
import re
from threading import Lock
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import networkx as nx


UTC = timezone.utc
NOW = datetime(2026, 10, 31, 18, 0, tzinfo=UTC)
REVIEW_POLICY_VERSION = "mcp-architecture-review/2026-10-31"
MAX_EVIDENCE_AGE = timedelta(days=90)
MAX_ATTESTATION_TTL = timedelta(hours=1)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,159}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_CATEGORIES = frozenset({
    "identity", "authorization", "provenance", "isolation", "egress",
    "data_protection", "telemetry", "incident_response", "recovery",
    "change_management",
})
TRUSTED_EVIDENCE_PRODUCERS = {
    kind: frozenset({f"producer:{kind}"})
    for kind in {
        "attestation", "configuration", "data_flow_review", "integration_test",
        "negative_test", "pipeline_test", "recovery_drill", "runtime_test",
        "sbom", "tabletop", "trace_replay",
    }
}


class ReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class EvidenceResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class ReviewState(StrEnum):
    NEEDS_REMEDIATION = "needs_remediation"
    ELIGIBLE_FOR_RISK_DECISION = "eligible_for_risk_decision"
    INVALIDATED = "invalidated"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        normalized = [_jsonable(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + sha256(payload).hexdigest()


def require_id(label: str, value: str) -> None:
    if not SAFE_ID.fullmatch(value):
        raise ReviewError("FIELD_INVALID", f"{label} must be a bounded identifier")


@dataclass(frozen=True)
class Component:
    component_id: str
    kind: str
    trust_zone: str
    tenant_scope: frozenset[str]
    owner: str
    version: str
    artifact_digest: str
    capabilities: frozenset[str]


@dataclass(frozen=True)
class DataFlow:
    flow_id: str
    source: str
    target: str
    protocol: str
    data_classification: str
    authenticated: bool
    encrypted: bool
    authorized_at_target: bool
    tenant_bound: bool
    telemetry: bool
    side_effect: bool


@dataclass(frozen=True)
class ArchitecturePackage:
    package_id: str
    version: str
    system_id: str
    title: str
    tenant_model: str
    business_owner: str
    technical_owner: str
    security_owner: str
    protocol_versions: tuple[str, ...]
    data_classes: frozenset[str]
    components: tuple[Component, ...]
    flows: tuple[DataFlow, ...]
    entrypoints: frozenset[str]
    protected_resources: frozenset[str]
    assumptions: tuple[str, ...]
    non_goals: tuple[str, ...]
    change_ids: tuple[str, ...]
    prepared_at: datetime
    package_digest: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("package_digest")
        return value


def seal_package(package: ArchitecturePackage) -> ArchitecturePackage:
    return replace(package, package_digest=digest(package.unsigned()))


@dataclass(frozen=True)
class ControlClaim:
    claim_id: str
    category: str
    statement: str
    subject_id: str
    owner: str
    required_evidence_kinds: frozenset[str]


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    claim_id: str
    subject_id: str
    subject_version: str
    kind: str
    producer: str
    source_locator: str
    test_ids: tuple[str, ...]
    result: EvidenceResult
    collected_at: datetime
    expires_at: datetime
    artifact_digest: str
    evidence_digest: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("evidence_digest")
        return value


def seal_evidence(item: EvidenceItem) -> EvidenceItem:
    return replace(item, evidence_digest=digest(item.unsigned()))


@dataclass(frozen=True)
class ThreatScenario:
    threat_id: str
    title: str
    entrypoint: str
    target: str
    attack_refs: tuple[str, ...]
    violated_properties: frozenset[str]
    abuse_test_id: str


@dataclass(frozen=True)
class AbuseResult:
    test_id: str
    threat_id: str
    package_digest: str
    tenant_id: str
    result: EvidenceResult
    observed_effect: str
    evidence_ids: tuple[str, ...]
    executed_at: datetime


@dataclass(frozen=True)
class ReviewFinding:
    finding_id: str
    severity: Severity
    code: str
    title: str
    rationale: str
    component_ids: tuple[str, ...]
    flow_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    owner: str
    remediation: str
    due_at: datetime


@dataclass(frozen=True)
class ReviewMetrics:
    claims: int
    satisfied_claims: int
    evidence_slots: int
    satisfied_evidence_slots: int
    threats: int
    tested_threats: int
    passed_abuse_tests: int
    protected_paths: int
    secured_protected_paths: int
    evidence_coverage: float
    threat_test_coverage: float
    abuse_defense_pass_rate: float | None
    critical_path_coverage: float | None


@dataclass(frozen=True)
class ReviewReport:
    report_id: str
    package_id: str
    package_version: str
    package_digest: str
    policy_version: str
    state: ReviewState
    findings: tuple[ReviewFinding, ...]
    metrics: ReviewMetrics
    reviewed_at: datetime
    production_authorized: bool
    report_digest: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("report_digest")
        return value


@dataclass(frozen=True)
class ReviewAttestation:
    attestation_id: str
    purpose: str
    package_digest: str
    report_digest: str
    reviewer_id: str
    reviewer_role: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


@dataclass(frozen=True)
class RecordedReview:
    operation_id: str
    package_id: str
    package_digest: str
    report_digest: str
    attestation_id: str
    state: ReviewState
    recorded_at: datetime
    production_authorized: bool


@dataclass(frozen=True)
class MaterialChange:
    change_id: str
    package_id: str
    prior_package_digest: str
    changed_dimensions: frozenset[str]
    observed_at: datetime


MATERIAL_DIMENSIONS = frozenset({
    "artifact", "capability", "protocol", "identity", "authorization",
    "tenant", "data_classification", "trust_boundary", "egress",
    "side_effect", "dependency", "recovery", "telemetry",
})


def validate_package(package: ArchitecturePackage) -> None:
    for label, value in (
        ("package_id", package.package_id), ("version", package.version),
        ("system_id", package.system_id), ("business_owner", package.business_owner),
        ("technical_owner", package.technical_owner), ("security_owner", package.security_owner),
    ):
        require_id(label, value)
    if package.prepared_at.tzinfo is None:
        raise ReviewError("TIME_INVALID", "package time must be timezone-aware")
    if not package.title or not package.protocol_versions or not package.data_classes:
        raise ReviewError("PACKAGE_INCOMPLETE", "title, protocol versions, and data classes are required")
    if not package.assumptions or not package.non_goals or not package.change_ids:
        raise ReviewError("PACKAGE_INCOMPLETE", "assumptions, non-goals, and change identity are required")
    if package.package_digest != digest(package.unsigned()):
        raise ReviewError("PACKAGE_INTEGRITY_INVALID", "architecture package digest does not verify")
    component_ids = [item.component_id for item in package.components]
    flow_ids = [item.flow_id for item in package.flows]
    if len(component_ids) != len(set(component_ids)) or len(flow_ids) != len(set(flow_ids)):
        raise ReviewError("PACKAGE_IDENTITY_CONFLICT", "component and flow IDs must be unique")
    if not package.entrypoints or not package.protected_resources:
        raise ReviewError("PACKAGE_INCOMPLETE", "entrypoints and protected resources are required")
    known = set(component_ids)
    if not package.entrypoints.issubset(known) or not package.protected_resources.issubset(known):
        raise ReviewError("PACKAGE_REFERENCE_INVALID", "entrypoints and resources must reference components")
    for component in package.components:
        for label, value in (("component_id", component.component_id), ("owner", component.owner), ("version", component.version)):
            require_id(label, value)
        if not DIGEST.fullmatch(component.artifact_digest) or not component.tenant_scope or not component.capabilities:
            raise ReviewError("COMPONENT_INVALID", "components require digest, tenant scope, and capabilities")
        for tenant_id in component.tenant_scope:
            require_id("tenant_id", tenant_id)
    endpoint_pairs: set[tuple[str, str]] = set()
    for flow in package.flows:
        require_id("flow_id", flow.flow_id)
        if flow.source not in known or flow.target not in known or not flow.protocol or not flow.data_classification:
            raise ReviewError("FLOW_INVALID", "flows require known endpoints, protocol, and classification")
        pair = (flow.source, flow.target)
        if pair in endpoint_pairs:
            raise ReviewError("FLOW_ENDPOINT_CONFLICT", "parallel flows require explicit intermediary components")
        endpoint_pairs.add(pair)


def _finding(
    package: ArchitecturePackage, code: str, severity: Severity, title: str, rationale: str,
    *, components: Iterable[str] = (), flows: Iterable[str] = (), evidence: Iterable[str] = (),
    owner: str | None = None, remediation: str, now: datetime,
) -> ReviewFinding:
    component_ids, flow_ids, evidence_ids = tuple(sorted(components)), tuple(sorted(flows)), tuple(sorted(evidence))
    payload = {"package": package.package_digest, "code": code, "components": component_ids, "flows": flow_ids, "evidence": evidence_ids}
    return ReviewFinding(
        "ARF-" + sha256(canonical_json(payload)).hexdigest()[:20], severity, code,
        title, rationale, component_ids, flow_ids, evidence_ids,
        owner or package.security_owner, remediation,
        now + (timedelta(days=7) if severity in {Severity.CRITICAL, Severity.HIGH} else timedelta(days=30)),
    )


class ArchitectureReviewer:
    """Deterministic review engine; findings are not deployment authorization."""

    def __init__(self, trusted_evidence_producers: Mapping[str, frozenset[str]] | None = None) -> None:
        self.trusted_evidence_producers = trusted_evidence_producers or TRUSTED_EVIDENCE_PRODUCERS

    def review(
        self, package: ArchitecturePackage, claims: Iterable[ControlClaim], evidence: Iterable[EvidenceItem],
        threats: Iterable[ThreatScenario], abuse_results: Iterable[AbuseResult], now: datetime,
    ) -> ReviewReport:
        validate_package(package)
        if now.tzinfo is None or now < package.prepared_at:
            raise ReviewError("TIME_INVALID", "review time must be aware and not precede the package")
        claim_list, evidence_list = tuple(claims), tuple(evidence)
        threat_list, result_list = tuple(threats), tuple(abuse_results)
        findings: list[ReviewFinding] = []
        claim_ids = [item.claim_id for item in claim_list]
        evidence_ids = [item.evidence_id for item in evidence_list]
        threat_ids = [item.threat_id for item in threat_list]
        result_ids = [item.test_id for item in result_list]
        if len(claim_ids) != len(set(claim_ids)) or len(evidence_ids) != len(set(evidence_ids)) or len(threat_ids) != len(set(threat_ids)) or len(result_ids) != len(set(result_ids)):
            raise ReviewError("REVIEW_IDENTITY_CONFLICT", "claim, evidence, threat, and test IDs must be unique")
        if not claim_list or not threat_list:
            raise ReviewError("REVIEW_SCOPE_EMPTY", "control claims and threats are required")

        component_map = {item.component_id: item for item in package.components}
        categories = {item.category for item in claim_list}
        for missing in sorted(REQUIRED_CATEGORIES - categories):
            findings.append(_finding(
                package, "CONTROL_CATEGORY_MISSING", Severity.HIGH, f"Required control category missing: {missing}",
                "The review has no falsifiable claim for a required control plane.",
                remediation=f"Define an owned {missing} claim and exact evidence requirements.", now=now,
            ))

        satisfied_claims = satisfied_slots = total_slots = 0
        valid_evidence_ids: set[str] = set()
        for claim in claim_list:
            require_id("claim_id", claim.claim_id)
            if claim.subject_id not in {package.package_id, *component_map} or not claim.owner or not claim.statement or not claim.required_evidence_kinds:
                findings.append(_finding(
                    package, "CONTROL_CLAIM_INVALID", Severity.HIGH, "Control claim is incomplete",
                    f"Claim {claim.claim_id} lacks a known subject, owner, statement, or evidence contract.",
                    components=(claim.subject_id,) if claim.subject_id in component_map else (),
                    remediation="Bind the claim to a known exact subject, owner, and required evidence kinds.", now=now,
                ))
                continue
            require_id("claim_owner", claim.owner)
            cited = [item for item in evidence_list if item.claim_id == claim.claim_id]
            kinds_passed: set[str] = set()
            for item in cited:
                require_id("evidence_id", item.evidence_id)
                subject_version = package.version if claim.subject_id == package.package_id else component_map[claim.subject_id].version
                subject_digest = package.package_digest if claim.subject_id == package.package_id else component_map[claim.subject_id].artifact_digest
                valid = (
                    item.subject_id == claim.subject_id and item.subject_version == subject_version
                    and item.result == EvidenceResult.PASS and item.collected_at.tzinfo is not None
                    and item.expires_at.tzinfo is not None and item.collected_at <= now < item.expires_at
                    and now - item.collected_at <= MAX_EVIDENCE_AGE
                    and item.artifact_digest == subject_digest
                    and item.evidence_digest == digest(item.unsigned())
                    and item.producer in self.trusted_evidence_producers.get(item.kind, frozenset())
                    and bool(item.source_locator and item.test_ids)
                )
                if valid:
                    kinds_passed.add(item.kind)
                    valid_evidence_ids.add(item.evidence_id)
                else:
                    findings.append(_finding(
                        package, "EVIDENCE_INVALID", Severity.HIGH, "Control evidence is invalid or out of scope",
                        f"Evidence {item.evidence_id} is stale, failed, inconclusive, tampered, incomplete, or names the wrong subject version.",
                        components=(claim.subject_id,) if claim.subject_id in component_map else (), evidence=(item.evidence_id,),
                        owner=claim.owner, remediation="Regenerate exact current passing evidence from an admitted producer.", now=now,
                    ))
            total_slots += len(claim.required_evidence_kinds)
            satisfied_slots += len(claim.required_evidence_kinds & kinds_passed)
            missing_kinds = claim.required_evidence_kinds - kinds_passed
            if missing_kinds:
                findings.append(_finding(
                    package, "CONTROL_EVIDENCE_MISSING", Severity.HIGH, "Control claim lacks required proof",
                    f"Claim {claim.claim_id} is missing passing evidence kinds: {', '.join(sorted(missing_kinds))}.",
                    components=(claim.subject_id,) if claim.subject_id in component_map else (), evidence=(item.evidence_id for item in cited),
                    owner=claim.owner, remediation="Run required positive and negative tests against the exact reviewed version.", now=now,
                ))
            else:
                satisfied_claims += 1

        graph = nx.DiGraph()
        graph.add_nodes_from(component_map)
        for flow in package.flows:
            graph.add_edge(flow.source, flow.target, flow=flow)
            crosses_zone = component_map[flow.source].trust_zone != component_map[flow.target].trust_zone
            if component_map[flow.source].tenant_scope.isdisjoint(component_map[flow.target].tenant_scope):
                findings.append(_finding(
                    package, "CROSS_TENANT_FLOW", Severity.CRITICAL, "Flow joins disjoint tenant scopes",
                    f"Flow {flow.flow_id} connects components with no shared authorized tenant scope.",
                    components=(flow.source, flow.target), flows=(flow.flow_id,),
                    remediation="Partition the path or obtain explicit cross-tenant investigative and resource authority.", now=now,
                ))
            if crosses_zone and not (flow.authenticated and flow.encrypted):
                findings.append(_finding(
                    package, "TRUST_BOUNDARY_UNPROTECTED", Severity.CRITICAL,
                    "Trust-boundary flow lacks authentication or encryption",
                    f"Flow {flow.flow_id} crosses security zones without both transport protections.",
                    components=(flow.source, flow.target), flows=(flow.flow_id,),
                    remediation="Authenticate both endpoints and encrypt the boundary transport.", now=now,
                ))
            if flow.data_classification in {"confidential", "restricted"} and not (flow.authorized_at_target and flow.tenant_bound):
                findings.append(_finding(
                    package, "RESOURCE_AUTHORIZATION_MISSING", Severity.CRITICAL,
                    "Sensitive flow lacks target authorization or tenant binding",
                    f"Flow {flow.flow_id} carries {flow.data_classification} data without enforcing both properties at the target.",
                    components=(flow.source, flow.target), flows=(flow.flow_id,),
                    remediation="Derive tenant and principal from authenticated state and authorize the exact target action.", now=now,
                ))
            if flow.side_effect and not flow.telemetry:
                findings.append(_finding(
                    package, "EFFECT_TELEMETRY_MISSING", Severity.HIGH, "Side-effect path lacks outcome telemetry",
                    f"Flow {flow.flow_id} can change state without reconstructable effect evidence.",
                    components=(flow.source, flow.target), flows=(flow.flow_id,),
                    remediation="Emit admitted request, decision, effect, and independent outcome evidence.", now=now,
                ))

        path_count = secured_paths = 0
        for entrypoint in sorted(package.entrypoints):
            for resource in sorted(package.protected_resources):
                if not nx.has_path(graph, entrypoint, resource):
                    findings.append(_finding(
                        package, "ARCHITECTURE_PATH_MISSING", Severity.HIGH, "Declared protected resource is unreachable",
                        f"No reviewed path connects {entrypoint} to {resource}; the DFD or scope is incomplete.",
                        components=(entrypoint, resource), remediation="Correct the DFD and inventory before drawing control conclusions.", now=now,
                    ))
                    continue
                for path in nx.all_simple_paths(graph, entrypoint, resource, cutoff=max(2, len(component_map))):
                    path_count += 1
                    path_flows = [graph.edges[path[index], path[index + 1]]["flow"] for index in range(len(path) - 1)]
                    enforcers = sum("policy_enforcer" in component_map[node].capabilities or "resource_authorizer" in component_map[node].capabilities for node in path)
                    secured = (
                        all(item.authenticated and item.encrypted and item.tenant_bound and item.authorized_at_target and item.telemetry for item in path_flows)
                        and enforcers >= 2
                        and "resource_authorizer" in component_map[resource].capabilities
                    )
                    if secured:
                        secured_paths += 1
                    else:
                        findings.append(_finding(
                            package, "PROTECTED_PATH_INCOMPLETE", Severity.CRITICAL,
                            "Protected path lacks complete independent enforcement",
                            f"Path {' -> '.join(path)} does not prove per-hop protection and at least two independent authorization enforcers.",
                            components=path, flows=(item.flow_id for item in path_flows),
                            remediation="Enforce tenant-bound authorization at MCP/tool and final resource boundaries and test bypass paths.", now=now,
                        ))

        tested_threats: set[str] = set()
        passed_results = 0
        for threat in threat_list:
            require_id("threat_id", threat.threat_id)
            require_id("abuse_test_id", threat.abuse_test_id)
            if threat.entrypoint not in component_map or threat.target not in component_map or not threat.title or not threat.attack_refs or not threat.violated_properties:
                findings.append(_finding(
                    package, "THREAT_SCENARIO_INVALID", Severity.HIGH, "Threat scenario is incomplete",
                    f"Threat {threat.threat_id} lacks known endpoints, adversary references, or violated properties.",
                    remediation="Bind the threat to reviewed components, protected properties, and current ATT&CK or ATLAS behavior.", now=now,
                ))
                continue
            matched = [item for item in result_list if item.threat_id == threat.threat_id and item.test_id == threat.abuse_test_id]
            authorized_tenants: set[str] = set()
            if threat.entrypoint in component_map and threat.target in component_map and nx.has_path(graph, threat.entrypoint, threat.target):
                for path in nx.all_simple_paths(graph, threat.entrypoint, threat.target, cutoff=max(2, len(component_map))):
                    path_tenants = set(component_map[path[0]].tenant_scope)
                    for node in path[1:]:
                        path_tenants &= component_map[node].tenant_scope
                    authorized_tenants |= path_tenants
            valid = [
                item for item in matched
                if item.package_digest == package.package_digest
                and item.tenant_id in authorized_tenants
                and item.executed_at.tzinfo is not None and item.executed_at <= now
                and bool(item.observed_effect and item.evidence_ids)
                and all(eid in valid_evidence_ids for eid in item.evidence_ids)
            ]
            if not valid:
                findings.append(_finding(
                    package, "ABUSE_TEST_MISSING", Severity.HIGH, "Threat lacks exact executable abuse evidence",
                    f"Threat {threat.threat_id} has no valid result for {threat.abuse_test_id} on this package digest.",
                    remediation="Execute the abuse case against the exact reviewed build and preserve admitted evidence IDs.", now=now,
                ))
                continue
            tested_threats.add(threat.threat_id)
            result = valid[-1]
            if result.result == EvidenceResult.PASS and result.observed_effect == "blocked_and_verified":
                passed_results += 1
            else:
                severity = Severity.CRITICAL if result.observed_effect == "forbidden_effect_completed" else Severity.HIGH
                findings.append(_finding(
                    package, "ABUSE_TEST_FAILED", severity, "Abuse-case defense is not proven",
                    f"Test {result.test_id} ended {result.result} with observed effect {result.observed_effect}.",
                    components=(threat.entrypoint, threat.target), evidence=result.evidence_ids,
                    remediation="Repair enforcement and rerun with an independent outcome oracle.", now=now,
                ))

        state = ReviewState.NEEDS_REMEDIATION if any(item.severity in {Severity.HIGH, Severity.CRITICAL} for item in findings) else ReviewState.ELIGIBLE_FOR_RISK_DECISION
        metrics = ReviewMetrics(
            len(claim_list), satisfied_claims, total_slots, satisfied_slots,
            len(threat_list), len(tested_threats), passed_results, path_count, secured_paths,
            satisfied_slots / total_slots if total_slots else 0.0,
            len(tested_threats) / len(threat_list),
            passed_results / len(tested_threats) if tested_threats else None,
            secured_paths / path_count if path_count else None,
        )
        unsigned = {
            "report_id": "ARR-" + sha256(canonical_json({"package": package.package_digest, "policy": REVIEW_POLICY_VERSION, "at": now})).hexdigest()[:20],
            "package_id": package.package_id, "package_version": package.version,
            "package_digest": package.package_digest, "policy_version": REVIEW_POLICY_VERSION,
            "state": state, "findings": tuple(sorted(findings, key=lambda item: (item.severity, item.code, item.finding_id))),
            "metrics": metrics, "reviewed_at": now, "production_authorized": False,
        }
        return ReviewReport(**unsigned, report_digest=digest(unsigned))


class ReviewRegistry:
    """Records peer-attested review outcomes; it cannot authorize deployment."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.records: dict[str, RecordedReview] = {}
        self.used_attestations: set[str] = set()
        self.lock = Lock()

    def attest(
        self, package: ArchitecturePackage, report: ReviewReport, reviewer_id: str,
        reviewer_role: str, now: datetime, ttl: timedelta = timedelta(minutes=30),
    ) -> ReviewAttestation:
        require_id("reviewer_id", reviewer_id)
        if reviewer_role not in {"security_architect", "architecture_review_board"}:
            raise ReviewError("REVIEWER_ROLE_INVALID", "review attestation requires an independent reviewer")
        if reviewer_id in {package.business_owner, package.technical_owner, package.security_owner}:
            raise ReviewError("REVIEWER_NOT_INDEPENDENT", "package owners cannot independently attest their own review")
        if ttl <= timedelta(0) or ttl > MAX_ATTESTATION_TTL:
            raise ReviewError("ATTESTATION_TTL_INVALID", "attestation TTL is outside policy")
        if now.tzinfo is None or now < report.reviewed_at:
            raise ReviewError("TIME_INVALID", "attestation time must be aware and follow the review")
        if report.package_digest != package.package_digest or report.report_digest != digest(report.unsigned()):
            raise ReviewError("REPORT_INTEGRITY_INVALID", "report is tampered or belongs to another package")
        unsigned = {
            "attestation_id": "ARA-" + sha256(canonical_json({"package": package.package_digest, "report": report.report_digest, "reviewer": reviewer_id, "at": now})).hexdigest()[:20],
            "purpose": "record_architecture_review", "package_digest": package.package_digest,
            "report_digest": report.report_digest, "reviewer_id": reviewer_id,
            "reviewer_role": reviewer_role, "issued_at": now, "expires_at": now + ttl,
        }
        return ReviewAttestation(**unsigned, signature=self.private_key.sign(canonical_json(unsigned)).hex())

    def record(
        self, operation_id: str, package: ArchitecturePackage, report: ReviewReport,
        attestation: ReviewAttestation, now: datetime,
    ) -> RecordedReview:
        require_id("operation_id", operation_id)
        if now.tzinfo is None:
            raise ReviewError("TIME_INVALID", "record time must be timezone-aware")
        try:
            self.private_key.public_key().verify(bytes.fromhex(attestation.signature), canonical_json(attestation.unsigned()))
        except (InvalidSignature, ValueError) as exc:
            raise ReviewError("ATTESTATION_SIGNATURE_INVALID", "attestation signature does not verify") from exc
        if attestation.purpose != "record_architecture_review" or attestation.package_digest != package.package_digest or attestation.report_digest != report.report_digest:
            raise ReviewError("ATTESTATION_SCOPE_MISMATCH", "attestation is not bound to the exact package and report")
        if now < attestation.issued_at or now >= attestation.expires_at:
            raise ReviewError("ATTESTATION_EXPIRED", "attestation is not currently valid")
        validate_package(package)
        if report.report_digest != digest(report.unsigned()) or report.package_digest != package.package_digest:
            raise ReviewError("REPORT_INTEGRITY_INVALID", "report does not verify for this package")
        proposed = RecordedReview(operation_id, package.package_id, package.package_digest, report.report_digest, attestation.attestation_id, report.state, now, False)
        with self.lock:
            existing = self.records.get(operation_id)
            if existing:
                if existing.package_digest != proposed.package_digest or existing.report_digest != proposed.report_digest:
                    raise ReviewError("OPERATION_CONFLICT", "operation ID already names a different review")
                return existing
            if attestation.attestation_id in self.used_attestations:
                raise ReviewError("ATTESTATION_REPLAYED", "attestation was already consumed")
            self.used_attestations.add(attestation.attestation_id)
            self.records[operation_id] = proposed
            return proposed

    def invalidate(self, operation_id: str, change: MaterialChange) -> RecordedReview:
        require_id("change_id", change.change_id)
        if not change.changed_dimensions or not change.changed_dimensions.issubset(MATERIAL_DIMENSIONS):
            raise ReviewError("CHANGE_INVALID", "change dimensions are empty or unknown")
        if change.observed_at.tzinfo is None:
            raise ReviewError("TIME_INVALID", "change time must be timezone-aware")
        with self.lock:
            existing = self.records.get(operation_id)
            if (
                existing is None or existing.package_id != change.package_id
                or existing.package_digest != change.prior_package_digest
                or change.observed_at < existing.recorded_at
            ):
                raise ReviewError("REVIEW_RECORD_NOT_FOUND", "change does not match a recorded review")
            invalidated = replace(existing, state=ReviewState.INVALIDATED, production_authorized=False)
            self.records[operation_id] = invalidated
            return invalidated


def review_portfolio_metrics(reports: Iterable[ReviewReport]) -> dict[str, float | int | None]:
    population = tuple(reports)
    if not population:
        raise ValueError("report population must not be empty")
    findings = [finding for report in population for finding in report.findings]
    by_severity = Counter(str(item.severity) for item in findings)
    path_values = [item.metrics.critical_path_coverage for item in population if item.metrics.critical_path_coverage is not None]
    return {
        "reviewed_packages": len(population),
        "eligible_packages": sum(item.state == ReviewState.ELIGIBLE_FOR_RISK_DECISION for item in population),
        "needs_remediation_packages": sum(item.state == ReviewState.NEEDS_REMEDIATION for item in population),
        "critical_findings": by_severity["critical"], "high_findings": by_severity["high"],
        "mean_evidence_coverage": sum(item.metrics.evidence_coverage for item in population) / len(population),
        "mean_threat_test_coverage": sum(item.metrics.threat_test_coverage for item in population) / len(population),
        "mean_critical_path_coverage": sum(path_values) / len(path_values) if path_values else None,
    }


def _component(component_id: str, kind: str, zone: str, capabilities: Iterable[str], version: str = "1.0.0") -> Component:
    return Component(component_id, kind, zone, frozenset({"tenant:acme"}), f"owner:{component_id.split(':')[-1]}", version, "sha256:" + sha256(component_id.encode()).hexdigest(), frozenset(capabilities))


def demo_package(*, secure: bool = True) -> ArchitecturePackage:
    components = (
        _component("component:host", "mcp_host", "user", {"policy_enforcer"}),
        _component("component:gateway", "mcp_gateway", "edge", {"policy_enforcer", "protocol_adapter"}),
        _component("component:server", "mcp_server", "workload", {"policy_enforcer", "tool_executor"}, "support-8.2.0"),
        _component("component:tickets", "protected_resource", "data", {"resource_authorizer", "system_of_record"}),
        _component("component:soc", "telemetry", "security", {"evidence_store"}),
    )
    flows = (
        DataFlow("flow:host-gateway", "component:host", "component:gateway", "MCP-2026-07-28/HTTPS", "confidential", True, True, True, True, True, False),
        DataFlow("flow:gateway-server", "component:gateway", "component:server", "MCP-2026-07-28/HTTPS", "confidential", True, True, True, True, True, False),
        DataFlow("flow:server-tickets", "component:server", "component:tickets", "OAuth2/HTTPS", "restricted", True, True, secure, secure, True, True),
        DataFlow("flow:server-soc", "component:server", "component:soc", "OTLP/HTTPS", "internal", True, True, True, True, True, False),
    )
    package = ArchitecturePackage(
        "package:support-agent", "29.1.0", "system:support-agent", "Multi-tenant support agent",
        "hard tenant partition with per-request resource authorization",
        "owner:business", "owner:platform", "owner:security",
        ("MCP-2026-07-28", "OAuth-2.1", "OTel-1.x"), frozenset({"internal", "confidential", "restricted"}),
        components, flows, frozenset({"component:host"}), frozenset({"component:tickets"}),
        ("identity provider and ticket ownership data are available", "MCP clients can be malicious"),
        ("model quality certification", "approval of production deployment"),
        ("change:capstone-review-29",), NOW - timedelta(hours=2), "",
    )
    return seal_package(package)


def demo_claims(package: ArchitecturePackage) -> tuple[ControlClaim, ...]:
    subjects = {
        "identity": "component:server", "authorization": "component:tickets", "provenance": "component:server",
        "isolation": "component:server", "egress": "component:server", "data_protection": package.package_id,
        "telemetry": "component:soc", "incident_response": package.package_id,
        "recovery": package.package_id, "change_management": package.package_id,
    }
    kinds = {
        "identity": {"integration_test", "configuration"}, "authorization": {"negative_test", "integration_test"},
        "provenance": {"attestation", "sbom"}, "isolation": {"runtime_test"}, "egress": {"negative_test"},
        "data_protection": {"data_flow_review"}, "telemetry": {"trace_replay"},
        "incident_response": {"tabletop"}, "recovery": {"recovery_drill"}, "change_management": {"pipeline_test"},
    }
    return tuple(ControlClaim(f"claim:{category}", category, f"The reviewed {category} boundary is enforced and independently testable.", subjects[category], f"owner:{category}", frozenset(kinds[category])) for category in sorted(REQUIRED_CATEGORIES))


def demo_evidence(package: ArchitecturePackage, claims: Iterable[ControlClaim], *, omit_kind: str | None = None) -> tuple[EvidenceItem, ...]:
    component_map = {item.component_id: item for item in package.components}
    items: list[EvidenceItem] = []
    counter = 0
    for claim in claims:
        version = package.version if claim.subject_id == package.package_id else component_map[claim.subject_id].version
        for kind in sorted(claim.required_evidence_kinds):
            if kind == omit_kind:
                continue
            counter += 1
            artifact_digest = package.package_digest if claim.subject_id == package.package_id else component_map[claim.subject_id].artifact_digest
            item = EvidenceItem(
                f"evidence:{counter:02d}", claim.claim_id, claim.subject_id, version, kind,
                f"producer:{kind}", f"repo://evidence/{counter:02d}", (f"test:{claim.category}:{kind}",),
                EvidenceResult.PASS, NOW - timedelta(days=1), NOW + timedelta(days=29),
                artifact_digest, "",
            )
            items.append(seal_evidence(item))
    return tuple(items)


def demo_threats() -> tuple[ThreatScenario, ...]:
    return (
        ThreatScenario("threat:cross-tenant", "Cross-tenant ticket disclosure", "component:host", "component:tickets", ("ATTACK:T1213", "ATLAS:AML.T0051"), frozenset({"confidentiality", "tenant_isolation"}), "test:cross-tenant"),
        ThreatScenario("threat:tool-misuse", "Indirect prompt injection drives a write", "component:host", "component:tickets", ("ATTACK:T1059", "ATTACK:T1204"), frozenset({"authorization", "integrity"}), "test:tool-misuse"),
        ThreatScenario("threat:token-replay", "Stolen delegated token is replayed", "component:gateway", "component:tickets", ("ATTACK:T1528",), frozenset({"identity", "least_privilege"}), "test:token-replay"),
    )


def demo_abuse_results(package: ArchitecturePackage, threats: Iterable[ThreatScenario], evidence: Iterable[EvidenceItem]) -> tuple[AbuseResult, ...]:
    evidence_ids = tuple(item.evidence_id for item in evidence)[:2]
    return tuple(AbuseResult(threat.abuse_test_id, threat.threat_id, package.package_digest, "tenant:acme", EvidenceResult.PASS, "blocked_and_verified", evidence_ids, NOW) for threat in threats)


def demo_review(*, secure: bool = True, omit_kind: str | None = None) -> tuple[ArchitecturePackage, tuple[ControlClaim, ...], tuple[EvidenceItem, ...], tuple[ThreatScenario, ...], tuple[AbuseResult, ...], ReviewReport]:
    package = demo_package(secure=secure)
    claims = demo_claims(package)
    evidence = demo_evidence(package, claims, omit_kind=omit_kind)
    threats = demo_threats()
    results = demo_abuse_results(package, threats, evidence)
    report = ArchitectureReviewer().review(package, claims, evidence, threats, results, NOW)
    return package, claims, evidence, threats, results, report


def main() -> None:
    _, _, _, _, _, flawed = demo_review(secure=False)
    package, _, _, _, _, report = demo_review()
    registry = ReviewRegistry()
    attestation = registry.attest(package, report, "reviewer:independent", "security_architect", NOW + timedelta(minutes=1))
    record = registry.record("operation:course29-review", package, report, attestation, NOW + timedelta(minutes=2))
    invalidated = registry.invalidate("operation:course29-review", MaterialChange(
        "change:server-capability", package.package_id, package.package_digest, frozenset({"capability"}), NOW + timedelta(days=1),
    ))
    print(json.dumps({
        "flawed_state": flawed.state, "flawed_critical_findings": sum(item.severity == Severity.CRITICAL for item in flawed.findings),
        "review_state": report.state, "evidence_coverage": report.metrics.evidence_coverage,
        "critical_path_coverage": report.metrics.critical_path_coverage,
        "recorded_state": record.state, "after_material_change": invalidated.state,
        "production_authorized": record.production_authorized,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
