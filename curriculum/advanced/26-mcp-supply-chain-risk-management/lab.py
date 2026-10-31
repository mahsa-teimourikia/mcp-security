"""Course 26 lab: evidence-bound MCP supply-chain admission and lifecycle.

The fixture is deterministic, offline, and credential-free. Ed25519 signatures
model authenticated supplier/component evidence and approval receipts. In-memory
stores model an enterprise inventory, exception register, and admission journal;
they are not a package scanner, registry, GRC platform, or production admission
controller.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum, StrEnum
from hashlib import sha256
import json
from threading import Lock
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


POLICY_VERSION = "mcp-scrm-policy-2026-10-30"


class SupplyChainError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class SupplierTier(StrEnum):
    STANDARD = "standard"
    ELEVATED = "elevated"
    CRITICAL = "critical"


class ServiceKind(StrEnum):
    MCP_SERVER = "mcp_server"
    SDK = "sdk"
    CONNECTOR = "connector"
    MODEL = "model"
    BUILD_PLATFORM = "build_platform"
    REGISTRY = "registry"
    DATA_SERVICE = "data_service"


class EvidenceKind(StrEnum):
    DUE_DILIGENCE = "due_diligence"
    SECURITY_PROGRAM = "security_program"
    CONTRACT = "contract"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"
    DATA_FLOW_REVIEW = "data_flow_review"
    INDEPENDENT_ASSESSMENT = "independent_assessment"
    SIGNATURE = "signature"
    PROVENANCE = "provenance"
    SBOM = "sbom"
    VULNERABILITY_REPORT = "vulnerability_report"
    LICENSE_REVIEW = "license_review"
    MODEL_CARD = "model_card"
    COMPENSATING_CONTROL_TEST = "compensating_control_test"


class EvidenceOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class FindingStatus(StrEnum):
    OPEN = "open"
    REMEDIATED = "remediated"
    NOT_AFFECTED = "not_affected"


class Exploitability(StrEnum):
    UNKNOWN = "unknown"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"


class Decision(StrEnum):
    APPROVE = "approve"
    CONDITIONAL = "conditional"
    DENY = "deny"


class AdmissionState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    CONDITIONAL = "conditional"
    DENIED = "denied"
    REASSESSMENT_REQUIRED = "reassessment_required"
    QUARANTINED = "quarantined"
    OFFBOARDED = "offboarded"


class SignalKind(StrEnum):
    ARTIFACT_DRIFT = "artifact_drift"
    NEW_VULNERABILITY = "new_vulnerability"
    SUPPLIER_INCIDENT = "supplier_incident"
    SIGNER_COMPROMISE = "signer_compromise"
    REGISTRY_REMOVAL = "registry_removal"
    OWNERSHIP_CHANGE = "ownership_change"
    MAINTENANCE_LAPSE = "maintenance_lapse"
    CONTRACT_CHANGE = "contract_change"
    SERVICE_CHANGE = "service_change"
    REVOCATION = "revocation"


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Mapping[str, Any]) -> str:
    return sha256(canonical_json(value)).hexdigest()


def is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


@dataclass(frozen=True)
class Principal:
    principal_id: str
    active: bool
    roles: frozenset[str]


@dataclass(frozen=True)
class SupplierProfile:
    supplier_id: str
    legal_name: str
    profile_version: str
    owner_id: str
    tier: SupplierTier
    service_kinds: tuple[ServiceKind, ...]
    security_contact: str
    incident_notice_hours: int
    data_regions: tuple[str, ...]
    subcontractor_ids: tuple[str, ...]
    exit_plan: str
    reviewed_at: int
    review_due_at: int

    def payload(self) -> dict[str, Any]:
        return {
            "supplier_id": self.supplier_id,
            "legal_name": self.legal_name,
            "profile_version": self.profile_version,
            "owner_id": self.owner_id,
            "tier": self.tier.value,
            "service_kinds": [item.value for item in self.service_kinds],
            "security_contact": self.security_contact,
            "incident_notice_hours": self.incident_notice_hours,
            "data_regions": list(self.data_regions),
            "subcontractor_ids": list(self.subcontractor_ids),
            "exit_plan": self.exit_plan,
            "reviewed_at": self.reviewed_at,
            "review_due_at": self.review_due_at,
        }


@dataclass(frozen=True)
class Component:
    component_id: str
    name: str
    kind: ServiceKind
    supplier_id: str
    version: str
    artifact_digest: str
    purl: str
    root: bool
    dependency_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    data_classes: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "name": self.name,
            "kind": self.kind.value,
            "supplier_id": self.supplier_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "purl": self.purl,
            "root": self.root,
            "dependency_ids": list(self.dependency_ids),
            "capabilities": list(self.capabilities),
            "data_classes": list(self.data_classes),
        }


@dataclass(frozen=True)
class IntakeRequest:
    intake_id: str
    tenant_scope: str
    business_owner_id: str
    use_case: str
    supplier: SupplierProfile
    components: tuple[Component, ...]
    requested_at: int
    policy_version: str
    version: int

    def payload(self) -> dict[str, Any]:
        return {
            "intake_id": self.intake_id,
            "tenant_scope": self.tenant_scope,
            "business_owner_id": self.business_owner_id,
            "use_case": self.use_case,
            "supplier": self.supplier.payload(),
            "components": [item.payload() for item in self.components],
            "requested_at": self.requested_at,
            "policy_version": self.policy_version,
            "version": self.version,
        }


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    kind: EvidenceKind
    subject_type: str
    subject_id: str
    subject_version: str
    subject_digest: str
    producer_id: str
    independent: bool
    outcome: EvidenceOutcome
    claim: str
    observed_at: int
    expires_at: int
    artifact_digest: str
    population: str
    numerator: int
    denominator: int
    unit: str

    def payload(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "subject_digest": self.subject_digest,
            "producer_id": self.producer_id,
            "independent": self.independent,
            "outcome": self.outcome.value,
            "claim": self.claim,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "artifact_digest": self.artifact_digest,
            "population": self.population,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class SignedEvidence:
    artifact: EvidenceArtifact
    signature: bytes


class EvidenceAuthority:
    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()

    def sign(self, artifact: EvidenceArtifact) -> SignedEvidence:
        return SignedEvidence(
            artifact, self._private_key.sign(canonical_json(artifact.payload()))
        )

    def verify(self, signed: SignedEvidence) -> None:
        try:
            self.public_key.verify(
                signed.signature, canonical_json(signed.artifact.payload())
            )
        except Exception as exc:
            raise SupplyChainError("EVIDENCE_SIGNATURE_INVALID") from exc


@dataclass(frozen=True)
class Finding:
    finding_id: str
    component_id: str
    severity: FindingSeverity
    status: FindingStatus
    exploitability: Exploitability
    source: str
    advisory_revision: str
    detected_at: int
    due_at: int
    resolution_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExceptionRequest:
    exception_id: str
    finding_id: str
    component_id: str
    component_version: str
    artifact_digest: str
    tenant_scope: str
    owner_id: str
    rationale: str
    compensating_controls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    monitoring_plan: str
    exit_plan: str
    starts_at: int
    review_at: int
    expires_at: int
    policy_version: str = POLICY_VERSION

    def payload(self) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "finding_id": self.finding_id,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "artifact_digest": self.artifact_digest,
            "tenant_scope": self.tenant_scope,
            "owner_id": self.owner_id,
            "rationale": self.rationale,
            "compensating_controls": list(self.compensating_controls),
            "evidence_ids": list(self.evidence_ids),
            "monitoring_plan": self.monitoring_plan,
            "exit_plan": self.exit_plan,
            "starts_at": self.starts_at,
            "review_at": self.review_at,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ActiveException:
    request: ExceptionRequest
    approver_id: str
    receipt_id: str


@dataclass(frozen=True)
class DecisionProposal:
    decision_id: str
    intake_id: str
    intake_version: int
    supplier_id: str
    supplier_profile_version: str
    recommendation: Decision
    verified_evidence_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    blockers: tuple[str, ...]
    expires_at: int
    policy_version: str = POLICY_VERSION

    def payload(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "intake_id": self.intake_id,
            "intake_version": self.intake_version,
            "supplier_id": self.supplier_id,
            "supplier_profile_version": self.supplier_profile_version,
            "recommendation": self.recommendation.value,
            "verified_evidence_ids": list(self.verified_evidence_ids),
            "exception_ids": list(self.exception_ids),
            "blockers": list(self.blockers),
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    kind: str
    payload_digest: str
    requester_id: str
    approver_id: str
    approver_role: str
    issued_at: int
    expires_at: int
    policy_version: str
    signature: bytes

    def unsigned(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "kind": self.kind,
            "payload_digest": self.payload_digest,
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "approver_role": self.approver_role,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
        }


class ApprovalService:
    def __init__(
        self,
        principals: Mapping[str, Principal],
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.principals = principals
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.receipts: dict[str, ApprovalReceipt] = {}
        self.consumed: set[str] = set()
        self._lock = Lock()

    def issue(
        self,
        kind: str,
        payload: Mapping[str, Any],
        requester_id: str,
        approver_id: str,
        approver_role: str,
        now: int,
        ttl_seconds: int = 300,
    ) -> ApprovalReceipt:
        approver = self.principals.get(approver_id)
        if requester_id == approver_id:
            raise SupplyChainError("SEPARATION_OF_DUTIES")
        if approver is None or not approver.active or approver_role not in approver.roles:
            raise SupplyChainError("APPROVER_NOT_AUTHORIZED")
        if ttl_seconds <= 0 or ttl_seconds > 900:
            raise SupplyChainError("APPROVAL_TTL_INVALID")
        payload_digest = digest(payload)
        receipt_id = sha256(
            f"{kind}|{payload_digest}|{approver_id}|{now}".encode()
        ).hexdigest()[:24]
        unsigned = {
            "receipt_id": receipt_id,
            "kind": kind,
            "payload_digest": payload_digest,
            "requester_id": requester_id,
            "approver_id": approver_id,
            "approver_role": approver_role,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "policy_version": POLICY_VERSION,
        }
        receipt = ApprovalReceipt(
            **unsigned, signature=self._private_key.sign(canonical_json(unsigned))
        )
        self.receipts[receipt_id] = receipt
        return receipt

    def consume(
        self,
        receipt_id: str,
        kind: str,
        payload: Mapping[str, Any],
        requester_id: str,
        now: int,
        allowed_roles: frozenset[str],
    ) -> ApprovalReceipt:
        with self._lock:
            receipt = self.receipts.get(receipt_id)
            if receipt is None:
                raise SupplyChainError("APPROVAL_UNKNOWN")
            try:
                self.public_key.verify(
                    receipt.signature, canonical_json(receipt.unsigned())
                )
            except Exception as exc:
                raise SupplyChainError("APPROVAL_SIGNATURE_INVALID") from exc
            if receipt_id in self.consumed:
                raise SupplyChainError("APPROVAL_REPLAY")
            if receipt.expires_at <= now:
                raise SupplyChainError("APPROVAL_EXPIRED")
            if receipt.policy_version != POLICY_VERSION:
                raise SupplyChainError("APPROVAL_POLICY_STALE")
            if receipt.kind != kind or receipt.requester_id != requester_id:
                raise SupplyChainError("APPROVAL_BINDING_MISMATCH")
            if receipt.payload_digest != digest(payload):
                raise SupplyChainError("APPROVAL_BINDING_MISMATCH")
            if receipt.approver_role not in allowed_roles:
                raise SupplyChainError("APPROVAL_ROLE_INSUFFICIENT")
            self.consumed.add(receipt_id)
            return receipt


@dataclass(frozen=True)
class SupplyChainPolicy:
    maximum_profile_age: int
    maximum_exception_duration: int
    maximum_decision_ttl: int
    supplier_requirements: Mapping[SupplierTier, frozenset[EvidenceKind]]
    component_requirements: Mapping[ServiceKind, frozenset[EvidenceKind]]
    decision_roles: Mapping[SupplierTier, frozenset[str]]
    quarantine_signals: frozenset[SignalKind]


BASE_COMPONENT_EVIDENCE = frozenset({
    EvidenceKind.SIGNATURE,
    EvidenceKind.PROVENANCE,
    EvidenceKind.SBOM,
    EvidenceKind.VULNERABILITY_REPORT,
})

DEFAULT_POLICY = SupplyChainPolicy(
    maximum_profile_age=90 * 86_400,
    maximum_exception_duration=14 * 86_400,
    maximum_decision_ttl=900,
    supplier_requirements={
        SupplierTier.STANDARD: frozenset({
            EvidenceKind.SECURITY_PROGRAM,
            EvidenceKind.CONTRACT,
            EvidenceKind.INCIDENT_RESPONSE,
        }),
        SupplierTier.ELEVATED: frozenset({
            EvidenceKind.SECURITY_PROGRAM,
            EvidenceKind.CONTRACT,
            EvidenceKind.INCIDENT_RESPONSE,
            EvidenceKind.DUE_DILIGENCE,
            EvidenceKind.BUSINESS_CONTINUITY,
        }),
        SupplierTier.CRITICAL: frozenset({
            EvidenceKind.SECURITY_PROGRAM,
            EvidenceKind.CONTRACT,
            EvidenceKind.INCIDENT_RESPONSE,
            EvidenceKind.DUE_DILIGENCE,
            EvidenceKind.BUSINESS_CONTINUITY,
            EvidenceKind.DATA_FLOW_REVIEW,
            EvidenceKind.INDEPENDENT_ASSESSMENT,
        }),
    },
    component_requirements={
        ServiceKind.MCP_SERVER: BASE_COMPONENT_EVIDENCE,
        ServiceKind.SDK: BASE_COMPONENT_EVIDENCE | {EvidenceKind.LICENSE_REVIEW},
        ServiceKind.CONNECTOR: BASE_COMPONENT_EVIDENCE | {EvidenceKind.DATA_FLOW_REVIEW},
        ServiceKind.MODEL: BASE_COMPONENT_EVIDENCE | {
            EvidenceKind.MODEL_CARD, EvidenceKind.LICENSE_REVIEW
        },
        ServiceKind.BUILD_PLATFORM: BASE_COMPONENT_EVIDENCE,
        ServiceKind.REGISTRY: BASE_COMPONENT_EVIDENCE,
        ServiceKind.DATA_SERVICE: BASE_COMPONENT_EVIDENCE | {EvidenceKind.DATA_FLOW_REVIEW},
    },
    decision_roles={
        SupplierTier.STANDARD: frozenset({"supply-chain-manager", "ciso"}),
        SupplierTier.ELEVATED: frozenset({"supply-chain-manager", "ciso"}),
        SupplierTier.CRITICAL: frozenset({"supply-chain-committee"}),
    },
    quarantine_signals=frozenset({
        SignalKind.SIGNER_COMPROMISE,
        SignalKind.ARTIFACT_DRIFT,
        SignalKind.REGISTRY_REMOVAL,
        SignalKind.REVOCATION,
    }),
)


@dataclass(frozen=True)
class Evaluation:
    intake_id: str
    verified_evidence_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    blockers: tuple[str, ...]


class SupplyChainEngine:
    def __init__(
        self,
        evidence_authority: EvidenceAuthority,
        principals: Mapping[str, Principal],
        policy: SupplyChainPolicy = DEFAULT_POLICY,
    ) -> None:
        self.evidence_authority = evidence_authority
        self.principals = principals
        self.policy = policy
        self.issued_proposals: dict[str, str] = {}

    def validate_intake(self, request: IntakeRequest, now: int) -> None:
        supplier = request.supplier
        owner = self.principals.get(request.business_owner_id)
        supplier_owner = self.principals.get(supplier.owner_id)
        required_text = (
            request.intake_id,
            request.tenant_scope,
            request.business_owner_id,
            request.use_case,
            supplier.supplier_id,
            supplier.legal_name,
            supplier.profile_version,
            supplier.security_contact,
            supplier.exit_plan,
        )
        if any(not item.strip() for item in required_text):
            raise SupplyChainError("INTAKE_METADATA_INCOMPLETE")
        if owner is None or not owner.active or supplier_owner is None or not supplier_owner.active:
            raise SupplyChainError("INTAKE_OWNER_INACTIVE")
        if request.policy_version != POLICY_VERSION:
            raise SupplyChainError("INTAKE_POLICY_STALE")
        if request.version < 1 or request.requested_at > now:
            raise SupplyChainError("INTAKE_VERSION_OR_TIME_INVALID")
        if (
            supplier.reviewed_at > now
            or now - supplier.reviewed_at > self.policy.maximum_profile_age
            or supplier.review_due_at <= now
        ):
            raise SupplyChainError("SUPPLIER_PROFILE_STALE")
        if supplier.incident_notice_hours <= 0 or not supplier.service_kinds:
            raise SupplyChainError("SUPPLIER_PROFILE_INCOMPLETE")
        if not request.components:
            raise SupplyChainError("COMPONENT_INVENTORY_EMPTY")
        ids = [item.component_id for item in request.components]
        if len(ids) != len(set(ids)):
            raise SupplyChainError("DUPLICATE_COMPONENT")
        roots = [item for item in request.components if item.root]
        if len(roots) != 1:
            raise SupplyChainError("ROOT_COMPONENT_INVALID")
        by_id = {item.component_id: item for item in request.components}
        for component in request.components:
            if (
                not component.component_id.strip()
                or not component.name.strip()
                or not component.version.strip()
                or component.supplier_id != supplier.supplier_id
                or not is_sha256_hex(component.artifact_digest)
                or not component.purl.startswith("pkg:")
                or not component.capabilities
            ):
                raise SupplyChainError("COMPONENT_METADATA_INVALID")
            if any(dep not in by_id or dep == component.component_id for dep in component.dependency_ids):
                raise SupplyChainError("DEPENDENCY_EDGE_INVALID")
        reachable: set[str] = set()
        pending = [roots[0].component_id]
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending.extend(by_id[current].dependency_ids)
        if reachable != set(by_id):
            raise SupplyChainError("DEPENDENCY_GRAPH_INCOMPLETE")

    def validate_evidence(
        self,
        signed: SignedEvidence,
        request: IntakeRequest,
        now: int,
    ) -> EvidenceArtifact:
        self.evidence_authority.verify(signed)
        artifact = signed.artifact
        producer = self.principals.get(artifact.producer_id)
        if producer is None or not producer.active or "evidence-producer" not in producer.roles:
            raise SupplyChainError("EVIDENCE_PRODUCER_UNTRUSTED")
        if artifact.observed_at > now or artifact.expires_at <= now:
            raise SupplyChainError("EVIDENCE_STALE")
        if artifact.outcome is not EvidenceOutcome.PASS:
            raise SupplyChainError("EVIDENCE_NOT_PASSING")
        if (
            not artifact.claim.strip()
            or not is_sha256_hex(artifact.artifact_digest)
            or not artifact.population.strip()
            or not artifact.unit.strip()
            or artifact.denominator <= 0
            or not 0 <= artifact.numerator <= artifact.denominator
        ):
            raise SupplyChainError("EVIDENCE_METRIC_INVALID")
        if artifact.subject_type == "supplier":
            expected_digest = digest(request.supplier.payload())
            if (
                artifact.subject_id != request.supplier.supplier_id
                or artifact.subject_version != request.supplier.profile_version
                or artifact.subject_digest != expected_digest
            ):
                raise SupplyChainError("EVIDENCE_SUBJECT_MISMATCH")
        elif artifact.subject_type == "component":
            components = {item.component_id: item for item in request.components}
            component = components.get(artifact.subject_id)
            if (
                component is None
                or artifact.subject_version != component.version
                or artifact.subject_digest != component.artifact_digest
            ):
                raise SupplyChainError("EVIDENCE_SUBJECT_MISMATCH")
        else:
            raise SupplyChainError("EVIDENCE_SUBJECT_TYPE_INVALID")
        return artifact

    def _valid_exception(
        self,
        active: ActiveException,
        request: IntakeRequest,
        finding: Finding,
        evidence_by_id: Mapping[str, EvidenceArtifact],
        now: int,
    ) -> bool:
        exception = active.request
        components = {item.component_id: item for item in request.components}
        component = components.get(finding.component_id)
        if component is None:
            return False
        if (
            exception.finding_id != finding.finding_id
            or exception.component_id != component.component_id
            or exception.component_version != component.version
            or exception.artifact_digest != component.artifact_digest
            or exception.tenant_scope != request.tenant_scope
            or exception.policy_version != POLICY_VERSION
            or not exception.starts_at <= now < exception.expires_at
            or exception.review_at <= now
            or exception.expires_at - exception.starts_at > self.policy.maximum_exception_duration
            or not exception.rationale.strip()
            or not exception.compensating_controls
            or not exception.evidence_ids
            or not exception.monitoring_plan.strip()
            or not exception.exit_plan.strip()
        ):
            return False
        if finding.severity is FindingSeverity.CRITICAL:
            return False
        if not set(exception.evidence_ids) <= evidence_by_id.keys():
            return False
        return all(
            evidence_by_id[eid].kind is EvidenceKind.COMPENSATING_CONTROL_TEST
            and evidence_by_id[eid].subject_type == "component"
            and evidence_by_id[eid].subject_id == component.component_id
            for eid in exception.evidence_ids
        )

    def evaluate(
        self,
        request: IntakeRequest,
        signed_evidence: Iterable[SignedEvidence],
        findings: Iterable[Finding],
        exceptions: Iterable[ActiveException],
        now: int,
    ) -> Evaluation:
        self.validate_intake(request, now)
        verified: dict[str, EvidenceArtifact] = {}
        blockers: list[str] = []
        for signed in signed_evidence:
            try:
                artifact = self.validate_evidence(signed, request, now)
                if artifact.evidence_id in verified:
                    blockers.append(f"evidence:{artifact.evidence_id}:DUPLICATE")
                else:
                    verified[artifact.evidence_id] = artifact
            except SupplyChainError as exc:
                blockers.append(f"evidence:{signed.artifact.evidence_id}:{exc.code}")
        supplier_kinds = {
            item.kind for item in verified.values() if item.subject_type == "supplier"
        }
        missing_supplier = self.policy.supplier_requirements[request.supplier.tier] - supplier_kinds
        for kind in sorted(missing_supplier, key=lambda item: item.value):
            blockers.append(f"supplier:missing:{kind.value}")
        if request.supplier.tier is SupplierTier.CRITICAL:
            independent = [
                item for item in verified.values()
                if item.kind is EvidenceKind.INDEPENDENT_ASSESSMENT and item.independent
            ]
            if not independent:
                blockers.append("supplier:independent_assessment_required")
        for component in request.components:
            kinds = {
                item.kind
                for item in verified.values()
                if item.subject_type == "component" and item.subject_id == component.component_id
            }
            missing = self.policy.component_requirements[component.kind] - kinds
            for kind in sorted(missing, key=lambda item: item.value):
                blockers.append(f"component:{component.component_id}:missing:{kind.value}")
        findings = tuple(findings)
        finding_ids = [item.finding_id for item in findings]
        if len(finding_ids) != len(set(finding_ids)):
            blockers.append("finding:duplicate")
        components = {item.component_id: item for item in request.components}
        exceptions = tuple(exceptions)
        active_by_finding = {item.request.finding_id: item for item in exceptions}
        if len(active_by_finding) != len(exceptions):
            blockers.append("exception:duplicate_finding_scope")
        used_exceptions: list[str] = []
        for finding in findings:
            if finding.component_id not in components:
                blockers.append(f"finding:{finding.finding_id}:component_unknown")
                continue
            if not finding.source.strip() or not finding.advisory_revision.strip():
                blockers.append(f"finding:{finding.finding_id}:provenance_incomplete")
                continue
            if finding.status in {FindingStatus.REMEDIATED, FindingStatus.NOT_AFFECTED}:
                if (
                    not finding.resolution_evidence_ids
                    or not set(finding.resolution_evidence_ids) <= verified.keys()
                    or any(
                        verified[eid].subject_type != "component"
                        or verified[eid].subject_id != finding.component_id
                        or verified[eid].kind is not EvidenceKind.VULNERABILITY_REPORT
                        for eid in finding.resolution_evidence_ids
                    )
                ):
                    blockers.append(
                        f"finding:{finding.finding_id}:resolution_evidence_missing"
                    )
                    continue
                if (
                    finding.status is FindingStatus.NOT_AFFECTED
                    and finding.exploitability is not Exploitability.NOT_AFFECTED
                ):
                    blockers.append(f"finding:{finding.finding_id}:status_conflict")
                continue
            if finding.exploitability is Exploitability.NOT_AFFECTED:
                blockers.append(f"finding:{finding.finding_id}:status_conflict")
                continue
            if finding.severity is FindingSeverity.CRITICAL:
                blockers.append(f"finding:{finding.finding_id}:critical_open")
                continue
            if finding.severity is FindingSeverity.HIGH or finding.due_at <= now:
                active = active_by_finding.get(finding.finding_id)
                if active and self._valid_exception(
                    active, request, finding, verified, now
                ):
                    used_exceptions.append(active.request.exception_id)
                else:
                    blockers.append(f"finding:{finding.finding_id}:unresolved")
        return Evaluation(
            request.intake_id,
            tuple(sorted(verified)),
            tuple(sorted(used_exceptions)),
            tuple(sorted(set(blockers))),
        )

    def propose_decision(
        self,
        request: IntakeRequest,
        signed_evidence: Iterable[SignedEvidence],
        findings: Iterable[Finding],
        exceptions: Iterable[ActiveException],
        now: int,
        decision_id: str,
    ) -> DecisionProposal:
        signed_evidence = tuple(signed_evidence)
        exceptions = tuple(exceptions)
        evaluation = self.evaluate(request, signed_evidence, findings, exceptions, now)
        if evaluation.blockers:
            recommendation = Decision.DENY
        elif evaluation.exception_ids:
            recommendation = Decision.CONDITIONAL
        else:
            recommendation = Decision.APPROVE
        evidence_expiries = [
            item.artifact.expires_at
            for item in signed_evidence
            if item.artifact.evidence_id in evaluation.verified_evidence_ids
        ]
        exception_expiries = [
            item.request.expires_at
            for item in exceptions
            if item.request.exception_id in evaluation.exception_ids
        ]
        expires_at = min(
            [now + self.policy.maximum_decision_ttl]
            + evidence_expiries
            + exception_expiries
        )
        proposal = DecisionProposal(
            decision_id,
            request.intake_id,
            request.version,
            request.supplier.supplier_id,
            request.supplier.profile_version,
            recommendation,
            evaluation.verified_evidence_ids,
            evaluation.exception_ids,
            evaluation.blockers,
            expires_at,
        )
        proposal_digest = digest(proposal.payload())
        prior = self.issued_proposals.get(decision_id)
        if prior is not None and prior != proposal_digest:
            raise SupplyChainError("DECISION_ID_CONFLICT")
        self.issued_proposals[decision_id] = proposal_digest
        return proposal

    def verify_proposal(self, proposal: DecisionProposal) -> None:
        if self.issued_proposals.get(proposal.decision_id) != digest(proposal.payload()):
            raise SupplyChainError("DECISION_PROPOSAL_UNTRUSTED")


@dataclass(frozen=True)
class AdmissionRecord:
    request: IntakeRequest
    state: AdmissionState
    version: int
    decision_id: str | None = None
    verified_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    intake_id: str
    outcome: str
    reason: str
    operation_id: str
    record_version: int
    timestamp: int
    policy_version: str = POLICY_VERSION


class SupplyChainRegistry:
    def __init__(
        self,
        engine: SupplyChainEngine,
        approvals: ApprovalService,
    ) -> None:
        self.engine = engine
        self.approvals = approvals
        self.records: dict[str, AdmissionRecord] = {}
        self.exceptions: dict[str, ActiveException] = {}
        self.decision_journal: dict[str, tuple[str, AdmissionRecord]] = {}
        self.signal_journal: set[str] = set()
        self.audit: list[AuditEvent] = []
        self._lock = Lock()

    def register(self, request: IntakeRequest, now: int) -> None:
        self.engine.validate_intake(request, now)
        if request.intake_id in self.records:
            raise SupplyChainError("INTAKE_ALREADY_EXISTS")
        self.records[request.intake_id] = AdmissionRecord(
            request, AdmissionState.PENDING, 1
        )

    def activate_exception(
        self,
        request: ExceptionRequest,
        receipt_id: str,
        requester_id: str,
        now: int,
    ) -> ActiveException:
        records = [
            record for record in self.records.values()
            if any(item.component_id == request.component_id for item in record.request.components)
        ]
        if len(records) != 1:
            raise SupplyChainError("EXCEPTION_COMPONENT_AMBIGUOUS")
        record = records[0]
        component = next(
            item for item in record.request.components
            if item.component_id == request.component_id
        )
        if (
            request.component_version != component.version
            or request.artifact_digest != component.artifact_digest
            or request.tenant_scope != record.request.tenant_scope
        ):
            raise SupplyChainError("EXCEPTION_SCOPE_MISMATCH")
        owner = self.engine.principals.get(request.owner_id)
        if (
            request.owner_id != requester_id
            or owner is None
            or not owner.active
            or not request.rationale.strip()
            or not request.compensating_controls
            or not request.evidence_ids
            or not request.monitoring_plan.strip()
            or not request.exit_plan.strip()
            or request.starts_at > now
            or request.review_at <= now
            or request.expires_at <= now
            or request.expires_at - request.starts_at > self.engine.policy.maximum_exception_duration
        ):
            raise SupplyChainError("EXCEPTION_INVALID")
        receipt = self.approvals.consume(
            receipt_id,
            "supply_chain_exception",
            request.payload(),
            requester_id,
            now,
            frozenset({"ciso"}),
        )
        active = ActiveException(request, receipt.approver_id, receipt.receipt_id)
        self.exceptions[request.exception_id] = active
        return active

    def apply_decision(
        self,
        proposal: DecisionProposal,
        receipt_id: str,
        requester_id: str,
        operation_id: str,
        now: int,
    ) -> AdmissionRecord:
        request_digest = digest(proposal.payload())
        with self._lock:
            prior = self.decision_journal.get(operation_id)
            if prior is not None:
                if prior[0] != request_digest:
                    raise SupplyChainError("DECISION_IDEMPOTENCY_CONFLICT")
                return prior[1]
            record = self.records.get(proposal.intake_id)
            if record is None:
                raise SupplyChainError("INTAKE_UNKNOWN")
            self.engine.verify_proposal(proposal)
            if record.request.version != proposal.intake_version:
                raise SupplyChainError("INTAKE_VERSION_STALE")
            if record.request.supplier.profile_version != proposal.supplier_profile_version:
                raise SupplyChainError("SUPPLIER_PROFILE_VERSION_STALE")
            if proposal.expires_at <= now or proposal.policy_version != POLICY_VERSION:
                raise SupplyChainError("DECISION_PROPOSAL_STALE")
            allowed_roles = self.engine.policy.decision_roles[record.request.supplier.tier]
            receipt = self.approvals.consume(
                receipt_id,
                "supply_chain_decision",
                proposal.payload(),
                requester_id,
                now,
                allowed_roles,
            )
            state = {
                Decision.APPROVE: AdmissionState.APPROVED,
                Decision.CONDITIONAL: AdmissionState.CONDITIONAL,
                Decision.DENY: AdmissionState.DENIED,
            }[proposal.recommendation]
            updated = replace(
                record,
                state=state,
                version=record.version + 1,
                decision_id=proposal.decision_id,
                verified_evidence_ids=proposal.verified_evidence_ids,
            )
            self.records[proposal.intake_id] = updated
            self.decision_journal[operation_id] = (request_digest, updated)
            self.audit.append(
                AuditEvent(
                    "supply_chain.decision",
                    proposal.intake_id,
                    proposal.recommendation.value,
                    "blockers:" + ",".join(proposal.blockers)
                    if proposal.blockers else "evidence_verified",
                    operation_id,
                    updated.version,
                    now,
                )
            )
            return updated

    def apply_signal(
        self,
        intake_id: str,
        signal_id: str,
        kind: SignalKind,
        old_version: str,
        new_version: str,
        now: int,
    ) -> AdmissionRecord:
        with self._lock:
            if signal_id in self.signal_journal:
                return self.records[intake_id]
            record = self.records.get(intake_id)
            if record is None:
                raise SupplyChainError("INTAKE_UNKNOWN")
            if not old_version or not new_version or old_version == new_version:
                raise SupplyChainError("SIGNAL_VERSION_INVALID")
            state = (
                AdmissionState.QUARANTINED
                if kind in self.engine.policy.quarantine_signals
                else AdmissionState.REASSESSMENT_REQUIRED
            )
            updated = replace(
                record,
                state=state,
                version=record.version + 1,
                decision_id=None,
                verified_evidence_ids=(),
            )
            self.records[intake_id] = updated
            self.signal_journal.add(signal_id)
            self.audit.append(
                AuditEvent(
                    "supply_chain.signal",
                    intake_id,
                    state.value,
                    kind.value,
                    signal_id,
                    updated.version,
                    now,
                )
            )
            return updated

    def offboard(self, intake_id: str, operation_id: str, now: int) -> AdmissionRecord:
        with self._lock:
            record = self.records.get(intake_id)
            if record is None:
                raise SupplyChainError("INTAKE_UNKNOWN")
            if record.state not in {
                AdmissionState.QUARANTINED,
                AdmissionState.REASSESSMENT_REQUIRED,
                AdmissionState.DENIED,
            }:
                raise SupplyChainError("OFFBOARD_PRECONDITION_FAILED")
            updated = replace(
                record,
                state=AdmissionState.OFFBOARDED,
                version=record.version + 1,
                decision_id=None,
                verified_evidence_ids=(),
            )
            self.records[intake_id] = updated
            self.audit.append(
                AuditEvent(
                    "supply_chain.offboard",
                    intake_id,
                    AdmissionState.OFFBOARDED.value,
                    "authority_removed_and_exit_plan_required",
                    operation_id,
                    updated.version,
                    now,
                )
            )
            return updated


def portfolio_metrics(
    records: Iterable[AdmissionRecord],
    observed_supplier_ids: Iterable[str],
    exceptions: Iterable[ActiveException],
    now: int,
) -> dict[str, Any]:
    records = list(records)
    observed = set(observed_supplier_ids)
    governed = {
        record.request.supplier.supplier_id
        for record in records
        if record.state is not AdmissionState.OFFBOARDED
    }
    components = [
        component
        for record in records
        if record.state is not AdmissionState.OFFBOARDED
        for component in record.request.components
    ]
    evidenced_components = {
        component.component_id
        for record in records
        if record.state in {AdmissionState.APPROVED, AdmissionState.CONDITIONAL}
        and record.verified_evidence_ids
        for component in record.request.components
    }
    critical_records = [
        record for record in records
        if record.request.supplier.tier is SupplierTier.CRITICAL
        and record.state is not AdmissionState.OFFBOARDED
    ]
    current_critical = [
        record for record in critical_records
        if record.request.supplier.review_due_at > now
    ]
    active_exceptions = [
        item for item in exceptions
        if item.request.starts_at <= now < item.request.expires_at
    ]
    return {
        "supplier_population": "observed supplier IDs",
        "observed_supplier_count": len(observed),
        "governed_observed_supplier_count": len(governed & observed),
        "supplier_inventory_coverage": (
            len(governed & observed) / len(observed) if observed else 0.0
        ),
        "component_population": "components in active admission records",
        "component_count": len(components),
        "evidenced_component_count": len(evidenced_components),
        "component_evidence_coverage": (
            len(evidenced_components) / len(components) if components else 0.0
        ),
        "critical_supplier_count": len(critical_records),
        "current_critical_supplier_count": len(current_critical),
        "critical_supplier_profile_freshness": (
            len(current_critical) / len(critical_records) if critical_records else 0.0
        ),
        "active_exception_count": len(active_exceptions),
        "exceptions_expiring_within_7d": sum(
            item.request.expires_at <= now + 7 * 86_400
            for item in active_exceptions
        ),
        "quarantined_record_count": sum(
            record.state is AdmissionState.QUARANTINED for record in records
        ),
    }


def demo_components(now: int = 1_000):
    principals = {
        "owner:maya": Principal("owner:maya", True, frozenset({"business-owner"})),
        "owner:supply": Principal("owner:supply", True, frozenset({"supplier-owner"})),
        "producer:ci": Principal("producer:ci", True, frozenset({"evidence-producer"})),
        "producer:grc": Principal("producer:grc", True, frozenset({"evidence-producer"})),
        "producer:assessor": Principal("producer:assessor", True, frozenset({"evidence-producer"})),
        "approver:manager": Principal("approver:manager", True, frozenset({"supply-chain-manager"})),
        "approver:ciso": Principal("approver:ciso", True, frozenset({"ciso"})),
        "committee:1": Principal("committee:1", True, frozenset({"supply-chain-committee"})),
    }
    supplier = SupplierProfile(
        "supplier:helpdesk",
        "Helpdesk Connector Ltd.",
        "profile-v4",
        "owner:supply",
        SupplierTier.CRITICAL,
        (ServiceKind.MCP_SERVER, ServiceKind.SDK),
        "security@example.invalid",
        24,
        ("CA", "US"),
        ("supplier:cloud",),
        "revoke connector identity, export configuration, restore internal adapter",
        now,
        now + 30 * 86_400,
    )
    sdk = Component(
        "component:sdk",
        "helpdesk-sdk",
        ServiceKind.SDK,
        supplier.supplier_id,
        "4.2.1",
        "b" * 64,
        "pkg:pypi/helpdesk-sdk@4.2.1",
        False,
        (),
        ("ticket:read",),
        ("confidential",),
    )
    server = Component(
        "component:server",
        "helpdesk-mcp",
        ServiceKind.MCP_SERVER,
        supplier.supplier_id,
        "7.4.0",
        "a" * 64,
        "pkg:oci/helpdesk-mcp@7.4.0",
        True,
        (sdk.component_id,),
        ("ticket:read", "ticket:update"),
        ("confidential",),
    )
    request = IntakeRequest(
        "INTAKE-001",
        "acme",
        "owner:maya",
        "read and update support tickets through the approved MCP gateway",
        supplier,
        (server, sdk),
        now,
        POLICY_VERSION,
        1,
    )
    authority = EvidenceAuthority()
    engine = SupplyChainEngine(authority, principals)
    approvals = ApprovalService(principals)
    registry = SupplyChainRegistry(engine, approvals)
    registry.register(request, now)
    return principals, authority, engine, approvals, registry, request


def evidence_fixture(
    authority: EvidenceAuthority,
    request: IntakeRequest,
    now: int = 1_000,
) -> tuple[SignedEvidence, ...]:
    profile_digest = digest(request.supplier.payload())
    supplier_kinds = (
        EvidenceKind.SECURITY_PROGRAM,
        EvidenceKind.CONTRACT,
        EvidenceKind.INCIDENT_RESPONSE,
        EvidenceKind.DUE_DILIGENCE,
        EvidenceKind.BUSINESS_CONTINUITY,
        EvidenceKind.DATA_FLOW_REVIEW,
        EvidenceKind.INDEPENDENT_ASSESSMENT,
    )
    artifacts: list[EvidenceArtifact] = []
    for index, kind in enumerate(supplier_kinds):
        artifacts.append(EvidenceArtifact(
            f"EV-SUP-{kind.value.upper()}",
            kind,
            "supplier",
            request.supplier.supplier_id,
            request.supplier.profile_version,
            profile_digest,
            "producer:assessor" if kind is EvidenceKind.INDEPENDENT_ASSESSMENT else "producer:grc",
            kind is EvidenceKind.INDEPENDENT_ASSESSMENT,
            EvidenceOutcome.PASS,
            f"{kind.value} evidence satisfies the scoped supplier requirement",
            now,
            now + 30 * 86_400,
            f"{index + 1:064x}",
            "1 scoped supplier profile",
            1,
            1,
            "profiles reviewed",
        ))
    component_kinds = {
        ServiceKind.MCP_SERVER: (
            EvidenceKind.SIGNATURE,
            EvidenceKind.PROVENANCE,
            EvidenceKind.SBOM,
            EvidenceKind.VULNERABILITY_REPORT,
        ),
        ServiceKind.SDK: (
            EvidenceKind.SIGNATURE,
            EvidenceKind.PROVENANCE,
            EvidenceKind.SBOM,
            EvidenceKind.VULNERABILITY_REPORT,
            EvidenceKind.LICENSE_REVIEW,
        ),
    }
    for component_index, component in enumerate(request.components):
        for kind_index, kind in enumerate(component_kinds[component.kind]):
            artifacts.append(EvidenceArtifact(
                f"EV-{component.component_id.split(':')[1].upper()}-{kind.value.upper()}",
                kind,
                "component",
                component.component_id,
                component.version,
                component.artifact_digest,
                "producer:ci",
                False,
                EvidenceOutcome.PASS,
                f"{kind.value} is bound to the exact component artifact",
                now,
                now + 7 * 86_400,
                f"{100 + component_index * 10 + kind_index:064x}",
                "1 immutable component artifact",
                1,
                1,
                "artifacts verified",
            ))
    return tuple(authority.sign(item) for item in artifacts)


def main() -> None:
    now = 1_000
    _, authority, engine, approvals, registry, request = demo_components(now)
    evidence = evidence_fixture(authority, request, now)
    proposal = engine.propose_decision(
        request, evidence, (), (), now + 1, "DEC-SCRM-001"
    )
    receipt = approvals.issue(
        "supply_chain_decision",
        proposal.payload(),
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        now + 1,
    )
    admitted = registry.apply_decision(
        proposal,
        receipt.receipt_id,
        request.business_owner_id,
        "operation-scrm-001",
        now + 2,
    )
    metrics = portfolio_metrics(
        registry.records.values(),
        ("supplier:helpdesk", "supplier:shadow"),
        registry.exceptions.values(),
        now + 2,
    )
    assert admitted.state is AdmissionState.APPROVED
    assert proposal.blockers == ()
    assert metrics["supplier_inventory_coverage"] == 0.5
    print(json.dumps({
        "intake_id": request.intake_id,
        "supplier_tier": request.supplier.tier.value,
        "component_count": len(request.components),
        "decision": proposal.recommendation.value,
        "verified_evidence_count": len(proposal.verified_evidence_ids),
        "inventory_coverage": metrics["supplier_inventory_coverage"],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
