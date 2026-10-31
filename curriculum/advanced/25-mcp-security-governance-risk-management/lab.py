"""Course 25 lab: evidence-backed MCP governance and risk decisions.

The lab is deterministic, offline, and credential-free. Ed25519 signatures
model authenticated evidence and decision receipts. In-memory stores model a
risk register, exception workflow, and decision journal; they are not a GRC
platform, legal determination, or production authorization service.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum, StrEnum
from hashlib import sha256
import json
from threading import Lock
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


POLICY_VERSION = "mcp-risk-policy-2026-10-30"


class GovernanceError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class Likelihood(IntEnum):
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class Impact(IntEnum):
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    SEVERE = 5


class RiskBand(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class Treatment(StrEnum):
    AVOID = "avoid"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    ACCEPT = "accept"
    MONITOR = "monitor"


class RiskState(StrEnum):
    ASSESSED = "assessed"
    AUTHORIZED = "authorized"
    CONDITIONAL = "conditional"
    REJECTED = "rejected"
    REASSESSMENT_REQUIRED = "reassessment_required"
    CLOSED = "closed"


class EvidenceKind(StrEnum):
    TEST = "test"
    TELEMETRY = "telemetry"
    INCIDENT_DRILL = "incident_drill"
    ARCHITECTURE_REVIEW = "architecture_review"
    AUDIT = "audit"


class EvidenceOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class Decision(StrEnum):
    APPROVE = "approve"
    CONDITIONAL = "conditional"
    REJECT = "reject"


class ChangeKind(StrEnum):
    CAPABILITY = "capability"
    MODEL = "model"
    TOOL_CONTRACT = "tool_contract"
    IDENTITY = "identity"
    DATA_CLASSIFICATION = "data_classification"
    VENDOR = "vendor"
    DEPLOYMENT = "deployment"
    CONTROL = "control"
    INCIDENT = "incident"
    LEGAL = "legal"
    TOPOLOGY = "topology"
    POLICY = "policy"


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Mapping[str, Any]) -> str:
    return sha256(canonical_json(value)).hexdigest()


RISK_MATRIX: dict[tuple[Likelihood, Impact], RiskBand] = {}
for likelihood in Likelihood:
    for impact in Impact:
        score = int(likelihood) * int(impact)
        RISK_MATRIX[(likelihood, impact)] = (
            RiskBand.LOW if score <= 4 else
            RiskBand.MODERATE if score <= 9 else
            RiskBand.HIGH if score <= 16 else
            RiskBand.CRITICAL
        )


def risk_band(likelihood: Likelihood, impact: Impact) -> RiskBand:
    """Apply a declared ordinal matrix; the product is not expected loss."""
    return RISK_MATRIX[(likelihood, impact)]


@dataclass(frozen=True)
class Principal:
    principal_id: str
    active: bool
    roles: frozenset[str]


@dataclass(frozen=True)
class Control:
    control_id: str
    objective: str
    owner_id: str
    required_evidence: frozenset[EvidenceKind]
    framework_refs: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    control_id: str
    system_id: str
    tenant_scope: str
    subject_version: str
    kind: EvidenceKind
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
            "control_id": self.control_id,
            "system_id": self.system_id,
            "tenant_scope": self.tenant_scope,
            "subject_version": self.subject_version,
            "kind": self.kind.value,
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
    """Training analogue for authenticated test and telemetry producers."""

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
            raise GovernanceError("EVIDENCE_SIGNATURE_INVALID") from exc


@dataclass(frozen=True)
class ResidualAssessment:
    likelihood: Likelihood
    impact: Impact
    rationale: str
    assessor_id: str
    evidence_ids: tuple[str, ...]
    assessed_at: int


@dataclass(frozen=True)
class TreatmentAction:
    action_id: str
    description: str
    owner_id: str
    due_at: int
    completed: bool
    completion_evidence_id: str | None = None


@dataclass(frozen=True)
class RiskRecord:
    risk_id: str
    system_id: str
    tenant_scope: str
    owner_id: str
    business_objective: str
    scenario: str
    threat_event: str
    vulnerability: str
    consequence: str
    affected_assets: tuple[str, ...]
    data_classification: str
    inherent_likelihood: Likelihood
    inherent_impact: Impact
    control_ids: tuple[str, ...]
    residual: ResidualAssessment
    treatment: Treatment
    actions: tuple[TreatmentAction, ...]
    system_version: str
    policy_version: str
    assessed_at: int
    review_due_at: int
    state: RiskState
    version: int
    decision_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "system_id": self.system_id,
            "tenant_scope": self.tenant_scope,
            "owner_id": self.owner_id,
            "business_objective": self.business_objective,
            "scenario": self.scenario,
            "threat_event": self.threat_event,
            "vulnerability": self.vulnerability,
            "consequence": self.consequence,
            "affected_assets": list(self.affected_assets),
            "data_classification": self.data_classification,
            "inherent_likelihood": int(self.inherent_likelihood),
            "inherent_impact": int(self.inherent_impact),
            "control_ids": list(self.control_ids),
            "residual": {
                "likelihood": int(self.residual.likelihood),
                "impact": int(self.residual.impact),
                "rationale": self.residual.rationale,
                "assessor_id": self.residual.assessor_id,
                "evidence_ids": list(self.residual.evidence_ids),
                "assessed_at": self.residual.assessed_at,
            },
            "treatment": self.treatment.value,
            "actions": [
                {
                    "action_id": action.action_id,
                    "description": action.description,
                    "owner_id": action.owner_id,
                    "due_at": action.due_at,
                    "completed": action.completed,
                    "completion_evidence_id": action.completion_evidence_id,
                }
                for action in self.actions
            ],
            "system_version": self.system_version,
            "policy_version": self.policy_version,
            "assessed_at": self.assessed_at,
            "review_due_at": self.review_due_at,
            "state": self.state.value,
            "version": self.version,
        }


@dataclass(frozen=True)
class ExceptionRequest:
    exception_id: str
    risk_id: str
    system_id: str
    tenant_scope: str
    control_id: str
    owner_id: str
    justification: str
    compensating_control_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    monitoring_plan: str
    exit_plan: str
    action_owner_id: str
    starts_at: int
    expires_at: int
    review_at: int
    system_version: str
    policy_version: str = POLICY_VERSION

    def payload(self) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "risk_id": self.risk_id,
            "system_id": self.system_id,
            "tenant_scope": self.tenant_scope,
            "control_id": self.control_id,
            "owner_id": self.owner_id,
            "justification": self.justification,
            "compensating_control_ids": list(self.compensating_control_ids),
            "evidence_ids": list(self.evidence_ids),
            "monitoring_plan": self.monitoring_plan,
            "exit_plan": self.exit_plan,
            "action_owner_id": self.action_owner_id,
            "starts_at": self.starts_at,
            "expires_at": self.expires_at,
            "review_at": self.review_at,
            "system_version": self.system_version,
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
    risk_id: str
    risk_version: int
    system_version: str
    residual_band: RiskBand
    recommendation: Decision
    verified_evidence_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    blockers: tuple[str, ...]
    expires_at: int
    policy_version: str = POLICY_VERSION

    def payload(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "risk_id": self.risk_id,
            "risk_version": self.risk_version,
            "system_version": self.system_version,
            "residual_band": self.residual_band.value,
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
    """Role-aware, signed, exact, expiring, atomically single-use receipts."""

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
            raise GovernanceError("SEPARATION_OF_DUTIES")
        if approver is None or not approver.active or approver_role not in approver.roles:
            raise GovernanceError("APPROVER_NOT_AUTHORIZED")
        if ttl_seconds <= 0 or ttl_seconds > 900:
            raise GovernanceError("APPROVAL_TTL_INVALID")
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
                raise GovernanceError("APPROVAL_UNKNOWN")
            try:
                self.public_key.verify(receipt.signature, canonical_json(receipt.unsigned()))
            except Exception as exc:
                raise GovernanceError("APPROVAL_SIGNATURE_INVALID") from exc
            if receipt_id in self.consumed:
                raise GovernanceError("APPROVAL_REPLAY")
            if receipt.expires_at <= now:
                raise GovernanceError("APPROVAL_EXPIRED")
            if receipt.policy_version != POLICY_VERSION:
                raise GovernanceError("APPROVAL_POLICY_STALE")
            if receipt.kind != kind or receipt.requester_id != requester_id:
                raise GovernanceError("APPROVAL_BINDING_MISMATCH")
            if receipt.payload_digest != digest(payload):
                raise GovernanceError("APPROVAL_BINDING_MISMATCH")
            if receipt.approver_role not in allowed_roles:
                raise GovernanceError("APPROVAL_ROLE_INSUFFICIENT")
            self.consumed.add(receipt_id)
            return receipt


@dataclass(frozen=True)
class RiskPolicy:
    maximum_assessment_age: int
    maximum_exception_duration: int
    maximum_decision_ttl: int
    required_independent_evidence_for: frozenset[RiskBand]
    decision_roles: Mapping[RiskBand, frozenset[str]]
    prohibited_bands: frozenset[RiskBand]
    material_changes: frozenset[ChangeKind]


DEFAULT_POLICY = RiskPolicy(
    maximum_assessment_age=90 * 86_400,
    maximum_exception_duration=14 * 86_400,
    maximum_decision_ttl=900,
    required_independent_evidence_for=frozenset({RiskBand.HIGH, RiskBand.CRITICAL}),
    decision_roles={
        RiskBand.LOW: frozenset({"system-owner", "risk-manager", "ciso"}),
        RiskBand.MODERATE: frozenset({"risk-manager", "ciso"}),
        RiskBand.HIGH: frozenset({"ciso"}),
        RiskBand.CRITICAL: frozenset({"risk-committee"}),
    },
    prohibited_bands=frozenset({RiskBand.CRITICAL}),
    material_changes=frozenset(ChangeKind),
)


@dataclass(frozen=True)
class Evaluation:
    risk_id: str
    residual_band: RiskBand
    verified_evidence_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    blockers: tuple[str, ...]


class GovernanceEngine:
    def __init__(
        self,
        controls: Iterable[Control],
        evidence_authority: EvidenceAuthority,
        principals: Mapping[str, Principal],
        policy: RiskPolicy = DEFAULT_POLICY,
    ) -> None:
        self.controls = {control.control_id: control for control in controls}
        self.evidence_authority = evidence_authority
        self.principals = principals
        self.policy = policy
        self.issued_proposals: dict[str, str] = {}

    def validate_record(self, record: RiskRecord, now: int) -> None:
        required_text = (
            record.risk_id, record.system_id, record.tenant_scope, record.owner_id,
            record.business_objective, record.scenario, record.threat_event,
            record.vulnerability, record.consequence, record.data_classification,
            record.system_version, record.residual.rationale,
        )
        if any(not item.strip() for item in required_text):
            raise GovernanceError("RISK_METADATA_INCOMPLETE")
        owner = self.principals.get(record.owner_id)
        assessor = self.principals.get(record.residual.assessor_id)
        if owner is None or not owner.active:
            raise GovernanceError("RISK_OWNER_INACTIVE")
        if record.owner_id == record.residual.assessor_id:
            raise GovernanceError("ASSESSMENT_NOT_INDEPENDENT")
        if assessor is None or not assessor.active or "risk-assessor" not in assessor.roles:
            raise GovernanceError("ASSESSOR_NOT_AUTHORIZED")
        if not record.affected_assets or not record.control_ids:
            raise GovernanceError("RISK_SCOPE_OR_CONTROLS_EMPTY")
        if len(set(record.control_ids)) != len(record.control_ids):
            raise GovernanceError("DUPLICATE_CONTROL")
        if any(control_id not in self.controls for control_id in record.control_ids):
            raise GovernanceError("CONTROL_UNKNOWN")
        if record.policy_version != POLICY_VERSION:
            raise GovernanceError("RISK_POLICY_STALE")
        if record.state is not RiskState.ASSESSED or record.version < 1:
            raise GovernanceError("RISK_INITIAL_STATE_INVALID")
        if record.assessed_at > now or now - record.assessed_at > self.policy.maximum_assessment_age:
            raise GovernanceError("ASSESSMENT_STALE")
        if record.review_due_at <= now:
            raise GovernanceError("RISK_REVIEW_OVERDUE")
        if not record.residual.evidence_ids:
            raise GovernanceError("RESIDUAL_EVIDENCE_EMPTY")
        if not record.residual.rationale.strip():
            raise GovernanceError("RESIDUAL_RATIONALE_EMPTY")
        for action in record.actions:
            action_owner = self.principals.get(action.owner_id)
            if (
                not action.action_id.strip()
                or not action.description.strip()
                or action_owner is None
                or not action_owner.active
                or action.due_at <= record.assessed_at
            ):
                raise GovernanceError("TREATMENT_ACTION_INVALID")
            if action.completed and not action.completion_evidence_id:
                raise GovernanceError("TREATMENT_COMPLETION_UNPROVEN")
        inherent = risk_band(record.inherent_likelihood, record.inherent_impact)
        residual = risk_band(record.residual.likelihood, record.residual.impact)
        if list(RiskBand).index(residual) < list(RiskBand).index(inherent):
            if len(record.residual.evidence_ids) < 2:
                raise GovernanceError("RESIDUAL_REDUCTION_UNSUPPORTED")

    def validate_evidence(
        self,
        signed: SignedEvidence,
        record: RiskRecord,
        now: int,
    ) -> EvidenceArtifact:
        self.evidence_authority.verify(signed)
        artifact = signed.artifact
        if artifact.control_id not in record.control_ids:
            raise GovernanceError("EVIDENCE_CONTROL_OUT_OF_SCOPE")
        if (
            artifact.system_id != record.system_id
            or artifact.tenant_scope != record.tenant_scope
            or artifact.subject_version != record.system_version
        ):
            raise GovernanceError("EVIDENCE_SUBJECT_MISMATCH")
        producer = self.principals.get(artifact.producer_id)
        if producer is None or not producer.active or "evidence-producer" not in producer.roles:
            raise GovernanceError("EVIDENCE_PRODUCER_UNTRUSTED")
        if artifact.observed_at > now or artifact.expires_at <= now:
            raise GovernanceError("EVIDENCE_STALE")
        if artifact.outcome is not EvidenceOutcome.PASS:
            raise GovernanceError("EVIDENCE_NOT_PASSING")
        if len(artifact.artifact_digest) != 64:
            raise GovernanceError("EVIDENCE_DIGEST_INVALID")
        if not artifact.population or not artifact.unit:
            raise GovernanceError("EVIDENCE_METRIC_UNDEFINED")
        if artifact.denominator <= 0 or not 0 <= artifact.numerator <= artifact.denominator:
            raise GovernanceError("EVIDENCE_METRIC_INVALID")
        return artifact

    def _valid_exception(
        self,
        active: ActiveException,
        record: RiskRecord,
        control_id: str,
        evidence_by_id: Mapping[str, EvidenceArtifact],
        now: int,
    ) -> bool:
        request = active.request
        if (
            request.risk_id != record.risk_id
            or request.system_id != record.system_id
            or request.tenant_scope != record.tenant_scope
            or request.control_id != control_id
            or request.system_version != record.system_version
            or request.policy_version != POLICY_VERSION
            or not request.starts_at <= now < request.expires_at
            or request.review_at <= now
            or request.expires_at - request.starts_at > self.policy.maximum_exception_duration
            or not request.justification.strip()
            or not request.compensating_control_ids
            or not request.evidence_ids
            or not request.monitoring_plan.strip()
            or not request.exit_plan.strip()
            or request.action_owner_id not in self.principals
            or not self.principals[request.action_owner_id].active
        ):
            return False
        if not set(request.evidence_ids) <= evidence_by_id.keys():
            return False
        compensating_controls = set(request.compensating_control_ids)
        if (
            request.control_id in compensating_controls
            or not compensating_controls <= self.controls.keys()
        ):
            return False
        return all(
            evidence_by_id[eid].outcome is EvidenceOutcome.PASS
            and evidence_by_id[eid].control_id in compensating_controls
            for eid in request.evidence_ids
        )

    def evaluate(
        self,
        record: RiskRecord,
        signed_evidence: Iterable[SignedEvidence],
        exceptions: Iterable[ActiveException],
        now: int,
    ) -> Evaluation:
        self.validate_record(record, now)
        verified: dict[str, EvidenceArtifact] = {}
        blockers: list[str] = []
        for signed in signed_evidence:
            try:
                artifact = self.validate_evidence(signed, record, now)
                verified[artifact.evidence_id] = artifact
            except GovernanceError as exc:
                blockers.append(f"evidence:{signed.artifact.evidence_id}:{exc.code}")
        if not set(record.residual.evidence_ids) <= verified.keys():
            blockers.append("residual_assessment_evidence_missing")
        band = risk_band(record.residual.likelihood, record.residual.impact)
        if band in self.policy.required_independent_evidence_for:
            if not any(item.independent for item in verified.values()):
                blockers.append("independent_evidence_required")
        active_exceptions = {item.request.control_id: item for item in exceptions}
        used_exceptions: list[str] = []
        for control_id in record.control_ids:
            control = self.controls[control_id]
            kinds = {item.kind for item in verified.values() if item.control_id == control_id}
            missing = control.required_evidence - kinds
            if missing:
                exception = active_exceptions.get(control_id)
                if exception and self._valid_exception(
                    exception, record, control_id, verified, now
                ):
                    used_exceptions.append(exception.request.exception_id)
                else:
                    blockers.append(
                        f"control:{control_id}:missing:{','.join(sorted(kind.value for kind in missing))}"
                    )
        if record.review_due_at <= now:
            blockers.append("risk_review_overdue")
        for action in record.actions:
            if not action.completed and action.due_at <= now:
                blockers.append(f"treatment_action_overdue:{action.action_id}")
        return Evaluation(
            record.risk_id,
            band,
            tuple(sorted(verified)),
            tuple(sorted(used_exceptions)),
            tuple(sorted(set(blockers))),
        )

    def propose_decision(
        self,
        record: RiskRecord,
        signed_evidence: Iterable[SignedEvidence],
        exceptions: Iterable[ActiveException],
        now: int,
        decision_id: str,
    ) -> DecisionProposal:
        signed_evidence = tuple(signed_evidence)
        exceptions = tuple(exceptions)
        evaluation = self.evaluate(record, signed_evidence, exceptions, now)
        if evaluation.residual_band in self.policy.prohibited_bands or evaluation.blockers:
            recommendation = Decision.REJECT
        elif evaluation.exception_ids or any(not action.completed for action in record.actions):
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
            record.risk_id,
            record.version,
            record.system_version,
            evaluation.residual_band,
            recommendation,
            evaluation.verified_evidence_ids,
            evaluation.exception_ids,
            evaluation.blockers,
            expires_at,
        )
        proposal_digest = digest(proposal.payload())
        prior = self.issued_proposals.get(decision_id)
        if prior is not None and prior != proposal_digest:
            raise GovernanceError("DECISION_ID_CONFLICT")
        self.issued_proposals[decision_id] = proposal_digest
        return proposal

    def verify_proposal(self, proposal: DecisionProposal) -> None:
        if self.issued_proposals.get(proposal.decision_id) != digest(proposal.payload()):
            raise GovernanceError("DECISION_PROPOSAL_UNTRUSTED")


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    risk_id: str
    decision: str
    reason: str
    timestamp: int
    operation_id: str
    record_version: int
    policy_version: str = POLICY_VERSION


class RiskRegistry:
    """Versioned register with exact decisions and idempotent unknown retries."""

    def __init__(
        self,
        engine: GovernanceEngine,
        approvals: ApprovalService,
    ) -> None:
        self.engine = engine
        self.approvals = approvals
        self.records: dict[str, RiskRecord] = {}
        self.exceptions: dict[str, ActiveException] = {}
        self.decision_journal: dict[str, tuple[str, RiskRecord]] = {}
        self.audit: list[AuditEvent] = []
        self._lock = Lock()

    def register(self, record: RiskRecord, now: int) -> None:
        self.engine.validate_record(record, now)
        if record.risk_id in self.records:
            raise GovernanceError("RISK_ALREADY_EXISTS")
        self.records[record.risk_id] = record

    def activate_exception(
        self,
        request: ExceptionRequest,
        receipt_id: str,
        requester_id: str,
        now: int,
    ) -> ActiveException:
        record = self.records.get(request.risk_id)
        if record is None:
            raise GovernanceError("RISK_UNKNOWN")
        if (
            request.system_id != record.system_id
            or request.tenant_scope != record.tenant_scope
            or request.system_version != record.system_version
            or request.control_id not in record.control_ids
        ):
            raise GovernanceError("EXCEPTION_SCOPE_MISMATCH")
        if request.owner_id != requester_id:
            raise GovernanceError("EXCEPTION_OWNER_MISMATCH")
        if (
            request.starts_at > now
            or request.expires_at <= now
            or request.review_at <= now
            or request.expires_at - request.starts_at > self.engine.policy.maximum_exception_duration
            or not request.justification.strip()
            or not request.compensating_control_ids
            or not request.evidence_ids
            or not request.monitoring_plan.strip()
            or not request.exit_plan.strip()
            or request.action_owner_id not in self.engine.principals
            or not self.engine.principals[request.action_owner_id].active
        ):
            raise GovernanceError("EXCEPTION_INVALID")
        compensating_controls = set(request.compensating_control_ids)
        if (
            request.control_id in compensating_controls
            or not compensating_controls <= self.engine.controls.keys()
        ):
            raise GovernanceError("EXCEPTION_COMPENSATION_INVALID")
        receipt = self.approvals.consume(
            receipt_id,
            "control_exception",
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
    ) -> RiskRecord:
        request_digest = digest(proposal.payload())
        with self._lock:
            prior = self.decision_journal.get(operation_id)
            if prior is not None:
                if prior[0] != request_digest:
                    raise GovernanceError("DECISION_IDEMPOTENCY_CONFLICT")
                return prior[1]
            record = self.records.get(proposal.risk_id)
            if record is None:
                raise GovernanceError("RISK_UNKNOWN")
            self.engine.verify_proposal(proposal)
            if record.version != proposal.risk_version:
                raise GovernanceError("RISK_VERSION_STALE")
            if record.system_version != proposal.system_version:
                raise GovernanceError("DECISION_SYSTEM_VERSION_STALE")
            if proposal.expires_at <= now or proposal.policy_version != POLICY_VERSION:
                raise GovernanceError("DECISION_PROPOSAL_STALE")
            allowed_roles = self.engine.policy.decision_roles[proposal.residual_band]
            receipt = self.approvals.consume(
                receipt_id,
                "risk_decision",
                proposal.payload(),
                requester_id,
                now,
                allowed_roles,
            )
            state = {
                Decision.APPROVE: RiskState.AUTHORIZED,
                Decision.CONDITIONAL: RiskState.CONDITIONAL,
                Decision.REJECT: RiskState.REJECTED,
            }[proposal.recommendation]
            updated = replace(
                record,
                state=state,
                version=record.version + 1,
                decision_id=proposal.decision_id,
            )
            self.records[record.risk_id] = updated
            self.decision_journal[operation_id] = (request_digest, updated)
            self.audit.append(
                AuditEvent(
                    "risk.decision",
                    record.risk_id,
                    proposal.recommendation.value,
                    "blockers:" + ",".join(proposal.blockers) if proposal.blockers else "evidence_verified",
                    now,
                    operation_id,
                    updated.version,
                )
            )
            return updated

    def material_change(
        self,
        system_id: str,
        kind: ChangeKind,
        old_version: str,
        new_version: str,
        now: int,
        change_id: str,
    ) -> tuple[str, ...]:
        if kind not in self.engine.policy.material_changes:
            return ()
        if not old_version or not new_version or old_version == new_version:
            raise GovernanceError("CHANGE_VERSION_INVALID")
        impacted: list[str] = []
        for risk_id, record in list(self.records.items()):
            if record.system_id != system_id or record.state is RiskState.CLOSED:
                continue
            changed = replace(
                record,
                state=RiskState.REASSESSMENT_REQUIRED,
                version=record.version + 1,
                decision_id=None,
            )
            self.records[risk_id] = changed
            impacted.append(risk_id)
            self.audit.append(
                AuditEvent(
                    "risk.reassessment_required",
                    risk_id,
                    "invalidate_prior_decision",
                    kind.value,
                    now,
                    change_id,
                    changed.version,
                )
            )
        return tuple(sorted(impacted))


def portfolio_metrics(
    records: Iterable[RiskRecord],
    exceptions: Iterable[ActiveException],
    now: int,
) -> dict[str, Any]:
    records = list(records)
    exceptions = list(exceptions)
    open_records = [record for record in records if record.state is not RiskState.CLOSED]
    above_tolerance = [
        record for record in open_records
        if risk_band(record.residual.likelihood, record.residual.impact) is RiskBand.CRITICAL
    ]
    overdue_reviews = [record for record in open_records if record.review_due_at <= now]
    expiring_exceptions = [
        item for item in exceptions if now < item.request.expires_at <= now + 7 * 86_400
    ]
    bands = {band.value: 0 for band in RiskBand}
    for record in open_records:
        bands[risk_band(record.residual.likelihood, record.residual.impact).value] += 1
    return {
        "population": "open risk records",
        "open_risk_count": len(open_records),
        "band_counts": bands,
        "above_tolerance_count": len(above_tolerance),
        "above_tolerance_rate": len(above_tolerance) / len(open_records) if open_records else 0.0,
        "overdue_review_count": len(overdue_reviews),
        "overdue_review_rate": len(overdue_reviews) / len(open_records) if open_records else 0.0,
        "active_exception_count": sum(
            item.request.starts_at <= now < item.request.expires_at for item in exceptions
        ),
        "exceptions_expiring_within_7d": len(expiring_exceptions),
    }


def demo_components(now: int = 1_000):
    principals = {
        "owner:maya": Principal("owner:maya", True, frozenset({"system-owner"})),
        "assessor:lee": Principal("assessor:lee", True, frozenset({"risk-assessor"})),
        "producer:ci": Principal("producer:ci", True, frozenset({"evidence-producer"})),
        "producer:soc": Principal("producer:soc", True, frozenset({"evidence-producer"})),
        "approver:ciso": Principal("approver:ciso", True, frozenset({"ciso"})),
        "approver:risk": Principal("approver:risk", True, frozenset({"risk-manager"})),
        "approver:owner": Principal("approver:owner", True, frozenset({"system-owner"})),
        "committee:1": Principal("committee:1", True, frozenset({"risk-committee"})),
    }
    controls = (
        Control(
            "CTRL-AUTHZ",
            "independently authorize tenant-bound MCP tool effects",
            "owner:maya",
            frozenset({EvidenceKind.TEST, EvidenceKind.TELEMETRY}),
            ("CSF-PR.AA", "AI-RMF-MANAGE-2"),
        ),
        Control(
            "CTRL-RECOVERY",
            "revoke authority and restore safe service",
            "owner:maya",
            frozenset({EvidenceKind.INCIDENT_DRILL}),
            ("CSF-RS.MI", "CSF-RC.RP"),
        ),
    )
    evidence_authority = EvidenceAuthority()
    engine = GovernanceEngine(controls, evidence_authority, principals)
    approvals = ApprovalService(principals)
    registry = RiskRegistry(engine, approvals)
    residual = ResidualAssessment(
        Likelihood.UNLIKELY,
        Impact.MAJOR,
        "tenant authorization tests and runtime evidence reduce likelihood; impact remains major",
        "assessor:lee",
        ("EV-AUTHZ-TEST", "EV-AUTHZ-TELEMETRY", "EV-RECOVERY-DRILL"),
        now,
    )
    record = RiskRecord(
        "R-MCP-001",
        "support-mcp",
        "acme",
        "owner:maya",
        "serve support tickets without cross-tenant disclosure",
        "a compromised or confused MCP server reads another tenant's ticket",
        "attacker steers a valid tool call across a tenant boundary",
        "caller and resource tenant are not independently enforced",
        "confidential customer data is disclosed and incident response is required",
        ("mcp://support", "api://tickets", "data://support-tickets"),
        "confidential",
        Likelihood.LIKELY,
        Impact.MAJOR,
        ("CTRL-AUTHZ", "CTRL-RECOVERY"),
        residual,
        Treatment.MITIGATE,
        (),
        "support-v7@sha256:abc",
        POLICY_VERSION,
        now,
        now + 30 * 86_400,
        RiskState.ASSESSED,
        1,
    )
    registry.register(record, now)
    return principals, controls, evidence_authority, engine, approvals, registry, record


def evidence_fixture(
    authority: EvidenceAuthority,
    record: RiskRecord,
    now: int = 1_000,
) -> tuple[SignedEvidence, ...]:
    fixtures = (
        EvidenceArtifact(
            "EV-AUTHZ-TEST", "CTRL-AUTHZ", record.system_id, record.tenant_scope,
            record.system_version, EvidenceKind.TEST, "producer:ci", True,
            EvidenceOutcome.PASS, "labelled cross-tenant suite blocked all forbidden reads",
            now, now + 7 * 86_400, "a" * 64, "40 labelled adversarial cases", 40, 40, "blocked cases",
        ),
        EvidenceArtifact(
            "EV-AUTHZ-TELEMETRY", "CTRL-AUTHZ", record.system_id, record.tenant_scope,
            record.system_version, EvidenceKind.TELEMETRY, "producer:soc", True,
            EvidenceOutcome.PASS, "no forbidden protected-resource effect in canary window",
            now, now + 86_400, "b" * 64, "120 labelled canary tool calls", 120, 120, "compliant calls",
        ),
        EvidenceArtifact(
            "EV-RECOVERY-DRILL", "CTRL-RECOVERY", record.system_id, record.tenant_scope,
            record.system_version, EvidenceKind.INCIDENT_DRILL, "producer:soc", True,
            EvidenceOutcome.PASS, "revocation converged and safe service was independently verified",
            now, now + 30 * 86_400, "c" * 64, "6 required enforcement points", 6, 6, "converged points",
        ),
    )
    return tuple(authority.sign(item) for item in fixtures)


def main() -> None:
    now = 1_000
    _, _, authority, engine, approvals, registry, record = demo_components(now)
    evidence = evidence_fixture(authority, record, now)
    proposal = engine.propose_decision(
        record, evidence, (), now + 1, "DEC-MCP-001"
    )
    receipt = approvals.issue(
        "risk_decision",
        proposal.payload(),
        record.owner_id,
        "approver:risk",
        "risk-manager",
        now + 1,
    )
    decided = registry.apply_decision(
        proposal,
        receipt.receipt_id,
        record.owner_id,
        "operation-risk-decision-001",
        now + 2,
    )
    metrics = portfolio_metrics(registry.records.values(), registry.exceptions.values(), now + 2)
    assert decided.state is RiskState.AUTHORIZED
    assert proposal.blockers == ()
    assert metrics["open_risk_count"] == 1
    print(json.dumps({
        "risk_id": record.risk_id,
        "inherent_band": risk_band(record.inherent_likelihood, record.inherent_impact).value,
        "residual_band": proposal.residual_band.value,
        "decision": proposal.recommendation.value,
        "verified_evidence": list(proposal.verified_evidence_ids),
        "metrics": metrics,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
