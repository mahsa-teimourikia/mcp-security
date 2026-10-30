"""Course 22: MCP recovery, revocation, rollback, and resilience.

The credential-free lab accepts a verified containment handoff, converges
revocation across every known authority path, verifies an immutable recovery
candidate and its provenance, stages it exactly once, validates security and
service health from independent evidence, and separately authorizes return to
service. Model output may propose a recovery hypothesis; it cannot select,
approve, execute, validate, or close recovery.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import hmac
import json
import re
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


UTC = timezone.utc
NOW = datetime(2026, 10, 30, 18, 30, tzinfo=UTC)
PROTOCOL_VERSION = "2026-07-28"
RECOVERY_POLICY_VERSION = "mcp-recovery/2026-10-30"
HANDOFF_POLICY_VERSION = "mcp-incident-response/2026-10-30"
MAX_CLOCK_SKEW = timedelta(seconds=5)
HANDOFF_KEY = b"course-22-containment-handoff-key"
REVOCATION_APPROVAL_KEY = b"course-22-revocation-approval-key"
RECOVERY_APPROVAL_KEY = b"course-22-recovery-approval-key"
EVIDENCE_KEY = b"course-22-recovery-evidence-key"
RETURN_APPROVAL_KEY = b"course-22-return-to-service-key"
BUILDER_SEED = sha256(b"course-22-trusted-builder-ed25519").digest()
TRUSTED_BUILDER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(BUILDER_SEED)
TRUSTED_BUILDER_PUBLIC_KEY = TRUSTED_BUILDER_PRIVATE_KEY.public_key()
TRUSTED_BUILDER_ID = "https://build.example.com/mcp/release-v2"
EXPECTED_SOURCE_REPOSITORY = "https://github.com/example/support-mcp"
EXPECTED_BUILD_TYPE = "https://build.example.com/types/python-wheel-v1"
APPROVER_ROLES = frozenset({"incident_commander", "recovery_commander"})
RETURN_APPROVER_ROLES = frozenset({"service_owner", "recovery_commander"})
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,199}$")


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + sha256(payload).hexdigest()


class RecoveryState(StrEnum):
    ACCEPTED = "accepted"
    REVOCATION_PROVEN = "revocation_proven"
    CANDIDATE_STAGED = "candidate_staged"
    VALIDATED = "validated"
    RETURNED_TO_SERVICE = "returned_to_service"
    REOPENED = "reopened"


class RecoveryStrategy(StrEnum):
    ROLLBACK = "rollback"
    FORWARD_FIX = "forward_fix"
    REBUILD = "rebuild"


class RevocationKind(StrEnum):
    DISABLE_BINDING = "disable_binding"
    INVALIDATE_CACHE = "invalidate_cache"
    CLOSE_SESSION = "close_session"
    REVOKE_CREDENTIAL = "revoke_credential"
    CANCEL_TASK = "cancel_task"
    BLOCK_EGRESS = "block_egress"


class OperationStatus(StrEnum):
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    RECONCILED = "reconciled"
    STAGED = "staged"
    RETURNED = "returned"


class EffectOutcome(StrEnum):
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class ContainmentHandoff:
    handoff_id: str
    incident_id: str
    tenant_id: str
    server_id: str
    contained_at: datetime
    containment_cut: datetime
    control_revision: int
    evidence_package_digest: str
    containment_plan_digest: str
    affected_artifacts: tuple[str, ...]
    affected_workloads: tuple[str, ...]
    affected_credentials: tuple[str, ...]
    affected_sessions: tuple[str, ...]
    affected_tasks: tuple[str, ...]
    affected_hosts: tuple[str, ...]
    affected_destinations: tuple[str, ...]
    required_remediation_ids: tuple[str, ...]
    unresolved_items: tuple[str, ...]
    authorized_recovery_actions: tuple[str, ...]
    policy_version: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


def create_handoff(*, now: datetime = NOW) -> ContainmentHandoff:
    unsigned = {
        "handoff_id": "handoff-incident-7",
        "incident_id": "incident-support-7",
        "tenant_id": "acme",
        "server_id": "support-v2",
        "contained_at": now,
        "containment_cut": now - timedelta(seconds=2),
        "control_revision": 41,
        "evidence_package_digest": digest(b"course-21-evidence-package"),
        "containment_plan_digest": digest(b"course-21-containment-plan"),
        "affected_artifacts": (digest(b"support-v2-compromised"),),
        "affected_workloads": ("spiffe://acme/mcp/support-v2",),
        "affected_credentials": ("credential-support-v2",),
        "affected_sessions": ("session-support-7",),
        "affected_tasks": ("task-export-7",),
        "affected_hosts": ("host-acme-1", "host-acme-2"),
        "affected_destinations": ("exfil.example",),
        "required_remediation_ids": ("IR-7-root-cause", "IR-7-regression"),
        "unresolved_items": ("confirm downstream token cache convergence",),
        "authorized_recovery_actions": (
            "revoke_authority",
            "stage_candidate",
            "return_to_service",
        ),
        "policy_version": HANDOFF_POLICY_VERSION,
    }
    signature = hmac.new(HANDOFF_KEY, canonical_json(unsigned), sha256).hexdigest()
    return ContainmentHandoff(**unsigned, signature=signature)


def verify_handoff(handoff: ContainmentHandoff, *, now: datetime) -> bool:
    expected = hmac.new(HANDOFF_KEY, canonical_json(handoff.unsigned()), sha256).hexdigest()
    return (
        hmac.compare_digest(expected, handoff.signature)
        and handoff.policy_version == HANDOFF_POLICY_VERSION
        and handoff.contained_at <= now + MAX_CLOCK_SKEW
        and handoff.containment_cut <= handoff.contained_at
        and handoff.control_revision > 0
        and DIGEST_RE.fullmatch(handoff.evidence_package_digest) is not None
        and DIGEST_RE.fullmatch(handoff.containment_plan_digest) is not None
        and bool(handoff.affected_artifacts)
        and bool(handoff.authorized_recovery_actions)
    )


@dataclass(frozen=True)
class RecoveryHypothesis:
    hypothesis_id: str
    proposed_by: str
    text_digest: str
    evidence_ids: tuple[str, ...]
    accepted_as_fact: bool = False


@dataclass(frozen=True)
class RecoveryCase:
    recovery_id: str
    incident_id: str
    handoff_id: str
    tenant_id: str
    server_id: str
    state: RecoveryState
    version: int
    accepted_at: datetime
    revocation_proven_at: datetime | None
    revocation_plan_digest: str
    recovery_plan_digest: str
    candidate_digest: str
    validated_evidence_digest: str
    returned_at: datetime | None
    required_remediation_ids: tuple[str, ...]
    hypotheses: tuple[RecoveryHypothesis, ...] = ()
    reopen_reason: str = ""


class VersionConflict(RuntimeError):
    pass


class RecoveryRepository:
    def __init__(self) -> None:
        self.cases: dict[str, RecoveryCase] = {}

    def create(self, case: RecoveryCase) -> None:
        if case.recovery_id in self.cases:
            raise VersionConflict("recovery case already exists")
        self.cases[case.recovery_id] = case

    def save(self, case: RecoveryCase, *, expected_version: int) -> None:
        current = self.cases[case.recovery_id]
        if current.version != expected_version or case.version != expected_version + 1:
            raise VersionConflict("stale recovery case version")
        self.cases[case.recovery_id] = case


class RecoveryManager:
    def __init__(self, repository: RecoveryRepository) -> None:
        self.repository = repository

    def accept_handoff(
        self,
        handoff: ContainmentHandoff,
        *,
        actor_id: str,
        actor_roles: frozenset[str],
        allowed_tenants: frozenset[str],
        now: datetime,
    ) -> RecoveryCase:
        if "recovery_coordinator" not in actor_roles:
            raise PermissionError("recovery coordinator role required")
        if handoff.tenant_id not in allowed_tenants:
            raise PermissionError("recovery tenant is outside coordinator authority")
        if not verify_handoff(handoff, now=now):
            raise ValueError("invalid containment handoff")
        if not {"revoke_authority", "stage_candidate", "return_to_service"}.issubset(
            handoff.authorized_recovery_actions
        ):
            raise PermissionError("handoff does not authorize the recovery workflow")
        recovery_id = "recovery-" + digest(
            (handoff.incident_id, handoff.handoff_id)
        ).split(":", 1)[1][:12]
        case = RecoveryCase(
            recovery_id=recovery_id,
            incident_id=handoff.incident_id,
            handoff_id=handoff.handoff_id,
            tenant_id=handoff.tenant_id,
            server_id=handoff.server_id,
            state=RecoveryState.ACCEPTED,
            version=1,
            accepted_at=now,
            revocation_proven_at=None,
            revocation_plan_digest="",
            recovery_plan_digest="",
            candidate_digest="",
            validated_evidence_digest="",
            returned_at=None,
            required_remediation_ids=handoff.required_remediation_ids,
        )
        self.repository.create(case)
        return case

    def add_model_hypothesis(
        self,
        case: RecoveryCase,
        *,
        proposed_by: str,
        text: str,
        evidence_ids: Iterable[str],
    ) -> RecoveryCase:
        ids = tuple(sorted(set(evidence_ids)))
        if not ids:
            raise ValueError("recovery hypothesis must cite evidence")
        hypothesis = RecoveryHypothesis(
            "hypothesis-" + digest((proposed_by, text, ids)).split(":", 1)[1][:12],
            proposed_by,
            digest(text),
            ids,
            False,
        )
        updated = replace(
            case,
            hypotheses=case.hypotheses + (hypothesis,),
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated

    def mark_revocation_proven(
        self,
        case: RecoveryCase,
        proof: "RevocationProof",
        *,
        now: datetime,
        actor_roles: frozenset[str],
    ) -> RecoveryCase:
        if "recovery_coordinator" not in actor_roles:
            raise PermissionError("recovery coordinator role required")
        if (
            case.state != RecoveryState.ACCEPTED
            or proof.incident_id != case.incident_id
            or not proof.complete
        ):
            raise ValueError("complete revocation proof for this incident is required")
        updated = replace(
            case,
            state=RecoveryState.REVOCATION_PROVEN,
            revocation_proven_at=now,
            revocation_plan_digest=proof.plan_digest,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated

    def mark_staged(
        self,
        case: RecoveryCase,
        plan: "RecoveryPlan",
        result: "DeploymentResult",
    ) -> RecoveryCase:
        if (
            case.state != RecoveryState.REVOCATION_PROVEN
            or plan.incident_id != case.incident_id
            or result.incident_id != case.incident_id
            or result.plan_digest != plan.plan_digest
            or result.candidate_digest != plan.candidate_digest
            or result.status not in {OperationStatus.STAGED, OperationStatus.RECONCILED}
        ):
            raise ValueError("verified staged candidate required")
        updated = replace(
            case,
            state=RecoveryState.CANDIDATE_STAGED,
            recovery_plan_digest=plan.plan_digest,
            candidate_digest=plan.candidate_digest,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated

    def mark_validated(
        self,
        case: RecoveryCase,
        evidence: "RecoveryEvidence",
    ) -> RecoveryCase:
        if (
            case.state != RecoveryState.CANDIDATE_STAGED
            or evidence.incident_id != case.incident_id
            or evidence.plan_digest != case.recovery_plan_digest
            or evidence.candidate_digest != case.candidate_digest
            or not evidence.complete
            or not verify_recovery_evidence(evidence)
        ):
            raise ValueError("complete signed recovery evidence required")
        updated = replace(
            case,
            state=RecoveryState.VALIDATED,
            validated_evidence_digest=evidence.evidence_digest,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated

    def mark_returned(
        self,
        case: RecoveryCase,
        proof: "SafeServiceProof",
        result: "DeploymentResult",
        *,
        now: datetime,
    ) -> RecoveryCase:
        if (
            case.state != RecoveryState.VALIDATED
            or proof.incident_id != case.incident_id
            or proof.plan_digest != case.recovery_plan_digest
            or proof.candidate_digest != case.candidate_digest
            or not proof.complete
            or result.status not in {OperationStatus.RETURNED, OperationStatus.RECONCILED}
            or result.plan_digest != case.recovery_plan_digest
            or result.candidate_digest != case.candidate_digest
            or proof.deployment_revision != result.deployment_revision
        ):
            raise ValueError("verified return-to-service proof required")
        updated = replace(
            case,
            state=RecoveryState.RETURNED_TO_SERVICE,
            returned_at=now,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated

    def reopen(
        self,
        case: RecoveryCase,
        *,
        reason: str,
        actor_roles: frozenset[str],
    ) -> RecoveryCase:
        if "incident_responder" not in actor_roles or not reason:
            raise PermissionError("incident responder and reason required")
        updated = replace(
            case,
            state=RecoveryState.REOPENED,
            reopen_reason=reason,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated


@dataclass(frozen=True)
class Provenance:
    subject_digest: str
    builder_id: str
    source_repository: str
    source_commit: str
    build_type: str
    external_parameters_digest: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


@dataclass(frozen=True)
class ArtifactCandidate:
    candidate_id: str
    artifact_bytes: bytes
    artifact_digest: str
    immutable_reference: str
    provenance: Provenance
    sbom_digest: str
    critical_vulnerabilities: int
    high_vulnerabilities: int
    security_regressions_passed: bool
    remediation_ids: tuple[str, ...]
    compatible_schema_versions: tuple[str, ...]
    config_digest: str
    policy_digest: str
    capability_contract_digest: str
    created_at: datetime


def build_candidate(
    *,
    name: str = "support-v3-fixed",
    remediation_ids: tuple[str, ...] = ("IR-7-root-cause", "IR-7-regression"),
    compatible_schema_versions: tuple[str, ...] = ("customer-schema-v4",),
    critical_vulnerabilities: int = 0,
    high_vulnerabilities: int = 0,
    security_regressions_passed: bool = True,
    builder_id: str = TRUSTED_BUILDER_ID,
    source_repository: str = EXPECTED_SOURCE_REPOSITORY,
    source_commit: str = "a" * 40,
    build_type: str = EXPECTED_BUILD_TYPE,
    now: datetime = NOW,
) -> ArtifactCandidate:
    artifact_bytes = f"wheel:{name}:deterministic".encode()
    artifact_digest = digest(artifact_bytes)
    provenance_unsigned = {
        "subject_digest": artifact_digest,
        "builder_id": builder_id,
        "source_repository": source_repository,
        "source_commit": source_commit,
        "build_type": build_type,
        "external_parameters_digest": digest(
            {"workflow": "release.yml", "ref": source_commit, "mode": "hermetic"}
        ),
    }
    signature = TRUSTED_BUILDER_PRIVATE_KEY.sign(
        canonical_json(provenance_unsigned)
    ).hex()
    provenance = Provenance(**provenance_unsigned, signature=signature)
    return ArtifactCandidate(
        "candidate-" + artifact_digest.split(":", 1)[1][:12],
        artifact_bytes,
        artifact_digest,
        f"registry.example.com/acme/support@{artifact_digest}",
        provenance,
        digest(b"cyclonedx-sbom-support-v3"),
        critical_vulnerabilities,
        high_vulnerabilities,
        security_regressions_passed,
        tuple(sorted(remediation_ids)),
        compatible_schema_versions,
        digest(b"config-v7"),
        digest(b"policy-v12"),
        digest(b"mcp-capability-contract-v3"),
        now,
    )


class CandidateVerifier:
    def __init__(self, public_key: Ed25519PublicKey = TRUSTED_BUILDER_PUBLIC_KEY) -> None:
        self.public_key = public_key

    def verify(
        self,
        candidate: ArtifactCandidate,
        *,
        required_remediation_ids: tuple[str, ...],
        current_schema_version: str,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if candidate.artifact_digest != digest(candidate.artifact_bytes):
            reasons.append("ARTIFACT_DIGEST_MISMATCH")
        if not DIGEST_RE.fullmatch(candidate.artifact_digest):
            reasons.append("ARTIFACT_DIGEST_INVALID")
        if not candidate.immutable_reference.endswith("@" + candidate.artifact_digest):
            reasons.append("MUTABLE_REFERENCE")
        provenance = candidate.provenance
        if provenance.subject_digest != candidate.artifact_digest:
            reasons.append("PROVENANCE_SUBJECT_MISMATCH")
        if provenance.builder_id != TRUSTED_BUILDER_ID:
            reasons.append("BUILDER_UNTRUSTED")
        if provenance.source_repository != EXPECTED_SOURCE_REPOSITORY:
            reasons.append("SOURCE_UNTRUSTED")
        if provenance.build_type != EXPECTED_BUILD_TYPE:
            reasons.append("BUILD_TYPE_UNEXPECTED")
        if not COMMIT_RE.fullmatch(provenance.source_commit):
            reasons.append("SOURCE_COMMIT_INVALID")
        expected_external_parameters_digest = digest(
            {
                "workflow": "release.yml",
                "ref": provenance.source_commit,
                "mode": "hermetic",
            }
        )
        if provenance.external_parameters_digest != expected_external_parameters_digest:
            reasons.append("EXTERNAL_PARAMETERS_UNEXPECTED")
        try:
            self.public_key.verify(
                bytes.fromhex(provenance.signature),
                canonical_json(provenance.unsigned()),
            )
        except (InvalidSignature, ValueError):
            reasons.append("PROVENANCE_SIGNATURE_INVALID")
        if not DIGEST_RE.fullmatch(candidate.sbom_digest):
            reasons.append("SBOM_INVALID")
        if candidate.critical_vulnerabilities or candidate.high_vulnerabilities:
            reasons.append("VULNERABILITY_GATE_FAILED")
        if not candidate.security_regressions_passed:
            reasons.append("SECURITY_REGRESSION_FAILED")
        if not set(required_remediation_ids).issubset(candidate.remediation_ids):
            reasons.append("ROOT_CAUSE_NOT_REMEDIATED")
        if current_schema_version not in candidate.compatible_schema_versions:
            reasons.append("SCHEMA_INCOMPATIBLE")
        if candidate.created_at > now + MAX_CLOCK_SKEW:
            reasons.append("CANDIDATE_FROM_FUTURE")
        return not reasons, tuple(reasons)


@dataclass(frozen=True)
class StrategyDecision:
    strategy: RecoveryStrategy
    candidate_digest: str
    reason_codes: tuple[str, ...]


def select_strategy(
    candidate: ArtifactCandidate,
    *,
    previous_digest: str,
    previous_is_vulnerable: bool,
    rebuild_required: bool,
) -> StrategyDecision:
    if rebuild_required:
        return StrategyDecision(
            RecoveryStrategy.REBUILD,
            candidate.artifact_digest,
            ("ENVIRONMENT_REBUILD_REQUIRED",),
        )
    if candidate.artifact_digest == previous_digest and not previous_is_vulnerable:
        return StrategyDecision(
            RecoveryStrategy.ROLLBACK,
            candidate.artifact_digest,
            ("KNOWN_GOOD_PREVIOUS_ARTIFACT",),
        )
    return StrategyDecision(
        RecoveryStrategy.FORWARD_FIX,
        candidate.artifact_digest,
        ("ROOT_CAUSE_FIX_AND_COMPATIBILITY_REQUIRED",),
    )


@dataclass(frozen=True)
class RevocationAction:
    action_id: str
    kind: RevocationKind
    tenant_id: str
    target: str
    secondary: str = ""


@dataclass(frozen=True)
class RevocationPlan:
    plan_id: str
    incident_id: str
    tenant_id: str
    required_epoch: int
    actions: tuple[RevocationAction, ...]
    required_control_points: tuple[str, ...]
    policy_version: str
    created_at: datetime
    expires_at: datetime
    plan_digest: str


def make_revocation_plan(
    handoff: ContainmentHandoff,
    *,
    current_epoch: int,
    now: datetime,
) -> RevocationPlan:
    actions: list[RevocationAction] = []
    for artifact in handoff.affected_artifacts:
        actions.append(
            RevocationAction(
                f"disable-{len(actions) + 1}",
                RevocationKind.DISABLE_BINDING,
                handoff.tenant_id,
                handoff.server_id,
                artifact,
            )
        )
    for host in handoff.affected_hosts:
        actions.append(
            RevocationAction(
                f"cache-{len(actions) + 1}",
                RevocationKind.INVALIDATE_CACHE,
                handoff.tenant_id,
                host,
            )
        )
    for session in handoff.affected_sessions:
        actions.append(
            RevocationAction(
                f"session-{len(actions) + 1}",
                RevocationKind.CLOSE_SESSION,
                handoff.tenant_id,
                session,
            )
        )
    for credential in handoff.affected_credentials:
        actions.append(
            RevocationAction(
                f"credential-{len(actions) + 1}",
                RevocationKind.REVOKE_CREDENTIAL,
                handoff.tenant_id,
                credential,
            )
        )
    for task in handoff.affected_tasks:
        actions.append(
            RevocationAction(
                f"task-{len(actions) + 1}",
                RevocationKind.CANCEL_TASK,
                handoff.tenant_id,
                task,
            )
        )
    for workload in handoff.affected_workloads:
        for destination in handoff.affected_destinations:
            actions.append(
                RevocationAction(
                    f"egress-{len(actions) + 1}",
                    RevocationKind.BLOCK_EGRESS,
                    handoff.tenant_id,
                    workload,
                    destination,
                )
            )
    required_points = (
        "registry",
        "host-cache",
        "gateway",
        "credential-issuer",
        "task-queue",
        "network",
    )
    unsigned = {
        "incident_id": handoff.incident_id,
        "tenant_id": handoff.tenant_id,
        "required_epoch": current_epoch + 1,
        "actions": tuple(actions),
        "required_control_points": required_points,
        "policy_version": RECOVERY_POLICY_VERSION,
        "created_at": now,
        "expires_at": now + timedelta(minutes=10),
    }
    plan_digest = digest(unsigned)
    return RevocationPlan(
        "revocation-" + plan_digest.split(":", 1)[1][:12],
        **unsigned,
        plan_digest=plan_digest,
    )


def verify_revocation_plan(plan: RevocationPlan) -> bool:
    unsigned = {
        "incident_id": plan.incident_id,
        "tenant_id": plan.tenant_id,
        "required_epoch": plan.required_epoch,
        "actions": plan.actions,
        "required_control_points": plan.required_control_points,
        "policy_version": plan.policy_version,
        "created_at": plan.created_at,
        "expires_at": plan.expires_at,
    }
    return (
        plan.plan_digest == digest(unsigned)
        and bool(plan.actions)
        and len({item.action_id for item in plan.actions}) == len(plan.actions)
    )


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    purpose: str
    incident_id: str
    tenant_id: str
    proposal_digest: str
    policy_version: str
    approver_id: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


def _approve(
    *,
    purpose: str,
    incident_id: str,
    tenant_id: str,
    proposal_digest: str,
    approver_id: str,
    approver_role: str,
    now: datetime,
    expires_at: datetime,
    key: bytes,
    allowed_roles: frozenset[str],
) -> ApprovalReceipt:
    if approver_role not in allowed_roles:
        raise PermissionError("approver role is not authorized")
    receipt_id = "receipt-" + digest(
        (purpose, incident_id, proposal_digest, approver_id, now)
    ).split(":", 1)[1][:14]
    unsigned = {
        "receipt_id": receipt_id,
        "purpose": purpose,
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "proposal_digest": proposal_digest,
        "policy_version": RECOVERY_POLICY_VERSION,
        "approver_id": approver_id,
        "approver_role": approver_role,
        "issued_at": now,
        "expires_at": min(expires_at, now + timedelta(minutes=5)),
        "nonce": "nonce-" + receipt_id[-8:],
    }
    signature = hmac.new(key, canonical_json(unsigned), sha256).hexdigest()
    return ApprovalReceipt(**unsigned, signature=signature)


def approve_revocation(
    plan: RevocationPlan,
    *,
    approver_id: str,
    approver_role: str,
    now: datetime,
) -> ApprovalReceipt:
    return _approve(
        purpose="revocation",
        incident_id=plan.incident_id,
        tenant_id=plan.tenant_id,
        proposal_digest=plan.plan_digest,
        approver_id=approver_id,
        approver_role=approver_role,
        now=now,
        expires_at=plan.expires_at,
        key=REVOCATION_APPROVAL_KEY,
        allowed_roles=APPROVER_ROLES,
    )


def verify_approval(
    receipt: ApprovalReceipt,
    *,
    key: bytes,
    allowed_roles: frozenset[str],
) -> bool:
    expected = hmac.new(key, canonical_json(receipt.unsigned()), sha256).hexdigest()
    return (
        hmac.compare_digest(expected, receipt.signature)
        and receipt.approver_role in allowed_roles
    )


@dataclass(frozen=True)
class AuthorityPlane:
    epoch: int
    disabled_bindings: frozenset[tuple[str, str]] = frozenset()
    invalidated_hosts: frozenset[str] = frozenset()
    closed_sessions: frozenset[str] = frozenset()
    revoked_credentials: frozenset[str] = frozenset()
    cancelled_tasks: frozenset[str] = frozenset()
    blocked_egress: frozenset[tuple[str, str]] = frozenset()
    observed_epochs: tuple[tuple[str, int], ...] = ()

    def satisfied(self, action: RevocationAction) -> bool:
        if action.kind == RevocationKind.DISABLE_BINDING:
            return (action.target, action.secondary) in self.disabled_bindings
        if action.kind == RevocationKind.INVALIDATE_CACHE:
            return action.target in self.invalidated_hosts
        if action.kind == RevocationKind.CLOSE_SESSION:
            return action.target in self.closed_sessions
        if action.kind == RevocationKind.REVOKE_CREDENTIAL:
            return action.target in self.revoked_credentials
        if action.kind == RevocationKind.CANCEL_TASK:
            return action.target in self.cancelled_tasks
        if action.kind == RevocationKind.BLOCK_EGRESS:
            return (action.target, action.secondary) in self.blocked_egress
        return False

    def apply(
        self,
        plan: RevocationPlan,
        *,
        unavailable_kinds: frozenset[RevocationKind] = frozenset(),
    ) -> "AuthorityPlane":
        available = tuple(
            item for item in plan.actions if item.kind not in unavailable_kinds
        )
        points = {
            "registry": RevocationKind.DISABLE_BINDING,
            "host-cache": RevocationKind.INVALIDATE_CACHE,
            "gateway": RevocationKind.CLOSE_SESSION,
            "credential-issuer": RevocationKind.REVOKE_CREDENTIAL,
            "task-queue": RevocationKind.CANCEL_TASK,
            "network": RevocationKind.BLOCK_EGRESS,
        }
        epochs = dict(self.observed_epochs)
        for point, kind in points.items():
            relevant = tuple(item for item in plan.actions if item.kind == kind)
            if relevant and all(item.kind not in unavailable_kinds for item in relevant):
                epochs[point] = plan.required_epoch
        return replace(
            self,
            epoch=max(self.epoch, plan.required_epoch),
            disabled_bindings=self.disabled_bindings
            | {
                (item.target, item.secondary)
                for item in available
                if item.kind == RevocationKind.DISABLE_BINDING
            },
            invalidated_hosts=self.invalidated_hosts
            | {
                item.target
                for item in available
                if item.kind == RevocationKind.INVALIDATE_CACHE
            },
            closed_sessions=self.closed_sessions
            | {
                item.target
                for item in available
                if item.kind == RevocationKind.CLOSE_SESSION
            },
            revoked_credentials=self.revoked_credentials
            | {
                item.target
                for item in available
                if item.kind == RevocationKind.REVOKE_CREDENTIAL
            },
            cancelled_tasks=self.cancelled_tasks
            | {
                item.target
                for item in available
                if item.kind == RevocationKind.CANCEL_TASK
            },
            blocked_egress=self.blocked_egress
            | {
                (item.target, item.secondary)
                for item in available
                if item.kind == RevocationKind.BLOCK_EGRESS
            },
            observed_epochs=tuple(sorted(epochs.items())),
        )


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    request_digest: str
    incident_id: str
    proposal_digest: str
    status: OperationStatus
    control_revision: int
    effect_ids: tuple[str, ...]
    reason_code: str
    occurred_at: datetime


class RevocationJournal:
    def __init__(self) -> None:
        self.operations: dict[str, OperationResult] = {}
        self.plans: dict[str, RevocationPlan] = {}
        self.consumed_receipts: set[str] = set()


class RevocationCoordinator:
    def __init__(
        self,
        authority: AuthorityPlane,
        journal: RevocationJournal | None = None,
    ) -> None:
        self.authority = authority
        self.journal = journal or RevocationJournal()

    def execute(
        self,
        operation_id: str,
        plan: RevocationPlan,
        receipt: ApprovalReceipt,
        case: RecoveryCase,
        *,
        now: datetime,
        unavailable_kinds: frozenset[RevocationKind] = frozenset(),
        simulate_lost_response: bool = False,
    ) -> OperationResult:
        request_digest = digest((plan.plan_digest, receipt.receipt_id))
        previous = self.journal.operations.get(operation_id)
        if previous is not None:
            if previous.request_digest != request_digest:
                raise ValueError("operation ID reused with a different revocation request")
            return self.reconcile(operation_id, now=now)
        if case.state != RecoveryState.ACCEPTED or case.incident_id != plan.incident_id:
            raise PermissionError("recovery case does not authorize revocation")
        if (
            not verify_revocation_plan(plan)
            or plan.policy_version != RECOVERY_POLICY_VERSION
            or now > plan.expires_at
        ):
            raise ValueError("revocation plan invalid, stale, or expired")
        if any(item.tenant_id != case.tenant_id for item in plan.actions):
            raise PermissionError("cross-tenant revocation action")
        if receipt.receipt_id in self.journal.consumed_receipts:
            raise ValueError("revocation receipt already consumed")
        if (
            not verify_approval(
                receipt,
                key=REVOCATION_APPROVAL_KEY,
                allowed_roles=APPROVER_ROLES,
            )
            or receipt.purpose != "revocation"
            or receipt.incident_id != plan.incident_id
            or receipt.tenant_id != plan.tenant_id
            or receipt.proposal_digest != plan.plan_digest
            or receipt.policy_version != plan.policy_version
            or now > receipt.expires_at
        ):
            raise PermissionError("receipt does not authorize this revocation plan")
        self.authority = self.authority.apply(
            plan, unavailable_kinds=unavailable_kinds
        )
        self.journal.consumed_receipts.add(receipt.receipt_id)
        self.journal.plans[operation_id] = plan
        all_satisfied = all(self.authority.satisfied(item) for item in plan.actions)
        status = (
            OperationStatus.UNKNOWN
            if simulate_lost_response and all_satisfied
            else OperationStatus.RECONCILED
            if all_satisfied
            else OperationStatus.PARTIAL
        )
        result = OperationResult(
            operation_id,
            request_digest,
            plan.incident_id,
            plan.plan_digest,
            status,
            self.authority.epoch,
            tuple(
                item.action_id
                for item in plan.actions
                if self.authority.satisfied(item)
            ),
            "OUTCOME_UNKNOWN_RECONCILE"
            if status == OperationStatus.UNKNOWN
            else "REVOCATION_CONVERGED"
            if all_satisfied
            else "CONTROL_POINT_UNAVAILABLE",
            now,
        )
        self.journal.operations[operation_id] = result
        return result

    def retry_missing(self, operation_id: str, *, now: datetime) -> OperationResult:
        plan = self.journal.plans[operation_id]
        self.authority = self.authority.apply(plan)
        return self.reconcile(operation_id, now=now)

    def reconcile(self, operation_id: str, *, now: datetime) -> OperationResult:
        previous = self.journal.operations[operation_id]
        plan = self.journal.plans[operation_id]
        all_satisfied = all(self.authority.satisfied(item) for item in plan.actions)
        epochs = dict(self.authority.observed_epochs)
        all_epochs = all(
            epochs.get(point, 0) >= plan.required_epoch
            for point in plan.required_control_points
        )
        result = replace(
            previous,
            status=OperationStatus.RECONCILED
            if all_satisfied and all_epochs
            else OperationStatus.PARTIAL,
            control_revision=self.authority.epoch,
            effect_ids=tuple(
                item.action_id
                for item in plan.actions
                if self.authority.satisfied(item)
            ),
            reason_code="REVOCATION_CONVERGED"
            if all_satisfied and all_epochs
            else "REVOCATION_INCOMPLETE",
            occurred_at=now,
        )
        self.journal.operations[operation_id] = result
        return result


@dataclass(frozen=True)
class EffectEvent:
    event_id: str
    tenant_id: str
    occurred_at: datetime
    workload_id: str
    credential_id: str
    session_id: str
    task_id: str
    destination: str
    outcome: EffectOutcome
    source: str


@dataclass(frozen=True)
class RevocationProof:
    incident_id: str
    plan_digest: str
    required_action_count: int
    satisfied_action_count: int
    required_control_point_count: int
    converged_control_point_count: int
    residual_authority_count: int
    post_cut_forbidden_effect_count: int
    complete: bool


def prove_revocation(
    plan: RevocationPlan,
    authority: AuthorityPlane,
    handoff: ContainmentHandoff,
    events: Iterable[EffectEvent],
    *,
    proof_time: datetime,
) -> RevocationProof:
    satisfied = sum(authority.satisfied(item) for item in plan.actions)
    epochs = dict(authority.observed_epochs)
    converged = sum(
        epochs.get(point, 0) >= plan.required_epoch
        for point in plan.required_control_points
    )
    residual = len(plan.actions) - satisfied
    forbidden = tuple(
        event
        for event in events
        if event.occurred_at > handoff.containment_cut
        and event.outcome == EffectOutcome.COMPLETED
        and (
            event.workload_id in handoff.affected_workloads
            or event.credential_id in handoff.affected_credentials
            or event.session_id in handoff.affected_sessions
            or event.task_id in handoff.affected_tasks
            or event.destination in handoff.affected_destinations
        )
    )
    complete = (
        satisfied == len(plan.actions)
        and converged == len(plan.required_control_points)
        and not forbidden
        and authority.epoch >= plan.required_epoch
        and proof_time >= handoff.contained_at
    )
    return RevocationProof(
        plan.incident_id,
        plan.plan_digest,
        len(plan.actions),
        satisfied,
        len(plan.required_control_points),
        converged,
        residual,
        len(forbidden),
        complete,
    )


@dataclass(frozen=True)
class RecoveryObjectives:
    rto_seconds: int
    maximum_safe_task_failure_rate: float
    maximum_forbidden_effect_rate: float


@dataclass(frozen=True)
class RecoveryPlan:
    plan_id: str
    incident_id: str
    tenant_id: str
    case_version: int
    strategy: RecoveryStrategy
    candidate_digest: str
    candidate_evidence_digest: str
    immutable_reference: str
    config_digest: str
    policy_digest: str
    capability_contract_digest: str
    canary_percent: int
    objectives: RecoveryObjectives
    policy_version: str
    created_at: datetime
    expires_at: datetime
    plan_digest: str


def make_recovery_plan(
    case: RecoveryCase,
    candidate: ArtifactCandidate,
    decision: StrategyDecision,
    verifier: CandidateVerifier,
    revocation_proof: RevocationProof,
    *,
    current_schema_version: str,
    now: datetime,
) -> RecoveryPlan:
    verified, reasons = verifier.verify(
        candidate,
        required_remediation_ids=case.required_remediation_ids,
        current_schema_version=current_schema_version,
        now=now,
    )
    if case.state != RecoveryState.REVOCATION_PROVEN:
        raise ValueError("revocation must be proven before recovery planning")
    if not revocation_proof.complete or revocation_proof.incident_id != case.incident_id:
        raise ValueError("complete revocation proof required")
    if revocation_proof.plan_digest != case.revocation_plan_digest:
        raise ValueError("revocation proof does not match the accepted plan")
    if not verified:
        raise ValueError("candidate verification failed: " + ",".join(reasons))
    if decision.candidate_digest != candidate.artifact_digest:
        raise ValueError("strategy does not reference the verified candidate")
    unsigned = {
        "incident_id": case.incident_id,
        "tenant_id": case.tenant_id,
        "case_version": case.version,
        "strategy": decision.strategy,
        "candidate_digest": candidate.artifact_digest,
        "candidate_evidence_digest": digest(candidate),
        "immutable_reference": candidate.immutable_reference,
        "config_digest": candidate.config_digest,
        "policy_digest": candidate.policy_digest,
        "capability_contract_digest": candidate.capability_contract_digest,
        "canary_percent": 10,
        "objectives": RecoveryObjectives(900, 0.01, 0.0),
        "policy_version": RECOVERY_POLICY_VERSION,
        "created_at": now,
        "expires_at": now + timedelta(minutes=15),
    }
    plan_digest = digest(unsigned)
    return RecoveryPlan(
        "recovery-plan-" + plan_digest.split(":", 1)[1][:12],
        **unsigned,
        plan_digest=plan_digest,
    )


def verify_recovery_plan(plan: RecoveryPlan) -> bool:
    unsigned = {
        "incident_id": plan.incident_id,
        "tenant_id": plan.tenant_id,
        "case_version": plan.case_version,
        "strategy": plan.strategy,
        "candidate_digest": plan.candidate_digest,
        "candidate_evidence_digest": plan.candidate_evidence_digest,
        "immutable_reference": plan.immutable_reference,
        "config_digest": plan.config_digest,
        "policy_digest": plan.policy_digest,
        "capability_contract_digest": plan.capability_contract_digest,
        "canary_percent": plan.canary_percent,
        "objectives": plan.objectives,
        "policy_version": plan.policy_version,
        "created_at": plan.created_at,
        "expires_at": plan.expires_at,
    }
    return (
        plan.plan_digest == digest(unsigned)
        and plan.immutable_reference.endswith("@" + plan.candidate_digest)
        and 0 < plan.canary_percent < 100
    )


def approve_recovery(
    plan: RecoveryPlan,
    *,
    approver_id: str,
    approver_role: str,
    now: datetime,
) -> ApprovalReceipt:
    return _approve(
        purpose="stage_recovery",
        incident_id=plan.incident_id,
        tenant_id=plan.tenant_id,
        proposal_digest=plan.plan_digest,
        approver_id=approver_id,
        approver_role=approver_role,
        now=now,
        expires_at=plan.expires_at,
        key=RECOVERY_APPROVAL_KEY,
        allowed_roles=APPROVER_ROLES,
    )


@dataclass(frozen=True)
class DeploymentState:
    revision: int = 0
    candidate_digest: str = ""
    immutable_reference: str = ""
    config_digest: str = ""
    policy_digest: str = ""
    capability_contract_digest: str = ""
    canary_percent: int = 0
    public_registry_enabled: bool = False

    def matches_stage(self, plan: RecoveryPlan) -> bool:
        return (
            self.candidate_digest == plan.candidate_digest
            and self.immutable_reference == plan.immutable_reference
            and self.config_digest == plan.config_digest
            and self.policy_digest == plan.policy_digest
            and self.capability_contract_digest
            == plan.capability_contract_digest
            and self.canary_percent == plan.canary_percent
            and not self.public_registry_enabled
        )

    def stage(self, plan: RecoveryPlan) -> "DeploymentState":
        return DeploymentState(
            self.revision + 1,
            plan.candidate_digest,
            plan.immutable_reference,
            plan.config_digest,
            plan.policy_digest,
            plan.capability_contract_digest,
            plan.canary_percent,
            False,
        )

    def promote(self, plan: RecoveryPlan) -> "DeploymentState":
        if not self.matches_stage(plan):
            raise ValueError("only the exact staged candidate can be promoted")
        return replace(
            self,
            revision=self.revision + 1,
            canary_percent=100,
            public_registry_enabled=True,
        )


@dataclass(frozen=True)
class DeploymentResult:
    operation_id: str
    request_digest: str
    incident_id: str
    plan_digest: str
    candidate_digest: str
    status: OperationStatus
    deployment_revision: int
    reason_code: str
    occurred_at: datetime


class RecoveryJournal:
    def __init__(self) -> None:
        self.stage_operations: dict[str, DeploymentResult] = {}
        self.promotion_operations: dict[str, DeploymentResult] = {}
        self.plans: dict[str, RecoveryPlan] = {}
        self.consumed_stage_receipts: set[str] = set()
        self.consumed_return_receipts: set[str] = set()


class RecoveryExecutor:
    def __init__(
        self,
        deployment: DeploymentState | None = None,
        journal: RecoveryJournal | None = None,
    ) -> None:
        self.deployment = deployment or DeploymentState()
        self.journal = journal or RecoveryJournal()

    def stage(
        self,
        operation_id: str,
        plan: RecoveryPlan,
        receipt: ApprovalReceipt,
        candidate: ArtifactCandidate,
        case: RecoveryCase,
        *,
        now: datetime,
        simulate_lost_response: bool = False,
    ) -> DeploymentResult:
        request_digest = digest(
            (plan.plan_digest, receipt.receipt_id, digest(candidate))
        )
        previous = self.journal.stage_operations.get(operation_id)
        if previous is not None:
            if previous.request_digest != request_digest:
                raise ValueError("stage operation ID reused with different request")
            return self.reconcile_stage(operation_id, now=now)
        if (
            case.state != RecoveryState.REVOCATION_PROVEN
            or case.incident_id != plan.incident_id
            or case.version != plan.case_version
        ):
            raise PermissionError("recovery case does not authorize staging")
        if (
            not verify_recovery_plan(plan)
            or plan.candidate_evidence_digest != digest(candidate)
            or candidate.artifact_digest != plan.candidate_digest
            or now > plan.expires_at
        ):
            raise ValueError("recovery plan or candidate integrity invalid")
        if receipt.receipt_id in self.journal.consumed_stage_receipts:
            raise ValueError("recovery approval already consumed")
        if (
            not verify_approval(
                receipt,
                key=RECOVERY_APPROVAL_KEY,
                allowed_roles=APPROVER_ROLES,
            )
            or receipt.purpose != "stage_recovery"
            or receipt.incident_id != plan.incident_id
            or receipt.tenant_id != plan.tenant_id
            or receipt.proposal_digest != plan.plan_digest
            or receipt.policy_version != plan.policy_version
            or now > receipt.expires_at
        ):
            raise PermissionError("receipt does not authorize this recovery plan")
        self.deployment = self.deployment.stage(plan)
        self.journal.consumed_stage_receipts.add(receipt.receipt_id)
        self.journal.plans[operation_id] = plan
        result = DeploymentResult(
            operation_id,
            request_digest,
            plan.incident_id,
            plan.plan_digest,
            plan.candidate_digest,
            OperationStatus.UNKNOWN
            if simulate_lost_response
            else OperationStatus.STAGED,
            self.deployment.revision,
            "OUTCOME_UNKNOWN_RECONCILE"
            if simulate_lost_response
            else "EXACT_CANDIDATE_STAGED",
            now,
        )
        self.journal.stage_operations[operation_id] = result
        return result

    def reconcile_stage(self, operation_id: str, *, now: datetime) -> DeploymentResult:
        previous = self.journal.stage_operations[operation_id]
        plan = self.journal.plans[operation_id]
        result = replace(
            previous,
            status=OperationStatus.RECONCILED
            if self.deployment.matches_stage(plan)
            else OperationStatus.UNKNOWN,
            deployment_revision=self.deployment.revision,
            reason_code="STAGED_STATE_CONFIRMED"
            if self.deployment.matches_stage(plan)
            else "STAGED_STATE_UNCONFIRMED",
            occurred_at=now,
        )
        self.journal.stage_operations[operation_id] = result
        return result

    def promote(
        self,
        operation_id: str,
        plan: RecoveryPlan,
        receipt: ApprovalReceipt,
        evidence: "RecoveryEvidence",
        case: RecoveryCase,
        *,
        now: datetime,
        simulate_lost_response: bool = False,
    ) -> DeploymentResult:
        request_digest = digest(
            (plan.plan_digest, receipt.receipt_id, evidence.evidence_digest)
        )
        previous = self.journal.promotion_operations.get(operation_id)
        if previous is not None:
            if previous.request_digest != request_digest:
                raise ValueError("promotion operation ID reused with different request")
            return self.reconcile_promotion(operation_id, plan=plan, now=now)
        if (
            case.state != RecoveryState.VALIDATED
            or case.incident_id != plan.incident_id
            or case.validated_evidence_digest != evidence.evidence_digest
        ):
            raise PermissionError("validated recovery case required")
        if (
            not verify_recovery_plan(plan)
            or now > plan.expires_at
            or not evidence.complete
            or not verify_recovery_evidence(evidence)
            or evidence.incident_id != plan.incident_id
            or evidence.plan_digest != plan.plan_digest
            or evidence.candidate_digest != plan.candidate_digest
        ):
            raise ValueError("valid independent recovery evidence required")
        if receipt.receipt_id in self.journal.consumed_return_receipts:
            raise ValueError("return-to-service approval already consumed")
        if (
            not verify_approval(
                receipt,
                key=RETURN_APPROVAL_KEY,
                allowed_roles=RETURN_APPROVER_ROLES,
            )
            or receipt.purpose != "return_to_service"
            or receipt.incident_id != plan.incident_id
            or receipt.tenant_id != plan.tenant_id
            or receipt.proposal_digest != digest(
                (plan.plan_digest, evidence.evidence_digest)
            )
            or receipt.policy_version != plan.policy_version
            or now > receipt.expires_at
        ):
            raise PermissionError("receipt does not authorize return to service")
        self.deployment = self.deployment.promote(plan)
        self.journal.consumed_return_receipts.add(receipt.receipt_id)
        self.journal.plans[operation_id] = plan
        result = DeploymentResult(
            operation_id,
            request_digest,
            plan.incident_id,
            plan.plan_digest,
            plan.candidate_digest,
            OperationStatus.UNKNOWN
            if simulate_lost_response
            else OperationStatus.RETURNED,
            self.deployment.revision,
            "OUTCOME_UNKNOWN_RECONCILE"
            if simulate_lost_response
            else "RETURN_TO_SERVICE_APPLIED",
            now,
        )
        self.journal.promotion_operations[operation_id] = result
        return result

    def reconcile_promotion(
        self,
        operation_id: str,
        *,
        plan: RecoveryPlan,
        now: datetime,
    ) -> DeploymentResult:
        previous = self.journal.promotion_operations[operation_id]
        returned = (
            self.deployment.candidate_digest == plan.candidate_digest
            and self.deployment.canary_percent == 100
            and self.deployment.public_registry_enabled
        )
        result = replace(
            previous,
            status=OperationStatus.RECONCILED
            if returned
            else OperationStatus.UNKNOWN,
            deployment_revision=self.deployment.revision,
            reason_code="RETURNED_STATE_CONFIRMED"
            if returned
            else "RETURNED_STATE_UNCONFIRMED",
            occurred_at=now,
        )
        self.journal.promotion_operations[operation_id] = result
        return result


@dataclass(frozen=True)
class RecoveryObservations:
    workload_artifact_digest: str
    registry_artifact_digest: str
    config_digest: str
    policy_digest: str
    capability_contract_digest: str
    security_regressions_total: int
    security_regressions_passed: int
    safe_tasks_total: int
    safe_tasks_succeeded: int
    forbidden_attempts_total: int
    forbidden_effects_completed: int
    compromise_indicator_count: int
    independent_sources: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryEvidence:
    evidence_id: str
    incident_id: str
    plan_digest: str
    candidate_digest: str
    deployment_revision: int
    validated_at: datetime
    checks: tuple[tuple[str, bool], ...]
    security_regressions_total: int
    security_regressions_passed: int
    safe_tasks_total: int
    safe_tasks_succeeded: int
    forbidden_attempts_total: int
    forbidden_effects_completed: int
    independent_sources: tuple[str, ...]
    complete: bool
    evidence_digest: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("evidence_digest")
        result.pop("signature")
        return result


def validate_recovery(
    plan: RecoveryPlan,
    deployment: DeploymentState,
    observations: RecoveryObservations,
    *,
    now: datetime,
) -> RecoveryEvidence:
    checks = (
        (
            "DEPLOYED_DIGEST_MATCHES",
            deployment.matches_stage(plan)
            and observations.workload_artifact_digest == plan.candidate_digest,
        ),
        (
            "REGISTRY_REMAINS_DISABLED_DURING_CANARY",
            not deployment.public_registry_enabled
            and observations.registry_artifact_digest == plan.candidate_digest,
        ),
        (
            "CONFIG_POLICY_CONTRACT_MATCH",
            observations.config_digest == plan.config_digest
            and observations.policy_digest == plan.policy_digest
            and observations.capability_contract_digest
            == plan.capability_contract_digest,
        ),
        (
            "SECURITY_REGRESSIONS_PASS",
            observations.security_regressions_total > 0
            and observations.security_regressions_passed
            == observations.security_regressions_total,
        ),
        (
            "SAFE_TASKS_PASS",
            observations.safe_tasks_total > 0
            and observations.safe_tasks_succeeded
            / observations.safe_tasks_total
            >= 1 - plan.objectives.maximum_safe_task_failure_rate,
        ),
        (
            "FORBIDDEN_EFFECTS_ABSENT",
            observations.forbidden_attempts_total > 0
            and observations.forbidden_effects_completed
            / observations.forbidden_attempts_total
            <= plan.objectives.maximum_forbidden_effect_rate,
        ),
        (
            "NO_COMPROMISE_INDICATORS",
            observations.compromise_indicator_count == 0,
        ),
        (
            "INDEPENDENT_SOURCES",
            len(set(observations.independent_sources)) >= 2,
        ),
    )
    complete = all(value for _, value in checks)
    evidence_id = "recovery-evidence-" + digest(
        (plan.plan_digest, deployment.revision, checks, now)
    ).split(":", 1)[1][:12]
    unsigned = {
        "evidence_id": evidence_id,
        "incident_id": plan.incident_id,
        "plan_digest": plan.plan_digest,
        "candidate_digest": plan.candidate_digest,
        "deployment_revision": deployment.revision,
        "validated_at": now,
        "checks": checks,
        "security_regressions_total": observations.security_regressions_total,
        "security_regressions_passed": observations.security_regressions_passed,
        "safe_tasks_total": observations.safe_tasks_total,
        "safe_tasks_succeeded": observations.safe_tasks_succeeded,
        "forbidden_attempts_total": observations.forbidden_attempts_total,
        "forbidden_effects_completed": observations.forbidden_effects_completed,
        "independent_sources": tuple(sorted(set(observations.independent_sources))),
        "complete": complete,
    }
    evidence_digest = digest(unsigned)
    signature = hmac.new(EVIDENCE_KEY, evidence_digest.encode(), sha256).hexdigest()
    return RecoveryEvidence(
        **unsigned,
        evidence_digest=evidence_digest,
        signature=signature,
    )


def verify_recovery_evidence(evidence: RecoveryEvidence) -> bool:
    expected_digest = digest(evidence.unsigned())
    expected_signature = hmac.new(
        EVIDENCE_KEY, expected_digest.encode(), sha256
    ).hexdigest()
    return (
        evidence.evidence_digest == expected_digest
        and hmac.compare_digest(evidence.signature, expected_signature)
    )


def approve_return_to_service(
    plan: RecoveryPlan,
    evidence: RecoveryEvidence,
    *,
    approver_id: str,
    approver_role: str,
    now: datetime,
) -> ApprovalReceipt:
    if (
        not evidence.complete
        or not verify_recovery_evidence(evidence)
        or evidence.incident_id != plan.incident_id
        or evidence.plan_digest != plan.plan_digest
        or evidence.candidate_digest != plan.candidate_digest
    ):
        raise ValueError("complete signed recovery evidence required")
    return _approve(
        purpose="return_to_service",
        incident_id=plan.incident_id,
        tenant_id=plan.tenant_id,
        proposal_digest=digest((plan.plan_digest, evidence.evidence_digest)),
        approver_id=approver_id,
        approver_role=approver_role,
        now=now,
        expires_at=plan.expires_at,
        key=RETURN_APPROVAL_KEY,
        allowed_roles=RETURN_APPROVER_ROLES,
    )


@dataclass(frozen=True)
class SafeServiceProof:
    incident_id: str
    plan_digest: str
    candidate_digest: str
    deployment_revision: int
    post_recovery_forbidden_effect_count: int
    evidence_valid: bool
    complete: bool


def prove_safe_service(
    plan: RecoveryPlan,
    deployment: DeploymentState,
    evidence: RecoveryEvidence,
    events: Iterable[EffectEvent],
    *,
    returned_at: datetime,
) -> SafeServiceProof:
    forbidden = tuple(
        event
        for event in events
        if event.occurred_at > returned_at
        and event.outcome == EffectOutcome.COMPLETED
        and event.tenant_id == plan.tenant_id
        and event.destination == "exfil.example"
    )
    evidence_valid = (
        verify_recovery_evidence(evidence)
        and evidence.incident_id == plan.incident_id
        and evidence.plan_digest == plan.plan_digest
        and evidence.candidate_digest == plan.candidate_digest
    )
    complete = (
        deployment.candidate_digest == plan.candidate_digest
        and deployment.canary_percent == 100
        and deployment.public_registry_enabled
        and not forbidden
        and evidence.complete
        and evidence_valid
    )
    return SafeServiceProof(
        plan.incident_id,
        plan.plan_digest,
        plan.candidate_digest,
        deployment.revision,
        len(forbidden),
        evidence_valid,
        complete,
    )


@dataclass(frozen=True)
class RecoveryMetrics:
    time_to_revoke_seconds: float
    time_to_safe_service_seconds: float
    residual_authority_rate: float
    security_regression_pass_rate: float
    safe_task_success_rate: float
    forbidden_effect_rate: float
    rto_met: bool


def calculate_metrics(
    case: RecoveryCase,
    revocation_proof: RevocationProof,
    evidence: RecoveryEvidence,
    *,
    contained_at: datetime,
    returned_at: datetime,
    objectives: RecoveryObjectives,
) -> RecoveryMetrics:
    if case.revocation_proven_at is None:
        raise ValueError("revocation proof time required")
    if not (
        evidence.security_regressions_total
        and evidence.safe_tasks_total
        and evidence.forbidden_attempts_total
        and revocation_proof.required_action_count
    ):
        raise ValueError("metric denominators must be non-zero")
    time_to_safe = (returned_at - contained_at).total_seconds()
    return RecoveryMetrics(
        (case.revocation_proven_at - case.accepted_at).total_seconds(),
        time_to_safe,
        revocation_proof.residual_authority_count
        / revocation_proof.required_action_count,
        evidence.security_regressions_passed
        / evidence.security_regressions_total,
        evidence.safe_tasks_succeeded / evidence.safe_tasks_total,
        evidence.forbidden_effects_completed / evidence.forbidden_attempts_total,
        time_to_safe <= objectives.rto_seconds,
    )


def make_otel_recovery_span(
    incident_id: str,
    candidate_digest: str,
) -> tuple[str, dict[str, Any]]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create({"service.name": "course-22-recovery"})
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("mcp-security-course-22")
    with tracer.start_as_current_span("incident.recovery") as span:
        span.set_attribute("incident.id", incident_id)
        span.set_attribute("recovery.candidate.digest", candidate_digest)
        span.set_attribute("recovery.policy.version", RECOVERY_POLICY_VERSION)
        span.set_attribute("recovery.outcome", "returned_to_service")
    finished = exporter.get_finished_spans()[0]
    return finished.name, dict(finished.attributes or {})


def build_valid_observations(
    plan: RecoveryPlan,
) -> RecoveryObservations:
    return RecoveryObservations(
        plan.candidate_digest,
        plan.candidate_digest,
        plan.config_digest,
        plan.policy_digest,
        plan.capability_contract_digest,
        8,
        8,
        20,
        20,
        5,
        0,
        0,
        ("workload.attestation", "protected.resource.audit", "gateway.probe"),
    )


def run_demo() -> dict[str, Any]:
    handoff = create_handoff()
    repository = RecoveryRepository()
    manager = RecoveryManager(repository)
    case = manager.accept_handoff(
        handoff,
        actor_id="coordinator-1",
        actor_roles=frozenset({"recovery_coordinator"}),
        allowed_tenants=frozenset({"acme"}),
        now=NOW + timedelta(seconds=1),
    )
    case = manager.add_model_hypothesis(
        case,
        proposed_by="assistant-model",
        text="rollback may be faster than a forward fix",
        evidence_ids=(handoff.evidence_package_digest,),
    )

    authority = AuthorityPlane(epoch=handoff.control_revision)
    revocation_plan = make_revocation_plan(
        handoff,
        current_epoch=authority.epoch,
        now=NOW + timedelta(seconds=2),
    )
    revocation_receipt = approve_revocation(
        revocation_plan,
        approver_id="commander-1",
        approver_role="incident_commander",
        now=NOW + timedelta(seconds=2),
    )
    revoker = RevocationCoordinator(authority)
    partial_revocation = revoker.execute(
        "revoke-operation-1",
        revocation_plan,
        revocation_receipt,
        case,
        now=NOW + timedelta(seconds=3),
        unavailable_kinds=frozenset({RevocationKind.INVALIDATE_CACHE}),
    )
    revocation_result = revoker.retry_missing(
        "revoke-operation-1",
        now=NOW + timedelta(seconds=4),
    )
    revocation_proof = prove_revocation(
        revocation_plan,
        revoker.authority,
        handoff,
        (),
        proof_time=NOW + timedelta(seconds=4),
    )
    case = manager.mark_revocation_proven(
        case,
        revocation_proof,
        now=NOW + timedelta(seconds=4),
        actor_roles=frozenset({"recovery_coordinator"}),
    )

    candidate = build_candidate(now=NOW)
    verifier = CandidateVerifier()
    candidate_verified, candidate_reasons = verifier.verify(
        candidate,
        required_remediation_ids=case.required_remediation_ids,
        current_schema_version="customer-schema-v4",
        now=NOW + timedelta(seconds=4),
    )
    decision = select_strategy(
        candidate,
        previous_digest=digest(b"support-v1-known-good"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    recovery_plan = make_recovery_plan(
        case,
        candidate,
        decision,
        verifier,
        revocation_proof,
        current_schema_version="customer-schema-v4",
        now=NOW + timedelta(seconds=5),
    )
    recovery_receipt = approve_recovery(
        recovery_plan,
        approver_id="commander-1",
        approver_role="recovery_commander",
        now=NOW + timedelta(seconds=5),
    )
    executor = RecoveryExecutor()
    first_stage = executor.stage(
        "stage-operation-1",
        recovery_plan,
        recovery_receipt,
        candidate,
        case,
        now=NOW + timedelta(seconds=6),
        simulate_lost_response=True,
    )
    staged = executor.stage(
        "stage-operation-1",
        recovery_plan,
        recovery_receipt,
        candidate,
        case,
        now=NOW + timedelta(seconds=7),
    )
    case = manager.mark_staged(case, recovery_plan, staged)

    observations = build_valid_observations(recovery_plan)
    evidence = validate_recovery(
        recovery_plan,
        executor.deployment,
        observations,
        now=NOW + timedelta(seconds=8),
    )
    case = manager.mark_validated(case, evidence)
    return_receipt = approve_return_to_service(
        recovery_plan,
        evidence,
        approver_id="service-owner-1",
        approver_role="service_owner",
        now=NOW + timedelta(seconds=9),
    )
    first_return = executor.promote(
        "return-operation-1",
        recovery_plan,
        return_receipt,
        evidence,
        case,
        now=NOW + timedelta(seconds=10),
        simulate_lost_response=True,
    )
    returned = executor.promote(
        "return-operation-1",
        recovery_plan,
        return_receipt,
        evidence,
        case,
        now=NOW + timedelta(seconds=11),
    )
    proof = prove_safe_service(
        recovery_plan,
        executor.deployment,
        evidence,
        (),
        returned_at=returned.occurred_at,
    )
    case = manager.mark_returned(
        case,
        proof,
        returned,
        now=NOW + timedelta(seconds=11),
    )
    metrics = calculate_metrics(
        case,
        revocation_proof,
        evidence,
        contained_at=handoff.contained_at,
        returned_at=returned.occurred_at,
        objectives=recovery_plan.objectives,
    )
    span_name, span_attributes = make_otel_recovery_span(
        case.incident_id,
        candidate.artifact_digest,
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "handoff": handoff,
        "case": case,
        "partial_revocation": partial_revocation,
        "revocation_result": revocation_result,
        "revocation_proof": revocation_proof,
        "candidate": candidate,
        "candidate_verified": candidate_verified,
        "candidate_reasons": candidate_reasons,
        "strategy": decision,
        "recovery_plan": recovery_plan,
        "first_stage": first_stage,
        "staged": staged,
        "observations": observations,
        "evidence": evidence,
        "first_return": first_return,
        "returned": returned,
        "safe_service_proof": proof,
        "metrics": metrics,
        "otel": {"span_name": span_name, "attributes": span_attributes},
    }


def main() -> None:
    result = run_demo()
    assert result["case"].state == RecoveryState.RETURNED_TO_SERVICE
    assert result["case"].hypotheses[0].accepted_as_fact is False
    assert result["partial_revocation"].status == OperationStatus.PARTIAL
    assert result["revocation_result"].status == OperationStatus.RECONCILED
    assert result["revocation_proof"].complete
    assert result["candidate_verified"]
    assert result["strategy"].strategy == RecoveryStrategy.FORWARD_FIX
    assert result["first_stage"].status == OperationStatus.UNKNOWN
    assert result["staged"].status == OperationStatus.RECONCILED
    assert result["evidence"].complete
    assert result["first_return"].status == OperationStatus.UNKNOWN
    assert result["returned"].status == OperationStatus.RECONCILED
    assert result["safe_service_proof"].complete
    assert result["metrics"].residual_authority_rate == 0.0
    assert result["metrics"].forbidden_effect_rate == 0.0
    print(
        "PASS: recovery converged revocation, verified a candidate, "
        "and proved safe return to service"
    )


if __name__ == "__main__":
    main()
