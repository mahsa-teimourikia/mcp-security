"""Course 13: a durable, evidence-bound CI/CD release controller.

The fixture is local and credential-free. It uses real Ed25519 verification,
strict contracts, optimistic concurrency, single-use approval, OIDC claim
validation, idempotent deployment operations, outcome reconciliation, health
verification, and an exact pre-approved rollback target.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator


UTC = timezone.utc
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
SHA_PATTERN = r"^[0-9a-f]{40}$"
ACTION_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use an explicit UTC offset")
    return parsed.astimezone(UTC)


def require_aware(*values: datetime) -> None:
    if any(value.tzinfo is None or value.utcoffset() is None for value in values):
        raise ValueError("security timestamps must be timezone-aware")


def canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    if isinstance(value, BaseModel):
        data = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    else:
        data = value
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(payload: bytes) -> str:
    return f"sha256:{sha256(payload).hexdigest()}"


def document_digest(value: BaseModel) -> str:
    return digest_bytes(canonical_json(value))


class PipelineDenied(PermissionError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class VersionConflict(RuntimeError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkflowStep(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    uses: str | None = Field(default=None, max_length=180)
    run: str | None = Field(default=None, max_length=2_000)
    env: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def exactly_one_execution_mode(self) -> "WorkflowStep":
        if (self.uses is None) == (self.run is None):
            raise ValueError("step must define exactly one of uses or run")
        return self


class JobContract(StrictModel):
    job_id: str = Field(min_length=1, max_length=100)
    phase: Literal["test", "build", "deploy"]
    trigger: Literal["pull_request", "push", "workflow_dispatch", "pull_request_target"]
    permissions: dict[str, Literal["none", "read", "write"]]
    environment: str | None = Field(default=None, max_length=100)
    secrets: tuple[str, ...] = ()
    requests_oidc: bool
    cache_write: bool
    ephemeral_runner: bool
    executes_checkout: bool
    checkout_ref: str = Field(min_length=1, max_length=200)
    steps: tuple[WorkflowStep, ...] = Field(min_length=1)


class WorkflowContract(StrictModel):
    workflow_path: str = Field(pattern=r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
    workflow_sha: str = Field(pattern=SHA_PATTERN)
    jobs: tuple[JobContract, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def unique_phases_and_jobs(self) -> "WorkflowContract":
        if len({job.job_id for job in self.jobs}) != len(self.jobs):
            raise ValueError("workflow job IDs must be unique")
        if {job.phase for job in self.jobs} != {"test", "build", "deploy"}:
            raise ValueError("workflow requires test, build, and deploy jobs")
        return self


class WorkflowPolicy(StrictModel):
    version: str
    repository: str
    repository_id: str
    owner_id: str
    protected_ref: Literal["refs/heads/main"]
    production_environment: Literal["production"]
    trusted_workflow_sha: str = Field(pattern=SHA_PATTERN)
    allowed_manual_actors: frozenset[str]
    allowed_approvers: frozenset[str]
    allowed_action_pins: frozenset[str]
    required_checks: frozenset[str]
    trusted_builder_id: str
    required_test_suite: str
    minimum_reviews: int = Field(ge=1, le=10)
    max_evidence_age: timedelta
    max_rollback_rehearsal_age: timedelta
    approval_ttl: timedelta
    credential_ttl: timedelta
    max_deploy_attempts: int = Field(ge=1, le=5)


class ReleaseRunContext(StrictModel):
    run_id: str
    repository: str
    repository_id: str
    owner_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    ref: str
    event: Literal["push", "workflow_dispatch"]
    actor: str
    source_repository: str
    source_repository_id: str
    workflow_path: str
    workflow_sha: str = Field(pattern=SHA_PATTERN)
    environment: Literal["production"]


class WorkflowAuditor:
    """Static workflow and runtime-context checks before privileged execution."""

    EXPECTED_PERMISSIONS = {
        "test": {"contents": "read"},
        "build": {
            "contents": "read",
            "id-token": "write",
            "attestations": "write",
            "packages": "write",
        },
        "deploy": {
            "contents": "read",
            "id-token": "write",
            "deployments": "write",
            "packages": "read",
        },
    }

    def __init__(self, policy: WorkflowPolicy) -> None:
        self.policy = policy

    def verify_contract(self, contract: WorkflowContract) -> str:
        if contract.workflow_sha != self.policy.trusted_workflow_sha:
            raise PipelineDenied(
                "WORKFLOW_NOT_REVIEWED", "workflow identity differs from trusted policy"
            )
        for job in contract.jobs:
            if job.permissions != self.EXPECTED_PERMISSIONS[job.phase]:
                raise PipelineDenied("TOKEN_PERMISSIONS_INVALID", f"{job.phase} permissions differ")
            if not job.ephemeral_runner:
                raise PipelineDenied("RUNNER_NOT_EPHEMERAL", "release runner must be ephemeral")
            if job.cache_write and job.phase in {"build", "deploy"}:
                raise PipelineDenied("PRIVILEGED_CACHE_WRITE", "privileged jobs cannot write shared cache")
            if job.phase == "test":
                if (
                    job.trigger != "pull_request"
                    or job.secrets
                    or job.requests_oidc
                    or not job.executes_checkout
                    or job.checkout_ref != "pull-request-merge-commit"
                ):
                    raise PipelineDenied("TEST_JOB_PRIVILEGED", "pull-request tests must be unprivileged")
            if job.phase == "build":
                if (
                    job.trigger != "push"
                    or job.environment is not None
                    or job.secrets
                    or not job.requests_oidc
                    or not job.executes_checkout
                    or job.checkout_ref != "refs/heads/main"
                ):
                    raise PipelineDenied("BUILD_JOB_BOUNDARY_INVALID", "build job boundary is invalid")
            if job.phase == "deploy":
                if job.trigger not in {"push", "workflow_dispatch"}:
                    raise PipelineDenied("DEPLOY_TRIGGER_INVALID", "deploy trigger is not trusted")
                if (
                    job.environment != self.policy.production_environment
                    or job.secrets
                    or not job.requests_oidc
                    or job.executes_checkout
                    or job.checkout_ref != "none"
                ):
                    raise PipelineDenied("DEPLOY_ENVIRONMENT_INVALID", "deploy must use protected environment and OIDC")
            for step in job.steps:
                if step.uses is not None:
                    if not ACTION_PATTERN.fullmatch(step.uses):
                        raise PipelineDenied("ACTION_NOT_IMMUTABLE", "action is not pinned to full commit SHA")
                    if step.uses not in self.policy.allowed_action_pins:
                        raise PipelineDenied("ACTION_NOT_ALLOWED", "action pin is not approved")
                if step.run is not None and "${{" in step.run:
                    raise PipelineDenied(
                        "SCRIPT_INJECTION_SURFACE",
                        "expressions must enter scripts through explicit environment variables",
                    )
        return digest_bytes(canonical_json(contract))

    def verify_run(self, context: ReleaseRunContext, contract: WorkflowContract) -> None:
        if (
            context.repository != self.policy.repository
            or context.repository_id != self.policy.repository_id
            or context.owner_id != self.policy.owner_id
        ):
            raise PipelineDenied("REPOSITORY_IDENTITY_MISMATCH", "repository identity differs")
        if (
            context.source_repository != context.repository
            or context.source_repository_id != context.repository_id
        ):
            raise PipelineDenied("UNTRUSTED_SOURCE_REPOSITORY", "release source is not the trusted repository")
        if context.ref != self.policy.protected_ref:
            raise PipelineDenied("UNPROTECTED_REF", "release must originate from protected main")
        if context.workflow_path != contract.workflow_path or context.workflow_sha != contract.workflow_sha:
            raise PipelineDenied("WORKFLOW_IDENTITY_MISMATCH", "runtime workflow differs from reviewed workflow")
        if context.environment != self.policy.production_environment:
            raise PipelineDenied("ENVIRONMENT_MISMATCH", "runtime environment differs")
        if context.event == "workflow_dispatch" and context.actor not in self.policy.allowed_manual_actors:
            raise PipelineDenied("MANUAL_ACTOR_NOT_ALLOWED", "manual release actor is not allowed")


class ProtectedRevisionEvidence(StrictModel):
    repository_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    ref: Literal["refs/heads/main"]
    review_count: int = Field(ge=0)
    checks: frozenset[str]
    branch_protected: bool
    admitted_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> "ProtectedRevisionEvidence":
        require_aware(self.admitted_at)
        return self


class BuildEvidence(StrictModel):
    run_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    artifact_name: str
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    builder_id: str
    built_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> "BuildEvidence":
        require_aware(self.built_at)
        return self


class TestEvidence(StrictModel):
    run_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    suite: str
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    report_digest: str = Field(pattern=SHA256_PATTERN)
    produced_at: datetime

    @model_validator(mode="after")
    def valid_test_report(self) -> "TestEvidence":
        require_aware(self.produced_at)
        if self.passed + self.failed + self.skipped == 0:
            raise ValueError("test report cannot have an empty population")
        return self


class SupplyChainDecision(StrictModel):
    run_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    provenance_digest: str = Field(pattern=SHA256_PATTERN)
    sbom_digest: str = Field(pattern=SHA256_PATTERN)
    scan_digest: str = Field(pattern=SHA256_PATTERN)
    verification_result: Literal["PASSED", "FAILED"]
    policy_version: str
    verified_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> "SupplyChainDecision":
        require_aware(self.verified_at)
        return self


class RollbackRehearsalEvidence(StrictModel):
    environment: Literal["production"]
    known_good_digest: str = Field(pattern=SHA256_PATTERN)
    rehearsal_id: str
    checks: frozenset[str]
    restored_seconds: int = Field(gt=0, le=3600)
    rehearsed_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> "RollbackRehearsalEvidence":
        require_aware(self.rehearsed_at)
        return self


class HealthEvidence(StrictModel):
    run_id: str
    operation_id: str
    environment: Literal["production"]
    expected_digest: str = Field(pattern=SHA256_PATTERN)
    observed_digest: str = Field(pattern=SHA256_PATTERN)
    checks: dict[str, bool]
    observed_at: datetime

    @model_validator(mode="after")
    def valid_observation(self) -> "HealthEvidence":
        require_aware(self.observed_at)
        if not self.checks:
            raise ValueError("health evidence requires named checks")
        return self


class EvidenceSignature(StrictModel):
    role: Literal["source", "builder", "tests", "security", "recovery", "health"]
    signer: str
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    signature: str


@dataclass(frozen=True)
class SignedEvidence:
    document: BaseModel
    signature: EvidenceSignature


class EvidenceTrustStore:
    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}
        self._revoked: set[tuple[str, str]] = set()

    def add(self, role: str, signer: str, key: Ed25519PublicKey) -> None:
        self._keys[(role, signer)] = key

    def revoke(self, role: str, signer: str) -> None:
        self._revoked.add((role, signer))

    def verify(self, signed: SignedEvidence, role: str, expected_type: type[BaseModel]) -> BaseModel:
        if not isinstance(signed.document, expected_type):
            raise PipelineDenied("EVIDENCE_SCHEMA_INVALID", "unexpected evidence document type")
        key_id = (role, signed.signature.signer)
        if signed.signature.role != role or key_id not in self._keys:
            raise PipelineDenied("EVIDENCE_SIGNER_NOT_TRUSTED", "evidence signer is not trusted")
        if key_id in self._revoked:
            raise PipelineDenied("EVIDENCE_SIGNER_REVOKED", "evidence signer is revoked")
        payload = canonical_json(signed.document)
        if digest_bytes(payload) != signed.signature.payload_digest:
            raise PipelineDenied("EVIDENCE_DIGEST_MISMATCH", "evidence payload digest differs")
        try:
            raw = base64.b64decode(signed.signature.signature, validate=True)
            self._keys[key_id].verify(raw, payload)
        except (ValueError, InvalidSignature) as exc:
            raise PipelineDenied("EVIDENCE_SIGNATURE_INVALID", "evidence signature is invalid") from exc
        return signed.document


class ReleasePlan(StrictModel):
    run_id: str
    source_sha: str = Field(pattern=SHA_PATTERN)
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    environment: Literal["production"]
    target: str
    previous_digest: str = Field(pattern=SHA256_PATTERN)
    workflow_contract_digest: str = Field(pattern=SHA256_PATTERN)
    source_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    build_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    test_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    security_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    rollback_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    policy_version: str


class ApprovalReceipt(StrictModel):
    receipt_id: str
    run_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    approver: str
    approver_role: Literal["release-approver"]
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid_window(self) -> "ApprovalReceipt":
        require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expiry must follow issuance")
        return self


@dataclass
class _StoredApproval:
    record: ApprovalReceipt
    state: Literal["issued", "consumed"] = "issued"


class ApprovalStore:
    def __init__(self, ttl: timedelta) -> None:
        self.ttl = ttl
        self._records: dict[str, _StoredApproval] = {}
        self._lock = threading.Lock()

    def issue(self, plan: ReleasePlan, approver: str, now: datetime) -> ApprovalReceipt:
        receipt = ApprovalReceipt(
            receipt_id=f"approval-{plan.run_id}-{plan.artifact_digest[7:19]}",
            run_id=plan.run_id,
            plan_digest=document_digest(plan),
            approver=approver,
            approver_role="release-approver",
            issued_at=now,
            expires_at=now + self.ttl,
        )
        with self._lock:
            if receipt.receipt_id in self._records:
                raise PipelineDenied("APPROVAL_ALREADY_EXISTS", "approval already exists")
            self._records[receipt.receipt_id] = _StoredApproval(receipt)
        return receipt

    def consume(self, receipt: ApprovalReceipt, plan: ReleasePlan, now: datetime) -> None:
        with self._lock:
            stored = self._records.get(receipt.receipt_id)
            if stored is None or stored.record != receipt:
                raise PipelineDenied("APPROVAL_NOT_FOUND", "approval is not trusted")
            if stored.state != "issued":
                raise PipelineDenied("APPROVAL_REPLAYED", "approval was already consumed")
            if now >= receipt.expires_at:
                raise PipelineDenied("APPROVAL_EXPIRED", "approval has expired")
            if receipt.plan_digest != document_digest(plan) or receipt.run_id != plan.run_id:
                raise PipelineDenied("APPROVAL_PLAN_MISMATCH", "approval binds another plan")
            stored.state = "consumed"


class OidcClaims(StrictModel):
    issuer: Literal["https://token.actions.githubusercontent.com"]
    audience: str
    subject: str
    repository_id: str
    owner_id: str
    workflow_path: str
    workflow_sha: str = Field(pattern=SHA_PATTERN)
    ref: str
    environment: Literal["production"]
    run_id: str
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid_window(self) -> "OidcClaims":
        require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("OIDC expiry must follow issuance")
        return self


class CloudCredential(StrictModel):
    credential_id: str
    run_id: str
    audience: str
    scope: tuple[str, ...]
    expires_at: datetime


class CredentialBroker:
    def __init__(self, policy: WorkflowPolicy) -> None:
        self.policy = policy

    def exchange(
        self,
        claims: OidcClaims,
        context: ReleaseRunContext,
        plan: ReleasePlan,
        now: datetime,
    ) -> CloudCredential:
        expected_subject = (
            f"repo:{self.policy.owner_id}/{self.policy.repository_id}:"
            f"environment:{self.policy.production_environment}"
        )
        if claims.audience != "deploy.example" or claims.subject != expected_subject:
            raise PipelineDenied("OIDC_SUBJECT_INVALID", "OIDC audience or subject differs")
        if (
            claims.repository_id != context.repository_id
            or claims.owner_id != context.owner_id
            or claims.workflow_path != context.workflow_path
            or claims.workflow_sha != context.workflow_sha
            or claims.ref != context.ref
            or claims.environment != plan.environment
            or claims.run_id != plan.run_id
        ):
            raise PipelineDenied("OIDC_CONTEXT_MISMATCH", "OIDC claims differ from release context")
        if claims.issued_at > now or now >= claims.expires_at:
            raise PipelineDenied("OIDC_TOKEN_EXPIRED", "OIDC token is outside its validity window")
        expiry = min(claims.expires_at, now + self.policy.credential_ttl)
        return CloudCredential(
            credential_id=f"cloud-{plan.run_id}-{plan.artifact_digest[7:15]}",
            run_id=plan.run_id,
            audience=claims.audience,
            scope=(f"deploy:{plan.environment}:{plan.target}",),
            expires_at=expiry,
        )


class RunState(StrEnum):
    SOURCE_ADMITTED = "source_admitted"
    BUILT = "built"
    TESTED = "tested"
    VERIFIED = "verified"
    APPROVED = "approved"
    DEPLOYING = "deploying"
    DEPLOY_RETRYABLE = "deploy_retryable"
    DEPLOYMENT_UNKNOWN = "deployment_unknown"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"


@dataclass
class RunRecord:
    run_id: str
    source_sha: str
    state: RunState
    version: int = 1
    artifact_digest: str | None = None
    source_evidence_digest: str | None = None
    build_evidence_digest: str | None = None
    test_evidence_digest: str | None = None
    plan: ReleasePlan | None = None
    operation_id: str | None = None
    deploy_attempts: int = 0
    terminal_reason: str | None = None


class RunStore:
    def __init__(self) -> None:
        self._records: dict[str, RunRecord] = {}
        self._lock = threading.Lock()

    def create(self, record: RunRecord) -> RunRecord:
        with self._lock:
            if record.run_id in self._records:
                raise PipelineDenied("RUN_ALREADY_EXISTS", "release run already exists")
            self._records[record.run_id] = copy.deepcopy(record)
            return copy.deepcopy(record)

    def get(self, run_id: str) -> RunRecord:
        with self._lock:
            if run_id not in self._records:
                raise PipelineDenied("RUN_NOT_FOUND", "release run does not exist")
            return copy.deepcopy(self._records[run_id])

    def transition(
        self,
        run_id: str,
        expected_version: int,
        allowed: set[RunState],
        new_state: RunState,
        **updates: Any,
    ) -> RunRecord:
        with self._lock:
            record = self._records.get(run_id)
            if record is None:
                raise PipelineDenied("RUN_NOT_FOUND", "release run does not exist")
            if record.version != expected_version:
                raise VersionConflict("run version changed; reload before transition")
            if record.state not in allowed:
                raise PipelineDenied("STAGE_ORDER_INVALID", "release stage is out of order")
            for key, value in updates.items():
                setattr(record, key, value)
            record.state = new_state
            record.version += 1
            return copy.deepcopy(record)


class DeployResult(StrEnum):
    SUCCESS = "success"
    TRANSIENT = "transient"
    UNKNOWN = "unknown"


class DeploymentTarget:
    """Idempotent environment API keyed by one stable logical operation ID."""

    def __init__(self, current_digest: str) -> None:
        self.current_digest = current_digest
        self._committed: dict[str, str] = {}
        self._lock = threading.Lock()

    def apply(self, operation_id: str, digest: str, outcome: DeployResult) -> DeployResult:
        with self._lock:
            prior = self._committed.get(operation_id)
            if prior is not None:
                if prior != digest:
                    raise PipelineDenied("IDEMPOTENCY_CONFLICT", "operation ID binds another digest")
                return DeployResult.SUCCESS
            if outcome == DeployResult.TRANSIENT:
                return outcome
            if outcome in {DeployResult.SUCCESS, DeployResult.UNKNOWN}:
                self._committed[operation_id] = digest
                self.current_digest = digest
            return outcome

    def status(self, operation_id: str) -> Literal["committed", "absent"]:
        with self._lock:
            return "committed" if operation_id in self._committed else "absent"


class AuditEvent(StrictModel):
    event: str
    run_id: str
    state: str
    decision: Literal["allow", "deny", "transition"]
    reason_code: str
    artifact_digest: str | None = None
    operation_id: str | None = None
    policy_version: str


class ReleaseController:
    def __init__(
        self,
        policy: WorkflowPolicy,
        auditor: WorkflowAuditor,
        trust: EvidenceTrustStore,
        approvals: ApprovalStore,
        credentials: CredentialBroker,
        store: RunStore,
        target: DeploymentTarget,
        context: ReleaseRunContext,
        contract: WorkflowContract,
    ) -> None:
        self.policy = policy
        self.auditor = auditor
        self.trust = trust
        self.approvals = approvals
        self.credentials = credentials
        self.store = store
        self.target = target
        self.context = context
        self.contract = contract
        self.contract_digest: str | None = None
        self.audit: list[AuditEvent] = []

    def _event(self, record: RunRecord, decision: str, code: str) -> None:
        self.audit.append(
            AuditEvent(
                event="release.pipeline",
                run_id=record.run_id,
                state=record.state,
                decision=decision,
                reason_code=code,
                artifact_digest=record.artifact_digest,
                operation_id=record.operation_id,
                policy_version=self.policy.version,
            )
        )

    def start(self, source: SignedEvidence, now: datetime) -> RunRecord:
        self.contract_digest = self.auditor.verify_contract(self.contract)
        self.auditor.verify_run(self.context, self.contract)
        document = self.trust.verify(source, "source", ProtectedRevisionEvidence)
        assert isinstance(document, ProtectedRevisionEvidence)
        if (
            document.repository_id != self.context.repository_id
            or document.source_sha != self.context.source_sha
            or document.ref != self.context.ref
            or not document.branch_protected
            or document.review_count < self.policy.minimum_reviews
            or document.checks != self.policy.required_checks
        ):
            raise PipelineDenied("SOURCE_ADMISSION_FAILED", "protected revision evidence differs")
        if document.admitted_at > now or now - document.admitted_at > self.policy.max_evidence_age:
            raise PipelineDenied("SOURCE_EVIDENCE_STALE", "source admission evidence is stale")
        record = self.store.create(
            RunRecord(
                self.context.run_id,
                self.context.source_sha,
                RunState.SOURCE_ADMITTED,
                source_evidence_digest=document_digest(document),
            )
        )
        self._event(record, "transition", "SOURCE_ADMITTED")
        return record

    def record_build(
        self,
        expected_version: int,
        artifact_bytes: bytes,
        signed: SignedEvidence,
        now: datetime,
    ) -> RunRecord:
        document = self.trust.verify(signed, "builder", BuildEvidence)
        assert isinstance(document, BuildEvidence)
        if (
            document.run_id != self.context.run_id
            or document.source_sha != self.context.source_sha
            or document.artifact_digest != digest_bytes(artifact_bytes)
            or document.builder_id != self.policy.trusted_builder_id
        ):
            raise PipelineDenied("BUILD_EVIDENCE_MISMATCH", "build evidence differs from bytes or run")
        if document.built_at > now or now - document.built_at > self.policy.max_evidence_age:
            raise PipelineDenied("BUILD_EVIDENCE_STALE", "build evidence is stale")
        record = self.store.transition(
            self.context.run_id,
            expected_version,
            {RunState.SOURCE_ADMITTED},
            RunState.BUILT,
            artifact_digest=document.artifact_digest,
            build_evidence_digest=document_digest(document),
        )
        self._event(record, "transition", "ARTIFACT_BUILT")
        return record

    def record_tests(self, expected_version: int, signed: SignedEvidence, now: datetime) -> RunRecord:
        current = self.store.get(self.context.run_id)
        document = self.trust.verify(signed, "tests", TestEvidence)
        assert isinstance(document, TestEvidence)
        if (
            document.run_id != current.run_id
            or document.source_sha != current.source_sha
            or document.artifact_digest != current.artifact_digest
            or document.suite != self.policy.required_test_suite
        ):
            raise PipelineDenied("TEST_EVIDENCE_MISMATCH", "test evidence names another subject")
        if document.failed or document.passed == 0:
            raise PipelineDenied("TESTS_FAILED", "release tests did not pass")
        if document.produced_at > now or now - document.produced_at > self.policy.max_evidence_age:
            raise PipelineDenied("TEST_EVIDENCE_STALE", "test evidence is stale")
        record = self.store.transition(
            current.run_id,
            expected_version,
            {RunState.BUILT},
            RunState.TESTED,
            test_evidence_digest=document_digest(document),
        )
        self._event(record, "transition", "TESTS_PASSED")
        return record

    def verify_release(
        self,
        expected_version: int,
        source: SignedEvidence,
        build: SignedEvidence,
        tests: SignedEvidence,
        security: SignedEvidence,
        rollback: SignedEvidence,
        now: datetime,
    ) -> RunRecord:
        current = self.store.get(self.context.run_id)
        source_doc = self.trust.verify(source, "source", ProtectedRevisionEvidence)
        build_doc = self.trust.verify(build, "builder", BuildEvidence)
        test_doc = self.trust.verify(tests, "tests", TestEvidence)
        security_doc = self.trust.verify(security, "security", SupplyChainDecision)
        rollback_doc = self.trust.verify(rollback, "recovery", RollbackRehearsalEvidence)
        assert isinstance(source_doc, ProtectedRevisionEvidence)
        assert isinstance(build_doc, BuildEvidence)
        assert isinstance(test_doc, TestEvidence)
        assert isinstance(security_doc, SupplyChainDecision)
        assert isinstance(rollback_doc, RollbackRehearsalEvidence)
        if any(
            value != current.run_id
            for value in (build_doc.run_id, test_doc.run_id, security_doc.run_id)
        ):
            raise PipelineDenied("EVIDENCE_RUN_MISMATCH", "evidence names another run")
        if any(
            value != current.source_sha
            for value in (source_doc.source_sha, build_doc.source_sha, test_doc.source_sha, security_doc.source_sha)
        ):
            raise PipelineDenied("EVIDENCE_SOURCE_MISMATCH", "evidence names another source revision")
        if any(
            value != current.artifact_digest
            for value in (build_doc.artifact_digest, test_doc.artifact_digest, security_doc.artifact_digest)
        ):
            raise PipelineDenied("EVIDENCE_ARTIFACT_MISMATCH", "evidence names another artifact")
        if (
            document_digest(source_doc) != current.source_evidence_digest
            or document_digest(build_doc) != current.build_evidence_digest
            or document_digest(test_doc) != current.test_evidence_digest
        ):
            raise PipelineDenied(
                "EVIDENCE_CHAIN_MISMATCH", "release evidence differs from admitted stage evidence"
            )
        if security_doc.verification_result != "PASSED" or security_doc.policy_version != self.policy.version:
            raise PipelineDenied("SECURITY_GATE_FAILED", "supply-chain policy did not pass")
        evidence_times = (
            source_doc.admitted_at,
            build_doc.built_at,
            test_doc.produced_at,
            security_doc.verified_at,
        )
        if any(value > now or now - value > self.policy.max_evidence_age for value in evidence_times):
            raise PipelineDenied("RELEASE_EVIDENCE_STALE", "release evidence is stale")
        if (
            rollback_doc.environment != self.context.environment
            or rollback_doc.known_good_digest != self.target.current_digest
            or rollback_doc.checks != frozenset({"service-ready", "tool-smoke", "authz-smoke"})
            or rollback_doc.rehearsed_at > now
            or now - rollback_doc.rehearsed_at > self.policy.max_rollback_rehearsal_age
        ):
            raise PipelineDenied("ROLLBACK_NOT_READY", "rollback evidence is not acceptable")
        assert self.contract_digest is not None
        plan = ReleasePlan(
            run_id=current.run_id,
            source_sha=current.source_sha,
            artifact_digest=current.artifact_digest or "",
            environment=self.context.environment,
            target="mcp-prod/support",
            previous_digest=rollback_doc.known_good_digest,
            workflow_contract_digest=self.contract_digest,
            source_evidence_digest=current.source_evidence_digest or "",
            build_evidence_digest=current.build_evidence_digest or "",
            test_evidence_digest=current.test_evidence_digest or "",
            security_evidence_digest=document_digest(security_doc),
            rollback_evidence_digest=document_digest(rollback_doc),
            policy_version=self.policy.version,
        )
        record = self.store.transition(
            current.run_id, expected_version, {RunState.TESTED}, RunState.VERIFIED, plan=plan
        )
        self._event(record, "transition", "RELEASE_EVIDENCE_VERIFIED")
        return record

    def approve(self, expected_version: int, approver: str, now: datetime) -> tuple[RunRecord, ApprovalReceipt]:
        current = self.store.get(self.context.run_id)
        if current.plan is None:
            raise PipelineDenied("PLAN_MISSING", "verified release plan is missing")
        if approver not in self.policy.allowed_approvers or approver == self.context.actor:
            raise PipelineDenied(
                "APPROVER_NOT_ELIGIBLE", "approver is not eligible or lacks separation of duties"
            )
        receipt = self.approvals.issue(current.plan, approver, now)
        record = self.store.transition(
            current.run_id, expected_version, {RunState.VERIFIED}, RunState.APPROVED
        )
        self._event(record, "transition", "RELEASE_APPROVED")
        return record, receipt

    def deploy(
        self,
        expected_version: int,
        receipt: ApprovalReceipt,
        claims: OidcClaims,
        outcome: DeployResult,
        now: datetime,
    ) -> RunRecord:
        current = self.store.get(self.context.run_id)
        if current.plan is None:
            raise PipelineDenied("PLAN_MISSING", "approved release plan is missing")
        if current.version != expected_version:
            raise VersionConflict("run version changed; reload before deployment")
        if current.state != RunState.APPROVED:
            raise PipelineDenied("STAGE_ORDER_INVALID", "release is not approved")
        self.credentials.exchange(claims, self.context, current.plan, now)
        self.approvals.consume(receipt, current.plan, now)
        operation_id = f"deploy:{current.run_id}:{current.plan.artifact_digest[7:19]}"
        deploying = self.store.transition(
            current.run_id,
            expected_version,
            {RunState.APPROVED},
            RunState.DEPLOYING,
            operation_id=operation_id,
            deploy_attempts=1,
        )
        result = self.target.apply(operation_id, current.plan.artifact_digest, outcome)
        state = {
            DeployResult.SUCCESS: RunState.VERIFYING,
            DeployResult.TRANSIENT: RunState.DEPLOY_RETRYABLE,
            DeployResult.UNKNOWN: RunState.DEPLOYMENT_UNKNOWN,
        }[result]
        record = self.store.transition(
            current.run_id, deploying.version, {RunState.DEPLOYING}, state
        )
        self._event(record, "transition", f"DEPLOY_{result.upper()}")
        return record

    def retry_deploy(
        self, expected_version: int, outcome: DeployResult
    ) -> RunRecord:
        current = self.store.get(self.context.run_id)
        if current.plan is None or current.operation_id is None:
            raise PipelineDenied("DEPLOYMENT_CONTEXT_MISSING", "deployment context is missing")
        if current.deploy_attempts >= self.policy.max_deploy_attempts:
            raise PipelineDenied("DEPLOY_RETRY_BUDGET_EXHAUSTED", "deployment retry budget exhausted")
        deploying = self.store.transition(
            current.run_id,
            expected_version,
            {RunState.DEPLOY_RETRYABLE},
            RunState.DEPLOYING,
            deploy_attempts=current.deploy_attempts + 1,
        )
        result = self.target.apply(current.operation_id, current.plan.artifact_digest, outcome)
        state = {
            DeployResult.SUCCESS: RunState.VERIFYING,
            DeployResult.TRANSIENT: RunState.DEPLOY_RETRYABLE,
            DeployResult.UNKNOWN: RunState.DEPLOYMENT_UNKNOWN,
        }[result]
        record = self.store.transition(
            current.run_id, deploying.version, {RunState.DEPLOYING}, state
        )
        self._event(record, "transition", f"DEPLOY_RETRY_{result.upper()}")
        return record

    def reconcile(self, expected_version: int) -> RunRecord:
        current = self.store.get(self.context.run_id)
        if current.operation_id is None:
            raise PipelineDenied("DEPLOYMENT_CONTEXT_MISSING", "operation ID is missing")
        status = self.target.status(current.operation_id)
        next_state = RunState.VERIFYING if status == "committed" else RunState.DEPLOY_RETRYABLE
        record = self.store.transition(
            current.run_id,
            expected_version,
            {RunState.DEPLOYMENT_UNKNOWN},
            next_state,
        )
        self._event(record, "transition", f"RECONCILED_{status.upper()}")
        return record

    def verify_health(
        self,
        expected_version: int,
        signed: SignedEvidence,
        now: datetime,
        rollback_outcome: DeployResult = DeployResult.SUCCESS,
    ) -> RunRecord:
        current = self.store.get(self.context.run_id)
        if current.plan is None or current.operation_id is None:
            raise PipelineDenied("DEPLOYMENT_CONTEXT_MISSING", "release plan or operation is missing")
        health = self.trust.verify(signed, "health", HealthEvidence)
        assert isinstance(health, HealthEvidence)
        if (
            health.run_id != current.run_id
            or health.operation_id != current.operation_id
            or health.environment != current.plan.environment
            or health.expected_digest != current.plan.artifact_digest
        ):
            raise PipelineDenied("HEALTH_EVIDENCE_MISMATCH", "health evidence names another deployment")
        if health.observed_at > now or now - health.observed_at > self.policy.max_evidence_age:
            raise PipelineDenied("HEALTH_EVIDENCE_STALE", "health evidence is outside freshness policy")
        healthy = (
            health.observed_digest == current.plan.artifact_digest
            and self.target.current_digest == current.plan.artifact_digest
            and all(health.checks.values())
        )
        if healthy:
            record = self.store.transition(
                current.run_id, expected_version, {RunState.VERIFYING}, RunState.SUCCEEDED
            )
            self._event(record, "transition", "DEPLOYMENT_VERIFIED")
            return record
        rollback_operation = f"rollback:{current.run_id}:{current.plan.previous_digest[7:19]}"
        result = self.target.apply(
            rollback_operation, current.plan.previous_digest, rollback_outcome
        )
        if result != DeployResult.SUCCESS or self.target.current_digest != current.plan.previous_digest:
            raise PipelineDenied("ROLLBACK_FAILED", "rollback did not restore known-good digest")
        record = self.store.transition(
            current.run_id,
            expected_version,
            {RunState.VERIFYING},
            RunState.ROLLED_BACK,
            terminal_reason="HEALTH_CHECK_FAILED",
        )
        self._event(record, "transition", "ROLLBACK_VERIFIED")
        return record


SOURCE_SIGNER = "github-source-control"
BUILDER_SIGNER = "hosted-builder"
TEST_SIGNER = "test-service"
SECURITY_SIGNER = "supply-chain-verifier"
RECOVERY_SIGNER = "recovery-service"
HEALTH_SIGNER = "production-observer"
SOURCE_SHA = "a" * 40
WORKFLOW_SHA = "b" * 40
ARTIFACT_BYTES = b"support-mcp-release:2.0.0\n"
ARTIFACT_DIGEST = digest_bytes(ARTIFACT_BYTES)
KNOWN_GOOD_DIGEST = f"sha256:{'c' * 64}"
ACTION_PINS = frozenset(
    {
        f"actions/checkout@{'1' * 40}",
        f"actions/setup-python@{'2' * 40}",
        f"actions/attest@{'3' * 40}",
        f"example/cloud-login@{'4' * 40}",
    }
)


def _private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def sign_evidence(
    document: BaseModel,
    role: Literal["source", "builder", "tests", "security", "recovery", "health"],
    signer: str,
    key: Ed25519PrivateKey,
) -> SignedEvidence:
    payload = canonical_json(document)
    signature = EvidenceSignature(
        role=role,
        signer=signer,
        payload_digest=digest_bytes(payload),
        signature=base64.b64encode(key.sign(payload)).decode(),
    )
    return SignedEvidence(document, signature)


def default_contract() -> WorkflowContract:
    checkout = f"actions/checkout@{'1' * 40}"
    setup = f"actions/setup-python@{'2' * 40}"
    attest = f"actions/attest@{'3' * 40}"
    login = f"example/cloud-login@{'4' * 40}"
    return WorkflowContract(
        workflow_path=".github/workflows/release.yml",
        workflow_sha=WORKFLOW_SHA,
        jobs=(
            JobContract(
                job_id="test",
                phase="test",
                trigger="pull_request",
                permissions={"contents": "read"},
                requests_oidc=False,
                cache_write=False,
                ephemeral_runner=True,
                executes_checkout=True,
                checkout_ref="pull-request-merge-commit",
                steps=(
                    WorkflowStep(name="checkout", uses=checkout),
                    WorkflowStep(name="setup", uses=setup),
                    WorkflowStep(
                        name="test",
                        run="set -euo pipefail\npython -m pytest -q",
                        env={"PR_TITLE": "${{ github.event.pull_request.title }}"},
                    ),
                ),
            ),
            JobContract(
                job_id="build",
                phase="build",
                trigger="push",
                permissions={
                    "contents": "read",
                    "id-token": "write",
                    "attestations": "write",
                    "packages": "write",
                },
                requests_oidc=True,
                cache_write=False,
                ephemeral_runner=True,
                executes_checkout=True,
                checkout_ref="refs/heads/main",
                steps=(
                    WorkflowStep(name="checkout", uses=checkout),
                    WorkflowStep(name="build", run="set -euo pipefail\npython -m build"),
                    WorkflowStep(name="attest", uses=attest),
                ),
            ),
            JobContract(
                job_id="deploy",
                phase="deploy",
                trigger="push",
                permissions={
                    "contents": "read",
                    "id-token": "write",
                    "deployments": "write",
                    "packages": "read",
                },
                environment="production",
                requests_oidc=True,
                cache_write=False,
                ephemeral_runner=True,
                executes_checkout=False,
                checkout_ref="none",
                steps=(
                    WorkflowStep(name="login", uses=login),
                    WorkflowStep(name="deploy", run="set -euo pipefail\n./trusted-deployer"),
                ),
            ),
        ),
    )


@dataclass(frozen=True)
class DemoEnvironment:
    now: datetime
    policy: WorkflowPolicy
    context: ReleaseRunContext
    contract: WorkflowContract
    controller: ReleaseController
    target: DeploymentTarget
    keys: dict[str, Ed25519PrivateKey]
    source: SignedEvidence
    build: SignedEvidence
    tests: SignedEvidence
    security: SignedEvidence
    rollback: SignedEvidence


def build_demo_environment() -> DemoEnvironment:
    now = utc("2026-09-29T03:00:00Z")
    policy = WorkflowPolicy(
        version="release-policy/2026-09-01",
        repository="acme/support-mcp",
        repository_id="repo-4201",
        owner_id="org-17",
        protected_ref="refs/heads/main",
        production_environment="production",
        trusted_workflow_sha=WORKFLOW_SHA,
        allowed_manual_actors=frozenset({"release-manager@example.com"}),
        allowed_approvers=frozenset({"approver@example.com", "security-reviewer@example.com"}),
        allowed_action_pins=ACTION_PINS,
        required_checks=frozenset({"unit", "integration", "contract", "security"}),
        trusted_builder_id="github-hosted/ubuntu-24.04",
        required_test_suite="mcp-release-suite/v3",
        minimum_reviews=2,
        max_evidence_age=timedelta(hours=24),
        max_rollback_rehearsal_age=timedelta(days=30),
        approval_ttl=timedelta(minutes=15),
        credential_ttl=timedelta(minutes=10),
        max_deploy_attempts=2,
    )
    context = ReleaseRunContext(
        run_id="run-2026-09-29-001",
        repository=policy.repository,
        repository_id=policy.repository_id,
        owner_id=policy.owner_id,
        source_sha=SOURCE_SHA,
        ref=policy.protected_ref,
        event="push",
        actor="github-actions",
        source_repository=policy.repository,
        source_repository_id=policy.repository_id,
        workflow_path=".github/workflows/release.yml",
        workflow_sha=WORKFLOW_SHA,
        environment="production",
    )
    keys = {
        SOURCE_SIGNER: _private_key("source"),
        BUILDER_SIGNER: _private_key("builder"),
        TEST_SIGNER: _private_key("tests"),
        SECURITY_SIGNER: _private_key("security"),
        RECOVERY_SIGNER: _private_key("recovery"),
        HEALTH_SIGNER: _private_key("health"),
    }
    trust = EvidenceTrustStore()
    for role, signer in (
        ("source", SOURCE_SIGNER),
        ("builder", BUILDER_SIGNER),
        ("tests", TEST_SIGNER),
        ("security", SECURITY_SIGNER),
        ("recovery", RECOVERY_SIGNER),
        ("health", HEALTH_SIGNER),
    ):
        trust.add(role, signer, keys[signer].public_key())
    source_doc = ProtectedRevisionEvidence(
        repository_id=policy.repository_id,
        source_sha=SOURCE_SHA,
        ref="refs/heads/main",
        review_count=2,
        checks=policy.required_checks,
        branch_protected=True,
        admitted_at=now - timedelta(minutes=40),
    )
    build_doc = BuildEvidence(
        run_id=context.run_id,
        source_sha=SOURCE_SHA,
        artifact_name="support-mcp.tar",
        artifact_digest=ARTIFACT_DIGEST,
        builder_id="github-hosted/ubuntu-24.04",
        built_at=now - timedelta(minutes=30),
    )
    tests_doc = TestEvidence(
        run_id=context.run_id,
        source_sha=SOURCE_SHA,
        artifact_digest=ARTIFACT_DIGEST,
        suite="mcp-release-suite/v3",
        passed=378,
        failed=0,
        skipped=0,
        report_digest=f"sha256:{'d' * 64}",
        produced_at=now - timedelta(minutes=25),
    )
    security_doc = SupplyChainDecision(
        run_id=context.run_id,
        source_sha=SOURCE_SHA,
        artifact_digest=ARTIFACT_DIGEST,
        provenance_digest=f"sha256:{'e' * 64}",
        sbom_digest=f"sha256:{'f' * 64}",
        scan_digest=f"sha256:{'1' * 64}",
        verification_result="PASSED",
        policy_version=policy.version,
        verified_at=now - timedelta(minutes=20),
    )
    rollback_doc = RollbackRehearsalEvidence(
        environment="production",
        known_good_digest=KNOWN_GOOD_DIGEST,
        rehearsal_id="rollback-drill-2026-09-15",
        checks=frozenset({"service-ready", "tool-smoke", "authz-smoke"}),
        restored_seconds=94,
        rehearsed_at=now - timedelta(days=14),
    )
    source = sign_evidence(source_doc, "source", SOURCE_SIGNER, keys[SOURCE_SIGNER])
    build = sign_evidence(build_doc, "builder", BUILDER_SIGNER, keys[BUILDER_SIGNER])
    tests = sign_evidence(tests_doc, "tests", TEST_SIGNER, keys[TEST_SIGNER])
    security = sign_evidence(
        security_doc, "security", SECURITY_SIGNER, keys[SECURITY_SIGNER]
    )
    rollback = sign_evidence(
        rollback_doc, "recovery", RECOVERY_SIGNER, keys[RECOVERY_SIGNER]
    )
    contract = default_contract()
    target = DeploymentTarget(KNOWN_GOOD_DIGEST)
    approvals = ApprovalStore(policy.approval_ttl)
    controller = ReleaseController(
        policy,
        WorkflowAuditor(policy),
        trust,
        approvals,
        CredentialBroker(policy),
        RunStore(),
        target,
        context,
        contract,
    )
    return DemoEnvironment(
        now,
        policy,
        context,
        contract,
        controller,
        target,
        keys,
        source,
        build,
        tests,
        security,
        rollback,
    )


def oidc_claims(env: DemoEnvironment) -> OidcClaims:
    return OidcClaims(
        issuer="https://token.actions.githubusercontent.com",
        audience="deploy.example",
        subject=f"repo:{env.policy.owner_id}/{env.policy.repository_id}:environment:production",
        repository_id=env.context.repository_id,
        owner_id=env.context.owner_id,
        workflow_path=env.context.workflow_path,
        workflow_sha=env.context.workflow_sha,
        ref=env.context.ref,
        environment="production",
        run_id=env.context.run_id,
        issued_at=env.now - timedelta(minutes=1),
        expires_at=env.now + timedelta(minutes=5),
    )


def health_evidence(
    env: DemoEnvironment,
    record: RunRecord,
    *,
    observed_digest: str | None = None,
    checks: dict[str, bool] | None = None,
) -> SignedEvidence:
    assert record.plan is not None and record.operation_id is not None
    document = HealthEvidence(
        run_id=record.run_id,
        operation_id=record.operation_id,
        environment="production",
        expected_digest=record.plan.artifact_digest,
        observed_digest=observed_digest or record.plan.artifact_digest,
        checks=checks or {"service-ready": True, "tool-smoke": True, "authz-smoke": True},
        observed_at=env.now + timedelta(minutes=2),
    )
    return sign_evidence(document, "health", HEALTH_SIGNER, env.keys[HEALTH_SIGNER])


def advance_to_verified(env: DemoEnvironment) -> RunRecord:
    record = env.controller.start(env.source, env.now)
    record = env.controller.record_build(record.version, ARTIFACT_BYTES, env.build, env.now)
    record = env.controller.record_tests(record.version, env.tests, env.now)
    return env.controller.verify_release(
        record.version,
        env.source,
        env.build,
        env.tests,
        env.security,
        env.rollback,
        env.now,
    )


def run_demo() -> dict[str, str]:
    env = build_demo_environment()
    record = advance_to_verified(env)
    record, approval = env.controller.approve(record.version, "approver@example.com", env.now)
    record = env.controller.deploy(
        record.version, approval, oidc_claims(env), DeployResult.UNKNOWN, env.now
    )
    unknown_state = record.state
    record = env.controller.reconcile(record.version)
    record = env.controller.verify_health(
        record.version, health_evidence(env, record), env.now + timedelta(minutes=2)
    )

    rollback_env = build_demo_environment()
    rollback_record = advance_to_verified(rollback_env)
    rollback_record, rollback_approval = rollback_env.controller.approve(
        rollback_record.version, "approver@example.com", rollback_env.now
    )
    rollback_record = rollback_env.controller.deploy(
        rollback_record.version,
        rollback_approval,
        oidc_claims(rollback_env),
        DeployResult.SUCCESS,
        rollback_env.now,
    )
    failing_health = health_evidence(
        rollback_env,
        rollback_record,
        checks={"service-ready": True, "tool-smoke": False, "authz-smoke": True},
    )
    rollback_record = rollback_env.controller.verify_health(
        rollback_record.version,
        failing_health,
        rollback_env.now + timedelta(minutes=2),
    )
    return {
        "unknown_outcome": unknown_state,
        "reconciled_release": record.state,
        "failed_health": rollback_record.state,
        "restored_digest": rollback_env.target.current_digest,
    }


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
