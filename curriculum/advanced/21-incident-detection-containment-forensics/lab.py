"""Course 21: MCP incident detection, containment, and forensics.

This credential-free lab models a durable incident workflow. Signed source
events are admitted into a restricted evidence store, deterministic rules
produce evidence-backed findings, authorized analysts declare and scope a case,
an exact single-use receipt gates containment, and an integrity-protected
forensic package supports investigation. Model text may propose a hypothesis;
it cannot admit evidence, authorize containment, or resolve an incident.
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

import networkx as nx
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


UTC = timezone.utc
NOW = datetime(2026, 10, 30, 16, 0, tzinfo=UTC)
SCHEMA_VERSION = "mcp.incident.event/1.0"
POLICY_VERSION = "mcp-incident-response/2026-10-30"
PROTOCOL_VERSION = "2026-07-28"
MAX_INGESTION_DELAY = timedelta(minutes=10)
MAX_CLOCK_SKEW = timedelta(seconds=5)
EVENT_KEYS = {
    "registry.sensor": b"course-21-registry-sensor-key",
    "mcp.gateway": b"course-21-gateway-key",
    "network.sensor": b"course-21-network-sensor-key",
    "resource.audit": b"course-21-resource-audit-key",
    "control.audit": b"course-21-control-audit-key",
}
PACKAGE_KEY = b"course-21-forensic-package-key"
APPROVAL_KEY = b"course-21-containment-approval-key"
PSEUDONYM_KEY = b"course-21-pseudonym-key"
APPROVER_ROLES = frozenset({"incident_commander", "security_duty_manager"})
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,159}$")


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return parsed.astimezone(UTC)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return str(value)
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


def pseudonym(value: str) -> str:
    return "hmac-sha256:" + hmac.new(PSEUDONYM_KEY, value.encode(), sha256).hexdigest()


class EventKind(StrEnum):
    REGISTRY = "registry"
    MCP_CALL = "mcp_call"
    POLICY = "policy"
    NETWORK = "network"
    RESOURCE = "resource"
    CONTROL = "control"


class Outcome(StrEnum):
    OBSERVED = "observed"
    ALLOWED = "allowed"
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IngestStatus(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class CaseState(StrEnum):
    OPEN = "open"
    DECLARED = "declared"
    CONTAINMENT_PENDING = "containment_pending"
    CONTAINED = "contained"
    INVESTIGATING = "investigating"
    RECOVERY_HANDOFF = "recovery_handoff"
    CLOSED = "closed"


class FindingKind(StrEnum):
    ARTIFACT_DRIFT = "artifact_drift"
    UNEXPECTED_EGRESS = "unexpected_egress"
    CROSS_TENANT_EFFECT = "cross_tenant_effect"
    DENY_EFFECT_MISMATCH = "deny_effect_mismatch"
    CORRELATED_INTRUSION = "correlated_intrusion"


class ActionKind(StrEnum):
    DISABLE_BINDING = "disable_binding"
    QUARANTINE_WORKLOAD = "quarantine_workload"
    REVOKE_CREDENTIAL = "revoke_credential"
    TERMINATE_SESSION = "terminate_session"
    BLOCK_EGRESS = "block_egress"


class ExecutionStatus(StrEnum):
    APPLIED = "applied"
    RECONCILED = "reconciled"
    UNKNOWN = "unknown"
    DENIED = "denied"


@dataclass(frozen=True)
class EventTemplate:
    event_id: str
    occurred_at: datetime
    observed_at: datetime
    tenant_id: str
    resource_tenant: str
    principal_id: str
    server_id: str
    artifact_digest: str
    workload_id: str
    trace_id: str
    operation_id: str
    session_id: str
    credential_id: str
    kind: EventKind
    action: str
    resource: str
    destination: str
    policy_decision: str
    outcome: Outcome
    source_locator: str


@dataclass(frozen=True)
class SecurityEvent:
    schema_version: str
    event_id: str
    emitter_id: str
    sequence: int
    occurred_at: datetime
    observed_at: datetime
    tenant_id: str
    resource_tenant: str
    principal_id: str
    server_id: str
    artifact_digest: str
    workload_id: str
    trace_id: str
    operation_id: str
    session_id: str
    credential_id: str
    kind: EventKind
    action: str
    resource: str
    destination: str
    policy_decision: str
    outcome: Outcome
    source_locator: str
    previous_hash: str
    event_hash: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("event_hash")
        result.pop("signature")
        return result


class EventEmitter:
    """Trusted source adapter that signs a complete per-emitter hash chain."""

    def __init__(self, emitter_id: str, signing_key: bytes) -> None:
        if not SAFE_ID.fullmatch(emitter_id):
            raise ValueError("invalid emitter identity")
        self.emitter_id = emitter_id
        self.signing_key = signing_key
        self.sequence = 0
        self.previous_hash = ""

    def emit(self, template: EventTemplate) -> SecurityEvent:
        self.sequence += 1
        unsigned = {
            "schema_version": SCHEMA_VERSION,
            "event_id": template.event_id,
            "emitter_id": self.emitter_id,
            "sequence": self.sequence,
            **asdict(template),
            "previous_hash": self.previous_hash,
        }
        event_hash = digest(unsigned)
        signature = hmac.new(self.signing_key, event_hash.encode(), sha256).hexdigest()
        event = SecurityEvent(**unsigned, event_hash=event_hash, signature=signature)
        self.previous_hash = event_hash
        return event


@dataclass(frozen=True)
class IngestResult:
    status: IngestStatus
    reason_code: str
    event_id: str


class EvidenceStore:
    """Restricted source-of-truth store; authorization precedes retrieval."""

    def __init__(
        self,
        *,
        signing_keys: dict[str, bytes] | None = None,
        emitter_tenants: dict[str, frozenset[str]] | None = None,
    ) -> None:
        self.signing_keys = dict(signing_keys or EVENT_KEYS)
        self.emitter_tenants = emitter_tenants or {
            emitter: frozenset({"acme", "beta"}) for emitter in self.signing_keys
        }
        self.events: dict[str, SecurityEvent] = {}
        self.rejections: list[IngestResult] = []
        self.last_by_emitter: dict[str, tuple[int, str]] = {}

    @staticmethod
    def _valid_identifier(value: str, *, optional: bool = False) -> bool:
        return (optional and value == "") or SAFE_ID.fullmatch(value) is not None

    def _schema_error(self, event: SecurityEvent) -> str | None:
        if event.schema_version != SCHEMA_VERSION:
            return "SCHEMA_VERSION_UNSUPPORTED"
        if not self._valid_identifier(event.event_id) or not self._valid_identifier(event.emitter_id):
            return "IDENTIFIER_INVALID"
        if event.sequence < 1 or not TRACE_ID.fullmatch(event.trace_id):
            return "SEQUENCE_OR_TRACE_INVALID"
        if not DIGEST.fullmatch(event.artifact_digest):
            return "ARTIFACT_DIGEST_INVALID"
        for value in (
            event.tenant_id,
            event.resource_tenant,
            event.principal_id,
            event.server_id,
            event.workload_id,
            event.operation_id,
            event.session_id,
            event.credential_id,
            event.action,
            event.resource,
            event.source_locator,
        ):
            if not self._valid_identifier(value):
                return "FIELD_INVALID"
        if event.destination and not self._valid_identifier(event.destination):
            return "FIELD_INVALID"
        if event.policy_decision not in {"allow", "deny", "not_applicable"}:
            return "POLICY_DECISION_INVALID"
        if event.occurred_at.tzinfo is None or event.observed_at.tzinfo is None:
            return "TIMESTAMP_INVALID"
        return None

    def ingest(self, event: SecurityEvent, *, now: datetime = NOW) -> IngestResult:
        existing = self.events.get(event.event_id)
        if existing is not None:
            if existing == event:
                return IngestResult(IngestStatus.DUPLICATE, "EXACT_DUPLICATE", event.event_id)
            result = IngestResult(IngestStatus.REJECTED, "EVENT_ID_CONFLICT", event.event_id)
            self.rejections.append(result)
            return result
        error = self._schema_error(event)
        if error:
            result = IngestResult(IngestStatus.REJECTED, error, event.event_id)
            self.rejections.append(result)
            return result
        key = self.signing_keys.get(event.emitter_id)
        if key is None:
            result = IngestResult(IngestStatus.REJECTED, "EMITTER_UNTRUSTED", event.event_id)
            self.rejections.append(result)
            return result
        if event.tenant_id not in self.emitter_tenants.get(event.emitter_id, frozenset()):
            result = IngestResult(IngestStatus.REJECTED, "EMITTER_TENANT_UNAUTHORIZED", event.event_id)
            self.rejections.append(result)
            return result
        if event.observed_at < event.occurred_at or event.observed_at - event.occurred_at > MAX_INGESTION_DELAY:
            result = IngestResult(IngestStatus.REJECTED, "INGESTION_DELAY_INVALID", event.event_id)
            self.rejections.append(result)
            return result
        if event.occurred_at > now + MAX_CLOCK_SKEW or event.observed_at > now + MAX_CLOCK_SKEW:
            result = IngestResult(IngestStatus.REJECTED, "EVENT_FROM_FUTURE", event.event_id)
            self.rejections.append(result)
            return result
        expected_hash = digest(event.unsigned())
        expected_signature = hmac.new(key, expected_hash.encode(), sha256).hexdigest()
        if event.event_hash != expected_hash or not hmac.compare_digest(event.signature, expected_signature):
            result = IngestResult(IngestStatus.REJECTED, "INTEGRITY_INVALID", event.event_id)
            self.rejections.append(result)
            return result
        previous_sequence, previous_hash = self.last_by_emitter.get(event.emitter_id, (0, ""))
        if event.sequence != previous_sequence + 1 or event.previous_hash != previous_hash:
            result = IngestResult(IngestStatus.REJECTED, "CHAIN_DISCONTINUITY", event.event_id)
            self.rejections.append(result)
            return result
        self.events[event.event_id] = event
        self.last_by_emitter[event.emitter_id] = (event.sequence, event.event_hash)
        return IngestResult(IngestStatus.ACCEPTED, "ACCEPTED", event.event_id)

    def get(self, event_id: str, *, allowed_tenants: frozenset[str]) -> SecurityEvent:
        event = self.events[event_id]
        if event.tenant_id not in allowed_tenants or event.resource_tenant not in allowed_tenants:
            raise PermissionError("evidence tenant is outside analyst authorization")
        return event

    def query(
        self,
        *,
        allowed_tenants: frozenset[str],
        started_at: datetime,
        ended_at: datetime,
    ) -> tuple[SecurityEvent, ...]:
        return tuple(
            event
            for event in self.events.values()
            if event.tenant_id in allowed_tenants
            and event.resource_tenant in allowed_tenants
            and started_at <= event.occurred_at <= ended_at
        )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    rule_version: str
    kind: FindingKind
    tenant_id: str
    server_id: str
    severity: Severity
    evidence_ids: tuple[str, ...]
    statement: str


@dataclass(frozen=True)
class IncidentAlert:
    alert_id: str
    created_at: datetime
    tenant_id: str
    server_id: str
    severity: Severity
    finding_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    alert_digest: str


class IncidentDetector:
    """Deterministic rules over admitted facts; outputs remain findings."""

    def __init__(
        self,
        *,
        expected_artifacts: dict[tuple[str, str], str],
        allowed_destinations: dict[tuple[str, str], frozenset[str]],
    ) -> None:
        self.expected_artifacts = expected_artifacts
        self.allowed_destinations = allowed_destinations

    @staticmethod
    def _finding(
        kind: FindingKind,
        severity: Severity,
        events: Iterable[SecurityEvent],
        statement: str,
    ) -> Finding:
        items = tuple(events)
        evidence_ids = tuple(sorted(item.event_id for item in items))
        tenant, server = items[0].tenant_id, items[0].server_id
        rule_id = f"mcp.{kind.value}"
        finding_id = "finding-" + digest((rule_id, evidence_ids)).split(":", 1)[1][:16]
        return Finding(finding_id, rule_id, "1.0.0", kind, tenant, server, severity, evidence_ids, statement)

    def detect(self, events: Iterable[SecurityEvent]) -> tuple[Finding, ...]:
        items = tuple(events)
        findings: list[Finding] = []
        for event in items:
            expected = self.expected_artifacts.get((event.tenant_id, event.server_id))
            if event.kind == EventKind.REGISTRY and expected and event.artifact_digest != expected:
                findings.append(self._finding(FindingKind.ARTIFACT_DRIFT, Severity.HIGH, (event,), "observed artifact differs from reviewed registry state"))
            allowed = self.allowed_destinations.get((event.tenant_id, event.server_id), frozenset())
            if event.kind in {EventKind.MCP_CALL, EventKind.NETWORK} and event.destination and event.destination not in allowed:
                findings.append(self._finding(FindingKind.UNEXPECTED_EGRESS, Severity.HIGH, (event,), "destination is outside reviewed server egress"))
            if event.resource_tenant != event.tenant_id and event.kind == EventKind.RESOURCE and event.outcome == Outcome.COMPLETED:
                findings.append(self._finding(FindingKind.CROSS_TENANT_EFFECT, Severity.CRITICAL, (event,), "resource effect crossed the authenticated tenant boundary"))
            if event.policy_decision == "deny" and event.outcome == Outcome.COMPLETED:
                findings.append(self._finding(FindingKind.DENY_EFFECT_MISMATCH, Severity.CRITICAL, (event,), "independent effect completed after a policy denial"))
        by_trace: dict[tuple[str, str, str], list[SecurityEvent]] = {}
        for event in items:
            by_trace.setdefault((event.tenant_id, event.server_id, event.trace_id), []).append(event)
        for group in by_trace.values():
            kinds = {item.kind for item in group}
            emitters = {item.emitter_id for item in group}
            if EventKind.NETWORK in kinds and EventKind.RESOURCE in kinds and len(emitters) >= 2:
                findings.append(self._finding(FindingKind.CORRELATED_INTRUSION, Severity.CRITICAL, group, "independent network and resource evidence correlate on the same trace"))
        unique = {item.finding_id: item for item in findings}
        return tuple(sorted(unique.values(), key=lambda item: item.finding_id))

    def alert(self, findings: Iterable[Finding], *, now: datetime) -> IncidentAlert | None:
        items = tuple(findings)
        critical = tuple(item for item in items if item.severity == Severity.CRITICAL)
        if not critical:
            return None
        evidence_ids = tuple(sorted({event_id for item in items for event_id in item.evidence_ids}))
        tenant, server = critical[0].tenant_id, critical[0].server_id
        payload = (tenant, server, tuple(item.finding_id for item in items), evidence_ids)
        alert_digest = digest(payload)
        return IncidentAlert(
            "alert-" + alert_digest.split(":", 1)[1][:16],
            now,
            tenant,
            server,
            Severity.CRITICAL,
            tuple(item.finding_id for item in items),
            evidence_ids,
            alert_digest,
        )


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    proposed_by: str
    text_digest: str
    evidence_ids: tuple[str, ...]
    accepted_as_fact: bool = False


@dataclass(frozen=True)
class IncidentCase:
    incident_id: str
    tenant_id: str
    server_id: str
    state: CaseState
    severity: Severity
    opened_at: datetime
    declared_at: datetime | None
    version: int
    alert_id: str
    finding_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    hypotheses: tuple[Hypothesis, ...] = ()


class VersionConflict(RuntimeError):
    pass


class IncidentRepository:
    def __init__(self) -> None:
        self.cases: dict[str, IncidentCase] = {}

    def create(self, case: IncidentCase) -> None:
        if case.incident_id in self.cases:
            raise VersionConflict("incident already exists")
        self.cases[case.incident_id] = case

    def get(self, incident_id: str) -> IncidentCase:
        return self.cases[incident_id]

    def save(self, case: IncidentCase, *, expected_version: int) -> None:
        current = self.cases[case.incident_id]
        if current.version != expected_version or case.version != expected_version + 1:
            raise VersionConflict("stale incident version")
        self.cases[case.incident_id] = case


class IncidentManager:
    def __init__(self, store: EvidenceStore, repository: IncidentRepository) -> None:
        self.store = store
        self.repository = repository

    def open_from_alert(
        self,
        alert: IncidentAlert,
        *,
        analyst_id: str,
        allowed_tenants: frozenset[str],
    ) -> IncidentCase:
        if alert.tenant_id not in allowed_tenants:
            raise PermissionError("analyst is not authorized for the alert tenant")
        events = tuple(self.store.get(event_id, allowed_tenants=allowed_tenants) for event_id in alert.evidence_ids)
        if not events or any(event.tenant_id != alert.tenant_id for event in events):
            raise ValueError("alert evidence does not support its tenant")
        if alert.alert_digest != digest((alert.tenant_id, alert.server_id, alert.finding_ids, alert.evidence_ids)):
            raise ValueError("alert integrity mismatch")
        incident_id = "incident-" + alert.alert_digest.split(":", 1)[1][:12]
        case = IncidentCase(
            incident_id,
            alert.tenant_id,
            alert.server_id,
            CaseState.OPEN,
            alert.severity,
            alert.created_at,
            None,
            1,
            alert.alert_id,
            alert.finding_ids,
            alert.evidence_ids,
        )
        self.repository.create(case)
        return case

    def add_hypothesis(self, case: IncidentCase, *, proposed_by: str, text: str, evidence_ids: Iterable[str]) -> IncidentCase:
        ids = tuple(sorted(set(evidence_ids)))
        if not set(ids).issubset(set(case.evidence_ids)):
            raise ValueError("hypothesis must cite evidence already admitted to the case")
        item = Hypothesis("hypothesis-" + digest((proposed_by, text, ids)).split(":", 1)[1][:12], proposed_by, digest(text), ids, False)
        updated = replace(case, hypotheses=case.hypotheses + (item,), version=case.version + 1)
        self.repository.save(updated, expected_version=case.version)
        return updated

    def declare(
        self,
        case: IncidentCase,
        findings: Iterable[Finding],
        *,
        responder_id: str,
        responder_roles: frozenset[str],
        now: datetime,
    ) -> IncidentCase:
        if "incident_responder" not in responder_roles:
            raise PermissionError("incident responder role required")
        items = tuple(findings)
        if {item.finding_id for item in items} != set(case.finding_ids):
            raise ValueError("declaration findings must match the admitted alert")
        cited = {event_id for item in items for event_id in item.evidence_ids}
        emitters = {self.store.events[event_id].emitter_id for event_id in cited}
        has_effect = any(item.kind in {FindingKind.CROSS_TENANT_EFFECT, FindingKind.DENY_EFFECT_MISMATCH} for item in items)
        if not cited.issubset(set(case.evidence_ids)) or len(emitters) < 2 or not has_effect:
            raise ValueError("declaration requires independent effect evidence")
        if case.state != CaseState.OPEN:
            raise ValueError("only an open case can be declared")
        updated = replace(case, state=CaseState.DECLARED, declared_at=now, version=case.version + 1)
        self.repository.save(updated, expected_version=case.version)
        return updated

    def mark_contained(
        self,
        case: IncidentCase,
        proof: "ContainmentProof",
        execution: "ExecutionResult",
        *,
        responder_roles: frozenset[str],
    ) -> IncidentCase:
        if "incident_responder" not in responder_roles:
            raise PermissionError("incident responder role required")
        if case.state != CaseState.DECLARED:
            raise ValueError("only a declared incident can become contained")
        if (
            proof.incident_id != case.incident_id
            or execution.incident_id != case.incident_id
            or proof.plan_digest != execution.plan_digest
            or proof.control_revision != execution.control_revision
        ):
            raise ValueError("containment proof is not bound to this case and execution")
        if not proof.complete or execution.status not in {
            ExecutionStatus.APPLIED,
            ExecutionStatus.RECONCILED,
        }:
            raise ValueError("verified containment effects are required")
        updated = replace(
            case,
            state=CaseState.CONTAINED,
            version=case.version + 1,
        )
        self.repository.save(updated, expected_version=case.version)
        return updated


@dataclass(frozen=True)
class ScopeReport:
    incident_id: str
    evidence_ids: tuple[str, ...]
    confirmed_tenants: tuple[str, ...]
    principals: tuple[str, ...]
    artifacts: tuple[str, ...]
    workloads: tuple[str, ...]
    sessions: tuple[str, ...]
    credentials: tuple[str, ...]
    destinations: tuple[str, ...]
    excluded_unauthorized_count: int
    started_at: datetime
    ended_at: datetime


class ScopeEngine:
    """Authorize before graph expansion; exact joins produce confirmed scope."""

    JOIN_FIELDS = ("trace_id", "operation_id", "artifact_digest", "workload_id", "session_id", "credential_id")

    def scope(
        self,
        case: IncidentCase,
        store: EvidenceStore,
        *,
        analyst_tenants: frozenset[str],
        started_at: datetime,
        ended_at: datetime,
    ) -> ScopeReport:
        if case.tenant_id not in analyst_tenants:
            raise PermissionError("analyst cannot scope this incident")
        authorized = store.query(allowed_tenants=analyst_tenants, started_at=started_at, ended_at=ended_at)
        in_window = tuple(event for event in store.events.values() if started_at <= event.occurred_at <= ended_at)
        graph = nx.Graph()
        for event in authorized:
            graph.add_node(event.event_id, event=event)
        for index, left in enumerate(authorized):
            for right in authorized[index + 1 :]:
                if any(getattr(left, field) == getattr(right, field) for field in self.JOIN_FIELDS):
                    graph.add_edge(left.event_id, right.event_id)
        seeds = tuple(event_id for event_id in case.evidence_ids if event_id in graph)
        scoped: set[str] = set()
        for seed in seeds:
            scoped.update(nx.node_connected_component(graph, seed))
        events = tuple(store.events[event_id] for event_id in sorted(scoped))
        return ScopeReport(
            case.incident_id,
            tuple(event.event_id for event in events),
            tuple(sorted({event.resource_tenant for event in events} | {event.tenant_id for event in events})),
            tuple(sorted({event.principal_id for event in events})),
            tuple(sorted({event.artifact_digest for event in events})),
            tuple(sorted({event.workload_id for event in events})),
            tuple(sorted({event.session_id for event in events})),
            tuple(sorted({event.credential_id for event in events})),
            tuple(sorted({event.destination for event in events if event.destination})),
            len(in_window) - len(authorized),
            started_at,
            ended_at,
        )


@dataclass(frozen=True)
class ScopeMetrics:
    true_positive_count: int
    predicted_count: int
    actual_count: int
    precision: float
    recall: float


def evaluate_scope(report: ScopeReport, actual_evidence_ids: frozenset[str]) -> ScopeMetrics:
    predicted = set(report.evidence_ids)
    true_positive = len(predicted & actual_evidence_ids)
    return ScopeMetrics(
        true_positive,
        len(predicted),
        len(actual_evidence_ids),
        true_positive / len(predicted) if predicted else 0.0,
        true_positive / len(actual_evidence_ids) if actual_evidence_ids else 0.0,
    )


@dataclass(frozen=True)
class CustodyRecord:
    sequence: int
    actor_id: str
    action: str
    occurred_at: datetime
    reason: str
    previous_hash: str
    record_hash: str
    signature: str


@dataclass(frozen=True)
class PreservedEvent:
    event_id: str
    emitter_id: str
    occurred_at: datetime
    observed_at: datetime
    event_hash: str
    trace_id: str
    server_id: str
    artifact_digest: str
    workload_id: str
    tenant_pseudonym: str
    principal_pseudonym: str
    action: str
    resource_digest: str
    destination_digest: str
    outcome: Outcome
    source_locator: str


@dataclass(frozen=True)
class ForensicPackage:
    package_id: str
    incident_id: str
    created_at: datetime
    custodian: str
    evidence: tuple[PreservedEvent, ...]
    retention_until: datetime
    legal_hold: bool
    manifest_digest: str
    signature: str
    custody: tuple[CustodyRecord, ...]


def _package_manifest(package: ForensicPackage) -> dict[str, Any]:
    return {
        "package_id": package.package_id,
        "incident_id": package.incident_id,
        "created_at": package.created_at,
        "evidence": package.evidence,
        "retention_until": package.retention_until,
        "legal_hold": package.legal_hold,
    }


class ForensicVault:
    def __init__(self, *, signing_key: bytes = PACKAGE_KEY) -> None:
        self.signing_key = signing_key

    def _custody_record(self, sequence: int, actor_id: str, action: str, occurred_at: datetime, reason: str, previous_hash: str) -> CustodyRecord:
        record_hash = digest((sequence, actor_id, action, occurred_at, reason, previous_hash))
        signature = hmac.new(self.signing_key, record_hash.encode(), sha256).hexdigest()
        return CustodyRecord(sequence, actor_id, action, occurred_at, reason, previous_hash, record_hash, signature)

    def preserve(
        self,
        case: IncidentCase,
        report: ScopeReport,
        store: EvidenceStore,
        *,
        actor_id: str,
        actor_roles: frozenset[str],
        allowed_tenants: frozenset[str],
        now: datetime,
        retention_until: datetime,
        legal_hold: bool,
    ) -> ForensicPackage:
        if "forensic_collector" not in actor_roles:
            raise PermissionError("forensic collector role required")
        if retention_until <= now:
            raise ValueError("retention must extend beyond collection")
        events = tuple(store.get(event_id, allowed_tenants=allowed_tenants) for event_id in report.evidence_ids)
        preserved = tuple(
            PreservedEvent(
                event.event_id,
                event.emitter_id,
                event.occurred_at,
                event.observed_at,
                event.event_hash,
                event.trace_id,
                event.server_id,
                event.artifact_digest,
                event.workload_id,
                pseudonym(event.tenant_id),
                pseudonym(event.principal_id),
                event.action,
                digest(event.resource),
                digest(event.destination),
                event.outcome,
                event.source_locator,
            )
            for event in events
        )
        package_id = "package-" + digest((case.incident_id, tuple(item.event_id for item in preserved), now)).split(":", 1)[1][:16]
        placeholder = ForensicPackage(package_id, case.incident_id, now, actor_id, preserved, retention_until, legal_hold, "", "", ())
        manifest_digest = digest(_package_manifest(placeholder))
        signature = hmac.new(self.signing_key, manifest_digest.encode(), sha256).hexdigest()
        custody = (self._custody_record(1, actor_id, "preserve", now, "incident evidence collection", ""),)
        return replace(placeholder, manifest_digest=manifest_digest, signature=signature, custody=custody)

    def verify(self, package: ForensicPackage) -> bool:
        if package.manifest_digest != digest(_package_manifest(package)):
            return False
        expected = hmac.new(self.signing_key, package.manifest_digest.encode(), sha256).hexdigest()
        if not hmac.compare_digest(package.signature, expected):
            return False
        previous = ""
        for sequence, record in enumerate(package.custody, 1):
            expected_hash = digest((sequence, record.actor_id, record.action, record.occurred_at, record.reason, previous))
            expected_signature = hmac.new(self.signing_key, expected_hash.encode(), sha256).hexdigest()
            if record.sequence != sequence or record.previous_hash != previous or record.record_hash != expected_hash or not hmac.compare_digest(record.signature, expected_signature):
                return False
            previous = record.record_hash
        return True

    def transfer(self, package: ForensicPackage, *, actor_id: str, actor_roles: frozenset[str], new_custodian: str, reason: str, now: datetime) -> ForensicPackage:
        if "forensic_custodian" not in actor_roles or not reason:
            raise PermissionError("authorized custody transfer requires a reason")
        if not self.verify(package):
            raise ValueError("cannot transfer an invalid package")
        previous = package.custody[-1].record_hash
        record = self._custody_record(len(package.custody) + 1, actor_id, f"transfer:{new_custodian}", now, reason, previous)
        return replace(package, custodian=new_custodian, custody=package.custody + (record,))


@dataclass(frozen=True)
class ContainmentAction:
    action_id: str
    kind: ActionKind
    tenant_id: str
    target: str
    secondary: str = ""


@dataclass(frozen=True)
class ContainmentPlan:
    plan_id: str
    incident_id: str
    tenant_id: str
    case_version: int
    actions: tuple[ContainmentAction, ...]
    requested_by: str
    policy_version: str
    created_at: datetime
    expires_at: datetime
    plan_digest: str


def make_plan(case: IncidentCase, scope: ScopeReport, *, requested_by: str, now: datetime) -> ContainmentPlan:
    if case.state != CaseState.DECLARED:
        raise ValueError("containment plan requires a declared incident")
    actions = (
        *(
            ContainmentAction(
                f"action-disable-{index}",
                ActionKind.DISABLE_BINDING,
                case.tenant_id,
                case.server_id,
                artifact,
            )
            for index, artifact in enumerate(scope.artifacts, 1)
        ),
        *(
            ContainmentAction(
                f"action-quarantine-{index}",
                ActionKind.QUARANTINE_WORKLOAD,
                case.tenant_id,
                workload,
            )
            for index, workload in enumerate(scope.workloads, 1)
        ),
        *(
            ContainmentAction(
                f"action-revoke-{index}",
                ActionKind.REVOKE_CREDENTIAL,
                case.tenant_id,
                credential,
            )
            for index, credential in enumerate(scope.credentials, 1)
        ),
        *(
            ContainmentAction(
                f"action-session-{index}",
                ActionKind.TERMINATE_SESSION,
                case.tenant_id,
                session_id,
            )
            for index, session_id in enumerate(scope.sessions, 1)
        ),
        *(
            ContainmentAction(
                f"action-egress-{index}",
                ActionKind.BLOCK_EGRESS,
                case.tenant_id,
                workload,
                destination,
            )
            for index, (workload, destination) in enumerate(
                (
                    (workload, destination)
                    for workload in scope.workloads
                    for destination in scope.destinations
                ),
                1,
            )
        ),
    )
    unsigned = {
        "incident_id": case.incident_id,
        "tenant_id": case.tenant_id,
        "case_version": case.version,
        "actions": actions,
        "requested_by": requested_by,
        "policy_version": POLICY_VERSION,
        "created_at": now,
        "expires_at": now + timedelta(minutes=10),
    }
    plan_digest = digest(unsigned)
    return ContainmentPlan("plan-" + plan_digest.split(":", 1)[1][:16], **unsigned, plan_digest=plan_digest)


def verify_plan(plan: ContainmentPlan) -> bool:
    unsigned = {
        "incident_id": plan.incident_id,
        "tenant_id": plan.tenant_id,
        "case_version": plan.case_version,
        "actions": plan.actions,
        "requested_by": plan.requested_by,
        "policy_version": plan.policy_version,
        "created_at": plan.created_at,
        "expires_at": plan.expires_at,
    }
    return plan.plan_digest == digest(unsigned) and bool(plan.actions)


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    incident_id: str
    tenant_id: str
    plan_digest: str
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


def approve_plan(plan: ContainmentPlan, *, approver_id: str, approver_role: str, now: datetime) -> ApprovalReceipt:
    if approver_role not in APPROVER_ROLES:
        raise PermissionError("incident containment approver role required")
    receipt_id = "receipt-" + digest((plan.plan_digest, approver_id, now)).split(":", 1)[1][:16]
    unsigned = {
        "receipt_id": receipt_id,
        "incident_id": plan.incident_id,
        "tenant_id": plan.tenant_id,
        "plan_digest": plan.plan_digest,
        "policy_version": plan.policy_version,
        "approver_id": approver_id,
        "approver_role": approver_role,
        "issued_at": now,
        "expires_at": min(plan.expires_at, now + timedelta(minutes=5)),
        "nonce": "nonce-" + receipt_id[-8:],
    }
    signature = hmac.new(APPROVAL_KEY, canonical_json(unsigned), sha256).hexdigest()
    return ApprovalReceipt(**unsigned, signature=signature)


def verify_receipt(receipt: ApprovalReceipt) -> bool:
    expected = hmac.new(APPROVAL_KEY, canonical_json(receipt.unsigned()), sha256).hexdigest()
    return hmac.compare_digest(receipt.signature, expected)


@dataclass(frozen=True)
class ControlPlane:
    revision: int = 0
    disabled_bindings: frozenset[tuple[str, str]] = frozenset()
    quarantined_workloads: frozenset[str] = frozenset()
    revoked_credentials: frozenset[str] = frozenset()
    terminated_sessions: frozenset[str] = frozenset()
    blocked_egress: frozenset[tuple[str, str]] = frozenset()

    def satisfied(self, action: ContainmentAction) -> bool:
        if action.kind == ActionKind.DISABLE_BINDING:
            return (action.target, action.secondary) in self.disabled_bindings
        if action.kind == ActionKind.QUARANTINE_WORKLOAD:
            return action.target in self.quarantined_workloads
        if action.kind == ActionKind.REVOKE_CREDENTIAL:
            return action.target in self.revoked_credentials
        if action.kind == ActionKind.TERMINATE_SESSION:
            return action.target in self.terminated_sessions
        if action.kind == ActionKind.BLOCK_EGRESS:
            return (action.target, action.secondary) in self.blocked_egress
        return False

    def apply(self, actions: tuple[ContainmentAction, ...]) -> "ControlPlane":
        if len({item.action_id for item in actions}) != len(actions):
            raise ValueError("duplicate containment action")
        allowed = set(ActionKind)
        if any(item.kind not in allowed or not item.target for item in actions):
            raise ValueError("unsupported or empty containment action")
        return replace(
            self,
            revision=self.revision + 1,
            disabled_bindings=self.disabled_bindings | {(item.target, item.secondary) for item in actions if item.kind == ActionKind.DISABLE_BINDING},
            quarantined_workloads=self.quarantined_workloads | {item.target for item in actions if item.kind == ActionKind.QUARANTINE_WORKLOAD},
            revoked_credentials=self.revoked_credentials | {item.target for item in actions if item.kind == ActionKind.REVOKE_CREDENTIAL},
            terminated_sessions=self.terminated_sessions | {item.target for item in actions if item.kind == ActionKind.TERMINATE_SESSION},
            blocked_egress=self.blocked_egress | {(item.target, item.secondary) for item in actions if item.kind == ActionKind.BLOCK_EGRESS},
        )


@dataclass(frozen=True)
class ExecutionResult:
    operation_id: str
    request_digest: str
    incident_id: str
    plan_digest: str
    status: ExecutionStatus
    control_revision: int
    action_ids: tuple[str, ...]
    reason_code: str
    applied_at: datetime


class ContainmentJournal:
    """Durable operation and receipt state shared across executor restarts."""

    def __init__(self) -> None:
        self.consumed_receipts: set[str] = set()
        self.operations: dict[str, ExecutionResult] = {}
        self.plans: dict[str, ContainmentPlan] = {}


class ContainmentExecutor:
    def __init__(
        self,
        controls: ControlPlane | None = None,
        journal: ContainmentJournal | None = None,
    ) -> None:
        self.controls = controls or ControlPlane()
        self.journal = journal or ContainmentJournal()
        self.consumed_receipts = self.journal.consumed_receipts
        self.operations = self.journal.operations
        self.plans = self.journal.plans

    @staticmethod
    def _request_digest(plan: ContainmentPlan, receipt: ApprovalReceipt, package: ForensicPackage) -> str:
        return digest((plan.plan_digest, receipt.receipt_id, package.manifest_digest))

    def execute(
        self,
        operation_id: str,
        plan: ContainmentPlan,
        receipt: ApprovalReceipt,
        package: ForensicPackage,
        vault: ForensicVault,
        case: IncidentCase,
        *,
        now: datetime,
        simulate_lost_response: bool = False,
    ) -> ExecutionResult:
        request_digest = self._request_digest(plan, receipt, package)
        previous = self.operations.get(operation_id)
        if previous is not None:
            if previous.request_digest != request_digest:
                raise ValueError("operation ID reused with different request")
            return self.reconcile(operation_id, now=now)
        if case.state != CaseState.DECLARED or case.incident_id != plan.incident_id or case.tenant_id != plan.tenant_id:
            raise PermissionError("case state or scope does not authorize containment")
        if plan.case_version != case.version or plan.policy_version != POLICY_VERSION or not verify_plan(plan):
            raise ValueError("plan integrity, case version, or policy version mismatch")
        if now > plan.expires_at:
            raise ValueError("containment plan expired")
        if any(item.tenant_id != case.tenant_id for item in plan.actions):
            raise PermissionError("cross-tenant containment action")
        if receipt.receipt_id in self.consumed_receipts:
            raise ValueError("approval receipt already consumed")
        if not verify_receipt(receipt) or receipt.approver_role not in APPROVER_ROLES or receipt.incident_id != plan.incident_id or receipt.tenant_id != plan.tenant_id or receipt.plan_digest != plan.plan_digest or receipt.policy_version != plan.policy_version or now > receipt.expires_at:
            raise PermissionError("approval receipt does not authorize this exact plan")
        if package.incident_id != case.incident_id or not vault.verify(package):
            raise ValueError("valid preserved evidence package required before mutation")
        self.controls = self.controls.apply(plan.actions)
        self.consumed_receipts.add(receipt.receipt_id)
        self.plans[operation_id] = plan
        status = ExecutionStatus.UNKNOWN if simulate_lost_response else ExecutionStatus.APPLIED
        result = ExecutionResult(
            operation_id,
            request_digest,
            plan.incident_id,
            plan.plan_digest,
            status,
            self.controls.revision,
            tuple(item.action_id for item in plan.actions),
            "OUTCOME_UNKNOWN_RECONCILE" if simulate_lost_response else "ALL_EFFECTS_VERIFIED",
            now,
        )
        self.operations[operation_id] = result
        return result

    def reconcile(self, operation_id: str, *, now: datetime) -> ExecutionResult:
        previous = self.operations[operation_id]
        plan = self.plans[operation_id]
        if all(self.controls.satisfied(action) for action in plan.actions):
            result = replace(previous, status=ExecutionStatus.RECONCILED, reason_code="CONTROL_STATE_CONFIRMED", control_revision=self.controls.revision, applied_at=now)
            self.operations[operation_id] = result
            return result
        return replace(previous, status=ExecutionStatus.UNKNOWN, reason_code="CONTROL_STATE_INCOMPLETE")


@dataclass(frozen=True)
class ContainmentProof:
    incident_id: str
    plan_digest: str
    complete: bool
    control_revision: int
    required_action_count: int
    satisfied_action_count: int
    post_cut_forbidden_effect_count: int
    forensic_package_valid: bool


def prove_containment(
    plan: ContainmentPlan,
    controls: ControlPlane,
    package: ForensicPackage,
    vault: ForensicVault,
    store: EvidenceStore,
    *,
    applied_at: datetime,
) -> ContainmentProof:
    satisfied = sum(controls.satisfied(action) for action in plan.actions)
    disabled_servers = {item.target for item in plan.actions if item.kind == ActionKind.DISABLE_BINDING}
    quarantined_workloads = {item.target for item in plan.actions if item.kind == ActionKind.QUARANTINE_WORKLOAD}
    revoked_credentials = {item.target for item in plan.actions if item.kind == ActionKind.REVOKE_CREDENTIAL}
    terminated_sessions = {item.target for item in plan.actions if item.kind == ActionKind.TERMINATE_SESSION}
    blocked_destinations = {item.secondary for item in plan.actions if item.kind == ActionKind.BLOCK_EGRESS}
    forbidden = tuple(
        event
        for event in store.events.values()
        if event.occurred_at > applied_at
        and event.outcome == Outcome.COMPLETED
        and (
            event.server_id in disabled_servers
            or event.workload_id in quarantined_workloads
            or event.credential_id in revoked_credentials
            or event.session_id in terminated_sessions
            or event.destination in blocked_destinations
        )
    )
    package_valid = vault.verify(package)
    return ContainmentProof(
        plan.incident_id,
        plan.plan_digest,
        satisfied == len(plan.actions) and not forbidden and package_valid,
        controls.revision,
        len(plan.actions),
        satisfied,
        len(forbidden),
        package_valid,
    )


@dataclass(frozen=True)
class DetectionCase:
    name: str
    events: tuple[SecurityEvent, ...]
    should_alert: bool


@dataclass(frozen=True)
class DetectionMetrics:
    true_positive_count: int
    false_positive_count: int
    true_negative_count: int
    false_negative_count: int
    precision: float
    recall: float


def evaluate_detector(detector: IncidentDetector, cases: Iterable[DetectionCase], *, now: datetime) -> DetectionMetrics:
    tp = fp = tn = fn = 0
    for case in cases:
        actual = detector.alert(detector.detect(case.events), now=now) is not None
        if case.should_alert and actual:
            tp += 1
        elif not case.should_alert and actual:
            fp += 1
        elif not case.should_alert and not actual:
            tn += 1
        else:
            fn += 1
    return DetectionMetrics(tp, fp, tn, fn, tp / (tp + fp) if tp + fp else 0.0, tp / (tp + fn) if tp + fn else 0.0)


@dataclass(frozen=True)
class IncidentMetrics:
    time_to_detect_seconds: float
    time_to_contain_seconds: float
    evidence_completeness: float
    evidence_present_count: int
    evidence_required_count: int
    scope_precision: float
    scope_recall: float
    valid_service_disruption_rate: float


def calculate_metrics(
    case: IncidentCase,
    alert: IncidentAlert,
    execution: ExecutionResult,
    package: ForensicPackage,
    scope_metrics: ScopeMetrics,
    *,
    valid_services_disrupted: int,
    valid_services_total: int,
) -> IncidentMetrics:
    required_emitters = {"registry.sensor", "mcp.gateway", "network.sensor", "resource.audit"}
    present = {item.emitter_id for item in package.evidence} & required_emitters
    earliest = min(item.occurred_at for item in package.evidence)
    if case.declared_at is None:
        raise ValueError("declared time required for containment metrics")
    return IncidentMetrics(
        (alert.created_at - earliest).total_seconds(),
        (execution.applied_at - case.declared_at).total_seconds(),
        len(present) / len(required_emitters),
        len(present),
        len(required_emitters),
        scope_metrics.precision,
        scope_metrics.recall,
        valid_services_disrupted / valid_services_total if valid_services_total else 0.0,
    )


def reviewed_digest(name: str) -> str:
    return digest(name.encode())


@dataclass(frozen=True)
class Environment:
    store: EvidenceStore
    detector: IncidentDetector
    malicious_events: tuple[SecurityEvent, ...]
    benign_events: tuple[SecurityEvent, ...]
    safe_denial_events: tuple[SecurityEvent, ...]
    actual_incident_evidence: frozenset[str]


def build_environment(*, now: datetime = NOW) -> Environment:
    emitters = {name: EventEmitter(name, key) for name, key in EVENT_KEYS.items()}
    trace = "a" * 32
    bad_digest = reviewed_digest("support-v2@compromised")
    common = {
        "tenant_id": "acme",
        "principal_id": "user:acme:42",
        "server_id": "support-v2",
        "artifact_digest": bad_digest,
        "workload_id": "spiffe://acme/mcp/support-v2",
        "trace_id": trace,
        "operation_id": "operation-export-7",
        "session_id": "session-support-7",
        "credential_id": "credential-support-v2",
    }

    def template(event_id: str, offset: int, kind: EventKind, action: str, resource: str, destination: str, policy: str, outcome: Outcome, locator: str, *, resource_tenant: str = "acme", **changes: Any) -> EventTemplate:
        values = {
            "event_id": event_id,
            "occurred_at": now + timedelta(seconds=offset),
            "observed_at": now + timedelta(seconds=offset, milliseconds=100),
            **common,
            "resource_tenant": resource_tenant,
            "kind": kind,
            "action": action,
            "resource": resource,
            "destination": destination,
            "policy_decision": policy,
            "outcome": outcome,
            "source_locator": locator,
        }
        values.update(changes)
        return EventTemplate(**values)

    malicious = (
        emitters["registry.sensor"].emit(template("event-registry-bad", -30, EventKind.REGISTRY, "deployment.observe", "registry://acme/support-v2", "", "not_applicable", Outcome.OBSERVED, "vault://registry/event-registry-bad")),
        emitters["mcp.gateway"].emit(template("event-call-export", -25, EventKind.MCP_CALL, "customer.export", "data://beta/customers", "exfil.example", "deny", Outcome.COMPLETED, "vault://gateway/event-call-export", resource_tenant="beta")),
        emitters["network.sensor"].emit(template("event-network-egress", -24, EventKind.NETWORK, "network.connect", "network://exfil.example", "exfil.example", "deny", Outcome.COMPLETED, "vault://network/event-network-egress")),
        emitters["resource.audit"].emit(template("event-beta-read", -23, EventKind.RESOURCE, "customer.read", "data://beta/customers", "", "deny", Outcome.COMPLETED, "vault://resource/event-beta-read", resource_tenant="beta")),
    )
    benign_common = {
        **common,
        "server_id": "support-v1",
        "artifact_digest": reviewed_digest("support-v1@reviewed"),
        "workload_id": "spiffe://acme/mcp/support-v1",
        "trace_id": "b" * 32,
        "operation_id": "operation-ticket-8",
        "session_id": "session-support-8",
        "credential_id": "credential-support-v1",
    }
    benign = (
        emitters["mcp.gateway"].emit(template("event-good-call", -20, EventKind.MCP_CALL, "ticket.read", "data://acme/tickets/8", "tickets.example.com", "allow", Outcome.COMPLETED, "vault://gateway/event-good-call", **benign_common)),
        emitters["network.sensor"].emit(template("event-good-network", -19, EventKind.NETWORK, "network.connect", "network://tickets.example.com", "tickets.example.com", "allow", Outcome.COMPLETED, "vault://network/event-good-network", **benign_common)),
    )
    safe_denial = (
        emitters["mcp.gateway"].emit(template("event-safe-denial", -18, EventKind.MCP_CALL, "customer.export", "data://acme/customers", "exfil.example", "deny", Outcome.DENIED, "vault://gateway/event-safe-denial", trace_id="c" * 32, operation_id="operation-denied-9", session_id="session-denied-9")),
    )
    store = EvidenceStore()
    for event in malicious + benign + safe_denial:
        result = store.ingest(event, now=now)
        if result.status != IngestStatus.ACCEPTED:
            raise AssertionError(result)
    detector = IncidentDetector(
        expected_artifacts={
            ("acme", "support-v2"): reviewed_digest("support-v2@reviewed"),
            ("acme", "support-v1"): reviewed_digest("support-v1@reviewed"),
        },
        allowed_destinations={
            ("acme", "support-v2"): frozenset({"tickets.example.com"}),
            ("acme", "support-v1"): frozenset({"tickets.example.com"}),
        },
    )
    return Environment(
        store,
        detector,
        malicious,
        benign,
        safe_denial,
        frozenset(event.event_id for event in malicious + safe_denial),
    )


def make_otel_incident_span(incident_id: str) -> tuple[str, dict[str, Any]]:
    """Create one real offline OpenTelemetry span with privacy-minimized fields."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "course-21-incident-workflow"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("mcp-security-course-21")
    with tracer.start_as_current_span("incident.containment") as span:
        span.set_attribute("incident.id", incident_id)
        span.set_attribute("incident.policy.version", POLICY_VERSION)
        span.set_attribute("incident.outcome", "contained")
    finished = exporter.get_finished_spans()[0]
    return finished.name, dict(finished.attributes or {})


def run_demo() -> dict[str, Any]:
    environment = build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    alert = environment.detector.alert(findings, now=NOW)
    assert alert is not None
    repository = IncidentRepository()
    manager = IncidentManager(environment.store, repository)
    analyst_tenants = frozenset({"acme", "beta"})
    case = manager.open_from_alert(alert, analyst_id="analyst-7", allowed_tenants=analyst_tenants)
    case = manager.add_hypothesis(case, proposed_by="assistant-model", text="credential theft may explain the sequence", evidence_ids=alert.evidence_ids)
    case = manager.declare(case, findings, responder_id="responder-2", responder_roles=frozenset({"incident_responder"}), now=NOW + timedelta(seconds=1))
    report = ScopeEngine().scope(case, environment.store, analyst_tenants=analyst_tenants, started_at=NOW - timedelta(minutes=2), ended_at=NOW)
    scope_metrics = evaluate_scope(report, environment.actual_incident_evidence)
    vault = ForensicVault()
    package = vault.preserve(case, report, environment.store, actor_id="collector-1", actor_roles=frozenset({"forensic_collector"}), allowed_tenants=analyst_tenants, now=NOW + timedelta(seconds=2), retention_until=NOW + timedelta(days=365), legal_hold=True)
    plan = make_plan(case, report, requested_by="responder-2", now=NOW + timedelta(seconds=3))
    receipt = approve_plan(plan, approver_id="commander-1", approver_role="incident_commander", now=NOW + timedelta(seconds=4))
    executor = ContainmentExecutor()
    first = executor.execute("containment-operation-1", plan, receipt, package, vault, case, now=NOW + timedelta(seconds=5), simulate_lost_response=True)
    reconciled = executor.execute("containment-operation-1", plan, receipt, package, vault, case, now=NOW + timedelta(seconds=6))
    proof = prove_containment(plan, executor.controls, package, vault, environment.store, applied_at=reconciled.applied_at)
    case = manager.mark_contained(
        case,
        proof,
        reconciled,
        responder_roles=frozenset({"incident_responder"}),
    )
    detection = evaluate_detector(environment.detector, (
        DetectionCase("malicious-sequence", environment.malicious_events, True),
        DetectionCase("valid-support", environment.benign_events, False),
        DetectionCase("blocked-export", environment.safe_denial_events, False),
    ), now=NOW)
    metrics = calculate_metrics(case, alert, reconciled, package, scope_metrics, valid_services_disrupted=0, valid_services_total=1)
    span_name, span_attributes = make_otel_incident_span(case.incident_id)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "findings": findings,
        "alert": alert,
        "case": case,
        "scope": report,
        "scope_metrics": scope_metrics,
        "package": package,
        "package_valid": vault.verify(package),
        "first_execution": first,
        "reconciled_execution": reconciled,
        "proof": proof,
        "detection_metrics": detection,
        "incident_metrics": metrics,
        "otel": {"span_name": span_name, "attributes": span_attributes},
    }


def main() -> None:
    result = run_demo()
    assert result["alert"].severity == Severity.CRITICAL
    assert result["case"].state == CaseState.CONTAINED
    assert result["case"].hypotheses[0].accepted_as_fact is False
    assert result["scope_metrics"].precision == 1.0
    assert result["scope_metrics"].recall == 1.0
    assert result["package_valid"] is True
    assert result["first_execution"].status == ExecutionStatus.UNKNOWN
    assert result["reconciled_execution"].status == ExecutionStatus.RECONCILED
    assert result["proof"].complete is True
    assert result["detection_metrics"].precision == 1.0
    assert result["detection_metrics"].recall == 1.0
    assert result["incident_metrics"].valid_service_disruption_rate == 0.0
    print("PASS: evidence-backed incident was scoped, preserved, contained, and reconciled")


if __name__ == "__main__":
    main()
