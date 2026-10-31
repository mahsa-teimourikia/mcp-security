"""Course 27: evidence-bound MCP security observability and SOC integration.

This offline, credential-free vertical slice uses real Ed25519 signatures and
OpenTelemetry spans. Trusted producers sign privacy-minimized events; a strict
normalizer validates them; a tenant-partitioned detector creates candidate
alerts; an idempotent router creates SOC cases; and an exact, single-use
approval gates containment. Logs and model output never become authority.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import json
import re
from statistics import median
from threading import Lock
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


UTC = timezone.utc
NOW = datetime(2026, 10, 31, 16, 0, tzinfo=UTC)
SCHEMA_VERSION = "mcp.security.event/1.0"
POLICY_VERSION = "mcp-soc-policy/2026-10-31"
MAX_CLOCK_SKEW = timedelta(seconds=10)
MAX_INGEST_DELAY = timedelta(minutes=10)
CORRELATION_WINDOW = timedelta(minutes=5)
LATE_EVENT_ALLOWANCE = timedelta(minutes=2)
SUPPRESSION_WINDOW = timedelta(minutes=15)
MAX_PARTITION_EVENTS = 100
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,159}$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_ATTRIBUTE_NAMES = frozenset(
    {"access_token", "authorization", "cookie", "password", "prompt", "raw_prompt", "secret"}
)


class SOCError(ValueError):
    """Stable machine-readable denial for course tests and adapters."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class EventKind(StrEnum):
    TOOL_CALL = "tool_call"
    POLICY = "policy"
    NETWORK = "network"
    RESOURCE = "resource"
    APPROVAL = "approval"
    CONTROL = "control"


class Outcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AlertState(StrEnum):
    CANDIDATE = "candidate"
    ROUTED = "routed"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class CaseState(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESPONSE_PENDING = "response_pending"
    CONTAINED = "contained"
    CLOSED = "closed"


class ActionKind(StrEnum):
    DISABLE_SERVER = "disable_server"
    QUARANTINE_WORKLOAD = "quarantine_workload"
    BLOCK_DESTINATION = "block_destination"


class ExecutionStatus(StrEnum):
    APPLIED = "applied"
    RECONCILED = "reconciled"
    UNKNOWN = "unknown"


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset, deque)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + sha256(payload).hexdigest()


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _require_safe(label: str, value: str) -> None:
    if not SAFE_ID.fullmatch(value):
        raise SOCError("EVENT_FIELD_INVALID", f"{label} is not a safe bounded identifier")


@dataclass(frozen=True)
class EventTemplate:
    event_id: str
    sequence: int
    occurred_at: datetime
    observed_at: datetime
    tenant_id: str
    resource_tenant: str
    principal_ref: str
    workload_id: str
    server_id: str
    artifact_digest: str
    capability_version: str
    trace_id: str
    span_id: str
    operation_id: str
    kind: EventKind
    action: str
    resource_id: str
    destination: str
    policy_version: str
    policy_decision: str
    outcome: Outcome
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SignedEvent:
    schema_version: str
    emitter_id: str
    event: EventTemplate
    signature: str

    def signed_payload(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "emitter_id": self.emitter_id, "event": self.event}


@dataclass(frozen=True)
class ProducerBinding:
    emitter_id: str
    public_key: bytes
    tenant_ids: frozenset[str]
    workload_ids: frozenset[str]
    event_kinds: frozenset[EventKind]


class EventEmitter:
    """A trusted adapter that signs the exact event envelope."""

    def __init__(self, emitter_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        _require_safe("emitter_id", emitter_id)
        self.emitter_id = emitter_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> bytes:
        return public_key_bytes(self.private_key.public_key())

    def emit(self, event: EventTemplate, schema_version: str = SCHEMA_VERSION) -> SignedEvent:
        unsigned = {"schema_version": schema_version, "emitter_id": self.emitter_id, "event": event}
        return SignedEvent(schema_version, self.emitter_id, event, self.private_key.sign(canonical_json(unsigned)).hex())


@dataclass(frozen=True)
class InventoryRecord:
    server_id: str
    workload_id: str
    artifact_digest: str
    capability_version: str
    tenant_ids: frozenset[str]
    allowed_actions: frozenset[str]
    allowed_destinations: frozenset[str]
    owner: str
    soc_route: str
    active: bool = True


class TrustedInventory:
    def __init__(self, records: Iterable[InventoryRecord]) -> None:
        self.records = {item.server_id: item for item in records}
        if not self.records:
            raise ValueError("inventory must not be empty")

    def lookup(self, server_id: str) -> InventoryRecord:
        try:
            return self.records[server_id]
        except KeyError as exc:
            raise SOCError("SERVER_UNKNOWN", "server is absent from trusted inventory") from exc


@dataclass(frozen=True)
class NormalizedEvent:
    schema_version: str
    event_id: str
    event_digest: str
    emitter_id: str
    sequence: int
    occurred_at: datetime
    observed_at: datetime
    tenant_id: str
    resource_tenant: str
    principal_ref: str
    workload_id: str
    server_id: str
    artifact_digest: str
    capability_version: str
    trace_id: str
    span_id: str
    operation_id: str
    kind: EventKind
    action: str
    resource_id: str
    destination: str
    policy_version: str
    policy_decision: str
    outcome: Outcome
    owner: str
    soc_route: str
    artifact_matches: bool
    capability_matches: bool
    policy_matches: bool
    action_approved: bool
    destination_approved: bool
    attributes: tuple[tuple[str, str], ...]

    def otel_log_projection(self) -> dict[str, Any]:
        """Map to stable OTel log-model concepts without claiming a vendor schema."""
        return {
            "Timestamp": self.occurred_at,
            "ObservedTimestamp": self.observed_at,
            "TraceId": self.trace_id,
            "SpanId": self.span_id,
            "EventName": f"mcp.security.{self.kind}",
            "Resource": {"service.name": self.server_id, "service.instance.id": self.workload_id},
            "Attributes": {
                "mcp.security.event_id": self.event_id,
                "mcp.security.tenant_id": self.tenant_id,
                "mcp.security.operation_id": self.operation_id,
                "mcp.security.action": self.action,
                "mcp.security.outcome": str(self.outcome),
                "mcp.security.policy.version": self.policy_version,
            },
        }

    def ocsf_projection(self) -> dict[str, Any]:
        """Illustrative mapping layer; validate against the deployed OCSF release."""
        return {
            "metadata": {"version": "deployment-selected", "product": {"name": self.server_id}},
            "time": int(self.occurred_at.timestamp() * 1000),
            "activity_name": str(self.kind),
            "status": str(self.outcome),
            "actor": {"user": {"uid": self.principal_ref}},
            "cloud": {"account": {"uid": self.tenant_id}},
            "unmapped": {
                "mcp_event_id": self.event_id,
                "mcp_artifact_digest": self.artifact_digest,
                "mcp_operation_id": self.operation_id,
            },
        }


class EventNormalizer:
    """Authenticate, validate, minimize, and enrich one producer event."""

    def __init__(self, bindings: Iterable[ProducerBinding], inventory: TrustedInventory) -> None:
        self.bindings = {item.emitter_id: item for item in bindings}
        self.inventory = inventory

    def normalize(self, envelope: SignedEvent, received_at: datetime) -> NormalizedEvent:
        if envelope.schema_version != SCHEMA_VERSION:
            raise SOCError("SCHEMA_UNSUPPORTED", "event schema is not admitted")
        binding = self.bindings.get(envelope.emitter_id)
        if binding is None:
            raise SOCError("EMITTER_UNKNOWN", "event emitter is not registered")
        try:
            Ed25519PublicKey.from_public_bytes(binding.public_key).verify(
                bytes.fromhex(envelope.signature), canonical_json(envelope.signed_payload())
            )
        except (InvalidSignature, ValueError) as exc:
            raise SOCError("SIGNATURE_INVALID", "event signature does not verify") from exc

        event = envelope.event
        for label, value in (
            ("event_id", event.event_id), ("tenant_id", event.tenant_id),
            ("resource_tenant", event.resource_tenant), ("principal_ref", event.principal_ref),
            ("workload_id", event.workload_id), ("server_id", event.server_id),
            ("operation_id", event.operation_id), ("action", event.action),
            ("resource_id", event.resource_id),
            ("capability_version", event.capability_version),
            ("policy_version", event.policy_version),
        ):
            _require_safe(label, value)
        if event.destination and (
            len(event.destination) > 253
            or "\n" in event.destination
            or "\r" in event.destination
            or not re.fullmatch(r"[A-Za-z0-9.-]+", event.destination)
        ):
            raise SOCError("DESTINATION_INVALID", "destination must be a bounded hostname")
        if event.policy_decision not in {"allow", "deny", "not_applicable"}:
            raise SOCError("POLICY_DECISION_INVALID", "policy decision is outside the event contract")
        if event.sequence < 1:
            raise SOCError("SEQUENCE_INVALID", "producer sequence must be positive")
        if not TRACE_ID.fullmatch(event.trace_id) or not SPAN_ID.fullmatch(event.span_id):
            raise SOCError("TRACE_CONTEXT_INVALID", "trace and span IDs must be lowercase W3C-sized hex")
        if not DIGEST.fullmatch(event.artifact_digest):
            raise SOCError("ARTIFACT_DIGEST_INVALID", "artifact digest must be sha256:<64 lowercase hex>")
        if event.occurred_at.tzinfo is None or event.observed_at.tzinfo is None or received_at.tzinfo is None:
            raise SOCError("TIME_INVALID", "timestamps must be timezone-aware")
        occurred = event.occurred_at.astimezone(UTC)
        observed = event.observed_at.astimezone(UTC)
        received = received_at.astimezone(UTC)
        if occurred > observed + MAX_CLOCK_SKEW or observed > received + MAX_CLOCK_SKEW:
            raise SOCError("CLOCK_SKEW_EXCEEDED", "event timestamps are implausibly in the future")
        if received - observed > MAX_INGEST_DELAY:
            raise SOCError("INGEST_DELAY_EXCEEDED", "event arrived outside the admitted delay")
        if event.tenant_id not in binding.tenant_ids or event.workload_id not in binding.workload_ids:
            raise SOCError("PRODUCER_SCOPE_MISMATCH", "producer binding does not cover tenant or workload")
        if event.kind not in binding.event_kinds:
            raise SOCError("EVENT_KIND_FORBIDDEN", "producer is not authorized to attest this event kind")
        if len(event.attributes) > 16:
            raise SOCError("ATTRIBUTES_EXCESSIVE", "event has too many custom attributes")
        seen: set[str] = set()
        for key, value in event.attributes:
            normalized_key = key.strip().lower()
            if normalized_key in seen:
                raise SOCError("ATTRIBUTE_DUPLICATE", "custom attribute keys must be unique")
            seen.add(normalized_key)
            if normalized_key in FORBIDDEN_ATTRIBUTE_NAMES or any(
                token in normalized_key for token in ("token", "password", "secret", "prompt")
            ):
                raise SOCError("SENSITIVE_ATTRIBUTE", "sensitive or model-content fields are forbidden")
            if len(key) > 64 or len(value) > 256 or "\n" in value or "\r" in value:
                raise SOCError("ATTRIBUTE_INVALID", "attribute is too large or contains log delimiters")

        record = self.inventory.lookup(event.server_id)
        if not record.active:
            raise SOCError("SERVER_INACTIVE", "server is inactive in trusted inventory")
        if event.tenant_id not in record.tenant_ids:
            raise SOCError("TENANT_NOT_IN_INVENTORY", "trusted inventory does not bind server to tenant")
        if event.workload_id != record.workload_id:
            raise SOCError("WORKLOAD_INVENTORY_MISMATCH", "observed workload does not match server inventory")
        return NormalizedEvent(
            envelope.schema_version, event.event_id, digest(envelope.signed_payload()), envelope.emitter_id,
            event.sequence, occurred, observed, event.tenant_id, event.resource_tenant,
            event.principal_ref, event.workload_id, event.server_id, event.artifact_digest,
            event.capability_version, event.trace_id, event.span_id, event.operation_id,
            event.kind, event.action, event.resource_id, event.destination, event.policy_version,
            event.policy_decision, event.outcome, record.owner, record.soc_route,
            event.artifact_digest == record.artifact_digest,
            event.capability_version == record.capability_version,
            event.policy_version == POLICY_VERSION,
            event.action in record.allowed_actions,
            not event.destination or event.destination in record.allowed_destinations,
            event.attributes,
        )


@dataclass(frozen=True)
class IngestResult:
    status: str
    event: NormalizedEvent


class EventStore:
    """Bounded, tenant-partitioned store with explicit replay/conflict behavior."""

    def __init__(self, max_events: int = MAX_PARTITION_EVENTS) -> None:
        if max_events < 3:
            raise ValueError("max_events must permit correlation")
        self.max_events = max_events
        self.partitions: dict[str, deque[NormalizedEvent]] = defaultdict(lambda: deque(maxlen=max_events))
        self.identities: dict[tuple[str, str], str] = {}
        self.identity_order: dict[str, deque[tuple[str, str]]] = defaultdict(deque)

    def ingest(self, event: NormalizedEvent) -> IngestResult:
        key = (event.tenant_id, event.event_id)
        previous = self.identities.get(key)
        if previous == event.event_digest:
            return IngestResult("duplicate", event)
        if previous is not None:
            raise SOCError("EVENT_ID_CONFLICT", "event ID was replayed with different signed content")
        order = self.identity_order[event.tenant_id]
        if len(order) >= self.max_events:
            evicted = order.popleft()
            self.identities.pop(evicted, None)
        self.identities[key] = event.event_digest
        order.append(key)
        self.partitions[event.tenant_id].append(event)
        return IngestResult("accepted", event)

    def recent(self, tenant_id: str, at: datetime, window: timedelta = CORRELATION_WINDOW) -> tuple[NormalizedEvent, ...]:
        lower = at - window
        upper = at + LATE_EVENT_ALLOWANCE
        return tuple(item for item in self.partitions[tenant_id] if lower <= item.occurred_at <= upper)

    def contains(self, tenant_id: str, event_id: str) -> bool:
        return (tenant_id, event_id) in self.identities


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    version: str
    title: str
    severity: Severity
    playbook: str


RULES = {
    "artifact_drift": DetectionRule("MCP-SOC-001", "1.0.0", "Unapproved MCP artifact", Severity.CRITICAL, "PB-MCP-SUPPLY-CHAIN"),
    "contract_drift": DetectionRule("MCP-SOC-002", "1.0.0", "MCP capability contract drift", Severity.HIGH, "PB-MCP-CONTRACT"),
    "unapproved_egress": DetectionRule("MCP-SOC-003", "1.1.0", "Unapproved MCP egress", Severity.HIGH, "PB-MCP-EGRESS"),
    "cross_tenant": DetectionRule("MCP-SOC-004", "1.0.0", "Cross-tenant resource effect", Severity.CRITICAL, "PB-MCP-TENANT"),
    "decision_effect_mismatch": DetectionRule("MCP-SOC-005", "1.0.0", "Denied operation produced an effect", Severity.CRITICAL, "PB-MCP-AUTHZ"),
    "repeated_denials": DetectionRule("MCP-SOC-006", "1.0.0", "Repeated denied MCP operations", Severity.MEDIUM, "PB-MCP-CREDENTIAL"),
    "unverified_effect": DetectionRule("MCP-SOC-007", "1.0.0", "High-risk effect lacks resource outcome", Severity.HIGH, "PB-MCP-OUTCOME"),
}


@dataclass(frozen=True)
class Alert:
    alert_id: str
    fingerprint: str
    rule_id: str
    rule_version: str
    title: str
    severity: Severity
    tenant_id: str
    server_id: str
    workload_id: str
    trace_id: str
    operation_id: str
    evidence_event_ids: tuple[str, ...]
    evidence_digest: str
    reason_codes: tuple[str, ...]
    playbook: str
    route: str
    detected_at: datetime
    state: AlertState = AlertState.CANDIDATE


class DetectionEngine:
    """Deterministic rules emit candidates; they do not authorize response."""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.emitted: set[tuple[str, str, tuple[str, ...]]] = set()

    def _alert(self, rule: DetectionRule, event: NormalizedEvent, evidence: Iterable[NormalizedEvent], now: datetime, reasons: Iterable[str]) -> Alert | None:
        evidence_list = sorted(evidence, key=lambda item: (item.occurred_at, item.event_id))
        evidence_ids = tuple(item.event_id for item in evidence_list)
        dedupe_key = (event.tenant_id, rule.rule_id, evidence_ids)
        if dedupe_key in self.emitted:
            return None
        if not evidence_ids or any(not self.store.contains(event.tenant_id, event_id) for event_id in evidence_ids):
            raise SOCError("ALERT_EVIDENCE_MISSING", "alert must cite admitted events in the same tenant")
        self.emitted.add(dedupe_key)
        evidence_digest = digest([item.event_digest for item in evidence_list])
        fingerprint = digest({"tenant": event.tenant_id, "server": event.server_id, "rule": rule.rule_id, "operation": event.operation_id})
        alert_id = "ALT-" + sha256(canonical_json({"fingerprint": fingerprint, "evidence": evidence_ids})).hexdigest()[:20]
        return Alert(
            alert_id, fingerprint, rule.rule_id, rule.version, rule.title, rule.severity,
            event.tenant_id, event.server_id, event.workload_id, event.trace_id,
            event.operation_id, evidence_ids, evidence_digest, tuple(sorted(set(reasons))),
            rule.playbook, event.soc_route, now,
        )

    def evaluate(self, event: NormalizedEvent, now: datetime) -> tuple[Alert, ...]:
        candidates: list[Alert | None] = []
        if not event.artifact_matches:
            candidates.append(self._alert(RULES["artifact_drift"], event, [event], now, ["ARTIFACT_NOT_APPROVED"]))
        if not event.capability_matches or not event.policy_matches or not event.action_approved:
            candidates.append(self._alert(RULES["contract_drift"], event, [event], now, ["CAPABILITY_POLICY_OR_ACTION_DRIFT"]))
        if event.kind == EventKind.NETWORK and not event.destination_approved:
            candidates.append(self._alert(RULES["unapproved_egress"], event, [event], now, ["DESTINATION_NOT_APPROVED"]))
        if event.kind == EventKind.RESOURCE and event.resource_tenant != event.tenant_id:
            candidates.append(self._alert(RULES["cross_tenant"], event, [event], now, ["RESOURCE_TENANT_MISMATCH"]))

        recent = self.store.recent(event.tenant_id, event.occurred_at)
        same_operation = [item for item in recent if item.operation_id == event.operation_id and item.server_id == event.server_id]
        denied = [item for item in same_operation if item.kind == EventKind.POLICY and item.outcome == Outcome.DENIED]
        effects = [item for item in same_operation if item.kind in {EventKind.NETWORK, EventKind.RESOURCE} and item.outcome == Outcome.SUCCEEDED]
        if denied and effects:
            candidates.append(self._alert(RULES["decision_effect_mismatch"], event, denied + effects, now, ["DENY_EFFECT_MISMATCH"]))

        principal_denials = [
            item for item in recent
            if item.principal_ref == event.principal_ref and item.server_id == event.server_id
            and item.kind == EventKind.POLICY and item.outcome == Outcome.DENIED
        ]
        if len(principal_denials) >= 3:
            candidates.append(self._alert(RULES["repeated_denials"], event, principal_denials[-3:], now, ["DENIAL_THRESHOLD_EXCEEDED"]))

        high_risk_call = [
            item for item in same_operation
            if item.kind == EventKind.TOOL_CALL and item.action in {"ticket.export", "ticket.update"}
            and item.outcome == Outcome.ALLOWED
        ]
        resource_outcome = [item for item in same_operation if item.kind == EventKind.RESOURCE]
        if high_risk_call and not resource_outcome and now - high_risk_call[0].occurred_at >= timedelta(seconds=30):
            candidates.append(self._alert(RULES["unverified_effect"], event, high_risk_call, now, ["RESOURCE_OUTCOME_MISSING"]))
        return tuple(candidate for candidate in candidates if candidate is not None)


@dataclass(frozen=True)
class SOCCase:
    case_id: str
    alert_id: str
    fingerprint: str
    tenant_id: str
    severity: Severity
    route: str
    playbook: str
    evidence_event_ids: tuple[str, ...]
    opened_at: datetime
    state: CaseState = CaseState.OPEN


class CaseRouter:
    """Create cases idempotently and suppress only exact bounded duplicates."""

    def __init__(self, allowed_routes: Mapping[str, str]) -> None:
        self.allowed_routes = dict(allowed_routes)
        self.cases: dict[str, SOCCase] = {}
        self.by_alert: dict[str, str] = {}
        self.last_by_fingerprint: dict[str, tuple[str, datetime]] = {}
        self.lock = Lock()

    def route(self, alert: Alert, now: datetime) -> SOCCase:
        expected_route = self.allowed_routes.get(alert.tenant_id)
        if expected_route is None or alert.route != expected_route:
            raise SOCError("SOC_ROUTE_INVALID", "alert route does not match trusted tenant routing")
        if not alert.evidence_event_ids:
            raise SOCError("CASE_EVIDENCE_EMPTY", "case requires alert evidence")
        with self.lock:
            existing_id = self.by_alert.get(alert.alert_id)
            if existing_id:
                return self.cases[existing_id]
            prior = self.last_by_fingerprint.get(alert.fingerprint)
            if prior and now - prior[1] <= SUPPRESSION_WINDOW and alert.severity != Severity.CRITICAL:
                self.by_alert[alert.alert_id] = prior[0]
                return self.cases[prior[0]]
            case_id = "CASE-" + sha256(canonical_json({"alert": alert.alert_id, "route": alert.route})).hexdigest()[:20]
            case = SOCCase(case_id, alert.alert_id, alert.fingerprint, alert.tenant_id, alert.severity, alert.route, alert.playbook, alert.evidence_event_ids, now)
            self.cases[case_id] = case
            self.by_alert[alert.alert_id] = case_id
            self.last_by_fingerprint[alert.fingerprint] = (case_id, now)
            return case

    def transition(self, case_id: str, expected: CaseState, target: CaseState) -> SOCCase:
        allowed = {
            CaseState.OPEN: {CaseState.ACKNOWLEDGED},
            CaseState.ACKNOWLEDGED: {CaseState.RESPONSE_PENDING, CaseState.CLOSED},
            CaseState.RESPONSE_PENDING: {CaseState.CONTAINED},
            CaseState.CONTAINED: {CaseState.CLOSED},
        }
        with self.lock:
            case = self.cases[case_id]
            if case.state != expected or target not in allowed.get(expected, set()):
                raise SOCError("CASE_TRANSITION_INVALID", "case state changed or transition is forbidden")
            updated = replace(case, state=target)
            self.cases[case_id] = updated
            return updated


@dataclass(frozen=True)
class ResponseProposal:
    proposal_id: str
    case_id: str
    tenant_id: str
    action: ActionKind
    target_id: str
    reason: str
    expected_state_version: int
    requested_by: str
    requested_at: datetime

    def payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    purpose: str
    proposal_digest: str
    approver_id: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


class ApprovalService:
    """Issue and atomically consume exact, short-lived response approvals."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.used: set[str] = set()
        self.lock = Lock()

    def issue(self, proposal: ResponseProposal, approver_id: str, role: str, now: datetime, ttl: timedelta = timedelta(minutes=5)) -> ApprovalReceipt:
        if role not in {"incident_commander", "security_duty_manager"}:
            raise SOCError("APPROVER_ROLE_INVALID", "role cannot approve containment")
        if ttl <= timedelta(0) or ttl > timedelta(minutes=15):
            raise SOCError("APPROVAL_TTL_INVALID", "approval TTL is outside policy")
        receipt_id = "APR-" + sha256(canonical_json({"proposal": proposal.payload(), "approver": approver_id, "at": now})).hexdigest()[:20]
        unsigned = {
            "receipt_id": receipt_id, "purpose": "mcp_soc_containment",
            "proposal_digest": digest(proposal.payload()), "approver_id": approver_id,
            "approver_role": role, "issued_at": now, "expires_at": now + ttl,
        }
        return ApprovalReceipt(**unsigned, signature=self.private_key.sign(canonical_json(unsigned)).hex())

    def consume(self, receipt: ApprovalReceipt, proposal: ResponseProposal, now: datetime) -> None:
        try:
            self.private_key.public_key().verify(bytes.fromhex(receipt.signature), canonical_json(receipt.unsigned()))
        except (InvalidSignature, ValueError) as exc:
            raise SOCError("APPROVAL_SIGNATURE_INVALID", "approval signature does not verify") from exc
        if receipt.purpose != "mcp_soc_containment" or receipt.proposal_digest != digest(proposal.payload()):
            raise SOCError("APPROVAL_SCOPE_MISMATCH", "approval is not bound to this exact proposal")
        if now < receipt.issued_at or now >= receipt.expires_at:
            raise SOCError("APPROVAL_EXPIRED", "approval is not currently valid")
        with self.lock:
            if receipt.receipt_id in self.used:
                raise SOCError("APPROVAL_REPLAYED", "approval receipt was already consumed")
            self.used.add(receipt.receipt_id)


@dataclass(frozen=True)
class ControlState:
    target_id: str
    tenant_id: str
    enabled: bool
    version: int


@dataclass(frozen=True)
class ExecutionRecord:
    operation_id: str
    proposal_digest: str
    target_id: str
    status: ExecutionStatus
    state_version: int
    executed_at: datetime


@dataclass(frozen=True)
class VerificationRecord:
    operation_id: str
    target_id: str
    expected_enabled: bool
    observed_enabled: bool
    observed_version: int
    verified_at: datetime
    verifier_id: str

    @property
    def verified(self) -> bool:
        return self.expected_enabled == self.observed_enabled


class ContainmentController:
    """Apply an approved operation idempotently; never infer outcome from intent."""

    def __init__(self, approvals: ApprovalService, states: Iterable[ControlState]) -> None:
        self.approvals = approvals
        self.states = {item.target_id: item for item in states}
        self.operations: dict[str, ExecutionRecord] = {}
        self.lock = Lock()

    def execute(self, operation_id: str, proposal: ResponseProposal, receipt: ApprovalReceipt, now: datetime) -> ExecutionRecord:
        _require_safe("operation_id", operation_id)
        proposal_digest = digest(proposal.payload())
        with self.lock:
            previous = self.operations.get(operation_id)
            if previous:
                if previous.proposal_digest != proposal_digest:
                    raise SOCError("OPERATION_CONFLICT", "operation ID is bound to different intent")
                return replace(previous, status=ExecutionStatus.RECONCILED)
            state = self.states.get(proposal.target_id)
            if state is None or state.tenant_id != proposal.tenant_id:
                raise SOCError("TARGET_SCOPE_INVALID", "target is absent or belongs to another tenant")
            if state.version != proposal.expected_state_version:
                raise SOCError("STATE_VERSION_CONFLICT", "target changed after proposal review")
            if proposal.action not in {ActionKind.DISABLE_SERVER, ActionKind.QUARANTINE_WORKLOAD}:
                raise SOCError("ACTION_UNSUPPORTED", "lab controller does not own that action")
            self.approvals.consume(receipt, proposal, now)
            updated = replace(state, enabled=False, version=state.version + 1)
            self.states[state.target_id] = updated
            record = ExecutionRecord(operation_id, proposal_digest, state.target_id, ExecutionStatus.APPLIED, updated.version, now)
            self.operations[operation_id] = record
            return record


class IndependentVerifier:
    def verify_disabled(self, controller: ContainmentController, operation_id: str, target_id: str, now: datetime) -> VerificationRecord:
        state = controller.states[target_id]
        return VerificationRecord(operation_id, target_id, False, state.enabled, state.version, now, "control-plane-reader")


@dataclass(frozen=True)
class LabelledEpisode:
    episode_id: str
    malicious: bool
    valid_operation_count: int
    first_event_at: datetime
    detected_at: datetime | None
    routed: bool
    contained_verified: bool


def detection_metrics(episodes: Iterable[LabelledEpisode]) -> dict[str, float | int | None]:
    population = tuple(episodes)
    if not population:
        raise ValueError("labelled population must not be empty")
    tp = sum(item.malicious and item.detected_at is not None for item in population)
    fn = sum(item.malicious and item.detected_at is None for item in population)
    fp = sum((not item.malicious) and item.detected_at is not None for item in population)
    tn = sum((not item.malicious) and item.detected_at is None for item in population)
    valid_operations = sum(item.valid_operation_count for item in population if not item.malicious)
    latencies = [
        (item.detected_at - item.first_event_at).total_seconds()
        for item in population if item.malicious and item.detected_at is not None
    ]
    routed = sum(item.routed for item in population)
    verified = sum(item.contained_verified for item in population)
    return {
        "population": len(population), "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "true_negatives": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positives_per_1000_valid_operations": fp * 1000 / valid_operations if valid_operations else None,
        "median_detection_seconds": median(latencies) if latencies else None,
        "routing_rate": routed / len(population),
        "verified_containment_rate": verified / len(population),
    }


def instrumented_route(router: CaseRouter, alert: Alert, now: datetime, tracer: Any) -> SOCCase:
    """Create a real OTel span without putting tenant IDs or evidence in its name."""
    with tracer.start_as_current_span("mcp.soc.route") as span:
        span.set_attribute("mcp.soc.rule_id", alert.rule_id)
        span.set_attribute("mcp.soc.severity", str(alert.severity))
        span.set_attribute("mcp.soc.evidence_count", len(alert.evidence_event_ids))
        case = router.route(alert, now)
        span.set_attribute("mcp.soc.case_created", True)
        return case


def event_fixture(
    emitter: EventEmitter, *, event_id: str = "EV-001", sequence: int = 1,
    occurred_at: datetime = NOW, observed_at: datetime = NOW + timedelta(seconds=1),
    tenant_id: str = "tenant:acme", resource_tenant: str = "tenant:acme",
    principal_ref: str = "principal:hmac:alice", workload_id: str = "workload:support-prod",
    server_id: str = "server:support", artifact_digest: str = "sha256:" + "a" * 64,
    capability_version: str = "support-tools/7", trace_id: str = "1" * 32,
    span_id: str = "2" * 16, operation_id: str = "OP-001",
    kind: EventKind = EventKind.TOOL_CALL, action: str = "ticket.read",
    resource_id: str = "ticket:1234", destination: str = "tickets.example.com",
    policy_version: str = POLICY_VERSION, policy_decision: str = "allow",
    outcome: Outcome = Outcome.ALLOWED,
    attributes: tuple[tuple[str, str], ...] = (("risk.band", "low"),),
) -> SignedEvent:
    template = EventTemplate(
        event_id, sequence, occurred_at, observed_at, tenant_id, resource_tenant,
        principal_ref, workload_id, server_id, artifact_digest, capability_version,
        trace_id, span_id, operation_id, kind, action, resource_id, destination,
        policy_version, policy_decision, outcome, attributes,
    )
    return emitter.emit(template)


def demo_components() -> tuple[EventEmitter, EventNormalizer, EventStore, DetectionEngine, CaseRouter, ApprovalService, ContainmentController]:
    emitter = EventEmitter("gateway:prod")
    inventory = TrustedInventory([
        InventoryRecord(
            "server:support", "workload:support-prod", "sha256:" + "a" * 64,
            "support-tools/7", frozenset({"tenant:acme"}),
            frozenset({"ticket.read", "ticket.update", "ticket.export"}),
            frozenset({"tickets.example.com"}), "team:support-platform", "soc:acme",
        )
    ])
    binding = ProducerBinding(
        emitter.emitter_id, emitter.public_key, frozenset({"tenant:acme"}),
        frozenset({"workload:support-prod"}), frozenset(EventKind),
    )
    normalizer = EventNormalizer([binding], inventory)
    store = EventStore()
    detector = DetectionEngine(store)
    router = CaseRouter({"tenant:acme": "soc:acme"})
    approvals = ApprovalService()
    controller = ContainmentController(approvals, [ControlState("server:support", "tenant:acme", True, 7)])
    return emitter, normalizer, store, detector, router, approvals, controller


def main() -> None:
    emitter, normalizer, store, detector, router, approvals, controller = demo_components()
    signed = event_fixture(
        emitter, event_id="EV-EGRESS-001", kind=EventKind.NETWORK,
        action="ticket.export", destination="exfil.example", outcome=Outcome.SUCCEEDED,
    )
    normalized = normalizer.normalize(signed, NOW + timedelta(seconds=2))
    store.ingest(normalized)
    alert = next(item for item in detector.evaluate(normalized, NOW + timedelta(seconds=3)) if item.rule_id == "MCP-SOC-003")

    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "course-27-soc-integration"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("course-27")
    case = instrumented_route(router, alert, NOW + timedelta(seconds=4), tracer)
    case = router.transition(case.case_id, CaseState.OPEN, CaseState.ACKNOWLEDGED)
    case = router.transition(case.case_id, CaseState.ACKNOWLEDGED, CaseState.RESPONSE_PENDING)
    proposal = ResponseProposal(
        "PROP-001", case.case_id, case.tenant_id, ActionKind.DISABLE_SERVER,
        "server:support", "unapproved egress with signed network evidence", 7,
        "analyst:oncall", NOW + timedelta(seconds=5),
    )
    receipt = approvals.issue(proposal, "commander:oncall", "incident_commander", NOW + timedelta(seconds=6))
    execution = controller.execute("EXEC-001", proposal, receipt, NOW + timedelta(seconds=7))
    verification = IndependentVerifier().verify_disabled(controller, execution.operation_id, execution.target_id, NOW + timedelta(seconds=8))
    if not verification.verified:
        raise RuntimeError("containment did not reach independently observed state")
    case = router.transition(case.case_id, CaseState.RESPONSE_PENDING, CaseState.CONTAINED)
    provider.force_flush()
    print(json.dumps({
        "alert": alert.rule_id, "case": case.case_id, "case_state": case.state,
        "evidence": alert.evidence_event_ids, "execution": execution.status,
        "verified": verification.verified, "otel_spans": len(exporter.get_finished_spans()),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
