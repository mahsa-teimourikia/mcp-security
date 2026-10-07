"""Course 16: secure runtime observability and continuous assurance.

The credential-free lab emits privacy-minimized, tamper-evident MCP security
events, validates them at a collector boundary, reconstructs traces, turns
deterministic findings into bounded controls, and evaluates the detector on a
labelled corpus. It also creates real in-memory OpenTelemetry spans; it never
contacts a telemetry backend or treats telemetry as authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import hmac
import json
import math
import re
from typing import Any, Iterable

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


UTC = timezone.utc
SCHEMA_VERSION = "mcp.security.event/1.0"
PROTOCOL_VERSION = "2026-07-28"
POLICY_VERSION = "runtime-assurance/2026-10-04"
REVIEWED_SERVER_DIGEST = "sha256:" + sha256(b"support-mcp-server@3.2.0").hexdigest()
REVIEWED_CONTRACT_DIGEST = "sha256:" + sha256(b"support-tools-contract@8").hexdigest()
PSEUDONYM_KEY = b"course-16-pseudonym-key"
SIGNING_KEY = b"course-16-event-signing-key"
MAX_EVENT_BYTES = 8_192
MAX_CLOCK_SKEW = timedelta(seconds=5)
MAX_INGESTION_DELAY = timedelta(minutes=5)
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
EVENT_ID = re.compile(r"^evt-[a-z0-9-]{1,48}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
KEYED_DIGEST = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
FORBIDDEN_ATTRIBUTE_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "client_secret",
        "cookie",
        "id_token",
        "api_key",
        "password",
        "refresh_token",
        "set_cookie",
        "token",
        "x_api_key",
    }
)


def matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return parsed.astimezone(UTC)


def _jsonable(value: Any) -> Any:
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
    return f"sha256:{sha256(payload).hexdigest()}"


def keyed_digest(value: str, key: bytes = PSEUDONYM_KEY) -> str:
    return f"hmac-sha256:{hmac.new(key, value.encode(), sha256).hexdigest()}"


class Phase(StrEnum):
    REQUEST = "request"
    POLICY = "policy"
    EFFECT = "effect"
    RESULT = "result"


class PolicyDecision(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    ALLOW = "allow"
    DENY = "deny"


class Outcome(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    ERROR = "error"


class Risk(StrEnum):
    READ = "read"
    EXTERNAL_WRITE = "external_write"
    ADMIN = "admin"


class ControlAction(StrEnum):
    NONE = "none"
    REVIEW = "review"
    QUARANTINE = "quarantine"
    REVOKE = "revoke"


class Severity(StrEnum):
    INFO = "info"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IngestStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class TrustedIdentity:
    principal_id: str
    tenant_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class SecurityEvent:
    schema_version: str
    event_id: str
    emitter_id: str
    sequence: int
    occurred_at: datetime
    trace_id: str
    span_id: str
    parent_span_id: str | None
    phase: Phase
    operation_id: str
    principal_pseudonym: str
    tenant_pseudonym: str
    server_digest: str
    server_version: str
    tool_name: str
    tool_contract_digest: str
    risk: Risk
    destination_digest: str | None
    argument_digest: str
    policy_version: str
    policy_decision: PolicyDecision
    reason_code: str
    outcome: Outcome
    duration_ms: int
    input_tokens: int
    output_tokens: int
    cost_microusd: int
    previous_event_hash: str | None
    event_hash: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("event_hash")
        result.pop("signature")
        return result


@dataclass(frozen=True)
class EventTemplate:
    event_id: str
    occurred_at: datetime
    trace_id: str
    span_id: str
    parent_span_id: str | None
    phase: Phase
    operation_id: str
    server_digest: str
    server_version: str
    tool_name: str
    tool_contract_digest: str
    risk: Risk
    destination: str | None
    arguments: dict[str, Any]
    policy_decision: PolicyDecision
    reason_code: str
    outcome: Outcome
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_microusd: int = 0


class TelemetryEmitter:
    """Trusted application emitter; raw values are minimized before export."""

    def __init__(
        self,
        emitter_id: str,
        identity: TrustedIdentity,
        *,
        signing_key: bytes = SIGNING_KEY,
    ) -> None:
        if not matches(SAFE_NAME, emitter_id):
            raise ValueError("invalid emitter ID")
        self.emitter_id = emitter_id
        self.identity = identity
        self.signing_key = signing_key
        self.sequence = 0
        self.previous_event_hash: str | None = None

    @staticmethod
    def _validate_arguments(arguments: dict[str, Any]) -> None:
        if not isinstance(arguments, dict):
            raise ValueError("arguments must be an object")
        def keys(value: Any) -> set[str]:
            if isinstance(value, dict):
                found = {
                    key.casefold().replace("-", "_")
                    for key in value
                    if isinstance(key, str)
                }
                for child in value.values():
                    found.update(keys(child))
                return found
            if isinstance(value, (list, tuple)):
                found: set[str] = set()
                for child in value:
                    found.update(keys(child))
                return found
            return set()

        if keys(arguments) & FORBIDDEN_ATTRIBUTE_KEYS:
            raise ValueError("secret-bearing field cannot enter the telemetry pipeline")
        if len(canonical_json(arguments)) > 2_048:
            raise ValueError("argument digest input exceeds telemetry budget")

    def emit(self, template: EventTemplate) -> SecurityEvent:
        self._validate_arguments(template.arguments)
        self.sequence += 1
        unsigned = {
            "schema_version": SCHEMA_VERSION,
            "event_id": template.event_id,
            "emitter_id": self.emitter_id,
            "sequence": self.sequence,
            "occurred_at": template.occurred_at,
            "trace_id": template.trace_id,
            "span_id": template.span_id,
            "parent_span_id": template.parent_span_id,
            "phase": template.phase,
            "operation_id": template.operation_id,
            "principal_pseudonym": keyed_digest(self.identity.principal_id),
            "tenant_pseudonym": keyed_digest(self.identity.tenant_id),
            "server_digest": template.server_digest,
            "server_version": template.server_version,
            "tool_name": template.tool_name,
            "tool_contract_digest": template.tool_contract_digest,
            "risk": template.risk,
            "destination_digest": (
                keyed_digest(template.destination) if template.destination is not None else None
            ),
            "argument_digest": digest(template.arguments),
            "policy_version": POLICY_VERSION,
            "policy_decision": template.policy_decision,
            "reason_code": template.reason_code,
            "outcome": template.outcome,
            "duration_ms": template.duration_ms,
            "input_tokens": template.input_tokens,
            "output_tokens": template.output_tokens,
            "cost_microusd": template.cost_microusd,
            "previous_event_hash": self.previous_event_hash,
        }
        event_hash = digest(unsigned)
        signature = hmac.new(self.signing_key, event_hash.encode(), sha256).hexdigest()
        event = SecurityEvent(**unsigned, event_hash=event_hash, signature=signature)
        if len(canonical_json(asdict(event))) > MAX_EVENT_BYTES:
            raise ValueError("security event exceeds byte budget")
        self.previous_event_hash = event_hash
        return event


@dataclass(frozen=True)
class IngestResult:
    status: IngestStatus
    reason_code: str
    event_id: str
    ingestion_delay_ms: int | None


class SecureCollector:
    """Validates source evidence before accepting it into the assurance store."""

    def __init__(self, *, signing_keys: dict[str, bytes] | None = None) -> None:
        self.signing_keys = (
            {"support.host": SIGNING_KEY} if signing_keys is None else signing_keys
        )
        self.events: list[SecurityEvent] = []
        self.rejections: list[IngestResult] = []
        self._last_by_emitter: dict[str, tuple[int, str]] = {}
        self._event_ids: set[str] = set()

    @staticmethod
    def _schema_error(event: SecurityEvent) -> str | None:
        if event.schema_version != SCHEMA_VERSION:
            return "SCHEMA_VERSION_UNSUPPORTED"
        if (
            not isinstance(event.occurred_at, datetime)
            or event.occurred_at.tzinfo is None
            or event.occurred_at.utcoffset() != timedelta(0)
        ):
            return "TIMESTAMP_INVALID"
        if not matches(EVENT_ID, event.event_id) or not matches(SAFE_NAME, event.emitter_id):
            return "IDENTIFIER_INVALID"
        if not matches(TRACE_ID, event.trace_id) or not matches(SPAN_ID, event.span_id):
            return "TRACE_CONTEXT_INVALID"
        if event.parent_span_id is not None and not matches(SPAN_ID, event.parent_span_id):
            return "TRACE_CONTEXT_INVALID"
        if not matches(DIGEST, event.server_digest) or not matches(
            DIGEST,
            event.tool_contract_digest
        ):
            return "ARTIFACT_DIGEST_INVALID"
        if not matches(KEYED_DIGEST, event.principal_pseudonym) or not matches(
            KEYED_DIGEST,
            event.tenant_pseudonym
        ):
            return "PSEUDONYM_INVALID"
        if event.destination_digest is not None and not matches(
            KEYED_DIGEST,
            event.destination_digest
        ):
            return "DESTINATION_DIGEST_INVALID"
        if (
            not matches(DIGEST, event.argument_digest)
            or not matches(DIGEST, event.event_hash)
            or not matches(SIGNATURE, event.signature)
        ):
            return "EVENT_INTEGRITY_FIELD_INVALID"
        if not matches(SAFE_NAME, event.tool_name) or not matches(
            REASON_CODE,
            event.reason_code
        ):
            return "ATTRIBUTE_INVALID"
        if (
            type(event.sequence) is not int
            or event.sequence < 1
            or not isinstance(event.operation_id, str)
            or not 1 <= len(event.operation_id) <= 64
            or not isinstance(event.policy_version, str)
            or not 1 <= len(event.policy_version) <= 64
            or not isinstance(event.server_version, str)
            or not 1 <= len(event.server_version) <= 32
        ):
            return "ATTRIBUTE_INVALID"
        if not all(
            isinstance(value, enum_type)
            for value, enum_type in (
                (event.phase, Phase),
                (event.policy_decision, PolicyDecision),
                (event.outcome, Outcome),
                (event.risk, Risk),
            )
        ):
            return "ATTRIBUTE_INVALID"
        measurements = (
            event.duration_ms,
            event.input_tokens,
            event.output_tokens,
            event.cost_microusd,
        )
        if any(type(value) is not int or value < 0 for value in measurements):
            return "MEASUREMENT_INVALID"
        return None

    def ingest(self, event: SecurityEvent, observed_at: datetime) -> IngestResult:
        schema_error = self._schema_error(event)
        if schema_error:
            return self._reject(event, schema_error)
        if event.event_id in self._event_ids:
            return self._reject(event, "EVENT_REPLAY")
        if event.occurred_at - observed_at > MAX_CLOCK_SKEW:
            return self._reject(event, "EVENT_FROM_FUTURE")
        delay = observed_at - event.occurred_at
        if delay > MAX_INGESTION_DELAY:
            return self._reject(event, "EVENT_TOO_OLD")
        if delay < -MAX_CLOCK_SKEW:
            return self._reject(event, "EVENT_FROM_FUTURE")
        signing_key = self.signing_keys.get(event.emitter_id)
        if signing_key is None:
            return self._reject(event, "EMITTER_NOT_TRUSTED")
        if digest(event.unsigned()) != event.event_hash:
            return self._reject(event, "EVENT_HASH_INVALID")
        expected_signature = hmac.new(signing_key, event.event_hash.encode(), sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, event.signature):
            return self._reject(event, "EVENT_SIGNATURE_INVALID")
        previous = self._last_by_emitter.get(event.emitter_id)
        if previous is None:
            if event.sequence != 1 or event.previous_event_hash is not None:
                return self._reject(event, "EVENT_CHAIN_INVALID")
        elif event.sequence != previous[0] + 1 or event.previous_event_hash != previous[1]:
            return self._reject(event, "EVENT_CHAIN_INVALID")
        self._event_ids.add(event.event_id)
        self._last_by_emitter[event.emitter_id] = (event.sequence, event.event_hash)
        self.events.append(event)
        return IngestResult(
            IngestStatus.ACCEPTED,
            "EVENT_ACCEPTED",
            event.event_id,
            max(0, round(delay.total_seconds() * 1_000)),
        )

    def _reject(self, event: SecurityEvent, reason: str) -> IngestResult:
        result = IngestResult(IngestStatus.REJECTED, reason, event.event_id, None)
        self.rejections.append(result)
        return result


@dataclass(frozen=True)
class TraceFinding:
    trace_id: str
    complete: bool
    violations: tuple[str, ...]
    duration_ms: int | None


class TraceVerifier:
    """Reconstructs application-owned outcomes from accepted event evidence."""

    def review(self, events: Iterable[SecurityEvent]) -> TraceFinding:
        ordered = tuple(sorted(events, key=lambda event: (event.occurred_at, event.sequence)))
        if not ordered:
            return TraceFinding("unknown", False, ("TRACE_EMPTY",), None)
        trace_id = ordered[0].trace_id
        violations: list[str] = []
        if any(event.trace_id != trace_id for event in ordered):
            violations.append("MIXED_TRACE_IDS")
        phases = tuple(event.phase for event in ordered)
        expected_prefix = (Phase.REQUEST, Phase.POLICY)
        if phases[:2] != expected_prefix or phases[-1:] != (Phase.RESULT,):
            violations.append("TRACE_PHASE_ORDER_INVALID")
        if phases.count(Phase.REQUEST) != 1 or phases.count(Phase.POLICY) != 1:
            violations.append("TRACE_CARDINALITY_INVALID")
        if phases.count(Phase.RESULT) != 1 or phases.count(Phase.EFFECT) > 1:
            violations.append("TRACE_CARDINALITY_INVALID")
        stable_fields = {
            (
                event.operation_id,
                event.principal_pseudonym,
                event.tenant_pseudonym,
                event.server_digest,
                event.server_version,
                event.tool_name,
                event.tool_contract_digest,
                event.risk,
                event.destination_digest,
                event.argument_digest,
                event.policy_version,
            )
            for event in ordered
        }
        if len(stable_fields) != 1:
            violations.append("TRACE_CONTEXT_DRIFT")
        root = ordered[0]
        if root.parent_span_id is not None:
            violations.append("TRACE_ROOT_HAS_PARENT")
        if any(event.parent_span_id != root.span_id for event in ordered[1:]):
            violations.append("TRACE_PARENT_INVALID")
        policies = [event for event in ordered if event.phase == Phase.POLICY]
        results = [event for event in ordered if event.phase == Phase.RESULT]
        effects = [event for event in ordered if event.phase == Phase.EFFECT]
        if len(policies) == 1 and len(results) == 1:
            decision = policies[0].policy_decision
            result = results[0]
            if decision == PolicyDecision.DENY and effects:
                violations.append("EFFECT_AFTER_DENY")
            if decision == PolicyDecision.DENY and result.outcome != Outcome.BLOCKED:
                violations.append("DENIAL_OUTCOME_MISMATCH")
            if decision == PolicyDecision.ALLOW and result.outcome == Outcome.COMPLETED and not effects:
                violations.append("EFFECT_EVIDENCE_MISSING")
            if decision == PolicyDecision.ALLOW and result.outcome == Outcome.BLOCKED:
                violations.append("ALLOW_OUTCOME_MISMATCH")
        duration_ms = max(event.duration_ms for event in ordered) if ordered else None
        return TraceFinding(trace_id, not violations, tuple(dict.fromkeys(violations)), duration_ms)


@dataclass(frozen=True)
class Signal:
    signal_id: str
    trace_id: str
    severity: Severity
    action: ControlAction
    reason_code: str
    target_digest: str | None
    detected_at: datetime


@dataclass(frozen=True)
class AssuranceConfig:
    reviewed_server_digest: str
    reviewed_contract_digest: str
    allowed_destination_digests: frozenset[str]
    denial_review_threshold: int = 3


class AssuranceEngine:
    """Creates bounded risk signals; it never grants execution authority."""

    def __init__(self, config: AssuranceConfig) -> None:
        self.config = config
        self._denials: dict[str, int] = {}

    def assess_event(self, event: SecurityEvent, detected_at: datetime) -> Signal | None:
        if event.server_digest != self.config.reviewed_server_digest:
            return self._signal(event, Severity.CRITICAL, ControlAction.QUARANTINE,
                                "SERVER_ARTIFACT_DRIFT", detected_at)
        if event.tool_contract_digest != self.config.reviewed_contract_digest:
            return self._signal(event, Severity.CRITICAL, ControlAction.QUARANTINE,
                                "TOOL_CONTRACT_DRIFT", detected_at)
        if (
            event.destination_digest is not None
            and event.destination_digest not in self.config.allowed_destination_digests
        ):
            return self._signal(event, Severity.CRITICAL, ControlAction.REVOKE,
                                "DESTINATION_NOT_APPROVED", detected_at)
        if event.phase == Phase.EFFECT and event.policy_decision == PolicyDecision.DENY:
            return self._signal(event, Severity.CRITICAL, ControlAction.REVOKE,
                                "EFFECT_AFTER_DENY", detected_at)
        if event.phase == Phase.POLICY and event.policy_decision == PolicyDecision.DENY:
            count = self._denials.get(event.principal_pseudonym, 0) + 1
            self._denials[event.principal_pseudonym] = count
            if count >= self.config.denial_review_threshold:
                return self._signal(event, Severity.MEDIUM, ControlAction.REVIEW,
                                    "REPEATED_POLICY_DENIAL", detected_at)
        return None

    @staticmethod
    def signal_for_trace(finding: TraceFinding, detected_at: datetime) -> Signal | None:
        if finding.complete:
            return None
        action = (
            ControlAction.REVOKE
            if "EFFECT_AFTER_DENY" in finding.violations
            else ControlAction.REVIEW
        )
        severity = Severity.CRITICAL if action == ControlAction.REVOKE else Severity.HIGH
        return Signal(
            f"signal-{digest((finding.trace_id, finding.violations))[7:23]}",
            finding.trace_id,
            severity,
            action,
            finding.violations[0],
            None,
            detected_at,
        )

    @staticmethod
    def signal_for_rejection(
        rejection: IngestResult, emitter_id: str, detected_at: datetime
    ) -> Signal:
        return Signal(
            f"signal-{digest((rejection.event_id, rejection.reason_code))[7:23]}",
            "unknown",
            Severity.CRITICAL,
            ControlAction.QUARANTINE,
            rejection.reason_code,
            emitter_id,
            detected_at,
        )

    @staticmethod
    def _signal(
        event: SecurityEvent,
        severity: Severity,
        action: ControlAction,
        reason: str,
        detected_at: datetime,
    ) -> Signal:
        return Signal(
            f"signal-{digest((event.event_id, reason))[7:23]}",
            event.trace_id,
            severity,
            action,
            reason,
            event.server_digest,
            detected_at,
        )


class ControlPlane:
    """Applies deny-only controls with explicit state; signals cannot authorize."""

    def __init__(self) -> None:
        self.quarantined_digests: set[str] = set()
        self.revoked_digests: set[str] = set()
        self.review_signals: list[str] = []

    def apply(self, signal: Signal) -> str:
        if signal.action == ControlAction.NONE:
            raise ValueError("no-op signal is not actionable")
        if signal.action == ControlAction.REVIEW:
            self.review_signals.append(signal.signal_id)
            return "REVIEW_CREATED"
        if signal.target_digest is None:
            return "TARGET_REQUIRED"
        if signal.action == ControlAction.QUARANTINE:
            self.quarantined_digests.add(signal.target_digest)
            return "TARGET_QUARANTINED"
        if signal.action == ControlAction.REVOKE:
            self.revoked_digests.add(signal.target_digest)
            return "TARGET_REVOKED"
        raise AssertionError("unknown control action")


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    expected_signal: bool
    safe_task: bool
    server_digest: str = REVIEWED_SERVER_DIGEST
    contract_digest: str = REVIEWED_CONTRACT_DIGEST
    tool_name: str = "ticket.read"
    risk: Risk = Risk.READ
    destination: str | None = None
    arguments: tuple[tuple[str, str], ...] = (("ticket_id", "acme-7"),)
    decision: PolicyDecision = PolicyDecision.ALLOW
    outcome: Outcome = Outcome.COMPLETED
    emit_effect: bool = True
    drop_phase: Phase | None = None
    tamper_signature: bool = False


def _span_id(seed: str) -> str:
    return sha256(seed.encode()).hexdigest()[:16]


def _trace_id(seed: str) -> str:
    return sha256(f"trace:{seed}".encode()).hexdigest()[:32]


def build_scenario_events(
    scenario: Scenario,
    now: datetime,
    *,
    identity: TrustedIdentity | None = None,
) -> tuple[SecurityEvent, ...]:
    identity = identity or TrustedIdentity("analyst-42", "acme", frozenset({"ticket:read"}))
    emitter = TelemetryEmitter("support.host", identity)
    trace_id = _trace_id(scenario.scenario_id)
    root_span = _span_id(f"{scenario.scenario_id}:request")
    operation_id = f"op-{scenario.scenario_id}"
    destination = scenario.destination
    arguments = dict(scenario.arguments)
    common = {
        "trace_id": trace_id,
        "operation_id": operation_id,
        "server_digest": scenario.server_digest,
        "server_version": "3.2.0",
        "tool_name": scenario.tool_name,
        "tool_contract_digest": scenario.contract_digest,
        "risk": scenario.risk,
        "destination": destination,
        "arguments": arguments,
    }
    templates = [
        EventTemplate(
            f"evt-{scenario.scenario_id}-request",
            now,
            span_id=root_span,
            parent_span_id=None,
            phase=Phase.REQUEST,
            policy_decision=PolicyDecision.NOT_APPLICABLE,
            reason_code="REQUEST_RECEIVED",
            outcome=Outcome.PENDING,
            input_tokens=64,
            **common,
        ),
        EventTemplate(
            f"evt-{scenario.scenario_id}-policy",
            now + timedelta(milliseconds=8),
            span_id=_span_id(f"{scenario.scenario_id}:policy"),
            parent_span_id=root_span,
            phase=Phase.POLICY,
            policy_decision=scenario.decision,
            reason_code=("POLICY_ALLOWED" if scenario.decision == PolicyDecision.ALLOW
                         else "POLICY_DENIED"),
            outcome=(Outcome.PENDING if scenario.decision == PolicyDecision.ALLOW
                     else Outcome.BLOCKED),
            duration_ms=8,
            **common,
        ),
    ]
    if scenario.emit_effect:
        templates.append(
            EventTemplate(
                f"evt-{scenario.scenario_id}-effect",
                now + timedelta(milliseconds=15),
                span_id=_span_id(f"{scenario.scenario_id}:effect"),
                parent_span_id=root_span,
                phase=Phase.EFFECT,
                policy_decision=scenario.decision,
                reason_code="EFFECT_OBSERVED",
                outcome=Outcome.COMPLETED,
                duration_ms=15,
                **common,
            )
        )
    templates.append(
        EventTemplate(
            f"evt-{scenario.scenario_id}-result",
            now + timedelta(milliseconds=21),
            span_id=_span_id(f"{scenario.scenario_id}:result"),
            parent_span_id=root_span,
            phase=Phase.RESULT,
            policy_decision=scenario.decision,
            reason_code=("CALL_COMPLETED" if scenario.outcome == Outcome.COMPLETED
                         else "CALL_BLOCKED"),
            outcome=scenario.outcome,
            duration_ms=21,
            output_tokens=20,
            cost_microusd=12,
            **common,
        )
    )
    events = [emitter.emit(template) for template in templates if template.phase != scenario.drop_phase]
    if scenario.tamper_signature and events:
        events[-1] = replace(events[-1], signature="0" * 64)
    return tuple(events)


def scenarios() -> tuple[Scenario, ...]:
    return (
        Scenario("safe-read", False, True),
        Scenario(
            "safe-message",
            False,
            True,
            tool_name="message.send",
            risk=Risk.EXTERNAL_WRITE,
            destination="mailto:buyer@acme.test",
            arguments=(
                ("ticket_id", "acme-7"),
                ("recipient", "buyer@acme.test"),
                ("body", "Your payment is confirmed."),
            ),
        ),
        Scenario(
            "artifact-drift",
            True,
            False,
            server_digest=digest("unreviewed-server"),
        ),
        Scenario(
            "contract-drift",
            True,
            False,
            contract_digest=digest("changed-tool-contract"),
        ),
        Scenario(
            "unapproved-egress",
            True,
            False,
            tool_name="customer.export",
            risk=Risk.EXTERNAL_WRITE,
            destination="https://attacker.invalid/drop",
            arguments=(("customer_id", "customer-7"),
                       ("destination", "https://attacker.invalid/drop")),
        ),
        Scenario(
            "effect-after-deny",
            True,
            False,
            decision=PolicyDecision.DENY,
            outcome=Outcome.BLOCKED,
            emit_effect=True,
        ),
        Scenario("missing-policy-event", True, False, drop_phase=Phase.POLICY),
        Scenario("tampered-event", True, False, tamper_signature=True),
        Scenario(
            "clean-denial",
            False,
            False,
            decision=PolicyDecision.DENY,
            outcome=Outcome.BLOCKED,
            emit_effect=False,
        ),
    )


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    detected: bool
    signal: Signal | None
    control_result: str | None
    trace_finding: TraceFinding | None
    accepted_events: int
    rejected_events: int
    safe_task_completed: bool
    detection_delay_ms: int | None


def run_scenario(scenario: Scenario, now: datetime) -> ScenarioResult:
    events = build_scenario_events(scenario, now)
    collector = SecureCollector()
    engine = AssuranceEngine(
        AssuranceConfig(
            REVIEWED_SERVER_DIGEST,
            REVIEWED_CONTRACT_DIGEST,
            frozenset({keyed_digest("mailto:buyer@acme.test")}),
        )
    )
    control = ControlPlane()
    signals: list[Signal] = []
    accepted: list[SecurityEvent] = []
    for index, event in enumerate(events):
        observed_at = event.occurred_at + timedelta(milliseconds=4)
        ingest = collector.ingest(event, observed_at)
        if ingest.status == IngestStatus.REJECTED:
            signals.append(engine.signal_for_rejection(ingest, event.emitter_id, observed_at))
            continue
        accepted.append(event)
        signal = engine.assess_event(event, observed_at)
        if signal:
            signals.append(signal)
    finding = TraceVerifier().review(accepted) if accepted else None
    if finding:
        trace_signal = engine.signal_for_trace(finding, now + timedelta(milliseconds=30))
        if trace_signal:
            signals.append(trace_signal)
    signal = sorted(
        signals,
        key=lambda item: (
            {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}[
                item.severity
            ],
            item.detected_at,
        ),
    )[0] if signals else None
    control_result = control.apply(signal) if signal else None
    result_events = [event for event in accepted if event.phase == Phase.RESULT]
    safe_completed = bool(
        scenario.safe_task
        and result_events
        and result_events[-1].outcome in {Outcome.COMPLETED, Outcome.BLOCKED}
        and (finding is None or finding.complete)
        and signal is None
    )
    delay = None
    if signal:
        related = next((event for event in accepted if event.trace_id == signal.trace_id), None)
        if related:
            delay = max(0, round((signal.detected_at - related.occurred_at).total_seconds() * 1_000))
    return ScenarioResult(
        scenario,
        signal is not None,
        signal,
        control_result,
        finding,
        len(collector.events),
        len(collector.rejections),
        safe_completed,
        delay,
    )


@dataclass(frozen=True)
class ConfusionMatrix:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    def metrics(self) -> dict[str, float]:
        precision_denominator = self.true_positive + self.false_positive
        recall_denominator = self.true_positive + self.false_negative
        negative_denominator = self.true_negative + self.false_positive
        return {
            "precision": (
                self.true_positive / precision_denominator if precision_denominator else 0.0
            ),
            "recall": self.true_positive / recall_denominator if recall_denominator else 0.0,
            "false_review_rate": (
                self.false_positive / negative_denominator if negative_denominator else 0.0
            ),
        }


@dataclass(frozen=True)
class CampaignReport:
    results: tuple[ScenarioResult, ...]
    confusion: ConfusionMatrix

    def metrics(self) -> dict[str, float]:
        safe = [result for result in self.results if result.scenario.safe_task]
        traceable = [result for result in self.results if result.trace_finding is not None]
        delays = [result.detection_delay_ms for result in self.results
                  if result.detection_delay_ms is not None]
        return {
            **self.confusion.metrics(),
            "safe_task_completion_rate": (
                sum(result.safe_task_completed for result in safe) / len(safe) if safe else 0.0
            ),
            "trace_completeness_rate": (
                sum(result.trace_finding.complete for result in traceable) / len(traceable)
                if traceable
                else 0.0
            ),
            "event_rejection_rate": (
                sum(result.rejected_events for result in self.results)
                / sum(result.accepted_events + result.rejected_events for result in self.results)
            ),
            "mean_detection_delay_ms": sum(delays) / len(delays) if delays else 0.0,
        }


def run_campaign(cases: Iterable[Scenario], now: datetime) -> CampaignReport:
    materialized = tuple(cases)
    if not materialized or len(materialized) > 100:
        raise ValueError("campaign size must be between 1 and 100")
    if len({case.scenario_id for case in materialized}) != len(materialized):
        raise ValueError("scenario IDs must be unique")
    results = tuple(run_scenario(case, now + timedelta(seconds=index))
                    for index, case in enumerate(materialized))
    tp = sum(result.scenario.expected_signal and result.detected for result in results)
    fp = sum(not result.scenario.expected_signal and result.detected for result in results)
    tn = sum(not result.scenario.expected_signal and not result.detected for result in results)
    fn = sum(result.scenario.expected_signal and not result.detected for result in results)
    return CampaignReport(results, ConfusionMatrix(tp, fp, tn, fn))


@dataclass(frozen=True)
class SloResult:
    name: str
    observed: float
    threshold: float
    direction: str
    passed: bool


def evaluate_slos(metrics: dict[str, float]) -> tuple[SloResult, ...]:
    definitions = (
        ("recall", metrics["recall"], 1.0, ">="),
        ("false_review_rate", metrics["false_review_rate"], 0.05, "<="),
        ("safe_task_completion_rate", metrics["safe_task_completion_rate"], 1.0, ">="),
        ("mean_detection_delay_ms", metrics["mean_detection_delay_ms"], 50.0, "<="),
    )
    return tuple(
        SloResult(name, observed, threshold, direction,
                  observed >= threshold if direction == ">=" else observed <= threshold)
        for name, observed, threshold, direction in definitions
    )


def wilson_interval(successes: int, attempts: int, z: float = 1.96) -> tuple[float, float]:
    if attempts <= 0 or successes < 0 or successes > attempts:
        raise ValueError("invalid binomial counts")
    proportion = successes / attempts
    denominator = 1 + z * z / attempts
    centre = (proportion + z * z / (2 * attempts)) / denominator
    margin = z * math.sqrt(
        proportion * (1 - proportion) / attempts + z * z / (4 * attempts * attempts)
    ) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


@dataclass(frozen=True)
class OtelEvidence:
    span_names: tuple[str, ...]
    one_trace: bool
    parent_links_valid: bool
    traceparent: str
    safe_attribute_keys: tuple[str, ...]


def run_otel_probe() -> OtelEvidence:
    """Create real OTel spans and W3C context without network export."""

    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": "course-16-support-host", "service.version": "1.0.0"}
        )
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("mcp-security-course", "1.0.0")
    carrier: dict[str, str] = {}
    with tracer.start_as_current_span("support.request") as root:
        root.set_attribute("mcp.protocol.version", PROTOCOL_VERSION)
        root.set_attribute("enduser.id", keyed_digest("analyst-42"))
        with tracer.start_as_current_span("mcp.tools.call") as call:
            call.set_attribute("mcp.method.name", "tools/call")
            call.set_attribute("mcp.tool.name", "ticket.read")
            call.set_attribute("mcp.tool.arguments.digest", digest({"ticket_id": "acme-7"}))
            call.set_attribute("security.policy.decision", "allow")
            TraceContextTextMapPropagator().inject(carrier)
            with tracer.start_as_current_span("ticket.backend.read") as backend:
                backend.set_attribute("server.address", "tickets.internal.test")
    provider.force_flush()
    spans = exporter.get_finished_spans()
    provider.shutdown()
    by_name = {span.name: span for span in spans}
    trace_ids = {span.context.trace_id for span in spans}
    call = by_name["mcp.tools.call"]
    backend = by_name["ticket.backend.read"]
    root = by_name["support.request"]
    keys = tuple(sorted({key for span in spans for key in span.attributes}))
    return OtelEvidence(
        tuple(span.name for span in spans),
        len(trace_ids) == 1,
        call.parent.span_id == root.context.span_id and backend.parent.span_id == call.context.span_id,
        carrier["traceparent"],
        keys,
    )


def run_demo() -> dict[str, Any]:
    now = utc("2026-10-04T18:30:00Z")
    report = run_campaign(scenarios(), now)
    metrics = report.metrics()
    slo_results = evaluate_slos(metrics)
    otel = run_otel_probe()
    positives = report.confusion.true_positive + report.confusion.false_negative
    return {
        "metrics": metrics,
        "confusion_matrix": asdict(report.confusion),
        "recall_interval": wilson_interval(report.confusion.true_positive, positives),
        "signals": [
            {
                "scenario": result.scenario.scenario_id,
                "action": result.signal.action if result.signal else ControlAction.NONE,
                "reason": result.signal.reason_code if result.signal else "NO_SIGNAL",
            }
            for result in report.results
        ],
        "slo_results": [asdict(result) for result in slo_results],
        "otel": {
            "one_trace": otel.one_trace,
            "parent_links_valid": otel.parent_links_valid,
            "span_names": otel.span_names,
            "traceparent_present": bool(otel.traceparent),
            "safe_attribute_keys": otel.safe_attribute_keys,
        },
    }


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
