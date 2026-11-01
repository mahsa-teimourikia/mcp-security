"""Course 28: hypothesis-led MCP threat hunting and anomaly detection.

The lab is deterministic, offline, and credential-free. A signed hunt grant
authorizes exact evidence scope before analytics. Data-readiness gates prevent
missing telemetry from becoming a clean result. Deterministic, robust-statistic,
sequence, and graph hunts emit evidence-linked candidates. Analyst disposition
and peer-reviewed detection promotion are separate; no anomaly authorizes an
effect or containment action.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import json
import math
import re
from statistics import median
from threading import Lock
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import networkx as nx


UTC = timezone.utc
NOW = datetime(2026, 10, 31, 16, 0, tzinfo=UTC)
EVENT_SCHEMA = "mcp.security.event/1.0"
HUNT_POLICY_VERSION = "mcp-hunting/2026-10-31"
MAX_QUERY_WINDOW = timedelta(days=30)
MAX_GRANT_TTL = timedelta(hours=8)
MAX_CLOCK_SKEW = timedelta(seconds=10)
MAX_INGEST_DELAY = timedelta(minutes=10)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,159}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


class HuntError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class EventKind(StrEnum):
    TOOL_CALL = "tool_call"
    POLICY = "policy"
    NETWORK = "network"
    RESOURCE = "resource"
    DELEGATION = "delegation"
    CONTROL = "control"


class Outcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class HuntMethod(StrEnum):
    INVARIANT = "invariant"
    ROBUST_MAD = "robust_mad"
    LOW_AND_SLOW = "low_and_slow"
    SEQUENCE = "sequence"
    GRAPH = "graph"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Disposition(StrEnum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class DetectionState(StrEnum):
    PROPOSED = "proposed"
    TEST = "test"
    ACTIVE = "active"
    RETIRED = "retired"


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
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + sha256(payload).hexdigest()


def require_safe(label: str, value: str) -> None:
    if not SAFE_ID.fullmatch(value):
        raise HuntError("FIELD_INVALID", f"{label} must be a bounded identifier")


@dataclass(frozen=True)
class RuntimeEvent:
    event_id: str
    schema_version: str
    source_id: str
    occurred_at: datetime
    observed_at: datetime
    ingested_at: datetime
    tenant_id: str
    resource_tenant: str
    principal_ref: str
    workload_id: str
    server_id: str
    artifact_digest: str
    capability_version: str
    trace_id: str
    operation_id: str
    kind: EventKind
    action: str
    destination: str
    policy_decision: str
    outcome: Outcome
    delegation_depth: int
    bytes_out: int
    signal_codes: tuple[str, ...]
    evidence_digest: str

    def identity(self) -> tuple[str, str]:
        return self.tenant_id, self.event_id


def event_fixture(
    *,
    event_id: str = "EV-001",
    source_id: str = "source:gateway",
    occurred_at: datetime = NOW,
    observed_at: datetime = NOW + timedelta(seconds=1),
    ingested_at: datetime = NOW + timedelta(seconds=2),
    tenant_id: str = "tenant:acme",
    resource_tenant: str = "tenant:acme",
    principal_ref: str = "principal:hmac:alice",
    workload_id: str = "workload:support-prod",
    server_id: str = "server:support",
    artifact_digest: str = "sha256:" + "a" * 64,
    capability_version: str = "support-tools/7",
    trace_id: str = "1" * 32,
    operation_id: str = "OP-001",
    kind: EventKind = EventKind.TOOL_CALL,
    action: str = "ticket.read",
    destination: str = "tickets.example.com",
    policy_decision: str = "allow",
    outcome: Outcome = Outcome.SUCCEEDED,
    delegation_depth: int = 1,
    bytes_out: int = 512,
    signal_codes: tuple[str, ...] = (),
    schema_version: str = EVENT_SCHEMA,
) -> RuntimeEvent:
    unsigned = {
        "event_id": event_id,
        "schema_version": schema_version,
        "source_id": source_id,
        "occurred_at": occurred_at,
        "observed_at": observed_at,
        "ingested_at": ingested_at,
        "tenant_id": tenant_id,
        "resource_tenant": resource_tenant,
        "principal_ref": principal_ref,
        "workload_id": workload_id,
        "server_id": server_id,
        "artifact_digest": artifact_digest,
        "capability_version": capability_version,
        "trace_id": trace_id,
        "operation_id": operation_id,
        "kind": kind,
        "action": action,
        "destination": destination,
        "policy_decision": policy_decision,
        "outcome": outcome,
        "delegation_depth": delegation_depth,
        "bytes_out": bytes_out,
        "signal_codes": signal_codes,
    }
    return RuntimeEvent(**unsigned, evidence_digest=digest(unsigned))


@dataclass(frozen=True)
class SourceContract:
    source_id: str
    tenant_ids: frozenset[str]
    event_kinds: frozenset[EventKind]
    required: bool


@dataclass(frozen=True)
class HuntGrant:
    grant_id: str
    hunter_id: str
    hunter_role: str
    purpose: str
    tenant_ids: frozenset[str]
    event_kinds: frozenset[EventKind]
    window_start: datetime
    window_end: datetime
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


class HuntAuthority:
    """Issue and verify exact read authority; it never grants response authority."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self.private_key = private_key or Ed25519PrivateKey.generate()

    def issue(
        self,
        hunter_id: str,
        role: str,
        tenant_ids: frozenset[str],
        event_kinds: frozenset[EventKind],
        start: datetime,
        end: datetime,
        now: datetime,
        ttl: timedelta = timedelta(hours=1),
    ) -> HuntGrant:
        require_safe("hunter_id", hunter_id)
        if role not in {"threat_hunter", "incident_responder"}:
            raise HuntError("HUNTER_ROLE_INVALID", "role cannot receive hunt access")
        if not tenant_ids or not event_kinds:
            raise HuntError("HUNT_SCOPE_EMPTY", "tenant and event-kind scope are required")
        if start.tzinfo is None or end.tzinfo is None or now.tzinfo is None:
            raise HuntError("TIME_INVALID", "grant times must be timezone-aware")
        if end <= start or end - start > MAX_QUERY_WINDOW:
            raise HuntError("HUNT_WINDOW_INVALID", "hunt window is empty or exceeds policy")
        if ttl <= timedelta(0) or ttl > MAX_GRANT_TTL:
            raise HuntError("GRANT_TTL_INVALID", "grant TTL is outside policy")
        unsigned = {
            "grant_id": "HGR-" + sha256(canonical_json({"hunter": hunter_id, "tenants": tenant_ids, "start": start, "end": end, "at": now})).hexdigest()[:20],
            "hunter_id": hunter_id,
            "hunter_role": role,
            "purpose": "mcp_threat_hunt_read",
            "tenant_ids": tenant_ids,
            "event_kinds": event_kinds,
            "window_start": start,
            "window_end": end,
            "policy_version": HUNT_POLICY_VERSION,
            "issued_at": now,
            "expires_at": now + ttl,
        }
        return HuntGrant(**unsigned, signature=self.private_key.sign(canonical_json(unsigned)).hex())

    def verify(self, grant: HuntGrant, now: datetime) -> None:
        try:
            self.private_key.public_key().verify(bytes.fromhex(grant.signature), canonical_json(grant.unsigned()))
        except (InvalidSignature, ValueError) as exc:
            raise HuntError("GRANT_SIGNATURE_INVALID", "hunt grant signature does not verify") from exc
        if grant.purpose != "mcp_threat_hunt_read" or grant.policy_version != HUNT_POLICY_VERSION:
            raise HuntError("GRANT_PURPOSE_INVALID", "grant purpose or policy is invalid")
        if now < grant.issued_at or now >= grant.expires_at:
            raise HuntError("GRANT_EXPIRED", "hunt grant is not currently valid")


@dataclass(frozen=True)
class HuntHypothesis:
    hypothesis_id: str
    version: str
    title: str
    statement: str
    rationale: str
    owner: str
    tenant_ids: frozenset[str]
    window_start: datetime
    window_end: datetime
    required_sources: frozenset[str]
    required_fields: frozenset[str]
    methods: frozenset[HuntMethod]
    exclusions: tuple[str, ...]
    validation_steps: tuple[str, ...]
    attack_refs: tuple[str, ...]
    promotion_criteria: tuple[str, ...]


def validate_hypothesis(hypothesis: HuntHypothesis) -> None:
    for label, value in (
        ("hypothesis_id", hypothesis.hypothesis_id),
        ("version", hypothesis.version),
        ("owner", hypothesis.owner),
    ):
        require_safe(label, value)
    if not all((hypothesis.title, hypothesis.statement, hypothesis.rationale)):
        raise HuntError("HYPOTHESIS_INCOMPLETE", "title, statement, and rationale are required")
    if not hypothesis.tenant_ids or not hypothesis.required_sources or not hypothesis.required_fields or not hypothesis.methods:
        raise HuntError("HYPOTHESIS_INCOMPLETE", "scope, sources, fields, and methods are required")
    if hypothesis.window_end <= hypothesis.window_start or hypothesis.window_end - hypothesis.window_start > MAX_QUERY_WINDOW:
        raise HuntError("HUNT_WINDOW_INVALID", "hypothesis window is invalid")
    if not hypothesis.validation_steps or not hypothesis.promotion_criteria:
        raise HuntError("HYPOTHESIS_INCOMPLETE", "validation and promotion criteria are required")


@dataclass(frozen=True)
class DataQualityReport:
    total_events: int
    usable_events: int
    duplicate_events: int
    invalid_events: int
    missing_required_fields: int
    source_coverage: float
    field_completeness: float
    late_event_rate: float
    clock_error_rate: float
    ready: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class PreparedEvidence:
    events: tuple[RuntimeEvent, ...]
    report: DataQualityReport


class EvidencePreparer:
    """Authorize first, validate source evidence, then report—not hide—data gaps."""

    def __init__(self, authority: HuntAuthority, sources: Iterable[SourceContract]) -> None:
        self.authority = authority
        self.sources = {item.source_id: item for item in sources}

    def prepare(
        self,
        events: Iterable[RuntimeEvent],
        grant: HuntGrant,
        hypothesis: HuntHypothesis,
        now: datetime,
        min_source_coverage: float = 1.0,
        min_field_completeness: float = 0.98,
    ) -> PreparedEvidence:
        self.authority.verify(grant, now)
        validate_hypothesis(hypothesis)
        if not hypothesis.tenant_ids.issubset(grant.tenant_ids):
            raise HuntError("HUNT_TENANT_UNAUTHORIZED", "hypothesis exceeds grant tenant scope")
        if hypothesis.window_start < grant.window_start or hypothesis.window_end > grant.window_end:
            raise HuntError("HUNT_WINDOW_UNAUTHORIZED", "hypothesis exceeds grant time scope")
        if min_source_coverage <= 0 or min_source_coverage > 1 or min_field_completeness <= 0 or min_field_completeness > 1:
            raise ValueError("quality thresholds must be in (0, 1]")

        population = tuple(events)
        identities: dict[tuple[str, str], str] = {}
        usable: list[RuntimeEvent] = []
        duplicates = invalid = missing = late = clock_error = time_checked = 0
        observed_sources: set[str] = set()
        fields = RuntimeEvent.__dataclass_fields__
        unknown_required = hypothesis.required_fields.difference(fields)
        if unknown_required:
            raise HuntError("REQUIRED_FIELD_UNKNOWN", "hypothesis requests fields outside the event contract")

        for event in population:
            if event.tenant_id not in grant.tenant_ids or event.kind not in grant.event_kinds:
                continue
            if not (grant.window_start <= event.occurred_at < grant.window_end):
                continue
            source = self.sources.get(event.source_id)
            if source is None or event.tenant_id not in source.tenant_ids or event.kind not in source.event_kinds:
                invalid += 1
                continue
            if event.schema_version != EVENT_SCHEMA or not DIGEST.fullmatch(event.artifact_digest) or not TRACE_ID.fullmatch(event.trace_id):
                invalid += 1
                continue
            expected_digest = digest({key: value for key, value in asdict(event).items() if key != "evidence_digest"})
            if event.evidence_digest != expected_digest:
                invalid += 1
                continue
            values = asdict(event)
            if any(
                values[name] is None or values[name] == "" or values[name] == () or values[name] == []
                for name in hypothesis.required_fields
            ):
                missing += 1
                continue
            key = event.identity()
            prior = identities.get(key)
            if prior == event.evidence_digest:
                duplicates += 1
                continue
            if prior is not None:
                invalid += 1
                continue
            identities[key] = event.evidence_digest
            time_checked += 1
            if event.occurred_at > event.observed_at + MAX_CLOCK_SKEW or event.observed_at > event.ingested_at + MAX_CLOCK_SKEW:
                clock_error += 1
                continue
            if event.ingested_at - event.observed_at > MAX_INGEST_DELAY:
                late += 1
            observed_sources.add(event.source_id)
            usable.append(event)

        required_sources = hypothesis.required_sources
        source_coverage = len(required_sources.intersection(observed_sources)) / len(required_sources)
        relevant_count = max(1, len(usable) + missing)
        field_completeness = len(usable) / relevant_count
        time_population = max(1, time_checked)
        late_rate = late / time_population
        clock_rate = clock_error / time_population
        reasons: list[str] = []
        if not usable:
            reasons.append("NO_USABLE_EVENTS")
        if source_coverage < min_source_coverage:
            reasons.append("SOURCE_COVERAGE_INCOMPLETE")
        if field_completeness < min_field_completeness:
            reasons.append("FIELD_COMPLETENESS_LOW")
        if invalid:
            reasons.append("INVALID_EVIDENCE_PRESENT")
        if clock_error:
            reasons.append("CLOCK_QUALITY_LOW")
        report = DataQualityReport(
            len(population), len(usable), duplicates, invalid, missing,
            source_coverage, field_completeness, late_rate, clock_rate,
            not reasons, tuple(sorted(reasons)),
        )
        return PreparedEvidence(tuple(sorted(usable, key=lambda item: (item.occurred_at, item.event_id))), report)


@dataclass(frozen=True)
class BaselineContract:
    baseline_id: str
    version: str
    tenant_id: str
    server_id: str
    action: str
    feature: str
    training_start: datetime
    training_end: datetime
    values: tuple[float, ...]
    minimum_samples: int
    threshold: float
    contamination_reviewed: bool


@dataclass(frozen=True)
class HuntFinding:
    finding_id: str
    hypothesis_id: str
    hypothesis_version: str
    method: HuntMethod
    tenant_id: str
    entity_id: str
    title: str
    evidence_event_ids: tuple[str, ...]
    evidence_digest: str
    reason_codes: tuple[str, ...]
    score: float | None
    threshold: float | None
    baseline_id: str | None
    baseline_version: str | None
    created_at: datetime
    confidence: Confidence
    disposition: Disposition = Disposition.CANDIDATE


def finding(
    hypothesis: HuntHypothesis,
    method: HuntMethod,
    tenant_id: str,
    entity_id: str,
    title: str,
    evidence: Iterable[RuntimeEvent],
    reasons: Iterable[str],
    now: datetime,
    *,
    score: float | None = None,
    threshold: float | None = None,
    baseline: BaselineContract | None = None,
    confidence: Confidence = Confidence.MEDIUM,
) -> HuntFinding:
    ordered = sorted(evidence, key=lambda item: (item.occurred_at, item.event_id))
    ids = tuple(item.event_id for item in ordered)
    if not ids or any(item.tenant_id != tenant_id for item in ordered):
        raise HuntError("FINDING_EVIDENCE_INVALID", "finding evidence must be non-empty and same-tenant")
    evidence_digest = digest([item.evidence_digest for item in ordered])
    finding_id = "HF-" + sha256(canonical_json({"hypothesis": hypothesis.hypothesis_id, "method": method, "tenant": tenant_id, "entity": entity_id, "evidence": ids})).hexdigest()[:20]
    return HuntFinding(
        finding_id, hypothesis.hypothesis_id, hypothesis.version, method, tenant_id,
        entity_id, title, ids, evidence_digest, tuple(sorted(set(reasons))), score,
        threshold, baseline.baseline_id if baseline else None,
        baseline.version if baseline else None, now, confidence,
    )


class HuntEngine:
    def __init__(
        self,
        approved_artifacts: Mapping[str, str],
        approved_capabilities: Mapping[str, str],
        approved_destinations: Mapping[str, frozenset[str]],
        approved_edges: frozenset[tuple[str, str]],
        approved_sequences: frozenset[tuple[str, ...]],
    ) -> None:
        self.approved_artifacts = dict(approved_artifacts)
        self.approved_capabilities = dict(approved_capabilities)
        self.approved_destinations = dict(approved_destinations)
        self.approved_edges = approved_edges
        self.approved_sequences = approved_sequences

    def require_ready(self, prepared: PreparedEvidence) -> tuple[RuntimeEvent, ...]:
        if not prepared.report.ready:
            raise HuntError("DATA_NOT_READY", ",".join(prepared.report.reason_codes))
        return prepared.events

    def invariant_hunt(self, prepared: PreparedEvidence, hypothesis: HuntHypothesis, now: datetime) -> tuple[HuntFinding, ...]:
        events = self.require_ready(prepared)
        results: list[HuntFinding] = []
        for event in events:
            reasons: list[str] = []
            if self.approved_artifacts.get(event.server_id) != event.artifact_digest:
                reasons.append("ARTIFACT_DRIFT")
            if self.approved_capabilities.get(event.server_id) != event.capability_version:
                reasons.append("CAPABILITY_DRIFT")
            if event.kind == EventKind.NETWORK and event.destination not in self.approved_destinations.get(event.server_id, frozenset()):
                reasons.append("UNAPPROVED_DESTINATION")
            if event.resource_tenant != event.tenant_id:
                reasons.append("CROSS_TENANT_RESOURCE")
            if event.delegation_depth > 2:
                reasons.append("DELEGATION_DEPTH_EXCEEDED")
            if reasons:
                results.append(finding(
                    hypothesis, HuntMethod.INVARIANT, event.tenant_id, event.server_id,
                    "MCP runtime invariant mismatch", [event], reasons, now,
                    confidence=Confidence.HIGH,
                ))
        return tuple(results)

    def robust_mad_hunt(
        self,
        prepared: PreparedEvidence,
        hypothesis: HuntHypothesis,
        baseline: BaselineContract,
        now: datetime,
    ) -> tuple[HuntFinding, ...]:
        events = self.require_ready(prepared)
        if baseline.feature != "bytes_out" or baseline.threshold <= 0:
            raise HuntError("BASELINE_INVALID", "lab supports a positive bytes_out MAD contract")
        if len(baseline.values) < baseline.minimum_samples or baseline.minimum_samples < 5:
            raise HuntError("BASELINE_INSUFFICIENT", "baseline lacks the reviewed sample minimum")
        if any(not math.isfinite(value) or value < 0 for value in baseline.values):
            raise HuntError("BASELINE_INVALID", "baseline values must be finite and non-negative")
        if baseline.training_end > hypothesis.window_start or baseline.training_end <= baseline.training_start:
            raise HuntError("BASELINE_TIME_INVALID", "baseline must precede the hunt window")
        if not baseline.contamination_reviewed:
            raise HuntError("BASELINE_CONTAMINATION_UNREVIEWED", "baseline contamination has not been reviewed")
        center = median(baseline.values)
        mad = median(abs(value - center) for value in baseline.values)
        if mad == 0:
            raise HuntError("BASELINE_ZERO_DISPERSION", "MAD score is undefined for zero dispersion")
        results: list[HuntFinding] = []
        for event in events:
            if (event.tenant_id, event.server_id, event.action) != (baseline.tenant_id, baseline.server_id, baseline.action):
                continue
            score = 0.6745 * abs(event.bytes_out - center) / mad
            if score >= baseline.threshold:
                results.append(finding(
                    hypothesis, HuntMethod.ROBUST_MAD, event.tenant_id, event.server_id,
                    "Outbound byte volume deviates from reviewed peer history", [event],
                    ["ROBUST_BYTES_OUTLIER"], now, score=score,
                    threshold=baseline.threshold, baseline=baseline,
                    confidence=Confidence.MEDIUM,
                ))
        return tuple(results)

    def low_and_slow_hunt(
        self,
        prepared: PreparedEvidence,
        hypothesis: HuntHypothesis,
        now: datetime,
        *,
        minimum_denials: int = 6,
        minimum_span: timedelta = timedelta(minutes=20),
        max_per_five_minutes: int = 2,
    ) -> tuple[HuntFinding, ...]:
        events = self.require_ready(prepared)
        if minimum_denials < 2 or minimum_span <= timedelta(0) or max_per_five_minutes < 1:
            raise ValueError("low-and-slow parameters must be positive")
        groups: dict[tuple[str, str, str], list[RuntimeEvent]] = defaultdict(list)
        for event in events:
            if event.kind == EventKind.POLICY and event.outcome == Outcome.DENIED:
                groups[(event.tenant_id, event.principal_ref, event.server_id)].append(event)
        results: list[HuntFinding] = []
        for (tenant, principal, server), group in groups.items():
            ordered = sorted(group, key=lambda item: item.occurred_at)
            if len(ordered) < minimum_denials or ordered[-1].occurred_at - ordered[0].occurred_at < minimum_span:
                continue
            buckets = Counter(int((item.occurred_at - hypothesis.window_start).total_seconds() // 300) for item in ordered)
            if max(buckets.values()) <= max_per_five_minutes:
                results.append(finding(
                    hypothesis, HuntMethod.LOW_AND_SLOW, tenant, f"{principal}@{server}",
                    "Low-and-slow authorization probing", ordered,
                    ["DISTRIBUTED_DENIAL_PATTERN"], now, confidence=Confidence.MEDIUM,
                ))
        return tuple(results)

    def sequence_hunt(self, prepared: PreparedEvidence, hypothesis: HuntHypothesis, now: datetime) -> tuple[HuntFinding, ...]:
        events = self.require_ready(prepared)
        groups: dict[tuple[str, str], list[RuntimeEvent]] = defaultdict(list)
        for event in events:
            groups[(event.tenant_id, event.operation_id)].append(event)
        results: list[HuntFinding] = []
        for (tenant, operation), group in groups.items():
            ordered = sorted(group, key=lambda item: (item.occurred_at, item.event_id))
            sequence = tuple(f"{item.kind}:{item.action}:{item.outcome}" for item in ordered)
            if len(sequence) >= 2 and sequence not in self.approved_sequences:
                results.append(finding(
                    hypothesis, HuntMethod.SEQUENCE, tenant, operation,
                    "Previously unreviewed MCP operation sequence", ordered,
                    ["NOVEL_OPERATION_SEQUENCE"], now, confidence=Confidence.LOW,
                ))
        return tuple(results)

    def graph_hunt(self, prepared: PreparedEvidence, hypothesis: HuntHypothesis, now: datetime) -> tuple[HuntFinding, ...]:
        events = self.require_ready(prepared)
        by_tenant: dict[str, list[RuntimeEvent]] = defaultdict(list)
        for event in events:
            by_tenant[event.tenant_id].append(event)
        results: list[HuntFinding] = []
        for tenant, tenant_events in by_tenant.items():
            graph = nx.DiGraph()
            edge_evidence: dict[tuple[str, str], list[RuntimeEvent]] = defaultdict(list)
            for event in tenant_events:
                principal_edge = (event.principal_ref, event.server_id)
                graph.add_edge(*principal_edge)
                edge_evidence[principal_edge].append(event)
                if event.destination:
                    egress_edge = (event.server_id, f"destination:{event.destination}")
                    graph.add_edge(*egress_edge)
                    edge_evidence[egress_edge].append(event)
            unexpected = sorted(edge for edge in graph.edges if edge not in self.approved_edges)
            for edge in unexpected:
                results.append(finding(
                    hypothesis, HuntMethod.GRAPH, tenant, "->".join(edge),
                    "Observed authority or egress edge is outside the reviewed graph",
                    edge_evidence[edge], ["UNAPPROVED_GRAPH_EDGE"], now,
                    confidence=Confidence.MEDIUM,
                ))
        return tuple(results)


@dataclass(frozen=True)
class AnalystDisposition:
    disposition_id: str
    finding_id: str
    finding_digest: str
    analyst_id: str
    analyst_role: str
    disposition: Disposition
    rationale: str
    evidence_event_ids: tuple[str, ...]
    decided_at: datetime


def disposition_finding(
    item: HuntFinding,
    analyst_id: str,
    role: str,
    disposition: Disposition,
    rationale: str,
    now: datetime,
) -> tuple[HuntFinding, AnalystDisposition]:
    require_safe("analyst_id", analyst_id)
    if role not in {"threat_hunter", "detection_engineer", "incident_responder"}:
        raise HuntError("ANALYST_ROLE_INVALID", "role cannot disposition hunt findings")
    if disposition == Disposition.CANDIDATE or not rationale.strip():
        raise HuntError("DISPOSITION_INVALID", "terminal analyst disposition and rationale are required")
    record = AnalystDisposition(
        "DISP-" + sha256(canonical_json({"finding": item.finding_id, "analyst": analyst_id, "at": now})).hexdigest()[:20],
        item.finding_id, digest(item), analyst_id, role, disposition, rationale,
        item.evidence_event_ids, now,
    )
    return replace(item, disposition=disposition), record


@dataclass(frozen=True)
class DetectionCandidate:
    candidate_id: str
    rule_id: str
    version: str
    title: str
    hypothesis_id: str
    source_finding_ids: tuple[str, ...]
    query_contract: str
    required_fields: tuple[str, ...]
    window: timedelta
    grouping: tuple[str, ...]
    threshold: float | None
    expected_false_positives: tuple[str, ...]
    validation_dataset_id: str
    precision: float
    recall: float
    owner: str
    state: DetectionState = DetectionState.PROPOSED

    def payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PromotionReceipt:
    receipt_id: str
    purpose: str
    candidate_digest: str
    reviewer_id: str
    reviewer_role: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


class DetectionRegistry:
    """Peer-review test rules; this registry cannot execute response actions."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.rules: dict[tuple[str, str], DetectionCandidate] = {}
        self.used_receipts: set[str] = set()
        self.lock = Lock()

    def issue_promotion(
        self,
        candidate: DetectionCandidate,
        reviewer_id: str,
        role: str,
        now: datetime,
        ttl: timedelta = timedelta(minutes=15),
    ) -> PromotionReceipt:
        if role != "detection_reviewer":
            raise HuntError("REVIEWER_ROLE_INVALID", "peer detection reviewer is required")
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise HuntError("PROMOTION_TTL_INVALID", "promotion TTL is outside policy")
        unsigned = {
            "receipt_id": "DPR-" + sha256(canonical_json({"candidate": candidate.payload(), "reviewer": reviewer_id, "at": now})).hexdigest()[:20],
            "purpose": "register_detection_test",
            "candidate_digest": digest(candidate.payload()),
            "reviewer_id": reviewer_id,
            "reviewer_role": role,
            "issued_at": now,
            "expires_at": now + ttl,
        }
        return PromotionReceipt(**unsigned, signature=self.private_key.sign(canonical_json(unsigned)).hex())

    def register_test(
        self,
        candidate: DetectionCandidate,
        receipt: PromotionReceipt,
        now: datetime,
        source_findings: Iterable[HuntFinding],
    ) -> DetectionCandidate:
        if candidate.state != DetectionState.PROPOSED:
            raise HuntError("CANDIDATE_STATE_INVALID", "only proposed rules can enter test")
        if not candidate.source_finding_ids or not candidate.query_contract or not candidate.required_fields:
            raise HuntError("CANDIDATE_INCOMPLETE", "evidence, query, and field contract are required")
        finding_map = {item.finding_id: item for item in source_findings}
        if any(
            finding_id not in finding_map
            or finding_map[finding_id].disposition != Disposition.SUPPORTED
            or finding_map[finding_id].hypothesis_id != candidate.hypothesis_id
            for finding_id in candidate.source_finding_ids
        ):
            raise HuntError(
                "PROMOTION_EVIDENCE_INVALID",
                "every source finding must exist, be analyst-supported, and match the candidate hypothesis",
            )
        if not (0 <= candidate.precision <= 1 and 0 <= candidate.recall <= 1):
            raise HuntError("CANDIDATE_METRICS_INVALID", "precision and recall must be bounded")
        try:
            self.private_key.public_key().verify(bytes.fromhex(receipt.signature), canonical_json(receipt.unsigned()))
        except (InvalidSignature, ValueError) as exc:
            raise HuntError("PROMOTION_SIGNATURE_INVALID", "promotion signature does not verify") from exc
        if receipt.purpose != "register_detection_test" or receipt.candidate_digest != digest(candidate.payload()):
            raise HuntError("PROMOTION_SCOPE_MISMATCH", "promotion is not bound to this exact candidate")
        if now < receipt.issued_at or now >= receipt.expires_at:
            raise HuntError("PROMOTION_EXPIRED", "promotion receipt is not currently valid")
        with self.lock:
            if receipt.receipt_id in self.used_receipts:
                raise HuntError("PROMOTION_REPLAYED", "promotion receipt was already consumed")
            key = (candidate.rule_id, candidate.version)
            existing = self.rules.get(key)
            promoted = replace(candidate, state=DetectionState.TEST)
            if existing:
                if digest(existing) != digest(promoted):
                    raise HuntError("DETECTION_VERSION_CONFLICT", "rule version already has different content")
                self.used_receipts.add(receipt.receipt_id)
                return existing
            self.used_receipts.add(receipt.receipt_id)
            self.rules[key] = promoted
            return promoted


@dataclass(frozen=True)
class LabelledEpisode:
    episode_id: str
    malicious: bool
    finding_ids: tuple[str, ...]
    first_event_at: datetime
    first_finding_at: datetime | None
    analyst_minutes: float
    scanned_events: int


def hunt_metrics(episodes: Iterable[LabelledEpisode]) -> dict[str, float | int | None]:
    population = tuple(episodes)
    if not population:
        raise ValueError("labelled episode population must not be empty")
    tp = sum(item.malicious and bool(item.finding_ids) for item in population)
    fn = sum(item.malicious and not item.finding_ids for item in population)
    fp = sum((not item.malicious) and bool(item.finding_ids) for item in population)
    tn = sum((not item.malicious) and not item.finding_ids for item in population)
    latencies = [
        (item.first_finding_at - item.first_event_at).total_seconds()
        for item in population if item.malicious and item.first_finding_at is not None
    ]
    total_scanned = sum(item.scanned_events for item in population)
    total_findings = sum(len(item.finding_ids) for item in population)
    analyst_minutes = sum(item.analyst_minutes for item in population)
    return {
        "population": len(population),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "median_time_to_finding_seconds": median(latencies) if latencies else None,
        "findings_per_1000_events": total_findings * 1000 / total_scanned if total_scanned else None,
        "analyst_minutes_per_detected_malicious_episode": analyst_minutes / tp if tp else None,
    }


def demo_hypothesis() -> HuntHypothesis:
    return HuntHypothesis(
        "HYP-MCP-EGRESS-001", "1.0.0", "Unreviewed MCP runtime paths",
        "A reviewed support server may execute an unapproved artifact, capability, destination, or authority path.",
        "Artifact, interface, network, and delegation drift can expose new authority without a deployment alert.",
        "team:detection-engineering", frozenset({"tenant:acme"}), NOW - timedelta(hours=1), NOW + timedelta(hours=1),
        frozenset({"source:gateway", "source:network"}),
        frozenset({"event_id", "tenant_id", "server_id", "artifact_digest", "capability_version", "trace_id", "operation_id"}),
        frozenset({HuntMethod.INVARIANT, HuntMethod.GRAPH}),
        ("approved emergency egress recorded in change register",),
        ("verify source evidence", "compare trusted inventory", "review resource outcome"),
        ("ATT&CK DET0397", "ATLAS AML.TA0005"),
        ("reproducible on labelled fixture", "peer-reviewed rule", "known false positives documented"),
    )


def demo_components() -> tuple[HuntAuthority, EvidencePreparer, HuntGrant, HuntHypothesis, HuntEngine]:
    authority = HuntAuthority()
    sources = [
        SourceContract("source:gateway", frozenset({"tenant:acme"}), frozenset({EventKind.TOOL_CALL, EventKind.POLICY, EventKind.DELEGATION}), True),
        SourceContract("source:network", frozenset({"tenant:acme"}), frozenset({EventKind.NETWORK}), True),
        SourceContract("source:resource", frozenset({"tenant:acme"}), frozenset({EventKind.RESOURCE}), False),
    ]
    preparer = EvidencePreparer(authority, sources)
    hypothesis = demo_hypothesis()
    grant = authority.issue(
        "hunter:oncall", "threat_hunter", frozenset({"tenant:acme"}), frozenset(EventKind),
        NOW - timedelta(hours=2), NOW + timedelta(hours=2), NOW - timedelta(minutes=1),
    )
    engine = HuntEngine(
        {"server:support": "sha256:" + "a" * 64},
        {"server:support": "support-tools/7"},
        {"server:support": frozenset({"tickets.example.com"})},
        frozenset({
            ("principal:hmac:alice", "server:support"),
            ("server:support", "destination:tickets.example.com"),
        }),
        frozenset({
            ("tool_call:ticket.read:succeeded",),
            ("tool_call:ticket.export:allowed", "network:ticket.export:succeeded", "resource:ticket.export:succeeded"),
        }),
    )
    return authority, preparer, grant, hypothesis, engine


def main() -> None:
    _, preparer, grant, hypothesis, engine = demo_components()
    events = [
        event_fixture(event_id="EV-TOOL", source_id="source:gateway", kind=EventKind.TOOL_CALL),
        event_fixture(
            event_id="EV-EGRESS", source_id="source:network", kind=EventKind.NETWORK,
            action="ticket.export", destination="exfil.example", bytes_out=50_000,
            occurred_at=NOW + timedelta(seconds=2), observed_at=NOW + timedelta(seconds=3),
            ingested_at=NOW + timedelta(seconds=4), operation_id="OP-EXFIL",
        ),
    ]
    prepared = preparer.prepare(events, grant, hypothesis, NOW)
    invariant = engine.invariant_hunt(prepared, hypothesis, NOW + timedelta(seconds=5))
    graph = engine.graph_hunt(prepared, hypothesis, NOW + timedelta(seconds=5))
    egress = next(item for item in invariant if "UNAPPROVED_DESTINATION" in item.reason_codes)
    supported, disposition = disposition_finding(
        egress, "analyst:oncall", "threat_hunter", Disposition.SUPPORTED,
        "trusted inventory and signed network evidence confirm unapproved egress", NOW + timedelta(seconds=6),
    )
    candidate = DetectionCandidate(
        "DC-MCP-EGRESS-001", "MCP-HUNT-001", "1.0.0", "Unapproved MCP egress",
        hypothesis.hypothesis_id, (supported.finding_id,),
        "kind=network AND destination NOT IN trusted_inventory.allowed_destinations",
        ("tenant_id", "server_id", "destination", "event_id"), timedelta(minutes=5),
        ("tenant_id", "server_id", "destination"), None,
        hypothesis.exclusions, "dataset:mcp-egress-v1", 1.0, 1.0,
        "team:detection-engineering",
    )
    registry = DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:peer", "detection_reviewer", NOW + timedelta(seconds=7))
    promoted = registry.register_test(candidate, receipt, NOW + timedelta(seconds=8), [supported])
    print(json.dumps({
        "data_ready": prepared.report.ready,
        "invariant_findings": len(invariant),
        "graph_findings": len(graph),
        "supported_finding": supported.finding_id,
        "disposition": disposition.disposition,
        "detection_state": promoted.state,
        "containment_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
