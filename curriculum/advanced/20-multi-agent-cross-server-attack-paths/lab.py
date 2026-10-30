"""Course 20: policy-aware multi-agent and cross-server attack graphs.

The lab is deliberately offline and deterministic. NetworkX enumerates bounded
topological paths; current control-plane state decides whether an edge is
executable; and an independent resource ledger proves whether an effect
actually occurred. A graph heuristic is never treated as authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac
import json
from typing import Iterable

import networkx as nx


UTC = timezone.utc
NOW = datetime(2026, 10, 28, 18, 0, tzinfo=UTC)
MAX_EVIDENCE_AGE = timedelta(hours=24)
SNAPSHOT_KEY = b"course-20-training-key-not-for-production"


def utc(value: str) -> datetime:
    """Parse an RFC 3339 timestamp and require timezone information."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class AssetKind(StrEnum):
    HOST = "host"
    AGENT = "agent"
    MCP_GATEWAY = "mcp_gateway"
    MCP_SERVER = "mcp_server"
    API = "api"
    DATA = "data"
    MEMORY = "memory"
    REGISTRY = "registry"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Relation(StrEnum):
    CALLS = "calls"
    ROUTES = "routes"
    READS = "reads"
    WRITES = "writes"
    DELEGATES = "delegates"
    REUSES_CREDENTIAL = "reuses_credential"
    INFLUENCES = "influences"
    DISCOVERS = "discovers"


class DecisionCode(StrEnum):
    ALLOW = "ALLOW"
    EDGE_DISABLED = "EDGE_DISABLED"
    ASSET_INACTIVE = "ASSET_INACTIVE"
    ASSET_QUARANTINED = "ASSET_QUARANTINED"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    ROUTE_DENIED = "ROUTE_DENIED"
    GATEWAY_REQUIRED = "GATEWAY_REQUIRED"
    REGISTRY_BINDING_INVALID = "REGISTRY_BINDING_INVALID"
    CREDENTIAL_MISSING = "CREDENTIAL_MISSING"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_TENANT_MISMATCH = "CREDENTIAL_TENANT_MISMATCH"
    CREDENTIAL_AUDIENCE_MISMATCH = "CREDENTIAL_AUDIENCE_MISMATCH"
    CREDENTIAL_ACTION_MISMATCH = "CREDENTIAL_ACTION_MISMATCH"
    CREDENTIAL_RESOURCE_MISMATCH = "CREDENTIAL_RESOURCE_MISMATCH"
    CREDENTIAL_PRESENTER_MISMATCH = "CREDENTIAL_PRESENTER_MISMATCH"
    WILDCARD_CREDENTIAL_DENIED = "WILDCARD_CREDENTIAL_DENIED"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    UNTRUSTED_SIGNAL_IS_NOT_AUTHORITY = "UNTRUSTED_SIGNAL_IS_NOT_AUTHORITY"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: AssetKind
    tenant: str
    zone: str
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    criticality: int = 1
    audience: str = ""
    resource: str = ""
    artifact_digest: str = ""
    workload_id: str = ""
    active: bool = True

    def __post_init__(self) -> None:
        if not self.asset_id or not self.tenant or not self.zone:
            raise ValueError("asset identity, tenant, and zone are required")
        if not 1 <= self.criticality <= 5:
            raise ValueError("criticality must be between 1 and 5")


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    kind: str
    observed_at: datetime
    digest: str

    def __post_init__(self) -> None:
        if not all((self.evidence_id, self.source, self.kind, self.digest)):
            raise ValueError("complete evidence provenance is required")
        if self.observed_at.tzinfo is None:
            raise ValueError("evidence time must be timezone-aware")


@dataclass(frozen=True)
class Credential:
    credential_id: str
    subject: str
    tenant: str
    audiences: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    expires_at: datetime
    sender_bound: bool
    presenter: str

    @property
    def contains_wildcard(self) -> bool:
        return "*" in self.audiences or "*" in self.actions or "*" in self.resources


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    tenant: str
    source: str
    target: str
    action: str
    resource: str
    expires_at: datetime
    consumed: bool = False


@dataclass(frozen=True)
class RegistryBinding:
    server_id: str
    tenant: str
    artifact_digest: str
    workload_id: str
    active: bool = True


@dataclass(frozen=True)
class AttackEdge:
    edge_id: str
    source: str
    target: str
    relation: Relation
    action: str
    resource: str
    tenant: str
    evidence_ids: tuple[str, ...]
    credential_id: str = ""
    approval_id: str = ""
    registry_server_id: str = ""
    requires_gateway: bool = False
    untrusted_signal_only: bool = False
    technique: str = ""
    active: bool = True

    def __post_init__(self) -> None:
        if not all((self.edge_id, self.source, self.target, self.action, self.tenant)):
            raise ValueError("edge identity and security context are required")
        if not self.evidence_ids:
            raise ValueError("every edge requires provenance evidence")


def _snapshot_payload(
    snapshot_id: str,
    epoch: int,
    observed_at: datetime,
    assets: tuple[Asset, ...],
    edges: tuple[AttackEdge, ...],
    evidence: tuple[Evidence, ...],
) -> dict[str, object]:
    def values(item: object) -> dict[str, object]:
        return {key: str(value) if isinstance(value, datetime) else value for key, value in item.__dict__.items()}

    return {
        "snapshot_id": snapshot_id,
        "epoch": epoch,
        "observed_at": observed_at.isoformat(),
        "assets": [values(asset) for asset in assets],
        "edges": [values(edge) for edge in edges],
        "evidence": [values(item) for item in evidence],
    }


@dataclass(frozen=True)
class GraphSnapshot:
    snapshot_id: str
    epoch: int
    observed_at: datetime
    assets: tuple[Asset, ...]
    edges: tuple[AttackEdge, ...]
    evidence: tuple[Evidence, ...]
    digest: str
    signature: str


def sign_snapshot(
    snapshot_id: str,
    epoch: int,
    observed_at: datetime,
    assets: Iterable[Asset],
    edges: Iterable[AttackEdge],
    evidence: Iterable[Evidence],
    *,
    key: bytes = SNAPSHOT_KEY,
) -> GraphSnapshot:
    asset_tuple, edge_tuple, evidence_tuple = tuple(assets), tuple(edges), tuple(evidence)
    payload = _snapshot_payload(snapshot_id, epoch, observed_at, asset_tuple, edge_tuple, evidence_tuple)
    digest = canonical_digest(payload)
    signature = hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()
    return GraphSnapshot(snapshot_id, epoch, observed_at, asset_tuple, edge_tuple, evidence_tuple, digest, signature)


def verify_snapshot(
    snapshot: GraphSnapshot,
    *,
    now: datetime,
    highest_epoch: int = 0,
    accepted_digest: str = "",
    key: bytes = SNAPSHOT_KEY,
) -> None:
    payload = _snapshot_payload(snapshot.snapshot_id, snapshot.epoch, snapshot.observed_at, snapshot.assets, snapshot.edges, snapshot.evidence)
    if snapshot.digest != canonical_digest(payload):
        raise ValueError("snapshot digest mismatch")
    expected = hmac.new(key, snapshot.digest.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(snapshot.signature, expected):
        raise ValueError("snapshot signature mismatch")
    if snapshot.epoch < highest_epoch:
        raise ValueError("snapshot rollback")
    if snapshot.epoch == highest_epoch and accepted_digest and snapshot.digest != accepted_digest:
        raise ValueError("snapshot equivocation")
    if snapshot.observed_at > now + timedelta(minutes=5):
        raise ValueError("snapshot from the future")
    if now - snapshot.observed_at > MAX_EVIDENCE_AGE:
        raise ValueError("snapshot is stale")
    for item in snapshot.evidence:
        if item.observed_at > snapshot.observed_at:
            raise ValueError("evidence is newer than its snapshot")


@dataclass(frozen=True)
class ControlPlane:
    revision: int
    updated_at: datetime
    credentials: tuple[Credential, ...]
    approvals: tuple[ApprovalReceipt, ...]
    registry_bindings: tuple[RegistryBinding, ...]
    allowed_routes: frozenset[tuple[str, str]]
    quarantined_assets: frozenset[str] = frozenset()
    revoked_credentials: frozenset[str] = frozenset()
    blocked_edges: frozenset[str] = frozenset()
    require_gateway: bool = False
    permit_wildcards: bool = True

    def credential(self, credential_id: str) -> Credential | None:
        return next((item for item in self.credentials if item.credential_id == credential_id), None)

    def approval(self, approval_id: str) -> ApprovalReceipt | None:
        return next((item for item in self.approvals if item.approval_id == approval_id), None)

    def binding(self, server_id: str) -> RegistryBinding | None:
        return next((item for item in self.registry_bindings if item.server_id == server_id), None)


@dataclass(frozen=True)
class EdgeDecision:
    edge_id: str
    allowed: bool
    code: DecisionCode
    detail: str


@dataclass(frozen=True)
class PathAssessment:
    nodes: tuple[str, ...]
    edge_ids: tuple[str, ...]
    decisions: tuple[EdgeDecision, ...]

    @property
    def executable(self) -> bool:
        return bool(self.edge_ids) and all(item.allowed for item in self.decisions)

    @property
    def first_denial(self) -> DecisionCode | None:
        return next((item.code for item in self.decisions if not item.allowed), None)


class AttackGraph:
    """A topology plus provenance; never an authorization engine by itself."""

    def __init__(self, snapshot: GraphSnapshot, *, now: datetime = NOW, highest_epoch: int = 0, accepted_digest: str = "") -> None:
        verify_snapshot(
            snapshot,
            now=now,
            highest_epoch=highest_epoch,
            accepted_digest=accepted_digest,
        )
        self.snapshot = snapshot
        self.assets = {item.asset_id: item for item in snapshot.assets}
        self.edges = {item.edge_id: item for item in snapshot.edges}
        self.evidence = {item.evidence_id: item for item in snapshot.evidence}
        if len(self.assets) != len(snapshot.assets):
            raise ValueError("duplicate asset identity")
        if len(self.edges) != len(snapshot.edges):
            raise ValueError("duplicate edge identity")
        if len(self.evidence) != len(snapshot.evidence):
            raise ValueError("duplicate evidence identity")
        self.graph = nx.DiGraph()
        for asset in snapshot.assets:
            self.graph.add_node(asset.asset_id, asset=asset)
        for edge in snapshot.edges:
            if edge.source not in self.assets or edge.target not in self.assets:
                raise ValueError(f"unknown endpoint on {edge.edge_id}")
            if any(evidence_id not in self.evidence for evidence_id in edge.evidence_ids):
                raise ValueError(f"unknown evidence on {edge.edge_id}")
            if self.graph.has_edge(edge.source, edge.target):
                raise ValueError("the training graph requires one edge per endpoint pair")
            self.graph.add_edge(edge.source, edge.target, edge_id=edge.edge_id)

    def topological_paths(self, source: str, target: str, *, max_hops: int = 6) -> tuple[tuple[str, ...], ...]:
        if source not in self.graph or target not in self.graph or not nx.has_path(self.graph, source, target):
            return ()
        return tuple(tuple(path) for path in nx.all_simple_paths(self.graph, source=source, target=target, cutoff=max_hops))

    def edge_for(self, source: str, target: str) -> AttackEdge:
        return self.edges[self.graph[source][target]["edge_id"]]

    def assess_edge(self, edge: AttackEdge, controls: ControlPlane, *, now: datetime = NOW) -> EdgeDecision:
        def deny(code: DecisionCode, detail: str) -> EdgeDecision:
            return EdgeDecision(edge.edge_id, False, code, detail)

        source, target = self.assets[edge.source], self.assets[edge.target]
        if not edge.active or edge.edge_id in controls.blocked_edges:
            return deny(DecisionCode.EDGE_DISABLED, "edge is disabled or blocked")
        if not source.active or not target.active:
            return deny(DecisionCode.ASSET_INACTIVE, "source or target is inactive")
        if edge.source in controls.quarantined_assets or edge.target in controls.quarantined_assets:
            return deny(DecisionCode.ASSET_QUARANTINED, "source or target is quarantined")
        for evidence_id in edge.evidence_ids:
            item = self.evidence.get(evidence_id)
            if item is None:
                return deny(DecisionCode.EVIDENCE_MISSING, evidence_id)
            if now - item.observed_at > MAX_EVIDENCE_AGE:
                return deny(DecisionCode.EVIDENCE_STALE, evidence_id)
        if source.tenant not in {edge.tenant, "shared"} or target.tenant not in {edge.tenant, "shared"}:
            return deny(DecisionCode.TENANT_MISMATCH, "edge crosses an unapproved tenant")
        if (edge.source, edge.target) not in controls.allowed_routes:
            return deny(DecisionCode.ROUTE_DENIED, "current network policy denies the route")
        if edge.requires_gateway and controls.require_gateway and source.kind != AssetKind.MCP_GATEWAY:
            return deny(DecisionCode.GATEWAY_REQUIRED, "direct route bypasses the gateway")
        if edge.untrusted_signal_only:
            return deny(DecisionCode.UNTRUSTED_SIGNAL_IS_NOT_AUTHORITY, "memory, prompt, or model content may influence but cannot authorize")
        if edge.registry_server_id:
            binding = controls.binding(edge.registry_server_id)
            if binding is None or not binding.active or binding.tenant != edge.tenant or binding.artifact_digest != target.artifact_digest or binding.workload_id != target.workload_id:
                return deny(DecisionCode.REGISTRY_BINDING_INVALID, "tenant, artifact, workload, and active state must match")
        if edge.credential_id:
            credential = controls.credential(edge.credential_id)
            if credential is None:
                return deny(DecisionCode.CREDENTIAL_MISSING, edge.credential_id)
            if credential.credential_id in controls.revoked_credentials:
                return deny(DecisionCode.CREDENTIAL_REVOKED, credential.credential_id)
            if credential.expires_at <= now:
                return deny(DecisionCode.CREDENTIAL_EXPIRED, credential.credential_id)
            if credential.tenant != edge.tenant:
                return deny(DecisionCode.CREDENTIAL_TENANT_MISMATCH, credential.tenant)
            if credential.contains_wildcard and not controls.permit_wildcards:
                return deny(DecisionCode.WILDCARD_CREDENTIAL_DENIED, credential.credential_id)
            if target.audience and target.audience not in credential.audiences and "*" not in credential.audiences:
                return deny(DecisionCode.CREDENTIAL_AUDIENCE_MISMATCH, target.audience)
            if edge.action not in credential.actions and "*" not in credential.actions:
                return deny(DecisionCode.CREDENTIAL_ACTION_MISMATCH, edge.action)
            if edge.resource and edge.resource not in credential.resources and "*" not in credential.resources:
                return deny(DecisionCode.CREDENTIAL_RESOURCE_MISMATCH, edge.resource)
            if credential.sender_bound and credential.presenter != edge.source:
                return deny(DecisionCode.CREDENTIAL_PRESENTER_MISMATCH, edge.source)
        if edge.approval_id:
            approval = controls.approval(edge.approval_id)
            if approval is None:
                return deny(DecisionCode.APPROVAL_MISSING, edge.approval_id)
            if approval.consumed or approval.expires_at <= now or approval.tenant != edge.tenant or approval.source != edge.source or approval.target != edge.target or approval.action != edge.action or approval.resource != edge.resource:
                return deny(DecisionCode.APPROVAL_INVALID, approval.approval_id)
        return EdgeDecision(edge.edge_id, True, DecisionCode.ALLOW, "all current gates allow")

    def assess_path(self, nodes: Iterable[str], controls: ControlPlane, *, now: datetime = NOW) -> PathAssessment:
        node_tuple = tuple(nodes)
        if len(node_tuple) < 2 or not nx.is_simple_path(self.graph, node_tuple):
            raise ValueError("a path must contain at least one valid, non-repeating edge")
        edges = tuple(self.edge_for(left, right) for left, right in nx.utils.pairwise(node_tuple))
        decisions = tuple(self.assess_edge(edge, controls, now=now) for edge in edges)
        return PathAssessment(node_tuple, tuple(edge.edge_id for edge in edges), decisions)

    def executable_paths(self, source: str, target: str, controls: ControlPlane, *, max_hops: int = 6, now: datetime = NOW) -> tuple[PathAssessment, ...]:
        return tuple(assessment for nodes in self.topological_paths(source, target, max_hops=max_hops) if (assessment := self.assess_path(nodes, controls, now=now)).executable)

    def sensitive_exposure(self, source: str, controls: ControlPlane, *, max_hops: int = 6, now: datetime = NOW) -> "ExposureReport":
        sensitive = tuple(sorted(asset.asset_id for asset in self.assets.values() if asset.sensitivity in {Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED}))
        reachable = tuple(asset_id for asset_id in sensitive if self.executable_paths(source, asset_id, controls, max_hops=max_hops, now=now))
        max_criticality = max((self.assets[item].criticality for item in reachable), default=0)
        return ExposureReport(source, sensitive, reachable, len(reachable) / len(sensitive) if sensitive else 0.0, max_criticality)

    def topological_choke_points(self, source: str, target: str) -> tuple[str, ...]:
        """Return planning hints, never an authorization or containment decision."""
        if source not in self.graph or target not in self.graph or not nx.has_path(self.graph, source, target):
            return ()
        return tuple(sorted(nx.minimum_node_cut(self.graph, source, target)))


@dataclass(frozen=True)
class ExposureReport:
    source: str
    sensitive_assets: tuple[str, ...]
    reachable_sensitive_assets: tuple[str, ...]
    exposure_rate: float
    maximum_criticality: int


@dataclass(frozen=True)
class EffectRecord:
    operation_id: str
    source: str
    target: str
    performed: bool
    observed_at: datetime
    reason: str


class ResourceLedger:
    """Independent outcome oracle: target state outranks agent or adapter prose."""

    def __init__(self) -> None:
        self.records: list[EffectRecord] = []

    def attempt(self, operation_id: str, assessment: PathAssessment, graph: AttackGraph, controls: ControlPlane, *, now: datetime = NOW, adapter_claim: str = "") -> EffectRecord:
        current = graph.assess_path(assessment.nodes, controls, now=now)
        target = graph.assets[current.nodes[-1]]
        performed = current.executable and target.kind == AssetKind.DATA
        reason = "final resource recorded the effect" if performed else (current.first_denial.value if current.first_denial else "target is not an effect resource")
        record = EffectRecord(operation_id, current.nodes[0], current.nodes[-1], performed, now, reason)
        self.records.append(record)
        return record

    def forbidden_effects_since(self, source: str, since: datetime) -> tuple[EffectRecord, ...]:
        return tuple(item for item in self.records if item.source == source and item.observed_at >= since and item.performed)


@dataclass(frozen=True)
class LabelledCase:
    name: str
    source: str
    target: str
    should_allow: bool


@dataclass(frozen=True)
class EvaluationReport:
    total: int
    unsafe_allow_count: int
    valid_case_count: int
    false_block_count: int
    unsafe_allow_rate: float
    false_block_rate: float
    decisions: tuple[tuple[str, bool, bool], ...]


def evaluate_cases(graph: AttackGraph, controls: ControlPlane, cases: Iterable[LabelledCase], *, now: datetime = NOW) -> EvaluationReport:
    results = tuple((case.name, case.should_allow, bool(graph.executable_paths(case.source, case.target, controls, now=now))) for case in cases)
    unsafe = sum(not expected and actual for _, expected, actual in results)
    valid = sum(expected for _, expected, _ in results)
    false_blocks = sum(expected and not actual for _, expected, actual in results)
    negative = len(results) - valid
    return EvaluationReport(len(results), unsafe, valid, false_blocks, unsafe / negative if negative else 0.0, false_blocks / valid if valid else 0.0, results)


@dataclass(frozen=True)
class ContainmentEvent:
    revision: int
    occurred_at: datetime
    kind: str
    target: str


def apply_containment_event(controls: ControlPlane, event: ContainmentEvent) -> ControlPlane:
    if event.revision != controls.revision + 1:
        raise ValueError("containment revisions must be contiguous")
    if event.occurred_at < controls.updated_at:
        raise ValueError("containment time cannot move backwards")
    changes: dict[str, object] = {"revision": event.revision, "updated_at": event.occurred_at}
    if event.kind == "quarantine_asset":
        changes["quarantined_assets"] = controls.quarantined_assets | {event.target}
    elif event.kind == "revoke_credential":
        changes["revoked_credentials"] = controls.revoked_credentials | {event.target}
    elif event.kind == "block_edge":
        changes["blocked_edges"] = controls.blocked_edges | {event.target}
    elif event.kind == "require_gateway":
        changes["require_gateway"] = True
    elif event.kind == "deny_wildcards":
        changes["permit_wildcards"] = False
    else:
        raise ValueError("unknown containment event")
    return replace(controls, **changes)


@dataclass(frozen=True)
class ContainmentProof:
    complete: bool
    required_revision: int
    observed_revision: int
    residual_targets: tuple[str, ...]
    forbidden_effect_count: int
    time_to_cut_seconds: float | None


def prove_containment(graph: AttackGraph, controls: ControlPlane, ledger: ResourceLedger, *, source: str, targets: Iterable[str], required_revision: int, incident_started_at: datetime, now: datetime) -> ContainmentProof:
    residual = tuple(target for target in targets if graph.executable_paths(source, target, controls, now=now))
    effects = ledger.forbidden_effects_since(source, controls.updated_at)
    propagated = controls.revision >= required_revision
    complete = propagated and not residual and not effects
    time_to_cut = (controls.updated_at - incident_started_at).total_seconds() if complete else None
    return ContainmentProof(complete, required_revision, controls.revision, residual, len(effects), time_to_cut)


@dataclass(frozen=True)
class Environment:
    graph: AttackGraph
    unsafe_controls: ControlPlane
    hardened_controls: ControlPlane
    cases: tuple[LabelledCase, ...]


def _asset(asset_id: str, kind: AssetKind, *, tenant: str = "acme", zone: str = "application", sensitivity: Sensitivity = Sensitivity.INTERNAL, criticality: int = 1, audience: str = "", resource: str = "", artifact: str = "", workload: str = "") -> Asset:
    return Asset(asset_id, kind, tenant, zone, sensitivity, criticality, audience, resource, artifact, workload)


def build_environment(*, now: datetime = NOW) -> Environment:
    """Build a synthetic but enterprise-shaped support platform."""
    assets = (
        _asset("triage-agent", AssetKind.AGENT, workload="spiffe://acme/agent/triage"),
        _asset("analytics-server", AssetKind.MCP_SERVER, audience="mcp://analytics", artifact="sha256:analytics-v1", workload="spiffe://acme/mcp/analytics"),
        _asset("mcp-gateway", AssetKind.MCP_GATEWAY, audience="mcp://gateway", zone="edge"),
        _asset("support-server", AssetKind.MCP_SERVER, audience="mcp://support", artifact="sha256:support-v3", workload="spiffe://acme/mcp/support"),
        _asset("ticket-api", AssetKind.API, audience="api://tickets", zone="data"),
        _asset("customer-pii", AssetKind.DATA, zone="data", sensitivity=Sensitivity.CONFIDENTIAL, criticality=4, resource="data://acme/customer-pii"),
        _asset("secrets-api", AssetKind.API, audience="api://secrets", zone="privileged"),
        _asset("production-secret", AssetKind.DATA, zone="privileged", sensitivity=Sensitivity.RESTRICTED, criticality=5, resource="secret://acme/production"),
        _asset("shared-memory", AssetKind.MEMORY, tenant="shared", zone="coordination"),
        _asset("rogue-support", AssetKind.MCP_SERVER, audience="mcp://support", artifact="sha256:rogue", workload="spiffe://evil/rogue"),
    )
    evidence = (
        Evidence("ev-registry", "enterprise-registry", "signed-binding", now - timedelta(minutes=8), "sha256:reg"),
        Evidence("ev-iam", "iam-export", "credential-binding", now - timedelta(minutes=7), "sha256:iam"),
        Evidence("ev-net", "network-policy", "allowed-route", now - timedelta(minutes=6), "sha256:net"),
        Evidence("ev-trace", "otel-collector", "observed-call", now - timedelta(minutes=5), "sha256:trace"),
    )

    def edge(edge_id: str, source: str, target: str, relation: Relation, action: str, resource: str, *, credential: str = "", registry: str = "", gateway: bool = False, signal: bool = False, technique: str = "") -> AttackEdge:
        return AttackEdge(edge_id, source, target, relation, action, resource, "acme", ("ev-registry", "ev-iam", "ev-net", "ev-trace"), credential_id=credential, registry_server_id=registry, requires_gateway=gateway, untrusted_signal_only=signal, technique=technique)

    edges = (
        edge("e-valid-agent-gateway", "triage-agent", "mcp-gateway", Relation.CALLS, "route", "mcp://support", credential="cred-triage"),
        edge("e-stolen-to-gateway", "analytics-server", "mcp-gateway", Relation.REUSES_CREDENTIAL, "route", "mcp://support", credential="cred-shared", technique="T1078 Valid Accounts"),
        edge("e-gateway-support", "mcp-gateway", "support-server", Relation.ROUTES, "ticket.read", "data://acme/customer-pii", credential="cred-gateway-support", registry="support-server"),
        edge("e-support-ticket", "support-server", "ticket-api", Relation.CALLS, "ticket.read", "data://acme/customer-pii", credential="cred-support-api"),
        edge("e-ticket-pii", "ticket-api", "customer-pii", Relation.READS, "data.read", "data://acme/customer-pii"),
        edge("e-direct-secrets", "analytics-server", "secrets-api", Relation.REUSES_CREDENTIAL, "secret.read", "secret://acme/production", credential="cred-shared", gateway=True, technique="T1021 Remote Services"),
        edge("e-secrets-data", "secrets-api", "production-secret", Relation.READS, "data.read", "secret://acme/production"),
        edge("e-poison-memory", "analytics-server", "shared-memory", Relation.WRITES, "memory.write", "memory://shared", credential="cred-shared"),
        edge("e-memory-agent", "shared-memory", "triage-agent", Relation.INFLUENCES, "agent.influence", "agent://triage", signal=True, technique="indirect prompt injection"),
        edge("e-discover-rogue", "analytics-server", "rogue-support", Relation.DISCOVERS, "server.discover", "mcp://support", credential="cred-shared", registry="rogue-support"),
        edge("e-rogue-secrets", "rogue-support", "secrets-api", Relation.CALLS, "secret.read", "secret://acme/production", credential="cred-shared", gateway=True),
    )
    snapshot = sign_snapshot("support-platform-graph", 7, now, assets, edges, evidence)
    graph = AttackGraph(snapshot, now=now, highest_epoch=6)
    credentials = (
        Credential("cred-shared", "svc:shared-ops", "acme", ("*",), ("*",), ("*",), now + timedelta(hours=8), False, ""),
        Credential("cred-triage", "agent:triage", "acme", ("mcp://gateway",), ("route",), ("mcp://support",), now + timedelta(minutes=10), True, "triage-agent"),
        Credential("cred-gateway-support", "gateway", "acme", ("mcp://support",), ("ticket.read",), ("data://acme/customer-pii",), now + timedelta(minutes=5), True, "mcp-gateway"),
        Credential("cred-support-api", "support-server", "acme", ("api://tickets",), ("ticket.read",), ("data://acme/customer-pii",), now + timedelta(minutes=5), True, "support-server"),
    )
    bindings = (
        RegistryBinding("support-server", "acme", "sha256:support-v3", "spiffe://acme/mcp/support"),
        RegistryBinding("rogue-support", "acme", "sha256:support-v3", "spiffe://acme/mcp/support", False),
    )
    routes = frozenset((item.source, item.target) for item in edges)
    unsafe = ControlPlane(1, now - timedelta(minutes=1), credentials, (), bindings, routes)
    hardened = replace(unsafe, revision=5, updated_at=now, revoked_credentials=frozenset({"cred-shared"}), quarantined_assets=frozenset({"analytics-server"}), blocked_edges=frozenset({"e-direct-secrets", "e-discover-rogue"}), require_gateway=True, permit_wildcards=False)
    cases = (
        LabelledCase("valid-triage-read", "triage-agent", "customer-pii", True),
        LabelledCase("stolen-shared-token-to-pii", "analytics-server", "customer-pii", False),
        LabelledCase("gateway-bypass-to-secret", "analytics-server", "production-secret", False),
        LabelledCase("poisoned-memory-to-pii", "shared-memory", "customer-pii", False),
        LabelledCase("rogue-registry-to-secret", "analytics-server", "production-secret", False),
    )
    return Environment(graph, unsafe, hardened, cases)


def run_demo() -> dict[str, object]:
    env = build_environment()
    graph = env.graph
    unsafe_exposure = graph.sensitive_exposure("analytics-server", env.unsafe_controls)
    hardened_exposure = graph.sensitive_exposure("analytics-server", env.hardened_controls)
    unsafe_evaluation = evaluate_cases(graph, env.unsafe_controls, env.cases)
    hardened_evaluation = evaluate_cases(graph, env.hardened_controls, env.cases)
    path = graph.executable_paths("analytics-server", "production-secret", env.unsafe_controls)[0]
    ledger = ResourceLedger()
    before = ledger.attempt(
        "op-before-containment",
        path,
        graph,
        env.unsafe_controls,
        now=NOW - timedelta(minutes=2),
        adapter_claim="blocked",
    )
    after = ledger.attempt("op-after-containment", path, graph, env.hardened_controls, adapter_claim="allowed")
    proof = prove_containment(graph, env.hardened_controls, ledger, source="analytics-server", targets=("customer-pii", "production-secret"), required_revision=5, incident_started_at=NOW - timedelta(minutes=4), now=NOW)
    return {
        "networkx_version": nx.__version__,
        "snapshot": {"epoch": graph.snapshot.epoch, "verified": True},
        "topological_paths_to_secret": len(graph.topological_paths("analytics-server", "production-secret")),
        "unsafe_exposure": unsafe_exposure,
        "hardened_exposure": hardened_exposure,
        "unsafe_evaluation": unsafe_evaluation,
        "hardened_evaluation": hardened_evaluation,
        "outcome_oracle": {"before": before.performed, "after": after.performed},
        "containment": proof,
        "choke_points_are_hints": graph.topological_choke_points("analytics-server", "production-secret"),
    }


def main() -> None:
    result = run_demo()
    assert result["unsafe_exposure"].exposure_rate == 1.0
    assert result["hardened_exposure"].exposure_rate == 0.0
    assert result["unsafe_evaluation"].unsafe_allow_count >= 2
    assert result["hardened_evaluation"].unsafe_allow_count == 0
    assert result["hardened_evaluation"].false_block_count == 0
    assert result["outcome_oracle"] == {"before": True, "after": False}
    assert result["containment"].complete is True
    print("PASS: policy-aware paths, effect state, and containment proof agree")


if __name__ == "__main__":
    main()
