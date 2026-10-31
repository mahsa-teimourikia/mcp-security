"""Course 23: evidence-backed enterprise MCP security architecture.

This credential-free lab treats architecture as an executable contract. It
signs a versioned platform manifest, enumerates every request path to protected
resources, verifies defense-in-depth controls and ownership, injects control-
plane failures, and evaluates labelled valid and adversarial requests. A model
may recommend a design, but trusted application code owns validation, approval,
catalog state, authorization, execution, and evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import hmac
import json
from threading import Lock
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import networkx as nx
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


UTC = timezone.utc
NOW = datetime(2026, 10, 31, 1, 0, tzinfo=UTC)
PROTOCOL_VERSION = "2026-07-28"
ARCHITECTURE_POLICY_VERSION = "enterprise-mcp-architecture/2026-10-31"
REQUIRED_CONTROL_REVISION = 17
MAX_REVIEW_AGE = timedelta(hours=1)
APPROVAL_KEY = b"course-23-architecture-approval"
ARCHITECTURE_SEED = sha256(b"course-23-architecture-signing-ed25519").digest()
ARCHITECTURE_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(ARCHITECTURE_SEED)
ARCHITECTURE_PUBLIC_KEY = ARCHITECTURE_PRIVATE_KEY.public_key()
APPROVER_ROLES = frozenset({"security_architect", "platform_risk_owner"})


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


class ComponentKind(StrEnum):
    HOST = "host"
    GATEWAY = "gateway"
    REGISTRY = "registry"
    IDENTITY = "identity"
    POLICY = "policy"
    MCP_SERVER = "mcp_server"
    SANDBOX = "sandbox"
    EGRESS = "egress"
    TELEMETRY = "telemetry"
    REVOCATION = "revocation"
    RESOURCE = "resource"


class Control(StrEnum):
    AUTHENTICATION = "authentication"
    IDENTITY_CONTEXT = "identity_context"
    TRANSPORT_AUTHORIZATION = "transport_authorization"
    TOOL_AUTHORIZATION = "tool_authorization"
    TENANT_ENFORCEMENT = "tenant_enforcement"
    CAPABILITY_CONFINEMENT = "capability_confinement"
    INPUT_VALIDATION = "input_validation"
    PROVENANCE = "provenance"
    LIFECYCLE = "lifecycle"
    POLICY_DISTRIBUTION = "policy_distribution"
    ISOLATION = "isolation"
    EGRESS = "egress"
    OBSERVABILITY = "observability"
    REVOCATION = "revocation"
    RATE_LIMIT = "rate_limit"
    AUDIT = "audit"


class RiskTier(StrEnum):
    LOW = "low"
    HIGH = "high"


class ReviewStatus(StrEnum):
    NEEDS_REMEDIATION = "needs_remediation"
    ELIGIBLE_FOR_HUMAN_REVIEW = "eligible_for_human_review"


class CatalogStatus(StrEnum):
    CANDIDATE = "candidate"
    APPROVED_REFERENCE = "approved_reference"


PATH_CONTROLS = frozenset(
    {
        Control.AUTHENTICATION,
        Control.IDENTITY_CONTEXT,
        Control.TRANSPORT_AUTHORIZATION,
        Control.TOOL_AUTHORIZATION,
        Control.TENANT_ENFORCEMENT,
        Control.CAPABILITY_CONFINEMENT,
        Control.INPUT_VALIDATION,
        Control.ISOLATION,
        Control.AUDIT,
    }
)
GLOBAL_CONTROLS = frozenset(
    {
        Control.PROVENANCE,
        Control.LIFECYCLE,
        Control.POLICY_DISTRIBUTION,
        Control.EGRESS,
        Control.OBSERVABILITY,
        Control.REVOCATION,
        Control.RATE_LIMIT,
    }
)
EXECUTABLE_KINDS = frozenset(
    {
        ComponentKind.HOST,
        ComponentKind.GATEWAY,
        ComponentKind.MCP_SERVER,
        ComponentKind.SANDBOX,
    }
)
FAIL_CLOSED_KINDS = frozenset(
    {
        ComponentKind.IDENTITY,
        ComponentKind.REGISTRY,
        ComponentKind.POLICY,
        ComponentKind.REVOCATION,
    }
)
RUNTIME_PLANE_KINDS = FAIL_CLOSED_KINDS
KIND_REQUIRED_CONTROLS = {
    ComponentKind.REGISTRY: frozenset({Control.PROVENANCE, Control.LIFECYCLE}),
    ComponentKind.IDENTITY: frozenset(
        {Control.AUTHENTICATION, Control.IDENTITY_CONTEXT}
    ),
    ComponentKind.POLICY: frozenset({Control.POLICY_DISTRIBUTION}),
    ComponentKind.EGRESS: frozenset({Control.EGRESS}),
    ComponentKind.TELEMETRY: frozenset({Control.OBSERVABILITY, Control.AUDIT}),
    ComponentKind.REVOCATION: frozenset({Control.REVOCATION}),
}
TOOL_CONTRACTS = {
    "tickets.read": ("tickets:read", "tools", RiskTier.LOW),
    "tickets.comment": ("tickets:comment", "tools", RiskTier.HIGH),
}


@dataclass(frozen=True)
class Component:
    component_id: str
    kind: ComponentKind
    resource_uri: str
    owner: str
    region: str
    trust_domain: str
    tenant_scope: tuple[str, ...]
    controls: tuple[Control, ...]
    fail_mode: str
    high_availability: bool
    artifact_digest: str
    provenance_verified: bool
    policy_version: str
    control_revision: int
    evidence_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    runbook_id: str


@dataclass(frozen=True)
class DataFlow:
    flow_id: str
    source: str
    target: str
    protocol: str
    purposes: tuple[str, ...]
    data_classes: tuple[str, ...]
    encrypted: bool
    mutually_authenticated: bool
    tenant_bound: bool
    max_payload_bytes: int


@dataclass(frozen=True)
class ArchitectureManifest:
    architecture_id: str
    version: int
    protocol_version: str
    policy_version: str
    required_control_revision: int
    created_at: datetime
    entrypoints: tuple[str, ...]
    protected_resources: tuple[str, ...]
    components: tuple[Component, ...]
    flows: tuple[DataFlow, ...]
    manifest_digest: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("manifest_digest")
        result.pop("signature")
        return result


def _component(
    component_id: str,
    kind: ComponentKind,
    controls: Iterable[Control],
    *,
    owner: str,
    resource_uri: str = "",
    region: str = "ca-west",
    trust_domain: str = "spiffe://acme.example",
    tenant_scope: tuple[str, ...] = ("acme", "beta"),
    fail_mode: str = "fail_closed",
    high_availability: bool = True,
    artifact_name: str = "",
    provenance_verified: bool = True,
    control_revision: int = REQUIRED_CONTROL_REVISION,
) -> Component:
    executable = kind in EXECUTABLE_KINDS
    artifact_digest = digest((artifact_name or component_id).encode()) if executable else ""
    return Component(
        component_id=component_id,
        kind=kind,
        resource_uri=resource_uri,
        owner=owner,
        region=region,
        trust_domain=trust_domain,
        tenant_scope=tenant_scope,
        controls=tuple(sorted(set(controls), key=str)),
        fail_mode=fail_mode,
        high_availability=high_availability,
        artifact_digest=artifact_digest,
        provenance_verified=provenance_verified if executable else False,
        policy_version=ARCHITECTURE_POLICY_VERSION,
        control_revision=control_revision,
        evidence_ids=(f"evidence:{component_id}:design", f"evidence:{component_id}:drill"),
        test_ids=(f"test:{component_id}:positive", f"test:{component_id}:negative"),
        runbook_id=f"runbook:{component_id}:failure",
    )


def _flow(
    flow_id: str,
    source: str,
    target: str,
    *,
    purposes: tuple[str, ...] = ("support-ticket-read", "support-ticket-comment"),
    data_classes: tuple[str, ...] = ("customer-confidential",),
) -> DataFlow:
    return DataFlow(
        flow_id,
        source,
        target,
        "mTLS+HTTP/JSON-RPC",
        purposes,
        data_classes,
        True,
        True,
        True,
        1_048_576,
    )


def sign_manifest(manifest: ArchitectureManifest) -> ArchitectureManifest:
    manifest_digest = digest(manifest.unsigned())
    signature = ARCHITECTURE_PRIVATE_KEY.sign(manifest_digest.encode()).hex()
    return replace(manifest, manifest_digest=manifest_digest, signature=signature)


def verify_manifest(
    manifest: ArchitectureManifest,
    public_key: Ed25519PublicKey = ARCHITECTURE_PUBLIC_KEY,
) -> bool:
    expected_digest = digest(manifest.unsigned())
    try:
        public_key.verify(bytes.fromhex(manifest.signature), expected_digest.encode())
    except (InvalidSignature, ValueError):
        return False
    return hmac.compare_digest(expected_digest, manifest.manifest_digest)


def build_reference_manifest(*, now: datetime = NOW) -> ArchitectureManifest:
    components = (
        _component(
            "host",
            ComponentKind.HOST,
            {
                Control.AUTHENTICATION,
                Control.IDENTITY_CONTEXT,
                Control.CAPABILITY_CONFINEMENT,
                Control.AUDIT,
            },
            owner="agent-platform",
        ),
        _component(
            "gateway",
            ComponentKind.GATEWAY,
            {
                Control.TRANSPORT_AUTHORIZATION,
                Control.TENANT_ENFORCEMENT,
                Control.RATE_LIMIT,
                Control.AUDIT,
            },
            owner="edge-security",
        ),
        _component(
            "registry",
            ComponentKind.REGISTRY,
            {Control.PROVENANCE, Control.LIFECYCLE},
            owner="software-supply-chain",
        ),
        _component(
            "identity",
            ComponentKind.IDENTITY,
            {Control.AUTHENTICATION, Control.IDENTITY_CONTEXT},
            owner="identity-platform",
        ),
        _component(
            "policy",
            ComponentKind.POLICY,
            {Control.POLICY_DISTRIBUTION},
            owner="authorization-platform",
        ),
        _component(
            "support-mcp",
            ComponentKind.MCP_SERVER,
            {
                Control.AUTHENTICATION,
                Control.IDENTITY_CONTEXT,
                Control.TRANSPORT_AUTHORIZATION,
                Control.TOOL_AUTHORIZATION,
                Control.TENANT_ENFORCEMENT,
                Control.CAPABILITY_CONFINEMENT,
                Control.INPUT_VALIDATION,
                Control.AUDIT,
                Control.REVOCATION,
            },
            owner="support-platform",
            resource_uri="https://mcp.example.com/support",
        ),
        _component(
            "sandbox",
            ComponentKind.SANDBOX,
            {Control.ISOLATION, Control.INPUT_VALIDATION},
            owner="runtime-security",
        ),
        _component(
            "egress",
            ComponentKind.EGRESS,
            {Control.EGRESS},
            owner="network-security",
        ),
        _component(
            "telemetry",
            ComponentKind.TELEMETRY,
            {Control.OBSERVABILITY, Control.AUDIT},
            owner="security-operations",
            fail_mode="degraded_buffer",
        ),
        _component(
            "revocation",
            ComponentKind.REVOCATION,
            {Control.REVOCATION},
            owner="incident-response",
        ),
        _component(
            "ticket-ledger",
            ComponentKind.RESOURCE,
            set(),
            owner="support-data",
            trust_domain="spiffe://data.acme.example",
        ),
    )
    flows = (
        _flow("host-gateway", "host", "gateway"),
        _flow("gateway-server", "gateway", "support-mcp"),
        _flow("server-sandbox", "support-mcp", "sandbox"),
        _flow("sandbox-resource", "sandbox", "ticket-ledger"),
    )
    unsigned = ArchitectureManifest(
        architecture_id="enterprise-mcp-reference",
        version=7,
        protocol_version=PROTOCOL_VERSION,
        policy_version=ARCHITECTURE_POLICY_VERSION,
        required_control_revision=REQUIRED_CONTROL_REVISION,
        created_at=now,
        entrypoints=("host",),
        protected_resources=("ticket-ledger",),
        components=components,
        flows=flows,
        manifest_digest="",
        signature="",
    )
    return sign_manifest(unsigned)


@dataclass(frozen=True)
class ReviewFinding:
    code: str
    severity: str
    component_id: str
    evidence: str
    owner: str


@dataclass(frozen=True)
class ArchitectureReview:
    architecture_id: str
    manifest_digest: str
    reviewed_at: datetime
    status: ReviewStatus
    findings: tuple[ReviewFinding, ...]
    path_count: int
    secured_path_count: int
    minimum_independent_enforcers: int
    evidence_coverage_rate: float
    production_authorized: bool
    review_digest: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("review_digest")
        return result


def verify_review(review: ArchitectureReview) -> bool:
    return (
        review.production_authorized is False
        and hmac.compare_digest(review.review_digest, digest(review.unsigned()))
    )


def _finding(
    code: str,
    component_id: str,
    evidence: str,
    owner: str = "security-architecture",
    severity: str = "important",
) -> ReviewFinding:
    return ReviewFinding(code, severity, component_id, evidence, owner)


def _component_map(manifest: ArchitectureManifest) -> dict[str, Component]:
    return {component.component_id: component for component in manifest.components}


def _graph(manifest: ArchitectureManifest) -> nx.DiGraph:
    graph = nx.DiGraph()
    for component in manifest.components:
        graph.add_node(component.component_id, component=component)
    for flow in manifest.flows:
        graph.add_edge(flow.source, flow.target, flow=flow)
    return graph


def review_architecture(
    manifest: ArchitectureManifest,
    *,
    now: datetime = NOW,
) -> ArchitectureReview:
    findings: list[ReviewFinding] = []
    ids = [component.component_id for component in manifest.components]
    components = _component_map(manifest)

    if not verify_manifest(manifest):
        findings.append(_finding("MANIFEST_INTEGRITY_INVALID", "manifest", "signature"))
    if manifest.protocol_version != PROTOCOL_VERSION:
        findings.append(_finding("PROTOCOL_VERSION_UNSUPPORTED", "manifest", manifest.protocol_version))
    if manifest.policy_version != ARCHITECTURE_POLICY_VERSION:
        findings.append(_finding("POLICY_VERSION_STALE", "manifest", manifest.policy_version))
    if manifest.required_control_revision < REQUIRED_CONTROL_REVISION:
        findings.append(_finding("CONTROL_REVISION_STALE", "manifest", str(manifest.required_control_revision)))
    if manifest.created_at > now + timedelta(seconds=5):
        findings.append(_finding("MANIFEST_FROM_FUTURE", "manifest", manifest.created_at.isoformat()))
    if len(ids) != len(set(ids)):
        findings.append(_finding("DUPLICATE_COMPONENT_ID", "manifest", "component IDs must be unique"))

    present_kinds = {component.kind for component in manifest.components}
    for kind in sorted(set(ComponentKind) - present_kinds, key=str):
        findings.append(_finding("COMPONENT_KIND_MISSING", str(kind), "required control plane"))

    evidence_slots = 0
    evidence_filled = 0
    for component in manifest.components:
        fields = (component.owner, component.evidence_ids, component.test_ids, component.runbook_id)
        evidence_slots += len(fields)
        evidence_filled += sum(bool(field) for field in fields)
        if not all(fields):
            findings.append(_finding("OWNERSHIP_OR_EVIDENCE_MISSING", component.component_id, "owner/evidence/test/runbook"))
        if not component.tenant_scope:
            findings.append(_finding("TENANT_SCOPE_EMPTY", component.component_id, "tenant scope"))
        if component.policy_version != manifest.policy_version:
            findings.append(_finding("COMPONENT_POLICY_STALE", component.component_id, component.policy_version))
        if component.control_revision < manifest.required_control_revision:
            findings.append(_finding("COMPONENT_REVISION_STALE", component.component_id, str(component.control_revision)))
        if component.kind in EXECUTABLE_KINDS:
            if not component.artifact_digest.startswith("sha256:"):
                findings.append(_finding("ARTIFACT_NOT_IMMUTABLE", component.component_id, component.artifact_digest))
            if not component.provenance_verified:
                findings.append(_finding("PROVENANCE_UNVERIFIED", component.component_id, "artifact provenance"))
        if component.kind == ComponentKind.MCP_SERVER and (
            not component.resource_uri.startswith("https://")
            or "#" in component.resource_uri
        ):
            findings.append(
                _finding(
                    "SERVER_RESOURCE_URI_INVALID",
                    component.component_id,
                    component.resource_uri,
                )
            )
        if component.kind in FAIL_CLOSED_KINDS and component.fail_mode != "fail_closed":
            findings.append(_finding("CONTROL_PLANE_FAILS_OPEN", component.component_id, component.fail_mode, severity="blocker"))
        if component.kind in FAIL_CLOSED_KINDS and not component.high_availability:
            findings.append(_finding("CONTROL_PLANE_SINGLETON", component.component_id, "no tested redundant instance"))

    for entrypoint in manifest.entrypoints:
        if entrypoint not in components:
            findings.append(_finding("ENTRYPOINT_UNKNOWN", entrypoint, "entrypoint"))
    for resource in manifest.protected_resources:
        if resource not in components or components[resource].kind != ComponentKind.RESOURCE:
            findings.append(_finding("PROTECTED_RESOURCE_INVALID", resource, "protected resource"))

    seen_flows: set[str] = set()
    for flow in manifest.flows:
        if flow.flow_id in seen_flows:
            findings.append(_finding("DUPLICATE_FLOW_ID", flow.flow_id, "flow ID"))
        seen_flows.add(flow.flow_id)
        if flow.source not in components or flow.target not in components:
            findings.append(_finding("FLOW_ENDPOINT_UNKNOWN", flow.flow_id, f"{flow.source}->{flow.target}"))
            continue
        if not flow.purposes or not flow.data_classes:
            findings.append(_finding("FLOW_UNCLASSIFIED", flow.flow_id, "purpose or data classification"))
        if not flow.encrypted or not flow.mutually_authenticated:
            findings.append(_finding("FLOW_CHANNEL_UNPROTECTED", flow.flow_id, "encryption and mutual authentication"))
        if not flow.tenant_bound:
            findings.append(_finding("FLOW_TENANT_UNBOUND", flow.flow_id, "tenant context"))
        if flow.max_payload_bytes <= 0 or flow.max_payload_bytes > 1_048_576:
            findings.append(_finding("FLOW_PAYLOAD_UNBOUNDED", flow.flow_id, str(flow.max_payload_bytes)))

    controls_present = {control for component in manifest.components for control in component.controls}
    for control in sorted(GLOBAL_CONTROLS - controls_present, key=str):
        findings.append(_finding("GLOBAL_CONTROL_MISSING", str(control), "control inventory"))
    for kind, required_controls in KIND_REQUIRED_CONTROLS.items():
        placed_controls = {
            control
            for component in manifest.components
            if component.kind == kind
            for control in component.controls
        }
        for control in sorted(required_controls - placed_controls, key=str):
            findings.append(
                _finding(
                    "CONTROL_PLACEMENT_INVALID",
                    str(kind),
                    str(control),
                )
            )

    graph = _graph(manifest)
    paths: list[list[str]] = []
    secured_paths = 0
    independent_enforcers: list[int] = []
    for entrypoint in manifest.entrypoints:
        for resource in manifest.protected_resources:
            if entrypoint not in graph or resource not in graph:
                continue
            for path in nx.all_simple_paths(graph, entrypoint, resource, cutoff=12):
                paths.append(path)
                if any(node not in components for node in path):
                    continue
                path_components = [components[node] for node in path]
                path_controls = {control for component in path_components for control in component.controls}
                missing = PATH_CONTROLS - path_controls
                servers = [component for component in path_components if component.kind == ComponentKind.MCP_SERVER]
                server_enforces_tool = any(
                    Control.TOOL_AUTHORIZATION in component.controls
                    and Control.TENANT_ENFORCEMENT in component.controls
                    and Control.AUDIT in component.controls
                    for component in servers
                )
                sandboxed = any(
                    component.kind == ComponentKind.SANDBOX and Control.ISOLATION in component.controls
                    for component in path_components
                )
                if missing:
                    findings.append(_finding("PATH_CONTROL_MISSING", "->".join(path), ",".join(sorted(map(str, missing))), severity="blocker"))
                if not server_enforces_tool:
                    findings.append(_finding("TOOL_BOUNDARY_AUTHORIZATION_MISSING", "->".join(path), "gateway authorization cannot replace resource authorization", severity="blocker"))
                if not sandboxed:
                    findings.append(_finding("SANDBOX_BYPASSED", "->".join(path), "execution path", severity="blocker"))
                if not missing and server_enforces_tool and sandboxed:
                    secured_paths += 1
                enforcers = {
                    component.component_id
                    for component in path_components
                    if set(component.controls)
                    & {Control.TRANSPORT_AUTHORIZATION, Control.TOOL_AUTHORIZATION, Control.TENANT_ENFORCEMENT}
                }
                independent_enforcers.append(len(enforcers))

    if not paths:
        findings.append(_finding("NO_PROTECTED_PATH", "manifest", "entrypoint to protected resource", severity="blocker"))
    minimum_enforcers = min(independent_enforcers, default=0)
    if paths and minimum_enforcers < 2:
        findings.append(_finding("NO_DEFENSE_IN_DEPTH", "manifest", str(minimum_enforcers)))

    unique_findings = tuple(
        {
            (finding.code, finding.severity, finding.component_id, finding.evidence, finding.owner): finding
            for finding in findings
        }.values()
    )
    status = ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW if not unique_findings else ReviewStatus.NEEDS_REMEDIATION
    unsigned = {
        "architecture_id": manifest.architecture_id,
        "manifest_digest": manifest.manifest_digest,
        "reviewed_at": now,
        "status": status,
        "findings": unique_findings,
        "path_count": len(paths),
        "secured_path_count": secured_paths,
        "minimum_independent_enforcers": minimum_enforcers,
        "evidence_coverage_rate": evidence_filled / evidence_slots if evidence_slots else 0.0,
        "production_authorized": False,
    }
    return ArchitectureReview(**unsigned, review_digest=digest(unsigned))


@dataclass(frozen=True)
class RuntimeState:
    available_components: frozenset[str]
    compromised_components: frozenset[str]
    policy_version: str
    control_revision: int
    registry_artifact_digest: str
    registry_provenance_verified: bool
    local_audit_buffer_available: bool


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    user_id: str
    workload_id: str
    tenant_id: str
    resource_tenant_id: str
    token_audience: str
    required_audience: str
    granted_scopes: frozenset[str]
    required_scope: str
    declared_capabilities: frozenset[str]
    required_capability: str
    tool_name: str
    risk_tier: RiskTier
    artifact_digest: str
    protocol_version: str
    route: tuple[str, ...]
    trace_id: str
    model_recommendation: str = ""


@dataclass(frozen=True)
class RequestDecision:
    request_id: str
    allowed: bool
    reason_codes: tuple[str, ...]
    manifest_digest: str
    policy_version: str
    control_revision: int
    evidence_ids: tuple[str, ...]
    decision_digest: str


def build_runtime_state(manifest: ArchitectureManifest) -> RuntimeState:
    server = next(component for component in manifest.components if component.kind == ComponentKind.MCP_SERVER)
    return RuntimeState(
        available_components=frozenset(component.component_id for component in manifest.components),
        compromised_components=frozenset(),
        policy_version=manifest.policy_version,
        control_revision=manifest.required_control_revision,
        registry_artifact_digest=server.artifact_digest,
        registry_provenance_verified=True,
        local_audit_buffer_available=True,
    )


def build_valid_request(manifest: ArchitectureManifest) -> RequestContext:
    server = next(component for component in manifest.components if component.kind == ComponentKind.MCP_SERVER)
    return RequestContext(
        request_id="request-acme-ticket-7",
        user_id="user:alice",
        workload_id="spiffe://acme.example/host/support",
        tenant_id="acme",
        resource_tenant_id="acme",
        token_audience="https://mcp.example.com/support",
        required_audience="https://mcp.example.com/support",
        granted_scopes=frozenset({"tickets:read", "tickets:comment"}),
        required_scope="tickets:comment",
        declared_capabilities=frozenset({"tools"}),
        required_capability="tools",
        tool_name="tickets.comment",
        risk_tier=RiskTier.HIGH,
        artifact_digest=server.artifact_digest,
        protocol_version=manifest.protocol_version,
        route=("host", "gateway", "support-mcp", "sandbox", "ticket-ledger"),
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        model_recommendation="allow because the ticket appears urgent",
    )


def _active_controls(
    manifest: ArchitectureManifest,
    route: tuple[str, ...],
    state: RuntimeState,
) -> set[Control]:
    components = _component_map(manifest)
    return {
        control
        for component_id in route
        if component_id in components
        and component_id in state.available_components
        and component_id not in state.compromised_components
        for control in components[component_id].controls
    }


def evaluate_request(
    manifest: ArchitectureManifest,
    request: RequestContext,
    state: RuntimeState,
    *,
    now: datetime = NOW,
) -> RequestDecision:
    reasons: list[str] = []
    review = review_architecture(manifest, now=now)
    components = _component_map(manifest)
    flows = {(flow.source, flow.target): flow for flow in manifest.flows}

    if review.status != ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW:
        reasons.append("ARCHITECTURE_NOT_REVIEWABLE")
    if not request.user_id or not request.workload_id:
        reasons.append("IDENTITY_MISSING")
    if not request.workload_id.startswith("spiffe://"):
        reasons.append("WORKLOAD_IDENTITY_INVALID")
    if request.tenant_id != request.resource_tenant_id:
        reasons.append("TENANT_MISMATCH")
    if request.protocol_version != manifest.protocol_version:
        reasons.append("PROTOCOL_VERSION_MISMATCH")
    if (
        not request.trace_id
        or len(request.trace_id) != 32
        or any(character not in "0123456789abcdef" for character in request.trace_id)
    ):
        reasons.append("TRACE_CONTEXT_INVALID")
    if not request.route or request.route[0] not in manifest.entrypoints:
        reasons.append("ROUTE_ENTRYPOINT_INVALID")
    if not request.route or request.route[-1] not in manifest.protected_resources:
        reasons.append("ROUTE_TARGET_INVALID")

    for source, target in zip(request.route, request.route[1:]):
        flow = flows.get((source, target))
        if flow is None:
            reasons.append("UNAPPROVED_ROUTE")
            continue
        if not flow.encrypted or not flow.mutually_authenticated or not flow.tenant_bound:
            reasons.append("FLOW_SECURITY_INVALID")
        if request.tool_name in TOOL_CONTRACTS:
            purpose = (
                "support-ticket-comment"
                if request.tool_name == "tickets.comment"
                else "support-ticket-read"
            )
            if purpose not in flow.purposes:
                reasons.append("PURPOSE_NOT_ALLOWED")

    if set(request.route) - set(state.available_components):
        reasons.append("ROUTE_COMPONENT_UNAVAILABLE")
    controls = _active_controls(manifest, request.route, state)
    if not PATH_CONTROLS.issubset(controls):
        reasons.append("PATH_CONTROL_UNAVAILABLE")

    kind_to_components: dict[ComponentKind, list[Component]] = {}
    for component in manifest.components:
        kind_to_components.setdefault(component.kind, []).append(component)
    for kind in RUNTIME_PLANE_KINDS:
        candidates = kind_to_components.get(kind, [])
        if not any(
            component.component_id in state.available_components
            and component.component_id not in state.compromised_components
            for component in candidates
        ):
            reasons.append(f"{str(kind).upper()}_PLANE_UNAVAILABLE")

    server = next(
        (
            components[item]
            for item in request.route
            if item in components and components[item].kind == ComponentKind.MCP_SERVER
        ),
        None,
    )
    if server is None:
        reasons.append("MCP_SERVER_NOT_ON_ROUTE")
    else:
        if (
            request.required_audience != server.resource_uri
            or request.token_audience != server.resource_uri
        ):
            reasons.append("AUDIENCE_MISMATCH")
        if request.tenant_id not in server.tenant_scope:
            reasons.append("TENANT_OUTSIDE_SERVER_SCOPE")
        if request.artifact_digest != server.artifact_digest:
            reasons.append("WORKLOAD_ARTIFACT_MISMATCH")
        if state.registry_artifact_digest != server.artifact_digest:
            reasons.append("REGISTRY_ARTIFACT_MISMATCH")
    for component_id in request.route:
        component = components.get(component_id)
        if component is not None and request.tenant_id not in component.tenant_scope:
            reasons.append("TENANT_OUTSIDE_COMPONENT_SCOPE")
    entrypoint = components.get(request.route[0]) if request.route else None
    if entrypoint is not None and not request.workload_id.startswith(
        entrypoint.trust_domain + "/"
    ):
        reasons.append("WORKLOAD_TRUST_DOMAIN_MISMATCH")

    contract = TOOL_CONTRACTS.get(request.tool_name)
    if contract is None:
        reasons.append("TOOL_NOT_IN_CONTRACT")
    else:
        expected_scope, expected_capability, expected_risk = contract
        if (
            request.required_scope != expected_scope
            or request.required_capability != expected_capability
            or request.risk_tier != expected_risk
        ):
            reasons.append("TOOL_CONTRACT_MISMATCH")
        if expected_scope not in request.granted_scopes:
            reasons.append("SCOPE_MISSING")
        if expected_capability not in request.declared_capabilities:
            reasons.append("CAPABILITY_NOT_DECLARED")
    if not state.registry_provenance_verified:
        reasons.append("REGISTRY_PROVENANCE_UNVERIFIED")
    if state.policy_version != manifest.policy_version:
        reasons.append("RUNTIME_POLICY_STALE")
    if state.control_revision < manifest.required_control_revision:
        reasons.append("REVOCATION_REVISION_STALE")

    telemetry = kind_to_components.get(ComponentKind.TELEMETRY, [])
    telemetry_available = any(
        component.component_id in state.available_components
        and component.component_id not in state.compromised_components
        for component in telemetry
    )
    if request.risk_tier == RiskTier.HIGH and not telemetry_available:
        reasons.append("HIGH_RISK_TELEMETRY_UNAVAILABLE")
    if request.risk_tier == RiskTier.LOW and not telemetry_available and not state.local_audit_buffer_available:
        reasons.append("AUDIT_EVIDENCE_UNAVAILABLE")

    reason_codes = tuple(sorted(set(reasons)))
    evidence_ids = tuple(
        sorted(
            {
                evidence_id
                for component_id in request.route
                if component_id in components
                for evidence_id in components[component_id].evidence_ids
            }
        )
    )
    unsigned = {
        "request_id": request.request_id,
        "allowed": not reason_codes,
        "reason_codes": reason_codes,
        "manifest_digest": manifest.manifest_digest,
        "policy_version": state.policy_version,
        "control_revision": state.control_revision,
        "evidence_ids": evidence_ids,
    }
    return RequestDecision(**unsigned, decision_digest=digest(unsigned))


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    request: RequestContext
    state: RuntimeState
    expected_allowed: bool
    slice_name: str


@dataclass(frozen=True)
class EvaluationResult:
    case_id: str
    expected_allowed: bool
    actual_allowed: bool
    correct: bool
    slice_name: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ArchitectureMetrics:
    total_cases: int
    correct_cases: int
    adversarial_cases: int
    adversarial_blocked: int
    valid_cases: int
    valid_allowed: int
    attack_block_rate: float
    valid_work_success_rate: float
    decision_accuracy: float
    path_coverage_rate: float
    evidence_coverage_rate: float
    minimum_independent_enforcers: int


def build_evaluation_cases(manifest: ArchitectureManifest) -> tuple[EvaluationCase, ...]:
    request = build_valid_request(manifest)
    state = build_runtime_state(manifest)
    component_ids = state.available_components
    return (
        EvaluationCase("valid-comment", request, state, True, "valid"),
        EvaluationCase(
            "valid-read",
            replace(request, request_id="request-read", tool_name="tickets.read", required_scope="tickets:read", risk_tier=RiskTier.LOW),
            state,
            True,
            "valid",
        ),
        EvaluationCase("cross-tenant", replace(request, resource_tenant_id="beta"), state, False, "tenant"),
        EvaluationCase("bad-audience", replace(request, token_audience="https://evil.example"), state, False, "identity"),
        EvaluationCase("missing-scope", replace(request, granted_scopes=frozenset({"tickets:read"})), state, False, "authorization"),
        EvaluationCase("capability-downgrade", replace(request, declared_capabilities=frozenset()), state, False, "protocol"),
        EvaluationCase("unknown-tool", replace(request, tool_name="admin.export_all"), state, False, "contract"),
        EvaluationCase("wrong-artifact", replace(request, artifact_digest=digest(b"unreviewed")), state, False, "supply-chain"),
        EvaluationCase("stale-policy", request, replace(state, policy_version="old-policy"), False, "policy"),
        EvaluationCase("stale-revocation", request, replace(state, control_revision=16), False, "revocation"),
        EvaluationCase("identity-outage", request, replace(state, available_components=component_ids - {"identity"}), False, "resilience"),
        EvaluationCase("policy-outage", request, replace(state, available_components=component_ids - {"policy"}), False, "resilience"),
        EvaluationCase("registry-compromise", request, replace(state, compromised_components=frozenset({"registry"})), False, "supply-chain"),
        EvaluationCase("server-compromise", request, replace(state, compromised_components=frozenset({"support-mcp"})), False, "defense-in-depth"),
        EvaluationCase("gateway-compromise-contained", request, replace(state, compromised_components=frozenset({"gateway"})), True, "defense-in-depth"),
        EvaluationCase("telemetry-outage-high-risk", request, replace(state, available_components=component_ids - {"telemetry"}), False, "observability"),
        EvaluationCase(
            "telemetry-outage-low-risk-buffered",
            replace(request, request_id="request-read-buffered", tool_name="tickets.read", required_scope="tickets:read", risk_tier=RiskTier.LOW),
            replace(state, available_components=component_ids - {"telemetry"}),
            True,
            "observability",
        ),
        EvaluationCase("unapproved-bypass", replace(request, route=("host", "support-mcp", "sandbox", "ticket-ledger")), state, False, "bypass"),
    )


def evaluate_suite(
    manifest: ArchitectureManifest,
    cases: Iterable[EvaluationCase],
) -> tuple[tuple[EvaluationResult, ...], ArchitectureMetrics]:
    results: list[EvaluationResult] = []
    for case in cases:
        decision = evaluate_request(manifest, case.request, case.state)
        results.append(
            EvaluationResult(
                case.case_id,
                case.expected_allowed,
                decision.allowed,
                decision.allowed == case.expected_allowed,
                case.slice_name,
                decision.reason_codes,
            )
        )
    result_tuple = tuple(results)
    adversarial = tuple(result for result in result_tuple if not result.expected_allowed)
    valid = tuple(result for result in result_tuple if result.expected_allowed)
    review = review_architecture(manifest)
    if not result_tuple or not adversarial or not valid or review.path_count == 0:
        raise ValueError("evaluation requires nonzero total, adversarial, valid, and path populations")
    metrics = ArchitectureMetrics(
        total_cases=len(result_tuple),
        correct_cases=sum(result.correct for result in result_tuple),
        adversarial_cases=len(adversarial),
        adversarial_blocked=sum(not result.actual_allowed for result in adversarial),
        valid_cases=len(valid),
        valid_allowed=sum(result.actual_allowed for result in valid),
        attack_block_rate=sum(not result.actual_allowed for result in adversarial) / len(adversarial),
        valid_work_success_rate=sum(result.actual_allowed for result in valid) / len(valid),
        decision_accuracy=sum(result.correct for result in result_tuple) / len(result_tuple),
        path_coverage_rate=review.secured_path_count / review.path_count,
        evidence_coverage_rate=review.evidence_coverage_rate,
        minimum_independent_enforcers=review.minimum_independent_enforcers,
    )
    return result_tuple, metrics


def build_gateway_only_manifest() -> ArchitectureManifest:
    manifest = build_reference_manifest()
    server = next(component for component in manifest.components if component.kind == ComponentKind.MCP_SERVER)
    weakened = replace(server, controls=(Control.INPUT_VALIDATION, Control.AUDIT, Control.REVOCATION))
    components = tuple(weakened if component.component_id == server.component_id else component for component in manifest.components)
    return sign_manifest(replace(manifest, architecture_id="central-gateway-only", components=components, manifest_digest="", signature=""))


@dataclass(frozen=True)
class ArchitectureComparison:
    architecture_id: str
    review_status: ReviewStatus
    finding_count: int
    attack_block_rate: float
    valid_work_success_rate: float
    path_coverage_rate: float
    independent_enforcers: int


def compare_architectures() -> tuple[ArchitectureComparison, ...]:
    comparisons: list[ArchitectureComparison] = []
    for manifest in (build_gateway_only_manifest(), build_reference_manifest()):
        review = review_architecture(manifest)
        _, metrics = evaluate_suite(manifest, build_evaluation_cases(manifest))
        comparisons.append(
            ArchitectureComparison(
                manifest.architecture_id,
                review.status,
                len(review.findings),
                metrics.attack_block_rate,
                metrics.valid_work_success_rate,
                metrics.path_coverage_rate,
                metrics.minimum_independent_enforcers,
            )
        )
    return tuple(comparisons)


@dataclass(frozen=True)
class ModelArchitectureRecommendation:
    recommendation_id: str
    proposal_digest: str
    evidence_ids: tuple[str, ...]
    accepted_as_fact: bool = False
    grants_authority: bool = False


def record_model_recommendation(text: str, evidence_ids: Iterable[str]) -> ModelArchitectureRecommendation:
    admitted = tuple(sorted(set(evidence_ids)))
    if not admitted:
        raise ValueError("model recommendation must cite admitted evidence")
    return ModelArchitectureRecommendation(
        "recommendation-" + digest((text, admitted)).split(":", 1)[1][:12],
        digest(text),
        admitted,
        False,
        False,
    )


@dataclass(frozen=True)
class ArchitectureApproval:
    receipt_id: str
    architecture_id: str
    manifest_digest: str
    review_digest: str
    approver_id: str
    approver_role: str
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result


def approve_architecture(
    manifest: ArchitectureManifest,
    review: ArchitectureReview,
    *,
    approver_id: str,
    approver_role: str,
    now: datetime,
) -> ArchitectureApproval:
    if approver_role not in APPROVER_ROLES:
        raise PermissionError("authorized architecture reviewer role required")
    if (
        not verify_manifest(manifest)
        or not verify_review(review)
        or review.status != ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW
        or review.architecture_id != manifest.architecture_id
        or review.manifest_digest != manifest.manifest_digest
        or review.reviewed_at > now + timedelta(seconds=5)
        or now - review.reviewed_at > MAX_REVIEW_AGE
    ):
        raise ValueError("complete review for the exact manifest required")
    unsigned = {
        "receipt_id": "architecture-approval-" + digest((manifest.manifest_digest, review.review_digest, approver_id, now)).split(":", 1)[1][:12],
        "architecture_id": manifest.architecture_id,
        "manifest_digest": manifest.manifest_digest,
        "review_digest": review.review_digest,
        "approver_id": approver_id,
        "approver_role": approver_role,
        "policy_version": manifest.policy_version,
        "issued_at": now,
        "expires_at": now + timedelta(minutes=30),
    }
    signature = hmac.new(APPROVAL_KEY, canonical_json(unsigned), sha256).hexdigest()
    return ArchitectureApproval(**unsigned, signature=signature)


def verify_approval(receipt: ArchitectureApproval) -> bool:
    expected = hmac.new(APPROVAL_KEY, canonical_json(receipt.unsigned()), sha256).hexdigest()
    return (
        receipt.approver_role in APPROVER_ROLES
        and receipt.expires_at > receipt.issued_at
        and hmac.compare_digest(expected, receipt.signature)
    )


@dataclass(frozen=True)
class ArchitectureRecord:
    architecture_id: str
    manifest_digest: str
    review_digest: str
    status: CatalogStatus
    version: int
    approved_at: datetime | None
    production_authorized: bool


class ArchitectureVersionConflict(RuntimeError):
    pass


class ArchitectureCatalog:
    def __init__(self) -> None:
        self.records: dict[str, ArchitectureRecord] = {}
        self.consumed_receipts: set[str] = set()
        self._lock = Lock()

    def register(self, manifest: ArchitectureManifest, review: ArchitectureReview) -> ArchitectureRecord:
        with self._lock:
            return self._register_locked(manifest, review)

    def _register_locked(
        self,
        manifest: ArchitectureManifest,
        review: ArchitectureReview,
    ) -> ArchitectureRecord:
        if manifest.architecture_id in self.records:
            raise ArchitectureVersionConflict("architecture already registered")
        if review.manifest_digest != manifest.manifest_digest:
            raise ValueError("review does not bind this manifest")
        record = ArchitectureRecord(
            manifest.architecture_id,
            manifest.manifest_digest,
            review.review_digest,
            CatalogStatus.CANDIDATE,
            1,
            None,
            False,
        )
        self.records[record.architecture_id] = record
        return record

    def promote(
        self,
        record: ArchitectureRecord,
        manifest: ArchitectureManifest,
        review: ArchitectureReview,
        receipt: ArchitectureApproval,
        *,
        expected_version: int,
        now: datetime,
    ) -> ArchitectureRecord:
        with self._lock:
            return self._promote_locked(
                record,
                manifest,
                review,
                receipt,
                expected_version=expected_version,
                now=now,
            )

    def _promote_locked(
        self,
        record: ArchitectureRecord,
        manifest: ArchitectureManifest,
        review: ArchitectureReview,
        receipt: ArchitectureApproval,
        *,
        expected_version: int,
        now: datetime,
    ) -> ArchitectureRecord:
        current = self.records[record.architecture_id]
        if current.version != expected_version or record.version != expected_version:
            raise ArchitectureVersionConflict("stale architecture catalog version")
        if receipt.receipt_id in self.consumed_receipts:
            raise ValueError("architecture approval already consumed")
        if (
            not verify_manifest(manifest)
            or not verify_review(review)
            or not verify_approval(receipt)
            or now > receipt.expires_at
            or receipt.architecture_id != record.architecture_id
            or receipt.manifest_digest != manifest.manifest_digest
            or receipt.review_digest != review.review_digest
            or receipt.policy_version != manifest.policy_version
            or record.manifest_digest != manifest.manifest_digest
            or record.review_digest != review.review_digest
            or review.status != ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW
        ):
            raise PermissionError("approval does not authorize this architecture record")
        promoted = replace(
            record,
            status=CatalogStatus.APPROVED_REFERENCE,
            version=record.version + 1,
            approved_at=now,
            production_authorized=False,
        )
        self.records[record.architecture_id] = promoted
        self.consumed_receipts.add(receipt.receipt_id)
        return promoted


def trace_architecture_review(
    manifest: ArchitectureManifest,
    review: ArchitectureReview,
) -> tuple[Any, ...]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "course-23-review"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("enterprise-mcp-architecture")
    with tracer.start_as_current_span("architecture.review") as span:
        span.set_attribute("architecture.id", manifest.architecture_id)
        span.set_attribute("architecture.version", manifest.version)
        span.set_attribute("architecture.manifest_digest", manifest.manifest_digest)
        span.set_attribute("architecture.review_digest", review.review_digest)
        span.set_attribute("architecture.finding_count", len(review.findings))
        span.set_attribute("architecture.path_count", review.path_count)
        span.set_attribute("architecture.secured_path_count", review.secured_path_count)
        span.set_attribute("architecture.production_authorized", False)
    provider.shutdown()
    return tuple(exporter.get_finished_spans())


def run_demo() -> dict[str, Any]:
    manifest = build_reference_manifest()
    review = review_architecture(manifest)
    assert review.status == ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW
    recommendation = record_model_recommendation(
        "prefer hybrid enforcement at gateway and MCP tool boundary",
        (manifest.manifest_digest, review.review_digest),
    )
    results, metrics = evaluate_suite(manifest, build_evaluation_cases(manifest))
    assert all(result.correct for result in results)
    assert metrics.attack_block_rate == 1.0
    assert metrics.valid_work_success_rate == 1.0
    approval = approve_architecture(
        manifest,
        review,
        approver_id="architect:maya",
        approver_role="security_architect",
        now=NOW + timedelta(seconds=1),
    )
    catalog = ArchitectureCatalog()
    record = catalog.register(manifest, review)
    promoted = catalog.promote(
        record,
        manifest,
        review,
        approval,
        expected_version=1,
        now=NOW + timedelta(seconds=2),
    )
    spans = trace_architecture_review(manifest, review)
    assert promoted.status == CatalogStatus.APPROVED_REFERENCE
    assert promoted.production_authorized is False
    assert recommendation.grants_authority is False
    assert len(spans) == 1
    return {
        "manifest": manifest,
        "review": review,
        "recommendation": recommendation,
        "results": results,
        "metrics": metrics,
        "approval": approval,
        "record": promoted,
        "comparisons": compare_architectures(),
        "spans": spans,
    }


def main() -> None:
    run_demo()
    print(
        "PASS: enterprise MCP architecture proved path controls, failure handling, "
        "tenant isolation, and evidence-backed human review"
    )


if __name__ == "__main__":
    main()
