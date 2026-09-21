"""Course 02: executable threat-model-as-code for an MCP support platform.

This lab evaluates the quality and traceability of a threat model. It never
claims that a documented control is effective merely because its fields are
complete. Control-evidence status is measured separately and starts unverified.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime
import re
from typing import Iterable


STRIDE = frozenset(
    {
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information disclosure",
        "Denial of service",
        "Elevation of privilege",
    }
)
REQUIRED_EVIDENCE = frozenset({"test", "telemetry", "runbook"})
VERIFIED_STATUS = {"test": "passed", "telemetry": "verified", "runbook": "exercised"}
DEFAULT_STATUS = {"test": "not_run", "telemetry": "not_verified", "runbook": "not_exercised"}
TRUSTED_PRODUCERS = {
    "test": "ci/course-security",
    "telemetry": "siem/validation-service",
    "runbook": "exercise/controller",
}
ARTIFACT_PREFIX = {"test": "ci://", "telemetry": "siem://", "runbook": "exercise://"}
ALLOWED_STATUS = {
    "test": frozenset({"not_run", "passed", "failed"}),
    "telemetry": frozenset({"not_verified", "verified", "failed"}),
    "runbook": frozenset({"not_exercised", "exercised", "failed"}),
}


@dataclass(frozen=True)
class Component:
    identifier: str
    name: str
    kind: str
    trust_zone: str
    operator: str
    authority: tuple[str, ...]


@dataclass(frozen=True)
class DataFlow:
    identifier: str
    source: str
    target: str
    data: tuple[str, ...]
    protocol: str
    trust_boundary: str
    identity_source: str
    authorization_point: str
    audit_event: str


@dataclass(frozen=True)
class EvidenceRecord:
    identifier: str
    threat_id: str
    kind: str
    requirement: str
    locator: str
    status: str
    owner: str
    receipt_id: str | None = None
    artifact_digest: str | None = None
    observed_at: str | None = None


@dataclass(frozen=True)
class EvidenceReceipt:
    identifier: str
    evidence_id: str
    model_version: str
    producer: str
    status: str
    artifact_locator: str
    artifact_digest: str
    observed_at: str


@dataclass(frozen=True)
class Threat:
    identifier: str
    title: str
    stride: str
    flow_id: str
    asset: str
    attacker_goal: str
    preconditions: tuple[str, ...]
    abuse_path: tuple[str, ...]
    invariant: str
    control: str
    risk_owner: str
    evidence_ids: tuple[str, ...]
    inherent_likelihood: int
    impact: int
    residual_likelihood: int
    treatment: str
    review_trigger: str


@dataclass(frozen=True)
class ThreatModel:
    identifier: str
    version: str
    scope: str
    assumptions: tuple[str, ...]
    components: tuple[Component, ...]
    flows: tuple[DataFlow, ...]
    threats: tuple[Threat, ...]
    evidence: tuple[EvidenceRecord, ...]


def _component(identifier: str, name: str, kind: str, zone: str, operator: str, *authority: str) -> Component:
    return Component(identifier, name, kind, zone, operator, tuple(authority))


COMPONENTS = (
    _component("C-USER", "Support analyst", "external entity", "user-device", "customer support", "request ticket read"),
    _component("C-HOST", "AI support host and MCP client", "process", "host-runtime", "application team", "select reviewed server", "enforce host policy"),
    _component("C-SERVER", "Tenant support MCP server", "process", "server-runtime", "integration team", "validate MCP request", "request narrow ticket read"),
    _component("C-POLICY", "Policy decision service", "process", "security-control", "security platform", "decide user/action/resource policy"),
    _component("C-TICKET", "Ticket system API", "external service", "downstream-api", "ticket platform", "authorize and return tenant ticket"),
    _component("C-REGISTRY", "Reviewed server registry", "data store", "supply-chain", "platform governance", "publish reviewed identity and digest"),
    _component("C-IDP", "Identity provider", "external service", "identity-plane", "identity team", "authenticate principals", "issue audience-bound tokens"),
    _component("C-SIEM", "Security telemetry pipeline", "data store", "observability", "security operations", "retain redacted audit evidence"),
)

FLOWS = (
    DataFlow("F-01", "C-USER", "C-HOST", ("request", "user session", "tenant context"), "HTTPS", "user session boundary", "authenticated host session", "host request policy", "request.received"),
    DataFlow("F-02", "C-REGISTRY", "C-HOST", ("server identity", "artifact digest", "capability review"), "signed registry API", "software supply-chain boundary", "registry workload identity", "host onboarding gate", "server.selected"),
    DataFlow("F-03", "C-HOST", "C-SERVER", ("MCP metadata", "tool arguments", "request identity"), "MCP over Streamable HTTP", "integration and network boundary", "host workload plus user delegation", "host gate and server policy", "mcp.request"),
    DataFlow("F-04", "C-SERVER", "C-HOST", ("tool result", "resource content", "prompt text"), "MCP over Streamable HTTP", "untrusted-content boundary", "server workload identity", "host output validation and next-action policy", "mcp.result"),
    DataFlow("F-05", "C-SERVER", "C-POLICY", ("subject", "action", "resource", "tenant", "purpose"), "mTLS policy API", "policy enforcement boundary", "server workload identity", "policy decision service", "policy.decision"),
    DataFlow("F-06", "C-SERVER", "C-TICKET", ("delegated identity", "tenant", "ticket identifier"), "HTTPS API", "downstream resource boundary", "audience-bound delegated credential", "ticket API", "ticket.read"),
    DataFlow("F-07", "C-IDP", "C-SERVER", ("issuer metadata", "keys", "token claims"), "OIDC/OAuth", "identity trust boundary", "verified issuer", "server token verifier", "identity.verified"),
    DataFlow("F-08", "C-SERVER", "C-SIEM", ("trace ID", "server digest", "policy decision", "result class"), "authenticated telemetry", "observability boundary", "server workload identity", "telemetry admission policy", "audit.ingested"),
)


def _evidence(threat_id: str, slug: str) -> tuple[EvidenceRecord, ...]:
    """Create explicit planned evidence without fabricating successful proof."""
    return (
        EvidenceRecord(f"EV-{slug}-TEST", threat_id, "test", "adversarial test demonstrates the invariant", f"planned-test:{slug}", "not_run", "quality engineering"),
        EvidenceRecord(f"EV-{slug}-SIGNAL", threat_id, "telemetry", "signal joins trace, identity, resource, and decision", f"planned-signal:{slug}", "not_verified", "security operations"),
        EvidenceRecord(f"EV-{slug}-RUNBOOK", threat_id, "runbook", "containment and recovery action is exercised", f"planned-runbook:{slug}", "not_exercised", "incident response"),
    )


EVIDENCE = tuple(
    record
    for threat_id, slug in (
        ("TM-01", "rogue-server"),
        ("TM-02", "capability-drift"),
        ("TM-03", "audit-gap"),
        ("TM-04", "cross-tenant-read"),
        ("TM-05", "tool-call-exhaustion"),
        ("TM-06", "untrusted-output-action"),
    )
    for record in _evidence(threat_id, slug)
)


def _evidence_ids(slug: str) -> tuple[str, ...]:
    return (f"EV-{slug}-TEST", f"EV-{slug}-SIGNAL", f"EV-{slug}-RUNBOOK")


THREATS = (
    Threat(
        "TM-01", "Rogue server impersonates a reviewed integration", "Spoofing", "F-02", "server identity and host authority", "connect attacker-controlled code with trusted branding", ("registry entry or host configuration can be altered",), ("publish familiar server name", "substitute artifact or endpoint", "host connects without immutable identity check"), "The host connects only to the reviewed server identity and artifact digest.", "Verify registry workload identity, endpoint, publisher, and immutable digest before connection.", "platform integration owner", _evidence_ids("rogue-server"), 4, 5, 2, "mitigate", "publisher, endpoint, digest, signature, or registry policy changes"
    ),
    Threat(
        "TM-02", "Capability contract expands after review", "Tampering", "F-03", "approved capability set", "add broad destinations or arguments", ("server can change tool metadata", "host trusts a stale capability cache"), ("replace narrow ticket schema", "advertise arbitrary URL or command", "model proposes the new operation"), "A capability change cannot widen authority without a new host review.", "Bind reviewed schemas to server identity/version and deny capability drift by default.", "host security owner", _evidence_ids("capability-drift"), 4, 4, 2, "mitigate", "tool, resource, prompt, extension, or schema changes"
    ),
    Threat(
        "TM-03", "Uncorrelated events prevent accountability", "Repudiation", "F-08", "audit and forensic evidence", "make an action impossible to attribute or reconstruct", ("trace identifiers are missing or inconsistent",), ("invoke ticket read", "drop or alter decision context", "dispute which principal or server acted"), "Every decision and effect is correlated to authenticated principals, server identity, resource, and result class.", "Emit redacted structured events through an authenticated telemetry path with retention and integrity controls.", "security operations owner", _evidence_ids("audit-gap"), 3, 4, 2, "mitigate_and_monitor", "event schema, retention, clock, identity, or telemetry route changes"
    ),
    Threat(
        "TM-04", "Server reads another tenant's ticket", "Information disclosure", "F-06", "tenant ticket data", "obtain a resource outside the user's tenant", ("tenant is accepted from a model-controlled argument", "downstream credential is broad"), ("supply other tenant identifier", "server forwards broad credential", "ticket API returns unauthorized record"), "Authenticated subject, tenant, audience, action, and resource ownership agree at the downstream boundary.", "Derive tenant from authenticated state, use narrow delegation, and enforce resource ownership at the ticket API.", "ticket platform owner", _evidence_ids("cross-tenant-read"), 4, 5, 2, "mitigate", "identity mapping, token audience/scope, tenancy, or ticket API policy changes"
    ),
    Threat(
        "TM-05", "Unbounded tool calls exhaust the service", "Denial of service", "F-03", "service availability and budget", "consume concurrency, time, or downstream quota", ("host permits unbounded parallel calls or retries",), ("generate repeated tool proposals", "amplify with retries", "exhaust server or ticket API capacity"), "Calls, concurrency, attempts, deadlines, and result sizes are bounded per principal and tenant.", "Enforce quotas, deadlines, bounded concurrency, cancellation, and retry classification outside the model.", "service reliability owner", _evidence_ids("tool-call-exhaustion"), 4, 4, 2, "mitigate_and_monitor", "traffic shape, model orchestration, retry, quota, or dependency capacity changes"
    ),
    Threat(
        "TM-06", "Untrusted tool output triggers a privileged action", "Elevation of privilege", "F-04", "host credentials and next-action authority", "turn data into instructions that cause a broader action", ("host places tool output into model context", "next action is not independently authorized"), ("return instruction disguised as ticket content", "model proposes secret upload or destructive tool", "host executes without a new policy decision"), "Tool, resource, and prompt content cannot grant authority or change policy.", "Label content as untrusted, validate output, and authorize every subsequent action against authenticated state.", "host security owner", _evidence_ids("untrusted-output-action"), 5, 5, 2, "mitigate", "new content source, model, tool chain, output renderer, or privileged action is introduced"
    ),
)


def build_model() -> ThreatModel:
    return ThreatModel(
        identifier="MCP-SUPPORT-TM",
        version="2026-09-20.1",
        scope="Tenant support host, one MCP server, and its identity, policy, supply-chain, ticket, and telemetry dependencies.",
        assumptions=(
            "The user identity and tenant originate in an authenticated host session, not model text.",
            "Server compromise is in scope; the ticket API remains an independent enforcement point.",
            "Model output, tool metadata, prompt text, and resource content are untrusted data.",
            "Evidence records begin unverified until a real test, signal validation, or exercise produces proof.",
        ),
        components=COMPONENTS,
        flows=FLOWS,
        threats=THREATS,
        evidence=EVIDENCE,
    )


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def lint_model(model: ThreatModel) -> tuple[str, ...]:
    """Return structural and semantic findings without claiming control efficacy."""
    findings: list[str] = []
    component_ids = {item.identifier for item in model.components}
    flow_ids = {item.identifier for item in model.flows}
    evidence_by_id = {item.identifier: item for item in model.evidence}

    for label, identifiers in (
        ("component", [item.identifier for item in model.components]),
        ("flow", [item.identifier for item in model.flows]),
        ("threat", [item.identifier for item in model.threats]),
        ("evidence", [item.identifier for item in model.evidence]),
    ):
        for duplicate in sorted(_duplicates(identifiers)):
            findings.append(f"duplicate {label} identifier: {duplicate}")

    zones = {item.identifier: item.trust_zone for item in model.components}
    for flow in model.flows:
        if flow.source not in component_ids or flow.target not in component_ids:
            findings.append(f"{flow.identifier}: source or target does not exist")
            continue
        if zones[flow.source] != zones[flow.target] and not flow.trust_boundary.strip():
            findings.append(f"{flow.identifier}: cross-zone flow has no trust boundary")
        if not flow.identity_source.strip() or not flow.authorization_point.strip():
            findings.append(f"{flow.identifier}: identity or authorization point is missing")

    observed_stride = {threat.stride for threat in model.threats}
    for missing in sorted(STRIDE - observed_stride):
        findings.append(f"scenario has no {missing} threat prompt")

    for threat in model.threats:
        if threat.stride not in STRIDE:
            findings.append(f"{threat.identifier}: unknown STRIDE category {threat.stride}")
        if threat.flow_id not in flow_ids:
            findings.append(f"{threat.identifier}: flow {threat.flow_id} does not exist")
        if not 1 <= threat.residual_likelihood <= threat.inherent_likelihood <= 5:
            findings.append(f"{threat.identifier}: likelihood must be 1..5 and residual cannot exceed inherent")
        if not 1 <= threat.impact <= 5:
            findings.append(f"{threat.identifier}: impact must be 1..5")
        if not threat.risk_owner.strip() or not threat.review_trigger.strip():
            findings.append(f"{threat.identifier}: risk owner or review trigger is missing")
        records = [evidence_by_id.get(identifier) for identifier in threat.evidence_ids]
        missing_ids = [identifier for identifier, record in zip(threat.evidence_ids, records) if record is None]
        if missing_ids:
            findings.append(f"{threat.identifier}: missing evidence {', '.join(missing_ids)}")
            continue
        kinds = {record.kind for record in records if record}
        if kinds != REQUIRED_EVIDENCE:
            findings.append(f"{threat.identifier}: requires test, telemetry, and runbook evidence")

    for record in model.evidence:
        if record.kind not in ALLOWED_STATUS:
            findings.append(f"{record.identifier}: unknown evidence kind {record.kind}")
        elif record.status not in ALLOWED_STATUS[record.kind]:
            findings.append(f"{record.identifier}: invalid {record.kind} status {record.status}")
        elif record.status != DEFAULT_STATUS[record.kind] and not all(
            (record.receipt_id, record.artifact_digest, record.observed_at)
        ):
            findings.append(f"{record.identifier}: non-default status has no bound evidence receipt")
        if record.threat_id not in {threat.identifier for threat in model.threats}:
            findings.append(f"{record.identifier}: threat {record.threat_id} does not exist")
    return tuple(findings)


def risk_band(likelihood: int, impact: int) -> str:
    """Map an explicit ordinal 1..5 matrix to a qualitative triage band."""
    score = likelihood * impact
    if score <= 4:
        return "low"
    if score <= 9:
        return "medium"
    if score <= 15:
        return "high"
    return "critical"


def _percent(numerator: int, denominator: int) -> int:
    return round(100 * numerator / denominator) if denominator else 0


def coverage_metrics(model: ThreatModel) -> dict[str, int]:
    """Separate documented traceability from verified control evidence."""
    evidence_by_id = {item.identifier: item for item in model.evidence}
    design_complete = 0
    verified = 0
    open_high_residual = 0
    for threat in model.threats:
        records = [evidence_by_id.get(identifier) for identifier in threat.evidence_ids]
        kinds = {record.kind for record in records if record}
        complete = (
            bool(threat.invariant.strip())
            and bool(threat.control.strip())
            and bool(threat.risk_owner.strip())
            and bool(threat.review_trigger.strip())
            and kinds == REQUIRED_EVIDENCE
        )
        design_complete += int(complete)
        verified += int(
            complete
            and all(
                record
                and record.status == VERIFIED_STATUS[record.kind]
                and record.receipt_id
                and record.artifact_digest
                and record.observed_at
                for record in records
            )
        )
        open_high_residual += int(risk_band(threat.residual_likelihood, threat.impact) in {"high", "critical"})

    total = len(model.threats)
    return {
        "total_threats": total,
        "design_complete_threats": design_complete,
        "design_traceability_percent": _percent(design_complete, total),
        "verified_control_threats": verified,
        "verified_control_percent": _percent(verified, total),
        "open_high_residual_threats": open_high_residual,
    }


def record_evidence(model: ThreatModel, receipt: EvidenceReceipt) -> ThreatModel:
    """Bind a typed producer receipt to one evidence requirement.

    The offline gate validates structure and an application-configured producer
    identity. A production adapter must authenticate that producer and verify
    the artifact digest before constructing this receipt.
    """
    updated: list[EvidenceRecord] = []
    found = False
    for record in model.evidence:
        if record.identifier != receipt.evidence_id:
            updated.append(record)
            continue
        if receipt.model_version != model.version:
            raise ValueError("evidence receipt is bound to a different model version")
        if receipt.producer != TRUSTED_PRODUCERS[record.kind]:
            raise PermissionError(f"untrusted {record.kind} evidence producer")
        if receipt.status not in ALLOWED_STATUS.get(record.kind, frozenset()):
            raise ValueError(f"invalid {record.kind} status: {receipt.status}")
        if not receipt.artifact_locator.startswith(ARTIFACT_PREFIX[record.kind]):
            raise ValueError(f"{record.kind} evidence requires an {ARTIFACT_PREFIX[record.kind]} locator")
        if not re.fullmatch(r"[0-9a-f]{64}", receipt.artifact_digest):
            raise ValueError("evidence artifact digest must be 64 lowercase hex characters")
        try:
            datetime.fromisoformat(receipt.observed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("evidence observed_at must be an ISO-8601 timestamp") from error
        if not receipt.identifier.strip():
            raise ValueError("evidence receipt requires an identifier")
        updated.append(
            replace(
                record,
                status=receipt.status,
                locator=receipt.artifact_locator,
                receipt_id=receipt.identifier,
                artifact_digest=receipt.artifact_digest,
                observed_at=receipt.observed_at,
            )
        )
        found = True
    if not found:
        raise KeyError(receipt.evidence_id)
    return replace(model, evidence=tuple(updated))


def find_attack_paths(
    model: ThreatModel, source: str, target: str, max_hops: int = 5
) -> tuple[tuple[str, ...], ...]:
    """Enumerate bounded simple directed paths through modeled data flows."""
    component_ids = {item.identifier for item in model.components}
    if source not in component_ids or target not in component_ids:
        raise KeyError("source and target must be modeled components")
    adjacency: dict[str, list[str]] = {identifier: [] for identifier in component_ids}
    for flow in model.flows:
        if flow.source in adjacency:
            adjacency[flow.source].append(flow.target)
    paths: list[tuple[str, ...]] = []

    def visit(node: str, path: tuple[str, ...]) -> None:
        if len(path) - 1 > max_hops:
            return
        if node == target:
            paths.append(path)
            return
        for neighbor in sorted(adjacency.get(node, [])):
            if neighbor not in path:
                visit(neighbor, path + (neighbor,))

    visit(source, (source,))
    return tuple(paths)


def model_summary(model: ThreatModel) -> dict[str, object]:
    """Return a serializable review summary without sensitive content."""
    return {
        "model": {"id": model.identifier, "version": model.version, "scope": model.scope},
        "inventory": {
            "components": len(model.components),
            "flows": len(model.flows),
            "threats": len(model.threats),
            "evidence_records": len(model.evidence),
        },
        "coverage": coverage_metrics(model),
        "findings": lint_model(model),
        "residual_risk": {
            threat.identifier: risk_band(threat.residual_likelihood, threat.impact)
            for threat in model.threats
        },
    }


def main() -> None:
    model = build_model()
    summary = model_summary(model)
    assert not summary["findings"]
    assert summary["coverage"] == {
        "total_threats": 6,
        "design_complete_threats": 6,
        "design_traceability_percent": 100,
        "verified_control_threats": 0,
        "verified_control_percent": 0,
        "open_high_residual_threats": 3,
    }
    supply_chain_paths = find_attack_paths(model, "C-REGISTRY", "C-TICKET")
    assert ("C-REGISTRY", "C-HOST", "C-SERVER", "C-TICKET") in supply_chain_paths
    print("PASS: threat model is structurally complete without fabricating control evidence")
    print(summary)
    print("supply-chain attack paths:", supply_chain_paths)
    print("first threat:", asdict(model.threats[0]))


if __name__ == "__main__":
    main()
