"""Executable invariants for Course 23 enterprise MCP security architecture."""

from dataclasses import replace
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/23-enterprise-mcp-security-architecture/lab.py"
SPEC = importlib.util.spec_from_file_location("course_23_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def resign(manifest, **changes):
    changed = replace(manifest, **changes, manifest_digest="", signature="")
    return lab.sign_manifest(changed)


def mutate_component(manifest, component_id, **changes):
    components = tuple(
        replace(component, **changes)
        if component.component_id == component_id
        else component
        for component in manifest.components
    )
    return resign(manifest, components=components)


def mutate_flow(manifest, flow_id, **changes):
    flows = tuple(
        replace(flow, **changes) if flow.flow_id == flow_id else flow
        for flow in manifest.flows
    )
    return resign(manifest, flows=flows)


def finding_codes(review):
    return {finding.code for finding in review.findings}


def resign_approval(receipt, **changes):
    unsigned = replace(receipt, **changes, signature="")
    signature = lab.hmac.new(
        lab.APPROVAL_KEY,
        lab.canonical_json(unsigned.unsigned()),
        lab.sha256,
    ).hexdigest()
    return replace(unsigned, signature=signature)


def approved_fixture():
    manifest = lab.build_reference_manifest()
    review = lab.review_architecture(manifest)
    receipt = lab.approve_architecture(
        manifest,
        review,
        approver_id="architect:maya",
        approver_role="security_architect",
        now=lab.NOW,
    )
    catalog = lab.ArchitectureCatalog()
    record = catalog.register(manifest, review)
    return manifest, review, receipt, catalog, record


def test_demo_proves_reference_architecture_without_production_authority():
    result = lab.run_demo()
    assert result["record"].status == lab.CatalogStatus.APPROVED_REFERENCE
    assert result["record"].production_authorized is False
    assert result["recommendation"].grants_authority is False
    assert result["metrics"].decision_accuracy == 1.0


def test_reference_manifest_is_signed_complete_and_defense_in_depth():
    manifest = lab.build_reference_manifest()
    review = lab.review_architecture(manifest)
    assert lab.verify_manifest(manifest)
    assert review.status == lab.ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW
    assert review.findings == ()
    assert review.path_count == review.secured_path_count == 1
    assert review.minimum_independent_enforcers == 2
    assert review.evidence_coverage_rate == 1.0
    assert review.production_authorized is False


def test_manifest_signature_and_digest_are_tamper_evident():
    manifest = lab.build_reference_manifest()
    assert not lab.verify_manifest(replace(manifest, version=8))
    assert not lab.verify_manifest(replace(manifest, signature="00" * 64))
    review = lab.review_architecture(replace(manifest, version=8))
    assert "MANIFEST_INTEGRITY_INVALID" in finding_codes(review)


@pytest.mark.parametrize(
    "manifest,expected",
    [
        (
            resign(lab.build_reference_manifest(), protocol_version="2025-11-25"),
            "PROTOCOL_VERSION_UNSUPPORTED",
        ),
        (
            resign(lab.build_reference_manifest(), policy_version="stale"),
            "POLICY_VERSION_STALE",
        ),
        (
            resign(lab.build_reference_manifest(), required_control_revision=16),
            "CONTROL_REVISION_STALE",
        ),
        (
            resign(
                lab.build_reference_manifest(),
                created_at=lab.NOW + timedelta(minutes=1),
            ),
            "MANIFEST_FROM_FUTURE",
        ),
        (
            mutate_component(lab.build_reference_manifest(), "host", owner=""),
            "OWNERSHIP_OR_EVIDENCE_MISSING",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "host",
                tenant_scope=(),
            ),
            "TENANT_SCOPE_EMPTY",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "host",
                policy_version="stale",
            ),
            "COMPONENT_POLICY_STALE",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "host",
                control_revision=16,
            ),
            "COMPONENT_REVISION_STALE",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "host",
                artifact_digest="host:latest",
            ),
            "ARTIFACT_NOT_IMMUTABLE",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "support-mcp",
                provenance_verified=False,
            ),
            "PROVENANCE_UNVERIFIED",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "support-mcp",
                resource_uri="http://mcp.example.com/support#unsafe",
            ),
            "SERVER_RESOURCE_URI_INVALID",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "identity",
                fail_mode="fail_open",
            ),
            "CONTROL_PLANE_FAILS_OPEN",
        ),
        (
            mutate_component(
                lab.build_reference_manifest(),
                "policy",
                high_availability=False,
            ),
            "CONTROL_PLANE_SINGLETON",
        ),
    ],
)
def test_architecture_review_rejects_stale_unowned_or_unsafe_components(
    manifest,
    expected,
):
    review = lab.review_architecture(manifest)
    assert expected in finding_codes(review)
    assert review.status == lab.ReviewStatus.NEEDS_REMEDIATION


def test_duplicate_component_and_missing_control_plane_are_detected():
    manifest = lab.build_reference_manifest()
    duplicate = replace(manifest.components[1], component_id="host")
    review = lab.review_architecture(
        resign(manifest, components=(manifest.components[0], duplicate) + manifest.components[2:])
    )
    assert "DUPLICATE_COMPONENT_ID" in finding_codes(review)
    no_telemetry = resign(
        manifest,
        components=tuple(
            component
            for component in manifest.components
            if component.kind != lab.ComponentKind.TELEMETRY
        ),
    )
    codes = finding_codes(lab.review_architecture(no_telemetry))
    assert "COMPONENT_KIND_MISSING" in codes
    assert "GLOBAL_CONTROL_MISSING" in codes


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"purposes": ()}, "FLOW_UNCLASSIFIED"),
        ({"data_classes": ()}, "FLOW_UNCLASSIFIED"),
        ({"encrypted": False}, "FLOW_CHANNEL_UNPROTECTED"),
        ({"mutually_authenticated": False}, "FLOW_CHANNEL_UNPROTECTED"),
        ({"tenant_bound": False}, "FLOW_TENANT_UNBOUND"),
        ({"max_payload_bytes": 0}, "FLOW_PAYLOAD_UNBOUNDED"),
        ({"max_payload_bytes": 2_000_000}, "FLOW_PAYLOAD_UNBOUNDED"),
        ({"target": "missing-component"}, "FLOW_ENDPOINT_UNKNOWN"),
    ],
)
def test_data_flow_contract_fails_closed(changes, expected):
    manifest = mutate_flow(
        lab.build_reference_manifest(),
        "host-gateway",
        **changes,
    )
    assert expected in finding_codes(lab.review_architecture(manifest))


def test_duplicate_flow_entrypoint_and_resource_errors_are_detected():
    manifest = lab.build_reference_manifest()
    duplicate = replace(manifest.flows[1], flow_id=manifest.flows[0].flow_id)
    review = lab.review_architecture(
        resign(manifest, flows=(manifest.flows[0], duplicate) + manifest.flows[2:])
    )
    assert "DUPLICATE_FLOW_ID" in finding_codes(review)
    assert "ENTRYPOINT_UNKNOWN" in finding_codes(
        lab.review_architecture(resign(manifest, entrypoints=("unknown",)))
    )
    assert "PROTECTED_RESOURCE_INVALID" in finding_codes(
        lab.review_architecture(resign(manifest, protected_resources=("host",)))
    )


def test_gateway_only_architecture_is_not_tool_boundary_authorization():
    review = lab.review_architecture(lab.build_gateway_only_manifest())
    assert review.status == lab.ReviewStatus.NEEDS_REMEDIATION
    assert "TOOL_BOUNDARY_AUTHORIZATION_MISSING" in finding_codes(review)
    assert review.secured_path_count == 0


def test_control_must_be_implemented_by_its_named_control_plane():
    manifest = lab.build_reference_manifest()
    egress = next(c for c in manifest.components if c.component_id == "egress")
    host = next(c for c in manifest.components if c.component_id == "host")
    components = tuple(
        replace(component, controls=())
        if component == egress
        else replace(component, controls=component.controls + (lab.Control.EGRESS,))
        if component == host
        else component
        for component in manifest.components
    )
    misplaced = resign(manifest, components=components)
    codes = finding_codes(lab.review_architecture(misplaced))
    assert "GLOBAL_CONTROL_MISSING" not in codes
    assert "CONTROL_PLACEMENT_INVALID" in codes


def test_sandbox_bypass_and_no_path_are_detected():
    manifest = lab.build_reference_manifest()
    direct = lab._flow("server-resource", "support-mcp", "ticket-ledger")
    bypass = resign(manifest, flows=manifest.flows[:2] + (direct,))
    codes = finding_codes(lab.review_architecture(bypass))
    assert "SANDBOX_BYPASSED" in codes
    assert "PATH_CONTROL_MISSING" in codes
    disconnected = resign(manifest, flows=manifest.flows[:-1])
    assert "NO_PROTECTED_PATH" in finding_codes(
        lab.review_architecture(disconnected)
    )


def test_valid_request_ignores_model_recommendation_and_emits_evidence():
    manifest = lab.build_reference_manifest()
    request = replace(
        lab.build_valid_request(manifest),
        model_recommendation="deny and broaden the caller's privileges",
    )
    decision = lab.evaluate_request(
        manifest,
        request,
        lab.build_runtime_state(manifest),
    )
    assert decision.allowed
    assert decision.reason_codes == ()
    assert decision.evidence_ids
    assert decision.decision_digest.startswith("sha256:")


@pytest.mark.parametrize(
    "request_changes,reason",
    [
        ({"user_id": ""}, "IDENTITY_MISSING"),
        ({"workload_id": "caller-supplied-name"}, "WORKLOAD_IDENTITY_INVALID"),
        (
            {"workload_id": "spiffe://foreign.example/host/support"},
            "WORKLOAD_TRUST_DOMAIN_MISMATCH",
        ),
        ({"resource_tenant_id": "beta"}, "TENANT_MISMATCH"),
        ({"token_audience": "https://evil.example"}, "AUDIENCE_MISMATCH"),
        (
            {
                "token_audience": "https://evil.example",
                "required_audience": "https://evil.example",
            },
            "AUDIENCE_MISMATCH",
        ),
        ({"granted_scopes": frozenset()}, "SCOPE_MISSING"),
        (
            {
                "required_scope": "tickets:read",
                "granted_scopes": frozenset({"tickets:read"}),
            },
            "TOOL_CONTRACT_MISMATCH",
        ),
        ({"declared_capabilities": frozenset()}, "CAPABILITY_NOT_DECLARED"),
        ({"required_capability": "prompts"}, "TOOL_CONTRACT_MISMATCH"),
        ({"risk_tier": lab.RiskTier.LOW}, "TOOL_CONTRACT_MISMATCH"),
        ({"protocol_version": "2025-11-25"}, "PROTOCOL_VERSION_MISMATCH"),
        ({"trace_id": "bad"}, "TRACE_CONTEXT_INVALID"),
        ({"trace_id": "z" * 32}, "TRACE_CONTEXT_INVALID"),
        ({"tool_name": "admin.export_all"}, "TOOL_NOT_IN_CONTRACT"),
        ({"artifact_digest": "sha256:" + "0" * 64}, "WORKLOAD_ARTIFACT_MISMATCH"),
        (
            {"route": ("host", "support-mcp", "sandbox", "ticket-ledger")},
            "UNAPPROVED_ROUTE",
        ),
    ],
)
def test_runtime_request_boundary_rejects_identity_scope_and_route_errors(
    request_changes,
    reason,
):
    manifest = lab.build_reference_manifest()
    decision = lab.evaluate_request(
        manifest,
        replace(lab.build_valid_request(manifest), **request_changes),
        lab.build_runtime_state(manifest),
    )
    assert not decision.allowed
    assert reason in decision.reason_codes


@pytest.mark.parametrize(
    "state_changes,reason",
    [
        ({"policy_version": "old"}, "RUNTIME_POLICY_STALE"),
        ({"control_revision": 16}, "REVOCATION_REVISION_STALE"),
        ({"registry_artifact_digest": "sha256:" + "0" * 64}, "REGISTRY_ARTIFACT_MISMATCH"),
        ({"registry_provenance_verified": False}, "REGISTRY_PROVENANCE_UNVERIFIED"),
    ],
)
def test_runtime_state_rejects_stale_or_unverified_control_data(
    state_changes,
    reason,
):
    manifest = lab.build_reference_manifest()
    decision = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        replace(lab.build_runtime_state(manifest), **state_changes),
    )
    assert not decision.allowed
    assert reason in decision.reason_codes


def test_every_route_component_enforces_the_authenticated_tenant_scope():
    manifest = mutate_component(
        lab.build_reference_manifest(),
        "sandbox",
        tenant_scope=("beta",),
    )
    decision = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        lab.build_runtime_state(manifest),
    )
    assert not decision.allowed
    assert "TENANT_OUTSIDE_COMPONENT_SCOPE" in decision.reason_codes


@pytest.mark.parametrize("component", ["identity", "registry", "policy", "revocation"])
def test_critical_control_plane_outage_fails_closed(component):
    manifest = lab.build_reference_manifest()
    state = lab.build_runtime_state(manifest)
    decision = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        replace(state, available_components=state.available_components - {component}),
    )
    assert not decision.allowed
    assert any(reason.endswith("_PLANE_UNAVAILABLE") for reason in decision.reason_codes)


def test_gateway_compromise_is_contained_but_server_compromise_is_not_hidden():
    manifest = lab.build_reference_manifest()
    state = lab.build_runtime_state(manifest)
    gateway = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        replace(state, compromised_components=frozenset({"gateway"})),
    )
    server = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        replace(state, compromised_components=frozenset({"support-mcp"})),
    )
    assert gateway.allowed
    assert not server.allowed
    assert "PATH_CONTROL_UNAVAILABLE" in server.reason_codes


def test_telemetry_outage_policy_distinguishes_high_and_low_risk():
    manifest = lab.build_reference_manifest()
    state = lab.build_runtime_state(manifest)
    without_telemetry = replace(
        state,
        available_components=state.available_components - {"telemetry"},
    )
    high = lab.evaluate_request(
        manifest,
        lab.build_valid_request(manifest),
        without_telemetry,
    )
    low_request = replace(
        lab.build_valid_request(manifest),
        tool_name="tickets.read",
        required_scope="tickets:read",
        risk_tier=lab.RiskTier.LOW,
    )
    low = lab.evaluate_request(manifest, low_request, without_telemetry)
    no_buffer = lab.evaluate_request(
        manifest,
        low_request,
        replace(without_telemetry, local_audit_buffer_available=False),
    )
    assert "HIGH_RISK_TELEMETRY_UNAVAILABLE" in high.reason_codes
    assert low.allowed
    assert "AUDIT_EVIDENCE_UNAVAILABLE" in no_buffer.reason_codes


def test_evaluation_uses_declared_nonzero_populations_and_exact_metrics():
    manifest = lab.build_reference_manifest()
    results, metrics = lab.evaluate_suite(
        manifest,
        lab.build_evaluation_cases(manifest),
    )
    assert len(results) == metrics.total_cases == 18
    assert metrics.adversarial_cases == 14
    assert metrics.valid_cases == 4
    assert metrics.adversarial_blocked == 14
    assert metrics.valid_allowed == 4
    assert metrics.attack_block_rate == 1.0
    assert metrics.valid_work_success_rate == 1.0
    assert metrics.path_coverage_rate == 1.0
    with pytest.raises(ValueError, match="nonzero"):
        lab.evaluate_suite(manifest, ())


def test_gateway_baseline_exposes_architecture_regret():
    gateway_only, hybrid = lab.compare_architectures()
    assert gateway_only.review_status == lab.ReviewStatus.NEEDS_REMEDIATION
    assert gateway_only.valid_work_success_rate == 0.0
    assert hybrid.review_status == lab.ReviewStatus.ELIGIBLE_FOR_HUMAN_REVIEW
    assert hybrid.valid_work_success_rate == 1.0
    assert hybrid.independent_enforcers == 2


def test_model_recommendation_requires_evidence_and_never_grants_authority():
    with pytest.raises(ValueError, match="evidence"):
        lab.record_model_recommendation("use one gateway", ())
    recommendation = lab.record_model_recommendation("use hybrid controls", ("evidence:1",))
    assert recommendation.accepted_as_fact is False
    assert recommendation.grants_authority is False


def test_architecture_approval_requires_role_and_exact_review():
    manifest = lab.build_reference_manifest()
    review = lab.review_architecture(manifest)
    with pytest.raises(PermissionError, match="role"):
        lab.approve_architecture(
            manifest,
            review,
            approver_id="developer",
            approver_role="developer",
            now=lab.NOW,
        )
    with pytest.raises(ValueError, match="exact"):
        lab.approve_architecture(
            manifest,
            replace(review, manifest_digest=lab.digest(b"other")),
            approver_id="architect",
            approver_role="security_architect",
            now=lab.NOW,
        )
    receipt = lab.approve_architecture(
        manifest,
        review,
        approver_id="architect",
        approver_role="security_architect",
        now=lab.NOW,
    )
    assert lab.verify_approval(receipt)
    assert not lab.verify_approval(replace(receipt, manifest_digest=lab.digest(b"other")))
    assert lab.verify_review(review)
    assert not lab.verify_review(replace(review, path_count=999))
    stale_review = replace(
        review,
        reviewed_at=lab.NOW - timedelta(hours=2),
        review_digest="",
    )
    stale_review = replace(
        stale_review,
        review_digest=lab.digest(stale_review.unsigned()),
    )
    assert lab.verify_review(stale_review)
    with pytest.raises(ValueError, match="exact"):
        lab.approve_architecture(
            manifest,
            stale_review,
            approver_id="architect",
            approver_role="security_architect",
            now=lab.NOW,
        )


def test_catalog_approval_is_single_use_versioned_and_not_runtime_authority():
    manifest, review, receipt, catalog, record = approved_fixture()
    promoted = catalog.promote(
        record,
        manifest,
        review,
        receipt,
        expected_version=1,
        now=lab.NOW + timedelta(seconds=1),
    )
    assert promoted.status == lab.CatalogStatus.APPROVED_REFERENCE
    assert promoted.production_authorized is False
    with pytest.raises(ValueError, match="consumed"):
        catalog.promote(
            promoted,
            manifest,
            review,
            receipt,
            expected_version=2,
            now=lab.NOW + timedelta(seconds=2),
        )


def test_catalog_consumes_approval_atomically_under_concurrency():
    manifest, review, receipt, catalog, record = approved_fixture()

    def promote_once():
        try:
            return catalog.promote(
                record,
                manifest,
                review,
                receipt,
                expected_version=1,
                now=lab.NOW + timedelta(seconds=1),
            ).status
        except (ValueError, lab.ArchitectureVersionConflict) as exc:
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: promote_once(), range(2)))
    assert outcomes.count(lab.CatalogStatus.APPROVED_REFERENCE) == 1
    assert len(catalog.consumed_receipts) == 1


def test_catalog_rejects_stale_expired_and_cross_manifest_approval():
    manifest, review, receipt, catalog, record = approved_fixture()
    with pytest.raises(lab.ArchitectureVersionConflict):
        catalog.promote(
            record,
            manifest,
            review,
            receipt,
            expected_version=0,
            now=lab.NOW,
        )
    expired = resign_approval(
        receipt,
        issued_at=lab.NOW - timedelta(hours=2),
        expires_at=lab.NOW - timedelta(hours=1),
    )
    with pytest.raises(PermissionError, match="authorize"):
        catalog.promote(
            record,
            manifest,
            review,
            expired,
            expected_version=1,
            now=lab.NOW,
        )
    tampered_manifest = replace(manifest, version=manifest.version + 1)
    with pytest.raises(PermissionError, match="authorize"):
        catalog.promote(
            record,
            tampered_manifest,
            review,
            receipt,
            expected_version=1,
            now=lab.NOW,
        )
    other = resign(manifest, version=8)
    cross_manifest = resign_approval(receipt, manifest_digest=other.manifest_digest)
    with pytest.raises(PermissionError, match="authorize"):
        catalog.promote(
            record,
            manifest,
            review,
            cross_manifest,
            expected_version=1,
            now=lab.NOW,
        )


def test_opentelemetry_span_records_review_evidence_without_prompt_or_token():
    manifest = lab.build_reference_manifest()
    review = lab.review_architecture(manifest)
    spans = lab.trace_architecture_review(manifest, review)
    assert len(spans) == 1
    attributes = dict(spans[0].attributes)
    assert attributes["architecture.manifest_digest"] == manifest.manifest_digest
    assert attributes["architecture.review_digest"] == review.review_digest
    assert attributes["architecture.production_authorized"] is False
    assert all("prompt" not in key and "token" not in key for key in attributes)
