"""Executable supply-chain lifecycle invariants for Course 26."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/26-mcp-supply-chain-risk-management/lab.py"
SPEC = importlib.util.spec_from_file_location("course_26_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = 1_000


def setup_demo():
    return lab.demo_components(NOW)


def valid_evidence(authority, request):
    return lab.evidence_fixture(authority, request, NOW)


def error_code(exc):
    return exc.value.code


def valid_proposal():
    principals, authority, engine, approvals, registry, request = setup_demo()
    evidence = valid_evidence(authority, request)
    proposal = engine.propose_decision(
        request, evidence, (), (), NOW + 1, "DEC-VALID"
    )
    return principals, authority, engine, approvals, registry, request, evidence, proposal


def compensation_evidence(authority, component, now=NOW):
    artifact = lab.EvidenceArtifact(
        "EV-COMPENSATION",
        lab.EvidenceKind.COMPENSATING_CONTROL_TEST,
        "component",
        component.component_id,
        component.version,
        component.artifact_digest,
        "producer:ci",
        True,
        lab.EvidenceOutcome.PASS,
        "network deny policy blocks vulnerable code path",
        now,
        now + 86_400,
        "f" * 64,
        "25 labelled exploit attempts",
        25,
        25,
        "attempts blocked",
    )
    return authority.sign(artifact)


def high_finding(request, **changes):
    finding = lab.Finding(
        "OSV-2026-001",
        request.components[1].component_id,
        lab.FindingSeverity.HIGH,
        lab.FindingStatus.OPEN,
        lab.Exploitability.AFFECTED,
        "OSV",
        "osv-db-2026-10-30",
        NOW,
        NOW + 86_400,
    )
    return replace(finding, **changes)


def active_exception(authority, approvals, registry, request, finding):
    component = next(
        item for item in request.components
        if item.component_id == finding.component_id
    )
    control_evidence = compensation_evidence(authority, component)
    exception = lab.ExceptionRequest(
        "EX-1",
        finding.finding_id,
        component.component_id,
        component.version,
        component.artifact_digest,
        request.tenant_scope,
        request.business_owner_id,
        "temporary exposure while fixed SDK is qualified",
        ("network-deny-vulnerable-path",),
        (control_evidence.artifact.evidence_id,),
        "alert on every attempted vulnerable operation",
        "upgrade to fixed SDK and remove the exception",
        NOW,
        NOW + 2 * 86_400,
        NOW + 5 * 86_400,
    )
    receipt = approvals.issue(
        "supply_chain_exception",
        exception.payload(),
        request.business_owner_id,
        "approver:ciso",
        "ciso",
        NOW,
    )
    active = registry.activate_exception(
        exception, receipt.receipt_id, request.business_owner_id, NOW + 1
    )
    return control_evidence, active


def test_demo_performs_evidence_bound_critical_supplier_admission(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"decision": "approve"' in output
    assert '"supplier_tier": "critical"' in output
    assert '"verified_evidence_count": 16' in output


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"tenant_scope": ""}, "INTAKE_METADATA_INCOMPLETE"),
        ({"use_case": ""}, "INTAKE_METADATA_INCOMPLETE"),
        ({"business_owner_id": "unknown"}, "INTAKE_OWNER_INACTIVE"),
        ({"policy_version": "old"}, "INTAKE_POLICY_STALE"),
        ({"version": 0}, "INTAKE_VERSION_OR_TIME_INVALID"),
        ({"requested_at": NOW + 1}, "INTAKE_VERSION_OR_TIME_INVALID"),
        ({"components": ()}, "COMPONENT_INVENTORY_EMPTY"),
    ],
)
def test_intake_requires_complete_current_owned_metadata(changes, expected):
    _, _, engine, _, _, request = setup_demo()
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(replace(request, **changes), NOW)
    assert error_code(exc) == expected


@pytest.mark.parametrize(
    ("profile_changes", "expected"),
    [
        ({"owner_id": "unknown"}, "INTAKE_OWNER_INACTIVE"),
        ({"reviewed_at": NOW + 1}, "SUPPLIER_PROFILE_STALE"),
        ({"reviewed_at": NOW - 91 * 86_400}, "SUPPLIER_PROFILE_STALE"),
        ({"review_due_at": NOW}, "SUPPLIER_PROFILE_STALE"),
        ({"incident_notice_hours": 0}, "SUPPLIER_PROFILE_INCOMPLETE"),
        ({"service_kinds": ()}, "SUPPLIER_PROFILE_INCOMPLETE"),
        ({"exit_plan": ""}, "INTAKE_METADATA_INCOMPLETE"),
    ],
)
def test_supplier_profile_requires_owner_freshness_and_exit_plan(profile_changes, expected):
    _, _, engine, _, _, request = setup_demo()
    candidate = replace(request, supplier=replace(request.supplier, **profile_changes))
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(candidate, NOW)
    assert error_code(exc) == expected


def test_dependency_inventory_requires_unique_components_and_one_root():
    _, _, engine, _, _, request = setup_demo()
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(
            replace(request, components=(request.components[0], request.components[0])),
            NOW,
        )
    assert error_code(exc) == "DUPLICATE_COMPONENT"
    no_root = tuple(replace(item, root=False) for item in request.components)
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(replace(request, components=no_root), NOW)
    assert error_code(exc) == "ROOT_COMPONENT_INVALID"


def test_dependency_graph_rejects_unknown_self_and_orphan_edges():
    _, _, engine, _, _, request = setup_demo()
    root, dependency = request.components
    for bad_dependencies in (("unknown",), (root.component_id,)):
        bad_root = replace(root, dependency_ids=bad_dependencies)
        with pytest.raises(lab.SupplyChainError) as exc:
            engine.validate_intake(
                replace(request, components=(bad_root, dependency)), NOW
            )
        assert error_code(exc) == "DEPENDENCY_EDGE_INVALID"
    orphan_root = replace(root, dependency_ids=())
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(
            replace(request, components=(orphan_root, dependency)), NOW
        )
    assert error_code(exc) == "DEPENDENCY_GRAPH_INCOMPLETE"


@pytest.mark.parametrize(
    "component_changes",
    [
        {"supplier_id": "other"},
        {"version": ""},
        {"artifact_digest": "short"},
        {"purl": "not-a-purl"},
        {"capabilities": ()},
    ],
)
def test_component_inventory_requires_pinned_scoped_metadata(component_changes):
    _, _, engine, _, _, request = setup_demo()
    root = replace(request.components[0], **component_changes)
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_intake(
            replace(request, components=(root, request.components[1])), NOW
        )
    assert error_code(exc) == "COMPONENT_METADATA_INVALID"


def test_signed_evidence_is_bound_to_exact_payload():
    _, authority, engine, _, _, request = setup_demo()
    signed = valid_evidence(authority, request)[0]
    engine.validate_evidence(signed, request, NOW + 1)
    tampered = replace(signed, artifact=replace(signed.artifact, numerator=0))
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_evidence(tampered, request, NOW + 1)
    assert error_code(exc) == "EVIDENCE_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"producer_id": "owner:maya"}, "EVIDENCE_PRODUCER_UNTRUSTED"),
        ({"observed_at": NOW + 2}, "EVIDENCE_STALE"),
        ({"expires_at": NOW + 1}, "EVIDENCE_STALE"),
        ({"outcome": lab.EvidenceOutcome.FAIL}, "EVIDENCE_NOT_PASSING"),
        ({"claim": ""}, "EVIDENCE_METRIC_INVALID"),
        ({"artifact_digest": "short"}, "EVIDENCE_METRIC_INVALID"),
        ({"population": ""}, "EVIDENCE_METRIC_INVALID"),
        ({"denominator": 0}, "EVIDENCE_METRIC_INVALID"),
        ({"numerator": -1}, "EVIDENCE_METRIC_INVALID"),
        ({"numerator": 2, "denominator": 1}, "EVIDENCE_METRIC_INVALID"),
        ({"subject_type": "unknown"}, "EVIDENCE_SUBJECT_TYPE_INVALID"),
        ({"subject_version": "old"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"subject_digest": "0" * 64}, "EVIDENCE_SUBJECT_MISMATCH"),
    ],
)
def test_evidence_rejects_untrusted_stale_failed_or_misscoped_claims(changes, expected):
    _, authority, engine, _, _, request = setup_demo()
    artifact = replace(valid_evidence(authority, request)[0].artifact, **changes)
    signed = authority.sign(artifact)
    with pytest.raises(lab.SupplyChainError) as exc:
        engine.validate_evidence(signed, request, NOW + 1)
    assert error_code(exc) == expected


@pytest.mark.parametrize(
    "kind",
    list(lab.DEFAULT_POLICY.supplier_requirements[lab.SupplierTier.CRITICAL]),
)
def test_every_critical_supplier_evidence_kind_is_required(kind):
    _, authority, engine, _, _, request = setup_demo()
    evidence = tuple(
        item for item in valid_evidence(authority, request)
        if not (
            item.artifact.subject_type == "supplier"
            and item.artifact.kind is kind
        )
    )
    result = engine.evaluate(request, evidence, (), (), NOW + 1)
    assert f"supplier:missing:{kind.value}" in result.blockers


def test_critical_supplier_independent_assessment_must_be_independent():
    _, authority, engine, _, _, request = setup_demo()
    evidence = tuple(
        authority.sign(replace(item.artifact, independent=False))
        if item.artifact.kind is lab.EvidenceKind.INDEPENDENT_ASSESSMENT
        else item
        for item in valid_evidence(authority, request)
    )
    result = engine.evaluate(request, evidence, (), (), NOW + 1)
    assert "supplier:independent_assessment_required" in result.blockers


@pytest.mark.parametrize(
    ("component_id", "kind"),
    [
        ("component:server", kind)
        for kind in lab.DEFAULT_POLICY.component_requirements[lab.ServiceKind.MCP_SERVER]
    ] + [
        ("component:sdk", kind)
        for kind in lab.DEFAULT_POLICY.component_requirements[lab.ServiceKind.SDK]
    ],
)
def test_every_component_evidence_kind_is_required(component_id, kind):
    _, authority, engine, _, _, request = setup_demo()
    evidence = tuple(
        item for item in valid_evidence(authority, request)
        if not (
            item.artifact.subject_id == component_id
            and item.artifact.kind is kind
        )
    )
    result = engine.evaluate(request, evidence, (), (), NOW + 1)
    assert f"component:{component_id}:missing:{kind.value}" in result.blockers


def test_duplicate_evidence_id_fails_closed():
    _, authority, engine, _, _, request = setup_demo()
    evidence = valid_evidence(authority, request)
    result = engine.evaluate(request, evidence + (evidence[0],), (), (), NOW + 1)
    assert f"evidence:{evidence[0].artifact.evidence_id}:DUPLICATE" in result.blockers


def test_green_provenance_signature_and_sbom_do_not_erase_open_critical_finding():
    _, authority, engine, _, _, request = setup_demo()
    finding = high_finding(
        request,
        severity=lab.FindingSeverity.CRITICAL,
        finding_id="CVE-CRITICAL",
    )
    proposal = engine.propose_decision(
        request, valid_evidence(authority, request), (finding,), (),
        NOW + 1, "DEC-CRITICAL",
    )
    assert proposal.recommendation is lab.Decision.DENY
    assert "finding:CVE-CRITICAL:critical_open" in proposal.blockers


def test_valid_high_finding_exception_produces_conditional_decision():
    _, authority, engine, approvals, registry, request = setup_demo()
    finding = high_finding(request)
    control_evidence, active = active_exception(
        authority, approvals, registry, request, finding
    )
    evidence = valid_evidence(authority, request) + (control_evidence,)
    proposal = engine.propose_decision(
        request, evidence, (finding,), (active,), NOW + 2, "DEC-CONDITIONAL"
    )
    assert proposal.recommendation is lab.Decision.CONDITIONAL
    assert proposal.exception_ids == ("EX-1",)
    assert not proposal.blockers


def test_critical_finding_cannot_use_exception_path():
    _, authority, engine, approvals, registry, request = setup_demo()
    finding = high_finding(
        request,
        severity=lab.FindingSeverity.CRITICAL,
        finding_id="CVE-CRITICAL",
    )
    control_evidence, active = active_exception(
        authority, approvals, registry, request, finding
    )
    proposal = engine.propose_decision(
        request,
        valid_evidence(authority, request) + (control_evidence,),
        (finding,),
        (active,),
        NOW + 2,
        "DEC-CRITICAL-EXCEPTION",
    )
    assert proposal.recommendation is lab.Decision.DENY


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"tenant_scope": "beta"}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"component_version": "old"}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"artifact_digest": "0" * 64}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"owner_id": "unknown"}, "EXCEPTION_INVALID"),
        ({"rationale": ""}, "EXCEPTION_INVALID"),
        ({"compensating_controls": ()}, "EXCEPTION_INVALID"),
        ({"evidence_ids": ()}, "EXCEPTION_INVALID"),
        ({"monitoring_plan": ""}, "EXCEPTION_INVALID"),
        ({"exit_plan": ""}, "EXCEPTION_INVALID"),
        ({"review_at": NOW}, "EXCEPTION_INVALID"),
        ({"expires_at": NOW}, "EXCEPTION_INVALID"),
        ({"expires_at": NOW + 15 * 86_400}, "EXCEPTION_INVALID"),
    ],
)
def test_exception_requires_exact_scope_owner_controls_and_bounded_lifecycle(changes, expected):
    _, _, _, approvals, registry, request = setup_demo()
    component = request.components[1]
    exception = lab.ExceptionRequest(
        "EX-BAD",
        "OSV-2026-001",
        component.component_id,
        component.version,
        component.artifact_digest,
        request.tenant_scope,
        request.business_owner_id,
        "temporary exposure",
        ("network-deny",),
        ("EV-COMPENSATION",),
        "monitor attempted calls",
        "upgrade and remove exception",
        NOW,
        NOW + 2 * 86_400,
        NOW + 5 * 86_400,
    )
    candidate = replace(exception, **changes)
    receipt = approvals.issue(
        "supply_chain_exception",
        candidate.payload(),
        request.business_owner_id,
        "approver:ciso",
        "ciso",
        NOW,
    )
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.activate_exception(
            candidate, receipt.receipt_id, request.business_owner_id, NOW + 1
        )
    assert error_code(exc) == expected


def test_exception_evidence_must_be_component_bound_compensating_control_test():
    _, authority, engine, approvals, registry, request = setup_demo()
    finding = high_finding(request)
    _, active = active_exception(authority, approvals, registry, request, finding)
    evidence = valid_evidence(authority, request)
    proposal = engine.propose_decision(
        request, evidence, (finding,), (active,), NOW + 2, "DEC-BAD-EX-EVIDENCE"
    )
    assert proposal.recommendation is lab.Decision.DENY
    assert f"finding:{finding.finding_id}:unresolved" in proposal.blockers


def test_open_medium_is_allowed_until_due_but_blocks_when_overdue():
    _, authority, engine, _, _, request = setup_demo()
    current = high_finding(
        request,
        finding_id="MEDIUM-1",
        severity=lab.FindingSeverity.MEDIUM,
        due_at=NOW + 100,
    )
    proposal = engine.propose_decision(
        request, valid_evidence(authority, request), (current,), (),
        NOW + 1, "DEC-MEDIUM-CURRENT",
    )
    assert proposal.recommendation is lab.Decision.APPROVE
    overdue = replace(current, due_at=NOW)
    proposal = engine.propose_decision(
        request, valid_evidence(authority, request), (overdue,), (),
        NOW + 1, "DEC-MEDIUM-OVERDUE",
    )
    assert proposal.recommendation is lab.Decision.DENY


def test_not_affected_claim_requires_consistent_finding_status():
    _, authority, engine, _, _, request = setup_demo()
    conflict = high_finding(
        request,
        finding_id="VEX-CONFLICT",
        exploitability=lab.Exploitability.NOT_AFFECTED,
        status=lab.FindingStatus.OPEN,
    )
    result = engine.evaluate(
        request, valid_evidence(authority, request), (conflict,), (), NOW + 1
    )
    assert "finding:VEX-CONFLICT:status_conflict" in result.blockers
    consistent = replace(conflict, status=lab.FindingStatus.NOT_AFFECTED)
    consistent = replace(
        consistent,
        resolution_evidence_ids=("EV-SDK-VULNERABILITY_REPORT",),
    )
    result = engine.evaluate(
        request, valid_evidence(authority, request), (consistent,), (), NOW + 1
    )
    assert not result.blockers


def test_resolved_finding_requires_current_component_bound_resolution_evidence():
    _, authority, engine, _, _, request = setup_demo()
    remediated = high_finding(
        request,
        finding_id="FIXED-1",
        status=lab.FindingStatus.REMEDIATED,
    )
    result = engine.evaluate(
        request, valid_evidence(authority, request), (remediated,), (), NOW + 1
    )
    assert "finding:FIXED-1:resolution_evidence_missing" in result.blockers
    evidenced = replace(
        remediated,
        resolution_evidence_ids=("EV-SDK-VULNERABILITY_REPORT",),
    )
    result = engine.evaluate(
        request, valid_evidence(authority, request), (evidenced,), (), NOW + 1
    )
    assert not result.blockers


def test_unknown_component_and_missing_finding_provenance_fail_closed():
    _, authority, engine, _, _, request = setup_demo()
    unknown = high_finding(request, finding_id="UNKNOWN", component_id="other")
    result = engine.evaluate(
        request, valid_evidence(authority, request), (unknown,), (), NOW + 1
    )
    assert "finding:UNKNOWN:component_unknown" in result.blockers
    no_source = high_finding(request, finding_id="NO-SOURCE", source="")
    result = engine.evaluate(
        request, valid_evidence(authority, request), (no_source,), (), NOW + 1
    )
    assert "finding:NO-SOURCE:provenance_incomplete" in result.blockers


def test_duplicate_finding_ids_fail_closed():
    _, authority, engine, _, _, request = setup_demo()
    finding = high_finding(request)
    result = engine.evaluate(
        request,
        valid_evidence(authority, request),
        (finding, finding),
        (),
        NOW + 1,
    )
    assert "finding:duplicate" in result.blockers


def test_approval_requires_separation_role_expiry_and_exact_payload():
    _, _, _, approvals, _, request = setup_demo()
    with pytest.raises(lab.SupplyChainError) as exc:
        approvals.issue(
            "supply_chain_decision", {"x": 1}, "committee:1",
            "committee:1", "supply-chain-committee", NOW,
        )
    assert error_code(exc) == "SEPARATION_OF_DUTIES"
    receipt = approvals.issue(
        "supply_chain_decision", {"x": 1}, request.business_owner_id,
        "committee:1", "supply-chain-committee", NOW, 1,
    )
    with pytest.raises(lab.SupplyChainError) as exc:
        approvals.consume(
            receipt.receipt_id,
            "supply_chain_decision",
            {"x": 1},
            request.business_owner_id,
            NOW + 1,
            frozenset({"supply-chain-committee"}),
        )
    assert error_code(exc) == "APPROVAL_EXPIRED"


def test_approval_consumption_is_atomic_under_concurrency():
    _, _, _, approvals, _, request = setup_demo()
    payload = {"intake": request.intake_id, "version": 1}
    receipt = approvals.issue(
        "supply_chain_decision",
        payload,
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        NOW,
    )

    def consume():
        try:
            approvals.consume(
                receipt.receipt_id,
                "supply_chain_decision",
                payload,
                request.business_owner_id,
                NOW + 1,
                frozenset({"supply-chain-committee"}),
            )
            return "ok"
        except lab.SupplyChainError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(), range(20)))
    assert results.count("ok") == 1
    assert results.count("APPROVAL_REPLAY") == 19


def test_critical_supplier_requires_committee_role():
    _, _, _, approvals, registry, request, _, proposal = valid_proposal()
    weak = approvals.issue(
        "supply_chain_decision",
        proposal.payload(),
        request.business_owner_id,
        "approver:manager",
        "supply-chain-manager",
        NOW + 1,
    )
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.apply_decision(
            proposal, weak.receipt_id, request.business_owner_id, "op-weak", NOW + 2
        )
    assert error_code(exc) == "APPROVAL_ROLE_INSUFFICIENT"


def test_fabricated_or_mutated_proposal_is_rejected():
    _, _, _, approvals, registry, request, _, proposal = valid_proposal()
    mutated = replace(proposal, verified_evidence_ids=())
    receipt = approvals.issue(
        "supply_chain_decision",
        mutated.payload(),
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        NOW + 1,
    )
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.apply_decision(
            mutated, receipt.receipt_id, request.business_owner_id,
            "op-fabricated", NOW + 2,
        )
    assert error_code(exc) == "DECISION_PROPOSAL_UNTRUSTED"


def test_decision_is_version_bound_and_idempotent_for_unknown_retry():
    _, _, _, approvals, registry, request, _, proposal = valid_proposal()
    receipt = approvals.issue(
        "supply_chain_decision",
        proposal.payload(),
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        NOW + 1,
    )
    first = registry.apply_decision(
        proposal, receipt.receipt_id, request.business_owner_id, "op-1", NOW + 2
    )
    second = registry.apply_decision(
        proposal, receipt.receipt_id, request.business_owner_id, "op-1", NOW + 3
    )
    assert first == second
    assert first.state is lab.AdmissionState.APPROVED
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.apply_decision(
            replace(proposal, decision_id="changed"),
            receipt.receipt_id,
            request.business_owner_id,
            "op-1",
            NOW + 3,
        )
    assert error_code(exc) == "DECISION_IDEMPOTENCY_CONFLICT"


def test_decision_expiry_is_bounded_by_shortest_evidence():
    _, authority, engine, _, _, request = setup_demo()
    evidence = list(valid_evidence(authority, request))
    evidence[0] = authority.sign(
        replace(evidence[0].artifact, expires_at=NOW + 100)
    )
    proposal = engine.propose_decision(
        request, evidence, (), (), NOW + 1, "DEC-EXPIRY"
    )
    assert proposal.expires_at == NOW + 100


def approve_registry_record():
    _, _, _, approvals, registry, request, _, proposal = valid_proposal()
    receipt = approvals.issue(
        "supply_chain_decision",
        proposal.payload(),
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        NOW + 1,
    )
    registry.apply_decision(
        proposal, receipt.receipt_id, request.business_owner_id,
        "op-approve", NOW + 2,
    )
    return registry, request


@pytest.mark.parametrize("kind", list(lab.SignalKind))
def test_every_material_signal_invalidates_prior_admission(kind):
    registry, request = approve_registry_record()
    updated = registry.apply_signal(
        request.intake_id,
        f"signal-{kind.value}",
        kind,
        request.supplier.profile_version,
        "profile-v5",
        NOW + 3,
    )
    expected = (
        lab.AdmissionState.QUARANTINED
        if kind in lab.DEFAULT_POLICY.quarantine_signals
        else lab.AdmissionState.REASSESSMENT_REQUIRED
    )
    assert updated.state is expected
    assert updated.decision_id is None
    assert updated.verified_evidence_ids == ()


def test_signal_is_idempotent_and_rejects_ambiguous_version_transition():
    registry, request = approve_registry_record()
    first = registry.apply_signal(
        request.intake_id, "signal-1", lab.SignalKind.NEW_VULNERABILITY,
        "v4", "v5", NOW + 3,
    )
    second = registry.apply_signal(
        request.intake_id, "signal-1", lab.SignalKind.NEW_VULNERABILITY,
        "v4", "v5", NOW + 4,
    )
    assert first == second
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.apply_signal(
            request.intake_id, "signal-2", lab.SignalKind.SERVICE_CHANGE,
            "v5", "v5", NOW + 5,
        )
    assert error_code(exc) == "SIGNAL_VERSION_INVALID"


def test_offboard_requires_invalidated_state_and_records_terminal_transition():
    registry, request = approve_registry_record()
    with pytest.raises(lab.SupplyChainError) as exc:
        registry.offboard(request.intake_id, "offboard-too-soon", NOW + 3)
    assert error_code(exc) == "OFFBOARD_PRECONDITION_FAILED"
    registry.apply_signal(
        request.intake_id, "revocation-1", lab.SignalKind.REVOCATION,
        "active", "revoked", NOW + 4,
    )
    offboarded = registry.offboard(request.intake_id, "offboard-1", NOW + 5)
    assert offboarded.state is lab.AdmissionState.OFFBOARDED
    assert registry.audit[-1].event_type == "supply_chain.offboard"


def test_portfolio_metrics_name_populations_and_denominators():
    _, _, _, approvals, registry, request, _, proposal = valid_proposal()
    receipt = approvals.issue(
        "supply_chain_decision",
        proposal.payload(),
        request.business_owner_id,
        "committee:1",
        "supply-chain-committee",
        NOW + 1,
    )
    registry.apply_decision(
        proposal, receipt.receipt_id, request.business_owner_id,
        "op-metrics", NOW + 2,
    )
    metrics = lab.portfolio_metrics(
        registry.records.values(),
        ("supplier:helpdesk", "supplier:shadow"),
        (),
        NOW + 2,
    )
    assert metrics["supplier_population"] == "observed supplier IDs"
    assert metrics["observed_supplier_count"] == 2
    assert metrics["governed_observed_supplier_count"] == 1
    assert metrics["supplier_inventory_coverage"] == 0.5
    assert metrics["component_population"] == "components in active admission records"
    assert metrics["component_evidence_coverage"] == 1.0
    assert metrics["critical_supplier_profile_freshness"] == 1.0


def test_audit_events_record_identifiers_not_sensitive_evidence_content():
    registry, request = approve_registry_record()
    event = registry.audit[-1]
    assert event.event_type == "supply_chain.decision"
    assert event.operation_id == "op-approve"
    assert event.policy_version == lab.POLICY_VERSION
    assert request.supplier.security_contact not in repr(event)
