"""Executable governance and risk invariants for Course 25."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/25-mcp-security-governance-risk-management/lab.py"
SPEC = importlib.util.spec_from_file_location("course_25_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = 1_000


def setup_demo():
    return lab.demo_components(NOW)


def valid_evidence(authority, record):
    return lab.evidence_fixture(authority, record, NOW)


def code(exc):
    return exc.value.code


def propose_valid():
    principals, controls, authority, engine, approvals, registry, record = setup_demo()
    evidence = valid_evidence(authority, record)
    proposal = engine.propose_decision(record, evidence, (), NOW + 1, "DEC-1")
    return principals, controls, authority, engine, approvals, registry, record, evidence, proposal


def test_demo_records_evidence_backed_decision(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"decision": "approve"' in output
    assert '"inherent_band": "high"' in output
    assert '"residual_band": "moderate"' in output


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [
        (lab.Likelihood.RARE, lab.Impact.NEGLIGIBLE, lab.RiskBand.LOW),
        (lab.Likelihood.UNLIKELY, lab.Impact.MINOR, lab.RiskBand.LOW),
        (lab.Likelihood.POSSIBLE, lab.Impact.MODERATE, lab.RiskBand.MODERATE),
        (lab.Likelihood.LIKELY, lab.Impact.MAJOR, lab.RiskBand.HIGH),
        (lab.Likelihood.ALMOST_CERTAIN, lab.Impact.MAJOR, lab.RiskBand.CRITICAL),
        (lab.Likelihood.ALMOST_CERTAIN, lab.Impact.SEVERE, lab.RiskBand.CRITICAL),
    ],
)
def test_declared_ordinal_matrix_has_explicit_boundaries(likelihood, impact, expected):
    assert lab.risk_band(likelihood, impact) is expected


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"owner_id": ""}, "RISK_METADATA_INCOMPLETE"),
        ({"owner_id": "unknown"}, "RISK_OWNER_INACTIVE"),
        ({"affected_assets": ()}, "RISK_SCOPE_OR_CONTROLS_EMPTY"),
        ({"control_ids": ()}, "RISK_SCOPE_OR_CONTROLS_EMPTY"),
        ({"control_ids": ("CTRL-AUTHZ", "CTRL-AUTHZ")}, "DUPLICATE_CONTROL"),
        ({"control_ids": ("CTRL-UNKNOWN",)}, "CONTROL_UNKNOWN"),
        ({"policy_version": "old"}, "RISK_POLICY_STALE"),
        ({"state": lab.RiskState.AUTHORIZED}, "RISK_INITIAL_STATE_INVALID"),
        ({"review_due_at": NOW}, "RISK_REVIEW_OVERDUE"),
        ({"assessed_at": NOW + 1}, "ASSESSMENT_STALE"),
    ],
)
def test_risk_record_requires_complete_current_governance_metadata(changes, expected):
    _, _, _, engine, _, _, record = setup_demo()
    candidate = replace(record, **changes)
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(candidate, NOW)
    assert code(exc) == expected


def test_assessment_requires_authorized_independent_assessor():
    principals, _, _, engine, _, _, record = setup_demo()
    same_person = replace(
        record, residual=replace(record.residual, assessor_id=record.owner_id)
    )
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(same_person, NOW)
    assert code(exc) == "ASSESSMENT_NOT_INDEPENDENT"
    unauthorized = replace(
        record, residual=replace(record.residual, assessor_id="approver:risk")
    )
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(unauthorized, NOW)
    assert code(exc) == "ASSESSOR_NOT_AUTHORIZED"
    assert principals["assessor:lee"].active


def test_residual_reduction_requires_multiple_evidence_sources():
    _, _, _, engine, _, _, record = setup_demo()
    unsupported = replace(
        record, residual=replace(record.residual, evidence_ids=("only-one",))
    )
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(unsupported, NOW)
    assert code(exc) == "RESIDUAL_REDUCTION_UNSUPPORTED"


def test_treatment_actions_require_owner_deadline_and_completion_proof():
    _, _, _, engine, _, _, record = setup_demo()
    invalid = lab.TreatmentAction("ACT-1", "", "owner:maya", NOW + 10, False)
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(replace(record, actions=(invalid,)), NOW)
    assert code(exc) == "TREATMENT_ACTION_INVALID"
    unproven = replace(invalid, description="rotate credentials", completed=True)
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_record(replace(record, actions=(unproven,)), NOW)
    assert code(exc) == "TREATMENT_COMPLETION_UNPROVEN"


def test_overdue_treatment_action_blocks_authorization():
    _, _, authority, engine, _, _, record = setup_demo()
    action = lab.TreatmentAction(
        "ACT-1", "finish recovery automation", "owner:maya", NOW + 1, False
    )
    candidate = replace(record, actions=(action,))
    result = engine.evaluate(candidate, valid_evidence(authority, candidate), (), NOW + 2)
    assert "treatment_action_overdue:ACT-1" in result.blockers


def test_signed_evidence_is_bound_to_exact_payload():
    _, _, authority, engine, _, _, record = setup_demo()
    signed = valid_evidence(authority, record)[0]
    engine.validate_evidence(signed, record, NOW + 1)
    tampered = replace(signed, artifact=replace(signed.artifact, numerator=39))
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_evidence(tampered, record, NOW + 1)
    assert code(exc) == "EVIDENCE_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"control_id": "OTHER"}, "EVIDENCE_CONTROL_OUT_OF_SCOPE"),
        ({"system_id": "other"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"tenant_scope": "beta"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"subject_version": "v-old"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"producer_id": "owner:maya"}, "EVIDENCE_PRODUCER_UNTRUSTED"),
        ({"observed_at": NOW + 2}, "EVIDENCE_STALE"),
        ({"expires_at": NOW + 1}, "EVIDENCE_STALE"),
        ({"outcome": lab.EvidenceOutcome.FAIL}, "EVIDENCE_NOT_PASSING"),
        ({"outcome": lab.EvidenceOutcome.INCONCLUSIVE}, "EVIDENCE_NOT_PASSING"),
        ({"artifact_digest": "short"}, "EVIDENCE_DIGEST_INVALID"),
        ({"population": ""}, "EVIDENCE_METRIC_UNDEFINED"),
        ({"denominator": 0}, "EVIDENCE_METRIC_INVALID"),
        ({"numerator": 41}, "EVIDENCE_METRIC_INVALID"),
        ({"numerator": -1}, "EVIDENCE_METRIC_INVALID"),
    ],
)
def test_evidence_validation_rejects_untrusted_or_ill_defined_claims(changes, expected):
    _, _, authority, engine, _, _, record = setup_demo()
    artifact = replace(valid_evidence(authority, record)[0].artifact, **changes)
    signed = authority.sign(artifact)
    with pytest.raises(lab.GovernanceError) as exc:
        engine.validate_evidence(signed, record, NOW + 1)
    assert code(exc) == expected


def test_evaluation_requires_every_residual_evidence_id():
    _, _, authority, engine, _, _, record = setup_demo()
    evidence = valid_evidence(authority, record)[:-1]
    result = engine.evaluate(record, evidence, (), NOW + 1)
    assert "residual_assessment_evidence_missing" in result.blockers
    assert any("CTRL-RECOVERY" in blocker for blocker in result.blockers)


def test_evaluation_requires_all_control_evidence_kinds():
    _, _, authority, engine, _, _, record = setup_demo()
    evidence = tuple(
        item for item in valid_evidence(authority, record)
        if item.artifact.kind is not lab.EvidenceKind.TELEMETRY
    )
    result = engine.evaluate(record, evidence, (), NOW + 1)
    assert "control:CTRL-AUTHZ:missing:telemetry" in result.blockers


def test_high_risk_requires_independent_evidence():
    _, _, authority, engine, _, _, record = setup_demo()
    high = replace(
        record,
        residual=replace(
            record.residual,
            likelihood=lab.Likelihood.LIKELY,
            impact=lab.Impact.MAJOR,
        ),
    )
    evidence = tuple(
        authority.sign(replace(item.artifact, independent=False))
        for item in valid_evidence(authority, high)
    )
    result = engine.evaluate(high, evidence, (), NOW + 1)
    assert "independent_evidence_required" in result.blockers


def test_prohibited_critical_risk_is_rejected_even_with_green_evidence():
    _, _, authority, engine, _, _, record = setup_demo()
    critical = replace(
        record,
        residual=replace(
            record.residual, likelihood=lab.Likelihood.ALMOST_CERTAIN,
            impact=lab.Impact.SEVERE,
        ),
    )
    proposal = engine.propose_decision(
        critical, valid_evidence(authority, critical), (), NOW + 1, "DEC-CRIT"
    )
    assert proposal.residual_band is lab.RiskBand.CRITICAL
    assert proposal.recommendation is lab.Decision.REJECT


def test_missing_control_evidence_produces_rejection_not_fake_success():
    _, _, authority, engine, _, _, record = setup_demo()
    proposal = engine.propose_decision(
        record, valid_evidence(authority, record)[:1], (), NOW + 1, "DEC-MISSING"
    )
    assert proposal.recommendation is lab.Decision.REJECT
    assert proposal.blockers


def test_exception_is_exact_bounded_compensated_and_ciso_approved():
    _, _, authority, engine, approvals, registry, record = setup_demo()
    record = replace(
        record,
        residual=replace(
            record.residual,
            evidence_ids=("EV-AUTHZ-TEST", "EV-AUTHZ-TELEMETRY"),
        ),
    )
    evidence = valid_evidence(authority, record)
    request = lab.ExceptionRequest(
        "EX-1", record.risk_id, record.system_id, record.tenant_scope,
        "CTRL-RECOVERY", record.owner_id, "recovery drill rescheduled after platform upgrade",
        ("CTRL-AUTHZ",), ("EV-AUTHZ-TEST",), "monitor authorization evidence",
        "complete the drill and remove the exception", record.owner_id,
        NOW, NOW + 5 * 86_400,
        NOW + 2 * 86_400, record.system_version,
    )
    receipt = approvals.issue(
        "control_exception", request.payload(), record.owner_id,
        "approver:ciso", "ciso", NOW,
    )
    active = registry.activate_exception(
        request, receipt.receipt_id, record.owner_id, NOW + 1
    )
    proposal = engine.propose_decision(
        record, evidence[:2], (active,), NOW + 2, "DEC-CONDITIONAL"
    )
    assert proposal.recommendation is lab.Decision.CONDITIONAL
    assert proposal.exception_ids == ("EX-1",)
    assert not proposal.blockers


def test_exception_evidence_must_prove_declared_compensating_control():
    _, _, authority, engine, approvals, registry, record = setup_demo()
    record = replace(
        record,
        residual=replace(
            record.residual,
            evidence_ids=("EV-AUTHZ-TEST", "EV-AUTHZ-TELEMETRY"),
        ),
    )
    request = lab.ExceptionRequest(
        "EX-WRONG-PROOF", record.risk_id, record.system_id, record.tenant_scope,
        "CTRL-RECOVERY", record.owner_id, "temporary drill gap",
        ("CTRL-AUTHZ",), ("EV-RECOVERY-DRILL",), "monitor authorization evidence",
        "complete the drill and remove the exception", record.owner_id,
        NOW, NOW + 5 * 86_400,
        NOW + 2 * 86_400, record.system_version,
    )
    receipt = approvals.issue(
        "control_exception", request.payload(), record.owner_id,
        "approver:ciso", "ciso", NOW,
    )
    active = registry.activate_exception(
        request, receipt.receipt_id, record.owner_id, NOW + 1
    )
    proposal = engine.propose_decision(
        record, valid_evidence(authority, record)[:2], (active,), NOW + 2,
        "DEC-WRONG-COMPENSATION",
    )
    assert proposal.recommendation is lab.Decision.REJECT
    assert any("CTRL-RECOVERY" in blocker for blocker in proposal.blockers)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"tenant_scope": "beta"}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"system_version": "old"}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"control_id": "OTHER"}, "EXCEPTION_SCOPE_MISMATCH"),
        ({"justification": ""}, "EXCEPTION_INVALID"),
        ({"compensating_control_ids": ()}, "EXCEPTION_INVALID"),
        ({"evidence_ids": ()}, "EXCEPTION_INVALID"),
        ({"monitoring_plan": ""}, "EXCEPTION_INVALID"),
        ({"exit_plan": ""}, "EXCEPTION_INVALID"),
        ({"action_owner_id": "unknown"}, "EXCEPTION_INVALID"),
        ({"expires_at": NOW}, "EXCEPTION_INVALID"),
        ({"review_at": NOW}, "EXCEPTION_INVALID"),
        ({"expires_at": NOW + 15 * 86_400}, "EXCEPTION_INVALID"),
    ],
)
def test_exception_request_rejects_scope_or_lifecycle_gaps(changes, expected):
    _, _, _, _, approvals, registry, record = setup_demo()
    request = lab.ExceptionRequest(
        "EX-BAD", record.risk_id, record.system_id, record.tenant_scope,
        "CTRL-RECOVERY", record.owner_id, "temporary gap", ("CTRL-AUTHZ",),
        ("EV-AUTHZ-TEST",), "monitor authorization evidence",
        "complete the drill and remove the exception", record.owner_id,
        NOW, NOW + 5 * 86_400,
        NOW + 2 * 86_400, record.system_version,
    )
    request = replace(request, **changes)
    receipt = approvals.issue(
        "control_exception", request.payload(), record.owner_id,
        "approver:ciso", "ciso", NOW,
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.activate_exception(request, receipt.receipt_id, record.owner_id, NOW + 1)
    assert code(exc) == expected


def test_exception_is_not_general_risk_acceptance():
    _, _, authority, engine, approvals, registry, record = setup_demo()
    critical = replace(
        record,
        residual=replace(record.residual, likelihood=lab.Likelihood.ALMOST_CERTAIN, impact=lab.Impact.SEVERE),
    )
    registry.records[record.risk_id] = critical
    request = lab.ExceptionRequest(
        "EX-CRIT", record.risk_id, record.system_id, record.tenant_scope,
        "CTRL-RECOVERY", record.owner_id, "temporary gap", ("CTRL-AUTHZ",),
        ("EV-AUTHZ-TEST",), "monitor authorization evidence",
        "complete the drill and remove the exception", record.owner_id,
        NOW, NOW + 5 * 86_400,
        NOW + 2 * 86_400, record.system_version,
    )
    receipt = approvals.issue(
        "control_exception", request.payload(), record.owner_id,
        "approver:ciso", "ciso", NOW,
    )
    active = registry.activate_exception(request, receipt.receipt_id, record.owner_id, NOW + 1)
    proposal = engine.propose_decision(
        critical, valid_evidence(authority, critical), (active,), NOW + 2, "DEC-CRIT-EX"
    )
    assert proposal.recommendation is lab.Decision.REJECT


def test_approval_requires_separation_role_expiry_and_exact_payload():
    principals, _, _, _, approvals, _, _ = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        approvals.issue("risk_decision", {"x": 1}, "approver:risk", "approver:risk", "risk-manager", NOW)
    assert code(exc) == "SEPARATION_OF_DUTIES"
    with pytest.raises(lab.GovernanceError) as exc:
        approvals.issue("risk_decision", {"x": 1}, "owner:maya", "producer:ci", "risk-manager", NOW)
    assert code(exc) == "APPROVER_NOT_AUTHORIZED"
    receipt = approvals.issue(
        "risk_decision", {"x": 1}, "owner:maya", "approver:risk", "risk-manager", NOW, 1
    )
    with pytest.raises(lab.GovernanceError) as exc:
        approvals.consume(receipt.receipt_id, "risk_decision", {"x": 1}, "owner:maya", NOW + 1, frozenset({"risk-manager"}))
    assert code(exc) == "APPROVAL_EXPIRED"
    assert principals["approver:risk"].active


def test_approval_consumption_is_atomic_under_concurrency():
    _, _, _, _, approvals, _, _ = setup_demo()
    payload = {"decision": "approve", "version": 1}
    receipt = approvals.issue(
        "risk_decision", payload, "owner:maya", "approver:risk", "risk-manager", NOW
    )

    def consume():
        try:
            approvals.consume(
                receipt.receipt_id, "risk_decision", payload, "owner:maya",
                NOW + 1, frozenset({"risk-manager"}),
            )
            return "ok"
        except lab.GovernanceError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(), range(20)))
    assert results.count("ok") == 1
    assert results.count("APPROVAL_REPLAY") == 19


def test_engine_issued_proposal_cannot_be_fabricated_or_mutated():
    _, _, _, engine, approvals, registry, record, _, proposal = propose_valid()
    mutated = replace(proposal, blockers=("ignored",))
    receipt = approvals.issue(
        "risk_decision", mutated.payload(), record.owner_id,
        "approver:risk", "risk-manager", NOW + 1,
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.apply_decision(
            mutated, receipt.receipt_id, record.owner_id, "op-fake", NOW + 2
        )
    assert code(exc) == "DECISION_PROPOSAL_UNTRUSTED"


def test_decision_requires_role_for_residual_band():
    _, _, _, _, approvals, registry, record, _, proposal = propose_valid()
    weak = approvals.issue(
        "risk_decision", proposal.payload(), record.owner_id,
        "approver:owner", "system-owner", NOW + 1,
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.apply_decision(
            proposal, weak.receipt_id, record.owner_id, "op-weak", NOW + 2
        )
    assert code(exc) == "APPROVAL_ROLE_INSUFFICIENT"


def test_decision_is_version_bound_and_idempotent_for_unknown_retry():
    _, _, _, _, approvals, registry, record, _, proposal = propose_valid()
    receipt = approvals.issue(
        "risk_decision", proposal.payload(), record.owner_id,
        "approver:risk", "risk-manager", NOW + 1,
    )
    first = registry.apply_decision(
        proposal, receipt.receipt_id, record.owner_id, "op-1", NOW + 2
    )
    second = registry.apply_decision(
        proposal, receipt.receipt_id, record.owner_id, "op-1", NOW + 3
    )
    assert first == second
    assert first.state is lab.RiskState.AUTHORIZED
    assert first.version == 2
    with pytest.raises(lab.GovernanceError) as exc:
        registry.apply_decision(
            replace(proposal, decision_id="other"), receipt.receipt_id,
            record.owner_id, "op-1", NOW + 3,
        )
    assert code(exc) == "DECISION_IDEMPOTENCY_CONFLICT"


def test_decision_expiry_is_no_later_than_evidence_or_exception():
    _, _, authority, engine, _, _, record = setup_demo()
    evidence = list(valid_evidence(authority, record))
    first = evidence[0].artifact
    evidence[0] = authority.sign(replace(first, expires_at=NOW + 100))
    proposal = engine.propose_decision(record, evidence, (), NOW + 1, "DEC-EXP")
    assert proposal.expires_at == NOW + 100


@pytest.mark.parametrize("kind", list(lab.ChangeKind))
def test_every_material_change_invalidates_prior_decision(kind):
    _, _, _, _, approvals, registry, record, _, proposal = propose_valid()
    receipt = approvals.issue(
        "risk_decision", proposal.payload(), record.owner_id,
        "approver:risk", "risk-manager", NOW + 1,
    )
    registry.apply_decision(proposal, receipt.receipt_id, record.owner_id, "op-decide", NOW + 2)
    impacted = registry.material_change(
        record.system_id, kind, record.system_version, "support-v8", NOW + 3,
        f"change-{kind.value}",
    )
    changed = registry.records[record.risk_id]
    assert impacted == (record.risk_id,)
    assert changed.state is lab.RiskState.REASSESSMENT_REQUIRED
    assert changed.decision_id is None


def test_material_change_rejects_ambiguous_version_transition():
    _, _, _, _, _, registry, record = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        registry.material_change(
            record.system_id, lab.ChangeKind.MODEL,
            record.system_version, record.system_version, NOW + 1, "change"
        )
    assert code(exc) == "CHANGE_VERSION_INVALID"


def test_portfolio_metrics_keep_counts_and_denominators_visible():
    _, _, _, _, _, registry, record = setup_demo()
    critical = replace(
        record,
        risk_id="R-CRIT",
        residual=replace(record.residual, likelihood=lab.Likelihood.ALMOST_CERTAIN, impact=lab.Impact.SEVERE),
        review_due_at=NOW,
    )
    metrics = lab.portfolio_metrics([record, critical], (), NOW)
    assert metrics["population"] == "open risk records"
    assert metrics["open_risk_count"] == 2
    assert metrics["above_tolerance_count"] == 1
    assert metrics["above_tolerance_rate"] == 0.5
    assert metrics["overdue_review_rate"] == 0.5
    assert metrics["band_counts"]["critical"] == 1


def test_audit_event_records_decision_without_hidden_reasoning_or_evidence_content():
    _, _, _, _, approvals, registry, record, _, proposal = propose_valid()
    receipt = approvals.issue(
        "risk_decision", proposal.payload(), record.owner_id,
        "approver:risk", "risk-manager", NOW + 1,
    )
    registry.apply_decision(proposal, receipt.receipt_id, record.owner_id, "op-audit", NOW + 2)
    event = registry.audit[-1]
    assert event.event_type == "risk.decision"
    assert event.operation_id == "op-audit"
    assert event.policy_version == lab.POLICY_VERSION
    assert "tenant authorization tests" not in repr(event)
