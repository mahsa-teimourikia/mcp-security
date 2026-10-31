"""Executable invariants for Course 22 recovery, revocation, and resilience."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/22-recovery-revocation-rollback-resilience/lab.py"
SPEC = importlib.util.spec_from_file_location("course_22_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def accepted_workflow():
    handoff = lab.create_handoff()
    repository = lab.RecoveryRepository()
    manager = lab.RecoveryManager(repository)
    case = manager.accept_handoff(
        handoff,
        actor_id="coordinator",
        actor_roles=frozenset({"recovery_coordinator"}),
        allowed_tenants=frozenset({"acme"}),
        now=lab.NOW + timedelta(seconds=1),
    )
    case = manager.add_model_hypothesis(
        case,
        proposed_by="assistant-model",
        text="rollback may be fastest",
        evidence_ids=(handoff.evidence_package_digest,),
    )
    return SimpleNamespace(
        handoff=handoff,
        repository=repository,
        manager=manager,
        case=case,
    )


def revoked_workflow():
    current = accepted_workflow()
    authority = lab.AuthorityPlane(epoch=current.handoff.control_revision)
    plan = lab.make_revocation_plan(
        current.handoff,
        current_epoch=authority.epoch,
        now=lab.NOW + timedelta(seconds=2),
    )
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW + timedelta(seconds=2),
    )
    coordinator = lab.RevocationCoordinator(authority)
    result = coordinator.execute(
        "revocation-operation",
        plan,
        receipt,
        current.case,
        now=lab.NOW + timedelta(seconds=3),
    )
    proof = lab.prove_revocation(
        plan,
        coordinator.authority,
        current.handoff,
        (),
        proof_time=lab.NOW + timedelta(seconds=3),
    )
    case = current.manager.mark_revocation_proven(
        current.case,
        proof,
        now=lab.NOW + timedelta(seconds=3),
        actor_roles=frozenset({"recovery_coordinator"}),
    )
    current.__dict__.update(
        authority=authority,
        revocation_plan=plan,
        revocation_receipt=receipt,
        coordinator=coordinator,
        revocation_result=result,
        revocation_proof=proof,
        case=case,
    )
    return current


def staged_workflow():
    current = revoked_workflow()
    candidate = lab.build_candidate(now=lab.NOW)
    verifier = lab.CandidateVerifier()
    decision = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"vulnerable-previous"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    plan = lab.make_recovery_plan(
        current.case,
        candidate,
        decision,
        verifier,
        current.revocation_proof,
        current_schema_version="customer-schema-v4",
        now=lab.NOW + timedelta(seconds=4),
    )
    receipt = lab.approve_recovery(
        plan,
        approver_id="commander",
        approver_role="recovery_commander",
        now=lab.NOW + timedelta(seconds=4),
    )
    executor = lab.RecoveryExecutor()
    result = executor.stage(
        "stage-operation",
        plan,
        receipt,
        candidate,
        current.case,
        now=lab.NOW + timedelta(seconds=5),
    )
    case = current.manager.mark_staged(current.case, plan, result)
    current.__dict__.update(
        candidate=candidate,
        verifier=verifier,
        strategy=decision,
        recovery_plan=plan,
        recovery_receipt=receipt,
        executor=executor,
        stage_result=result,
        case=case,
    )
    return current


def validated_workflow():
    current = staged_workflow()
    observations = lab.build_valid_observations(current.recovery_plan)
    evidence = lab.validate_recovery(
        current.recovery_plan,
        current.executor.deployment,
        observations,
        now=lab.NOW + timedelta(seconds=6),
    )
    case = current.manager.mark_validated(current.case, evidence)
    current.__dict__.update(
        observations=observations,
        evidence=evidence,
        case=case,
    )
    return current


def returned_workflow():
    current = validated_workflow()
    receipt = lab.approve_return_to_service(
        current.recovery_plan,
        current.evidence,
        approver_id="owner",
        approver_role="service_owner",
        now=lab.NOW + timedelta(seconds=7),
    )
    result = current.executor.promote(
        "return-operation",
        current.recovery_plan,
        receipt,
        current.evidence,
        current.case,
        now=lab.NOW + timedelta(seconds=8),
    )
    proof = lab.prove_safe_service(
        current.recovery_plan,
        current.executor.deployment,
        current.evidence,
        (),
        returned_at=result.occurred_at,
    )
    case = current.manager.mark_returned(
        current.case,
        proof,
        result,
        now=result.occurred_at,
    )
    current.__dict__.update(
        return_receipt=receipt,
        return_result=result,
        safe_proof=proof,
        case=case,
    )
    return current


def resign_receipt(receipt, key, **changes):
    unsigned = replace(receipt, **changes, signature="")
    signature = lab.hmac.new(
        key, lab.canonical_json(unsigned.unsigned()), lab.sha256
    ).hexdigest()
    return replace(unsigned, signature=signature)


def resign_handoff(handoff, **changes):
    unsigned = replace(handoff, **changes, signature="")
    signature = lab.hmac.new(
        lab.HANDOFF_KEY,
        lab.canonical_json(unsigned.unsigned()),
        lab.sha256,
    ).hexdigest()
    return replace(unsigned, signature=signature)


def resign_evidence(evidence, **changes):
    unsigned = replace(evidence, **changes, evidence_digest="", signature="")
    evidence_digest = lab.digest(unsigned.unsigned())
    signature = lab.hmac.new(
        lab.EVIDENCE_KEY,
        evidence_digest.encode(),
        lab.sha256,
    ).hexdigest()
    return replace(
        unsigned,
        evidence_digest=evidence_digest,
        signature=signature,
    )


def test_demo_runs_complete_containment_handoff_to_safe_service():
    result = lab.run_demo()
    assert result["protocol_version"] == "2026-07-28"
    assert result["case"].state == lab.RecoveryState.RETURNED_TO_SERVICE
    assert result["case"].hypotheses[0].accepted_as_fact is False
    assert result["partial_revocation"].status == lab.OperationStatus.PARTIAL
    assert result["revocation_result"].status == lab.OperationStatus.RECONCILED
    assert result["revocation_proof"].complete is True
    assert result["candidate_verified"] is True
    assert result["strategy"].strategy == lab.RecoveryStrategy.FORWARD_FIX
    assert result["first_stage"].status == lab.OperationStatus.UNKNOWN
    assert result["staged"].status == lab.OperationStatus.RECONCILED
    assert result["evidence"].complete is True
    assert result["first_return"].status == lab.OperationStatus.UNKNOWN
    assert result["returned"].status == lab.OperationStatus.RECONCILED
    assert result["safe_service_proof"].complete is True


def test_demo_uses_real_ed25519_and_opentelemetry_without_network_export():
    result = lab.run_demo()
    verified, reasons = lab.CandidateVerifier().verify(
        result["candidate"],
        required_remediation_ids=result["case"].required_remediation_ids,
        current_schema_version="customer-schema-v4",
        now=lab.NOW,
    )
    assert verified and reasons == ()
    assert result["otel"]["span_name"] == "incident.recovery"
    assert (
        result["otel"]["attributes"]["recovery.candidate.digest"]
        == result["candidate"].artifact_digest
    )


def test_handoff_signature_and_required_fields_verify():
    handoff = lab.create_handoff()
    assert lab.verify_handoff(handoff, now=lab.NOW)
    assert handoff.evidence_package_digest.startswith("sha256:")
    assert handoff.control_revision > 0


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": "beta"},
        {"control_revision": 0},
        {"evidence_package_digest": "bad"},
        {"contained_at": lab.NOW + timedelta(minutes=1)},
        {"containment_cut": lab.NOW + timedelta(seconds=1)},
    ],
)
def test_handoff_tamper_or_invalid_state_fails_closed(change):
    handoff = replace(lab.create_handoff(), **change)
    assert lab.verify_handoff(handoff, now=lab.NOW) is False


def test_accept_handoff_requires_role_tenant_and_authorized_actions():
    handoff = lab.create_handoff()
    manager = lab.RecoveryManager(lab.RecoveryRepository())
    with pytest.raises(PermissionError, match="coordinator"):
        manager.accept_handoff(
            handoff,
            actor_id="user",
            actor_roles=frozenset(),
            allowed_tenants=frozenset({"acme"}),
            now=lab.NOW,
        )
    with pytest.raises(PermissionError, match="tenant"):
        manager.accept_handoff(
            handoff,
            actor_id="coordinator",
            actor_roles=frozenset({"recovery_coordinator"}),
            allowed_tenants=frozenset({"beta"}),
            now=lab.NOW,
        )
    narrowed = resign_handoff(
        handoff,
        authorized_recovery_actions=("revoke_authority",),
    )
    with pytest.raises(PermissionError, match="authorize"):
        manager.accept_handoff(
            narrowed,
            actor_id="coordinator",
            actor_roles=frozenset({"recovery_coordinator"}),
            allowed_tenants=frozenset({"acme"}),
            now=lab.NOW,
        )


def test_model_hypothesis_never_becomes_fact_and_requires_evidence():
    current = accepted_workflow()
    assert current.case.hypotheses[-1].accepted_as_fact is False
    with pytest.raises(ValueError, match="cite"):
        current.manager.add_model_hypothesis(
            current.case,
            proposed_by="model",
            text="guess",
            evidence_ids=(),
        )


def test_repository_optimistic_lock_rejects_stale_case_write():
    current = accepted_workflow()
    with pytest.raises(lab.VersionConflict):
        current.repository.save(
            replace(current.case, version=current.case.version + 1),
            expected_version=current.case.version - 1,
        )


@pytest.mark.parametrize(
    "mutator,reason",
    [
        (lambda c: replace(c, artifact_bytes=b"tampered"), "ARTIFACT_DIGEST_MISMATCH"),
        (lambda c: replace(c, immutable_reference="registry.example.com/support:latest"), "MUTABLE_REFERENCE"),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, subject_digest=lab.digest(b"other")),
            ),
            "PROVENANCE_SUBJECT_MISMATCH",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, builder_id="https://evil.example/builder"),
            ),
            "BUILDER_UNTRUSTED",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, source_repository="https://evil.example/repo"),
            ),
            "SOURCE_UNTRUSTED",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, build_type="unexpected"),
            ),
            "BUILD_TYPE_UNEXPECTED",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, source_commit="short"),
            ),
            "SOURCE_COMMIT_INVALID",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(
                    c.provenance,
                    external_parameters_digest=lab.digest(b"unreviewed-inputs"),
                ),
            ),
            "EXTERNAL_PARAMETERS_UNEXPECTED",
        ),
        (
            lambda c: replace(
                c,
                provenance=replace(c.provenance, signature="00" * 64),
            ),
            "PROVENANCE_SIGNATURE_INVALID",
        ),
        (lambda c: replace(c, sbom_digest="missing"), "SBOM_INVALID"),
        (lambda c: replace(c, critical_vulnerabilities=1), "VULNERABILITY_GATE_FAILED"),
        (lambda c: replace(c, high_vulnerabilities=1), "VULNERABILITY_GATE_FAILED"),
        (
            lambda c: replace(c, security_regressions_passed=False),
            "SECURITY_REGRESSION_FAILED",
        ),
        (
            lambda c: replace(c, remediation_ids=("IR-7-root-cause",)),
            "ROOT_CAUSE_NOT_REMEDIATED",
        ),
        (
            lambda c: replace(c, compatible_schema_versions=("schema-old",)),
            "SCHEMA_INCOMPATIBLE",
        ),
        (
            lambda c: replace(c, created_at=lab.NOW + timedelta(minutes=1)),
            "CANDIDATE_FROM_FUTURE",
        ),
    ],
)
def test_candidate_verification_fails_closed(mutator, reason):
    candidate = mutator(lab.build_candidate())
    verified, reasons = lab.CandidateVerifier().verify(
        candidate,
        required_remediation_ids=("IR-7-root-cause", "IR-7-regression"),
        current_schema_version="customer-schema-v4",
        now=lab.NOW,
    )
    assert verified is False
    assert reason in reasons


def test_strategy_distinguishes_rollback_forward_fix_and_rebuild():
    candidate = lab.build_candidate()
    rollback = lab.select_strategy(
        candidate,
        previous_digest=candidate.artifact_digest,
        previous_is_vulnerable=False,
        rebuild_required=False,
    )
    forward = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"old"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    rebuild = lab.select_strategy(
        candidate,
        previous_digest=candidate.artifact_digest,
        previous_is_vulnerable=False,
        rebuild_required=True,
    )
    assert rollback.strategy == lab.RecoveryStrategy.ROLLBACK
    assert forward.strategy == lab.RecoveryStrategy.FORWARD_FIX
    assert rebuild.strategy == lab.RecoveryStrategy.REBUILD


def test_revocation_plan_covers_every_known_authority_path():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(
        current.handoff,
        current_epoch=41,
        now=lab.NOW,
    )
    assert lab.verify_revocation_plan(plan)
    assert {item.kind for item in plan.actions} == set(lab.RevocationKind)
    assert plan.required_epoch == 42
    assert set(plan.required_control_points) == {
        "registry",
        "host-cache",
        "gateway",
        "credential-issuer",
        "task-queue",
        "network",
    }


def test_revocation_plan_and_approval_detect_mutation_and_bad_role():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    assert not lab.verify_revocation_plan(
        replace(plan, required_epoch=plan.required_epoch + 1)
    )
    with pytest.raises(PermissionError, match="role"):
        lab.approve_revocation(
            plan,
            approver_id="user",
            approver_role="analyst",
            now=lab.NOW,
        )
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    assert lab.verify_approval(
        receipt,
        key=lab.REVOCATION_APPROVAL_KEY,
        allowed_roles=lab.APPROVER_ROLES,
    )
    assert not lab.verify_approval(
        replace(receipt, proposal_digest="changed"),
        key=lab.REVOCATION_APPROVAL_KEY,
        allowed_roles=lab.APPROVER_ROLES,
    )


def test_partial_revocation_reports_unavailable_control_then_converges():
    current = accepted_workflow()
    authority = lab.AuthorityPlane(epoch=41)
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    coordinator = lab.RevocationCoordinator(authority)
    partial = coordinator.execute(
        "operation",
        plan,
        receipt,
        current.case,
        now=lab.NOW,
        unavailable_kinds=frozenset({lab.RevocationKind.INVALIDATE_CACHE}),
    )
    assert partial.status == lab.OperationStatus.PARTIAL
    assert dict(coordinator.authority.observed_epochs).get("host-cache", 0) < 42
    complete = coordinator.retry_missing(
        "operation", now=lab.NOW + timedelta(seconds=1)
    )
    assert complete.status == lab.OperationStatus.RECONCILED
    assert len(complete.effect_ids) == len(plan.actions)


def test_lost_revocation_response_reconciles_across_restart_without_reapply():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    first = lab.RevocationCoordinator(lab.AuthorityPlane(epoch=41))
    unknown = first.execute(
        "operation",
        plan,
        receipt,
        current.case,
        now=lab.NOW,
        simulate_lost_response=True,
    )
    restarted = lab.RevocationCoordinator(first.authority, first.journal)
    reconciled = restarted.execute(
        "operation",
        plan,
        receipt,
        current.case,
        now=lab.NOW + timedelta(seconds=1),
    )
    assert unknown.status == lab.OperationStatus.UNKNOWN
    assert reconciled.status == lab.OperationStatus.RECONCILED
    assert restarted.authority.epoch == 42


def test_revocation_rejects_operation_conflict_receipt_replay_and_expiry():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    coordinator = lab.RevocationCoordinator(lab.AuthorityPlane(epoch=41))
    coordinator.execute("operation", plan, receipt, current.case, now=lab.NOW)
    changed_receipt = lab.approve_revocation(
        plan,
        approver_id="other",
        approver_role="recovery_commander",
        now=lab.NOW,
    )
    with pytest.raises(ValueError, match="different"):
        coordinator.execute(
            "operation",
            plan,
            changed_receipt,
            current.case,
            now=lab.NOW,
        )
    with pytest.raises(ValueError, match="consumed"):
        coordinator.execute(
            "another-operation",
            plan,
            receipt,
            current.case,
            now=lab.NOW,
        )
    expired = replace(plan, expires_at=lab.NOW - timedelta(seconds=1))
    with pytest.raises(ValueError, match="invalid"):
        lab.RevocationCoordinator(lab.AuthorityPlane(epoch=41)).execute(
            "expired",
            expired,
            receipt,
            current.case,
            now=lab.NOW,
        )


def test_revocation_rejects_cross_tenant_action_even_with_valid_plan_digest():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    actions = (replace(plan.actions[0], tenant_id="beta"),) + plan.actions[1:]
    unsigned = {
        "incident_id": plan.incident_id,
        "tenant_id": plan.tenant_id,
        "required_epoch": plan.required_epoch,
        "actions": actions,
        "required_control_points": plan.required_control_points,
        "policy_version": plan.policy_version,
        "created_at": plan.created_at,
        "expires_at": plan.expires_at,
    }
    plan = replace(plan, actions=actions, plan_digest=lab.digest(unsigned))
    receipt = lab.approve_revocation(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    with pytest.raises(PermissionError, match="cross-tenant"):
        lab.RevocationCoordinator(lab.AuthorityPlane(epoch=41)).execute(
            "operation",
            plan,
            receipt,
            current.case,
            now=lab.NOW,
        )


def test_revocation_proof_requires_actions_epochs_and_no_late_effects():
    current = revoked_workflow()
    assert current.revocation_proof.complete
    incomplete = lab.prove_revocation(
        current.revocation_plan,
        replace(current.coordinator.authority, invalidated_hosts=frozenset()),
        current.handoff,
        (),
        proof_time=lab.NOW + timedelta(seconds=3),
    )
    assert not incomplete.complete
    late = lab.EffectEvent(
        "event-late",
        "acme",
        lab.NOW + timedelta(seconds=5),
        current.handoff.affected_workloads[0],
        current.handoff.affected_credentials[0],
        current.handoff.affected_sessions[0],
        current.handoff.affected_tasks[0],
        current.handoff.affected_destinations[0],
        lab.EffectOutcome.COMPLETED,
        "protected.resource.audit",
    )
    failed = lab.prove_revocation(
        current.revocation_plan,
        current.coordinator.authority,
        current.handoff,
        (late,),
        proof_time=lab.NOW + timedelta(seconds=6),
    )
    assert not failed.complete
    assert failed.post_cut_forbidden_effect_count == 1


def test_case_cannot_mark_revocation_with_wrong_incident_or_role():
    current = accepted_workflow()
    plan = lab.make_revocation_plan(current.handoff, current_epoch=41, now=lab.NOW)
    authority = lab.AuthorityPlane(epoch=41).apply(plan)
    proof = lab.prove_revocation(
        plan, authority, current.handoff, (), proof_time=lab.NOW
    )
    with pytest.raises(PermissionError, match="coordinator"):
        current.manager.mark_revocation_proven(
            current.case, proof, now=lab.NOW, actor_roles=frozenset()
        )
    with pytest.raises(ValueError, match="required"):
        current.manager.mark_revocation_proven(
            current.case,
            replace(proof, incident_id="other"),
            now=lab.NOW,
            actor_roles=frozenset({"recovery_coordinator"}),
        )


def test_recovery_plan_requires_proven_revocation_and_verified_candidate():
    accepted = accepted_workflow()
    candidate = lab.build_candidate()
    verifier = lab.CandidateVerifier()
    decision = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"old"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    dummy = lab.RevocationProof(
        accepted.case.incident_id,
        "plan",
        1,
        1,
        1,
        1,
        0,
        0,
        True,
    )
    with pytest.raises(ValueError, match="revocation"):
        lab.make_recovery_plan(
            accepted.case,
            candidate,
            decision,
            verifier,
            dummy,
            current_schema_version="customer-schema-v4",
            now=lab.NOW,
        )
    revoked = revoked_workflow()
    bad = replace(candidate, high_vulnerabilities=1)
    with pytest.raises(ValueError, match="verification"):
        lab.make_recovery_plan(
            revoked.case,
            bad,
            decision,
            verifier,
            revoked.revocation_proof,
            current_schema_version="customer-schema-v4",
            now=lab.NOW,
        )
    with pytest.raises(ValueError, match="accepted plan"):
        lab.make_recovery_plan(
            revoked.case,
            candidate,
            decision,
            verifier,
            replace(revoked.revocation_proof, plan_digest=lab.digest(b"other-plan")),
            current_schema_version="customer-schema-v4",
            now=lab.NOW,
        )


def test_recovery_plan_and_approval_bind_exact_candidate_and_policy():
    current = revoked_workflow()
    candidate = lab.build_candidate()
    decision = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"old"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    plan = lab.make_recovery_plan(
        current.case,
        candidate,
        decision,
        lab.CandidateVerifier(),
        current.revocation_proof,
        current_schema_version="customer-schema-v4",
        now=lab.NOW,
    )
    assert lab.verify_recovery_plan(plan)
    assert not lab.verify_recovery_plan(replace(plan, candidate_digest=lab.digest(b"other")))
    with pytest.raises(PermissionError, match="role"):
        lab.approve_recovery(
            plan,
            approver_id="user",
            approver_role="analyst",
            now=lab.NOW,
        )


def test_stage_unknown_outcome_reconciles_across_restart_once():
    current = revoked_workflow()
    candidate = lab.build_candidate()
    decision = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"old"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    plan = lab.make_recovery_plan(
        current.case,
        candidate,
        decision,
        lab.CandidateVerifier(),
        current.revocation_proof,
        current_schema_version="customer-schema-v4",
        now=lab.NOW,
    )
    receipt = lab.approve_recovery(
        plan,
        approver_id="commander",
        approver_role="recovery_commander",
        now=lab.NOW,
    )
    first = lab.RecoveryExecutor()
    unknown = first.stage(
        "operation",
        plan,
        receipt,
        candidate,
        current.case,
        now=lab.NOW,
        simulate_lost_response=True,
    )
    restarted = lab.RecoveryExecutor(first.deployment, first.journal)
    reconciled = restarted.stage(
        "operation",
        plan,
        receipt,
        candidate,
        current.case,
        now=lab.NOW + timedelta(seconds=1),
    )
    assert unknown.status == lab.OperationStatus.UNKNOWN
    assert reconciled.status == lab.OperationStatus.RECONCILED
    assert restarted.deployment.revision == 1


def test_stage_rejects_candidate_mutation_receipt_policy_and_replay():
    current = revoked_workflow()
    candidate = lab.build_candidate()
    decision = lab.select_strategy(
        candidate,
        previous_digest=lab.digest(b"old"),
        previous_is_vulnerable=True,
        rebuild_required=False,
    )
    plan = lab.make_recovery_plan(
        current.case,
        candidate,
        decision,
        lab.CandidateVerifier(),
        current.revocation_proof,
        current_schema_version="customer-schema-v4",
        now=lab.NOW,
    )
    receipt = lab.approve_recovery(
        plan,
        approver_id="commander",
        approver_role="recovery_commander",
        now=lab.NOW,
    )
    executor = lab.RecoveryExecutor()
    with pytest.raises(ValueError, match="integrity"):
        executor.stage(
            "bad-candidate",
            plan,
            receipt,
            replace(candidate, artifact_bytes=b"changed"),
            current.case,
            now=lab.NOW,
        )
    wrong_policy = resign_receipt(
        receipt,
        lab.RECOVERY_APPROVAL_KEY,
        policy_version="old-policy",
    )
    with pytest.raises(PermissionError, match="receipt"):
        executor.stage(
            "bad-policy",
            plan,
            wrong_policy,
            candidate,
            current.case,
            now=lab.NOW,
        )
    executor.stage(
        "operation",
        plan,
        receipt,
        candidate,
        current.case,
        now=lab.NOW,
    )
    with pytest.raises(ValueError, match="consumed"):
        executor.stage(
            "another",
            plan,
            receipt,
            candidate,
            current.case,
            now=lab.NOW,
        )


def test_stage_operation_id_cannot_be_reused_for_different_request():
    current = staged_workflow()
    other = lab.approve_recovery(
        current.recovery_plan,
        approver_id="other",
        approver_role="incident_commander",
        now=lab.NOW,
    )
    with pytest.raises(ValueError, match="different"):
        current.executor.stage(
            "stage-operation",
            current.recovery_plan,
            other,
            current.candidate,
            replace(current.case, state=lab.RecoveryState.REVOCATION_PROVEN, version=current.recovery_plan.case_version),
            now=lab.NOW,
        )


@pytest.mark.parametrize(
    "change,check_name",
    [
        ({"workload_artifact_digest": lab.digest(b"wrong")}, "DEPLOYED_DIGEST_MATCHES"),
        ({"registry_artifact_digest": lab.digest(b"wrong")}, "REGISTRY_REMAINS_DISABLED_DURING_CANARY"),
        ({"config_digest": lab.digest(b"wrong")}, "CONFIG_POLICY_CONTRACT_MATCH"),
        ({"security_regressions_passed": 7}, "SECURITY_REGRESSIONS_PASS"),
        ({"safe_tasks_succeeded": 18}, "SAFE_TASKS_PASS"),
        ({"forbidden_effects_completed": 1}, "FORBIDDEN_EFFECTS_ABSENT"),
        ({"compromise_indicator_count": 1}, "NO_COMPROMISE_INDICATORS"),
        ({"independent_sources": ("gateway.probe",)}, "INDEPENDENT_SOURCES"),
    ],
)
def test_recovery_validation_fails_each_independent_check(change, check_name):
    current = staged_workflow()
    observations = replace(
        lab.build_valid_observations(current.recovery_plan),
        **change,
    )
    evidence = lab.validate_recovery(
        current.recovery_plan,
        current.executor.deployment,
        observations,
        now=lab.NOW,
    )
    assert evidence.complete is False
    assert dict(evidence.checks)[check_name] is False


def test_recovery_evidence_is_signed_and_tamper_evident():
    current = validated_workflow()
    assert lab.verify_recovery_evidence(current.evidence)
    assert not lab.verify_recovery_evidence(
        replace(current.evidence, safe_tasks_succeeded=0)
    )
    with pytest.raises(ValueError, match="complete"):
        lab.approve_return_to_service(
            current.recovery_plan,
            replace(current.evidence, complete=False),
            approver_id="owner",
            approver_role="service_owner",
            now=lab.NOW,
        )


def test_recovery_evidence_cannot_be_replayed_across_plans():
    staged = staged_workflow()
    evidence = lab.validate_recovery(
        staged.recovery_plan,
        staged.executor.deployment,
        lab.build_valid_observations(staged.recovery_plan),
        now=lab.NOW,
    )
    cross_plan = resign_evidence(evidence, plan_digest=lab.digest(b"other-plan"))
    assert lab.verify_recovery_evidence(cross_plan)
    with pytest.raises(ValueError, match="evidence"):
        staged.manager.mark_validated(staged.case, cross_plan)
    with pytest.raises(ValueError, match="evidence"):
        lab.approve_return_to_service(
            staged.recovery_plan,
            cross_plan,
            approver_id="owner",
            approver_role="service_owner",
            now=lab.NOW,
        )
    promoted = returned_workflow()
    assert not lab.prove_safe_service(
        promoted.recovery_plan,
        promoted.executor.deployment,
        resign_evidence(
            promoted.evidence,
            plan_digest=lab.digest(b"other-plan"),
        ),
        (),
        returned_at=promoted.return_result.occurred_at,
    ).complete


def test_return_to_service_requires_separate_authorized_role():
    current = validated_workflow()
    with pytest.raises(PermissionError, match="role"):
        lab.approve_return_to_service(
            current.recovery_plan,
            current.evidence,
            approver_id="analyst",
            approver_role="analyst",
            now=lab.NOW,
        )
    receipt = lab.approve_return_to_service(
        current.recovery_plan,
        current.evidence,
        approver_id="owner",
        approver_role="service_owner",
        now=lab.NOW,
    )
    assert receipt.purpose == "return_to_service"
    assert receipt.proposal_digest == lab.digest(
        (current.recovery_plan.plan_digest, current.evidence.evidence_digest)
    )


def test_promotion_unknown_outcome_reconciles_across_restart():
    current = validated_workflow()
    receipt = lab.approve_return_to_service(
        current.recovery_plan,
        current.evidence,
        approver_id="owner",
        approver_role="service_owner",
        now=lab.NOW,
    )
    unknown = current.executor.promote(
        "operation",
        current.recovery_plan,
        receipt,
        current.evidence,
        current.case,
        now=lab.NOW,
        simulate_lost_response=True,
    )
    restarted = lab.RecoveryExecutor(
        current.executor.deployment, current.executor.journal
    )
    reconciled = restarted.promote(
        "operation",
        current.recovery_plan,
        receipt,
        current.evidence,
        current.case,
        now=lab.NOW + timedelta(seconds=1),
    )
    assert unknown.status == lab.OperationStatus.UNKNOWN
    assert reconciled.status == lab.OperationStatus.RECONCILED
    assert restarted.deployment.revision == 2


def test_promotion_rejects_tampered_evidence_policy_and_replayed_receipt():
    current = validated_workflow()
    receipt = lab.approve_return_to_service(
        current.recovery_plan,
        current.evidence,
        approver_id="owner",
        approver_role="service_owner",
        now=lab.NOW,
    )
    with pytest.raises(ValueError, match="evidence"):
        current.executor.promote(
            "tampered",
            current.recovery_plan,
            receipt,
            replace(current.evidence, signature="bad"),
            current.case,
            now=lab.NOW,
        )
    wrong_policy = resign_receipt(
        receipt,
        lab.RETURN_APPROVAL_KEY,
        policy_version="old-policy",
    )
    with pytest.raises(PermissionError, match="receipt"):
        current.executor.promote(
            "wrong-policy",
            current.recovery_plan,
            wrong_policy,
            current.evidence,
            current.case,
            now=lab.NOW,
        )
    current.executor.promote(
        "operation",
        current.recovery_plan,
        receipt,
        current.evidence,
        current.case,
        now=lab.NOW,
    )
    with pytest.raises(ValueError, match="consumed"):
        current.executor.promote(
            "another",
            current.recovery_plan,
            receipt,
            current.evidence,
            current.case,
            now=lab.NOW,
        )


def test_safe_service_proof_requires_exact_state_evidence_and_no_late_effect():
    current = returned_workflow()
    assert current.safe_proof.complete
    wrong_state = replace(
        current.executor.deployment,
        public_registry_enabled=False,
    )
    assert not lab.prove_safe_service(
        current.recovery_plan,
        wrong_state,
        current.evidence,
        (),
        returned_at=current.return_result.occurred_at,
    ).complete
    late = lab.EffectEvent(
        "event-reentry",
        "acme",
        current.return_result.occurred_at + timedelta(seconds=1),
        "spiffe://acme/mcp/support-v3",
        "credential-support-v3",
        "session-recovered",
        "task-recovered",
        "exfil.example",
        lab.EffectOutcome.COMPLETED,
        "protected.resource.audit",
    )
    failed = lab.prove_safe_service(
        current.recovery_plan,
        current.executor.deployment,
        current.evidence,
        (late,),
        returned_at=current.return_result.occurred_at,
    )
    assert not failed.complete
    assert failed.post_recovery_forbidden_effect_count == 1


def test_case_return_binding_and_reopen_are_application_owned():
    current = validated_workflow()
    receipt = lab.approve_return_to_service(
        current.recovery_plan,
        current.evidence,
        approver_id="owner",
        approver_role="service_owner",
        now=lab.NOW,
    )
    result = current.executor.promote(
        "operation",
        current.recovery_plan,
        receipt,
        current.evidence,
        current.case,
        now=lab.NOW,
    )
    proof = lab.prove_safe_service(
        current.recovery_plan,
        current.executor.deployment,
        current.evidence,
        (),
        returned_at=result.occurred_at,
    )
    with pytest.raises(ValueError, match="proof"):
        current.manager.mark_returned(
            current.case,
            replace(proof, deployment_revision=0),
            result,
            now=lab.NOW,
        )
    with pytest.raises(ValueError, match="proof"):
        current.manager.mark_returned(
            current.case,
            replace(proof, plan_digest=lab.digest(b"other-plan")),
            result,
            now=lab.NOW,
        )
    returned = current.manager.mark_returned(
        current.case, proof, result, now=lab.NOW
    )
    with pytest.raises(PermissionError, match="responder"):
        current.manager.reopen(
            returned,
            reason="new indicator",
            actor_roles=frozenset(),
        )
    reopened = current.manager.reopen(
        returned,
        reason="new post-recovery compromise indicator",
        actor_roles=frozenset({"incident_responder"}),
    )
    assert reopened.state == lab.RecoveryState.REOPENED
    assert "indicator" in reopened.reopen_reason


def test_metrics_use_explicit_nonzero_denominators_and_objectives():
    result = lab.run_demo()
    metrics = result["metrics"]
    assert metrics.time_to_revoke_seconds == 3.0
    assert metrics.time_to_safe_service_seconds == 11.0
    assert metrics.residual_authority_rate == 0.0
    assert metrics.security_regression_pass_rate == 1.0
    assert metrics.safe_task_success_rate == 1.0
    assert metrics.forbidden_effect_rate == 0.0
    assert metrics.rto_met is True
    with pytest.raises(ValueError, match="denominators"):
        lab.calculate_metrics(
            result["case"],
            result["revocation_proof"],
            replace(result["evidence"], safe_tasks_total=0),
            contained_at=result["handoff"].contained_at,
            returned_at=result["returned"].occurred_at,
            objectives=result["recovery_plan"].objectives,
        )
