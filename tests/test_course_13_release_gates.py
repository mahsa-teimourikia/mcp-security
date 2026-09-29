"""Executable invariants for Course 13 secure CI/CD release gates."""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/13-secure-mcp-cicd-release-gates/lab.py"
SPEC = importlib.util.spec_from_file_location("course_13_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


@pytest.fixture
def env():
    return lab.build_demo_environment()


def assert_code(call, code):
    with pytest.raises(lab.PipelineDenied) as denied:
        call()
    assert denied.value.code == code


def mutate_contract(env, mutator):
    data = env.contract.model_dump(mode="json")
    mutator(data)
    return lab.WorkflowContract.model_validate(data)


def mutate_evidence(env, attribute, mutator):
    signed = getattr(env, attribute)
    data = signed.document.model_dump(mode="json")
    mutator(data)
    mapping = {
        "source": (lab.ProtectedRevisionEvidence, "source", lab.SOURCE_SIGNER),
        "build": (lab.BuildEvidence, "builder", lab.BUILDER_SIGNER),
        "tests": (lab.TestEvidence, "tests", lab.TEST_SIGNER),
        "security": (lab.SupplyChainDecision, "security", lab.SECURITY_SIGNER),
        "rollback": (lab.RollbackRehearsalEvidence, "recovery", lab.RECOVERY_SIGNER),
    }
    model, role, signer = mapping[attribute]
    document = model.model_validate(data)
    return lab.sign_evidence(document, role, signer, env.keys[signer])


def advance_to_built(env):
    record = env.controller.start(env.source, env.now)
    return env.controller.record_build(record.version, lab.ARTIFACT_BYTES, env.build, env.now)


def advance_to_tested(env):
    record = advance_to_built(env)
    return env.controller.record_tests(record.version, env.tests, env.now)


def advance_to_approved(env):
    record = lab.advance_to_verified(env)
    return env.controller.approve(record.version, "approver@example.com", env.now)


def deploy_success(env):
    record, receipt = advance_to_approved(env)
    return env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.SUCCESS, env.now
    )


def test_demo_reconciles_unknown_outcome_and_rolls_back_failed_health():
    result = lab.run_demo()
    assert result == {
        "unknown_outcome": "deployment_unknown",
        "reconciled_release": "succeeded",
        "failed_health": "rolled_back",
        "restored_digest": lab.KNOWN_GOOD_DIGEST,
    }


def test_reviewed_workflow_contract_has_stable_digest(env):
    digest = lab.WorkflowAuditor(env.policy).verify_contract(env.contract)
    assert digest == lab.digest_bytes(lab.canonical_json(env.contract))


def test_workflow_identity_must_be_owned_by_trusted_policy(env):
    contract = mutate_contract(
        env, lambda data: data.update({"workflow_sha": "f" * 40})
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "WORKFLOW_NOT_REVIEWED",
    )


def test_action_tag_is_not_an_immutable_pin(env):
    contract = mutate_contract(
        env, lambda data: data["jobs"][0]["steps"][0].update({"uses": "actions/checkout@v6"})
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "ACTION_NOT_IMMUTABLE",
    )


def test_unapproved_full_action_pin_is_rejected(env):
    contract = mutate_contract(
        env,
        lambda data: data["jobs"][0]["steps"][0].update(
            {"uses": f"attacker/checkout@{'9' * 40}"}
        ),
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract), "ACTION_NOT_ALLOWED"
    )


@pytest.mark.parametrize("phase", ["test", "build", "deploy"])
def test_token_permissions_must_match_job_need(env, phase):
    def mutate(data):
        job = next(item for item in data["jobs"] if item["phase"] == phase)
        job["permissions"]["issues"] = "write"

    contract = mutate_contract(env, mutate)
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "TOKEN_PERMISSIONS_INVALID",
    )


def test_release_jobs_require_ephemeral_runners(env):
    contract = mutate_contract(
        env, lambda data: data["jobs"][1].update({"ephemeral_runner": False})
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "RUNNER_NOT_EPHEMERAL",
    )


@pytest.mark.parametrize("index", [1, 2])
def test_privileged_jobs_cannot_write_shared_cache(env, index):
    contract = mutate_contract(env, lambda data: data["jobs"][index].update({"cache_write": True}))
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "PRIVILEGED_CACHE_WRITE",
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"trigger": "pull_request_target"},
        {"secrets": ["DEPLOY_KEY"]},
        {"requests_oidc": True},
        {"executes_checkout": False},
        {"checkout_ref": "refs/heads/main"},
    ],
)
def test_pull_request_test_job_remains_unprivileged(env, updates):
    contract = mutate_contract(env, lambda data: data["jobs"][0].update(updates))
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "TEST_JOB_PRIVILEGED",
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"trigger": "workflow_dispatch"},
        {"environment": "production"},
        {"secrets": ["REGISTRY_PASSWORD"]},
        {"requests_oidc": False},
        {"checkout_ref": "feature/attacker"},
    ],
)
def test_build_job_uses_protected_source_and_no_deploy_secret(env, updates):
    contract = mutate_contract(env, lambda data: data["jobs"][1].update(updates))
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "BUILD_JOB_BOUNDARY_INVALID",
    )


def test_deploy_job_trigger_must_be_trusted(env):
    contract = mutate_contract(
        env, lambda data: data["jobs"][2].update({"trigger": "pull_request_target"})
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "DEPLOY_TRIGGER_INVALID",
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"environment": None},
        {"secrets": ["LONG_LIVED_CLOUD_KEY"]},
        {"requests_oidc": False},
        {"executes_checkout": True, "checkout_ref": "refs/heads/main"},
    ],
)
def test_deploy_job_uses_protected_environment_oidc_and_no_checkout(env, updates):
    contract = mutate_contract(env, lambda data: data["jobs"][2].update(updates))
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "DEPLOY_ENVIRONMENT_INVALID",
    )


def test_direct_expression_in_shell_is_rejected(env):
    contract = mutate_contract(
        env,
        lambda data: data["jobs"][0]["steps"][2].update(
            {"run": 'echo "${{ github.event.pull_request.title }}"'}
        ),
    )
    assert_code(
        lambda: lab.WorkflowAuditor(env.policy).verify_contract(contract),
        "SCRIPT_INJECTION_SURFACE",
    )


def test_untrusted_context_may_enter_non_interpreted_env_field(env):
    assert env.contract.jobs[0].steps[2].env["PR_TITLE"].startswith("${{")
    assert lab.WorkflowAuditor(env.policy).verify_contract(env.contract).startswith("sha256:")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("repository_id", "repo-attacker", "REPOSITORY_IDENTITY_MISMATCH"),
        ("owner_id", "org-attacker", "REPOSITORY_IDENTITY_MISMATCH"),
        ("ref", "refs/heads/feature", "UNPROTECTED_REF"),
        ("workflow_sha", "f" * 40, "WORKFLOW_IDENTITY_MISMATCH"),
    ],
)
def test_runtime_workflow_identity_is_exact(env, field, value, code):
    context = env.context.model_copy(update={field: value})
    assert_code(lambda: env.controller.auditor.verify_run(context, env.contract), code)


def test_fork_source_cannot_enter_release_run(env):
    context = env.context.model_copy(
        update={"source_repository": "attacker/support-mcp", "source_repository_id": "repo-x"}
    )
    assert_code(
        lambda: env.controller.auditor.verify_run(context, env.contract),
        "UNTRUSTED_SOURCE_REPOSITORY",
    )


def test_unapproved_manual_actor_is_rejected(env):
    context = env.context.model_copy(update={"event": "workflow_dispatch", "actor": "intern"})
    assert_code(
        lambda: env.controller.auditor.verify_run(context, env.contract),
        "MANUAL_ACTOR_NOT_ALLOWED",
    )


def test_approved_manual_actor_is_accepted(env):
    context = env.context.model_copy(
        update={"event": "workflow_dispatch", "actor": "release-manager@example.com"}
    )
    env.controller.auditor.verify_run(context, env.contract)


def test_source_admission_starts_durable_state_machine(env):
    record = env.controller.start(env.source, env.now)
    assert record.state == lab.RunState.SOURCE_ADMITTED
    assert record.version == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_id", "repo-other"),
        ("source_sha", "f" * 40),
        ("review_count", 1),
        ("checks", ["unit"]),
        ("branch_protected", False),
    ],
)
def test_source_admission_requires_protected_reviewed_revision(env, field, value):
    source = mutate_evidence(env, "source", lambda data: data.update({field: value}))
    assert_code(lambda: env.controller.start(source, env.now), "SOURCE_ADMISSION_FAILED")


def test_source_schema_rejects_non_protected_ref(env):
    data = env.source.document.model_dump(mode="json")
    data["ref"] = "refs/heads/dev"
    with pytest.raises(ValidationError):
        lab.ProtectedRevisionEvidence.model_validate(data)


def test_stale_source_admission_is_rejected(env):
    source = mutate_evidence(
        env, "source", lambda data: data.update({"admitted_at": "2026-09-20T03:00:00Z"})
    )
    assert_code(lambda: env.controller.start(source, env.now), "SOURCE_EVIDENCE_STALE")


def test_evidence_payload_cannot_change_after_signature(env):
    changed = env.source.document.model_copy(update={"review_count": 9})
    signed = lab.SignedEvidence(changed, env.source.signature)
    assert_code(lambda: env.controller.start(signed, env.now), "EVIDENCE_DIGEST_MISMATCH")


def test_evidence_signature_is_cryptographically_verified(env):
    signature = env.source.signature.model_copy(
        update={"signature": base64.b64encode(b"x" * 64).decode()}
    )
    signed = lab.SignedEvidence(env.source.document, signature)
    assert_code(lambda: env.controller.start(signed, env.now), "EVIDENCE_SIGNATURE_INVALID")


def test_evidence_role_and_signer_are_allowlisted(env):
    signature = env.source.signature.model_copy(update={"signer": "attacker"})
    signed = lab.SignedEvidence(env.source.document, signature)
    assert_code(lambda: env.controller.start(signed, env.now), "EVIDENCE_SIGNER_NOT_TRUSTED")


def test_revoked_evidence_signer_is_rejected(env):
    env.controller.trust.revoke("source", lab.SOURCE_SIGNER)
    assert_code(lambda: env.controller.start(env.source, env.now), "EVIDENCE_SIGNER_REVOKED")


def test_duplicate_run_is_rejected(env):
    env.controller.start(env.source, env.now)
    assert_code(lambda: env.controller.start(env.source, env.now), "RUN_ALREADY_EXISTS")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda data: data.update({"run_id": "other-run"}), "BUILD_EVIDENCE_MISMATCH"),
        (lambda data: data.update({"source_sha": "f" * 40}), "BUILD_EVIDENCE_MISMATCH"),
        (lambda data: data.update({"builder_id": "self-hosted/untrusted"}), "BUILD_EVIDENCE_MISMATCH"),
        (lambda data: data.update({"built_at": "2026-09-20T03:00:00Z"}), "BUILD_EVIDENCE_STALE"),
    ],
)
def test_build_evidence_binds_run_source_builder_and_freshness(env, mutation, code):
    record = env.controller.start(env.source, env.now)
    build = mutate_evidence(env, "build", mutation)
    assert_code(
        lambda: env.controller.record_build(record.version, lab.ARTIFACT_BYTES, build, env.now),
        code,
    )


def test_build_rehashes_actual_artifact_bytes(env):
    record = env.controller.start(env.source, env.now)
    assert_code(
        lambda: env.controller.record_build(
            record.version, lab.ARTIFACT_BYTES + b"tampered", env.build, env.now
        ),
        "BUILD_EVIDENCE_MISMATCH",
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("run_id", "other", "TEST_EVIDENCE_MISMATCH"),
        ("source_sha", "f" * 40, "TEST_EVIDENCE_MISMATCH"),
        ("artifact_digest", f"sha256:{'0' * 64}", "TEST_EVIDENCE_MISMATCH"),
        ("suite", "smoke-only", "TEST_EVIDENCE_MISMATCH"),
        ("failed", 1, "TESTS_FAILED"),
        ("passed", 0, "TESTS_FAILED"),
        ("produced_at", "2026-09-20T03:00:00Z", "TEST_EVIDENCE_STALE"),
    ],
)
def test_test_evidence_binds_subject_suite_outcome_and_freshness(env, field, value, code):
    record = advance_to_built(env)
    def mutate(data):
        data[field] = value
        if field == "passed" and value == 0:
            data["skipped"] = 1

    tests = mutate_evidence(env, "tests", mutate)
    assert_code(
        lambda: env.controller.record_tests(record.version, tests, env.now), code
    )


@pytest.mark.parametrize(
    ("attribute", "field", "value", "code"),
    [
        ("build", "run_id", "other", "EVIDENCE_RUN_MISMATCH"),
        ("security", "source_sha", "f" * 40, "EVIDENCE_SOURCE_MISMATCH"),
        ("security", "artifact_digest", f"sha256:{'0' * 64}", "EVIDENCE_ARTIFACT_MISMATCH"),
        ("security", "verification_result", "FAILED", "SECURITY_GATE_FAILED"),
        ("security", "policy_version", "old-policy", "SECURITY_GATE_FAILED"),
        ("security", "verified_at", "2026-09-20T03:00:00Z", "RELEASE_EVIDENCE_STALE"),
    ],
)
def test_release_gate_correlates_all_evidence(env, attribute, field, value, code):
    record = advance_to_tested(env)
    values = {name: getattr(env, name) for name in ("source", "build", "tests", "security", "rollback")}
    values[attribute] = mutate_evidence(
        env, attribute, lambda data: data.update({field: value})
    )
    assert_code(
        lambda: env.controller.verify_release(
            record.version,
            values["source"],
            values["build"],
            values["tests"],
            values["security"],
            values["rollback"],
            env.now,
        ),
        code,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("known_good_digest", f"sha256:{'0' * 64}"),
        ("checks", ["service-ready"]),
        ("rehearsed_at", "2026-08-01T03:00:00Z"),
    ],
)
def test_rollback_requires_exact_recent_rehearsal(env, field, value):
    record = advance_to_tested(env)
    rollback = mutate_evidence(env, "rollback", lambda data: data.update({field: value}))
    assert_code(
        lambda: env.controller.verify_release(
            record.version,
            env.source,
            env.build,
            env.tests,
            env.security,
            rollback,
            env.now,
        ),
        "ROLLBACK_NOT_READY",
    )


def test_rollback_schema_rejects_non_production_environment(env):
    data = env.rollback.document.model_dump(mode="json")
    data["environment"] = "staging"
    with pytest.raises(ValidationError):
        lab.RollbackRehearsalEvidence.model_validate(data)


def test_verified_plan_binds_every_evidence_digest(env):
    record = lab.advance_to_verified(env)
    assert record.state == lab.RunState.VERIFIED
    assert record.plan is not None
    assert record.plan.artifact_digest == lab.ARTIFACT_DIGEST
    assert record.plan.previous_digest == lab.KNOWN_GOOD_DIGEST
    assert record.plan.workflow_contract_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("attribute", "field", "value"),
    [
        ("source", "review_count", 3),
        ("build", "artifact_name", "renamed-support-mcp.tar"),
        ("tests", "report_digest", f"sha256:{'9' * 64}"),
    ],
)
def test_release_uses_exact_evidence_admitted_at_each_stage(env, attribute, field, value):
    record = advance_to_tested(env)
    evidence = {
        name: getattr(env, name)
        for name in ("source", "build", "tests", "security", "rollback")
    }
    evidence[attribute] = mutate_evidence(
        env, attribute, lambda data: data.update({field: value})
    )
    assert_code(
        lambda: env.controller.verify_release(
            record.version,
            evidence["source"],
            evidence["build"],
            evidence["tests"],
            evidence["security"],
            evidence["rollback"],
            env.now,
        ),
        "EVIDENCE_CHAIN_MISMATCH",
    )


def test_cannot_approve_before_plan_exists(env):
    record = env.controller.start(env.source, env.now)
    assert_code(
        lambda: env.controller.approve(record.version, "approver@example.com", env.now),
        "PLAN_MISSING",
    )


def test_approver_must_be_eligible(env):
    record = lab.advance_to_verified(env)
    assert_code(
        lambda: env.controller.approve(record.version, "intern@example.com", env.now),
        "APPROVER_NOT_ELIGIBLE",
    )


def test_release_actor_cannot_approve_own_release(env):
    record = lab.advance_to_verified(env)
    env.controller.context = env.context.model_copy(
        update={"actor": "approver@example.com"}
    )
    assert_code(
        lambda: env.controller.approve(record.version, "approver@example.com", env.now),
        "APPROVER_NOT_ELIGIBLE",
    )


def test_approval_is_bound_to_exact_plan(env):
    record = lab.advance_to_verified(env)
    record, receipt = env.controller.approve(record.version, "approver@example.com", env.now)
    assert record.plan is not None
    changed = record.plan.model_copy(update={"target": "mcp-prod/other"})
    assert_code(
        lambda: env.controller.approvals.consume(receipt, changed, env.now),
        "APPROVAL_PLAN_MISMATCH",
    )


def test_forged_approval_is_not_trusted(env):
    record = lab.advance_to_verified(env)
    assert record.plan is not None
    forged = lab.ApprovalReceipt(
        receipt_id="forged",
        run_id=record.run_id,
        plan_digest=lab.document_digest(record.plan),
        approver="attacker",
        approver_role="release-approver",
        issued_at=env.now,
        expires_at=env.now + timedelta(minutes=5),
    )
    assert_code(
        lambda: env.controller.approvals.consume(forged, record.plan, env.now),
        "APPROVAL_NOT_FOUND",
    )


def test_expired_approval_is_rejected(env):
    record, receipt = advance_to_approved(env)
    claims = lab.oidc_claims(env).model_copy(
        update={
            "issued_at": receipt.expires_at - timedelta(minutes=1),
            "expires_at": receipt.expires_at + timedelta(minutes=1),
        }
    )
    assert_code(
        lambda: env.controller.deploy(
            record.version,
            receipt,
            claims,
            lab.DeployResult.SUCCESS,
            receipt.expires_at,
        ),
        "APPROVAL_EXPIRED",
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("audience", "other-api", "OIDC_SUBJECT_INVALID"),
        ("subject", "repo:attacker", "OIDC_SUBJECT_INVALID"),
        ("repository_id", "repo-other", "OIDC_CONTEXT_MISMATCH"),
        ("workflow_sha", "f" * 40, "OIDC_CONTEXT_MISMATCH"),
        ("ref", "refs/heads/dev", "OIDC_CONTEXT_MISMATCH"),
        ("run_id", "other", "OIDC_CONTEXT_MISMATCH"),
        ("expires_at", lab.utc("2026-09-29T02:59:00Z"), "OIDC_TOKEN_EXPIRED"),
    ],
)
def test_oidc_exchange_binds_workflow_context(field, value, code, env):
    record, receipt = advance_to_approved(env)
    claims = lab.oidc_claims(env).model_copy(update={field: value})
    assert_code(
        lambda: env.controller.deploy(
            record.version, receipt, claims, lab.DeployResult.SUCCESS, env.now
        ),
        code,
    )


def test_invalid_oidc_does_not_consume_approval(env):
    record, receipt = advance_to_approved(env)
    bad = lab.oidc_claims(env).model_copy(update={"audience": "other"})
    assert_code(
        lambda: env.controller.deploy(
            record.version, receipt, bad, lab.DeployResult.SUCCESS, env.now
        ),
        "OIDC_SUBJECT_INVALID",
    )
    success = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.SUCCESS, env.now
    )
    assert success.state == lab.RunState.VERIFYING


def test_deployment_approval_is_single_use(env):
    record, receipt = advance_to_approved(env)
    record = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.SUCCESS, env.now
    )
    assert_code(
        lambda: env.controller.approvals.consume(receipt, record.plan, env.now),
        "APPROVAL_REPLAYED",
    )


def test_transient_deployment_retries_same_logical_operation(env):
    record, receipt = advance_to_approved(env)
    record = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.TRANSIENT, env.now
    )
    operation_id = record.operation_id
    assert record.state == lab.RunState.DEPLOY_RETRYABLE
    record = env.controller.retry_deploy(record.version, lab.DeployResult.SUCCESS)
    assert record.state == lab.RunState.VERIFYING
    assert record.operation_id == operation_id
    assert record.deploy_attempts == 2


def test_retry_budget_is_bounded(env):
    record, receipt = advance_to_approved(env)
    record = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.TRANSIENT, env.now
    )
    record = env.controller.retry_deploy(record.version, lab.DeployResult.TRANSIENT)
    assert_code(
        lambda: env.controller.retry_deploy(record.version, lab.DeployResult.SUCCESS),
        "DEPLOY_RETRY_BUDGET_EXHAUSTED",
    )


def test_unknown_committed_outcome_is_reconciled_before_retry(env):
    record, receipt = advance_to_approved(env)
    record = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.UNKNOWN, env.now
    )
    assert record.state == lab.RunState.DEPLOYMENT_UNKNOWN
    record = env.controller.reconcile(record.version)
    assert record.state == lab.RunState.VERIFYING
    assert env.target.current_digest == lab.ARTIFACT_DIGEST


def test_unknown_absent_outcome_becomes_retryable(env):
    class UnknownAbsentTarget(lab.DeploymentTarget):
        def apply(self, operation_id, digest, outcome):
            if outcome == lab.DeployResult.UNKNOWN:
                return lab.DeployResult.UNKNOWN
            return super().apply(operation_id, digest, outcome)

    target = UnknownAbsentTarget(lab.KNOWN_GOOD_DIGEST)
    env.controller.target = target
    record, receipt = advance_to_approved(env)
    record = env.controller.deploy(
        record.version, receipt, lab.oidc_claims(env), lab.DeployResult.UNKNOWN, env.now
    )
    record = env.controller.reconcile(record.version)
    assert record.state == lab.RunState.DEPLOY_RETRYABLE
    assert target.current_digest == lab.KNOWN_GOOD_DIGEST


def test_idempotency_key_cannot_be_reused_for_another_digest():
    target = lab.DeploymentTarget(lab.KNOWN_GOOD_DIGEST)
    target.apply("operation-1", lab.ARTIFACT_DIGEST, lab.DeployResult.SUCCESS)
    assert_code(
        lambda: target.apply("operation-1", lab.KNOWN_GOOD_DIGEST, lab.DeployResult.SUCCESS),
        "IDEMPOTENCY_CONFLICT",
    )


def test_success_requires_observed_digest_and_all_health_checks(env):
    record = deploy_success(env)
    signed = lab.health_evidence(env, record)
    record = env.controller.verify_health(
        record.version, signed, env.now + timedelta(minutes=2)
    )
    assert record.state == lab.RunState.SUCCEEDED
    assert env.target.current_digest == lab.ARTIFACT_DIGEST


def test_health_evidence_is_bound_to_operation(env):
    record = deploy_success(env)
    signed = lab.health_evidence(env, record)
    changed = signed.document.model_copy(update={"operation_id": "other-operation"})
    resigned = lab.sign_evidence(
        changed, "health", lab.HEALTH_SIGNER, env.keys[lab.HEALTH_SIGNER]
    )
    assert_code(
        lambda: env.controller.verify_health(
            record.version, resigned, env.now + timedelta(minutes=2)
        ),
        "HEALTH_EVIDENCE_MISMATCH",
    )


def test_stale_health_observation_is_rejected(env):
    record = deploy_success(env)
    signed = lab.health_evidence(env, record)
    changed = signed.document.model_copy(
        update={"observed_at": env.now - timedelta(days=2)}
    )
    resigned = lab.sign_evidence(
        changed, "health", lab.HEALTH_SIGNER, env.keys[lab.HEALTH_SIGNER]
    )
    assert_code(
        lambda: env.controller.verify_health(record.version, resigned, env.now),
        "HEALTH_EVIDENCE_STALE",
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"observed_digest": lab.KNOWN_GOOD_DIGEST},
        {"checks": {"service-ready": True, "tool-smoke": False}},
    ],
)
def test_failed_health_restores_exact_known_good_digest(env, changes):
    record = deploy_success(env)
    signed = lab.health_evidence(env, record, **changes)
    record = env.controller.verify_health(
        record.version, signed, env.now + timedelta(minutes=2)
    )
    assert record.state == lab.RunState.ROLLED_BACK
    assert record.terminal_reason == "HEALTH_CHECK_FAILED"
    assert env.target.current_digest == lab.KNOWN_GOOD_DIGEST


def test_rollback_failure_is_not_reported_as_success(env):
    record = deploy_success(env)
    signed = lab.health_evidence(env, record, checks={"service-ready": False})
    assert_code(
        lambda: env.controller.verify_health(
            record.version,
            signed,
            env.now + timedelta(minutes=2),
            rollback_outcome=lab.DeployResult.TRANSIENT,
        ),
        "ROLLBACK_FAILED",
    )
    assert env.controller.store.get(record.run_id).state == lab.RunState.VERIFYING


def test_optimistic_concurrency_rejects_stale_transition(env):
    record = env.controller.start(env.source, env.now)
    env.controller.record_build(record.version, lab.ARTIFACT_BYTES, env.build, env.now)
    with pytest.raises(lab.VersionConflict):
        env.controller.store.transition(
            record.run_id,
            record.version,
            {lab.RunState.BUILT},
            lab.RunState.TESTED,
        )


def test_concurrent_approval_consumption_allows_one_winner(env):
    record, receipt = advance_to_approved(env)
    assert record.plan is not None

    def consume(_):
        try:
            env.controller.approvals.consume(receipt, record.plan, env.now)
            return "consumed"
        except lab.PipelineDenied as denied:
            return denied.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, range(2)))
    assert outcomes.count("consumed") == 1
    assert outcomes.count("APPROVAL_REPLAYED") == 1


def test_audit_records_observable_state_without_credentials_or_signatures(env):
    record = deploy_success(env)
    record = env.controller.verify_health(
        record.version, lab.health_evidence(env, record), env.now + timedelta(minutes=2)
    )
    serialized = json.dumps([event.model_dump(mode="json") for event in env.controller.audit])
    assert "DEPLOYMENT_VERIFIED" in serialized
    assert "cloud-" not in serialized
    assert env.source.signature.signature not in serialized
    assert lab.ARTIFACT_BYTES.decode().strip() not in serialized


def test_strict_contracts_reject_unknown_fields(env):
    data = env.context.model_dump(mode="json")
    data["trusted"] = True
    with pytest.raises(ValidationError):
        lab.ReleaseRunContext.model_validate(data)
