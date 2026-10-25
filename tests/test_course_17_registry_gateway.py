"""Executable invariants for Course 17 registry trust and enterprise gateway."""

import asyncio
from dataclasses import asdict, replace
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import sys

from hypothesis import given, settings, strategies as st
import jwt
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = (
    ROOT
    / "curriculum/advanced/17-server-registry-discovery-trust-enterprise-gateways/lab.py"
)
SPEC = importlib.util.spec_from_file_location("course_17_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.utc("2026-10-07T17:30:00Z")


def run(coroutine):
    return asyncio.run(coroutine)


def environment():
    return run(lab.reviewed_environment(NOW))


def resign_record(record, **changes):
    candidate = replace(record, **changes, record_digest="", signature="")
    record_digest = lab.digest(candidate.unsigned())
    return replace(
        candidate,
        record_digest=record_digest,
        signature=lab.sign(record_digest),
    )


def resign_snapshot(snapshot, **changes):
    candidate = replace(snapshot, **changes, snapshot_digest="", signature="")
    snapshot_digest = lab.digest(candidate.unsigned())
    return replace(
        candidate,
        snapshot_digest=snapshot_digest,
        signature=lab.sign(snapshot_digest),
    )


def issue_token(env, *, principal=None, now=NOW, request_id="req-token"):
    principal = principal or env.principal
    return env.broker.issue(
        principal,
        env.record,
        env.record.grants[0],
        now,
        request_id,
    )


def mutate_token(token, **changes):
    claims = jwt.decode(token, options={"verify_signature": False})
    claims.update(changes)
    return jwt.encode(claims, lab.TOKEN_SIGNING_KEY, algorithm="HS256")


def test_demo_proves_discovery_admission_gateway_and_revocation_boundaries():
    demo = run(lab.run_demo())
    assert demo["registry"]["status"] == "active"
    assert demo["approved_call"] == {
        "decision": lab.Decision.ALLOW,
        "reason": "GATEWAY_AND_SERVER_POLICY_ALLOW",
        "ticket": "acme-7",
        "downstream_token_issued": True,
    }
    assert demo["direct_bypass_allowed"] is False
    assert demo["campaign"]["metrics"] == {
        "decision_accuracy": 1.0,
        "unsafe_allow_rate": 0.0,
        "false_block_rate": 0.0,
        "safe_task_completion_rate": 1.0,
    }
    assert demo["revocation"]["before_revocation"] == lab.Decision.ALLOW
    assert demo["revocation"]["after_revocation"] == lab.Decision.DENY
    assert demo["revocation"]["effect_count"] == 1


def test_utc_canonical_json_digest_and_signature_are_deterministic():
    assert lab.utc("2026-10-07T17:30:00Z") == NOW
    with pytest.raises(ValueError, match="UTC"):
        lab.utc("2026-10-07T10:30:00-07:00")
    left = {"b": 2, "a": 1}
    right = {"a": 1, "b": 2}
    assert lab.canonical_json(left) == lab.canonical_json(right)
    assert lab.digest(left) == lab.digest(right)
    assert lab.sign(left) == lab.sign(right)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://mcp.example.test/mcp",
        "https://user:pass@mcp.example.test/mcp",
        "https://mcp.example.test/mcp#fragment",
        "not-a-url",
    ],
)
def test_endpoint_validation_requires_unambiguous_https(endpoint):
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.require_https_endpoint(endpoint)
    assert denied.value.code == "ENDPOINT_INVALID"


def test_real_mcp_sdk_contract_is_stable_and_complete():
    env = environment()
    contract_digest, tools = run(lab.inspect_contract(env.target.mcp))
    assert tools == ("ticket.read",)
    assert contract_digest == env.record.contract_digest
    assert lab.is_digest(contract_digest)


def test_public_discovery_metadata_does_not_enable_direct_execution():
    env = environment()
    assert env.metadata.status == "active"
    assert run(lab.direct_call_without_gateway(env.target, NOW)) is False
    assert env.target.calls["ticket.read"] == 0


def test_admission_binds_complete_reviewed_subject_and_accountability():
    env = environment()
    record = env.record
    assert record.server_name == env.metadata.name == env.evidence.server_name
    assert record.server_version == env.metadata.version == env.evidence.server_version
    assert record.package_type == env.metadata.package_type
    assert record.package_identifier == env.metadata.package_identifier
    assert record.package_version == env.metadata.package_version
    assert record.source_repository_id == env.evidence.source_repository_id
    assert record.endpoint == env.evidence.endpoint
    assert record.artifact_digest == env.evidence.artifact_digest
    assert record.contract_digest == env.evidence.contract_digest
    assert record.provenance_digest == env.evidence.provenance_digest
    assert record.sbom_digest == env.evidence.sbom_digest
    assert record.scan_digest == env.evidence.scan_digest
    assert record.owner == "platform-security"
    assert record.incident_contact == "soc-oncall"
    assert record.gateway_required is True
    assert record.tenant_id == "acme"
    assert record.environment == "prod"
    assert record.status == lab.Lifecycle.ACTIVE


def test_admission_record_is_signed_and_chained():
    env = environment()
    lab.verify_record(env.record)
    assert env.record.revision == 1
    assert env.record.registry_epoch == 1
    assert env.record.previous_record_digest is None
    assert env.record.record_digest == lab.digest(env.record.unsigned())


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"package_identifier": ""}, "RECORD_PACKAGE_INVALID"),
        ({"owner": ""}, "RECORD_ACCOUNTABILITY_INVALID"),
        ({"provenance_digest": "latest"}, "RECORD_EVIDENCE_INVALID"),
        ({"workload_identity": "dns://unverified"}, "RECORD_WORKLOAD_IDENTITY_INVALID"),
    ],
)
def test_signed_records_still_require_semantic_validation(mutation, code):
    env = environment()
    record = resign_record(env.record, **mutation)
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.verify_record(record)
    assert denied.value.code == code


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"name": "bad name"}, "SERVER_NAME_INVALID"),
        ({"version": "latest"}, "VERSION_NOT_PINNED"),
        ({"package_version": "latest"}, "PACKAGE_VERSION_MISMATCH"),
        ({"status": "deprecated"}, "PUBLIC_ENTRY_NOT_ACTIVE"),
        ({"status": "deleted"}, "PUBLIC_ENTRY_NOT_ACTIVE"),
        ({"package_type": "shell"}, "PACKAGE_TYPE_DENIED"),
        ({"package_identifier": ""}, "PUBLIC_PROVENANCE_INCOMPLETE"),
        ({"repository_id": ""}, "PUBLIC_PROVENANCE_INCOMPLETE"),
        ({"package_digest": "latest"}, "PACKAGE_DIGEST_INVALID"),
        ({"remote_url": "http://mcp.support.acme.test/mcp"}, "ENDPOINT_INVALID"),
        (
            {"registry_updated_at": NOW + timedelta(seconds=6)},
            "PUBLIC_METADATA_FROM_FUTURE",
        ),
    ],
)
def test_registry_rejects_untrusted_or_ambiguous_public_metadata(mutation, code):
    env = environment()
    registry = lab.TrustRegistry()
    with pytest.raises(lab.RegistryDenied) as denied:
        registry.admit(
            replace(env.metadata, **mutation),
            env.evidence,
            tenant_id="acme",
            environment="prod",
            actor="reviewer",
            now=NOW,
        )
    assert denied.value.code == code
    assert registry.epoch == 0


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"server_name": "com.acme/other"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"server_version": "9.9.9"}, "EVIDENCE_SUBJECT_MISMATCH"),
        ({"artifact_digest": lab.digest("other")}, "ARTIFACT_DIGEST_MISMATCH"),
        ({"source_repository_id": "github:other"}, "REPOSITORY_ID_MISMATCH"),
        ({"endpoint": "https://mcp.other.test/mcp"}, "ENDPOINT_MISMATCH"),
        ({"owner": ""}, "ACCOUNTABLE_OWNER_REQUIRED"),
        ({"incident_contact": ""}, "ACCOUNTABLE_OWNER_REQUIRED"),
        ({"data_classification": "unbounded"}, "DATA_CLASSIFICATION_DENIED"),
        ({"sandbox_profile": "privileged"}, "SANDBOX_PROFILE_DENIED"),
        ({"workload_identity": "support-server"}, "WORKLOAD_IDENTITY_INVALID"),
        ({"contract_digest": "reviewed"}, "EVIDENCE_DIGEST_INVALID"),
        ({"reviewed_at": NOW + timedelta(seconds=1)}, "REVIEW_NOT_CURRENT"),
        ({"expires_at": NOW}, "REVIEW_NOT_CURRENT"),
        (
            {
                "reviewed_at": NOW - timedelta(days=1),
                "expires_at": NOW + timedelta(days=90),
            },
            "REVIEW_WINDOW_TOO_LONG",
        ),
        ({"grants": ()}, "CAPABILITY_GRANT_REQUIRED"),
    ],
)
def test_registry_rejects_incomplete_or_mismatched_review_evidence(mutation, code):
    env = environment()
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.TrustRegistry().admit(
            env.metadata,
            replace(env.evidence, **mutation),
            tenant_id="acme",
            environment="prod",
            actor="reviewer",
            now=NOW,
        )
    assert denied.value.code == code


def test_registry_rejects_duplicate_and_invalid_capability_grants():
    env = environment()
    grant = env.evidence.grants[0]
    with pytest.raises(lab.RegistryDenied) as duplicate:
        lab.TrustRegistry().admit(
            env.metadata,
            replace(env.evidence, grants=(grant, grant)),
            tenant_id="acme",
            environment="prod",
            actor="reviewer",
            now=NOW,
        )
    assert duplicate.value.code == "CAPABILITY_GRANT_DUPLICATE"

    invalid = replace(grant, server_tool="filesystem.read")
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.TrustRegistry().admit(
            env.metadata,
            replace(env.evidence, grants=(invalid,)),
            tenant_id="acme",
            environment="prod",
            actor="reviewer",
            now=NOW,
        )
    assert denied.value.code == "CAPABILITY_GRANT_INVALID"


@pytest.mark.parametrize(
    "tenant,environment_name", [("", "prod"), ("acme", "../prod")]
)
def test_registry_rejects_invalid_enterprise_scope(tenant, environment_name):
    environment_fixture = environment()
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.TrustRegistry().admit(
            environment_fixture.metadata,
            environment_fixture.evidence,
            tenant_id=tenant,
            environment=environment_name,
            actor="reviewer",
            now=NOW,
        )
    assert denied.value.code == "SCOPE_INVALID"


def test_optimistic_revision_prevents_lost_update():
    env = environment()
    with pytest.raises(lab.RegistryDenied) as denied:
        env.registry.admit(
            env.metadata,
            env.evidence,
            tenant_id="acme",
            environment="prod",
            actor="second-reviewer",
            now=NOW + timedelta(seconds=1),
            expected_revision=0,
        )
    assert denied.value.code == "REVISION_CONFLICT"
    assert env.registry.get(env.record.key) == env.record


def test_status_transition_is_signed_chained_and_audited():
    env = environment()
    quarantined = env.registry.transition(
        env.record.key,
        lab.Lifecycle.QUARANTINED,
        expected_revision=1,
        actor="soc-17",
        reason_code="DRIFT_CONFIRMED",
        now=NOW + timedelta(seconds=1),
    )
    lab.verify_record(quarantined)
    assert quarantined.revision == 2
    assert quarantined.registry_epoch == 2
    assert quarantined.previous_record_digest == env.record.record_digest
    assert env.registry.audit[-1].actor == "soc-17"
    assert env.registry.audit[-1].reason_code == "DRIFT_CONFIRMED"


def test_revocation_is_terminal_but_quarantine_requires_fresh_readmission():
    env = environment()
    revoked = env.registry.transition(
        env.record.key,
        lab.Lifecycle.REVOKED,
        expected_revision=1,
        actor="soc-17",
        reason_code="COMPROMISED",
        now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(lab.RegistryDenied) as transition:
        env.registry.transition(
            revoked.key,
            lab.Lifecycle.ACTIVE,
            expected_revision=revoked.revision,
            actor="operator",
            reason_code="TRY_REENABLE",
            now=NOW + timedelta(seconds=2),
        )
    assert transition.value.code == "LIFECYCLE_TRANSITION_DENIED"
    with pytest.raises(lab.RegistryDenied) as readmit:
        env.registry.admit(
            env.metadata,
            env.evidence,
            tenant_id="acme",
            environment="prod",
            actor="reviewer",
            now=NOW + timedelta(seconds=2),
            expected_revision=revoked.revision,
        )
    assert readmit.value.code == "REVOCATION_TERMINAL"


def test_quarantine_can_only_reactivate_through_new_evidence_revision():
    env = environment()
    quarantined = env.registry.transition(
        env.record.key,
        lab.Lifecycle.QUARANTINED,
        expected_revision=1,
        actor="soc-17",
        reason_code="REVIEW_REQUIRED",
        now=NOW + timedelta(seconds=1),
    )
    reapproved = env.registry.admit(
        env.metadata,
        replace(
            env.evidence,
            reviewed_at=NOW + timedelta(seconds=2),
            expires_at=NOW + timedelta(days=30),
        ),
        tenant_id="acme",
        environment="prod",
        actor="reviewer-18",
        now=NOW + timedelta(seconds=2),
        expected_revision=quarantined.revision,
    )
    assert reapproved.status == lab.Lifecycle.ACTIVE
    assert reapproved.revision == 3
    assert reapproved.previous_record_digest == quarantined.record_digest


def test_snapshot_is_signed_and_contains_latest_record_only():
    env = environment()
    lab.verify_snapshot(env.snapshot)
    assert env.snapshot.epoch == 1
    assert env.snapshot.expires_at - env.snapshot.issued_at == lab.MAX_CACHE_AGE
    assert env.snapshot.records == (env.record,)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("owner", "attacker", "RECORD_DIGEST_INVALID"),
        ("record_digest", lab.digest("other"), "RECORD_DIGEST_INVALID"),
        ("signature", "0" * 64, "RECORD_SIGNATURE_INVALID"),
    ],
)
def test_record_tampering_is_rejected(field, value, code):
    env = environment()
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.verify_record(replace(env.record, **{field: value}))
    assert denied.value.code == code


def test_snapshot_tampering_and_duplicate_keys_are_rejected():
    env = environment()
    with pytest.raises(lab.RegistryDenied) as digest_error:
        lab.verify_snapshot(replace(env.snapshot, epoch=2))
    assert digest_error.value.code == "SNAPSHOT_DIGEST_INVALID"

    with pytest.raises(lab.RegistryDenied) as signature_error:
        lab.verify_snapshot(replace(env.snapshot, signature="0" * 64))
    assert signature_error.value.code == "SNAPSHOT_SIGNATURE_INVALID"

    duplicate = resign_snapshot(env.snapshot, records=(env.record, env.record))
    with pytest.raises(lab.RegistryDenied) as duplicate_error:
        lab.verify_snapshot(duplicate)
    assert duplicate_error.value.code == "SNAPSHOT_DUPLICATE_RECORD"


def test_snapshot_rejects_record_from_later_epoch():
    env = environment()
    future_record = resign_record(env.record, registry_epoch=2)
    invalid = resign_snapshot(env.snapshot, records=(future_record,))
    with pytest.raises(lab.RegistryDenied) as denied:
        lab.verify_snapshot(invalid)
    assert denied.value.code == "SNAPSHOT_EPOCH_INVALID"


def test_host_sync_is_atomic_when_new_snapshot_fails_validation():
    env = environment()
    before = env.cache.record(env.record.key)
    invalid = replace(env.snapshot, signature="0" * 64)
    with pytest.raises(lab.RegistryDenied):
        env.cache.sync(invalid, NOW + timedelta(seconds=1))
    assert env.cache.record(env.record.key) == before
    assert env.cache.epoch == 1


def test_host_and_server_views_reject_snapshot_rollback():
    env = environment()
    env.registry.transition(
        env.record.key,
        lab.Lifecycle.REVOKED,
        expected_revision=1,
        actor="soc",
        reason_code="COMPROMISED",
        now=NOW + timedelta(seconds=1),
    )
    newer = env.registry.snapshot(NOW + timedelta(seconds=1))
    env.cache.sync(newer, NOW + timedelta(seconds=1))
    env.server_view.sync(newer)
    with pytest.raises(lab.RegistryDenied, match="SNAPSHOT_ROLLBACK"):
        env.cache.sync(env.snapshot, NOW + timedelta(seconds=2))
    with pytest.raises(lab.RegistryDenied, match="SNAPSHOT_ROLLBACK"):
        env.server_view.sync(env.snapshot)


def test_same_epoch_same_state_can_refresh_but_equivocation_is_rejected():
    env = environment()
    refreshed = env.registry.snapshot(NOW + timedelta(seconds=1))
    env.cache.sync(refreshed, NOW + timedelta(seconds=1))

    other = run(lab.reviewed_environment(NOW))
    changed_record = resign_record(other.record, owner="different-owner")
    equivocation = resign_snapshot(other.snapshot, records=(changed_record,))
    with pytest.raises(lab.RegistryDenied) as denied:
        env.cache.sync(equivocation, NOW + timedelta(seconds=2))
    assert denied.value.code == "SNAPSHOT_EQUIVOCATION"


def test_cache_fails_closed_when_stale_missing_inactive_or_expired():
    env = environment()
    assert env.cache.resolve(
        tenant_id="acme", environment="prod", server_name=lab.SERVER_NAME, now=NOW
    ) == env.record
    with pytest.raises(lab.GatewayDenied, match="REGISTRY_CACHE_STALE"):
        env.cache.resolve(
            tenant_id="acme",
            environment="prod",
            server_name=lab.SERVER_NAME,
            now=NOW + lab.MAX_CACHE_AGE + timedelta(microseconds=1),
        )
    with pytest.raises(lab.GatewayDenied, match="SERVER_NOT_ADMITTED"):
        env.cache.resolve(
            tenant_id="globex",
            environment="prod",
            server_name=lab.SERVER_NAME,
            now=NOW,
        )

    inactive = resign_record(env.record, status=lab.Lifecycle.QUARANTINED)
    inactive_snapshot = resign_snapshot(env.snapshot, records=(inactive,))
    other_cache = lab.HostTrustCache()
    other_cache.sync(inactive_snapshot, NOW)
    with pytest.raises(lab.GatewayDenied, match="SERVER_NOT_ACTIVE"):
        other_cache.resolve(
            tenant_id="acme",
            environment="prod",
            server_name=lab.SERVER_NAME,
            now=NOW,
        )

    expired = resign_record(env.record, expires_at=NOW)
    expired_snapshot = resign_snapshot(env.snapshot, records=(expired,))
    expired_cache = lab.HostTrustCache()
    expired_cache.sync(expired_snapshot, NOW)
    with pytest.raises(lab.GatewayDenied, match="REVIEW_EXPIRED"):
        expired_cache.resolve(
            tenant_id="acme",
            environment="prod",
            server_name=lab.SERVER_NAME,
            now=NOW,
        )


def test_cache_rejects_snapshot_from_future():
    env = environment()
    future = resign_snapshot(env.snapshot, issued_at=NOW + timedelta(seconds=6))
    cache = lab.HostTrustCache()
    with pytest.raises(lab.RegistryDenied) as denied:
        cache.sync(future, NOW)
    assert denied.value.code == "SNAPSHOT_FROM_FUTURE"

    expired = resign_snapshot(
        env.snapshot,
        issued_at=NOW - lab.MAX_CACHE_AGE,
        expires_at=NOW,
    )
    with pytest.raises(lab.RegistryDenied) as denied:
        cache.sync(expired, NOW)
    assert denied.value.code == "SNAPSHOT_EXPIRED"


def test_broker_issues_narrow_audience_bound_short_lived_authority():
    env = environment()
    token = issue_token(env)
    claims = jwt.decode(
        token,
        lab.TOKEN_SIGNING_KEY,
        algorithms=["HS256"],
        audience=lab.ENDPOINT,
        issuer=lab.TOKEN_ISSUER,
        options={"verify_exp": False},
    )
    assert claims["sub"] == env.principal.subject
    assert claims["tenant"] == env.principal.tenant_id
    assert claims["scope"] == "ticket:read"
    assert claims["aud"] == lab.ENDPOINT
    assert claims["registry_record"] == env.record.record_digest
    assert claims["exp"] - claims["iat"] == int(lab.TOKEN_LIFETIME.total_seconds())


def test_broker_refuses_to_issue_permission_not_held_by_principal():
    env = environment()
    principal = replace(env.principal, permissions=frozenset())
    with pytest.raises(lab.GatewayDenied) as denied:
        issue_token(env, principal=principal)
    assert denied.value.code == "PERMISSION_DENIED"


def test_resource_server_accepts_valid_token_and_returns_bound_claims():
    env = environment()
    claims = env.authorizer.validate(
        issue_token(env),
        audience=lab.ENDPOINT,
        required_scope="ticket:read",
        now=NOW,
    )
    assert claims["tenant"] == "acme"
    assert claims["registry_record"] in env.server_view.active_record_digests


@pytest.mark.parametrize(
    "token_factory,audience,scope,when,message",
    [
        (lambda env, token: token, "https://other.example/mcp", "ticket:read", NOW, "invalid"),
        (
            lambda env, token: mutate_token(token, scope="ticket:list"),
            lab.ENDPOINT,
            "ticket:read",
            NOW,
            "scope denied",
        ),
        (
            lambda env, token: token,
            lab.ENDPOINT,
            "ticket:read",
            NOW + lab.TOKEN_LIFETIME,
            "expired",
        ),
        (
            lambda env, token: issue_token(
                env, now=NOW + timedelta(seconds=6), request_id="req-future"
            ),
            lab.ENDPOINT,
            "ticket:read",
            NOW,
            "future-dated",
        ),
        (
            lambda env, token: mutate_token(token, server="com.attacker/rogue"),
            lab.ENDPOINT,
            "ticket:read",
            NOW,
            "target invalid",
        ),
    ],
)
def test_resource_server_rejects_invalid_authority(
    token_factory, audience, scope, when, message
):
    env = environment()
    if when >= env.snapshot.expires_at:
        env.server_view.sync(env.registry.snapshot(when - timedelta(seconds=1)))
    token = token_factory(env, issue_token(env))
    with pytest.raises(lab.ToolError, match=message):
        env.authorizer.validate(token, audience=audience, required_scope=scope, now=when)


def test_resource_server_rejects_jti_and_record_revocation():
    env = environment()
    token = issue_token(env)
    claims = jwt.decode(token, options={"verify_signature": False})
    env.broker.revoke_jti(claims["jti"])
    with pytest.raises(lab.ToolError, match="token revoked"):
        env.authorizer.validate(
            token, audience=lab.ENDPOINT, required_scope="ticket:read", now=NOW
        )

    env2 = environment()
    token2 = issue_token(env2)
    env2.broker.revoke_record(env2.record.record_digest)
    with pytest.raises(lab.ToolError, match="authority revoked"):
        env2.authorizer.validate(
            token2, audience=lab.ENDPOINT, required_scope="ticket:read", now=NOW
        )


def test_resource_server_rejects_inactive_or_expired_registry_binding():
    env = environment()
    token = issue_token(env)
    env.registry.transition(
        env.record.key,
        lab.Lifecycle.REVOKED,
        expected_revision=1,
        actor="soc",
        reason_code="COMPROMISED",
        now=NOW + timedelta(seconds=1),
    )
    env.server_view.sync(env.registry.snapshot(NOW + timedelta(seconds=1)))
    with pytest.raises(lab.ToolError, match="not active"):
        env.authorizer.validate(
            token,
            audience=lab.ENDPOINT,
            required_scope="ticket:read",
            now=NOW + timedelta(seconds=1),
        )

    env2 = environment()
    env2.server_view.sync(
        env2.registry.snapshot(env2.record.expires_at - timedelta(seconds=1))
    )
    token2 = issue_token(
        env2,
        now=env2.record.expires_at - timedelta(seconds=1),
        request_id="req-review-expiry",
    )
    with pytest.raises(lab.ToolError, match="review expired"):
        env2.authorizer.validate(
            token2,
            audience=lab.ENDPOINT,
            required_scope="ticket:read",
            now=env2.record.expires_at,
        )

    env3 = environment()
    token3 = issue_token(env3)
    with pytest.raises(lab.ToolError, match="registry view stale"):
        env3.authorizer.validate(
            token3,
            audience=lab.ENDPOINT,
            required_scope="ticket:read",
            now=env3.snapshot.expires_at,
        )


def test_gateway_uses_authenticated_tenant_and_ignores_caller_claims_and_token():
    env = environment()
    call = lab.request()
    assert call.claimed_tenant == "globex"
    assert "attacker" in call.client_authorization
    result = run(env.gateway.handle(call, env.principal, env.target, NOW))
    assert result.decision == lab.Decision.ALLOW
    assert result.response.ticket.ticket_id == "acme-7"
    assert result.downstream_jti is not None
    audit = env.gateway.audit[-1]
    serialized = json.dumps(lab._jsonable(asdict(audit)), sort_keys=True)
    assert "analyst-42" not in serialized
    assert "attacker-controlled-token" not in serialized
    assert "Payment is pending" not in serialized


def test_gateway_checks_live_artifact_endpoint_workload_and_contract_before_effect():
    for case_id in (
        "artifact-drift",
        "endpoint-swap",
        "workload-identity-drift",
        "contract-drift",
    ):
        result = run(lab.run_case(next(case for case in lab.CASES if case.case_id == case_id)))
        assert not result.actual_allow
        assert result.effect_count == 0


@pytest.mark.parametrize("case", lab.CASES, ids=lambda case: case.case_id)
def test_labelled_gateway_cases_match_expected_decision_without_forbidden_effect(case):
    result = run(lab.run_case(case))
    assert result.actual_allow is case.expected_allow
    assert result.effect_count == (1 if case.expected_allow else 0)


def test_resource_server_rejects_cross_tenant_ticket_after_gateway_allow_stage():
    result = run(
        lab.run_case(
            next(case for case in lab.CASES if case.case_id == "resource-server-tenant-deny")
        )
    )
    assert result.reason_code == "RESOURCE_SERVER_DENIED"
    assert result.effect_count == 0


def test_gateway_rejects_protocol_method_identifier_and_schema_errors():
    env = environment()
    calls = (
        replace(lab.request(), protocol_version="2025-11-25"),
        replace(lab.request(), method="resources/read"),
        replace(lab.request(), request_id="bad request"),
        replace(lab.request(), arguments={"ticket_id": 7}),
    )
    reasons = []
    for index, call in enumerate(calls):
        call = replace(call, request_id=call.request_id if index != 0 else "req-version")
        result = run(env.gateway.handle(call, env.principal, env.target, NOW))
        reasons.append(result.reason_code)
    assert reasons == [
        "PROTOCOL_VERSION_DENIED",
        "METHOD_DENIED",
        "REQUEST_ID_INVALID",
        "INVALID_TOOL_ARGUMENTS",
    ]
    assert env.target.calls["ticket.read"] == 0


def test_gateway_rate_limit_is_per_authenticated_subject_and_capability():
    env = environment()
    first = run(env.gateway.handle(lab.request(), env.principal, env.target, NOW))
    second = run(
        env.gateway.handle(
            lab.request(request_id="req-safe-2", trace_id="trace-safe-2"),
            env.principal,
            env.target,
            NOW,
        )
    )
    third = run(
        env.gateway.handle(
            lab.request(request_id="req-safe-3", trace_id="trace-safe-3"),
            env.principal,
            env.target,
            NOW,
        )
    )
    assert first.decision == second.decision == lab.Decision.ALLOW
    assert third.reason_code == "RATE_LIMIT_EXCEEDED"
    assert env.target.calls["ticket.read"] == 2


def test_revocation_propagates_to_registry_host_server_and_tokens_before_next_effect():
    evidence = run(lab.revocation_exercise())
    assert evidence == {
        "before_revocation": lab.Decision.ALLOW,
        "after_revocation": lab.Decision.DENY,
        "after_reason": "SERVER_NOT_ACTIVE",
        "registry_revision": 2,
        "registry_epoch": 2,
        "host_epoch": 2,
        "server_epoch": 2,
        "propagation_ms": 25,
        "effect_count": 1,
    }


def test_campaign_metrics_use_labelled_allow_and_deny_populations():
    report = run(lab.run_campaign())
    assert report.true_allow == 1
    assert report.false_allow == 0
    assert report.true_deny == len(lab.CASES) - 1
    assert report.false_deny == 0
    assert report.metrics()["unsafe_allow_rate"] == 0.0
    assert report.metrics()["false_block_rate"] == 0.0
    assert report.metrics()["safe_task_completion_rate"] == 1.0


def test_campaign_rejects_empty_duplicate_and_oversized_sets():
    with pytest.raises(ValueError, match="between"):
        run(lab.run_campaign(()))
    case = lab.CASES[0]
    with pytest.raises(ValueError, match="unique"):
        run(lab.run_campaign((case, case)))
    too_many = tuple(
        replace(case, case_id=f"case-{index}") for index in range(51)
    )
    with pytest.raises(ValueError, match="between"):
        run(lab.run_campaign(too_many))


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=40))
@settings(max_examples=30, deadline=None)
def test_property_unregistered_tenants_never_resolve(tenant):
    if tenant == "acme" or lab.ID_PATTERN.fullmatch(tenant) is None:
        return
    env = environment()
    with pytest.raises(lab.GatewayDenied):
        env.cache.resolve(
            tenant_id=tenant,
            environment="prod",
            server_name=lab.SERVER_NAME,
            now=NOW,
        )


@given(st.text(min_size=1, max_size=100))
@settings(max_examples=30, deadline=None)
def test_property_tampered_owner_never_validates(owner):
    env = environment()
    if owner == env.record.owner:
        return
    tampered = replace(env.record, owner=owner)
    with pytest.raises(lab.RegistryDenied, match="RECORD_DIGEST_INVALID"):
        lab.verify_record(tampered)
