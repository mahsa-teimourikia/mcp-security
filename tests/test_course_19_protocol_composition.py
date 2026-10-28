"""Executable invariants for Course 19 protocol composition security."""

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

from a2a.types import Message
import jwt
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/19-protocol-composition-security/lab.py"
SPEC = importlib.util.spec_from_file_location("course_19_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


def environment(*, action="read", operation_id="op-test"):
    return lab.reviewed_environment(action=action, operation_id=operation_id)


def compose(env, **changes):
    arguments = {
        "peer": env.peer,
        "parent": env.parent,
        "proposal": env.proposal,
        "message": env.message,
        "source_token": env.source_token,
        "now": env.now,
    }
    arguments.update(changes)
    return run(env.adapter.compose(**arguments))


def assert_denied(code, callback):
    with pytest.raises(lab.CompositionDenied) as denied:
        callback()
    assert denied.value.code == code


def mutate_token(token, **changes):
    claims = jwt.decode(token, options={"verify_signature": False})
    claims.update(changes)
    return jwt.encode(claims, lab.TOKEN_KEY, algorithm="HS256")


def reissue(env, proposal, message=None, parent=None, peer=None):
    message = message or lab.build_a2a_message(proposal)
    token = lab.issue_source_grant(
        parent or env.parent,
        peer or env.peer,
        proposal,
        message,
        now=env.now,
    )
    return message, token


def target_token(env):
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    return env.adapter.exchange.exchange(
        env.source_token, context, env.message, now=env.now
    )


def test_demo_uses_both_official_sdks_and_proves_safe_reconciliation():
    result = lab.run_demo()
    assert result["sdk_types"] == {"a2a": "Message", "mcp": "MCPServer"}
    assert result["protocols"] == {"a2a": "1.0", "mcp": "2026-07-28"}
    assert result["unknown"]["state"] == "unknown"
    assert result["reconciled"]["state"] == "completed"
    assert result["reconciled"]["reconciled"] is True
    assert result["comment_effect_count"] == 1
    assert result["source_and_target_tokens_are_distinct"] is True
    assert result["campaign"] == {
        "cases": [
            ("valid-read", True, True),
            ("valid-comment", True, True),
            ("unknown-is-not-success", False, False),
            ("denial-is-not-retryable", False, False),
        ],
        "decision_accuracy": 1.0,
        "unsafe_allow_rate": 0.0,
        "false_block_rate": 0.0,
        "duplicate_effect_rate": 0,
    }


def test_a2a_message_is_real_wire_type_but_metadata_is_not_authority():
    env = environment()
    assert isinstance(env.message, Message)
    assert env.message.DESCRIPTOR.full_name == "lf.a2a.v1.Message"
    assert env.message.metadata["tenantHint"] == "untrusted"
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    assert context.tenant_id == env.peer.tenant_id == "acme"


def test_real_mcp_discovery_and_call_return_expected_ticket():
    env = environment()
    result = compose(env)
    assert result.state == lab.OutcomeState.COMPLETED
    assert result.result["ticket"]["ticket_id"] == "acme-7"
    assert result.result["operation_id"] == env.proposal.operation_id


def test_source_and_target_grants_are_audience_bound_and_attenuated():
    env = environment()
    source = lab.decode_grant(env.source_token, lab.SOURCE_AUDIENCE, now=env.now)
    child_token = target_token(env)
    child = lab.decode_grant(child_token, lab.TARGET_AUDIENCE, now=env.now)
    assert source["aud"] == lab.SOURCE_AUDIENCE
    assert child["aud"] == lab.TARGET_AUDIENCE
    assert child["parent_jti"] == source["jti"]
    assert child["actor"] == "protocol-adapter"
    assert child["act"] == {"sub": env.peer.agent_id}
    assert child["action"] == source["action"]
    assert child["resource"] == source["resource"]
    assert_denied(
        "GRANT_INVALID",
        lambda: lab.decode_grant(
            env.source_token, lab.TARGET_AUDIENCE, now=env.now
        ),
    )
    assert_denied(
        "GRANT_INVALID",
        lambda: lab.decode_grant(
            child_token, lab.SOURCE_AUDIENCE, now=env.now
        ),
    )


@pytest.mark.parametrize(
    "peer_change,code",
    [
        ({"agent_id": "unreviewed-agent"}, "A2A_PEER_NOT_TRUSTED"),
        ({"workload_id": "spiffe://evil.test/a2a/triage"}, "A2A_PEER_NOT_TRUSTED"),
        ({"tenant_id": "other"}, "A2A_TENANT_MISMATCH"),
    ],
)
def test_adapter_uses_authenticated_peer_not_claimed_message_identity(
    peer_change, code
):
    env = environment()
    assert_denied(
        code,
        lambda: compose(env, peer=replace(env.peer, **peer_change)),
    )


@pytest.mark.parametrize(
    "proposal_change,code",
    [
        ({"skill_id": "admin-everything"}, "SKILL_NOT_MAPPED"),
        ({"deadline": lab.utc("2026-10-28T20:00:00Z")}, "REQUEST_DEADLINE_EXPIRED"),
        ({"traceparent": "trace-1"}, "TRACE_CONTEXT_INVALID"),
        (
            {
                "traceparent": (
                    "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
                )
            },
            "TRACE_CONTEXT_INVALID",
        ),
    ],
)
def test_adapter_rejects_unmapped_expired_or_malformed_proposals(
    proposal_change, code
):
    env = environment()
    proposal = replace(env.proposal, **proposal_change)
    message = lab.build_a2a_message(proposal)
    assert_denied(
        code,
        lambda: env.adapter.normalize(
            env.peer, env.parent, proposal, message, now=env.now
        ),
    )


def test_message_and_application_proposal_must_match_exactly():
    env = environment()
    different = replace(env.proposal, attempt_id="attempt-2")
    assert_denied(
        "A2A_MESSAGE_PROPOSAL_MISMATCH",
        lambda: env.adapter.normalize(
            env.peer, env.parent, different, env.message, now=env.now
        ),
    )


def test_malformed_a2a_part_fails_closed():
    env = environment()
    malformed = Message(
        message_id=env.message.message_id,
        context_id=env.message.context_id,
        role=env.message.role,
        parts=[],
    )
    assert_denied(
        "A2A_MESSAGE_SHAPE_INVALID",
        lambda: env.adapter.normalize(
            env.peer, env.parent, env.proposal, malformed, now=env.now
        ),
    )


@pytest.mark.parametrize(
    "parent_change,code",
    [
        ({"actions": ("ticket.comment",)}, "SOURCE_ACTION_ESCALATION"),
        ({"resources": ("ticket://acme/acme-8",)}, "SOURCE_RESOURCE_ESCALATION"),
        ({"purpose": "train-model"}, "SOURCE_PURPOSE_ESCALATION"),
        (
            {"expires_at": lab.utc("2026-10-28T20:00:00Z")},
            "SOURCE_AUTHORITY_EXPIRED",
        ),
    ],
)
def test_source_grant_is_a_strict_subset_of_parent(parent_change, code):
    env = environment()
    assert_denied(
        code,
        lambda: lab.issue_source_grant(
            replace(env.parent, **parent_change),
            env.peer,
            env.proposal,
            env.message,
            now=env.now,
        ),
    )


@pytest.mark.parametrize(
    "claim,value,code",
    [
        ("action", "ticket.comment", "GRANT_ACTION_MISMATCH"),
        ("resource", "ticket://acme/acme-8", "GRANT_RESOURCE_MISMATCH"),
        ("tenant", "other", "GRANT_TENANT_MISMATCH"),
        ("purpose", "train-model", "GRANT_PURPOSE_MISMATCH"),
        ("operation_id", "other-op", "GRANT_OPERATION_ID_MISMATCH"),
        ("a2a_version", "0.3", "GRANT_A2A_VERSION_MISMATCH"),
        ("policy_version", "old-policy", "GRANT_POLICY_VERSION_MISMATCH"),
    ],
)
def test_exchange_rejects_context_loss_or_authority_widening(claim, value, code):
    env = environment()
    tampered = mutate_token(env.source_token, **{claim: value})
    assert_denied(
        code,
        lambda: compose(env, source_token=tampered),
    )


def test_exchange_rejects_wrong_audience_bad_signature_and_expiry():
    env = environment()
    wrong_audience = mutate_token(env.source_token, aud="adapter://other")
    bad_signature = jwt.encode(
        jwt.decode(env.source_token, options={"verify_signature": False}),
        "attacker-key-that-is-long-enough-for-hs256",
        algorithm="HS256",
    )
    expired = mutate_token(env.source_token, exp=int(env.now.timestamp()))
    for token in (wrong_audience, bad_signature):
        assert_denied("GRANT_INVALID", lambda token=token: compose(env, source_token=token))
    assert_denied("GRANT_EXPIRED", lambda: compose(env, source_token=expired))


def test_grant_is_bound_to_exact_a2a_message_digest():
    env = environment()
    env.message.metadata["extra"] = "changed-after-issuance"
    assert_denied(
        "GRANT_MESSAGE_DIGEST_MISMATCH",
        lambda: compose(env),
    )


def test_read_requires_no_approval_but_comment_requires_trusted_receipt():
    assert compose(environment(action="read")).state == lab.OutcomeState.COMPLETED
    env = environment(action="comment")
    env.approvals._receipts.clear()
    assert_denied("APPROVAL_REQUIRED", lambda: compose(env))


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("subject", "user:other:9", "APPROVAL_BINDING_MISMATCH"),
        ("actor", "other-agent", "APPROVAL_BINDING_MISMATCH"),
        ("tenant_id", "other", "APPROVAL_BINDING_MISMATCH"),
        ("resource", "ticket://acme/acme-8", "APPROVAL_BINDING_MISMATCH"),
        ("operation_id", "other-op", "APPROVAL_BINDING_MISMATCH"),
        ("effect_digest", "0" * 64, "APPROVAL_BINDING_MISMATCH"),
        ("policy_version", "old", "APPROVAL_BINDING_MISMATCH"),
        ("signature", "0" * 64, "APPROVAL_SIGNATURE_INVALID"),
    ],
)
def test_approval_is_bound_to_exact_effect_and_integrity(field, value, code):
    env = environment(action="comment")
    receipt = env.approvals._receipts[env.proposal.approval_id]
    changed = replace(receipt, **{field: value})
    if field != "signature":
        changed = replace(changed, signature="")
        changed = replace(changed, signature=env.approvals._sign(changed))
    env.approvals.replace(changed)
    assert_denied(code, lambda: compose(env))


def test_approval_expiry_and_future_issue_are_denied():
    for field, value in (
        ("expires_at", lab.utc("2026-10-28T20:00:00Z")),
        ("issued_at", lab.utc("2026-10-28T20:01:00Z")),
    ):
        env = environment(action="comment")
        receipt = env.approvals._receipts[env.proposal.approval_id]
        changed = replace(receipt, **{field: value}, signature="")
        changed = replace(changed, signature=env.approvals._sign(changed))
        env.approvals.replace(changed)
        assert_denied("APPROVAL_EXPIRED", lambda env=env: compose(env))


def test_approval_is_consumed_at_effect_boundary_not_adapter_precheck():
    env = environment(action="comment")
    receipt = env.approvals._receipts[env.proposal.approval_id]
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    env.approvals.require(
        env.proposal.approval_id,
        context,
        env.proposal.arguments(),
        now=env.now,
        consume=False,
    )
    assert env.approvals._receipts[receipt.approval_id].consumed is False
    compose(env)
    assert env.approvals._receipts[receipt.approval_id].consumed is True


def test_contract_drift_blocks_before_tool_execution():
    env = environment()
    env.adapter.reviewed_tools = {
        **lab.REVIEWED_TOOL_VIEWS,
        "ticket.admin": {
            "name": "ticket.admin",
            "fields": (),
            "types": (),
            "required": (),
            "additional_properties": None,
        },
    }
    assert_denied("MCP_TOOL_SET_DRIFT", lambda: compose(env))
    assert env.target.effect_ledger == {}


def test_contract_schema_change_is_distinct_from_tool_set_change():
    env = environment()
    altered = dict(lab.REVIEWED_TOOL_VIEWS["ticket.read"])
    altered["required"] = ()
    env.adapter.reviewed_tools = {
        **lab.REVIEWED_TOOL_VIEWS,
        "ticket.read": altered,
    }
    assert_denied("MCP_TOOL_CONTRACT_DRIFT", lambda: compose(env))


def test_cancel_before_dispatch_has_no_effect_and_is_not_retryable():
    env = environment(action="comment")
    env.adapter.cancel(env.proposal.operation_id)
    outcome = compose(env)
    assert outcome.state == lab.OutcomeState.CANCELLED
    assert outcome.retryable is False
    assert env.target.comments == []
    assert env.approvals._receipts[env.proposal.approval_id].consumed is False


def test_transient_before_effect_is_retryable_and_has_no_effect():
    env = environment(action="comment")
    outcome = compose(env, simulate="transient-before-effect")
    assert outcome.state == lab.OutcomeState.TRANSIENT
    assert outcome.retryable is True
    assert env.target.comments == []
    assert env.adapter.ledger == {}


def test_timeout_after_commit_is_unknown_then_reconciled_without_duplicate():
    env = environment(action="comment")
    unknown = compose(env, simulate="response-loss-after-effect")
    assert unknown.state == lab.OutcomeState.UNKNOWN
    assert unknown.retryable is True
    assert len(env.target.comments) == 1
    reconciled = compose(env)
    assert reconciled.state == lab.OutcomeState.COMPLETED
    assert reconciled.code == "RECONCILED"
    assert reconciled.reconciled is True
    assert len(env.target.comments) == 1


def test_same_operation_with_changed_effect_is_idempotency_conflict():
    env = environment(action="comment")
    compose(env, simulate="response-loss-after-effect")
    changed = replace(env.proposal, comment="Different comment", attempt_id="attempt-2")
    changed_message, changed_token = reissue(env, changed)
    assert_denied(
        "ADAPTER_IDEMPOTENCY_CONFLICT",
        lambda: compose(
            env,
            proposal=changed,
            message=changed_message,
            source_token=changed_token,
        ),
    )
    assert len(env.target.comments) == 1


def test_completed_operation_replay_returns_cached_result_without_second_effect():
    env = environment(action="comment")
    first = compose(env)
    second = compose(env)
    assert first.result == second.result
    assert second.reconciled is True
    assert len(env.target.comments) == 1


@pytest.mark.parametrize(
    "code,effect_possible,state,retryable",
    [
        ("TARGET_TENANT_DENIED", False, lab.OutcomeState.DENIED, False),
        ("APPROVAL_REQUIRED", False, lab.OutcomeState.DENIED, False),
        ("TRACE_CONTEXT_INVALID", False, lab.OutcomeState.INVALID, False),
        ("UPSTREAM_UNAVAILABLE", False, lab.OutcomeState.TRANSIENT, True),
        ("RATE_LIMITED", False, lab.OutcomeState.TRANSIENT, True),
        ("CONNECTION_LOST", True, lab.OutcomeState.UNKNOWN, True),
        ("novel-error", False, lab.OutcomeState.INVALID, False),
    ],
)
def test_failure_mapping_never_turns_denial_or_unknown_into_success(
    code, effect_possible, state, retryable
):
    outcome = lab.classify_failure(code, effect_possible=effect_possible)
    assert outcome.state == state
    assert outcome.retryable is retryable


def test_trace_continuity_preserves_trace_id_and_changes_span_per_hop():
    outcome = compose(environment())
    trace_ids = {entry["traceparent"].split("-")[1] for entry in outcome.trace}
    span_ids = [entry["traceparent"].split("-")[2] for entry in outcome.trace]
    assert trace_ids == {"4bf92f3577b34da6a3ce929d0e0e4736"}
    assert len(set(span_ids)) == len(span_ids)
    assert all(lab.TRACEPARENT_RE.fullmatch(entry["traceparent"]) for entry in outcome.trace)


def test_attempt_id_is_not_the_logical_idempotency_key():
    env = environment()
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    assert context.operation_id == "op-test"
    assert context.attempt_id == "attempt-1"
    assert context.operation_id != context.attempt_id


def test_target_token_contains_no_broad_scope_or_source_audience():
    env = environment()
    claims = lab.decode_grant(target_token(env), lab.TARGET_AUDIENCE, now=env.now)
    assert "scope" not in claims
    assert claims["aud"] != lab.SOURCE_AUDIENCE
    assert claims["resource"] == "ticket://acme/acme-7"
    assert claims["action"] == "ticket.read"


def test_grant_lifetime_is_bounded_by_deadline_and_parent():
    env = environment()
    source = lab.decode_grant(env.source_token, lab.SOURCE_AUDIENCE, now=env.now)
    child = lab.decode_grant(target_token(env), lab.TARGET_AUDIENCE, now=env.now)
    assert source["exp"] <= int(env.proposal.deadline.timestamp())
    assert child["exp"] <= source["exp"]
    assert child["exp"] - child["iat"] <= lab.MAX_GRANT_SECONDS


def test_policy_versions_and_protocol_versions_are_explicit_evidence():
    env = environment()
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    assert context.source_version == lab.A2A_PROTOCOL_VERSION == "1.0"
    assert context.target_version == lab.MCP_PROTOCOL_VERSION == "2026-07-28"
    assert context.policy_version == lab.POLICY_VERSION


def test_source_grant_rejects_tenant_mismatch_between_parent_and_peer():
    env = environment()
    peer = replace(env.peer, tenant_id="other")
    assert_denied(
        "SOURCE_IDENTITY_MISMATCH",
        lambda: lab.issue_source_grant(
            env.parent, peer, env.proposal, env.message, now=env.now
        ),
    )


def test_child_traceparent_rejects_invalid_parent_and_is_deterministic():
    valid = environment().proposal.traceparent
    assert lab.child_traceparent(valid, "hop") == lab.child_traceparent(valid, "hop")
    assert lab.child_traceparent(valid, "hop") != lab.child_traceparent(valid, "other")
    assert_denied(
        "TRACE_CONTEXT_INVALID", lambda: lab.child_traceparent("bad", "hop")
    )


def test_receipt_replay_is_rejected_if_target_is_called_outside_adapter_cache():
    env = environment(action="comment")
    compose(env)
    receipt = env.approvals._receipts[env.proposal.approval_id]
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    assert receipt.consumed is True
    assert_denied(
        "APPROVAL_ALREADY_CONSUMED",
        lambda: env.approvals.require(
            env.proposal.approval_id,
            context,
            env.proposal.arguments(),
            now=env.now,
            consume=True,
        ),
    )


def test_unknown_unmapped_failure_fails_closed():
    result = lab.classify_failure("brand-new-error")
    assert result.state == lab.OutcomeState.INVALID
    assert result.code == "UNMAPPED_FAILURE"
    assert result.retryable is False


def test_stable_resource_identifier_includes_authenticated_tenant():
    env = environment()
    context = env.adapter.normalize(
        env.peer, env.parent, env.proposal, env.message, now=env.now
    )
    assert context.resource == lab.resource_for(env.peer.tenant_id, "acme-7")
    assert context.resource == "ticket://acme/acme-7"


def test_adapter_ledger_starts_only_after_preflight_security_checks():
    env = environment(action="comment")
    env.approvals._receipts.clear()
    assert_denied("APPROVAL_REQUIRED", lambda: compose(env))
    assert env.adapter.ledger == {}
    assert env.target.comments == []


def test_runtime_cannot_select_arbitrary_mcp_tool_name():
    env = environment()
    proposal = replace(env.proposal, skill_id="ticket.comment")
    message = lab.build_a2a_message(proposal)
    assert_denied(
        "SKILL_NOT_MAPPED",
        lambda: env.adapter.normalize(
            env.peer, env.parent, proposal, message, now=env.now
        ),
    )


def test_source_grant_does_not_expire_after_parent():
    env = environment()
    parent = replace(env.parent, expires_at=env.now + timedelta(seconds=30))
    token = lab.issue_source_grant(
        parent, env.peer, env.proposal, env.message, now=env.now
    )
    claims = lab.decode_grant(token, lab.SOURCE_AUDIENCE, now=env.now)
    assert claims["exp"] == int(parent.expires_at.timestamp())
