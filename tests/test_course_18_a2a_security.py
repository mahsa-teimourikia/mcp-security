"""Executable security invariants for Course 18 A2A delegation."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

from a2a.types import Message, Role, Task, TaskState, TaskStatus
from hypothesis import given, settings, strategies as st
import jwt
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/18-agent-to-agent-a2a-security-delegation/lab.py"
SPEC = importlib.util.spec_from_file_location("course_18_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.utc("2026-10-25T19:00:00Z")
PUBLIC_IP = ("93.184.216.34",)


def environment():
    return lab.reviewed_environment(NOW)


def issue(env, *, parent=None, sender=None, request=None, recipient="support-agent", now=NOW):
    return env.broker.issue(
        parent=parent or env.parent,
        sender=sender or env.sender,
        recipient_agent_id=recipient,
        request=request or env.request,
        now=now,
    )


def receive(env, *, principal=None, request=None, message=None, token=None, now=NOW, ips=PUBLIC_IP):
    return env.server.receive(
        principal=principal or env.sender,
        request=request or env.request,
        message=message or env.message,
        task_grant=token or env.token,
        now=now,
        push_ips=ips,
    )


def mutate_token(token, **changes):
    claims = jwt.decode(token, options={"verify_signature": False})
    claims.update(changes)
    return jwt.encode(claims, lab.TOKEN_SIGNING_KEY, algorithm="HS256")


def resign_record(record, **changes):
    candidate = replace(record, **changes, record_signature="")
    return replace(candidate, record_signature=lab.sign_peer_record(candidate.unsigned()))


def assert_denied(code, callback):
    with pytest.raises(lab.A2ADenied) as denied:
        callback()
    assert denied.value.code == code


def test_demo_uses_official_sdk_and_proves_safe_unknown_outcome_retry():
    demo = lab.run_demo()
    assert demo["sdk_types"] == {"card": "AgentCard", "message": "Message", "task": "Task"}
    assert demo["task"]["state"] == "TASK_STATE_COMPLETED"
    assert demo["task"]["retry_same_task"] is True
    assert demo["retry_same_result"] is True
    assert demo["effect_count"] == 1
    assert demo["result"]["duplicate_effect"] is False
    assert demo["campaign"]["metrics"] == {
        "decision_accuracy": 1.0,
        "unsafe_allow_rate": 0.0,
        "false_block_rate": 0.0,
    }


def test_card_message_and_task_are_real_a2a_sdk_types():
    env = environment()
    assert env.recipient_card.DESCRIPTOR.full_name == "lf.a2a.v1.AgentCard"
    assert env.message.DESCRIPTOR.full_name == "lf.a2a.v1.Message"
    task, _ = receive(env)
    assert task.DESCRIPTOR.full_name == "lf.a2a.v1.Task"
    assert task.status.state == TaskState.TASK_STATE_COMPLETED


def test_card_digest_is_deterministic_and_changes_with_card_version():
    assert lab.card_digest(lab.build_agent_card()) == lab.card_digest(lab.build_agent_card())
    assert lab.card_digest(lab.build_agent_card(version="2.4.1")) != lab.card_digest(
        lab.build_agent_card(version="2.4.0")
    )


def test_wire_message_carries_task_data_but_not_authority():
    env = environment()
    message = env.message
    assert message.message_id == env.request.message_id
    assert message.context_id == env.request.context_id
    assert message.role == Role.ROLE_USER
    assert message.metadata["authorization"] == "untrusted"
    assert env.token not in message.SerializeToString().decode(errors="ignore")


@pytest.mark.parametrize(
    "url",
    [
        "http://agent.example.test/a2a",
        "https://user:pass@agent.example.test/a2a",
        "https://agent.example.test/a2a#fragment",
        "not-a-url",
    ],
)
def test_peer_admission_requires_unambiguous_https_endpoint(url):
    card = lab.build_agent_card()
    card.supported_interfaces[0].url = url
    directory = lab.PeerDirectory()
    assert_denied(
        "AGENT_ENDPOINT_INVALID",
        lambda: directory.admit(
            agent_id="peer",
            card=card,
            workload_id="spiffe://acme.test/peer",
            tenants=("acme",),
            supported_extensions=(lab.REQUIRED_EXTENSION,),
            now=NOW,
        ),
    )


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"agent_id": ""}, "PEER_IDENTITY_INVALID"),
        ({"workload_id": "dns://agent"}, "PEER_IDENTITY_INVALID"),
        ({"tenants": ()}, "PEER_TENANT_INVALID"),
    ],
)
def test_peer_admission_rejects_incomplete_trust_evidence(mutation, code):
    arguments = {
        "agent_id": "peer",
        "card": lab.build_agent_card(),
        "workload_id": "spiffe://acme.test/peer",
        "tenants": ("acme",),
        "supported_extensions": (lab.REQUIRED_EXTENSION,),
        "now": NOW,
    }
    arguments.update(mutation)
    assert_denied(code, lambda: lab.PeerDirectory().admit(**arguments))


def test_peer_admission_rejects_wrong_protocol_version_and_empty_skills():
    card = lab.build_agent_card()
    card.supported_interfaces[0].protocol_version = "0.3"
    assert_denied(
        "PROTOCOL_VERSION_UNSUPPORTED",
        lambda: lab.PeerDirectory().admit(
            agent_id="peer",
            card=card,
            workload_id="spiffe://acme.test/peer",
            tenants=("acme",),
            supported_extensions=(),
            now=NOW,
        ),
    )
    card = lab.build_agent_card()
    del card.skills[:]
    assert_denied(
        "PEER_SKILL_INVALID",
        lambda: lab.PeerDirectory().admit(
            agent_id="peer",
            card=card,
            workload_id="spiffe://acme.test/peer",
            tenants=("acme",),
            supported_extensions=(),
            now=NOW,
        ),
    )


@pytest.mark.parametrize(
    "record_change,principal_change,tenant,when,code",
    [
        ({"state": lab.PeerState.SUSPENDED}, {}, "acme", NOW, "PEER_NOT_ACTIVE"),
        ({"state": lab.PeerState.REVOKED}, {}, "acme", NOW, "PEER_NOT_ACTIVE"),
        ({"expires_at": NOW}, {}, "acme", NOW, "PEER_REVIEW_EXPIRED"),
        ({"reviewed_at": NOW + timedelta(minutes=1)}, {}, "acme", NOW, "PEER_REVIEW_FROM_FUTURE"),
        ({"record_signature": "0" * 64}, {}, "acme", NOW, "PEER_RECORD_SIGNATURE_INVALID"),
        ({}, {"spiffe_id": "spiffe://evil.test/peer"}, "acme", NOW, "WORKLOAD_IDENTITY_MISMATCH"),
        ({}, {"tenant_id": "other"}, "other", NOW, "PEER_TENANT_DENIED"),
    ],
)
def test_peer_directory_enforces_lifecycle_identity_and_tenant(
    record_change, principal_change, tenant, when, code
):
    env = environment()
    record = replace(env.peer_record, **record_change)
    if "record_signature" not in record_change:
        record = resign_record(env.peer_record, **record_change)
    env.directory.replace(record)
    principal = replace(env.sender, **principal_change)
    assert_denied(
        code,
        lambda: env.directory.require_peer(principal, tenant_id=tenant, now=when),
    )


def test_unknown_peer_is_not_authorized_by_claimed_agent_id():
    env = environment()
    stranger = replace(env.sender, agent_id="unknown")
    assert_denied(
        "PEER_NOT_REVIEWED",
        lambda: env.directory.require_peer(stranger, tenant_id="acme", now=NOW),
    )


@pytest.mark.parametrize(
    "request_change,parent_change,code",
    [
        ({"tenant_id": "other"}, {}, "DELEGATION_TENANT_ESCALATION"),
        ({"action": "ticket.delete"}, {}, "DELEGATION_ACTION_ESCALATION"),
        ({"resource": "ticket/acme-99"}, {}, "DELEGATION_RESOURCE_ESCALATION"),
        ({"purpose": "marketing"}, {}, "DELEGATION_PURPOSE_ESCALATION"),
        ({}, {"expires_at": NOW}, "PARENT_AUTHORITY_EXPIRED"),
        ({}, {"delegation_depth": lab.MAX_DELEGATION_DEPTH}, "DELEGATION_DEPTH_EXCEEDED"),
        ({}, {"chain": ("human-user", "triage-agent")}, "DELEGATION_LOOP"),
        ({}, {"chain": ("human-user", "support-agent")}, "DELEGATION_LOOP"),
    ],
)
def test_broker_attenuates_parent_authority(request_change, parent_change, code):
    env = environment()
    request = replace(env.request, **request_change)
    parent = replace(env.parent, **parent_change)
    assert_denied(code, lambda: issue(env, parent=parent, request=request))


def test_grant_contains_subject_actor_recipient_and_exact_task_bounds():
    env = environment()
    claims = jwt.decode(
        env.token,
        lab.TOKEN_SIGNING_KEY,
        algorithms=["HS256"],
        audience="support-agent",
        issuer=lab.TOKEN_ISSUER,
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )
    assert claims["sub"] == "user-123"
    assert claims["act"] == "triage-agent"
    assert claims["aud"] == "support-agent"
    expected = {
        "tenant": env.request.tenant_id,
        "action": env.request.action,
        "resource": env.request.resource,
        "purpose": env.request.purpose,
        "message_id": env.request.message_id,
        "operation_id": env.request.operation_id,
    }
    for key, value in expected.items():
        assert claims[key] == value
    assert claims["exp"] - claims["iat"] <= lab.MAX_DELEGATION_SECONDS
    assert claims["parent_digest"] == lab.digest(env.parent)


@pytest.mark.parametrize(
    "claim,value,code",
    [
        ("aud", "other-agent", "TASK_GRANT_WRONG_AUDIENCE"),
        ("act", "other-agent", "TASK_GRANT_ACT_MISMATCH"),
        ("tenant", "other", "TASK_GRANT_TENANT_MISMATCH"),
        ("action", "ticket.delete", "TASK_GRANT_ACTION_MISMATCH"),
        ("resource", "ticket/acme-99", "TASK_GRANT_RESOURCE_MISMATCH"),
        ("purpose", "marketing", "TASK_GRANT_PURPOSE_MISMATCH"),
        ("message_id", "other-message", "TASK_GRANT_MESSAGE_ID_MISMATCH"),
        ("operation_id", "other-operation", "TASK_GRANT_OPERATION_ID_MISMATCH"),
        ("context_id", "other-context", "TASK_GRANT_CONTEXT_ID_MISMATCH"),
        ("protocol_version", "0.3", "TASK_GRANT_PROTOCOL_VERSION_MISMATCH"),
        ("card_digest", "0" * 64, "TASK_GRANT_CARD_DIGEST_MISMATCH"),
        ("extensions", ["https://evil.test/ext"], "TASK_GRANT_EXTENSIONS_MISMATCH"),
        ("depth", 0, "TASK_GRANT_DEPTH_INVALID"),
        ("depth", 99, "TASK_GRANT_DEPTH_INVALID"),
        ("chain", ["triage-agent", "triage-agent"], "TASK_GRANT_CHAIN_LOOP"),
    ],
)
def test_recipient_rejects_mutated_but_resigned_grants(claim, value, code):
    env = environment()
    token = mutate_token(env.token, **{claim: value})
    assert_denied(
        code,
        lambda: lab.verify_task_grant(
            token,
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )


def test_recipient_rejects_invalid_expiry_nbf_iat_and_signature():
    env = environment()
    assert_denied(
        "TASK_GRANT_EXPIRED",
        lambda: lab.verify_task_grant(
            mutate_token(env.token, exp=lab.timestamp(NOW) - 10),
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )
    assert_denied(
        "TASK_GRANT_NOT_YET_VALID",
        lambda: lab.verify_task_grant(
            mutate_token(env.token, nbf=lab.timestamp(NOW) + 60),
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )
    assert_denied(
        "TASK_GRANT_ISSUED_IN_FUTURE",
        lambda: lab.verify_task_grant(
            mutate_token(env.token, iat=lab.timestamp(NOW) + 60),
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )
    claims = jwt.decode(env.token, options={"verify_signature": False})
    claims["exp"] = claims["iat"] + lab.MAX_DELEGATION_SECONDS + 1
    assert_denied(
        "TASK_GRANT_LIFETIME_EXCESSIVE",
        lambda: lab.verify_task_grant(
            jwt.encode(claims, lab.TOKEN_SIGNING_KEY, algorithm="HS256"),
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )
    assert_denied(
        "TASK_GRANT_INVALID",
        lambda: lab.verify_task_grant(
            env.token + "tampered",
            recipient_agent_id="support-agent",
            sender=env.sender,
            request=env.request,
            now=NOW,
        ),
    )


@pytest.mark.parametrize(
    "request_change,message_change,code",
    [
        ({"message_id": ""}, {}, "TASK_IDENTIFIERS_INVALID"),
        ({"operation_id": ""}, {}, "TASK_IDENTIFIERS_INVALID"),
        ({"context_id": ""}, {}, "TASK_IDENTIFIERS_INVALID"),
        ({"protocol_version": "0.3"}, {}, "PROTOCOL_VERSION_UNSUPPORTED"),
        ({"card_digest": "0" * 64}, {}, "RECIPIENT_CARD_DRIFT"),
        ({"skill_id": "admin"}, {}, "SKILL_NOT_ADVERTISED"),
        ({"required_extensions": ("https://evil.test/ext",)}, {}, "REQUIRED_EXTENSION_UNSUPPORTED"),
        (
            {"required_extensions": (lab.REQUIRED_EXTENSION, lab.REQUIRED_EXTENSION)},
            {},
            "REQUIRED_EXTENSION_DUPLICATE",
        ),
        ({}, {"message_id": "other"}, "MESSAGE_ID_MISMATCH"),
        ({}, {"context_id": "other"}, "CONTEXT_ID_MISMATCH"),
        ({}, {"task_id": "client-picked"}, "CLIENT_TASK_ID_NOT_ALLOWED"),
        ({}, {"role": Role.ROLE_AGENT}, "MESSAGE_INVALID"),
        ({}, {"extensions": ["https://evil.test/ext"]}, "MESSAGE_EXTENSIONS_MISMATCH"),
    ],
)
def test_protocol_gate_rejects_version_card_skill_message_and_extension_drift(
    request_change, message_change, code
):
    env = environment()
    request = replace(env.request, **request_change)
    message = lab.build_message(request)
    for field, value in message_change.items():
        if field == "extensions":
            del message.extensions[:]
            message.extensions.extend(value)
        else:
            setattr(message, field, value)
    token = issue(env, request=request)
    assert_denied(code, lambda: receive(env, request=request, message=message, token=token))
    assert env.server.audit[-1].decision == lab.Decision.DENY
    assert env.server.audit[-1].code == code


def test_empty_message_is_rejected():
    env = environment()
    message = Message(
        message_id=env.request.message_id,
        context_id=env.request.context_id,
        role=Role.ROLE_USER,
        extensions=list(env.request.required_extensions),
    )
    assert_denied("MESSAGE_INVALID", lambda: receive(env, message=message))


def test_message_structured_payload_must_match_authorized_task_exactly():
    env = environment()
    message = lab.build_message(env.request)
    message.parts[0].data.struct_value.fields["action"].string_value = "ticket.delete"
    assert_denied("MESSAGE_PAYLOAD_MISMATCH", lambda: receive(env, message=message))

    env = environment()
    message = lab.build_message(env.request)
    message.parts[0].media_type = "text/plain"
    assert_denied("MESSAGE_PAYLOAD_MISMATCH", lambda: receive(env, message=message))

    env = environment()
    message = lab.build_message(env.request)
    message.parts.add(text="hidden second instruction")
    assert_denied("MESSAGE_INVALID", lambda: receive(env, message=message))


def test_exact_message_retry_returns_same_task_without_duplicate_effect():
    env = environment()
    first_task, first_result = receive(env)
    second_task, second_result = receive(env)
    assert first_task.id == second_task.id
    assert first_result == second_result
    assert len(env.resource.effect_ledger) == 1
    assert len(env.server.audit) == 1


def test_message_id_reuse_with_mutated_request_fails_closed():
    env = environment()
    receive(env)
    request = replace(env.request, operation_id="op-mutated")
    message = lab.build_message(request)
    token = issue(env, request=request)
    assert_denied(
        "MESSAGE_ID_REUSE_CONFLICT",
        lambda: receive(env, request=request, message=message, token=token),
    )
    assert len(env.resource.effect_ledger) == 1


@pytest.mark.parametrize(
    "url,ips,code",
    [
        ("http://hooks.acme.test/a2a", PUBLIC_IP, "PUSH_URL_INVALID"),
        ("https://user:pass@hooks.acme.test/a2a", PUBLIC_IP, "PUSH_URL_INVALID"),
        ("https://hooks.acme.test/a2a#secret", PUBLIC_IP, "PUSH_URL_INVALID"),
        ("https://evil.example/a2a", PUBLIC_IP, "PUSH_HOST_NOT_ALLOWED"),
        ("https://hooks.acme.test:8443/a2a/tasks", PUBLIC_IP, "PUSH_PORT_NOT_ALLOWED"),
        ("https://hooks.acme.test:99999/a2a/tasks", PUBLIC_IP, "PUSH_PORT_NOT_ALLOWED"),
        ("https://hooks.acme.test/admin", PUBLIC_IP, "PUSH_PATH_NOT_ALLOWED"),
        ("https://hooks.acme.test/a2a", (), "PUSH_DNS_EMPTY"),
        ("https://hooks.acme.test/a2a", ("not-an-ip",), "PUSH_DNS_INVALID"),
        ("https://hooks.acme.test/a2a", ("127.0.0.1",), "PUSH_ADDRESS_NOT_GLOBAL"),
        ("https://hooks.acme.test/a2a", ("10.0.0.8",), "PUSH_ADDRESS_NOT_GLOBAL"),
        ("https://hooks.acme.test/a2a", ("169.254.169.254",), "PUSH_ADDRESS_NOT_GLOBAL"),
        ("https://hooks.acme.test/a2a", ("::1",), "PUSH_ADDRESS_NOT_GLOBAL"),
    ],
)
def test_push_notification_url_policy_blocks_ssrf(url, ips, code):
    assert_denied(code, lambda: lab.validate_push_url(url, resolved_ips=ips))


def test_push_notification_url_policy_accepts_reviewed_public_endpoint():
    assert (
        lab.validate_push_url("https://hooks.acme.test/a2a/tasks", resolved_ips=PUBLIC_IP)
        == "https://hooks.acme.test/a2a/tasks"
    )


@pytest.mark.parametrize(
    "start,end",
    [
        (TaskState.TASK_STATE_SUBMITTED, TaskState.TASK_STATE_WORKING),
        (TaskState.TASK_STATE_SUBMITTED, TaskState.TASK_STATE_REJECTED),
        (TaskState.TASK_STATE_WORKING, TaskState.TASK_STATE_INPUT_REQUIRED),
        (TaskState.TASK_STATE_WORKING, TaskState.TASK_STATE_AUTH_REQUIRED),
        (TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_WORKING),
        (TaskState.TASK_STATE_AUTH_REQUIRED, TaskState.TASK_STATE_CANCELED),
    ],
)
def test_documented_task_lifecycle_transitions_are_allowed(start, end):
    task = Task(id="task-1", context_id="ctx-1", status=TaskStatus(state=start))
    assert lab.transition(task, end).status.state == end
    assert task.status.state == start


@pytest.mark.parametrize(
    "start,end",
    [
        (TaskState.TASK_STATE_SUBMITTED, TaskState.TASK_STATE_COMPLETED),
        (TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_COMPLETED),
        (TaskState.TASK_STATE_COMPLETED, TaskState.TASK_STATE_WORKING),
        (TaskState.TASK_STATE_FAILED, TaskState.TASK_STATE_WORKING),
        (TaskState.TASK_STATE_CANCELED, TaskState.TASK_STATE_WORKING),
        (TaskState.TASK_STATE_REJECTED, TaskState.TASK_STATE_WORKING),
    ],
)
def test_illegal_or_terminal_task_lifecycle_transitions_are_denied(start, end):
    task = Task(id="task-1", context_id="ctx-1", status=TaskStatus(state=start))
    assert_denied("TASK_TRANSITION_INVALID", lambda: lab.transition(task, end))


def test_resource_server_independently_enforces_audience_action_tenant_and_operation():
    env = environment()
    claims = lab.verify_task_grant(
        env.token,
        recipient_agent_id="support-agent",
        sender=env.sender,
        request=env.request,
        now=NOW,
    )
    for changes, code in (
        ({"aud": "coordinator"}, "RESOURCE_WRONG_AUDIENCE"),
        ({"action": "ticket.delete"}, "RESOURCE_ACTION_DENIED"),
        ({"tenant": "other"}, "RESOURCE_TOKEN_TENANT_MISMATCH"),
        ({"operation_id": ""}, "RESOURCE_OPERATION_ID_REQUIRED"),
    ):
        assert_denied(code, lambda changes=changes: env.resource.execute({**claims, **changes}, env.request))
    wrong_resource = replace(env.request, resource="ticket/other-1")
    assert_denied("RESOURCE_TENANT_DENIED", lambda: env.resource.execute(claims, wrong_resource))


def test_resource_operation_ledger_is_an_independent_effect_oracle():
    env = environment()
    claims = lab.verify_task_grant(
        env.token,
        recipient_agent_id="support-agent",
        sender=env.sender,
        request=env.request,
        now=NOW,
    )
    assert env.resource.execute(claims, env.request)["duplicate_effect"] is False
    assert env.resource.execute(claims, env.request)["duplicate_effect"] is True
    assert len(env.resource.effect_ledger) == 1


def test_audit_records_minimized_digests_not_bearer_tokens_or_message_content():
    env = environment()
    receive(env)
    event = env.server.audit[0]
    assert event.decision == lab.Decision.ALLOW
    assert event.authority_digest == lab.digest(env.token)
    assert env.token not in repr(event)
    assert "account-access" not in repr(event)


def test_direct_baseline_exposes_architecture_regret_signal():
    env = environment()
    assert lab.direct_baseline(env.parent, env.request, NOW)
    assert not lab.direct_baseline(env.parent, replace(env.request, action="ticket.delete"), NOW)
    assert not lab.direct_baseline(env.parent, env.request, env.parent.expires_at)
    demo = lab.run_demo()
    assert demo["architecture"]["a2a_boundary_checks"] > demo["architecture"][
        "direct_baseline_policy_checks"
    ]
    assert len(demo["architecture"]["extra_failure_domains"]) == 4


@settings(max_examples=40, deadline=None)
@given(
    action=st.sampled_from(["ticket.read", "ticket.delete", "ticket.comment"]),
    resource=st.sampled_from(["ticket/acme-7", "ticket/acme-8", "ticket/other-1"]),
    tenant=st.sampled_from(["acme", "other"]),
)
def test_property_child_authority_never_exceeds_parent(action, resource, tenant):
    env = environment()
    request = replace(env.request, action=action, resource=resource, tenant_id=tenant)
    should_issue = action == "ticket.read" and resource == "ticket/acme-7" and tenant == "acme"
    try:
        issue(env, request=request)
        issued = True
    except lab.A2ADenied:
        issued = False
    assert issued is should_issue


def test_campaign_covers_allow_and_multiple_independent_failure_planes():
    campaign = lab.run_campaign()
    assert len(campaign["results"]) == 9
    assert campaign["results"][0]["actual"] == lab.Decision.ALLOW
    denial_codes = {item["code"] for item in campaign["results"][1:]}
    assert {
        "DELEGATION_TENANT_ESCALATION",
        "DELEGATION_ACTION_ESCALATION",
        "DELEGATION_RESOURCE_ESCALATION",
        "WORKLOAD_IDENTITY_MISMATCH",
        "RECIPIENT_CARD_DRIFT",
        "REQUIRED_EXTENSION_UNSUPPORTED",
        "PUSH_ADDRESS_NOT_GLOBAL",
        "MESSAGE_ID_MISMATCH",
    } == denial_codes
