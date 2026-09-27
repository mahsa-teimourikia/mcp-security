"""Executable delegation and confused-deputy invariants for Course 08."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import importlib.util
import json
from pathlib import Path
import sys

from mcp import Client
import pytest
from pydantic import SecretStr, ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/08-delegation-token-exchange-confused-deputy/lab.py"
SPEC = importlib.util.spec_from_file_location("course_08_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = datetime(2026, 9, 27, 17, 0, tzinfo=UTC)


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def environment():
    return lab.default_environment(NOW)


def exchange(sts, parent, actor, **updates):
    values = {
        "exchange_id": "exchange-test-1",
        "resource": lab.TICKETS_API,
        "scopes": frozenset({"ticket:read"}),
        "resource_ids": ("acme-100",),
        "purpose": "support",
        "transaction_id": "txn-test-1",
        "ttl": 60,
    }
    values.update(updates)
    request = lab.exchange_request(parent, **values)
    return request, sts.exchange(request, actor=actor, now=NOW)


def child_token(response):
    return response.access_token.get_secret_value()


def test_end_to_end_scenario_uses_exchange_and_blocks_confused_deputy():
    evidence = run(lab.run_scenario())
    assert evidence["mcp_read_allowed"] is True
    assert evidence["cross_tenant_denied"] is True
    assert evidence["passthrough_reason"] == "SOURCE_AUDIENCE_INVALID"
    assert evidence["delegated_subject"] == "analyst-42"
    assert evidence["delegated_actor"] == "workload:support-mcp"
    assert evidence["accepted_parent_token"] is False
    assert evidence["revocation_reason"] == "DELEGATION_LINEAGE_REVOKED"


def test_exchange_response_is_rfc_shaped_and_has_no_refresh_token(environment):
    sts, _, parent, actor, _ = environment
    _, response = exchange(sts, parent, actor)
    assert response.issued_token_type == lab.ACCESS_TOKEN_TYPE
    assert response.token_type == "Bearer"
    assert response.scope == "ticket:read"
    assert response.expires_in == 60
    assert "refresh_token" not in type(response).model_fields


def test_child_is_signed_audience_bound_and_strictly_narrower(environment):
    sts, _, parent, actor, _ = environment
    _, response = exchange(sts, parent, actor)
    claims = sts.decode_for_resource(child_token(response), audience=lab.TICKETS_API, now=NOW)
    assert claims["sub"] == "analyst-42"
    assert claims["aud"] == lab.TICKETS_API
    assert claims["scope"] == "ticket:read"
    assert claims["resource_ids"] == ["acme-100"]
    assert claims["purpose"] == "support"
    assert claims["delegation_depth"] == 1
    assert claims["parent_jti"] == "root-grant-1"
    assert claims["exp"] <= int((NOW + timedelta(seconds=60)).timestamp())


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"scopes": frozenset({"ticket:write"})}, "SCOPE_ESCALATION"),
        ({"resource_ids": ("acme-101",)}, "RESOURCE_ESCALATION"),
        ({"resource_ids": ("globex-200",)}, "RESOURCE_ESCALATION"),
        ({"purpose": "analytics"}, "PURPOSE_ESCALATION"),
        ({"resource": "https://admin.example/api"}, "TARGET_NOT_ALLOWED"),
        ({"ttl": 100}, "TTL_EXCEEDS_TARGET_POLICY"),
    ],
)
def test_exchange_rejects_authority_expansion(environment, updates, reason):
    sts, _, parent, actor, _ = environment
    request = lab.exchange_request(parent, **updates)
    with pytest.raises(lab.ExchangeDenied) as denied:
        sts.exchange(request, actor=actor, now=NOW)
    assert denied.value.code == reason
    assert sts.events[-1].decision == "deny"
    assert sts.events[-1].reason_code == reason


def test_unregistered_or_spoofed_actor_cannot_exchange(environment):
    sts, _, parent, actor, _ = environment
    unregistered = lab.WorkloadIdentity(
        workload_id="workload:attacker", trust_domain="evil.example"
    )
    with pytest.raises(lab.ExchangeDenied) as missing:
        sts.exchange(lab.exchange_request(parent), actor=unregistered, now=NOW)
    assert missing.value.code == "ACTOR_NOT_REGISTERED"
    spoofed = actor.model_copy(update={"trust_domain": "evil.example"})
    with pytest.raises(lab.ExchangeDenied) as changed:
        sts.exchange(lab.exchange_request(parent), actor=spoofed, now=NOW)
    assert changed.value.code == "ACTOR_NOT_REGISTERED"


def test_subject_token_must_be_issued_for_exchanging_actor_resource(environment):
    sts, _, _, actor, _ = environment
    wrong_audience = sts.issue_subject_token(
        subject="analyst-42",
        tenant_id="acme",
        audience="https://other.example/api",
        scopes=frozenset({"ticket:read"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=NOW,
        jti="wrong-source-audience",
    )
    with pytest.raises(lab.ExchangeDenied) as denied:
        sts.exchange(lab.exchange_request(wrong_audience), actor=actor, now=NOW)
    assert denied.value.code == "SOURCE_AUDIENCE_INVALID"


def test_expired_or_revoked_subject_token_cannot_be_exchanged(environment):
    sts, _, parent, actor, _ = environment
    with pytest.raises(lab.ExchangeDenied) as expired:
        sts.exchange(
            lab.exchange_request(parent),
            actor=actor,
            now=NOW + timedelta(minutes=6),
        )
    assert expired.value.code == "TOKEN_EXPIRED"
    sts.revoke("root-grant-1")
    with pytest.raises(lab.ExchangeDenied) as revoked:
        sts.exchange(lab.exchange_request(parent), actor=actor, now=NOW)
    assert revoked.value.code == "SUBJECT_TOKEN_REVOKED"


def test_exchange_id_is_idempotent_for_exact_request(environment):
    sts, _, parent, actor, _ = environment
    request = lab.exchange_request(parent)
    first = sts.exchange(request, actor=actor, now=NOW)
    second = sts.exchange(request, actor=actor, now=NOW)
    assert first.access_token.get_secret_value() == second.access_token.get_secret_value()
    assert sts.events[-1].reason_code == "EXCHANGE_DEDUPLICATED"


def test_exchange_id_cannot_be_reused_for_changed_authority(environment):
    sts, _, parent, actor, _ = environment
    sts.exchange(lab.exchange_request(parent), actor=actor, now=NOW)
    changed = lab.exchange_request(
        parent,
        scopes=frozenset({"trace:append"}),
    )
    with pytest.raises(lab.ExchangeDenied) as denied:
        sts.exchange(changed, actor=actor, now=NOW)
    assert denied.value.code == "EXCHANGE_ID_CONFLICT"


def test_child_lifetime_is_capped_by_parent_expiry(environment):
    sts, _, _, actor, _ = environment
    short_parent = sts.issue_subject_token(
        subject="analyst-42",
        tenant_id="acme",
        audience=lab.MCP_RESOURCE,
        scopes=frozenset({"ticket:read"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=NOW,
        lifetime=timedelta(seconds=20),
        jti="short-parent",
    )
    request = lab.exchange_request(short_parent, ttl=60)
    response = sts.exchange(request, actor=actor, now=NOW)
    assert response.expires_in == 20


def test_multi_hop_chain_preserves_prior_actor_and_narrows_again(environment):
    sts, _, parent, support_actor, ticket_actor = environment
    first_request = lab.exchange_request(
        parent,
        scopes=frozenset({"ticket:read", "trace:append"}),
        transaction_id="txn-chain-1",
    )
    first = sts.exchange(first_request, actor=support_actor, now=NOW)
    second_request = lab.exchange_request(
        child_token(first),
        exchange_id="exchange-chain-2",
        resource=lab.AUDIT_API,
        scopes=frozenset({"trace:append"}),
        resource_ids=("acme-100",),
        purpose="support",
        transaction_id="txn-chain-1",
        ttl=30,
    )
    second = sts.exchange(second_request, actor=ticket_actor, now=NOW)
    claims = sts.decode_for_resource(child_token(second), audience=lab.AUDIT_API, now=NOW)
    assert claims["delegation_depth"] == 2
    assert claims["act"]["sub"] == "workload:ticket-api"
    assert claims["act"]["act"]["sub"] == "workload:support-mcp"
    assert claims["scope"] == "trace:append"


def test_multi_hop_transaction_cannot_drift(environment):
    sts, _, parent, support_actor, ticket_actor = environment
    first = sts.exchange(
        lab.exchange_request(
            parent,
            scopes=frozenset({"ticket:read", "trace:append"}),
            transaction_id="txn-chain-1",
        ),
        actor=support_actor,
        now=NOW,
    )
    changed = lab.exchange_request(
        child_token(first),
        exchange_id="exchange-chain-drift",
        resource=lab.AUDIT_API,
        scopes=frozenset({"trace:append"}),
        transaction_id="txn-other",
        ttl=30,
    )
    with pytest.raises(lab.ExchangeDenied) as denied:
        sts.exchange(changed, actor=ticket_actor, now=NOW)
    assert denied.value.code == "TRANSACTION_ESCALATION"


def test_maximum_delegation_depth_is_enforced(environment):
    sts, _, _, support_actor, ticket_actor = environment
    shallow_parent = sts.issue_subject_token(
        subject="analyst-42",
        tenant_id="acme",
        audience=lab.MCP_RESOURCE,
        scopes=frozenset({"ticket:read", "trace:append"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=NOW,
        max_delegation_depth=1,
        jti="shallow-root",
    )
    first = sts.exchange(
        lab.exchange_request(
            shallow_parent,
            scopes=frozenset({"ticket:read", "trace:append"}),
            transaction_id="txn-depth",
        ),
        actor=support_actor,
        now=NOW,
    )
    with pytest.raises(lab.ExchangeDenied) as denied:
        sts.exchange(
            lab.exchange_request(
                child_token(first),
                exchange_id="exchange-depth-2",
                resource=lab.AUDIT_API,
                scopes=frozenset({"trace:append"}),
                transaction_id="txn-depth",
                ttl=30,
            ),
            actor=ticket_actor,
            now=NOW,
        )
    assert denied.value.code == "DELEGATION_DEPTH_EXCEEDED"


def test_downstream_accepts_valid_caller_bound_child(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor)
    result = api.read_ticket(
        token=child_token(response),
        presenter=actor,
        ticket_id="acme-100",
        transaction_id=request.transaction_id,
        now=NOW,
    )
    assert result["delegated_subject"] == "analyst-42"
    assert result["delegated_actor"] == actor.workload_id
    assert api.events[-1].reason_code == "CALLER_BOUND_READ_ALLOWED"


def test_parent_token_passthrough_is_rejected_by_downstream_audience(environment):
    _, api, parent, actor, _ = environment
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=parent,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-passthrough",
            now=NOW,
        )
    assert denied.value.code == "SOURCE_AUDIENCE_INVALID"


def test_child_cannot_be_presented_by_another_workload(environment):
    sts, api, parent, actor, other_actor = environment
    request, response = exchange(sts, parent, actor)
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=child_token(response),
            presenter=other_actor,
            ticket_id="acme-100",
            transaction_id=request.transaction_id,
            now=NOW,
        )
    assert denied.value.code == "ACTOR_BINDING_INVALID"


def test_downstream_enforces_transaction_scope_resource_and_current_policy(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor)
    token = child_token(response)
    with pytest.raises(lab.DownstreamDenied) as transaction_denied:
        api.read_ticket(
            token=token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-different",
            now=NOW,
        )
    assert transaction_denied.value.code == "TRANSACTION_MISMATCH"
    with pytest.raises(lab.DownstreamDenied) as resource_denied:
        api.read_ticket(
            token=token,
            presenter=actor,
            ticket_id="acme-101",
            transaction_id=request.transaction_id,
            now=NOW,
        )
    assert resource_denied.value.code == "RESOURCE_NOT_DELEGATED"
    api.tickets["acme-100"] = replace(
        api.tickets["acme-100"], assigned_subject="analyst-99"
    )
    with pytest.raises(lab.DownstreamDenied) as policy_denied:
        api.read_ticket(
            token=token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id=request.transaction_id,
            now=NOW,
        )
    assert policy_denied.value.code == "CURRENT_RESOURCE_POLICY_DENIED"


def test_downstream_denies_child_without_required_scope(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(
        sts,
        parent,
        actor,
        scopes=frozenset({"trace:append"}),
    )
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=child_token(response),
            presenter=actor,
            ticket_id="acme-100",
            transaction_id=request.transaction_id,
            now=NOW,
        )
    assert denied.value.code == "SCOPE_DENIED"


def test_lineage_revocation_propagates_by_explicit_status_policy(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor)
    sts.revoke("root-grant-1")
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=child_token(response),
            presenter=actor,
            ticket_id="acme-100",
            transaction_id=request.transaction_id,
            now=NOW,
        )
    assert denied.value.code == "DELEGATION_LINEAGE_REVOKED"


def test_bearer_child_is_replayable_until_expiry_or_revocation(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor)
    kwargs = {
        "token": child_token(response),
        "presenter": actor,
        "ticket_id": "acme-100",
        "transaction_id": request.transaction_id,
        "now": NOW,
    }
    assert api.read_ticket(**kwargs) == api.read_ticket(**kwargs)
    assert len(api.accepted_token_fingerprints) == 2


def test_expired_child_is_denied(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor, ttl=10)
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=child_token(response),
            presenter=actor,
            ticket_id="acme-100",
            transaction_id=request.transaction_id,
            now=NOW + timedelta(seconds=20),
        )
    assert denied.value.code == "TOKEN_EXPIRED"


def test_workload_only_service_token_cannot_replace_delegated_user_context(environment):
    sts, api, _, actor, _ = environment
    workload_token = sts.issue_subject_token(
        subject=actor.workload_id,
        tenant_id="acme",
        audience=lab.TICKETS_API,
        scopes=frozenset({"ticket:read"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=NOW,
        jti="workload-only",
    )
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=workload_token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-workload-only",
            now=NOW,
        )
    assert denied.value.code == "ACTOR_BINDING_INVALID"


def test_token_from_untrusted_sts_signature_is_denied(environment):
    _, api, _, actor, _ = environment
    attacker = lab.EphemeralSecurityTokenService()
    token = attacker.issue_subject_token(
        subject="analyst-42",
        tenant_id="acme",
        audience=lab.TICKETS_API,
        scopes=frozenset({"ticket:read"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=NOW,
        jti="attacker-token",
    )
    with pytest.raises(lab.DownstreamDenied) as denied:
        api.read_ticket(
            token=token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-attack",
            now=NOW,
        )
    assert denied.value.code == "SIGNATURE_INVALID"


def test_mcp_schema_exposes_resource_id_but_not_identity_or_token_controls(environment):
    sts, api, parent, actor, _ = environment
    service = lab.DelegatingSupportService(sts, api, parent, actor, NOW)

    async def inspect():
        async with Client(lab.build_mcp_server(service)) as client:
            return await client.list_tools()

    tools = run(inspect()).tools
    assert len(tools) == 1
    schema = json.dumps(tools[0].input_schema)
    assert "ticket_id" in schema
    for forbidden in ("tenant", "audience", "scope", "token", "actor", "purpose"):
        assert forbidden not in schema.lower()


def test_mcp_service_presents_exchanged_child_not_parent(environment):
    sts, api, parent, actor, _ = environment
    service = lab.DelegatingSupportService(sts, api, parent, actor, NOW)

    async def call():
        async with Client(lab.build_mcp_server(service)) as client:
            return await client.call_tool("ticket.read", {"ticket_id": "acme-100"})

    result = run(call())
    assert result.is_error is False
    assert sts.fingerprint(parent) not in api.accepted_token_fingerprints
    assert len(api.accepted_token_fingerprints) == 1


def test_sts_outage_fails_closed_without_parent_passthrough(environment):
    sts, api, parent, actor, _ = environment
    sts.available = False
    service = lab.DelegatingSupportService(sts, api, parent, actor, NOW)
    with pytest.raises(lab.ExchangeDenied) as denied:
        service.read_ticket("acme-100")
    assert denied.value.code == "STS_UNAVAILABLE"
    assert api.accepted_token_fingerprints == []


def test_tokens_are_redacted_from_models_and_audit(environment):
    sts, api, parent, actor, _ = environment
    request, response = exchange(sts, parent, actor)
    token = child_token(response)
    api.read_ticket(
        token=token,
        presenter=actor,
        ticket_id="acme-100",
        transaction_id=request.transaction_id,
        now=NOW,
    )
    assert parent not in repr(request)
    assert token not in repr(response)
    serialized = json.dumps(
        {
            "exchange": [event.__dict__ for event in sts.events],
            "downstream": [event.__dict__ for event in api.events],
        }
    )
    assert parent not in serialized
    assert token not in serialized
    assert sts.fingerprint(parent) in serialized


def test_exchange_request_rejects_multiple_resource_representation(environment):
    _, _, parent, _, _ = environment
    with pytest.raises(ValidationError):
        lab.TokenExchangeRequest(
            exchange_id="exchange-invalid-resource",
            subject_token=SecretStr(parent),
            resource=[lab.TICKETS_API, lab.AUDIT_API],
            scopes=frozenset({"ticket:read"}),
            resource_ids=("acme-100",),
            purpose="support",
            transaction_id="txn-invalid-resource",
            requested_ttl_seconds=30,
        )
