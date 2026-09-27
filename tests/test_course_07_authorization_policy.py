"""Executable authorization invariants for Course 07."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import importlib.util
import json
from pathlib import Path
import sys

from mcp import Client
import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/07-authorization-policy-enforcement/lab.py"
SPEC = importlib.util.spec_from_file_location("course_07_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = datetime(2026, 9, 27, 16, 0, tzinfo=UTC)


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def environment():
    return lab.default_environment(NOW)


def context(**updates):
    values = {
        "request_id": "request-test",
        "purpose": "support",
        "managed_device": True,
        "risk": lab.Risk.LOW,
        "now": NOW,
    }
    values.update(updates)
    return lab.RequestContext(**values)


def decision(enforcement, principal, action="ticket.read", ticket_id="acme-100", **context_updates):
    ticket = enforcement.tickets.get(ticket_id)
    request = enforcement._request(
        principal=principal,
        action=action,
        ticket=ticket,
        context=context(**context_updates),
    )
    return enforcement.pdp.decide(request)


def approved_proposal(enforcement, agent, supervisor, operation_id="op-approved-1"):
    proposal = enforcement.prepare_reply(
        agent,
        ticket_id="acme-100",
        operation_id=operation_id,
        body="We confirmed the retry completed.",
        context=context(request_id=f"prepare-{operation_id}"),
    )
    receipt = enforcement.approvals.issue(
        approver=supervisor,
        principal=agent,
        proposal=proposal,
        policy_version=lab.POLICY_VERSION,
        now=NOW,
    )
    return proposal, receipt


def test_end_to_end_scenario_enforces_policy_approval_obligations_and_idempotency():
    evidence = run(lab.run_scenario())
    assert evidence["read_allowed"] is True
    assert evidence["cross_tenant_denied"] is True
    assert evidence["unapproved_send_denied"] is True
    assert evidence["execution_count"] == 1
    assert evidence["retry_deduplicated"] is True
    assert evidence["approval_state"] == "consumed"
    assert evidence["reply_body_in_audit"] is False


def test_mcp_tool_schemas_do_not_accept_identity_tenant_role_or_permission(environment):
    enforcement, _, _, session = environment

    async def inspect():
        async with Client(lab.build_mcp_server(enforcement, session)) as client:
            return await client.list_tools()

    tools = {tool.name: tool for tool in run(inspect()).tools}
    serialized = json.dumps({name: tool.input_schema for name, tool in tools.items()})
    for forbidden in ("principal", "tenant_id", "roles", "permissions"):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    ("principal_update", "reason"),
    [
        ({"permissions": frozenset()}, "PERMISSION_MISSING"),
        ({"roles": frozenset()}, "ROLE_NOT_ALLOWED"),
        ({"suspended": True}, "PRINCIPAL_SUSPENDED"),
        ({"tenant_id": "globex"}, "TENANT_MISMATCH"),
    ],
)
def test_identity_role_permission_and_tenant_denials(environment, principal_update, reason):
    enforcement, agent, _, _ = environment
    changed = agent.model_copy(update=principal_update)
    result = decision(enforcement, changed)
    assert result.effect is lab.Effect.DENY
    assert result.reason_code == reason


def test_purpose_is_trusted_context_and_fail_closed(environment):
    enforcement, agent, _, _ = environment
    result = decision(enforcement, agent, purpose="audit")
    assert result.effect is lab.Effect.DENY
    assert result.reason_code == "PURPOSE_NOT_ALLOWED"


def test_relationship_is_required_even_with_role_and_permission(environment):
    enforcement, agent, _, _ = environment
    result = decision(enforcement, agent, ticket_id="acme-101")
    assert result.effect is lab.Effect.DENY
    assert result.reason_code == "RELATIONSHIP_MISSING"


def test_closed_resource_blocks_reply_after_relationship_check(environment):
    enforcement, agent, _, _ = environment
    ticket = enforcement.tickets.get("acme-101")
    enforcement.tickets.update(ticket.model_copy(update={"assigned_subjects": frozenset({agent.subject})}))
    result = decision(enforcement, agent, action="ticket.reply.draft", ticket_id="acme-101")
    assert result.effect is lab.Effect.DENY
    assert result.reason_code == "RESOURCE_STATE_DENIED"


def test_unknown_action_is_default_deny(environment):
    enforcement, agent, _, _ = environment
    result = decision(enforcement, agent, action="filesystem.delete")
    assert result.effect is lab.Effect.DENY
    assert result.reason_code == "ACTION_NOT_IN_POLICY"


def test_read_obligations_are_actually_enforced_on_output(environment):
    enforcement, agent, _, _ = environment
    result = enforcement.read_ticket(agent, "acme-100", context())
    assert result["customer_email"] == "[redacted]"
    assert "internal_note" not in result
    assert result["authorization_decision_id"].startswith("decision-")
    assert enforcement.audit[-1].obligations == (
        "redact:customer_email",
        "omit:internal_note",
    )


def test_resource_attribute_outage_denies_without_stale_fallback(environment):
    enforcement, agent, _, _ = environment
    enforcement.tickets.available = False
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.read_ticket(agent, "acme-100", context())
    assert denied.value.code == "RESOURCE_ATTRIBUTES_UNAVAILABLE"


def test_policy_repository_outage_is_audited_and_denied(environment):
    enforcement, agent, _, _ = environment
    enforcement.policies.available = False
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.read_ticket(agent, "acme-100", context())
    assert denied.value.code == "POLICY_EVALUATION_ERROR"
    assert enforcement.audit[-1].effect == "DENY"
    assert enforcement.audit[-1].policy_version == "unavailable"


def test_policy_evaluator_exception_is_audited_and_denied(environment, monkeypatch):
    enforcement, agent, _, _ = environment

    def fail(_request):
        raise RuntimeError("engine unavailable")

    monkeypatch.setattr(enforcement.pdp, "decide", fail)
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.read_ticket(agent, "acme-100", context())
    assert denied.value.code == "POLICY_EVALUATION_ERROR"
    assert enforcement.audit[-1].reason_code == "POLICY_EVALUATION_ERROR"


def test_boolean_or_caller_fabricated_approval_cannot_authorize_send(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, _ = approved_proposal(enforcement, agent, supervisor)
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id="true",
            context=context(request_id="fabricated-approval"),
        )
    assert denied.value.code == "APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    ("approver_update", "reason"),
    [
        ({"tenant_id": "globex"}, "APPROVER_TENANT_MISMATCH"),
        ({"roles": frozenset()}, "APPROVER_ROLE_REQUIRED"),
        ({"permissions": frozenset()}, "APPROVER_PERMISSION_REQUIRED"),
        ({"subject": "analyst-42"}, "SEPARATION_OF_DUTIES_REQUIRED"),
    ],
)
def test_approval_issuer_is_tenant_role_and_separation_bound(environment, approver_update, reason):
    enforcement, agent, supervisor, _ = environment
    proposal = enforcement.prepare_reply(
        agent,
        ticket_id="acme-100",
        operation_id="op-approval-check",
        body="Validated response",
        context=context(),
    )
    approver = supervisor.model_copy(update=approver_update)
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.approvals.issue(
            approver=approver,
            principal=agent,
            proposal=proposal,
            policy_version=lab.POLICY_VERSION,
            now=NOW,
        )
    assert denied.value.code == reason


def test_expired_approval_is_denied(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(now=NOW + timedelta(minutes=6)),
        )
    assert denied.value.code == "APPROVAL_EXPIRED"


def test_revoked_approval_is_denied(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    enforcement.approvals.revoke(receipt.receipt_id)
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(),
        )
    assert denied.value.code == "APPROVAL_REVOKED"


def test_altered_proposal_fails_digest_validation_before_policy(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, _ = approved_proposal(enforcement, agent, supervisor)
    altered = proposal.model_dump(mode="json") | {"body": "Send credentials instead"}
    with pytest.raises(ValidationError, match="proposal digest mismatch"):
        lab.ReplyProposal.model_validate(altered)


def test_receipt_is_bound_to_exact_operation_and_proposal_digest(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    changed = lab.ReplyProposal.create(
        operation_id="op-different",
        ticket_id=proposal.ticket_id,
        resource_version=proposal.resource_version,
        body=proposal.body,
    )
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=changed,
            approval_id=receipt.receipt_id,
            context=context(),
        )
    assert denied.value.code == "APPROVAL_OPERATION_ID_MISMATCH"


def test_resource_change_invalidates_stale_proposal_before_approval(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    ticket = enforcement.tickets.get(proposal.ticket_id)
    enforcement.tickets.update(ticket.model_copy(update={"version": ticket.version + 1}))
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(),
        )
    assert denied.value.code == "RESOURCE_VERSION_STALE"


def test_policy_rollout_invalidates_receipt_for_old_policy(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    old = enforcement.policies.active()
    enforcement.policies.activate(old.model_copy(update={"version": "support-authz/8"}))
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(),
        )
    assert denied.value.code == "APPROVAL_POLICY_VERSION_MISMATCH"


def test_device_and_risk_guardrails_override_valid_approval(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    with pytest.raises(lab.AuthorizationDenied) as device_denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(managed_device=False),
        )
    assert device_denied.value.code == "DEVICE_POSTURE_REQUIRED"
    with pytest.raises(lab.AuthorizationDenied) as risk_denied:
        enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(risk=lab.Risk.ELEVATED),
        )
    assert risk_denied.value.code == "RISK_TOO_HIGH"


def test_single_use_receipt_and_stable_operation_make_retry_idempotent(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    first, first_deduplicated = enforcement.send_reply(
        agent, proposal=proposal, approval_id=receipt.receipt_id, context=context()
    )
    second, second_deduplicated = enforcement.send_reply(
        agent, proposal=proposal, approval_id=receipt.receipt_id, context=context()
    )
    assert first == second
    assert first_deduplicated is False
    assert second_deduplicated is True
    assert len(enforcement.executions) == 1
    assert enforcement.approvals.get(receipt.receipt_id).state is lab.ReceiptState.CONSUMED
    assert enforcement.audit[-1].reason_code == "REPLY_STATUS_ALLOWED"


def test_completed_operation_status_is_still_subject_and_policy_authorized(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    enforcement.send_reply(
        agent, proposal=proposal, approval_id=receipt.receipt_id, context=context()
    )
    other = agent.model_copy(update={"subject": "analyst-99"})
    with pytest.raises(lab.AuthorizationDenied) as owner_denied:
        enforcement.send_reply(
            other,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(request_id="other-principal-retry"),
        )
    assert owner_denied.value.code == "OPERATION_OWNER_MISMATCH"
    suspended = agent.model_copy(update={"suspended": True})
    with pytest.raises(lab.AuthorizationDenied) as status_denied:
        enforcement.send_reply(
            suspended,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(request_id="suspended-retry"),
        )
    assert status_denied.value.code == "PRINCIPAL_SUSPENDED"


def test_same_operation_id_with_mutated_effect_is_denied(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    enforcement.send_reply(
        agent, proposal=proposal, approval_id=receipt.receipt_id, context=context()
    )
    changed = lab.ReplyProposal.create(
        operation_id=proposal.operation_id,
        ticket_id=proposal.ticket_id,
        resource_version=proposal.resource_version,
        body="A different reply",
    )
    with pytest.raises(lab.AuthorizationDenied) as denied:
        enforcement.send_reply(
            agent,
            proposal=changed,
            approval_id=receipt.receipt_id,
            context=context(),
        )
    assert denied.value.code == "IDEMPOTENCY_CONFLICT"


def test_concurrent_retry_executes_effect_once(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)

    def attempt(index):
        return enforcement.send_reply(
            agent,
            proposal=proposal,
            approval_id=receipt.receipt_id,
            context=context(request_id=f"concurrent-{index}"),
        )[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        deduplicated = list(pool.map(attempt, range(8)))
    assert deduplicated.count(False) == 1
    assert deduplicated.count(True) == 7
    assert len(enforcement.executions) == 1


def test_audit_is_redacted_and_contains_policy_evidence(environment):
    enforcement, agent, supervisor, _ = environment
    proposal, receipt = approved_proposal(enforcement, agent, supervisor)
    enforcement.send_reply(
        agent, proposal=proposal, approval_id=receipt.receipt_id, context=context()
    )
    serialized = json.dumps([event.__dict__ for event in enforcement.audit], default=str)
    assert proposal.body not in serialized
    event = enforcement.audit[-1]
    assert event.decision_id.startswith("decision-")
    assert event.policy_version == lab.POLICY_VERSION
    assert event.relationship_revision == 12
    assert event.operation_id == proposal.operation_id
    assert event.reason_code == "REPLY_SEND_ALLOWED"
    assert event.approval_id == receipt.receipt_id


def test_labelled_policy_evaluation_reports_correct_denominators(environment):
    enforcement, agent, _, _ = environment
    no_permission = agent.model_copy(update={"permissions": frozenset()})
    wrong_tenant = agent.model_copy(update={"tenant_id": "globex"})
    cases = (
        lab.PolicyCase("assigned read", agent, "ticket.read", "acme-100", "support", lab.Effect.ALLOW),
        lab.PolicyCase("draft", agent, "ticket.reply.draft", "acme-100", "support", lab.Effect.ALLOW),
        lab.PolicyCase("no permission", no_permission, "ticket.read", "acme-100", "support", lab.Effect.DENY),
        lab.PolicyCase("wrong tenant", wrong_tenant, "ticket.read", "acme-100", "support", lab.Effect.DENY),
        lab.PolicyCase("wrong purpose", agent, "ticket.read", "acme-100", "audit", lab.Effect.DENY),
    )
    report = lab.evaluate_cases(enforcement, cases, NOW)
    assert report.total == 5
    assert report.expected_allows == 2
    assert report.expected_denies == 3
    assert report.false_allows == 0
    assert report.false_denies == 0
    assert report.false_allow_rate == 0.0
    assert report.false_deny_rate == 0.0
