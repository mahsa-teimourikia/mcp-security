"""Executable security claims for Course 04's real MCP SDK server."""

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/beginner/04-minimal-secure-mcp-server/lab.py"
SPEC = importlib.util.spec_from_file_location("course_04_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


def test_real_protocol_scenario_covers_every_published_surface():
    evidence, payload = run(lab.run_scenario())
    assert evidence.protocol_version == "2026-07-28"
    assert evidence.server_name == "tenant-support-course-04"
    assert evidence.server_version == lab.SERVER_VERSION
    assert evidence.tools == ("ticket.list_open", "ticket.propose_reply", "ticket.read")
    assert evidence.resources == ("support://acme/policy/2026-09-21",)
    assert evidence.prompts == ("support_summary",)
    assert evidence.output_schemas_closed is True
    assert evidence.exact_arguments_enforced is True
    assert evidence.expected_denial_is_error is True
    assert evidence.external_effect_count == 0
    assert payload["proposal"]["executed"] is False


def test_discovery_exposes_no_execution_filesystem_network_or_shell_capability():
    async def inspect():
        async with Client(lab.mcp) as client:
            tools = await client.list_tools()
            denied = await client.call_tool(
                "ticket.send_reply", {"ticket_id": "acme-7", "body": "Hello"}
            )
            return tools, denied

    listed, denied = run(inspect())
    names = {tool.name for tool in listed.tools}
    assert names == set(lab.EXPECTED_TOOL_ARGUMENTS)
    assert all(
        marker not in " ".join(names)
        for marker in ("execute", "send", "shell", "file", "url", "http", "admin")
    )
    assert denied.is_error is True
    assert lab.EXTERNAL_EFFECTS == []


def test_generated_schemas_are_bounded_and_outputs_are_closed():
    async def inspect():
        async with Client(lab.mcp) as client:
            return {tool.name: tool for tool in (await client.list_tools()).tools}

    tools = run(inspect())
    read_id = tools["ticket.read"].input_schema["properties"]["ticket_id"]
    body = tools["ticket.propose_reply"].input_schema["properties"]["body"]
    assert read_id["pattern"] == "^[a-z0-9][a-z0-9-]*$"
    assert read_id["maxLength"] == 63
    assert body["minLength"] == 1 and body["maxLength"] == 500
    assert all(tool.output_schema["additionalProperties"] is False for tool in tools.values())


def test_exact_argument_middleware_rejects_extra_and_missing_fields_before_handler():
    async def attempt():
        lab.reset_runtime_evidence()
        async with Client(lab.mcp) as client:
            extra = await client.call_tool(
                "ticket.read", {"ticket_id": "acme-7", "debug": True}
            )
            missing = await client.call_tool("ticket.read", {})
            return extra, missing

    extra, missing = run(attempt())
    assert extra.is_error and missing.is_error
    assert lab.HANDLER_CALLS["ticket.read"] == 0
    assert lab.AUDIT_EVENTS == []


def test_sdk_schema_validation_rejects_bad_types_and_bounds_before_handler():
    async def attempt():
        lab.reset_runtime_evidence()
        async with Client(lab.mcp) as client:
            wrong_type = await client.call_tool("ticket.read", {"ticket_id": 7})
            oversized = await client.call_tool(
                "ticket.propose_reply", {"ticket_id": "acme-7", "body": "x" * 501}
            )
            return wrong_type, oversized

    wrong_type, oversized = run(attempt())
    assert wrong_type.is_error and oversized.is_error
    assert lab.HANDLER_CALLS == {
        "ticket.read": 0,
        "ticket.list_open": 0,
        "ticket.propose_reply": 0,
    }


def test_cross_tenant_and_unknown_ids_share_neutral_tool_error():
    async def attempt():
        lab.reset_runtime_evidence()
        async with Client(lab.mcp) as client:
            cross_tenant = await client.call_tool("ticket.read", {"ticket_id": "globex-9"})
            missing = await client.call_tool("ticket.read", {"ticket_id": "acme-404"})
            return cross_tenant, missing

    cross_tenant, missing = run(attempt())
    assert cross_tenant.is_error and missing.is_error
    assert cross_tenant.structured_content is None
    assert missing.structured_content is None
    assert "ticket is unavailable" in cross_tenant.content[0].text
    assert "ticket is unavailable" in missing.content[0].text
    assert [event.reason_code for event in lab.AUDIT_EVENTS] == [
        "NOT_FOUND_OR_FORBIDDEN",
        "NOT_FOUND_OR_FORBIDDEN",
    ]


def test_valid_read_returns_schema_conformant_untrusted_content():
    async def attempt():
        async with Client(lab.mcp) as client:
            return await client.call_tool("ticket.read", {"ticket_id": "acme-7"})

    result = run(attempt())
    validated = lab.TicketReadResult.model_validate(result.structured_content)
    assert result.is_error is False
    assert validated.ticket.ticket_id == "acme-7"
    assert validated.ticket.content_trust == "untrusted-customer-content"
    assert validated.policy_version == lab.POLICY_VERSION


def test_open_list_is_sorted_bounded_and_tenant_scoped():
    async def attempt():
        async with Client(lab.mcp) as client:
            return await client.call_tool("ticket.list_open", {})

    result = run(attempt())
    validated = lab.TicketListResult.model_validate(result.structured_content)
    assert validated.count == 1
    assert [ticket.ticket_id for ticket in validated.tickets] == ["acme-7"]
    assert all(not ticket.ticket_id.startswith("globex-") for ticket in validated.tickets)
    assert validated.count <= lab.POLICY.max_list_results


def test_reply_tool_only_proposes_and_same_length_mutation_changes_digest():
    async def attempt():
        lab.reset_runtime_evidence()
        async with Client(lab.mcp) as client:
            first = await client.call_tool(
                "ticket.propose_reply", {"ticket_id": "acme-7", "body": "Allow access"}
            )
            changed = await client.call_tool(
                "ticket.propose_reply", {"ticket_id": "acme-7", "body": "Deny access!"}
            )
            return first, changed

    first, changed = run(attempt())
    proposal = lab.ReplyProposalResult.model_validate(first.structured_content)
    mutation = lab.ReplyProposalResult.model_validate(changed.structured_content)
    assert proposal.executed is False and mutation.executed is False
    assert proposal.action_digest == lab.canonical_digest(
        {
            "action": "ticket.reply.proposed",
            "body": "Allow access",
            "policy_version": lab.POLICY_VERSION,
            "tenant_id": "acme",
            "ticket_id": "acme-7",
        }
    )
    assert proposal.action_digest != mutation.action_digest
    assert lab.EXTERNAL_EFFECTS == []


def test_closed_ticket_cannot_receive_a_reply_proposal():
    async def attempt():
        async with Client(lab.mcp) as client:
            return await client.call_tool(
                "ticket.propose_reply", {"ticket_id": "acme-8", "body": "Hello"}
            )

    result = run(attempt())
    assert result.is_error is True
    assert result.structured_content is None
    assert "ticket is not open" in result.content[0].text


def test_proposal_log_and_audit_record_do_not_contain_body(caplog):
    secret_body = "temporary-secret-value"

    async def attempt():
        async with Client(lab.mcp) as client:
            return await client.call_tool(
                "ticket.propose_reply", {"ticket_id": "acme-7", "body": secret_body}
            )

    lab.reset_runtime_evidence()
    with caplog.at_level(logging.INFO):
        result = run(attempt())
    assert result.is_error is False
    assert secret_body not in caplog.text
    assert secret_body not in json.dumps([event.__dict__ for event in lab.AUDIT_EVENTS])
    assert lab.AUDIT_EVENTS[-1].argument_digest == result.structured_content["action_digest"]


def test_policy_resource_has_version_digest_and_explicit_trust_label():
    async def attempt():
        async with Client(lab.mcp) as client:
            return await client.read_resource("support://acme/policy/2026-09-21")

    result = run(attempt())
    document = json.loads(result.contents[0].text)
    assert document["policy_version"] == lab.POLICY_VERSION
    assert document["content_trust"] == "untrusted-server-resource"
    supplied_digest = document.pop("content_digest")
    expected_digest = lab.canonical_digest(
        {"policy": json.dumps(document, sort_keys=True, separators=(",", ":"))}
    )
    assert supplied_digest == expected_digest
    assert "send_reply" in document["prohibited_effects"]


def test_unregistered_resource_uri_is_rejected():
    async def attempt():
        async with Client(lab.mcp) as client:
            with pytest.raises(MCPError, match="Unknown resource"):
                await client.read_resource("support://acme/policy/latest")

    run(attempt())


def test_prompt_is_versioned_labeled_and_grants_no_effect():
    async def attempt():
        lab.reset_runtime_evidence()
        async with Client(lab.mcp) as client:
            return await client.get_prompt("support_summary", {"ticket_id": "acme-7"})

    result = run(attempt())
    text = result.messages[0].content.text
    assert "version=1.0.0" in text
    assert "trust=untrusted-template" in text
    assert lab.EXTERNAL_EFFECTS == []
    assert lab.HANDLER_CALLS == {
        "ticket.read": 0,
        "ticket.list_open": 0,
        "ticket.propose_reply": 0,
    }


def test_tool_annotations_are_hints_consistent_with_real_no_effect_behavior():
    async def inspect():
        async with Client(lab.mcp) as client:
            return await client.list_tools()

    tools = run(inspect()).tools
    assert all(tool.annotations.read_only_hint is True for tool in tools)
    assert all(tool.annotations.open_world_hint is False for tool in tools)
    assert lab.EXTERNAL_EFFECTS == []


def test_sdk_turns_invalid_handler_output_into_an_error_result():
    class ExpectedOutput(BaseModel):
        value: int

    broken = MCPServer("course-04-invalid-output-test")

    @broken.tool(structured_output=True)
    def malformed_output() -> ExpectedOutput:
        return {"unexpected": "field"}  # type: ignore[return-value]

    async def attempt():
        async with Client(broken) as client:
            return await client.call_tool("malformed_output", {})

    result = run(attempt())
    assert result.is_error is True
    assert result.structured_content is None
    assert "Error executing tool malformed_output" in result.content[0].text
