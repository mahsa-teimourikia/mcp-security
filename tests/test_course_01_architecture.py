"""Executable security claims for Course 01's MCP trust-boundary lab."""

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from mcp import Client


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/beginner/01-mcp-architecture-lifecycle-trust-boundaries/lab.py"
SPEC = importlib.util.spec_from_file_location("course_01_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


def test_real_sdk_negotiates_and_executes_the_approved_read():
    lab.SERVER_CALLS.update({"ticket.read": 0, "fetch_url": 0})
    evidence, payload = run(lab.run_scenario())

    assert evidence.protocol_version == "2026-07-28"
    assert evidence.server_name == "tenant-support-course-01"
    assert {"tools", "resources", "prompts"}.issubset(evidence.capabilities)
    assert {"ticket.read", "fetch_url"}.issubset(evidence.tools)
    assert payload["ticket"]["ticket"]["ticket_id"] == "acme-7"
    assert lab.SERVER_CALLS == {"ticket.read": 1, "fetch_url": 0}


def test_discovered_broad_tool_is_denied_before_server_execution():
    decision = lab.HostPolicy().authorize_tool(
        "analyst-42", "fetch_url", {"url": "http://169.254.169.254/"}
    )
    assert decision.allowed is False
    assert decision.reason == "tool is not host-approved"


def test_policy_wrapper_never_sends_the_denied_call_to_the_server():
    async def attempt():
        lab.SERVER_CALLS["fetch_url"] = 0
        async with Client(lab.mcp) as client:
            with pytest.raises(lab.PolicyDenied, match="not host-approved"):
                await lab.call_with_policy(
                    client,
                    lab.HostPolicy(),
                    "analyst-42",
                    "fetch_url",
                    {"url": "http://169.254.169.254/"},
                )
        assert lab.SERVER_CALLS["fetch_url"] == 0

    run(attempt())


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"ticket_id": "acme-7", "debug": True}, "arguments do not match the reviewed contract"),
        ({"ticket_id": "other-7"}, "ticket is outside the tenant boundary"),
        ({"ticket_id": 7}, "ticket is outside the tenant boundary"),
    ],
)
def test_host_rejects_schema_or_tenant_drift(arguments, reason):
    decision = lab.HostPolicy().authorize_tool("analyst-42", "ticket.read", arguments)
    assert decision.allowed is False
    assert decision.reason == reason


def test_cross_tenant_resource_is_denied():
    decision = lab.HostPolicy().authorize_resource("analyst-42", "support://other/policy")
    assert decision.allowed is False


def test_client_cannot_call_before_entering_its_lifecycle_context():
    async def attempt():
        client = Client(lab.mcp)
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.list_tools()

    run(attempt())


def test_legacy_trace_reviewer_detects_missing_initialized_notification():
    trace = [
        event
        for event in lab.build_legacy_trace()
        if event.get("method") != "notifications/initialized"
    ]
    assert lab.review_legacy_trace(trace) == ["legacy client did not confirm initialization"]
