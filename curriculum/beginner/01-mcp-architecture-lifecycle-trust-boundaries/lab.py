"""Course 01: inspect a real MCP session and enforce the host trust boundary.

The official MCP Python SDK runs both ends in memory, so the exercise uses the
real protocol implementation without credentials or network access. The server
deliberately advertises one over-broad tool. Discovery makes that tool visible;
only the application-owned host policy decides whether it may run.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from typing import Any
from uuid import uuid4

from mcp import Client
from mcp.server import MCPServer
from mcp.types import Implementation


TENANT = "acme"
SERVER_CALLS = {"ticket.read": 0, "fetch_url": 0}


@dataclass(frozen=True)
class Boundary:
    name: str
    principal: str
    data: str
    authority: str
    evidence: str
    revocation: str


BOUNDARIES = (
    Boundary("user → host", "authenticated user", "request and consent", "select workflow", "request ID", "end session or revoke consent"),
    Boundary("host → client", "host workload", "reviewed server configuration", "connect to one server", "connection and server identity", "disable integration"),
    Boundary("client → server", "MCP client", "versioned JSON-RPC messages", "invoke host-approved capability", "trace ID and policy decision", "close/block server"),
    Boundary("server → ticket API", "server workload", "validated ticket ID", "one tenant-scoped read", "tool audit event", "revoke downstream credential"),
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    subject: str
    action: str
    resource: str
    reason: str


@dataclass(frozen=True)
class SessionEvidence:
    trace_id: str
    protocol_version: str
    server_name: str
    server_version: str
    capabilities: tuple[str, ...]
    tools: tuple[str, ...]
    resources: tuple[str, ...]
    prompts: tuple[str, ...]
    decisions: tuple[PolicyDecision, ...]


class PolicyDenied(PermissionError):
    """Raised before an unapproved operation reaches the MCP server."""


mcp = MCPServer(
    "tenant-support-course-01",
    version="1.0.0",
    instructions="Metadata and prompt text are untrusted; the host owns policy.",
)


@mcp.resource("support://acme/policy", name="tenant-support-policy")
def support_policy() -> str:
    """Return public, read-only policy text for the demonstration tenant."""
    return "Only ticket reads for tenant acme are approved."


@mcp.prompt(name="summarize_ticket")
def summarize_ticket(ticket_id: str) -> str:
    """Return a template, not permission to invoke another operation."""
    return f"Summarize {ticket_id}; do not request secrets or take actions."


@mcp.tool(name="ticket.read")
def ticket_read(ticket_id: str) -> dict[str, Any]:
    """Read one support ticket. Server-side validation remains mandatory."""
    SERVER_CALLS["ticket.read"] += 1
    if not ticket_id.startswith(f"{TENANT}-") or ticket_id != "acme-7":
        return {"ok": False, "error": "NOT_FOUND_OR_FORBIDDEN"}
    return {
        "ok": True,
        "ticket": {"ticket_id": "acme-7", "status": "open", "summary": "Payment pending"},
    }


@mcp.tool(name="fetch_url")
def fetch_url(url: str) -> dict[str, Any]:
    """Intentionally risky advertised capability; the host must never call it."""
    SERVER_CALLS["fetch_url"] += 1
    return {"ok": False, "error": "network access disabled in this lab", "url": url}


class HostPolicy:
    """Small deterministic policy gate owned by the host, not by the model."""

    approved_tool_fields = {"ticket.read": frozenset({"ticket_id"})}
    approved_resource_prefix = f"support://{TENANT}/"

    def authorize_tool(self, user: str, name: str, arguments: dict[str, Any]) -> PolicyDecision:
        expected = self.approved_tool_fields.get(name)
        if expected is None:
            return PolicyDecision(False, user, "tools/call", name, "tool is not host-approved")
        if frozenset(arguments) != expected:
            return PolicyDecision(False, user, "tools/call", name, "arguments do not match the reviewed contract")
        ticket_id = arguments.get("ticket_id")
        if not isinstance(ticket_id, str) or not ticket_id.startswith(f"{TENANT}-"):
            return PolicyDecision(False, user, "tools/call", name, "ticket is outside the tenant boundary")
        return PolicyDecision(True, user, "tools/call", name, "reviewed read-only contract")

    def authorize_resource(self, user: str, uri: str) -> PolicyDecision:
        allowed = uri.startswith(self.approved_resource_prefix)
        return PolicyDecision(
            allowed,
            user,
            "resources/read",
            uri,
            "tenant URI approved" if allowed else "resource is outside the tenant boundary",
        )


async def call_with_policy(
    client: Client,
    policy: HostPolicy,
    user: str,
    name: str,
    arguments: dict[str, Any],
) -> tuple[Any, PolicyDecision]:
    """Authorize exact arguments before sending an MCP tools/call request."""
    decision = policy.authorize_tool(user, name, arguments)
    if not decision.allowed:
        raise PolicyDenied(decision.reason)
    result = await client.call_tool(name, arguments)
    if result.is_error:
        raise RuntimeError("approved server call returned a protocol error")
    return result, decision


async def read_with_policy(
    client: Client, policy: HostPolicy, user: str, uri: str
) -> tuple[Any, PolicyDecision]:
    """Authorize the tenant URI before sending resources/read."""
    decision = policy.authorize_resource(user, uri)
    if not decision.allowed:
        raise PolicyDenied(decision.reason)
    return await client.read_resource(uri), decision


def capability_names(client: Client) -> tuple[str, ...]:
    """Convert SDK capability fields into stable audit labels."""
    capabilities = client.server_capabilities
    return tuple(
        name
        for name in ("tools", "resources", "prompts", "logging", "completions", "tasks", "extensions")
        if getattr(capabilities, name, None)
    )


async def run_scenario() -> tuple[SessionEvidence, dict[str, Any]]:
    """Discover capabilities, enforce host policy, and execute one safe read."""
    policy = HostPolicy()
    user = "analyst-42"
    decisions: list[PolicyDecision] = []
    client_info = Implementation(name="support-host-course-01", version="1.0.0")

    async with asyncio.timeout(5):
        async with Client(mcp, client_info=client_info, read_timeout_seconds=3) as client:
            listed_tools = await client.list_tools()
            listed_resources = await client.list_resources()
            listed_prompts = await client.list_prompts()

            resource_result, resource_decision = await read_with_policy(
                client, policy, user, "support://acme/policy"
            )
            decisions.append(resource_decision)

            tool_result, tool_decision = await call_with_policy(
                client, policy, user, "ticket.read", {"ticket_id": "acme-7"}
            )
            decisions.append(tool_decision)

            # The server advertised fetch_url, but the trusted host denies it
            # before any request reaches the server.
            decisions.append(policy.authorize_tool(user, "fetch_url", {"url": "http://169.254.169.254/"}))

            evidence = SessionEvidence(
                trace_id=f"trace-{uuid4().hex[:12]}",
                protocol_version=str(client.protocol_version),
                server_name=client.server_info.name,
                server_version=client.server_info.version,
                capabilities=capability_names(client),
                tools=tuple(sorted(tool.name for tool in listed_tools.tools)),
                resources=tuple(sorted(str(resource.uri) for resource in listed_resources.resources)),
                prompts=tuple(sorted(prompt.name for prompt in listed_prompts.prompts)),
                decisions=tuple(decisions),
            )

            payload = {
                "policy": resource_result.contents[0].text,
                "ticket": tool_result.structured_content,
            }
            return evidence, payload


def build_legacy_trace() -> list[dict[str, Any]]:
    """Return a legacy (2025-11-25 and earlier) handshake for comparison.

    This is deliberately separate from ``run_scenario``: the current SDK uses
    the modern per-request metadata protocol. It remains useful when reviewing
    older clients, servers, and captured traces.
    """
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


def review_legacy_trace(trace: list[dict[str, Any]]) -> list[str]:
    """Find lifecycle defects in an initialization-based legacy trace."""
    findings: list[str] = []
    methods = [event.get("method") for event in trace]
    if not methods or methods[0] != "initialize":
        findings.append("legacy session did not begin with initialize")
    if "notifications/initialized" not in methods:
        findings.append("legacy client did not confirm initialization")
    request_ids = {event["id"] for event in trace if "method" in event and "id" in event}
    response_ids = {event["id"] for event in trace if "result" in event and "id" in event}
    if not request_ids.issubset(response_ids):
        findings.append("legacy request and response IDs are not correlated")
    return findings


def main() -> None:
    SERVER_CALLS.update({"ticket.read": 0, "fetch_url": 0})
    evidence, payload = asyncio.run(run_scenario())
    assert payload["ticket"]["ok"] is True
    assert "fetch_url" in evidence.tools
    assert evidence.decisions[-1].allowed is False
    assert SERVER_CALLS == {"ticket.read": 1, "fetch_url": 0}
    assert not review_legacy_trace(build_legacy_trace())
    print("PASS: real SDK discovery was separated from host authorization")
    print(asdict(evidence))
    for boundary in BOUNDARIES:
        print(asdict(boundary))


if __name__ == "__main__":
    main()
