"""Offline, deterministic MCP lifecycle trace for Course 01.

This is a protocol-shaped teaching fixture, not a replacement for an MCP SDK.
It makes lifecycle messages and security-relevant boundary metadata visible
without credentials, network access, or a live server. Course 04 uses the
official SDK to implement the corresponding server.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Boundary:
    name: str
    principal: str
    credentials: str
    data: str
    authority: str
    trust: str
    logging: str
    failure: str
    revocation: str


BOUNDARIES = (
    Boundary("user → host", "user", "interactive session", "request and consent", "select workflow", "user-controlled", "request ID", "deny request", "end session"),
    Boundary("host → client", "host workload", "host-to-client process identity", "selected server configuration", "launch/connect", "same product boundary", "connection ID", "do not connect", "disable integration"),
    Boundary("client → server", "MCP client", "transport/session credentials", "JSON-RPC protocol messages", "invoke advertised capabilities", "server is untrusted until approved", "session and trace IDs", "close session", "revoke server"),
    Boundary("server → downstream API", "MCP server", "audience-bound delegated credential", "validated tool arguments", "perform narrowly authorized action", "separate resource boundary", "tool-call audit event", "deny/retry only when safe", "revoke credential"),
)


def request(message_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "method": method, "params": params or {}}


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def response(message_id: int, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def build_trace() -> list[dict[str, Any]]:
    """Return a compact but representative protocol lifecycle trace."""
    return [
        request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {"roots": {"listChanged": True}}, "clientInfo": {"name": "support-host", "version": "1.0"}}),
        response(1, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": True}, "resources": {"subscribe": False}, "prompts": {"listChanged": True}}, "serverInfo": {"name": "tenant-support", "version": "1.0"}}),
        notification("notifications/initialized"),
        request(2, "tools/list"),
        response(2, {"tools": [{"name": "ticket.read", "description": "Read one ticket in the caller tenant", "inputSchema": {"type": "object", "required": ["ticket_id"], "properties": {"ticket_id": {"type": "string"}}, "additionalProperties": False}}]}),
        request(3, "resources/read", {"uri": "support://acme/policy"}),
        response(3, {"contents": [{"uri": "support://acme/policy", "mimeType": "text/plain", "text": "Read-only support policy"}]}),
        request(4, "tools/call", {"name": "ticket.read", "arguments": {"ticket_id": "acme-7"}}),
        response(4, {"content": [{"type": "text", "text": "Ticket acme-7: payment pending"}], "isError": False}),
        notification("notifications/cancelled", {"requestId": 5, "reason": "user ended session"}),
    ]


def security_review(trace: list[dict[str, Any]]) -> list[str]:
    """Assert the invariants this early lifecycle exercise teaches."""
    methods = [event.get("method") for event in trace]
    findings: list[str] = []
    if methods[:1] != ["initialize"]:
        findings.append("session did not begin with initialize")
    if "notifications/initialized" not in methods:
        findings.append("client did not confirm initialization")
    tool_call = next((event for event in trace if event.get("method") == "tools/call"), None)
    if not tool_call or set(tool_call["params"]["arguments"]) != {"ticket_id"}:
        findings.append("tool call is not a narrow, typed contract")
    if not any(event.get("method") == "resources/read" for event in trace):
        findings.append("resource boundary is not observable")
    return findings


def main() -> None:
    trace = build_trace()
    assert not security_review(trace)
    assert trace[0]["method"] == "initialize"
    assert trace[4]["result"]["tools"][0]["inputSchema"]["additionalProperties"] is False
    assert trace[8]["result"]["isError"] is False
    print("PASS: lifecycle trace contains negotiated, narrow, observable calls")
    for boundary in BOUNDARIES:
        print(asdict(boundary))


if __name__ == "__main__":
    main()
