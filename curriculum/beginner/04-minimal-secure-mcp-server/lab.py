"""A real MCP Python SDK server for Course 04 (offline, stdio by default)."""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from hashlib import sha256

from mcp.server import MCPServer

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
LOG = logging.getLogger("secure-support-mcp")
TENANT = "acme"  # Deployment-scoped teaching fixture; Course 06 adds authenticated identity.


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    status: str
    summary: str


TICKETS = {"acme-7": Ticket("acme-7", "open", "Payment is pending")}
mcp = MCPServer("tenant-support-secure-baseline")


def error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}


def tenant_ticket(ticket_id: str) -> Ticket | None:
    if not isinstance(ticket_id, str) or not ticket_id.startswith(f"{TENANT}-"):
        return None
    return TICKETS.get(ticket_id)


@mcp.resource("support://acme/policy")
def support_policy() -> str:
    """Read-only deployment policy; no credentials or customer content."""
    return "Only acme ticket reads are enabled. Reply drafts require a separate approval identifier."


@mcp.prompt()
def summarize_ticket(ticket_id: str) -> str:
    """A versioned teaching prompt: content is not an authorization grant."""
    return f"Summarize ticket {ticket_id} without requesting secrets or taking additional actions."


@mcp.tool()
def ticket_read(ticket_id: str) -> dict[str, object]:
    """Read one tenant-scoped support ticket (read-only)."""
    ticket = tenant_ticket(ticket_id)
    if ticket is None:
        LOG.warning("decision=deny tool=ticket_read ticket_id=%r reason=tenant_or_missing", ticket_id)
        return error("NOT_FOUND_OR_FORBIDDEN", "ticket is unavailable")
    LOG.info("decision=allow tool=ticket_read ticket_id=%s", ticket.ticket_id)
    return {"ok": True, "ticket": asdict(ticket)}


@mcp.tool()
def ticket_list_open() -> dict[str, object]:
    """List open tickets for this deployment's tenant (read-only)."""
    open_tickets = [asdict(ticket) for ticket in TICKETS.values() if ticket.status == "open"]
    LOG.info("decision=allow tool=ticket_list_open count=%d", len(open_tickets))
    return {"ok": True, "tickets": open_tickets}


@mcp.tool()
def ticket_draft_reply(ticket_id: str, body: str, approval_id: str) -> dict[str, object]:
    """Propose a reply draft only when its exact action has an approval identifier."""
    ticket = tenant_ticket(ticket_id)
    if ticket is None or not isinstance(body, str) or not body.strip() or len(body) > 500:
        return error("INVALID_ARGUMENT", "use an existing tenant ticket and a 1-500 character body")
    fingerprint = sha256(f"{ticket_id}:{body}".encode()).hexdigest()[:16]
    expected = f"demo-approval-{fingerprint}"
    if approval_id != expected:
        LOG.warning("decision=deny tool=ticket_draft_reply ticket_id=%s reason=approval_mismatch", ticket_id)
        return error("APPROVAL_REQUIRED", f"approval must bind to action fingerprint {fingerprint}")
    LOG.info("decision=allow tool=ticket_draft_reply ticket_id=%s fingerprint=%s", ticket_id, fingerprint)
    return {"ok": True, "draft": {"ticket_id": ticket_id, "body": body, "action_fingerprint": fingerprint, "sent": False}}


def main() -> None:
    """Start the real stdio MCP server. Install `pip install -e '.[mcp]'` first."""
    mcp.run()


if __name__ == "__main__":
    main()
