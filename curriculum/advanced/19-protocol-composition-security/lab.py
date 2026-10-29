"""Course 19 lab: preserve authority and outcome semantics across A2A and MCP.

The lab is deterministic, offline, and credential-free. It uses the official
``a2a-sdk`` protobuf types and official MCP Python SDK in-memory transport.
PyJWT models an RFC 8693-style exchange, but the shared keys and process-local
stores are training fixtures—not production identity or durability controls.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from a2a.types import Message, Part, Role
from google.protobuf.struct_pb2 import Struct, Value
import jwt
from mcp import Client
from mcp.server import MCPServer
from mcp.types import Implementation, Tool


A2A_PROTOCOL_VERSION = "1.0"
MCP_PROTOCOL_VERSION = "2026-07-28"
SOURCE_AUDIENCE = "adapter://a2a-mcp"
TARGET_AUDIENCE = "mcp://support"
TOKEN_ISSUER = "https://sts.acme.test"
TOKEN_KEY = "course-19-training-key-not-for-production"
APPROVAL_KEY = b"course-19-approval-key-not-for-production"
POLICY_VERSION = "composition-policy-2026-10-28"
MAX_GRANT_SECONDS = 180
TRACEPARENT_RE = re.compile(
    r"^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}$"
)


class CompositionDenied(PermissionError):
    """Stable policy failure that must never be converted into a fallback."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class OutcomeState(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    INVALID = "invalid"
    TRANSIENT = "transient"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RuntimeProposal:
    """Untrusted runtime output; the trusted application owns all checks."""

    operation_id: str
    attempt_id: str
    skill_id: str
    ticket_id: str
    purpose: str
    traceparent: str
    deadline: datetime
    comment: str | None = None
    approval_id: str | None = None

    def arguments(self) -> dict[str, str]:
        values = {"ticket_id": self.ticket_id}
        if self.comment is not None:
            values["body"] = self.comment
        return values


@dataclass(frozen=True)
class AuthenticatedPeer:
    """A2A peer identity established by the transport, not message metadata."""

    agent_id: str
    workload_id: str
    tenant_id: str
    credential_id: str


@dataclass(frozen=True)
class ParentAuthority:
    subject: str
    actor: str
    tenant_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    purpose: str
    expires_at: datetime


@dataclass(frozen=True)
class ActionContract:
    skill_id: str
    action: str
    argument_names: tuple[str, ...]
    approval_required: bool


ACTION_CONTRACTS = {
    "ticket-read": ActionContract("ticket-read", "ticket.read", ("ticket_id",), False),
    "ticket-comment": ActionContract(
        "ticket-comment", "ticket.comment", ("body", "ticket_id"), True
    ),
}


@dataclass(frozen=True)
class NormalizedContext:
    subject: str
    actor: str
    sender_agent: str
    sender_workload: str
    tenant_id: str
    source_protocol: str
    source_version: str
    target_protocol: str
    target_version: str
    source_audience: str
    target_audience: str
    action: str
    resource: str
    purpose: str
    operation_id: str
    attempt_id: str
    message_id: str
    traceparent: str
    deadline: datetime
    approval_id: str | None
    policy_version: str


@dataclass(frozen=True)
class CompositionOutcome:
    state: OutcomeState
    code: str
    retryable: bool
    operation_id: str
    result: dict[str, Any] | None = None
    reconciled: bool = False
    trace: tuple[dict[str, str], ...] = ()


def utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be canonical UTC and end in Z")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError("timestamp must be UTC")
    return parsed


def timestamp(value: datetime) -> int:
    if value.tzinfo != UTC:
        raise ValueError("timestamp must be timezone-aware UTC")
    return int(value.timestamp())


def canonical_json(value: Any) -> str:
    if hasattr(value, "DESCRIPTOR"):
        value = value.SerializeToString(deterministic=True).hex()
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def resource_for(tenant_id: str, ticket_id: str) -> str:
    return f"ticket://{tenant_id}/{ticket_id}"


def require_traceparent(value: str) -> None:
    if not TRACEPARENT_RE.fullmatch(value):
        raise CompositionDenied("TRACE_CONTEXT_INVALID")


def child_traceparent(parent: str, hop: str) -> str:
    """Preserve the trace ID but derive a distinct deterministic training span."""

    require_traceparent(parent)
    _, trace_id, _, flags = parent.split("-")
    span_id = hashlib.sha256(f"{parent}:{hop}".encode()).hexdigest()[:16]
    if span_id == "0" * 16:
        span_id = "1" + span_id[1:]
    return f"00-{trace_id}-{span_id}-{flags}"


def build_a2a_message(proposal: RuntimeProposal) -> Message:
    """Use the official A2A wire type; message content still grants no authority."""

    payload = Struct()
    payload.update(
        {
            "operationId": proposal.operation_id,
            "attemptId": proposal.attempt_id,
            "skillId": proposal.skill_id,
            "ticketId": proposal.ticket_id,
            "purpose": proposal.purpose,
            "traceparent": proposal.traceparent,
            "comment": proposal.comment or "",
            "approvalId": proposal.approval_id or "",
        }
    )
    return Message(
        message_id=f"msg-{proposal.operation_id}",
        context_id=f"ctx-{proposal.operation_id}",
        role=Role.ROLE_USER,
        parts=[Part(data=Value(struct_value=payload), media_type="application/json")],
        metadata={
            "tenantHint": "untrusted",
            "authorization": "never read authority from this object",
        },
    )


def message_payload(message: Message) -> dict[str, str]:
    if len(message.parts) != 1 or not message.parts[0].HasField("data"):
        raise CompositionDenied("A2A_MESSAGE_SHAPE_INVALID")
    fields = message.parts[0].data.struct_value.fields
    required = {
        "operationId",
        "attemptId",
        "skillId",
        "ticketId",
        "purpose",
        "traceparent",
        "comment",
        "approvalId",
    }
    if set(fields) != required or any(
        value.WhichOneof("kind") != "string_value" for value in fields.values()
    ):
        raise CompositionDenied("A2A_MESSAGE_SHAPE_INVALID")
    return {name: value.string_value for name, value in fields.items()}


def issue_source_grant(
    parent: ParentAuthority,
    peer: AuthenticatedPeer,
    proposal: RuntimeProposal,
    message: Message,
    *,
    now: datetime,
) -> str:
    """Attenuate human authority for one A2A message and adapter audience."""

    contract = ACTION_CONTRACTS.get(proposal.skill_id)
    if contract is None:
        raise CompositionDenied("SKILL_NOT_MAPPED")
    resource = resource_for(peer.tenant_id, proposal.ticket_id)
    if peer.agent_id != parent.actor or peer.tenant_id != parent.tenant_id:
        raise CompositionDenied("SOURCE_IDENTITY_MISMATCH")
    if contract.action not in parent.actions:
        raise CompositionDenied("SOURCE_ACTION_ESCALATION")
    if resource not in parent.resources:
        raise CompositionDenied("SOURCE_RESOURCE_ESCALATION")
    if proposal.purpose != parent.purpose:
        raise CompositionDenied("SOURCE_PURPOSE_ESCALATION")
    if now >= parent.expires_at or proposal.deadline <= now:
        raise CompositionDenied("SOURCE_AUTHORITY_EXPIRED")
    expires_at = min(
        parent.expires_at, proposal.deadline, now + timedelta(seconds=MAX_GRANT_SECONDS)
    )
    claims = {
        "iss": TOKEN_ISSUER,
        "aud": SOURCE_AUDIENCE,
        "sub": parent.subject,
        "actor": parent.actor,
        "sender_workload": peer.workload_id,
        "tenant": peer.tenant_id,
        "action": contract.action,
        "resource": resource,
        "purpose": proposal.purpose,
        "operation_id": proposal.operation_id,
        "message_id": message.message_id,
        "message_digest": digest(message),
        "a2a_version": A2A_PROTOCOL_VERSION,
        "traceparent": proposal.traceparent,
        "approval_id": proposal.approval_id,
        "policy_version": POLICY_VERSION,
        "iat": timestamp(now),
        "exp": timestamp(expires_at),
        "jti": f"source-{proposal.operation_id}",
    }
    return jwt.encode(claims, TOKEN_KEY, algorithm="HS256")


def decode_grant(token: str, audience: str, *, now: datetime) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            TOKEN_KEY,
            algorithms=["HS256"],
            audience=audience,
            issuer=TOKEN_ISSUER,
            options={"verify_exp": False},
        )
    except jwt.PyJWTError as error:
        raise CompositionDenied("GRANT_INVALID") from error
    if now.timestamp() >= claims.get("exp", 0):
        raise CompositionDenied("GRANT_EXPIRED")
    return claims


class TokenExchange:
    """Training STS: verify the parent, then mint a distinct target token."""

    def exchange(
        self,
        source_token: str,
        context: NormalizedContext,
        message: Message,
        *,
        now: datetime,
    ) -> str:
        source = decode_grant(source_token, SOURCE_AUDIENCE, now=now)
        exact = {
            "sub": context.subject,
            "actor": context.actor,
            "sender_workload": context.sender_workload,
            "tenant": context.tenant_id,
            "action": context.action,
            "resource": context.resource,
            "purpose": context.purpose,
            "operation_id": context.operation_id,
            "message_id": context.message_id,
            "message_digest": digest(message),
            "a2a_version": context.source_version,
            "traceparent": context.traceparent,
            "approval_id": context.approval_id,
            "policy_version": context.policy_version,
        }
        for key, expected in exact.items():
            if source.get(key) != expected:
                raise CompositionDenied(f"GRANT_{key.upper()}_MISMATCH")
        expires_at = min(
            datetime.fromtimestamp(source["exp"], tz=UTC),
            context.deadline,
            now + timedelta(seconds=MAX_GRANT_SECONDS),
        )
        if expires_at <= now:
            raise CompositionDenied("GRANT_EXPIRED")
        target_claims = {
            "iss": TOKEN_ISSUER,
            "aud": context.target_audience,
            "sub": context.subject,
            "actor": "protocol-adapter",
            "act": {"sub": context.actor},
            "azp": "protocol-adapter",
            "tenant": context.tenant_id,
            "action": context.action,
            "resource": context.resource,
            "purpose": context.purpose,
            "operation_id": context.operation_id,
            "traceparent": child_traceparent(context.traceparent, "adapter-to-mcp"),
            "approval_id": context.approval_id,
            "policy_version": context.policy_version,
            "mcp_version": context.target_version,
            "parent_jti": source["jti"],
            "iat": timestamp(now),
            "exp": timestamp(expires_at),
            "jti": f"target-{context.operation_id}",
        }
        return jwt.encode(target_claims, TOKEN_KEY, algorithm="HS256")


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    subject: str
    actor: str
    tenant_id: str
    action: str
    resource: str
    operation_id: str
    effect_digest: str
    policy_version: str
    approver: str
    issued_at: datetime
    expires_at: datetime
    consumed: bool
    signature: str

    def unsigned(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}


class ApprovalStore:
    """Trusted, single-use approval state; IDs and arguments are not proof."""

    def __init__(self) -> None:
        self._receipts: dict[str, ApprovalReceipt] = {}

    @staticmethod
    def _sign(receipt: ApprovalReceipt) -> str:
        return hmac.new(
            APPROVAL_KEY, canonical_json(receipt.unsigned()).encode(), hashlib.sha256
        ).hexdigest()

    def issue(
        self,
        *,
        approval_id: str,
        parent: ParentAuthority,
        proposal: RuntimeProposal,
        now: datetime,
    ) -> ApprovalReceipt:
        unsigned = ApprovalReceipt(
            approval_id=approval_id,
            subject=parent.subject,
            actor=parent.actor,
            tenant_id=parent.tenant_id,
            action="ticket.comment",
            resource=resource_for(parent.tenant_id, proposal.ticket_id),
            operation_id=proposal.operation_id,
            effect_digest=digest(proposal.arguments()),
            policy_version=POLICY_VERSION,
            approver="support-manager-7",
            issued_at=now,
            expires_at=min(parent.expires_at, now + timedelta(minutes=5)),
            consumed=False,
            signature="",
        )
        receipt = replace(unsigned, signature=self._sign(unsigned))
        self._receipts[approval_id] = receipt
        return receipt

    def replace(self, receipt: ApprovalReceipt) -> None:
        self._receipts[receipt.approval_id] = receipt

    def require(
        self,
        approval_id: str | None,
        context: NormalizedContext,
        arguments: Mapping[str, str],
        *,
        now: datetime,
        consume: bool,
    ) -> ApprovalReceipt:
        if not approval_id or approval_id not in self._receipts:
            raise CompositionDenied("APPROVAL_REQUIRED")
        receipt = self._receipts[approval_id]
        if not hmac.compare_digest(receipt.signature, self._sign(receipt)):
            raise CompositionDenied("APPROVAL_SIGNATURE_INVALID")
        expected = (
            context.subject,
            context.actor,
            context.tenant_id,
            context.action,
            context.resource,
            context.operation_id,
            digest(dict(arguments)),
            context.policy_version,
        )
        actual = (
            receipt.subject,
            receipt.actor,
            receipt.tenant_id,
            receipt.action,
            receipt.resource,
            receipt.operation_id,
            receipt.effect_digest,
            receipt.policy_version,
        )
        if actual != expected:
            raise CompositionDenied("APPROVAL_BINDING_MISMATCH")
        if receipt.consumed:
            raise CompositionDenied("APPROVAL_ALREADY_CONSUMED")
        if now < receipt.issued_at or now >= receipt.expires_at:
            raise CompositionDenied("APPROVAL_EXPIRED")
        if consume:
            receipt = replace(receipt, consumed=True, signature="")
            receipt = replace(receipt, signature=self._sign(receipt))
            self._receipts[approval_id] = receipt
        return receipt


@dataclass(frozen=True)
class TargetCallContext:
    token: str
    now: datetime
    cancelled_operations: frozenset[str]


TARGET_CONTEXT: ContextVar[TargetCallContext | None] = ContextVar(
    "course_19_target_context", default=None
)


class SupportMCP:
    """The final resource server independently authorizes and records effects."""

    def __init__(self, approvals: ApprovalStore) -> None:
        self.approvals = approvals
        self.tickets = {
            "acme-7": {
                "ticket_id": "acme-7",
                "status": "open",
                "summary": "Payment pending",
            }
        }
        self.comments: list[dict[str, str]] = []
        self.effect_ledger: dict[str, tuple[str, dict[str, Any]]] = {}
        self.server = MCPServer(
            "support-course-19",
            version="1.0.0",
            instructions="The transport authenticates; tool arguments never carry tokens.",
        )

        @self.server.tool(name="ticket.read")
        def ticket_read(ticket_id: str) -> dict[str, Any]:
            claims = self._authorize("ticket.read", {"ticket_id": ticket_id})
            ticket = self.tickets.get(ticket_id)
            if ticket is None:
                raise CompositionDenied("RESOURCE_NOT_FOUND")
            return {
                "ok": True,
                "ticket": ticket,
                "operation_id": claims["operation_id"],
            }

        @self.server.tool(name="ticket.comment")
        def ticket_comment(ticket_id: str, body: str) -> dict[str, Any]:
            arguments = {"ticket_id": ticket_id, "body": body}
            claims = self._authorize("ticket.comment", arguments)
            operation_id = claims["operation_id"]
            request_digest = digest(arguments)
            previous = self.effect_ledger.get(operation_id)
            if previous is not None:
                if previous[0] != request_digest:
                    raise CompositionDenied("TARGET_IDEMPOTENCY_CONFLICT")
                return {**previous[1], "duplicate_effect": False, "replayed": True}
            normalized = normalized_from_claims(claims)
            self.approvals.require(
                claims.get("approval_id"),
                normalized,
                arguments,
                now=self._context().now,
                consume=True,
            )
            comment = {
                "ticket_id": ticket_id,
                "body": body,
                "operation_id": operation_id,
            }
            self.comments.append(comment)
            result = {"ok": True, "comment": comment, "duplicate_effect": False}
            self.effect_ledger[operation_id] = (request_digest, result)
            return result

    def _context(self) -> TargetCallContext:
        context = TARGET_CONTEXT.get()
        if context is None:
            raise CompositionDenied("TARGET_AUTH_CONTEXT_MISSING")
        return context

    def _authorize(self, action: str, arguments: Mapping[str, str]) -> dict[str, Any]:
        call = self._context()
        claims = decode_grant(call.token, TARGET_AUDIENCE, now=call.now)
        ticket_id = arguments.get("ticket_id", "")
        resource = resource_for(claims.get("tenant", ""), ticket_id)
        required = {
            "actor": "protocol-adapter",
            "azp": "protocol-adapter",
            "tenant": "acme",
            "action": action,
            "resource": resource,
            "purpose": "resolve-support-case",
            "policy_version": POLICY_VERSION,
            "mcp_version": MCP_PROTOCOL_VERSION,
        }
        for key, expected in required.items():
            if claims.get(key) != expected:
                raise CompositionDenied(f"TARGET_{key.upper()}_DENIED")
        if not ticket_id.startswith(f"{claims['tenant']}-"):
            raise CompositionDenied("TARGET_TENANT_DENIED")
        if claims["operation_id"] in call.cancelled_operations:
            raise CompositionDenied("OPERATION_CANCELLED")
        require_traceparent(claims.get("traceparent", ""))
        return claims

    async def invoke(
        self,
        client: Client,
        *,
        token: str,
        action: str,
        arguments: dict[str, str],
        now: datetime,
        cancelled_operations: frozenset[str],
    ) -> dict[str, Any]:
        marker = TARGET_CONTEXT.set(TargetCallContext(token, now, cancelled_operations))
        try:
            result = await client.call_tool(action, arguments)
        finally:
            TARGET_CONTEXT.reset(marker)
        if result.is_error:
            raise CompositionDenied("MCP_TOOL_ERROR")
        if not isinstance(result.structured_content, dict):
            raise CompositionDenied("MCP_RESULT_INVALID")
        return result.structured_content

    def reconcile(
        self, operation_id: str, arguments: Mapping[str, str]
    ) -> dict[str, Any] | None:
        previous = self.effect_ledger.get(operation_id)
        if previous is None:
            return None
        if previous[0] != digest(dict(arguments)):
            raise CompositionDenied("TARGET_IDEMPOTENCY_CONFLICT")
        return previous[1]


def normalized_from_claims(claims: Mapping[str, Any]) -> NormalizedContext:
    """Reconstruct only the fields the target needs for approval verification."""

    return NormalizedContext(
        subject=claims["sub"],
        actor=claims.get("act", {}).get("sub", ""),
        sender_agent="",
        sender_workload="",
        tenant_id=claims["tenant"],
        source_protocol="A2A",
        source_version=A2A_PROTOCOL_VERSION,
        target_protocol="MCP",
        target_version=claims["mcp_version"],
        source_audience=SOURCE_AUDIENCE,
        target_audience=TARGET_AUDIENCE,
        action=claims["action"],
        resource=claims["resource"],
        purpose=claims["purpose"],
        operation_id=claims["operation_id"],
        attempt_id="",
        message_id="",
        traceparent=claims["traceparent"],
        deadline=datetime.fromtimestamp(claims["exp"], tz=UTC),
        approval_id=claims.get("approval_id"),
        policy_version=claims["policy_version"],
    )


def reviewed_tool_view(tool: Tool) -> dict[str, Any]:
    properties = tool.input_schema.get("properties", {})
    return {
        "name": tool.name,
        "fields": tuple(sorted(properties)),
        "types": tuple(
            sorted((name, value.get("type")) for name, value in properties.items())
        ),
        "required": tuple(sorted(tool.input_schema.get("required", []))),
        "additional_properties": tool.input_schema.get("additionalProperties"),
    }


REVIEWED_TOOL_VIEWS = {
    "ticket.read": {
        "name": "ticket.read",
        "fields": ("ticket_id",),
        "types": (("ticket_id", "string"),),
        "required": ("ticket_id",),
        "additional_properties": None,
    },
    "ticket.comment": {
        "name": "ticket.comment",
        "fields": ("body", "ticket_id"),
        "types": (("body", "string"), ("ticket_id", "string")),
        "required": ("body", "ticket_id"),
        "additional_properties": None,
    },
}


def verify_discovery(
    tools: list[Tool], reviewed: Mapping[str, dict[str, Any]]
) -> None:
    discovered = {tool.name: reviewed_tool_view(tool) for tool in tools}
    if set(discovered) != set(reviewed):
        raise CompositionDenied("MCP_TOOL_SET_DRIFT")
    for name, expected in reviewed.items():
        if discovered[name] != expected:
            raise CompositionDenied("MCP_TOOL_CONTRACT_DRIFT")


@dataclass
class AdapterLedgerEntry:
    request_digest: str
    state: OutcomeState
    outcome: CompositionOutcome | None = None


class ProtocolAdapter:
    """Trusted application boundary; the model never owns this bridge."""

    def __init__(self, target: SupportMCP, approvals: ApprovalStore) -> None:
        self.target = target
        self.approvals = approvals
        self.exchange = TokenExchange()
        self.ledger: dict[str, AdapterLedgerEntry] = {}
        self.cancelled_operations: set[str] = set()
        self.reviewed_tools: Mapping[str, dict[str, Any]] = REVIEWED_TOOL_VIEWS

    def cancel(self, operation_id: str) -> None:
        self.cancelled_operations.add(operation_id)

    def normalize(
        self,
        peer: AuthenticatedPeer,
        parent: ParentAuthority,
        proposal: RuntimeProposal,
        message: Message,
        *,
        now: datetime,
    ) -> NormalizedContext:
        if (
            peer.agent_id != parent.actor
            or peer.workload_id != "spiffe://acme.test/a2a/triage"
        ):
            raise CompositionDenied("A2A_PEER_NOT_TRUSTED")
        if peer.tenant_id != parent.tenant_id:
            raise CompositionDenied("A2A_TENANT_MISMATCH")
        if proposal.deadline <= now:
            raise CompositionDenied("REQUEST_DEADLINE_EXPIRED")
        require_traceparent(proposal.traceparent)
        contract = ACTION_CONTRACTS.get(proposal.skill_id)
        if contract is None:
            raise CompositionDenied("SKILL_NOT_MAPPED")
        if tuple(sorted(proposal.arguments())) != contract.argument_names:
            raise CompositionDenied("ACTION_ARGUMENTS_INVALID")
        payload = message_payload(message)
        expected_payload = {
            "operationId": proposal.operation_id,
            "attemptId": proposal.attempt_id,
            "skillId": proposal.skill_id,
            "ticketId": proposal.ticket_id,
            "purpose": proposal.purpose,
            "traceparent": proposal.traceparent,
            "comment": proposal.comment or "",
            "approvalId": proposal.approval_id or "",
        }
        if (
            payload != expected_payload
            or message.message_id != f"msg-{proposal.operation_id}"
        ):
            raise CompositionDenied("A2A_MESSAGE_PROPOSAL_MISMATCH")
        return NormalizedContext(
            subject=parent.subject,
            actor=parent.actor,
            sender_agent=peer.agent_id,
            sender_workload=peer.workload_id,
            tenant_id=peer.tenant_id,
            source_protocol="A2A",
            source_version=A2A_PROTOCOL_VERSION,
            target_protocol="MCP",
            target_version=MCP_PROTOCOL_VERSION,
            source_audience=SOURCE_AUDIENCE,
            target_audience=TARGET_AUDIENCE,
            action=contract.action,
            resource=resource_for(peer.tenant_id, proposal.ticket_id),
            purpose=proposal.purpose,
            operation_id=proposal.operation_id,
            attempt_id=proposal.attempt_id,
            message_id=message.message_id,
            traceparent=proposal.traceparent,
            deadline=proposal.deadline,
            approval_id=proposal.approval_id,
            policy_version=POLICY_VERSION,
        )

    async def compose(
        self,
        *,
        peer: AuthenticatedPeer,
        parent: ParentAuthority,
        proposal: RuntimeProposal,
        message: Message,
        source_token: str,
        now: datetime,
        simulate: str | None = None,
    ) -> CompositionOutcome:
        context = self.normalize(peer, parent, proposal, message, now=now)
        request_digest = digest(
            {
                "context": asdict(context),
                "arguments": proposal.arguments(),
                "message": digest(message),
            }
        )
        previous = self.ledger.get(context.operation_id)
        if previous is not None:
            if previous.request_digest != request_digest:
                raise CompositionDenied("ADAPTER_IDEMPOTENCY_CONFLICT")
            if previous.state == OutcomeState.COMPLETED and previous.outcome:
                return replace(previous.outcome, reconciled=True)
            if previous.state == OutcomeState.UNKNOWN:
                found = self.target.reconcile(
                    context.operation_id, proposal.arguments()
                )
                if found is not None:
                    outcome = self._outcome(
                        context, OutcomeState.COMPLETED, "RECONCILED", found, True
                    )
                    previous.state = OutcomeState.COMPLETED
                    previous.outcome = outcome
                    return outcome
        if context.operation_id in self.cancelled_operations:
            return self._outcome(
                context, OutcomeState.CANCELLED, "OPERATION_CANCELLED"
            )
        if simulate == "transient-before-effect":
            return self._outcome(
                context, OutcomeState.TRANSIENT, "UPSTREAM_UNAVAILABLE"
            )
        target_token = self.exchange.exchange(
            source_token, context, message, now=now
        )
        if ACTION_CONTRACTS[proposal.skill_id].approval_required:
            self.approvals.require(
                context.approval_id,
                context,
                proposal.arguments(),
                now=now,
                consume=False,
            )
        self.ledger[context.operation_id] = AdapterLedgerEntry(
            request_digest, OutcomeState.UNKNOWN
        )
        client_info = Implementation(
            name="course-19-protocol-adapter", version="1.0.0"
        )
        protocol_error: CompositionDenied | None = None
        result: dict[str, Any] | None = None
        async with asyncio.timeout(5):
            async with Client(
                self.target.server,
                client_info=client_info,
                read_timeout_seconds=3,
            ) as client:
                try:
                    if str(client.protocol_version) != MCP_PROTOCOL_VERSION:
                        raise CompositionDenied("MCP_VERSION_UNSUPPORTED")
                    listed = await client.list_tools()
                    verify_discovery(listed.tools, self.reviewed_tools)
                    result = await self.target.invoke(
                        client,
                        token=target_token,
                        action=context.action,
                        arguments=proposal.arguments(),
                        now=now,
                        cancelled_operations=frozenset(self.cancelled_operations),
                    )
                except CompositionDenied as error:
                    # Let the SDK task group shut down cleanly, then preserve the
                    # original stable security error outside the transport scope.
                    protocol_error = error
        if protocol_error is not None:
            raise protocol_error
        if result is None:
            raise CompositionDenied("MCP_RESULT_INVALID")
        if simulate == "response-loss-after-effect":
            return self._outcome(
                context, OutcomeState.UNKNOWN, "OUTCOME_UNKNOWN"
            )
        outcome = self._outcome(
            context, OutcomeState.COMPLETED, "OK", result
        )
        entry = self.ledger[context.operation_id]
        entry.state = OutcomeState.COMPLETED
        entry.outcome = outcome
        return outcome

    @staticmethod
    def _outcome(
        context: NormalizedContext,
        state: OutcomeState,
        code: str,
        result: dict[str, Any] | None = None,
        reconciled: bool = False,
    ) -> CompositionOutcome:
        retryable = state in {OutcomeState.TRANSIENT, OutcomeState.UNKNOWN}
        trace = (
            {"hop": "runtime-to-a2a", "traceparent": context.traceparent},
            {
                "hop": "a2a-to-adapter",
                "traceparent": child_traceparent(
                    context.traceparent, "a2a-to-adapter"
                ),
            },
            {
                "hop": "adapter-to-mcp",
                "traceparent": child_traceparent(
                    context.traceparent, "adapter-to-mcp"
                ),
            },
            {
                "hop": "mcp-to-resource",
                "traceparent": child_traceparent(
                    context.traceparent, "mcp-to-resource"
                ),
            },
        )
        return CompositionOutcome(
            state,
            code,
            retryable,
            context.operation_id,
            result,
            reconciled,
            trace,
        )


def classify_failure(
    code: str, *, effect_possible: bool = False
) -> CompositionOutcome:
    """Preserve denial, validation, transient, and unknown-outcome semantics."""

    operation_id = "unbound"
    if effect_possible:
        return CompositionOutcome(OutcomeState.UNKNOWN, code, True, operation_id)
    if code.startswith(
        ("GRANT_", "TARGET_", "APPROVAL_", "A2A_", "SOURCE_")
    ):
        return CompositionOutcome(OutcomeState.DENIED, code, False, operation_id)
    if code.startswith(
        ("REQUEST_", "TRACE_", "ACTION_", "MCP_TOOL_CONTRACT")
    ):
        return CompositionOutcome(OutcomeState.INVALID, code, False, operation_id)
    if code in {"UPSTREAM_UNAVAILABLE", "RATE_LIMITED"}:
        return CompositionOutcome(OutcomeState.TRANSIENT, code, True, operation_id)
    return CompositionOutcome(
        OutcomeState.INVALID, "UNMAPPED_FAILURE", False, operation_id
    )


@dataclass
class LabEnvironment:
    now: datetime
    peer: AuthenticatedPeer
    parent: ParentAuthority
    proposal: RuntimeProposal
    message: Message
    source_token: str
    approvals: ApprovalStore
    target: SupportMCP
    adapter: ProtocolAdapter


def reviewed_environment(
    *, action: str = "read", operation_id: str = "op-1901"
) -> LabEnvironment:
    now = utc("2026-10-28T20:00:00Z")
    peer = AuthenticatedPeer(
        "triage-agent",
        "spiffe://acme.test/a2a/triage",
        "acme",
        "mtls-cert-42",
    )
    skill_id = "ticket-comment" if action == "comment" else "ticket-read"
    proposal = RuntimeProposal(
        operation_id=operation_id,
        attempt_id="attempt-1",
        skill_id=skill_id,
        ticket_id="acme-7",
        purpose="resolve-support-case",
        traceparent=(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ),
        deadline=now + timedelta(minutes=2),
        comment=(
            "Customer identity verified; retry payment."
            if action == "comment"
            else None
        ),
        approval_id=f"approval-{operation_id}" if action == "comment" else None,
    )
    contract = ACTION_CONTRACTS[skill_id]
    parent = ParentAuthority(
        subject="user:acme:42",
        actor=peer.agent_id,
        tenant_id="acme",
        actions=(contract.action,),
        resources=(resource_for("acme", "acme-7"),),
        purpose="resolve-support-case",
        expires_at=now + timedelta(minutes=5),
    )
    message = build_a2a_message(proposal)
    source_token = issue_source_grant(
        parent, peer, proposal, message, now=now
    )
    approvals = ApprovalStore()
    if action == "comment":
        approvals.issue(
            approval_id=proposal.approval_id or "",
            parent=parent,
            proposal=proposal,
            now=now,
        )
    target = SupportMCP(approvals)
    adapter = ProtocolAdapter(target, approvals)
    return LabEnvironment(
        now,
        peer,
        parent,
        proposal,
        message,
        source_token,
        approvals,
        target,
        adapter,
    )


async def run_demo_async() -> dict[str, Any]:
    read_env = reviewed_environment(action="read", operation_id="op-read")
    read = await read_env.adapter.compose(
        peer=read_env.peer,
        parent=read_env.parent,
        proposal=read_env.proposal,
        message=read_env.message,
        source_token=read_env.source_token,
        now=read_env.now,
    )
    comment_env = reviewed_environment(
        action="comment", operation_id="op-comment"
    )
    unknown = await comment_env.adapter.compose(
        peer=comment_env.peer,
        parent=comment_env.parent,
        proposal=comment_env.proposal,
        message=comment_env.message,
        source_token=comment_env.source_token,
        now=comment_env.now,
        simulate="response-loss-after-effect",
    )
    reconciled = await comment_env.adapter.compose(
        peer=comment_env.peer,
        parent=comment_env.parent,
        proposal=comment_env.proposal,
        message=comment_env.message,
        source_token=comment_env.source_token,
        now=comment_env.now,
    )
    labelled = [
        ("valid-read", True, read.state == OutcomeState.COMPLETED),
        (
            "valid-comment",
            True,
            reconciled.state == OutcomeState.COMPLETED,
        ),
        (
            "unknown-is-not-success",
            False,
            unknown.state == OutcomeState.COMPLETED,
        ),
        (
            "denial-is-not-retryable",
            False,
            classify_failure("TARGET_TENANT_DENIED").retryable,
        ),
    ]
    correct = sum(expected == observed for _, expected, observed in labelled)
    unsafe_allows = sum(
        not expected and observed for _, expected, observed in labelled
    )
    false_blocks = sum(
        expected and not observed for _, expected, observed in labelled
    )
    normalized = comment_env.adapter.normalize(
        comment_env.peer,
        comment_env.parent,
        comment_env.proposal,
        comment_env.message,
        now=comment_env.now,
    )
    target_token = TokenExchange().exchange(
        comment_env.source_token,
        normalized,
        comment_env.message,
        now=comment_env.now,
    )
    return {
        "sdk_types": {
            "a2a": type(read_env.message).__name__,
            "mcp": type(read_env.target.server).__name__,
        },
        "protocols": {
            "a2a": A2A_PROTOCOL_VERSION,
            "mcp": MCP_PROTOCOL_VERSION,
        },
        "read": asdict(read),
        "unknown": asdict(unknown),
        "reconciled": asdict(reconciled),
        "comment_effect_count": len(comment_env.target.comments),
        "source_and_target_tokens_are_distinct": (
            comment_env.source_token != target_token
        ),
        "campaign": {
            "cases": labelled,
            "decision_accuracy": correct / len(labelled),
            "unsafe_allow_rate": unsafe_allows / 2,
            "false_block_rate": false_blocks / 2,
            "duplicate_effect_rate": max(
                0, len(comment_env.target.comments) - 1
            ),
        },
    }


def run_demo() -> dict[str, Any]:
    return asyncio.run(run_demo_async())


def main() -> None:
    result = run_demo()
    assert result["comment_effect_count"] == 1
    assert result["reconciled"]["reconciled"] is True
    assert result["campaign"]["unsafe_allow_rate"] == 0
    print(json.dumps(result, indent=2, default=str))
    print(
        "PASS: authority, lifecycle, error, trace, and effect invariants "
        "survived composition"
    )


if __name__ == "__main__":
    main()
