"""Course 07: deterministic authorization policy and enforcement for MCP tools.

The lab uses Pydantic for strict contracts and the official MCP Python SDK for
real tool calls. Identity is injected through trusted session state, never tool
arguments. The in-memory stores make the course credential-free; they do not
claim distributed durability or production approval/execution guarantees.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
import json
from threading import Lock
from typing import Any, Literal

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


POLICY_VERSION = "support-authz/7"
MAX_REPLY_CHARS = 800


class Effect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Risk(StrEnum):
    LOW = "low"
    ELEVATED = "elevated"


class AuthenticatedPrincipal(BaseModel):
    """Identity and grants derived from authenticated application state."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    subject: str = Field(min_length=1, max_length=80)
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    roles: frozenset[str]
    permissions: frozenset[str]
    suspended: bool = False


class RequestContext(BaseModel):
    """Trusted request facts assembled by the application, not by the model."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    request_id: str = Field(min_length=1, max_length=80)
    purpose: Literal["support", "audit"]
    managed_device: bool
    risk: Risk
    now: datetime

    @model_validator(mode="after")
    def require_utc(self):
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return self


class TicketResource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    ticket_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}-[0-9]{1,8}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    assigned_subjects: frozenset[str]
    classification: Literal["internal", "restricted"]
    status: Literal["open", "closed"]
    version: int = Field(ge=1)
    relationship_revision: int = Field(ge=1)
    title: str
    customer_email: str
    internal_note: str


class PolicyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    version: str
    activated_at: datetime
    permitted_actions: frozenset[str]


class AuthorizationInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    principal: AuthenticatedPrincipal
    action: str
    resource: TicketResource
    context: RequestContext
    policy_version: str
    operation_id: str | None = None
    proposal_digest: str | None = None
    approval_id: str | None = None


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    decision_id: str
    effect: Effect
    reason_code: str
    policy_version: str
    obligations: tuple[str, ...] = ()
    relationship_revision: int


class ReplyProposal(BaseModel):
    """Validated proposal; still not authority to execute the reply."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]{3,64}$")
    ticket_id: str
    resource_version: int = Field(ge=1)
    body: str = Field(min_length=1, max_length=MAX_REPLY_CHARS)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @staticmethod
    def compute_digest(operation_id: str, ticket_id: str, resource_version: int, body: str) -> str:
        canonical = json.dumps(
            {
                "body": body,
                "operation_id": operation_id,
                "resource_version": resource_version,
                "ticket_id": ticket_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode()).hexdigest()

    @classmethod
    def create(cls, *, operation_id: str, ticket_id: str, resource_version: int, body: str):
        normalized = body.strip()
        return cls(
            operation_id=operation_id,
            ticket_id=ticket_id,
            resource_version=resource_version,
            body=normalized,
            digest=cls.compute_digest(operation_id, ticket_id, resource_version, normalized),
        )

    @model_validator(mode="after")
    def validate_digest(self):
        expected = self.compute_digest(
            self.operation_id, self.ticket_id, self.resource_version, self.body
        )
        if self.digest != expected:
            raise ValueError("proposal digest mismatch")
        return self


class ReceiptState(StrEnum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    REVOKED = "revoked"


@dataclass
class ApprovalReceipt:
    receipt_id: str
    tenant_id: str
    subject: str
    action: str
    resource_id: str
    operation_id: str
    proposal_digest: str
    resource_version: int
    policy_version: str
    approver_subject: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime
    state: ReceiptState = ReceiptState.ISSUED
    consumed_at: datetime | None = None


class AuthorizationDenied(RuntimeError):
    def __init__(self, code: str, message: str = "request is not authorized") -> None:
        super().__init__(message)
        self.code = code


class PolicyRepository:
    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle
        self.available = True

    def active(self) -> PolicyBundle:
        if not self.available:
            raise RuntimeError("policy repository unavailable")
        return self._bundle

    def activate(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle


class TicketStore:
    def __init__(self, tickets: list[TicketResource]) -> None:
        self._tickets = {ticket.ticket_id: ticket for ticket in tickets}
        self.available = True

    def get(self, ticket_id: str) -> TicketResource:
        if not self.available:
            raise RuntimeError("resource attribute store unavailable")
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise AuthorizationDenied("RESOURCE_NOT_AVAILABLE", "ticket is unavailable")
        return ticket

    def update(self, ticket: TicketResource) -> None:
        self._tickets[ticket.ticket_id] = ticket


class ApprovalStore:
    """Trusted receipt store; issuance is intentionally not exposed as an MCP tool."""

    def __init__(self) -> None:
        self._receipts: dict[str, ApprovalReceipt] = {}
        self._sequence = 0

    def issue(
        self,
        *,
        approver: AuthenticatedPrincipal,
        principal: AuthenticatedPrincipal,
        proposal: ReplyProposal,
        policy_version: str,
        now: datetime,
        lifetime: timedelta = timedelta(minutes=5),
    ) -> ApprovalReceipt:
        if approver.tenant_id != principal.tenant_id:
            raise AuthorizationDenied("APPROVER_TENANT_MISMATCH")
        if "support_supervisor" not in approver.roles:
            raise AuthorizationDenied("APPROVER_ROLE_REQUIRED")
        if "approval:issue" not in approver.permissions:
            raise AuthorizationDenied("APPROVER_PERMISSION_REQUIRED")
        if approver.subject == principal.subject:
            raise AuthorizationDenied("SEPARATION_OF_DUTIES_REQUIRED")
        self._sequence += 1
        receipt = ApprovalReceipt(
            receipt_id=f"approval-{self._sequence}",
            tenant_id=principal.tenant_id,
            subject=principal.subject,
            action="ticket.reply.send",
            resource_id=proposal.ticket_id,
            operation_id=proposal.operation_id,
            proposal_digest=proposal.digest,
            resource_version=proposal.resource_version,
            policy_version=policy_version,
            approver_subject=approver.subject,
            approver_role="support_supervisor",
            issued_at=now,
            expires_at=now + lifetime,
        )
        self._receipts[receipt.receipt_id] = receipt
        return receipt

    def inspect(self, request: AuthorizationInput) -> tuple[bool, str]:
        receipt = self._receipts.get(request.approval_id or "")
        if receipt is None:
            return False, "APPROVAL_REQUIRED"
        expected = {
            "tenant_id": request.principal.tenant_id,
            "subject": request.principal.subject,
            "action": request.action,
            "resource_id": request.resource.ticket_id,
            "operation_id": request.operation_id,
            "proposal_digest": request.proposal_digest,
            "resource_version": request.resource.version,
            "policy_version": request.policy_version,
        }
        for field_name, value in expected.items():
            if getattr(receipt, field_name) != value:
                return False, f"APPROVAL_{field_name.upper()}_MISMATCH"
        if receipt.state is ReceiptState.CONSUMED:
            return False, "APPROVAL_ALREADY_CONSUMED"
        if receipt.state is ReceiptState.REVOKED:
            return False, "APPROVAL_REVOKED"
        if request.context.now < receipt.issued_at:
            return False, "APPROVAL_NOT_YET_VALID"
        if request.context.now >= receipt.expires_at:
            return False, "APPROVAL_EXPIRED"
        return True, "APPROVAL_VALID"

    def consume(self, receipt_id: str, now: datetime) -> None:
        receipt = self._receipts[receipt_id]
        if receipt.state is not ReceiptState.ISSUED:
            raise AuthorizationDenied("APPROVAL_ALREADY_USED")
        receipt.state = ReceiptState.CONSUMED
        receipt.consumed_at = now

    def revoke(self, receipt_id: str) -> None:
        receipt = self._receipts[receipt_id]
        if receipt.state is ReceiptState.ISSUED:
            receipt.state = ReceiptState.REVOKED

    def get(self, receipt_id: str) -> ApprovalReceipt:
        return self._receipts[receipt_id]


class PolicyDecisionPoint:
    """Small Cedar-shaped PARC evaluator: default deny and deny overrides."""

    ACTION_PERMISSIONS = {
        "ticket.read": "ticket:read",
        "ticket.reply.draft": "ticket:reply:draft",
        "ticket.reply.send": "ticket:reply:send",
        "ticket.reply.status": "ticket:reply:send",
    }

    def __init__(self, repository: PolicyRepository, approvals: ApprovalStore) -> None:
        self.repository = repository
        self.approvals = approvals

    @staticmethod
    def _decision(
        request: AuthorizationInput,
        effect: Effect,
        reason: str,
        obligations: tuple[str, ...] = (),
    ) -> AuthorizationDecision:
        material = json.dumps(
            {
                "action": request.action,
                "policy": request.policy_version,
                "request": request.context.request_id,
                "resource": request.resource.ticket_id,
                "revision": request.resource.relationship_revision,
                "subject": request.principal.subject,
            },
            sort_keys=True,
        )
        return AuthorizationDecision(
            decision_id="decision-" + sha256(material.encode()).hexdigest()[:16],
            effect=effect,
            reason_code=reason,
            policy_version=request.policy_version,
            obligations=obligations,
            relationship_revision=request.resource.relationship_revision,
        )

    def decide(self, request: AuthorizationInput) -> AuthorizationDecision:
        bundle = self.repository.active()
        if request.policy_version != bundle.version:
            return self._decision(request, Effect.DENY, "POLICY_VERSION_STALE")
        if request.action not in bundle.permitted_actions:
            return self._decision(request, Effect.DENY, "ACTION_NOT_IN_POLICY")
        if request.principal.suspended:
            return self._decision(request, Effect.DENY, "PRINCIPAL_SUSPENDED")
        if request.principal.tenant_id != request.resource.tenant_id:
            return self._decision(request, Effect.DENY, "TENANT_MISMATCH")
        if request.context.purpose != "support":
            return self._decision(request, Effect.DENY, "PURPOSE_NOT_ALLOWED")
        permission = self.ACTION_PERMISSIONS.get(request.action)
        if permission is None or permission not in request.principal.permissions:
            return self._decision(request, Effect.DENY, "PERMISSION_MISSING")
        if "support_agent" not in request.principal.roles:
            return self._decision(request, Effect.DENY, "ROLE_NOT_ALLOWED")
        if request.principal.subject not in request.resource.assigned_subjects:
            return self._decision(request, Effect.DENY, "RELATIONSHIP_MISSING")

        if request.action.startswith("ticket.reply") and request.resource.status != "open":
            return self._decision(request, Effect.DENY, "RESOURCE_STATE_DENIED")
        if request.action == "ticket.reply.send":
            if not request.context.managed_device:
                return self._decision(request, Effect.DENY, "DEVICE_POSTURE_REQUIRED")
            if request.context.risk is not Risk.LOW:
                return self._decision(request, Effect.DENY, "RISK_TOO_HIGH")
            approved, reason = self.approvals.inspect(request)
            if not approved:
                return self._decision(request, Effect.DENY, reason)
            return self._decision(
                request,
                Effect.ALLOW,
                "REPLY_SEND_ALLOWED",
                ("consume:approval", "audit:effect", "verify:result"),
            )
        if request.action == "ticket.read":
            obligations = ("redact:customer_email", "omit:internal_note")
            return self._decision(request, Effect.ALLOW, "TICKET_READ_ALLOWED", obligations)
        if request.action == "ticket.reply.status":
            return self._decision(
                request,
                Effect.ALLOW,
                "REPLY_STATUS_ALLOWED",
                ("release:operation-status-only",),
            )
        return self._decision(
            request,
            Effect.ALLOW,
            "REPLY_DRAFT_ALLOWED",
            ("label:proposal", "execute:false"),
        )


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    operation_id: str | None
    decision_id: str
    subject: str
    tenant_id: str
    action: str
    resource_id: str
    effect: str
    reason_code: str
    policy_version: str
    relationship_revision: int
    obligations: tuple[str, ...]
    approval_id: str | None


class ReplyExecution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    operation_id: str
    ticket_id: str
    proposal_digest: str
    subject: str
    tenant_id: str
    status: Literal["sent"] = "sent"
    executed_at: datetime


@dataclass
class EnforcementPoint:
    """Trusted application boundary: assemble facts, ask PDP, enforce result."""

    policies: PolicyRepository
    tickets: TicketStore
    approvals: ApprovalStore
    pdp: PolicyDecisionPoint
    audit: list[AuditEvent] = field(default_factory=list)
    executions: dict[str, ReplyExecution] = field(default_factory=dict)
    _execution_lock: Lock = field(default_factory=Lock)

    def _request(
        self,
        *,
        principal: AuthenticatedPrincipal,
        action: str,
        ticket: TicketResource,
        context: RequestContext,
        operation_id: str | None = None,
        proposal_digest: str | None = None,
        approval_id: str | None = None,
    ) -> AuthorizationInput:
        try:
            policy_version = self.policies.active().version
        except Exception:
            policy_version = "unavailable"
        return AuthorizationInput(
            principal=principal,
            action=action,
            resource=ticket,
            context=context,
            policy_version=policy_version,
            operation_id=operation_id,
            proposal_digest=proposal_digest,
            approval_id=approval_id,
        )

    def _authorize(self, request: AuthorizationInput) -> AuthorizationDecision:
        try:
            decision = self.pdp.decide(request)
        except Exception:
            decision = PolicyDecisionPoint._decision(
                request, Effect.DENY, "POLICY_EVALUATION_ERROR"
            )
        self.audit.append(
            AuditEvent(
                request_id=request.context.request_id,
                operation_id=request.operation_id,
                decision_id=decision.decision_id,
                subject=request.principal.subject,
                tenant_id=request.principal.tenant_id,
                action=request.action,
                resource_id=request.resource.ticket_id,
                effect=decision.effect.value,
                reason_code=decision.reason_code,
                policy_version=decision.policy_version,
                relationship_revision=decision.relationship_revision,
                obligations=decision.obligations,
                approval_id=request.approval_id,
            )
        )
        if decision.effect is Effect.DENY:
            raise AuthorizationDenied(decision.reason_code)
        return decision

    def _load_ticket(self, ticket_id: str) -> TicketResource:
        try:
            return self.tickets.get(ticket_id)
        except AuthorizationDenied:
            raise
        except Exception as exc:
            raise AuthorizationDenied("RESOURCE_ATTRIBUTES_UNAVAILABLE") from exc

    def read_ticket(
        self,
        principal: AuthenticatedPrincipal,
        ticket_id: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        ticket = self._load_ticket(ticket_id)
        decision = self._authorize(
            self._request(principal=principal, action="ticket.read", ticket=ticket, context=context)
        )
        result: dict[str, Any] = ticket.model_dump(mode="json")
        if "redact:customer_email" in decision.obligations:
            result["customer_email"] = "[redacted]"
        if "omit:internal_note" in decision.obligations:
            result.pop("internal_note", None)
        result["authorization_decision_id"] = decision.decision_id
        return result

    def prepare_reply(
        self,
        principal: AuthenticatedPrincipal,
        *,
        ticket_id: str,
        operation_id: str,
        body: str,
        context: RequestContext,
    ) -> ReplyProposal:
        ticket = self._load_ticket(ticket_id)
        self._authorize(
            self._request(
                principal=principal,
                action="ticket.reply.draft",
                ticket=ticket,
                context=context,
                operation_id=operation_id,
            )
        )
        return ReplyProposal.create(
            operation_id=operation_id,
            ticket_id=ticket.ticket_id,
            resource_version=ticket.version,
            body=body,
        )

    def send_reply(
        self,
        principal: AuthenticatedPrincipal,
        *,
        proposal: ReplyProposal,
        approval_id: str,
        context: RequestContext,
    ) -> tuple[ReplyExecution, bool]:
        ticket = self._load_ticket(proposal.ticket_id)
        if ticket.version != proposal.resource_version:
            raise AuthorizationDenied("RESOURCE_VERSION_STALE")
        with self._execution_lock:
            previous = self.executions.get(proposal.operation_id)
            if previous is not None:
                if previous.proposal_digest != proposal.digest:
                    raise AuthorizationDenied("IDEMPOTENCY_CONFLICT")
                if (
                    previous.subject != principal.subject
                    or previous.tenant_id != principal.tenant_id
                ):
                    raise AuthorizationDenied("OPERATION_OWNER_MISMATCH")
                self._authorize(
                    self._request(
                        principal=principal,
                        action="ticket.reply.status",
                        ticket=ticket,
                        context=context,
                        operation_id=proposal.operation_id,
                        proposal_digest=proposal.digest,
                    )
                )
                return previous, True
            request = self._request(
                principal=principal,
                action="ticket.reply.send",
                ticket=ticket,
                context=context,
                operation_id=proposal.operation_id,
                proposal_digest=proposal.digest,
                approval_id=approval_id,
            )
            self._authorize(request)
            self.approvals.consume(approval_id, context.now)
            execution = ReplyExecution(
                operation_id=proposal.operation_id,
                ticket_id=proposal.ticket_id,
                proposal_digest=proposal.digest,
                subject=principal.subject,
                tenant_id=principal.tenant_id,
                executed_at=context.now,
            )
            self.executions[proposal.operation_id] = execution
            return execution, False


@dataclass(frozen=True)
class TrustedSession:
    principal: AuthenticatedPrincipal
    purpose: Literal["support", "audit"]
    managed_device: bool
    risk: Risk
    now: datetime


def build_mcp_server(enforcement: EnforcementPoint, session: TrustedSession) -> MCPServer:
    """Bind an authenticated session outside schemas exposed to the model."""

    server = MCPServer("northstar-policy-enforced-support")
    request_sequence = 0

    def context() -> RequestContext:
        nonlocal request_sequence
        request_sequence += 1
        return RequestContext(
            request_id=f"request-{request_sequence}",
            purpose=session.purpose,
            managed_device=session.managed_device,
            risk=session.risk,
            now=session.now,
        )

    @server.tool(name="ticket.read")
    def ticket_read(ticket_id: str) -> dict[str, Any]:
        try:
            return enforcement.read_ticket(session.principal, ticket_id, context())
        except AuthorizationDenied as exc:
            raise ToolError("ticket is unavailable") from exc

    @server.tool(name="ticket.reply.prepare")
    def reply_prepare(ticket_id: str, operation_id: str, body: str) -> dict[str, Any]:
        try:
            return enforcement.prepare_reply(
                session.principal,
                ticket_id=ticket_id,
                operation_id=operation_id,
                body=body,
                context=context(),
            ).model_dump(mode="json")
        except (AuthorizationDenied, ValidationError) as exc:
            raise ToolError("reply proposal denied") from exc

    @server.tool(name="ticket.reply.send")
    def reply_send(proposal: ReplyProposal, approval_id: str) -> dict[str, Any]:
        try:
            execution, deduplicated = enforcement.send_reply(
                session.principal,
                proposal=proposal,
                approval_id=approval_id,
                context=context(),
            )
            return {
                **execution.model_dump(
                    mode="json", exclude={"subject", "tenant_id"}
                ),
                "deduplicated": deduplicated,
            }
        except (AuthorizationDenied, ValidationError) as exc:
            raise ToolError("reply send denied") from exc

    return server


@dataclass(frozen=True)
class PolicyCase:
    name: str
    principal: AuthenticatedPrincipal
    action: str
    ticket_id: str
    purpose: Literal["support", "audit"]
    expected: Effect


@dataclass(frozen=True)
class EvaluationReport:
    total: int
    expected_allows: int
    expected_denies: int
    false_allows: int
    false_denies: int
    false_allow_rate: float
    false_deny_rate: float


def evaluate_cases(enforcement: EnforcementPoint, cases: tuple[PolicyCase, ...], now: datetime) -> EvaluationReport:
    false_allows = 0
    false_denies = 0
    expected_allows = sum(case.expected is Effect.ALLOW for case in cases)
    expected_denies = len(cases) - expected_allows
    for index, case in enumerate(cases, 1):
        try:
            ticket = enforcement.tickets.get(case.ticket_id)
            request = enforcement._request(
                principal=case.principal,
                action=case.action,
                ticket=ticket,
                context=RequestContext(
                    request_id=f"evaluation-{index}",
                    purpose=case.purpose,
                    managed_device=True,
                    risk=Risk.LOW,
                    now=now,
                ),
            )
            actual = enforcement.pdp.decide(request).effect
        except Exception:
            actual = Effect.DENY
        false_allows += int(actual is Effect.ALLOW and case.expected is Effect.DENY)
        false_denies += int(actual is Effect.DENY and case.expected is Effect.ALLOW)
    return EvaluationReport(
        total=len(cases),
        expected_allows=expected_allows,
        expected_denies=expected_denies,
        false_allows=false_allows,
        false_denies=false_denies,
        false_allow_rate=false_allows / expected_denies if expected_denies else 0.0,
        false_deny_rate=false_denies / expected_allows if expected_allows else 0.0,
    )


def default_environment(now: datetime | None = None):
    now = now or datetime.now(UTC)
    bundle = PolicyBundle(
        version=POLICY_VERSION,
        activated_at=now - timedelta(hours=1),
        permitted_actions=frozenset(
            {
                "ticket.read",
                "ticket.reply.draft",
                "ticket.reply.send",
                "ticket.reply.status",
            }
        ),
    )
    repository = PolicyRepository(bundle)
    tickets = TicketStore(
        [
            TicketResource(
                ticket_id="acme-100",
                tenant_id="acme",
                assigned_subjects=frozenset({"analyst-42"}),
                classification="restricted",
                status="open",
                version=3,
                relationship_revision=12,
                title="Invoice retry",
                customer_email="customer@example.test",
                internal_note="Account recovery evidence attached",
            ),
            TicketResource(
                ticket_id="acme-101",
                tenant_id="acme",
                assigned_subjects=frozenset({"analyst-99"}),
                classification="internal",
                status="closed",
                version=2,
                relationship_revision=10,
                title="Resolved export delay",
                customer_email="other@example.test",
                internal_note="Closed after confirmation",
            ),
            TicketResource(
                ticket_id="globex-200",
                tenant_id="globex",
                assigned_subjects=frozenset({"analyst-42"}),
                classification="restricted",
                status="open",
                version=1,
                relationship_revision=4,
                title="Partner sync issue",
                customer_email="partner@example.test",
                internal_note="Globex-only context",
            ),
        ]
    )
    approvals = ApprovalStore()
    pdp = PolicyDecisionPoint(repository, approvals)
    enforcement = EnforcementPoint(repository, tickets, approvals, pdp)
    agent = AuthenticatedPrincipal(
        subject="analyst-42",
        tenant_id="acme",
        roles=frozenset({"support_agent"}),
        permissions=frozenset(
            {"ticket:read", "ticket:reply:draft", "ticket:reply:send"}
        ),
    )
    supervisor = AuthenticatedPrincipal(
        subject="supervisor-7",
        tenant_id="acme",
        roles=frozenset({"support_supervisor"}),
        permissions=frozenset({"approval:issue"}),
    )
    session = TrustedSession(agent, "support", True, Risk.LOW, now)
    return enforcement, agent, supervisor, session


def parse_tool_json(result: Any) -> dict[str, Any]:
    return json.loads(result.content[0].text)


async def run_scenario() -> dict[str, Any]:
    now = datetime(2026, 9, 27, 16, 0, tzinfo=UTC)
    enforcement, agent, supervisor, session = default_environment(now)
    server = build_mcp_server(enforcement, session)
    async with Client(server, raise_exceptions=False) as client:
        allowed_read = await client.call_tool("ticket.read", {"ticket_id": "acme-100"})
        cross_tenant = await client.call_tool("ticket.read", {"ticket_id": "globex-200"})
        prepared = await client.call_tool(
            "ticket.reply.prepare",
            {
                "ticket_id": "acme-100",
                "operation_id": "op-reply-100",
                "body": "We retried the invoice and confirmed recovery.",
            },
        )
        proposal = ReplyProposal.model_validate(parse_tool_json(prepared))
        without_approval = await client.call_tool(
            "ticket.reply.send",
            {"proposal": proposal.model_dump(mode="json"), "approval_id": "missing"},
        )
        receipt = enforcement.approvals.issue(
            approver=supervisor,
            principal=agent,
            proposal=proposal,
            policy_version=POLICY_VERSION,
            now=now,
        )
        sent = await client.call_tool(
            "ticket.reply.send",
            {"proposal": proposal.model_dump(mode="json"), "approval_id": receipt.receipt_id},
        )
        retried = await client.call_tool(
            "ticket.reply.send",
            {"proposal": proposal.model_dump(mode="json"), "approval_id": receipt.receipt_id},
        )

    read_payload = parse_tool_json(allowed_read)
    sent_payload = parse_tool_json(sent)
    retried_payload = parse_tool_json(retried)
    audit_json = json.dumps([event.__dict__ for event in enforcement.audit], default=str)
    evidence = {
        "read_allowed": not allowed_read.is_error,
        "cross_tenant_denied": cross_tenant.is_error,
        "unapproved_send_denied": without_approval.is_error,
        "send_executed": sent_payload["status"] == "sent",
        "retry_deduplicated": retried_payload["deduplicated"],
        "execution_count": len(enforcement.executions),
        "approval_state": enforcement.approvals.get(receipt.receipt_id).state.value,
        "customer_email": read_payload["customer_email"],
        "internal_note_exposed": "internal_note" in read_payload,
        "reply_body_in_audit": proposal.body in audit_json,
        "decision_reasons": sorted({event.reason_code for event in enforcement.audit}),
    }
    assert evidence == {
        "read_allowed": True,
        "cross_tenant_denied": True,
        "unapproved_send_denied": True,
        "send_executed": True,
        "retry_deduplicated": True,
        "execution_count": 1,
        "approval_state": "consumed",
        "customer_email": "[redacted]",
        "internal_note_exposed": False,
        "reply_body_in_audit": False,
        "decision_reasons": [
            "APPROVAL_REQUIRED",
            "REPLY_DRAFT_ALLOWED",
            "REPLY_SEND_ALLOWED",
            "REPLY_STATUS_ALLOWED",
            "TENANT_MISMATCH",
            "TICKET_READ_ALLOWED",
        ],
    }
    return evidence


def main() -> None:
    evidence = asyncio.run(run_scenario())
    print("PASS: trusted policy—not model choice—authorizes and constrains MCP effects")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
