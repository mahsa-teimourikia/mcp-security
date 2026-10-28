"""Course 18 lab: secure an A2A task handoff without trusting agent prose.

The exercise is deterministic and offline. It uses the official ``a2a-sdk``
wire types, PyJWT for a compact training token, and in-memory policy stores.
Production systems should replace the shared training key, static DNS view,
and process-local stores with an authorization server, durable atomic storage,
and network enforcement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import hmac
import ipaddress
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
)
from google.protobuf.struct_pb2 import Struct, Value
import jwt


PROTOCOL_VERSION = "1.0"
TOKEN_ISSUER = "https://sts.acme.test"
TOKEN_SIGNING_KEY = "course-18-training-key-not-for-production"
CARD_SIGNING_KEY = b"course-18-card-key-not-for-production"
MAX_CLOCK_SKEW_SECONDS = 5
MAX_DELEGATION_SECONDS = 300
MAX_DELEGATION_DEPTH = 2
REQUIRED_EXTENSION = "https://acme.test/a2a/extensions/task-grant/v1"
ALLOWED_PUSH_HOSTS = frozenset({"hooks.acme.test"})
ALLOWED_PUSH_PATH_PREFIXES = ("/a2a/",)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PeerState(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class A2ADenied(RuntimeError):
    """A stable machine-readable denial, safe to aggregate in telemetry."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def utc(value: str) -> datetime:
    """Parse a canonical ``Z`` timestamp and reject ambiguous local time."""

    if not value.endswith("Z"):
        raise ValueError("timestamp must be UTC and end in Z")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError("timestamp must be UTC")
    return parsed


def timestamp(value: datetime) -> int:
    if value.tzinfo != UTC:
        raise ValueError("timestamp must be UTC")
    return int(value.timestamp())


def canonical_json(value: Any) -> str:
    if hasattr(value, "unsigned"):
        value = value.unsigned()
    elif hasattr(value, "DESCRIPTOR"):
        value = value.SerializeToString(deterministic=True).hex()
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def sign_peer_record(value: Any) -> str:
    return hmac.new(
        CARD_SIGNING_KEY, canonical_json(value).encode(), hashlib.sha256
    ).hexdigest()


def card_digest(card: AgentCard) -> str:
    return hashlib.sha256(card.SerializeToString(deterministic=True)).hexdigest()


def build_agent_card(*, version: str = "2.4.0") -> AgentCard:
    """Create a real A2A v1 card. It advertises; it does not authorize."""

    return AgentCard(
        name="acme-support-agent",
        description="Tenant-bound support ticket analysis",
        version=version,
        supported_interfaces=[
            AgentInterface(
                url="https://support-agent.acme.test/a2a",
                protocol_binding="HTTP+JSON",
                protocol_version=PROTOCOL_VERSION,
            )
        ],
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=True,
            extended_agent_card=True,
        ),
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json"],
        skills=[
            AgentSkill(
                id="ticket-triage",
                name="Ticket triage",
                description="Read and classify an existing support ticket",
                tags=["support", "read-only"],
                input_modes=["application/json"],
                output_modes=["application/json"],
            )
        ],
    )


@dataclass(frozen=True)
class AuthenticatedWorkload:
    """Identity obtained from mTLS/workload auth, never message metadata."""

    agent_id: str
    spiffe_id: str
    tenant_id: str
    credential_id: str


@dataclass(frozen=True)
class PeerRecord:
    agent_id: str
    card_name: str
    card_version: str
    card_digest: str
    record_signature: str
    endpoint: str
    protocol_version: str
    workload_id: str
    tenants: tuple[str, ...]
    skills: tuple[str, ...]
    supported_extensions: tuple[str, ...]
    state: PeerState
    reviewed_at: datetime
    expires_at: datetime

    def unsigned(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "record_signature"}


class PeerDirectory:
    """The reviewed trust plane; public discovery alone never reaches it."""

    def __init__(self) -> None:
        self._records: dict[str, PeerRecord] = {}

    def admit(
        self,
        *,
        agent_id: str,
        card: AgentCard,
        workload_id: str,
        tenants: Iterable[str],
        supported_extensions: Iterable[str],
        now: datetime,
    ) -> PeerRecord:
        if not agent_id or not workload_id.startswith("spiffe://"):
            raise A2ADenied("PEER_IDENTITY_INVALID")
        if not card.name or not card.version or len(card.supported_interfaces) != 1:
            raise A2ADenied("AGENT_CARD_INCOMPLETE")
        interface = card.supported_interfaces[0]
        require_https_url(interface.url, code="AGENT_ENDPOINT_INVALID")
        if interface.protocol_version != PROTOCOL_VERSION:
            raise A2ADenied("PROTOCOL_VERSION_UNSUPPORTED")
        tenant_set = tuple(sorted(set(tenants)))
        if not tenant_set or any(not tenant for tenant in tenant_set):
            raise A2ADenied("PEER_TENANT_INVALID")
        skill_ids = tuple(sorted(skill.id for skill in card.skills))
        if not skill_ids or any(not skill for skill in skill_ids):
            raise A2ADenied("PEER_SKILL_INVALID")
        reviewed_digest = card_digest(card)
        unsigned_record = PeerRecord(
            agent_id=agent_id,
            card_name=card.name,
            card_version=card.version,
            card_digest=reviewed_digest,
            record_signature="",
            endpoint=interface.url,
            protocol_version=interface.protocol_version,
            workload_id=workload_id,
            tenants=tenant_set,
            skills=skill_ids,
            supported_extensions=tuple(sorted(set(supported_extensions))),
            state=PeerState.ACTIVE,
            reviewed_at=now,
            expires_at=now + timedelta(days=30),
        )
        record = replace(
            unsigned_record,
            record_signature=sign_peer_record(unsigned_record.unsigned()),
        )
        self._records[agent_id] = record
        return record

    def replace(self, record: PeerRecord) -> None:
        self._records[record.agent_id] = record

    def require_peer(
        self,
        principal: AuthenticatedWorkload,
        *,
        tenant_id: str,
        now: datetime,
    ) -> PeerRecord:
        record = self._records.get(principal.agent_id)
        if record is None:
            raise A2ADenied("PEER_NOT_REVIEWED")
        if record.state != PeerState.ACTIVE:
            raise A2ADenied("PEER_NOT_ACTIVE")
        if now < record.reviewed_at - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise A2ADenied("PEER_REVIEW_FROM_FUTURE")
        if now >= record.expires_at:
            raise A2ADenied("PEER_REVIEW_EXPIRED")
        if not hmac.compare_digest(
            record.record_signature, sign_peer_record(record.unsigned())
        ):
            raise A2ADenied("PEER_RECORD_SIGNATURE_INVALID")
        if principal.spiffe_id != record.workload_id:
            raise A2ADenied("WORKLOAD_IDENTITY_MISMATCH")
        if principal.tenant_id != tenant_id or tenant_id not in record.tenants:
            raise A2ADenied("PEER_TENANT_DENIED")
        return record


@dataclass(frozen=True)
class ParentAuthority:
    subject: str
    tenant_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    purpose: str
    expires_at: datetime
    delegation_depth: int = 0
    chain: tuple[str, ...] = ("human-user",)


@dataclass(frozen=True)
class TaskRequest:
    message_id: str
    operation_id: str
    context_id: str
    tenant_id: str
    action: str
    resource: str
    purpose: str
    skill_id: str
    protocol_version: str
    card_digest: str
    required_extensions: tuple[str, ...] = (REQUIRED_EXTENSION,)
    push_url: str | None = None

    def policy_view(self) -> dict[str, Any]:
        return asdict(self)


def build_message(request: TaskRequest) -> Message:
    """Build the official wire object; authority remains outside its content."""

    payload = Struct()
    payload.update(
        {
            "action": request.action,
            "resource": request.resource,
            "purpose": request.purpose,
            "skillId": request.skill_id,
            "operationId": request.operation_id,
        }
    )
    return Message(
        message_id=request.message_id,
        context_id=request.context_id,
        role=Role.ROLE_USER,
        parts=[
            Part(
                data=Value(struct_value=payload),
                media_type="application/json",
            )
        ],
        extensions=list(request.required_extensions),
        metadata={"tenantHint": request.tenant_id, "authorization": "untrusted"},
    )


class DelegationBroker:
    """Attenuate parent authority into a short-lived, recipient-bound token."""

    def issue(
        self,
        *,
        parent: ParentAuthority,
        sender: AuthenticatedWorkload,
        recipient_agent_id: str,
        request: TaskRequest,
        now: datetime,
    ) -> str:
        if sender.tenant_id != parent.tenant_id or request.tenant_id != parent.tenant_id:
            raise A2ADenied("DELEGATION_TENANT_ESCALATION")
        if request.action not in parent.actions:
            raise A2ADenied("DELEGATION_ACTION_ESCALATION")
        if request.resource not in parent.resources:
            raise A2ADenied("DELEGATION_RESOURCE_ESCALATION")
        if request.purpose != parent.purpose:
            raise A2ADenied("DELEGATION_PURPOSE_ESCALATION")
        if now >= parent.expires_at:
            raise A2ADenied("PARENT_AUTHORITY_EXPIRED")
        child_depth = parent.delegation_depth + 1
        if child_depth > MAX_DELEGATION_DEPTH:
            raise A2ADenied("DELEGATION_DEPTH_EXCEEDED")
        if recipient_agent_id in parent.chain or sender.agent_id in parent.chain:
            raise A2ADenied("DELEGATION_LOOP")
        expires = min(parent.expires_at, now + timedelta(seconds=MAX_DELEGATION_SECONDS))
        claims = {
            "iss": TOKEN_ISSUER,
            "sub": parent.subject,
            "act": sender.agent_id,
            "aud": recipient_agent_id,
            "tenant": request.tenant_id,
            "action": request.action,
            "resource": request.resource,
            "purpose": request.purpose,
            "message_id": request.message_id,
            "operation_id": request.operation_id,
            "context_id": request.context_id,
            "protocol_version": request.protocol_version,
            "card_digest": request.card_digest,
            "extensions": list(request.required_extensions),
            "depth": child_depth,
            "chain": [*parent.chain, sender.agent_id],
            "parent_digest": digest(parent),
            "iat": timestamp(now),
            "nbf": timestamp(now),
            "exp": timestamp(expires),
            "jti": digest([request.operation_id, request.message_id, sender.credential_id]),
        }
        return jwt.encode(claims, TOKEN_SIGNING_KEY, algorithm="HS256")


def verify_task_grant(
    token: str,
    *,
    recipient_agent_id: str,
    sender: AuthenticatedWorkload,
    request: TaskRequest,
    now: datetime,
) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            TOKEN_SIGNING_KEY,
            algorithms=["HS256"],
            audience=recipient_agent_id,
            issuer=TOKEN_ISSUER,
            options={
                "require": ["exp", "iat", "nbf", "jti", "sub", "aud"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise A2ADenied("TASK_GRANT_EXPIRED") from exc
    except jwt.ImmatureSignatureError as exc:
        raise A2ADenied("TASK_GRANT_NOT_YET_VALID") from exc
    except jwt.InvalidAudienceError as exc:
        raise A2ADenied("TASK_GRANT_WRONG_AUDIENCE") from exc
    except jwt.InvalidTokenError as exc:
        raise A2ADenied("TASK_GRANT_INVALID") from exc

    current = timestamp(now)
    if current >= claims["exp"] + MAX_CLOCK_SKEW_SECONDS:
        raise A2ADenied("TASK_GRANT_EXPIRED")
    if current + MAX_CLOCK_SKEW_SECONDS < claims["nbf"]:
        raise A2ADenied("TASK_GRANT_NOT_YET_VALID")

    expected = {
        "act": sender.agent_id,
        "tenant": request.tenant_id,
        "action": request.action,
        "resource": request.resource,
        "purpose": request.purpose,
        "message_id": request.message_id,
        "operation_id": request.operation_id,
        "context_id": request.context_id,
        "protocol_version": request.protocol_version,
        "card_digest": request.card_digest,
    }
    for name, value in expected.items():
        if claims.get(name) != value:
            raise A2ADenied(f"TASK_GRANT_{name.upper()}_MISMATCH")
    if tuple(claims.get("extensions", ())) != request.required_extensions:
        raise A2ADenied("TASK_GRANT_EXTENSIONS_MISMATCH")
    if not 0 < int(claims.get("depth", 0)) <= MAX_DELEGATION_DEPTH:
        raise A2ADenied("TASK_GRANT_DEPTH_INVALID")
    chain = claims.get("chain", [])
    if len(chain) != len(set(chain)):
        raise A2ADenied("TASK_GRANT_CHAIN_LOOP")
    if claims["exp"] - claims["iat"] > MAX_DELEGATION_SECONDS:
        raise A2ADenied("TASK_GRANT_LIFETIME_EXCESSIVE")
    if current + MAX_CLOCK_SKEW_SECONDS < claims["iat"]:
        raise A2ADenied("TASK_GRANT_ISSUED_IN_FUTURE")
    return claims


def require_https_url(url: str, *, code: str = "URL_INVALID") -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise A2ADenied(code)


def validate_push_url(url: str, *, resolved_ips: Iterable[str]) -> str:
    """Preflight policy. Production must revalidate DNS on connect/redirect."""

    require_https_url(url, code="PUSH_URL_INVALID")
    parsed = urlsplit(url)
    assert parsed.hostname
    if parsed.hostname not in ALLOWED_PUSH_HOSTS:
        raise A2ADenied("PUSH_HOST_NOT_ALLOWED")
    try:
        port = parsed.port
    except ValueError as exc:
        raise A2ADenied("PUSH_PORT_NOT_ALLOWED") from exc
    if port not in (None, 443):
        raise A2ADenied("PUSH_PORT_NOT_ALLOWED")
    if not any(
        parsed.path == prefix.rstrip("/") or parsed.path.startswith(prefix)
        for prefix in ALLOWED_PUSH_PATH_PREFIXES
    ):
        raise A2ADenied("PUSH_PATH_NOT_ALLOWED")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise A2ADenied("PUSH_IP_LITERAL_DENIED")
    addresses = tuple(resolved_ips)
    if not addresses:
        raise A2ADenied("PUSH_DNS_EMPTY")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise A2ADenied("PUSH_DNS_INVALID") from exc
        if not address.is_global:
            raise A2ADenied("PUSH_ADDRESS_NOT_GLOBAL")
    return url


TERMINAL_STATES = frozenset(
    {
        TaskState.TASK_STATE_COMPLETED,
        TaskState.TASK_STATE_FAILED,
        TaskState.TASK_STATE_CANCELED,
        TaskState.TASK_STATE_REJECTED,
    }
)
TRANSITIONS = {
    TaskState.TASK_STATE_SUBMITTED: frozenset(
        {
            TaskState.TASK_STATE_WORKING,
            TaskState.TASK_STATE_CANCELED,
            TaskState.TASK_STATE_REJECTED,
        }
    ),
    TaskState.TASK_STATE_WORKING: frozenset(
        {
            TaskState.TASK_STATE_COMPLETED,
            TaskState.TASK_STATE_FAILED,
            TaskState.TASK_STATE_CANCELED,
            TaskState.TASK_STATE_INPUT_REQUIRED,
            TaskState.TASK_STATE_AUTH_REQUIRED,
        }
    ),
    TaskState.TASK_STATE_INPUT_REQUIRED: frozenset(
        {TaskState.TASK_STATE_WORKING, TaskState.TASK_STATE_CANCELED}
    ),
    TaskState.TASK_STATE_AUTH_REQUIRED: frozenset(
        {TaskState.TASK_STATE_WORKING, TaskState.TASK_STATE_CANCELED}
    ),
}


def transition(task: Task, next_state: int) -> Task:
    current = task.status.state
    if current in TERMINAL_STATES or next_state not in TRANSITIONS.get(current, frozenset()):
        raise A2ADenied("TASK_TRANSITION_INVALID")
    updated = Task()
    updated.CopyFrom(task)
    updated.status.state = next_state
    return updated


@dataclass
class TicketResourceServer:
    """Final enforcement point; it does not inherit the coordinator's trust."""

    owners: dict[str, str] = field(default_factory=lambda: {"ticket/acme-7": "acme"})
    effect_ledger: set[str] = field(default_factory=set)

    def execute(self, claims: dict[str, Any], request: TaskRequest) -> dict[str, Any]:
        if claims.get("aud") != "support-agent":
            raise A2ADenied("RESOURCE_WRONG_AUDIENCE")
        if claims.get("action") != "ticket.read" or request.action != "ticket.read":
            raise A2ADenied("RESOURCE_ACTION_DENIED")
        if self.owners.get(request.resource) != request.tenant_id:
            raise A2ADenied("RESOURCE_TENANT_DENIED")
        if claims.get("tenant") != request.tenant_id:
            raise A2ADenied("RESOURCE_TOKEN_TENANT_MISMATCH")
        operation_id = claims.get("operation_id")
        if not operation_id:
            raise A2ADenied("RESOURCE_OPERATION_ID_REQUIRED")
        duplicate = operation_id in self.effect_ledger
        self.effect_ledger.add(operation_id)
        return {
            "ticket": request.resource.removeprefix("ticket/"),
            "classification": "account-access",
            "duplicate_effect": duplicate,
        }


@dataclass(frozen=True)
class AuditEvent:
    decision: Decision
    code: str
    actor: str
    tenant_id: str
    message_id: str
    operation_id: str
    task_id: str | None
    authority_digest: str


class SecureA2AServer:
    """Recipient-side trust, authorization, idempotency, and task lifecycle."""

    def __init__(
        self,
        *,
        agent_id: str,
        card: AgentCard,
        peers: PeerDirectory,
        resource_server: TicketResourceServer,
    ) -> None:
        self.agent_id = agent_id
        self.card = card
        self.peers = peers
        self.resource_server = resource_server
        self._messages: dict[str, tuple[str, str]] = {}
        self._tasks: dict[str, Task] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self.audit: list[AuditEvent] = []

    def receive(
        self,
        *,
        principal: AuthenticatedWorkload,
        request: TaskRequest,
        message: Message,
        task_grant: str,
        now: datetime,
        push_ips: Iterable[str] = (),
    ) -> tuple[Task, dict[str, Any]]:
        authority_digest = digest(task_grant)
        try:
            peer = self.peers.require_peer(principal, tenant_id=request.tenant_id, now=now)
            self._validate_protocol(peer, request, message, push_ips)
            claims = verify_task_grant(
                task_grant,
                recipient_agent_id=self.agent_id,
                sender=principal,
                request=request,
                now=now,
            )
            request_digest = digest(request.policy_view())
            duplicate = self._messages.get(request.message_id)
            if duplicate:
                stored_digest, task_id = duplicate
                if stored_digest != request_digest:
                    raise A2ADenied("MESSAGE_ID_REUSE_CONFLICT")
                return self._tasks[task_id], self._results[task_id]

            task_id = "task-" + digest([request.message_id, request.context_id])[:16]
            task = Task(
                id=task_id,
                context_id=request.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                history=[message],
                metadata={
                    "tenant": request.tenant_id,
                    "operationId": request.operation_id,
                    "authorityDigest": authority_digest,
                },
            )
            self._messages[request.message_id] = (request_digest, task_id)
            self._tasks[task_id] = task
            task = transition(task, TaskState.TASK_STATE_WORKING)
            result = self.resource_server.execute(claims, request)
            task = transition(task, TaskState.TASK_STATE_COMPLETED)
            self._tasks[task_id] = task
            self._results[task_id] = result
            self._audit(
                Decision.ALLOW,
                "A2A_TASK_COMPLETED",
                principal,
                request,
                task_id,
                authority_digest,
            )
            return task, result
        except A2ADenied as denied:
            self._audit(
                Decision.DENY,
                denied.code,
                principal,
                request,
                None,
                authority_digest,
            )
            raise

    def _validate_protocol(
        self,
        peer: PeerRecord,
        request: TaskRequest,
        message: Message,
        push_ips: Iterable[str],
    ) -> None:
        identifiers = (request.message_id, request.operation_id, request.context_id)
        if any(not identifier or len(identifier) > 128 for identifier in identifiers):
            raise A2ADenied("TASK_IDENTIFIERS_INVALID")
        if request.protocol_version != PROTOCOL_VERSION:
            raise A2ADenied("PROTOCOL_VERSION_UNSUPPORTED")
        if request.card_digest != card_digest(self.card):
            raise A2ADenied("RECIPIENT_CARD_DRIFT")
        if peer.protocol_version != request.protocol_version:
            raise A2ADenied("PEER_PROTOCOL_VERSION_MISMATCH")
        if request.skill_id not in {skill.id for skill in self.card.skills}:
            raise A2ADenied("SKILL_NOT_ADVERTISED")
        unsupported = set(request.required_extensions) - set(peer.supported_extensions)
        if unsupported:
            raise A2ADenied("REQUIRED_EXTENSION_UNSUPPORTED")
        if len(request.required_extensions) != len(set(request.required_extensions)):
            raise A2ADenied("REQUIRED_EXTENSION_DUPLICATE")
        if message.message_id != request.message_id:
            raise A2ADenied("MESSAGE_ID_MISMATCH")
        if message.context_id != request.context_id:
            raise A2ADenied("CONTEXT_ID_MISMATCH")
        if message.task_id:
            raise A2ADenied("CLIENT_TASK_ID_NOT_ALLOWED")
        if message.role != Role.ROLE_USER or len(message.parts) != 1:
            raise A2ADenied("MESSAGE_INVALID")
        expected_message = build_message(request)
        if message.parts[0] != expected_message.parts[0]:
            raise A2ADenied("MESSAGE_PAYLOAD_MISMATCH")
        if tuple(message.extensions) != request.required_extensions:
            raise A2ADenied("MESSAGE_EXTENSIONS_MISMATCH")
        if request.push_url:
            validate_push_url(request.push_url, resolved_ips=push_ips)

    def _audit(
        self,
        decision: Decision,
        code: str,
        principal: AuthenticatedWorkload,
        request: TaskRequest,
        task_id: str | None,
        authority_digest: str,
    ) -> None:
        self.audit.append(
            AuditEvent(
                decision=decision,
                code=code,
                actor=principal.agent_id,
                tenant_id=request.tenant_id,
                message_id=request.message_id,
                operation_id=request.operation_id,
                task_id=task_id,
                authority_digest=authority_digest,
            )
        )


def direct_baseline(parent: ParentAuthority, request: TaskRequest, now: datetime) -> bool:
    """A simpler non-agent baseline for the architecture-regret comparison."""

    return (
        now < parent.expires_at
        and request.tenant_id == parent.tenant_id
        and request.action in parent.actions
        and request.resource in parent.resources
        and request.purpose == parent.purpose
    )


@dataclass
class Environment:
    now: datetime
    sender: AuthenticatedWorkload
    parent: ParentAuthority
    request: TaskRequest
    message: Message
    token: str
    sender_card: AgentCard
    recipient_card: AgentCard
    peer_record: PeerRecord
    directory: PeerDirectory
    resource: TicketResourceServer
    server: SecureA2AServer
    broker: DelegationBroker


def reviewed_environment(now: datetime | None = None) -> Environment:
    now = now or utc("2026-10-25T19:00:00Z")
    sender_card = AgentCard(
        name="acme-triage-agent",
        description="Coordinates bounded support triage",
        version="3.1.0",
        supported_interfaces=[
            AgentInterface(
                url="https://triage-agent.acme.test/a2a",
                protocol_binding="HTTP+JSON",
                protocol_version=PROTOCOL_VERSION,
            )
        ],
        capabilities=AgentCapabilities(),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        skills=[AgentSkill(id="triage", name="Triage", description="Coordinate triage")],
    )
    recipient_card = build_agent_card()
    directory = PeerDirectory()
    peer_record = directory.admit(
        agent_id="triage-agent",
        card=sender_card,
        workload_id="spiffe://acme.test/agent/triage/prod",
        tenants=("acme",),
        supported_extensions=(REQUIRED_EXTENSION,),
        now=now - timedelta(days=1),
    )
    sender = AuthenticatedWorkload(
        agent_id="triage-agent",
        spiffe_id="spiffe://acme.test/agent/triage/prod",
        tenant_id="acme",
        credential_id="mtls-cert-42",
    )
    parent = ParentAuthority(
        subject="user-123",
        tenant_id="acme",
        actions=("ticket.read",),
        resources=("ticket/acme-7",),
        purpose="support-triage",
        expires_at=now + timedelta(minutes=10),
    )
    request = TaskRequest(
        message_id="msg-018-0001",
        operation_id="op-018-0001",
        context_id="ctx-acme-7",
        tenant_id="acme",
        action="ticket.read",
        resource="ticket/acme-7",
        purpose="support-triage",
        skill_id="ticket-triage",
        protocol_version=PROTOCOL_VERSION,
        card_digest=card_digest(recipient_card),
        push_url="https://hooks.acme.test/a2a/tasks",
    )
    message = build_message(request)
    broker = DelegationBroker()
    token = broker.issue(
        parent=parent,
        sender=sender,
        recipient_agent_id="support-agent",
        request=request,
        now=now,
    )
    resource = TicketResourceServer()
    server = SecureA2AServer(
        agent_id="support-agent",
        card=recipient_card,
        peers=directory,
        resource_server=resource,
    )
    return Environment(
        now=now,
        sender=sender,
        parent=parent,
        request=request,
        message=message,
        token=token,
        sender_card=sender_card,
        recipient_card=recipient_card,
        peer_record=peer_record,
        directory=directory,
        resource=resource,
        server=server,
        broker=broker,
    )


@dataclass(frozen=True)
class CampaignCase:
    name: str
    expected: Decision
    mutate: str


def run_campaign() -> dict[str, Any]:
    cases = (
        CampaignCase("approved handoff", Decision.ALLOW, "none"),
        CampaignCase("wrong tenant", Decision.DENY, "tenant"),
        CampaignCase("scope escalation", Decision.DENY, "action"),
        CampaignCase("resource escalation", Decision.DENY, "resource"),
        CampaignCase("workload drift", Decision.DENY, "workload"),
        CampaignCase("card drift", Decision.DENY, "card"),
        CampaignCase("unsupported required extension", Decision.DENY, "extension"),
        CampaignCase("push SSRF", Decision.DENY, "push"),
        CampaignCase("message mutation", Decision.DENY, "message"),
    )
    results = []
    for index, case in enumerate(cases):
        env = reviewed_environment()
        request = replace(
            env.request,
            message_id=f"msg-campaign-{index}",
            operation_id=f"op-campaign-{index}",
        )
        principal = env.sender
        message = build_message(request)
        push_ips = ("93.184.216.34",)
        if case.mutate == "tenant":
            request = replace(request, tenant_id="other")
            message = build_message(request)
        elif case.mutate == "action":
            request = replace(request, action="ticket.delete")
            message = build_message(request)
        elif case.mutate == "resource":
            request = replace(request, resource="ticket/acme-99")
            message = build_message(request)
        elif case.mutate == "workload":
            principal = replace(principal, spiffe_id="spiffe://evil.test/agent")
        elif case.mutate == "card":
            request = replace(request, card_digest=digest("old-card"))
            message = build_message(request)
        elif case.mutate == "extension":
            request = replace(request, required_extensions=("https://evil.test/ext/v9",))
            message = build_message(request)
        elif case.mutate == "push":
            push_ips = ("127.0.0.1",)
        elif case.mutate == "message":
            message.message_id = "different-message"
        try:
            token = env.broker.issue(
                parent=env.parent,
                sender=env.sender,
                recipient_agent_id="support-agent",
                request=request,
                now=env.now,
            )
            env.server.receive(
                principal=principal,
                request=request,
                message=message,
                task_grant=token,
                now=env.now,
                push_ips=push_ips,
            )
            actual, code = Decision.ALLOW, "A2A_TASK_COMPLETED"
        except A2ADenied as denied:
            actual, code = Decision.DENY, denied.code
        results.append(
            {"name": case.name, "expected": case.expected, "actual": actual, "code": code}
        )
    correct = sum(item["expected"] == item["actual"] for item in results)
    unsafe = sum(
        item["expected"] == Decision.DENY and item["actual"] == Decision.ALLOW
        for item in results
    )
    false_blocks = sum(
        item["expected"] == Decision.ALLOW and item["actual"] == Decision.DENY
        for item in results
    )
    return {
        "results": results,
        "metrics": {
            "decision_accuracy": correct / len(results),
            "unsafe_allow_rate": unsafe / sum(c.expected == Decision.DENY for c in cases),
            "false_block_rate": false_blocks / sum(c.expected == Decision.ALLOW for c in cases),
        },
    }


def run_demo() -> dict[str, Any]:
    env = reviewed_environment()
    assert direct_baseline(env.parent, env.request, env.now)
    task, result = env.server.receive(
        principal=env.sender,
        request=env.request,
        message=env.message,
        task_grant=env.token,
        now=env.now,
        push_ips=("93.184.216.34",),
    )
    # Simulate a lost response: retry the exact message and reconcile by stable IDs.
    retried_task, retried_result = env.server.receive(
        principal=env.sender,
        request=env.request,
        message=env.message,
        task_grant=env.token,
        now=env.now,
        push_ips=("93.184.216.34",),
    )
    campaign = run_campaign()
    return {
        "sdk_types": {
            "card": type(env.recipient_card).__name__,
            "message": type(env.message).__name__,
            "task": type(task).__name__,
        },
        "task": {
            "id": task.id,
            "context_id": task.context_id,
            "state": TaskState.Name(task.status.state),
            "retry_same_task": retried_task.id == task.id,
        },
        "result": result,
        "retry_same_result": retried_result == result,
        "effect_count": len(env.resource.effect_ledger),
        "authority": {
            "parent_actions": env.parent.actions,
            "delegated_action": env.request.action,
            "recipient": "support-agent",
        },
        "architecture": {
            "direct_baseline_policy_checks": 5,
            "a2a_boundary_checks": 12,
            "extra_failure_domains": (
                "peer-directory",
                "token-service",
                "task-store",
                "notification-delivery",
            ),
        },
        "campaign": campaign,
        "audit_events": len(env.server.audit),
    }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, default=str))
