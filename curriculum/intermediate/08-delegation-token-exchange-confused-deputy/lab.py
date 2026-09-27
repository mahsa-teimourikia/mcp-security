"""Course 08: signed token exchange and confused-deputy defenses.

The lab implements a credential-free RFC 8693-shaped exchange service with
ephemeral RSA keys, PyJWT, a real MCP tool call, and an independently enforcing
downstream API. It is a learning profile, not a production authorization server.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from typing import Any, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


ISSUER = "https://id.example/"
MCP_RESOURCE = "https://support.example/mcp"
TICKETS_API = "https://tickets.example/api"
AUDIT_API = "https://audit.example/api"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ALGORITHM = "RS256"
MAX_EXCHANGE_TTL_SECONDS = 120
CLOCK_SKEW_SECONDS = 5


class WorkloadIdentity(BaseModel):
    """Authenticated workload identity supplied by mTLS/private-key auth in production."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    workload_id: str = Field(pattern=r"^workload:[a-z0-9-]{3,64}$")
    trust_domain: str = Field(pattern=r"^[a-z][a-z0-9.-]{2,80}$")


class TargetPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    resource: str
    allowed_scopes: frozenset[str]
    allowed_purposes: frozenset[str]
    max_ttl_seconds: int = Field(ge=1, le=MAX_EXCHANGE_TTL_SECONDS)


class ActorRegistration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    actor: WorkloadIdentity
    source_audience: str
    targets: tuple[TargetPolicy, ...]

    def target(self, resource: str) -> TargetPolicy | None:
        return next((target for target in self.targets if target.resource == resource), None)


class TokenExchangeRequest(BaseModel):
    """RFC 8693-shaped request plus local resource/purpose/transaction profile."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    grant_type: Literal[TOKEN_EXCHANGE_GRANT] = TOKEN_EXCHANGE_GRANT
    exchange_id: str = Field(pattern=r"^exchange-[a-z0-9-]{3,64}$")
    subject_token: SecretStr
    subject_token_type: Literal[ACCESS_TOKEN_TYPE] = ACCESS_TOKEN_TYPE
    requested_token_type: Literal[ACCESS_TOKEN_TYPE] = ACCESS_TOKEN_TYPE
    resource: str
    scopes: frozenset[str] = Field(min_length=1)
    resource_ids: tuple[str, ...] = Field(min_length=1, max_length=10)
    purpose: str = Field(min_length=1, max_length=40)
    transaction_id: str = Field(pattern=r"^txn-[a-z0-9-]{3,64}$")
    requested_ttl_seconds: int = Field(ge=1, le=MAX_EXCHANGE_TTL_SECONDS)

    @model_validator(mode="after")
    def require_unique_resources(self):
        if len(set(self.resource_ids)) != len(self.resource_ids):
            raise ValueError("resource_ids must be unique")
        return self


class TokenExchangeResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    access_token: SecretStr
    issued_token_type: Literal[ACCESS_TOKEN_TYPE] = ACCESS_TOKEN_TYPE
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int = Field(gt=0)
    scope: str


class ExchangeDenied(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DownstreamDenied(RuntimeError):
    def __init__(self, code: str, message: str = "resource is unavailable") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class GrantStatus:
    jti: str
    parent_jti: str | None
    revoked: bool = False


@dataclass(frozen=True)
class ExchangeEvent:
    exchange_id: str
    decision: str
    reason_code: str
    subject_token_fingerprint: str
    parent_jti: str | None
    child_jti: str | None
    subject: str | None
    actor: str
    audience: str
    scopes: tuple[str, ...]
    resource_ids: tuple[str, ...]
    transaction_id: str


@dataclass(frozen=True)
class ExchangeLedgerEntry:
    request_digest: str
    response: TokenExchangeResponse


class EphemeralSecurityTokenService:
    """Signed, policy-enforcing STS fixture with lineage-aware revocation."""

    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._kid = "sts-key-1"
        self._actors: dict[str, ActorRegistration] = {}
        self._grant_status: dict[str, GrantStatus] = {}
        self._exchange_ledger: dict[str, ExchangeLedgerEntry] = {}
        self.events: list[ExchangeEvent] = []
        self.available = True

    @staticmethod
    def fingerprint(token: str) -> str:
        return sha256(token.encode()).hexdigest()[:16]

    def register_actor(self, registration: ActorRegistration) -> None:
        self._actors[registration.actor.workload_id] = registration

    def _encode(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims,
            self._private_key,
            algorithm=ALGORITHM,
            headers={"kid": self._kid, "typ": "at+jwt"},
        )

    def _decode(self, token: str, *, audience: str, now: datetime) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != ALGORITHM or header.get("typ") != "at+jwt":
                raise ExchangeDenied("TOKEN_HEADER_INVALID")
            if header.get("kid") != self._kid:
                raise ExchangeDenied("TOKEN_KEY_UNKNOWN")
            claims = jwt.decode(
                token,
                self._private_key.public_key(),
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=ISSUER,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "require": [
                        "iss", "sub", "aud", "iat", "nbf", "exp", "jti",
                        "scope", "tenant_id", "purpose", "resource_ids",
                        "delegation_depth", "max_delegation_depth",
                    ],
                },
            )
        except ExchangeDenied:
            raise
        except jwt.InvalidAudienceError as exc:
            raise ExchangeDenied("SOURCE_AUDIENCE_INVALID") from exc
        except jwt.InvalidIssuerError as exc:
            raise ExchangeDenied("ISSUER_INVALID") from exc
        except jwt.InvalidSignatureError as exc:
            raise ExchangeDenied("SIGNATURE_INVALID") from exc
        except jwt.PyJWTError as exc:
            raise ExchangeDenied("TOKEN_INVALID") from exc
        now_seconds = int(now.timestamp())
        for claim in ("iat", "nbf", "exp", "delegation_depth", "max_delegation_depth"):
            if isinstance(claims[claim], bool) or not isinstance(claims[claim], int):
                raise ExchangeDenied(f"{claim.upper()}_INVALID")
        if now_seconds + CLOCK_SKEW_SECONDS < claims["nbf"]:
            raise ExchangeDenied("TOKEN_NOT_YET_VALID")
        if now_seconds - CLOCK_SKEW_SECONDS >= claims["exp"]:
            raise ExchangeDenied("TOKEN_EXPIRED")
        if not isinstance(claims["scope"], str) or not claims["scope"].split():
            raise ExchangeDenied("SCOPE_INVALID")
        if not isinstance(claims["resource_ids"], list) or not claims["resource_ids"]:
            raise ExchangeDenied("RESOURCE_IDS_INVALID")
        return claims

    def issue_subject_token(
        self,
        *,
        subject: str,
        tenant_id: str,
        audience: str,
        scopes: frozenset[str],
        resource_ids: tuple[str, ...],
        purpose: str,
        now: datetime,
        lifetime: timedelta = timedelta(minutes=5),
        max_delegation_depth: int = 2,
        jti: str = "root-grant-1",
    ) -> str:
        claims = {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + lifetime).timestamp()),
            "jti": jti,
            "client_id": "support-host",
            "scope": " ".join(sorted(scopes)),
            "tenant_id": tenant_id,
            "purpose": purpose,
            "resource_ids": list(resource_ids),
            "delegation_depth": 0,
            "max_delegation_depth": max_delegation_depth,
        }
        self._grant_status[jti] = GrantStatus(jti=jti, parent_jti=None)
        return self._encode(claims)

    @staticmethod
    def _request_digest(request: TokenExchangeRequest, parent_jti: str, actor: str) -> str:
        canonical = json.dumps(
            {
                "actor": actor,
                "parent_jti": parent_jti,
                "purpose": request.purpose,
                "resource": request.resource,
                "resource_ids": sorted(request.resource_ids),
                "scopes": sorted(request.scopes),
                "transaction_id": request.transaction_id,
                "ttl": request.requested_ttl_seconds,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode()).hexdigest()

    def _event(
        self,
        request: TokenExchangeRequest,
        actor: WorkloadIdentity,
        *,
        decision: str,
        reason: str,
        parent: dict[str, Any] | None = None,
        child_jti: str | None = None,
    ) -> None:
        self.events.append(
            ExchangeEvent(
                exchange_id=request.exchange_id,
                decision=decision,
                reason_code=reason,
                subject_token_fingerprint=self.fingerprint(
                    request.subject_token.get_secret_value()
                ),
                parent_jti=parent.get("jti") if parent else None,
                child_jti=child_jti,
                subject=parent.get("sub") if parent else None,
                actor=actor.workload_id,
                audience=request.resource,
                scopes=tuple(sorted(request.scopes)),
                resource_ids=tuple(sorted(request.resource_ids)),
                transaction_id=request.transaction_id,
            )
        )

    def exchange(
        self,
        request: TokenExchangeRequest,
        *,
        actor: WorkloadIdentity,
        now: datetime,
    ) -> TokenExchangeResponse:
        parent: dict[str, Any] | None = None
        try:
            if not self.available:
                raise ExchangeDenied("STS_UNAVAILABLE")
            registration = self._actors.get(actor.workload_id)
            if registration is None or registration.actor != actor:
                raise ExchangeDenied("ACTOR_NOT_REGISTERED")
            parent = self._decode(
                request.subject_token.get_secret_value(),
                audience=registration.source_audience,
                now=now,
            )
            if not self.is_lineage_active(parent["jti"]):
                raise ExchangeDenied("SUBJECT_TOKEN_REVOKED")
            target = registration.target(request.resource)
            if target is None:
                raise ExchangeDenied("TARGET_NOT_ALLOWED")
            parent_scopes = frozenset(parent["scope"].split())
            effective_scopes = parent_scopes & target.allowed_scopes
            if not request.scopes <= effective_scopes:
                raise ExchangeDenied("SCOPE_ESCALATION")
            parent_resources = frozenset(parent["resource_ids"])
            if not frozenset(request.resource_ids) <= parent_resources:
                raise ExchangeDenied("RESOURCE_ESCALATION")
            if request.purpose != parent["purpose"] or request.purpose not in target.allowed_purposes:
                raise ExchangeDenied("PURPOSE_ESCALATION")
            if (
                parent.get("transaction_id") is not None
                and request.transaction_id != parent["transaction_id"]
            ):
                raise ExchangeDenied("TRANSACTION_ESCALATION")
            if parent["delegation_depth"] >= parent["max_delegation_depth"]:
                raise ExchangeDenied("DELEGATION_DEPTH_EXCEEDED")
            if request.requested_ttl_seconds > target.max_ttl_seconds:
                raise ExchangeDenied("TTL_EXCEEDS_TARGET_POLICY")
            now_seconds = int(now.timestamp())
            child_exp = min(now_seconds + request.requested_ttl_seconds, parent["exp"])
            if child_exp <= now_seconds:
                raise ExchangeDenied("NO_REMAINING_LIFETIME")

            request_digest = self._request_digest(request, parent["jti"], actor.workload_id)
            previous = self._exchange_ledger.get(request.exchange_id)
            if previous is not None:
                if previous.request_digest != request_digest:
                    raise ExchangeDenied("EXCHANGE_ID_CONFLICT")
                self._event(
                    request,
                    actor,
                    decision="allow",
                    reason="EXCHANGE_DEDUPLICATED",
                    parent=parent,
                )
                return previous.response

            child_jti = "grant-" + sha256(
                f"{request.exchange_id}:{request_digest}".encode()
            ).hexdigest()[:20]
            previous_actor = parent.get("act")
            current_actor: dict[str, Any] = {
                "sub": actor.workload_id,
                "iss": actor.trust_domain,
            }
            if previous_actor is not None:
                current_actor["act"] = previous_actor
            child_claims = {
                "iss": ISSUER,
                "sub": parent["sub"],
                "aud": request.resource,
                "iat": now_seconds,
                "nbf": now_seconds,
                "exp": child_exp,
                "jti": child_jti,
                "azp": actor.workload_id,
                "scope": " ".join(sorted(request.scopes)),
                "tenant_id": parent["tenant_id"],
                "purpose": request.purpose,
                "resource_ids": list(request.resource_ids),
                "transaction_id": request.transaction_id,
                "delegation_depth": parent["delegation_depth"] + 1,
                "max_delegation_depth": parent["max_delegation_depth"],
                "parent_jti": parent["jti"],
                "act": current_actor,
            }
            child_token = self._encode(child_claims)
            response = TokenExchangeResponse(
                access_token=SecretStr(child_token),
                expires_in=child_exp - now_seconds,
                scope=child_claims["scope"],
            )
            self._grant_status[child_jti] = GrantStatus(
                jti=child_jti, parent_jti=parent["jti"]
            )
            self._exchange_ledger[request.exchange_id] = ExchangeLedgerEntry(
                request_digest=request_digest,
                response=response,
            )
            self._event(
                request,
                actor,
                decision="allow",
                reason="EXCHANGE_ALLOWED",
                parent=parent,
                child_jti=child_jti,
            )
            return response
        except ExchangeDenied as exc:
            self._event(
                request,
                actor,
                decision="deny",
                reason=exc.code,
                parent=parent,
            )
            raise

    def decode_for_resource(self, token: str, *, audience: str, now: datetime) -> dict[str, Any]:
        return self._decode(token, audience=audience, now=now)

    def revoke(self, jti: str) -> None:
        status = self._grant_status.get(jti)
        if status:
            status.revoked = True

    def is_lineage_active(self, jti: str) -> bool:
        seen: set[str] = set()
        current: str | None = jti
        while current is not None:
            if current in seen:
                return False
            seen.add(current)
            status = self._grant_status.get(current)
            if status is None or status.revoked:
                return False
            current = status.parent_jti
        return True


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    tenant_id: str
    assigned_subject: str
    title: str


@dataclass(frozen=True)
class DownstreamEvent:
    decision: str
    reason_code: str
    token_fingerprint: str
    subject: str | None
    actor: str
    ticket_id: str
    transaction_id: str
    grant_jti: str | None


class TicketAPI:
    """Independent resource server: validates token and current resource policy."""

    def __init__(self, sts: EphemeralSecurityTokenService, tickets: tuple[Ticket, ...]) -> None:
        self.sts = sts
        self.tickets = {ticket.ticket_id: ticket for ticket in tickets}
        self.events: list[DownstreamEvent] = []
        self.accepted_token_fingerprints: list[str] = []

    def _deny(
        self,
        *,
        code: str,
        token: str,
        presenter: WorkloadIdentity,
        ticket_id: str,
        transaction_id: str,
        claims: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            DownstreamEvent(
                decision="deny",
                reason_code=code,
                token_fingerprint=self.sts.fingerprint(token),
                subject=claims.get("sub") if claims else None,
                actor=presenter.workload_id,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
                grant_jti=claims.get("jti") if claims else None,
            )
        )
        raise DownstreamDenied(code)

    def read_ticket(
        self,
        *,
        token: str,
        presenter: WorkloadIdentity,
        ticket_id: str,
        transaction_id: str,
        now: datetime,
    ) -> dict[str, str]:
        claims: dict[str, Any] | None = None
        try:
            claims = self.sts.decode_for_resource(token, audience=TICKETS_API, now=now)
        except ExchangeDenied as exc:
            self._deny(
                code=exc.code,
                token=token,
                presenter=presenter,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
            )
        actor_claim = claims.get("act")
        if (
            not isinstance(actor_claim, dict)
            or actor_claim.get("sub") != presenter.workload_id
            or actor_claim.get("iss") != presenter.trust_domain
        ):
            self._deny(
                code="ACTOR_BINDING_INVALID",
                token=token,
                presenter=presenter,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
                claims=claims,
            )
        if not self.sts.is_lineage_active(claims["jti"]):
            self._deny(
                code="DELEGATION_LINEAGE_REVOKED",
                token=token,
                presenter=presenter,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
                claims=claims,
            )
        checks = (
            (transaction_id == claims.get("transaction_id"), "TRANSACTION_MISMATCH"),
            (claims.get("purpose") == "support", "PURPOSE_DENIED"),
            ("ticket:read" in claims["scope"].split(), "SCOPE_DENIED"),
            (ticket_id in claims.get("resource_ids", []), "RESOURCE_NOT_DELEGATED"),
            (0 < claims["delegation_depth"] <= claims["max_delegation_depth"], "DEPTH_INVALID"),
        )
        for allowed, reason in checks:
            if not allowed:
                self._deny(
                    code=reason,
                    token=token,
                    presenter=presenter,
                    ticket_id=ticket_id,
                    transaction_id=transaction_id,
                    claims=claims,
                )
        ticket = self.tickets.get(ticket_id)
        if (
            ticket is None
            or ticket.tenant_id != claims.get("tenant_id")
            or ticket.assigned_subject != claims.get("sub")
        ):
            self._deny(
                code="CURRENT_RESOURCE_POLICY_DENIED",
                token=token,
                presenter=presenter,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
                claims=claims,
            )
        fingerprint = self.sts.fingerprint(token)
        self.accepted_token_fingerprints.append(fingerprint)
        self.events.append(
            DownstreamEvent(
                decision="allow",
                reason_code="CALLER_BOUND_READ_ALLOWED",
                token_fingerprint=fingerprint,
                subject=claims["sub"],
                actor=presenter.workload_id,
                ticket_id=ticket_id,
                transaction_id=transaction_id,
                grant_jti=claims["jti"],
            )
        )
        return {
            "ticket_id": ticket.ticket_id,
            "title": ticket.title,
            "delegated_subject": claims["sub"],
            "delegated_actor": actor_claim["sub"],
        }


@dataclass
class DelegatingSupportService:
    sts: EphemeralSecurityTokenService
    ticket_api: TicketAPI
    subject_token: str
    actor: WorkloadIdentity
    now: datetime
    request_sequence: int = 0

    def read_ticket(self, ticket_id: str) -> dict[str, str]:
        self.request_sequence += 1
        transaction_id = f"txn-support-{self.request_sequence}"
        request = TokenExchangeRequest(
            exchange_id=f"exchange-support-{self.request_sequence}",
            subject_token=SecretStr(self.subject_token),
            resource=TICKETS_API,
            scopes=frozenset({"ticket:read"}),
            resource_ids=(ticket_id,),
            purpose="support",
            transaction_id=transaction_id,
            requested_ttl_seconds=60,
        )
        response = self.sts.exchange(request, actor=self.actor, now=self.now)
        return self.ticket_api.read_ticket(
            token=response.access_token.get_secret_value(),
            presenter=self.actor,
            ticket_id=ticket_id,
            transaction_id=transaction_id,
            now=self.now,
        )


def build_mcp_server(service: DelegatingSupportService) -> MCPServer:
    server = MCPServer("northstar-delegating-support")

    @server.tool(name="ticket.read")
    def ticket_read(ticket_id: str) -> dict[str, str]:
        try:
            return service.read_ticket(ticket_id)
        except (ExchangeDenied, DownstreamDenied) as exc:
            raise ToolError("ticket is unavailable") from exc

    return server


def exchange_request(
    parent_token: str,
    *,
    exchange_id: str = "exchange-manual-1",
    resource: str = TICKETS_API,
    scopes: frozenset[str] = frozenset({"ticket:read"}),
    resource_ids: tuple[str, ...] = ("acme-100",),
    purpose: str = "support",
    transaction_id: str = "txn-manual-1",
    ttl: int = 60,
) -> TokenExchangeRequest:
    return TokenExchangeRequest(
        exchange_id=exchange_id,
        subject_token=SecretStr(parent_token),
        resource=resource,
        scopes=scopes,
        resource_ids=resource_ids,
        purpose=purpose,
        transaction_id=transaction_id,
        requested_ttl_seconds=ttl,
    )


def default_environment(now: datetime | None = None):
    now = now or datetime.now(UTC)
    sts = EphemeralSecurityTokenService()
    support_actor = WorkloadIdentity(
        workload_id="workload:support-mcp", trust_domain="northstar.example"
    )
    ticket_actor = WorkloadIdentity(
        workload_id="workload:ticket-api", trust_domain="northstar.example"
    )
    sts.register_actor(
        ActorRegistration(
            actor=support_actor,
            source_audience=MCP_RESOURCE,
            targets=(
                TargetPolicy(
                    resource=TICKETS_API,
                    allowed_scopes=frozenset({"ticket:read", "trace:append"}),
                    allowed_purposes=frozenset({"support"}),
                    max_ttl_seconds=90,
                ),
            ),
        )
    )
    sts.register_actor(
        ActorRegistration(
            actor=ticket_actor,
            source_audience=TICKETS_API,
            targets=(
                TargetPolicy(
                    resource=AUDIT_API,
                    allowed_scopes=frozenset({"trace:append"}),
                    allowed_purposes=frozenset({"support"}),
                    max_ttl_seconds=30,
                ),
            ),
        )
    )
    parent_token = sts.issue_subject_token(
        subject="analyst-42",
        tenant_id="acme",
        audience=MCP_RESOURCE,
        scopes=frozenset({"ticket:read", "trace:append"}),
        resource_ids=("acme-100",),
        purpose="support",
        now=now,
        max_delegation_depth=2,
    )
    ticket_api = TicketAPI(
        sts,
        (
            Ticket("acme-100", "acme", "analyst-42", "Invoice retry"),
            Ticket("acme-101", "acme", "analyst-99", "Export delay"),
            Ticket("globex-200", "globex", "analyst-42", "Partner sync"),
        ),
    )
    return sts, ticket_api, parent_token, support_actor, ticket_actor


def parse_tool_json(result: Any) -> dict[str, Any]:
    return json.loads(result.content[0].text)


async def run_scenario() -> dict[str, Any]:
    now = datetime(2026, 9, 27, 17, 0, tzinfo=UTC)
    sts, ticket_api, parent_token, actor, _ = default_environment(now)
    service = DelegatingSupportService(sts, ticket_api, parent_token, actor, now)
    server = build_mcp_server(service)
    async with Client(server, raise_exceptions=False) as client:
        allowed = await client.call_tool("ticket.read", {"ticket_id": "acme-100"})
        cross_tenant = await client.call_tool("ticket.read", {"ticket_id": "globex-200"})

    try:
        ticket_api.read_ticket(
            token=parent_token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-passthrough",
            now=now,
        )
    except DownstreamDenied as exc:
        passthrough_reason = exc.code
    else:
        raise AssertionError("parent-token passthrough was accepted")

    request = exchange_request(parent_token)
    child = sts.exchange(request, actor=actor, now=now)
    child_token = child.access_token.get_secret_value()
    first = ticket_api.read_ticket(
        token=child_token,
        presenter=actor,
        ticket_id="acme-100",
        transaction_id="txn-manual-1",
        now=now,
    )
    second = ticket_api.read_ticket(
        token=child_token,
        presenter=actor,
        ticket_id="acme-100",
        transaction_id="txn-manual-1",
        now=now,
    )
    sts.revoke("root-grant-1")
    try:
        ticket_api.read_ticket(
            token=child_token,
            presenter=actor,
            ticket_id="acme-100",
            transaction_id="txn-manual-1",
            now=now,
        )
    except DownstreamDenied as exc:
        revocation_reason = exc.code
    else:
        raise AssertionError("revoked delegation lineage was accepted")

    audit_json = json.dumps(
        {
            "exchange": [event.__dict__ for event in sts.events],
            "downstream": [event.__dict__ for event in ticket_api.events],
        }
    )
    parent_fingerprint = sts.fingerprint(parent_token)
    evidence = {
        "mcp_read_allowed": not allowed.is_error,
        "cross_tenant_denied": cross_tenant.is_error,
        "passthrough_reason": passthrough_reason,
        "delegated_subject": parse_tool_json(allowed)["delegated_subject"],
        "delegated_actor": parse_tool_json(allowed)["delegated_actor"],
        "bearer_replay_observed": first == second,
        "revocation_reason": revocation_reason,
        "accepted_parent_token": parent_fingerprint in ticket_api.accepted_token_fingerprints,
        "raw_parent_in_audit": parent_token in audit_json,
        "raw_child_in_audit": child_token in audit_json,
        "exchange_reasons": sorted({event.reason_code for event in sts.events}),
    }
    assert evidence == {
        "mcp_read_allowed": True,
        "cross_tenant_denied": True,
        "passthrough_reason": "SOURCE_AUDIENCE_INVALID",
        "delegated_subject": "analyst-42",
        "delegated_actor": "workload:support-mcp",
        "bearer_replay_observed": True,
        "revocation_reason": "DELEGATION_LINEAGE_REVOKED",
        "accepted_parent_token": False,
        "raw_parent_in_audit": False,
        "raw_child_in_audit": False,
        "exchange_reasons": ["EXCHANGE_ALLOWED", "RESOURCE_ESCALATION"],
    }
    return evidence


def main() -> None:
    evidence = asyncio.run(run_scenario())
    print("PASS: token exchange narrows authority and blocks confused-deputy use")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
