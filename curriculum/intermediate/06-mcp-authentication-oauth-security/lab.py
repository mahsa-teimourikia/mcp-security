"""Course 06: a signed OAuth access-token boundary for an HTTP MCP server.

The lab is credential-free: it creates ephemeral RSA keys and runs the official
MCP Python SDK through an in-process ASGI HTTP transport. It is deliberately a
resource-server lab, not an authorization-server implementation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import time
from typing import Any

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl


ISSUER = "https://id.example/"
RESOURCE = "https://support.example/mcp"
HOST = "support.example"
GLOBAL_SCOPE = "mcp:access"
READ_SCOPE = "ticket:read"
ALGORITHM = "RS256"
MAX_TOKEN_LIFETIME_SECONDS = 300
CLOCK_SKEW_SECONDS = 5
TENANT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


@dataclass(frozen=True)
class SigningKey:
    """One authorization-server key; private material stays in the issuer fixture."""

    kid: str
    private_key: rsa.RSAPrivateKey

    @property
    def public_key(self):
        return self.private_key.public_key()


class EphemeralAuthorizationServer:
    """Small test fixture that issues signed access tokens; not a production IdP."""

    def __init__(self) -> None:
        self._keys: dict[str, SigningKey] = {}
        self.active_kid = ""
        self.rotate("key-1")

    def rotate(self, kid: str) -> None:
        if kid in self._keys:
            raise ValueError("kid already exists")
        self._keys[kid] = SigningKey(
            kid=kid,
            private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        )
        self.active_kid = kid

    def retire(self, kid: str) -> None:
        self._keys.pop(kid, None)

    def public_key(self, kid: str):
        record = self._keys.get(kid)
        return record.public_key if record else None

    @property
    def public_kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def issue(
        self,
        *,
        subject: str = "analyst-42",
        tenant_id: str = "acme",
        client_id: str = "support-copilot",
        scopes: tuple[str, ...] = (GLOBAL_SCOPE, READ_SCOPE),
        issuer: str = ISSUER,
        audience: str | list[str] = RESOURCE,
        lifetime_seconds: int = 120,
        not_before_offset: int = 0,
        issued_at_offset: int = 0,
        token_id: str = "token-1",
        token_type: str = "at+jwt",
        kid: str | None = None,
        extra_claims: dict[str, Any] | None = None,
        omit_claims: frozenset[str] = frozenset(),
    ) -> str:
        now = int(time.time())
        selected_kid = kid or self.active_kid
        key = self._keys[selected_kid]
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + lifetime_seconds,
            "nbf": now + not_before_offset,
            "iat": now + issued_at_offset,
            "jti": token_id,
            "client_id": client_id,
            "scope": " ".join(scopes),
            "tenant_id": tenant_id,
        }
        claims.update(extra_claims or {})
        for claim in omit_claims:
            claims.pop(claim, None)
        return jwt.encode(
            claims,
            key.private_key,
            algorithm=ALGORITHM,
            headers={"kid": selected_kid, "typ": token_type},
        )


@dataclass(frozen=True)
class ValidationEvent:
    token_fingerprint: str
    decision: str
    reason: str
    kid: str | None = None
    subject: str | None = None


class JwtAccessTokenVerifier:
    """Fail-closed MCP TokenVerifier backed by PyJWT and an issuer key set."""

    def __init__(self, issuer: EphemeralAuthorizationServer) -> None:
        self.issuer = issuer
        self.revoked_jtis: set[str] = set()
        self.events: list[ValidationEvent] = []

    @staticmethod
    def fingerprint(token: str) -> str:
        return sha256(token.encode()).hexdigest()[:16]

    def _deny(self, token: str, reason: str, kid: str | None = None) -> None:
        self.events.append(ValidationEvent(self.fingerprint(token), "deny", reason, kid))

    async def verify_token(self, token: str) -> AccessToken | None:
        kid: str | None = None
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if header.get("alg") != ALGORITHM:
                raise ValueError("algorithm_not_allowed")
            if header.get("typ") != "at+jwt":
                raise ValueError("wrong_token_type")
            if not isinstance(kid, str) or not kid:
                raise ValueError("missing_kid")
            public_key = self.issuer.public_key(kid)
            if public_key is None:
                raise ValueError("unknown_kid")

            claims = jwt.decode(
                token,
                public_key,
                algorithms=[ALGORITHM],
                audience=RESOURCE,
                issuer=ISSUER,
                leeway=CLOCK_SKEW_SECONDS,
                options={
                    "require": [
                        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
                        "client_id", "scope", "tenant_id",
                    ]
                },
            )
            now = int(time.time())
            for name in ("exp", "nbf", "iat"):
                if isinstance(claims[name], bool) or not isinstance(claims[name], int):
                    raise ValueError(f"invalid_{name}")
            if claims["iat"] > now + CLOCK_SKEW_SECONDS:
                raise ValueError("issued_in_future")
            if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME_SECONDS:
                raise ValueError("lifetime_too_long")
            if not isinstance(claims["jti"], str) or not claims["jti"]:
                raise ValueError("invalid_jti")
            if claims["jti"] in self.revoked_jtis:
                raise ValueError("revoked")
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                raise ValueError("invalid_subject")
            if not isinstance(claims["client_id"], str) or not claims["client_id"]:
                raise ValueError("invalid_client_id")
            if not isinstance(claims["tenant_id"], str) or not TENANT_PATTERN.fullmatch(claims["tenant_id"]):
                raise ValueError("invalid_tenant")
            if not isinstance(claims["scope"], str):
                raise ValueError("invalid_scope")
            scopes = claims["scope"].split()
            if not scopes or len(scopes) != len(set(scopes)):
                raise ValueError("invalid_scope")

            self.events.append(
                ValidationEvent(self.fingerprint(token), "allow", "validated", kid, claims["sub"])
            )
            return AccessToken(
                token=token,
                client_id=claims["client_id"],
                scopes=scopes,
                expires_at=claims["exp"],
                resource=RESOURCE,
                subject=claims["sub"],
                claims={
                    "iss": claims["iss"],
                    "jti": claims["jti"],
                    "tenant_id": claims["tenant_id"],
                },
            )
        except jwt.ExpiredSignatureError:
            self._deny(token, "expired", kid)
        except jwt.ImmatureSignatureError:
            self._deny(token, "not_yet_valid", kid)
        except jwt.InvalidIssuerError:
            self._deny(token, "issuer_mismatch", kid)
        except jwt.InvalidAudienceError:
            self._deny(token, "audience_mismatch", kid)
        except jwt.InvalidSignatureError:
            self._deny(token, "invalid_signature", kid)
        except jwt.MissingRequiredClaimError as exc:
            self._deny(token, f"missing_{exc.claim}", kid)
        except jwt.PyJWTError:
            self._deny(token, "malformed_or_invalid_jwt", kid)
        except (KeyError, TypeError, ValueError) as exc:
            self._deny(token, str(exc) or "invalid_claim", kid)
        return None


@dataclass(frozen=True)
class AuthorizationEvent:
    decision: str
    reason: str
    subject: str
    tenant_id: str
    ticket_id: str
    token_fingerprint: str


@dataclass
class RuntimeEvidence:
    handler_calls: int = 0
    authorization_events: list[AuthorizationEvent] = field(default_factory=list)


TICKETS = {
    "acme-100": {"tenant_id": "acme", "title": "Invoice retry", "status": "open"},
    "globex-200": {"tenant_id": "globex", "title": "Export delay", "status": "open"},
}


@dataclass
class LabEnvironment:
    authorization_server: EphemeralAuthorizationServer
    verifier: JwtAccessTokenVerifier
    runtime: RuntimeEvidence
    server: MCPServer
    app: Any


def build_environment() -> LabEnvironment:
    authorization_server = EphemeralAuthorizationServer()
    verifier = JwtAccessTokenVerifier(authorization_server)
    runtime = RuntimeEvidence()
    server = MCPServer(
        "northstar-support-authenticated",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(ISSUER),
            resource_server_url=AnyHttpUrl(RESOURCE),
            required_scopes=[GLOBAL_SCOPE],
            validate_token_resource=True,
        ),
    )

    @server.tool(name="ticket.read")
    def read_ticket(ticket_id: str) -> dict[str, str]:
        runtime.handler_calls += 1
        access_token = get_access_token()
        if access_token is None or access_token.claims is None:
            raise ToolError("authenticated identity unavailable")
        subject = access_token.subject or "unknown"
        tenant_id = str(access_token.claims.get("tenant_id", ""))
        fingerprint = verifier.fingerprint(access_token.token)
        if READ_SCOPE not in access_token.scopes:
            runtime.authorization_events.append(
                AuthorizationEvent("deny", "missing_ticket_read_scope", subject, tenant_id, ticket_id, fingerprint)
            )
            raise ToolError("not authorized to read tickets")
        ticket = TICKETS.get(ticket_id)
        if ticket is None or ticket["tenant_id"] != tenant_id:
            runtime.authorization_events.append(
                AuthorizationEvent("deny", "ticket_not_available", subject, tenant_id, ticket_id, fingerprint)
            )
            raise ToolError("ticket is unavailable")
        runtime.authorization_events.append(
            AuthorizationEvent("allow", "tenant_and_scope_match", subject, tenant_id, ticket_id, fingerprint)
        )
        return {"ticket_id": ticket_id, "title": ticket["title"], "status": ticket["status"]}

    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host=HOST,
    )
    return LabEnvironment(authorization_server, verifier, runtime, server, app)


def protocol_request() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}


async def request_boundary(
    environment: LabEnvironment,
    *,
    token: str | None,
    path: str = "/mcp",
) -> httpx2.Response:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": "2026-07-28",
    }
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    transport = httpx2.ASGITransport(app=environment.app)
    async with httpx2.AsyncClient(transport=transport, base_url=f"https://{HOST}") as client:
        return await client.post(path, headers=headers, json=protocol_request())


async def call_ticket(environment: LabEnvironment, token: str, ticket_id: str) -> Any:
    transport = httpx2.ASGITransport(app=environment.app)
    async with httpx2.AsyncClient(
        transport=transport,
        base_url=f"https://{HOST}",
        headers={"authorization": f"Bearer {token}"},
    ) as http_client:
        async with Client(
            streamable_http_client(RESOURCE, http_client=http_client),
            raise_exceptions=False,
        ) as client:
            return await client.call_tool("ticket.read", {"ticket_id": ticket_id})


async def protected_resource_metadata(environment: LabEnvironment) -> dict[str, Any]:
    transport = httpx2.ASGITransport(app=environment.app)
    async with httpx2.AsyncClient(transport=transport, base_url=f"https://{HOST}") as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")
        response.raise_for_status()
        return response.json()


async def run_scenario() -> dict[str, Any]:
    environment = build_environment()
    issuer = environment.authorization_server
    token = issuer.issue()
    missing = await request_boundary(environment, token=None)
    wrong_audience = await request_boundary(
        environment,
        token=issuer.issue(audience="https://inventory.example/api", token_id="wrong-aud"),
    )
    metadata = await protected_resource_metadata(environment)

    async with environment.app.router.lifespan_context(environment.app):
        allowed = await call_ticket(environment, token, "acme-100")
        cross_tenant = await call_ticket(environment, token, "globex-200")
        environment.verifier.revoked_jtis.add("token-1")
        revoked = await request_boundary(environment, token=token)

    evidence = {
        "metadata_resource": metadata["resource"],
        "metadata_authorization_servers": metadata["authorization_servers"],
        "missing_token_status": missing.status_code,
        "wrong_audience_status": wrong_audience.status_code,
        "valid_call_is_error": allowed.is_error,
        "cross_tenant_is_error": cross_tenant.is_error,
        "revoked_status": revoked.status_code,
        "handler_calls": environment.runtime.handler_calls,
        "validation_reasons": sorted({event.reason for event in environment.verifier.events}),
        "raw_token_in_evidence": token in json.dumps(
            {
                "validation": [event.__dict__ for event in environment.verifier.events],
                "authorization": [event.__dict__ for event in environment.runtime.authorization_events],
            }
        ),
    }
    assert evidence == {
        "metadata_resource": RESOURCE,
        "metadata_authorization_servers": [ISSUER],
        "missing_token_status": 401,
        "wrong_audience_status": 401,
        "valid_call_is_error": False,
        "cross_tenant_is_error": True,
        "revoked_status": 401,
        "handler_calls": 2,
        "validation_reasons": ["audience_mismatch", "revoked", "validated"],
        "raw_token_in_evidence": False,
    }
    return evidence


def main() -> None:
    evidence = asyncio.run(run_scenario())
    print("PASS: signed OAuth access tokens are enforced at the HTTP MCP boundary")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
