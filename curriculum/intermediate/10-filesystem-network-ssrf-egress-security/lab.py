"""Course 10: race-resistant file reads and deterministic SSRF/egress controls.

The lab performs real descriptor-relative filesystem reads. Network behavior is
exercised through an offline resolver and transport so redirect, DNS, address,
credential, timeout, and response invariants are deterministic and credential-free.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Literal
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, model_validator


PUBLIC_TICKET_IP = "93.184.216.34"
METADATA_IP = "169.254.169.254"
TICKET_HOST = "tickets.example.com"
MAX_URL_LENGTH = 2_048
MAX_DNS_ANSWERS = 8
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
TICKET_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]{1,15}-[0-9]{1,8}$")
HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class IdentityContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    subject: str = Field(pattern=r"^[a-z][a-z0-9-]{2,40}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")


class FileRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    file_id: str = Field(pattern=r"^file-[a-z0-9-]{3,48}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    root_id: str = Field(pattern=r"^root-[a-z0-9-]{3,32}$")
    relative_path: str = Field(min_length=1, max_length=200)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    max_bytes: int = Field(default=32_768, ge=1, le=65_536)


class DestinationPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    destination_id: str = Field(pattern=r"^dest-[a-z0-9-]{3,40}$")
    scheme: Literal["https"] = "https"
    host: str
    port: Literal[443] = 443
    path_prefix: str = Field(pattern=r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*/$")
    allowed_methods: frozenset[Literal["GET", "HEAD"]] = frozenset({"GET"})
    allowed_content_types: frozenset[str] = frozenset({"application/json"})
    max_redirects: int = Field(default=2, ge=0, le=5)
    max_response_bytes: int = Field(default=4_096, ge=128, le=65_536)
    timeout_ms: int = Field(default=750, ge=50, le=5_000)
    credential_audience: str = "tickets-api"

    @model_validator(mode="after")
    def canonical_destination(self):
        if self.host != self.host.lower() or self.host.endswith("."):
            raise ValueError("host must be lowercase without a trailing dot")
        if not HOST_PATTERN.fullmatch(self.host):
            raise ValueError("host must be an exact ASCII DNS name")
        return self


class EgressRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    request_id: str = Field(pattern=r"^net-[a-z0-9-]{3,64}$")
    destination_id: str = Field(pattern=r"^dest-[a-z0-9-]{3,40}$")
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(min_length=1, max_length=1_024)


@dataclass(frozen=True)
class FileEvent:
    file_id: str
    tenant_id: str
    decision: str
    reason_code: str
    root_id: str | None
    content_fingerprint: str | None
    bytes_read: int


@dataclass(frozen=True)
class EgressEvent:
    request_id: str
    destination_id: str
    redirect_hop: int
    decision: str
    reason_code: str
    scheme: str | None
    host: str | None
    port: int | None
    address_classes: tuple[str, ...]
    path_fingerprint: str | None
    query_present: bool


@dataclass(frozen=True)
class ResponseEvent:
    request_id: str
    decision: str
    reason_code: str
    status: int | None
    content_type: str | None
    response_bytes: int
    redirect_count: int


@dataclass(frozen=True)
class TransportCall:
    request_id: str
    connect_ip: str
    tls_server_name: str
    method: str
    header_names: tuple[str, ...]
    authorization_fingerprint: str | None


@dataclass(frozen=True)
class ApprovedTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    approved_ips: tuple[str, ...]
    connect_ip: str


@dataclass(frozen=True)
class FakeResponse:
    status: int
    headers: dict[str, str]
    body_chunks: tuple[bytes, ...] = ()


class FileDenied(RuntimeError):
    def __init__(self, code: str, message: str = "file is unavailable") -> None:
        super().__init__(message)
        self.code = code


class EgressDenied(RuntimeError):
    def __init__(self, code: str, message: str = "ticket is unavailable") -> None:
        super().__init__(message)
        self.code = code


class TransportTimeout(RuntimeError):
    pass


class DescriptorFileStore:
    """Reads regular files by directory descriptor without following symlinks."""

    def __init__(
        self,
        roots: dict[str, Path],
        records: tuple[FileRecord, ...],
    ) -> None:
        self.roots = dict(roots)
        self.records = {record.file_id: record for record in records}
        self.events: list[FileEvent] = []

    def _event(
        self,
        *,
        file_id: str,
        tenant_id: str,
        decision: str,
        reason: str,
        record: FileRecord | None,
        digest: str | None = None,
        bytes_read: int = 0,
    ) -> None:
        self.events.append(
            FileEvent(
                file_id=file_id,
                tenant_id=tenant_id,
                decision=decision,
                reason_code=reason,
                root_id=record.root_id if record else None,
                content_fingerprint=digest[:16] if digest else None,
                bytes_read=bytes_read,
            )
        )

    @staticmethod
    def _safe_parts(relative_path: str) -> tuple[str, ...]:
        candidate = PurePosixPath(relative_path)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or "\\" in relative_path
            or "\x00" in relative_path
        ):
            raise FileDenied("PATH_INVALID")
        return candidate.parts

    @staticmethod
    def _open_flags(*, directory: bool) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        return flags

    def _read_beneath(self, root: Path, relative_path: str, max_bytes: int) -> bytes:
        parts = self._safe_parts(relative_path)
        root_fd = os.open(root, self._open_flags(directory=True))
        opened: list[int] = [root_fd]
        try:
            directory_fd = root_fd
            for part in parts[:-1]:
                directory_fd = os.open(
                    part,
                    self._open_flags(directory=True),
                    dir_fd=directory_fd,
                )
                opened.append(directory_fd)
            file_fd = os.open(
                parts[-1],
                self._open_flags(directory=False),
                dir_fd=directory_fd,
            )
            opened.append(file_fd)
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise FileDenied("NOT_REGULAR_FILE")
            if metadata.st_size > max_bytes:
                raise FileDenied("FILE_SIZE_LIMIT_EXCEEDED")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, min(8_192, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise FileDenied("FILE_SIZE_LIMIT_EXCEEDED")
            return b"".join(chunks)
        except FileDenied:
            raise
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
            raise FileDenied("PATH_OR_SYMLINK_DENIED") from exc
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def read(self, identity: IdentityContext, file_id: str) -> dict[str, Any]:
        record = self.records.get(file_id)
        try:
            if record is None:
                raise FileDenied("FILE_NOT_REGISTERED")
            if record.tenant_id != identity.tenant_id:
                raise FileDenied("TENANT_MISMATCH")
            root = self.roots.get(record.root_id)
            if root is None:
                raise FileDenied("ROOT_NOT_AVAILABLE")
            content = self._read_beneath(root, record.relative_path, record.max_bytes)
            digest = sha256(content).hexdigest()
            if digest != record.expected_sha256:
                raise FileDenied("CONTENT_DIGEST_MISMATCH")
            self._event(
                file_id=file_id,
                tenant_id=identity.tenant_id,
                decision="allow",
                reason="FILE_READ_ALLOWED",
                record=record,
                digest=digest,
                bytes_read=len(content),
            )
            return {
                "file_id": file_id,
                "text": content.decode("utf-8"),
                "sha256": digest,
                "bytes": len(content),
            }
        except FileDenied as exc:
            self._event(
                file_id=file_id,
                tenant_id=identity.tenant_id,
                decision="deny",
                reason=exc.code,
                record=record,
            )
            raise


class ScriptedResolver:
    """Deterministic A/AAAA resolver with optional answer changes per lookup."""

    def __init__(self, answers: dict[str, tuple[tuple[str, ...], ...]]) -> None:
        self.answers = {host: tuple(sequence) for host, sequence in answers.items()}
        self.calls: dict[str, int] = {}

    def resolve(self, host: str) -> tuple[str, ...]:
        sequences = self.answers.get(host)
        if not sequences:
            raise EgressDenied("DNS_NO_ANSWER")
        index = self.calls.get(host, 0)
        self.calls[host] = index + 1
        return sequences[min(index, len(sequences) - 1)]


def normalized_address(value: str) -> IPv4Address | IPv6Address:
    address = ip_address(value)
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def address_class(value: str) -> str:
    address = normalized_address(value)
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if address.is_reserved:
        return "reserved"
    if not address.is_global:
        return "non-global"
    return "global"


class URLGate:
    """Strict logical destination plus all-answer IP policy."""

    def __init__(self, resolver: ScriptedResolver) -> None:
        self.resolver = resolver
        self.events: list[EgressEvent] = []

    @staticmethod
    def _path_fingerprint(path: str) -> str:
        return sha256(path.encode()).hexdigest()[:16]

    def _event(
        self,
        *,
        request_id: str,
        policy: DestinationPolicy,
        hop: int,
        allowed: bool,
        reason: str,
        scheme: str | None = None,
        host: str | None = None,
        port: int | None = None,
        addresses: tuple[str, ...] = (),
        path: str | None = None,
        query_present: bool = False,
    ) -> None:
        def classify(value: str) -> str:
            try:
                return address_class(value)
            except ValueError:
                return "invalid"

        self.events.append(
            EgressEvent(
                request_id=request_id,
                destination_id=policy.destination_id,
                redirect_hop=hop,
                decision="allow" if allowed else "deny",
                reason_code=reason,
                scheme=scheme,
                host=host,
                port=port,
                address_classes=tuple(classify(item) for item in addresses),
                path_fingerprint=self._path_fingerprint(path) if path else None,
                query_present=query_present,
            )
        )

    @staticmethod
    def _validate_path(path: str, prefix: str) -> None:
        if not path.startswith(prefix) or INVALID_PERCENT.search(path):
            raise EgressDenied("PATH_NOT_ALLOWED")
        decoded = path
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        parts = PurePosixPath(decoded).parts
        if "\\" in decoded or any(part in {".", ".."} for part in parts):
            raise EgressDenied("PATH_AMBIGUOUS")

    def approve(
        self,
        url: str,
        policy: DestinationPolicy,
        *,
        request_id: str,
        hop: int,
    ) -> ApprovedTarget:
        scheme: str | None = None
        host: str | None = None
        port: int | None = None
        path: str | None = None
        query_present = False
        addresses: tuple[str, ...] = ()
        try:
            if len(url) > MAX_URL_LENGTH or any(ord(char) <= 32 or ord(char) == 127 for char in url):
                raise EgressDenied("URL_SYNTAX_INVALID")
            if "\\" in url:
                raise EgressDenied("URL_SYNTAX_INVALID")
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            path = parsed.path or "/"
            query_present = bool(parsed.query)
            if scheme != policy.scheme:
                raise EgressDenied("SCHEME_NOT_ALLOWED")
            if not parsed.netloc or parsed.fragment:
                raise EgressDenied("URL_SYNTAX_INVALID")
            if parsed.username is not None or parsed.password is not None or "%" in parsed.netloc:
                raise EgressDenied("USERINFO_OR_ENCODED_AUTHORITY_DENIED")
            try:
                host = parsed.hostname
                port = parsed.port or 443
            except ValueError as exc:
                raise EgressDenied("PORT_INVALID") from exc
            if host is None or host != host.lower() or host.endswith("."):
                raise EgressDenied("HOST_SYNTAX_INVALID")
            try:
                host.encode("ascii")
            except UnicodeEncodeError as exc:
                raise EgressDenied("HOST_SYNTAX_INVALID") from exc
            if not HOST_PATTERN.fullmatch(host):
                raise EgressDenied("HOST_SYNTAX_INVALID")
            if host != policy.host:
                raise EgressDenied("HOST_NOT_ALLOWED")
            if port != policy.port:
                raise EgressDenied("PORT_NOT_ALLOWED")
            self._validate_path(path, policy.path_prefix)
            addresses = self.resolver.resolve(host)
            if not addresses or len(addresses) > MAX_DNS_ANSWERS:
                raise EgressDenied("DNS_ANSWER_COUNT_INVALID")
            normalized: list[str] = []
            for answer in addresses:
                try:
                    address = normalized_address(answer)
                except ValueError as exc:
                    raise EgressDenied("DNS_ANSWER_INVALID") from exc
                if address_class(str(address)) != "global":
                    raise EgressDenied("NON_GLOBAL_ADDRESS")
                normalized.append(str(address))
            approved_ips = tuple(sorted(set(normalized)))
            target = ApprovedTarget(
                url=urlunsplit((scheme, f"{host}:{port}", path, parsed.query, "")),
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                query=parsed.query,
                approved_ips=approved_ips,
                connect_ip=approved_ips[0],
            )
            self._event(
                request_id=request_id,
                policy=policy,
                hop=hop,
                allowed=True,
                reason="TARGET_APPROVED",
                scheme=scheme,
                host=host,
                port=port,
                addresses=approved_ips,
                path=path,
                query_present=query_present,
            )
            return target
        except EgressDenied as exc:
            self._event(
                request_id=request_id,
                policy=policy,
                hop=hop,
                allowed=False,
                reason=exc.code,
                scheme=scheme,
                host=host,
                port=port,
                addresses=addresses,
                path=path,
                query_present=query_present,
            )
            raise


class CredentialBroker:
    """Returns destination-bound headers; raw tokens never enter audit events."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self.tokens = dict(tokens)

    def headers_for(self, policy: DestinationPolicy, target: ApprovedTarget) -> dict[str, str]:
        if target.host != policy.host or target.port != policy.port:
            raise EgressDenied("CREDENTIAL_TARGET_MISMATCH")
        token = self.tokens.get(policy.credential_audience)
        if token is None:
            raise EgressDenied("CREDENTIAL_UNAVAILABLE")
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "northstar-support/1.0",
        }


class ScriptedTransport:
    """Offline transport that connects only to the already-approved IP."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str, str], FakeResponse | Exception] = {}
        self.calls: list[TransportCall] = []

    def add(
        self,
        *,
        connect_ip: str,
        method: str,
        url: str,
        result: FakeResponse | Exception,
    ) -> None:
        self.routes[(connect_ip, method, url)] = result

    def send(
        self,
        target: ApprovedTarget,
        *,
        request_id: str,
        method: str,
        headers: dict[str, str],
        timeout_ms: int,
    ) -> FakeResponse:
        authorization = headers.get("Authorization")
        self.calls.append(
            TransportCall(
                request_id=request_id,
                connect_ip=target.connect_ip,
                tls_server_name=target.host,
                method=method,
                header_names=tuple(sorted(headers)),
                authorization_fingerprint=(
                    sha256(authorization.encode()).hexdigest()[:16] if authorization else None
                ),
            )
        )
        result = self.routes.get((target.connect_ip, method, target.url))
        if result is None:
            raise ConnectionError("no scripted route")
        if isinstance(result, Exception):
            raise result
        return result


class EgressClient:
    """Manual redirects, per-hop revalidation, pinned connect IP, bounded body."""

    def __init__(
        self,
        policies: tuple[DestinationPolicy, ...],
        gate: URLGate,
        transport: ScriptedTransport,
        credentials: CredentialBroker,
    ) -> None:
        self.policies = {policy.destination_id: policy for policy in policies}
        self.gate = gate
        self.transport = transport
        self.credentials = credentials
        self.events: list[ResponseEvent] = []

    def _event(
        self,
        request: EgressRequest,
        *,
        allowed: bool,
        reason: str,
        status: int | None,
        content_type: str | None,
        response_bytes: int,
        redirects: int,
    ) -> None:
        self.events.append(
            ResponseEvent(
                request_id=request.request_id,
                decision="allow" if allowed else "deny",
                reason_code=reason,
                status=status,
                content_type=content_type,
                response_bytes=response_bytes,
                redirect_count=redirects,
            )
        )

    def fetch_json(self, request: EgressRequest) -> dict[str, Any]:
        policy = self.policies.get(request.destination_id)
        if policy is None:
            raise EgressDenied("DESTINATION_NOT_REGISTERED")
        if request.method not in policy.allowed_methods:
            raise EgressDenied("METHOD_NOT_ALLOWED")
        initial = urlunsplit((policy.scheme, f"{policy.host}:{policy.port}", request.path, "", ""))
        current = initial
        visited: set[str] = set()
        redirects = 0
        try:
            while True:
                if current in visited:
                    raise EgressDenied("REDIRECT_CYCLE")
                visited.add(current)
                target = self.gate.approve(
                    current,
                    policy,
                    request_id=request.request_id,
                    hop=redirects,
                )
                headers = self.credentials.headers_for(policy, target)
                try:
                    response = self.transport.send(
                        target,
                        request_id=request.request_id,
                        method=request.method,
                        headers=headers,
                        timeout_ms=policy.timeout_ms,
                    )
                except TransportTimeout as exc:
                    raise EgressDenied("UPSTREAM_TIMEOUT") from exc
                except ConnectionError as exc:
                    raise EgressDenied("UPSTREAM_CONNECTION_FAILED") from exc
                normalized_headers = {key.lower(): value for key, value in response.headers.items()}
                if response.status in REDIRECT_STATUSES:
                    location = normalized_headers.get("location")
                    if location is None:
                        raise EgressDenied("REDIRECT_LOCATION_MISSING")
                    if redirects >= policy.max_redirects:
                        raise EgressDenied("REDIRECT_LIMIT_EXCEEDED")
                    current = urljoin(target.url, location)
                    redirects += 1
                    continue
                if response.status != 200:
                    raise EgressDenied("UPSTREAM_STATUS_DENIED")
                content_type = normalized_headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type not in policy.allowed_content_types:
                    raise EgressDenied("CONTENT_TYPE_DENIED")
                declared = normalized_headers.get("content-length")
                if declared is not None:
                    if not declared.isdigit():
                        raise EgressDenied("CONTENT_LENGTH_INVALID")
                    if int(declared) > policy.max_response_bytes:
                        raise EgressDenied("RESPONSE_TOO_LARGE")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.body_chunks:
                    total += len(chunk)
                    if total > policy.max_response_bytes:
                        raise EgressDenied("RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
                try:
                    payload = json.loads(b"".join(chunks))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise EgressDenied("RESPONSE_JSON_INVALID") from exc
                if not isinstance(payload, dict):
                    raise EgressDenied("RESPONSE_SCHEMA_INVALID")
                self._event(
                    request,
                    allowed=True,
                    reason="RESPONSE_ALLOWED",
                    status=response.status,
                    content_type=content_type,
                    response_bytes=total,
                    redirects=redirects,
                )
                return payload
        except EgressDenied as exc:
            self._event(
                request,
                allowed=False,
                reason=exc.code,
                status=None,
                content_type=None,
                response_bytes=0,
                redirects=redirects,
            )
            raise


class SecureSupportService:
    def __init__(
        self,
        identity: IdentityContext,
        files: DescriptorFileStore,
        egress: EgressClient,
    ) -> None:
        self.identity = identity
        self.files = files
        self.egress = egress
        self.sequence = 0

    def read_workspace_file(self, file_id: str) -> dict[str, Any]:
        return self.files.read(self.identity, file_id)

    def lookup_ticket(self, ticket_id: str) -> dict[str, Any]:
        if not TICKET_ID_PATTERN.fullmatch(ticket_id):
            raise EgressDenied("TICKET_ID_INVALID")
        if not ticket_id.startswith(f"{self.identity.tenant_id}-"):
            raise EgressDenied("TENANT_MISMATCH")
        self.sequence += 1
        request = EgressRequest(
            request_id=f"net-ticket-{self.sequence}",
            destination_id="dest-tickets-api",
            path=f"/v1/tickets/{quote(ticket_id, safe='')}",
        )
        payload = self.egress.fetch_json(request)
        if (
            payload.get("ticket_id") != ticket_id
            or payload.get("tenant_id") != self.identity.tenant_id
            or not isinstance(payload.get("title"), str)
        ):
            raise EgressDenied("RESPONSE_BINDING_INVALID")
        return {
            "ticket_id": payload["ticket_id"],
            "title": payload["title"],
            "tenant_id": payload["tenant_id"],
        }


def build_mcp_server(service: SecureSupportService) -> MCPServer:
    server = MCPServer("northstar-bounded-io")

    @server.tool(name="workspace.read")
    def workspace_read(file_id: str) -> dict[str, Any]:
        try:
            return service.read_workspace_file(file_id)
        except FileDenied as exc:
            raise ToolError("file is unavailable") from exc

    @server.tool(name="ticket.lookup")
    def ticket_lookup(ticket_id: str) -> dict[str, Any]:
        try:
            return service.lookup_ticket(ticket_id)
        except EgressDenied as exc:
            raise ToolError("ticket is unavailable") from exc

    return server


@dataclass
class LabEnvironment:
    temporary: tempfile.TemporaryDirectory[str]
    identity: IdentityContext
    file_store: DescriptorFileStore
    resolver: ScriptedResolver
    gate: URLGate
    transport: ScriptedTransport
    credentials: CredentialBroker
    destination: DestinationPolicy
    egress: EgressClient
    service: SecureSupportService
    raw_token: str
    paths: dict[str, Path] = field(default_factory=dict)

    def close(self) -> None:
        self.temporary.cleanup()


def json_response(payload: dict[str, Any], *, status: int = 200) -> FakeResponse:
    body = json.dumps(payload, sort_keys=True).encode()
    return FakeResponse(
        status=status,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        body_chunks=(body,),
    )


def canonical_ticket_url(ticket_id: str) -> str:
    return f"https://{TICKET_HOST}:443/v1/tickets/{quote(ticket_id, safe='')}"


def default_environment() -> LabEnvironment:
    temporary = tempfile.TemporaryDirectory(prefix="mcp-course10-")
    base = Path(temporary.name)
    root = base / "workspace"
    (root / "published").mkdir(parents=True)
    (root / "other").mkdir()
    outside = base / "outside-secret.txt"
    outside.write_text("cloud-token=must-not-leak\n")
    policy_content = b"Support exports require approval.\n"
    policy_path = root / "published" / "support-policy.txt"
    policy_path.write_bytes(policy_content)
    other_content = b"Globex private material.\n"
    other_path = root / "other" / "globex.txt"
    other_path.write_bytes(other_content)
    symlink_path = root / "published" / "outside-link.txt"
    symlink_path.symlink_to(outside)
    records = (
        FileRecord(
            file_id="file-support-policy",
            tenant_id="acme",
            root_id="root-workspace",
            relative_path="published/support-policy.txt",
            expected_sha256=sha256(policy_content).hexdigest(),
        ),
        FileRecord(
            file_id="file-other-tenant",
            tenant_id="globex",
            root_id="root-workspace",
            relative_path="other/globex.txt",
            expected_sha256=sha256(other_content).hexdigest(),
        ),
        FileRecord(
            file_id="file-symlink-escape",
            tenant_id="acme",
            root_id="root-workspace",
            relative_path="published/outside-link.txt",
            expected_sha256=sha256(outside.read_bytes()).hexdigest(),
        ),
    )
    file_store = DescriptorFileStore({"root-workspace": root}, records)
    resolver = ScriptedResolver({TICKET_HOST: ((PUBLIC_TICKET_IP,),)})
    gate = URLGate(resolver)
    transport = ScriptedTransport()
    raw_token = "course10-secret-token"
    credentials = CredentialBroker({"tickets-api": raw_token})
    destination = DestinationPolicy(
        destination_id="dest-tickets-api",
        host=TICKET_HOST,
        path_prefix="/v1/tickets/",
    )
    transport.add(
        connect_ip=PUBLIC_TICKET_IP,
        method="GET",
        url=canonical_ticket_url("acme-100"),
        result=json_response(
            {"ticket_id": "acme-100", "tenant_id": "acme", "title": "Invoice retry"}
        ),
    )
    egress = EgressClient((destination,), gate, transport, credentials)
    identity = IdentityContext(subject="analyst-42", tenant_id="acme")
    service = SecureSupportService(identity, file_store, egress)
    return LabEnvironment(
        temporary=temporary,
        identity=identity,
        file_store=file_store,
        resolver=resolver,
        gate=gate,
        transport=transport,
        credentials=credentials,
        destination=destination,
        egress=egress,
        service=service,
        raw_token=raw_token,
        paths={"root": root, "outside": outside, "policy": policy_path, "symlink": symlink_path},
    )


def serialized_events(environment: LabEnvironment) -> str:
    events = [
        *[asdict(event) for event in environment.file_store.events],
        *[asdict(event) for event in environment.gate.events],
        *[asdict(event) for event in environment.egress.events],
        *[asdict(event) for event in environment.transport.calls],
    ]
    return json.dumps(events, sort_keys=True)


async def run_scenario() -> dict[str, Any]:
    environment = default_environment()
    try:
        server = build_mcp_server(environment.service)
        async with Client(server, raise_exceptions=False) as client:
            file_allowed = await client.call_tool(
                "workspace.read", {"file_id": "file-support-policy"}
            )
            ticket_allowed = await client.call_tool(
                "ticket.lookup", {"ticket_id": "acme-100"}
            )
            symlink_denied = await client.call_tool(
                "workspace.read", {"file_id": "file-symlink-escape"}
            )
            cross_tenant_denied = await client.call_tool(
                "ticket.lookup", {"ticket_id": "globex-200"}
            )

        rebinding_resolver = ScriptedResolver({TICKET_HOST: ((METADATA_IP,),)})
        rebinding_gate = URLGate(rebinding_resolver)
        try:
            rebinding_gate.approve(
                canonical_ticket_url("acme-100"),
                environment.destination,
                request_id="net-attack-rebinding",
                hop=0,
            )
        except EgressDenied as exc:
            rebinding_reason = exc.code
        else:
            raise AssertionError("private DNS answer was approved")

        redirect_url = canonical_ticket_url("acme-redirect")
        environment.transport.add(
            connect_ip=PUBLIC_TICKET_IP,
            method="GET",
            url=redirect_url,
            result=FakeResponse(
                status=302,
                headers={"Location": f"http://{METADATA_IP}/latest/meta-data"},
            ),
        )
        try:
            environment.egress.fetch_json(
                EgressRequest(
                    request_id="net-attack-redirect",
                    destination_id="dest-tickets-api",
                    path="/v1/tickets/acme-redirect",
                )
            )
        except EgressDenied as exc:
            redirect_reason = exc.code
        else:
            raise AssertionError("metadata redirect was followed")

        serialized = serialized_events(environment)
        evidence = {
            "file_read_allowed": not file_allowed.is_error,
            "ticket_lookup_allowed": not ticket_allowed.is_error,
            "symlink_escape_denied": symlink_denied.is_error,
            "cross_tenant_denied": cross_tenant_denied.is_error,
            "dns_rebinding_reason": rebinding_reason,
            "metadata_redirect_reason": redirect_reason,
            "transport_connected_to_approved_ip": environment.transport.calls[0].connect_ip
            == PUBLIC_TICKET_IP,
            "tls_name_preserved": environment.transport.calls[0].tls_server_name == TICKET_HOST,
            "raw_token_absent_from_events": environment.raw_token not in serialized,
            "raw_query_absent_from_events": "?" not in serialized,
            "forbidden_effects_observed": 0,
        }
        assert all(
            evidence[key] is True
            for key in (
                "file_read_allowed",
                "ticket_lookup_allowed",
                "symlink_escape_denied",
                "cross_tenant_denied",
                "transport_connected_to_approved_ip",
                "tls_name_preserved",
                "raw_token_absent_from_events",
                "raw_query_absent_from_events",
            )
        )
        assert evidence["dns_rebinding_reason"] == "NON_GLOBAL_ADDRESS"
        assert evidence["metadata_redirect_reason"] == "SCHEME_NOT_ALLOWED"
        return evidence
    finally:
        environment.close()


def main() -> None:
    evidence = asyncio.run(run_scenario())
    print("PASS: descriptor-relative file reads and per-hop egress policy block tested attacks")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
