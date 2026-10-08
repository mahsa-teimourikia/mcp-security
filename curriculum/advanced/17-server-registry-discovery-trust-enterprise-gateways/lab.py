"""Course 17: evidence-backed MCP registry trust and an enterprise gateway.

The credential-free lab uses the official MCP Python SDK over its in-memory
transport. Public registry metadata is treated as discovery input only. A trusted
enterprise registry admits one exact server version after evidence review, signs
versioned records and snapshots, and propagates revocation to both the host and
resource server. The gateway authenticates a caller, evaluates registry and
capability policy, mints a narrow audience-bound JWT, validates the live MCP tool
contract, calls the server, and validates the result. The server independently
validates the token and tenant boundary: the gateway never replaces resource-
server authorization.

HMAC keys, JWTs, identities, and timestamps are deterministic teaching fixtures.
No network, package registry, identity provider, or production system is used.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
import hmac
import json
import re
from contextvars import ContextVar
from typing import Annotated, Any, Iterable, Literal
from urllib.parse import urlparse

import jwt
from jwt import InvalidTokenError
from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import Implementation, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError


PROTOCOL_VERSION = "2026-07-28"
REGISTRY_SCHEMA = "mcp.enterprise.registry/1.0"
POLICY_VERSION = "enterprise-registry-gateway/2026-10-07"
TOKEN_ISSUER = "https://identity.acme.test"
REGISTRY_SIGNING_KEY = b"course-17-registry-signing-key"
TOKEN_SIGNING_KEY = b"course-17-downstream-token-key!!"
MAX_CACHE_AGE = timedelta(seconds=30)
MAX_REVIEW_AGE = timedelta(days=90)
TOKEN_LIFETIME = timedelta(minutes=5)
ALLOWED_PACKAGE_TYPES = frozenset({"pypi", "npm", "oci", "mcpb"})
ALLOWED_DATA_CLASSES = frozenset({"internal", "confidential"})
ALLOWED_SANDBOX_PROFILES = frozenset({"remote-managed", "restricted-container"})
SERVER_NAME = "com.acme/support"
SERVER_VERSION = "3.4.1"
ENDPOINT = "https://mcp.support.acme.test/mcp"
WORKLOAD_ID = "spiffe://prod.acme.test/ns/support/sa/mcp-server"
SOURCE_REPOSITORY_ID = "github:10420817"
ARTIFACT_DIGEST = "sha256:" + sha256(b"support-mcp-server@3.4.1").hexdigest()
PROVENANCE_DIGEST = "sha256:" + sha256(b"slsa-provenance@build-991").hexdigest()
SBOM_DIGEST = "sha256:" + sha256(b"cyclonedx-sbom@build-991").hexdigest()
SCAN_DIGEST = "sha256:" + sha256(b"vulnerability-scan@build-991").hexdigest()
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}/[a-z0-9][a-z0-9._-]{0,62}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,95}$")
TRACE_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return parsed.astimezone(UTC)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + sha256(payload).hexdigest()


def sign(value: Any, key: bytes = REGISTRY_SIGNING_KEY) -> str:
    return hmac.new(key, canonical_json(value), sha256).hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def require_https_endpoint(value: str) -> None:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RegistryDenied("ENDPOINT_INVALID", value)


class Lifecycle(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class Risk(StrEnum):
    READ = "read"
    EXTERNAL_WRITE = "external_write"
    ADMIN = "admin"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Outcome(StrEnum):
    NOT_EXECUTED = "not_executed"
    COMPLETED = "completed"
    SERVER_ERROR = "server_error"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


TicketId = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=True,
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    ),
]


class TicketReadInput(StrictModel):
    ticket_id: TicketId


class TicketView(StrictModel):
    ticket_id: TicketId
    status: Literal["open", "closed"]
    summary: Annotated[str, StringConstraints(strict=True, max_length=240)]
    content_trust: Literal["untrusted-customer-content"]


class TicketReadOutput(StrictModel):
    ticket: TicketView
    policy_version: Literal[POLICY_VERSION]


class RegistryDenied(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class GatewayDenied(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class PublicServerMetadata:
    """Discovery metadata; namespace ownership is not enterprise approval."""

    name: str
    version: str
    status: Literal["active", "deprecated", "deleted"]
    package_type: str
    package_identifier: str
    package_version: str
    package_digest: str
    repository_id: str
    remote_url: str
    registry_updated_at: datetime


@dataclass(frozen=True)
class CapabilityGrant:
    exposed_name: str
    server_tool: str
    required_permission: str
    downstream_scope: str
    risk: Risk
    max_calls_per_minute: int


@dataclass(frozen=True)
class ReviewEvidence:
    server_name: str
    server_version: str
    artifact_digest: str
    contract_digest: str
    provenance_digest: str
    sbom_digest: str
    scan_digest: str
    source_repository_id: str
    endpoint: str
    workload_identity: str
    owner: str
    incident_contact: str
    data_classification: str
    sandbox_profile: str
    grants: tuple[CapabilityGrant, ...]
    reviewed_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class RegistryRecord:
    schema_version: str
    record_id: str
    revision: int
    registry_epoch: int
    tenant_id: str
    environment: str
    server_name: str
    server_version: str
    package_type: str
    package_identifier: str
    package_version: str
    source_repository_id: str
    status: Lifecycle
    status_reason: str
    owner: str
    incident_contact: str
    endpoint: str
    workload_identity: str
    artifact_digest: str
    contract_digest: str
    provenance_digest: str
    sbom_digest: str
    scan_digest: str
    evidence_digest: str
    data_classification: str
    sandbox_profile: str
    gateway_required: bool
    grants: tuple[CapabilityGrant, ...]
    reviewed_at: datetime
    expires_at: datetime
    changed_at: datetime
    previous_record_digest: str | None
    record_digest: str
    signature: str

    @property
    def key(self) -> tuple[str, str, str]:
        return self.tenant_id, self.environment, self.server_name

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("record_digest")
        result.pop("signature")
        return result


@dataclass(frozen=True)
class RegistrySnapshot:
    schema_version: str
    epoch: int
    issued_at: datetime
    expires_at: datetime
    records: tuple[RegistryRecord, ...]
    snapshot_digest: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("snapshot_digest")
        result.pop("signature")
        return result


@dataclass(frozen=True)
class RegistryAuditEvent:
    epoch: int
    record_id: str
    revision: int
    actor: str
    action: str
    reason_code: str
    occurred_at: datetime
    record_digest: str


class TrustRegistry:
    """Versioned enterprise admission registry with optimistic transitions."""

    def __init__(self, signing_key: bytes = REGISTRY_SIGNING_KEY) -> None:
        self._signing_key = signing_key
        self._records: dict[tuple[str, str, str], RegistryRecord] = {}
        self._epoch = 0
        self.audit: list[RegistryAuditEvent] = []

    @property
    def epoch(self) -> int:
        return self._epoch

    @staticmethod
    def _validate_metadata(metadata: PublicServerMetadata, now: datetime) -> None:
        if NAME_PATTERN.fullmatch(metadata.name) is None:
            raise RegistryDenied("SERVER_NAME_INVALID", metadata.name)
        if VERSION_PATTERN.fullmatch(metadata.version) is None:
            raise RegistryDenied("VERSION_NOT_PINNED", metadata.version)
        if metadata.package_version != metadata.version:
            raise RegistryDenied("PACKAGE_VERSION_MISMATCH", metadata.package_version)
        if metadata.status != "active":
            raise RegistryDenied("PUBLIC_ENTRY_NOT_ACTIVE", metadata.status)
        if metadata.package_type not in ALLOWED_PACKAGE_TYPES:
            raise RegistryDenied("PACKAGE_TYPE_DENIED", metadata.package_type)
        if not metadata.package_identifier or not metadata.repository_id:
            raise RegistryDenied("PUBLIC_PROVENANCE_INCOMPLETE")
        if not is_digest(metadata.package_digest):
            raise RegistryDenied("PACKAGE_DIGEST_INVALID", metadata.package_digest)
        if metadata.registry_updated_at > now + timedelta(seconds=5):
            raise RegistryDenied("PUBLIC_METADATA_FROM_FUTURE")
        require_https_endpoint(metadata.remote_url)

    @staticmethod
    def _validate_evidence(
        metadata: PublicServerMetadata,
        evidence: ReviewEvidence,
        now: datetime,
    ) -> None:
        if (metadata.name, metadata.version) != (
            evidence.server_name,
            evidence.server_version,
        ):
            raise RegistryDenied("EVIDENCE_SUBJECT_MISMATCH")
        if metadata.package_digest != evidence.artifact_digest:
            raise RegistryDenied("ARTIFACT_DIGEST_MISMATCH")
        if metadata.repository_id != evidence.source_repository_id:
            raise RegistryDenied("REPOSITORY_ID_MISMATCH")
        if metadata.remote_url != evidence.endpoint:
            raise RegistryDenied("ENDPOINT_MISMATCH")
        if not evidence.owner or not evidence.incident_contact:
            raise RegistryDenied("ACCOUNTABLE_OWNER_REQUIRED")
        if evidence.data_classification not in ALLOWED_DATA_CLASSES:
            raise RegistryDenied("DATA_CLASSIFICATION_DENIED")
        if evidence.sandbox_profile not in ALLOWED_SANDBOX_PROFILES:
            raise RegistryDenied("SANDBOX_PROFILE_DENIED")
        if not evidence.workload_identity.startswith("spiffe://"):
            raise RegistryDenied("WORKLOAD_IDENTITY_INVALID")
        require_https_endpoint(evidence.endpoint)
        evidence_digests = (
            evidence.artifact_digest,
            evidence.contract_digest,
            evidence.provenance_digest,
            evidence.sbom_digest,
            evidence.scan_digest,
        )
        if not all(is_digest(item) for item in evidence_digests):
            raise RegistryDenied("EVIDENCE_DIGEST_INVALID")
        if evidence.reviewed_at > now or evidence.expires_at <= now:
            raise RegistryDenied("REVIEW_NOT_CURRENT")
        if evidence.expires_at - evidence.reviewed_at > MAX_REVIEW_AGE:
            raise RegistryDenied("REVIEW_WINDOW_TOO_LONG")
        if not evidence.grants:
            raise RegistryDenied("CAPABILITY_GRANT_REQUIRED")
        names = [grant.exposed_name for grant in evidence.grants]
        tools = [grant.server_tool for grant in evidence.grants]
        if len(names) != len(set(names)) or len(tools) != len(set(tools)):
            raise RegistryDenied("CAPABILITY_GRANT_DUPLICATE")
        for grant in evidence.grants:
            if (
                not grant.exposed_name.startswith("support.")
                or not grant.server_tool.startswith("ticket.")
                or not grant.required_permission
                or not grant.downstream_scope
                or not 1 <= grant.max_calls_per_minute <= 60
            ):
                raise RegistryDenied("CAPABILITY_GRANT_INVALID", grant.exposed_name)

    def admit(
        self,
        metadata: PublicServerMetadata,
        evidence: ReviewEvidence,
        *,
        tenant_id: str,
        environment: str,
        actor: str,
        now: datetime,
        expected_revision: int = 0,
    ) -> RegistryRecord:
        self._validate_metadata(metadata, now)
        self._validate_evidence(metadata, evidence, now)
        if not ID_PATTERN.fullmatch(tenant_id) or not ID_PATTERN.fullmatch(environment):
            raise RegistryDenied("SCOPE_INVALID")
        key = tenant_id, environment, metadata.name
        previous = self._records.get(key)
        actual_revision = previous.revision if previous else 0
        if expected_revision != actual_revision:
            raise RegistryDenied(
                "REVISION_CONFLICT", f"expected={expected_revision} actual={actual_revision}"
            )
        if previous and previous.status == Lifecycle.REVOKED:
            raise RegistryDenied("REVOCATION_TERMINAL", previous.record_id)
        self._epoch += 1
        unsigned = {
            "schema_version": REGISTRY_SCHEMA,
            "record_id": (
                previous.record_id
                if previous
                else "record-" + digest((tenant_id, environment, metadata.name))[7:27]
            ),
            "revision": actual_revision + 1,
            "registry_epoch": self._epoch,
            "tenant_id": tenant_id,
            "environment": environment,
            "server_name": metadata.name,
            "server_version": metadata.version,
            "package_type": metadata.package_type,
            "package_identifier": metadata.package_identifier,
            "package_version": metadata.package_version,
            "source_repository_id": evidence.source_repository_id,
            "status": Lifecycle.ACTIVE,
            "status_reason": "EVIDENCE_REVIEW_APPROVED",
            "owner": evidence.owner,
            "incident_contact": evidence.incident_contact,
            "endpoint": evidence.endpoint,
            "workload_identity": evidence.workload_identity,
            "artifact_digest": evidence.artifact_digest,
            "contract_digest": evidence.contract_digest,
            "provenance_digest": evidence.provenance_digest,
            "sbom_digest": evidence.sbom_digest,
            "scan_digest": evidence.scan_digest,
            "evidence_digest": digest(evidence),
            "data_classification": evidence.data_classification,
            "sandbox_profile": evidence.sandbox_profile,
            "gateway_required": True,
            "grants": evidence.grants,
            "reviewed_at": evidence.reviewed_at,
            "expires_at": evidence.expires_at,
            "changed_at": now,
            "previous_record_digest": previous.record_digest if previous else None,
        }
        record_digest = digest(unsigned)
        record = RegistryRecord(
            **unsigned,
            record_digest=record_digest,
            signature=sign(record_digest, self._signing_key),
        )
        self._records[key] = record
        self.audit.append(
            RegistryAuditEvent(
                self._epoch,
                record.record_id,
                record.revision,
                actor,
                "admit",
                record.status_reason,
                now,
                record.record_digest,
            )
        )
        return record

    def transition(
        self,
        key: tuple[str, str, str],
        status: Lifecycle,
        *,
        expected_revision: int,
        actor: str,
        reason_code: str,
        now: datetime,
    ) -> RegistryRecord:
        current = self._records.get(key)
        if current is None:
            raise RegistryDenied("RECORD_NOT_FOUND")
        if current.revision != expected_revision:
            raise RegistryDenied(
                "REVISION_CONFLICT",
                f"expected={expected_revision} actual={current.revision}",
            )
        allowed = {
            Lifecycle.ACTIVE: {
                Lifecycle.DEPRECATED,
                Lifecycle.QUARANTINED,
                Lifecycle.REVOKED,
            },
            Lifecycle.DEPRECATED: {Lifecycle.QUARANTINED, Lifecycle.REVOKED},
            Lifecycle.QUARANTINED: {Lifecycle.REVOKED},
            Lifecycle.REVOKED: set(),
        }
        if status not in allowed[current.status]:
            raise RegistryDenied(
                "LIFECYCLE_TRANSITION_DENIED", f"{current.status}->{status}"
            )
        if not reason_code or len(reason_code) > 96:
            raise RegistryDenied("REASON_CODE_INVALID")
        self._epoch += 1
        unsigned = current.unsigned()
        unsigned.update(
            {
                "revision": current.revision + 1,
                "registry_epoch": self._epoch,
                "status": status,
                "status_reason": reason_code,
                "changed_at": now,
                "previous_record_digest": current.record_digest,
            }
        )
        record_digest = digest(unsigned)
        updated = RegistryRecord(
            **unsigned,
            record_digest=record_digest,
            signature=sign(record_digest, self._signing_key),
        )
        self._records[key] = updated
        self.audit.append(
            RegistryAuditEvent(
                self._epoch,
                updated.record_id,
                updated.revision,
                actor,
                "transition",
                reason_code,
                now,
                updated.record_digest,
            )
        )
        return updated

    def get(self, key: tuple[str, str, str]) -> RegistryRecord | None:
        return self._records.get(key)

    def snapshot(self, now: datetime) -> RegistrySnapshot:
        unsigned = {
            "schema_version": REGISTRY_SCHEMA,
            "epoch": self._epoch,
            "issued_at": now,
            "expires_at": now + MAX_CACHE_AGE,
            "records": tuple(sorted(self._records.values(), key=lambda item: item.key)),
        }
        snapshot_digest = digest(unsigned)
        return RegistrySnapshot(
            **unsigned,
            snapshot_digest=snapshot_digest,
            signature=sign(snapshot_digest, self._signing_key),
        )


def verify_record(record: RegistryRecord, signing_key: bytes = REGISTRY_SIGNING_KEY) -> None:
    if record.schema_version != REGISTRY_SCHEMA:
        raise RegistryDenied("RECORD_SCHEMA_UNSUPPORTED")
    if record.revision < 1 or record.registry_epoch < 1:
        raise RegistryDenied("RECORD_REVISION_INVALID")
    if digest(record.unsigned()) != record.record_digest:
        raise RegistryDenied("RECORD_DIGEST_INVALID")
    if not hmac.compare_digest(sign(record.record_digest, signing_key), record.signature):
        raise RegistryDenied("RECORD_SIGNATURE_INVALID")
    if (
        NAME_PATTERN.fullmatch(record.server_name) is None
        or VERSION_PATTERN.fullmatch(record.server_version) is None
        or ID_PATTERN.fullmatch(record.tenant_id) is None
        or ID_PATTERN.fullmatch(record.environment) is None
    ):
        raise RegistryDenied("RECORD_SUBJECT_INVALID")
    if (
        record.package_type not in ALLOWED_PACKAGE_TYPES
        or not record.package_identifier
        or record.package_version != record.server_version
        or not record.source_repository_id
    ):
        raise RegistryDenied("RECORD_PACKAGE_INVALID")
    if not record.owner or not record.incident_contact:
        raise RegistryDenied("RECORD_ACCOUNTABILITY_INVALID")
    if record.data_classification not in ALLOWED_DATA_CLASSES:
        raise RegistryDenied("RECORD_DATA_CLASSIFICATION_INVALID")
    if record.sandbox_profile not in ALLOWED_SANDBOX_PROFILES:
        raise RegistryDenied("RECORD_SANDBOX_PROFILE_INVALID")
    if not record.workload_identity.startswith("spiffe://"):
        raise RegistryDenied("RECORD_WORKLOAD_IDENTITY_INVALID")
    require_https_endpoint(record.endpoint)
    if not all(
        is_digest(value)
        for value in (
            record.artifact_digest,
            record.contract_digest,
            record.provenance_digest,
            record.sbom_digest,
            record.scan_digest,
            record.evidence_digest,
        )
    ):
        raise RegistryDenied("RECORD_EVIDENCE_INVALID")
    if record.reviewed_at >= record.expires_at:
        raise RegistryDenied("RECORD_REVIEW_WINDOW_INVALID")


def verify_snapshot(
    snapshot: RegistrySnapshot, signing_key: bytes = REGISTRY_SIGNING_KEY
) -> None:
    if snapshot.schema_version != REGISTRY_SCHEMA:
        raise RegistryDenied("SNAPSHOT_SCHEMA_UNSUPPORTED")
    if digest(snapshot.unsigned()) != snapshot.snapshot_digest:
        raise RegistryDenied("SNAPSHOT_DIGEST_INVALID")
    if not hmac.compare_digest(
        sign(snapshot.snapshot_digest, signing_key), snapshot.signature
    ):
        raise RegistryDenied("SNAPSHOT_SIGNATURE_INVALID")
    if snapshot.expires_at <= snapshot.issued_at:
        raise RegistryDenied("SNAPSHOT_WINDOW_INVALID")
    seen: set[tuple[str, str, str]] = set()
    for record in snapshot.records:
        verify_record(record, signing_key)
        if record.key in seen:
            raise RegistryDenied("SNAPSHOT_DUPLICATE_RECORD")
        if record.registry_epoch > snapshot.epoch:
            raise RegistryDenied("SNAPSHOT_EPOCH_INVALID")
        seen.add(record.key)


class HostTrustCache:
    """Atomically consumes signed snapshots and fails closed when stale."""

    def __init__(self, signing_key: bytes = REGISTRY_SIGNING_KEY) -> None:
        self._signing_key = signing_key
        self._records: dict[tuple[str, str, str], RegistryRecord] = {}
        self.epoch = 0
        self.synced_at: datetime | None = None
        self.expires_at: datetime | None = None
        self.snapshot_digest: str | None = None
        self.state_digest: str | None = None

    def sync(self, snapshot: RegistrySnapshot, now: datetime) -> None:
        verify_snapshot(snapshot, self._signing_key)
        if snapshot.epoch < self.epoch:
            raise RegistryDenied("SNAPSHOT_ROLLBACK")
        state_digest = digest(
            tuple((record.key, record.record_digest) for record in snapshot.records)
        )
        if snapshot.epoch == self.epoch and self.state_digest not in {None, state_digest}:
            raise RegistryDenied("SNAPSHOT_EQUIVOCATION")
        if snapshot.issued_at > now + timedelta(seconds=5):
            raise RegistryDenied("SNAPSHOT_FROM_FUTURE")
        if now >= snapshot.expires_at:
            raise RegistryDenied("SNAPSHOT_EXPIRED")
        replacement = {record.key: record for record in snapshot.records}
        self._records = replacement
        self.epoch = snapshot.epoch
        self.synced_at = now
        self.expires_at = snapshot.expires_at
        self.snapshot_digest = snapshot.snapshot_digest
        self.state_digest = state_digest

    def resolve(
        self,
        *,
        tenant_id: str,
        environment: str,
        server_name: str,
        now: datetime,
    ) -> RegistryRecord:
        if (
            self.synced_at is None
            or self.expires_at is None
            or now >= self.expires_at
            or now - self.synced_at > MAX_CACHE_AGE
        ):
            raise GatewayDenied("REGISTRY_CACHE_STALE")
        record = self._records.get((tenant_id, environment, server_name))
        if record is None:
            raise GatewayDenied("SERVER_NOT_ADMITTED", server_name)
        if record.status != Lifecycle.ACTIVE:
            raise GatewayDenied("SERVER_NOT_ACTIVE", record.status)
        if now >= record.expires_at:
            raise GatewayDenied("REVIEW_EXPIRED", record.record_id)
        return record

    def record(self, key: tuple[str, str, str]) -> RegistryRecord | None:
        return self._records.get(key)


class ServerTrustView:
    """Independent registry view used by the protected MCP resource server."""

    def __init__(self, signing_key: bytes = REGISTRY_SIGNING_KEY) -> None:
        self._signing_key = signing_key
        self.epoch = 0
        self.snapshot_digest: str | None = None
        self.state_digest: str | None = None
        self.expires_at: datetime | None = None
        self.active_records: dict[str, RegistryRecord] = {}

    @property
    def active_record_digests(self) -> set[str]:
        return set(self.active_records)

    def sync(self, snapshot: RegistrySnapshot) -> None:
        verify_snapshot(snapshot, self._signing_key)
        if snapshot.epoch < self.epoch:
            raise RegistryDenied("SNAPSHOT_ROLLBACK")
        state_digest = digest(
            tuple((record.key, record.record_digest) for record in snapshot.records)
        )
        if snapshot.epoch == self.epoch and self.state_digest not in {None, state_digest}:
            raise RegistryDenied("SNAPSHOT_EQUIVOCATION")
        self.epoch = snapshot.epoch
        self.snapshot_digest = snapshot.snapshot_digest
        self.state_digest = state_digest
        self.expires_at = snapshot.expires_at
        self.active_records = {
            record.record_digest: record
            for record in snapshot.records
            if record.status == Lifecycle.ACTIVE
        }


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    tenant_id: str
    permissions: frozenset[str]

    @property
    def audit_subject(self) -> str:
        return "subject-" + hmac.new(
            b"course-17-audit-pseudonym", self.subject.encode(), sha256
        ).hexdigest()[:20]


class TokenBroker:
    """Issues server-specific, short-lived child authority after gateway policy."""

    def __init__(self, key: bytes = TOKEN_SIGNING_KEY) -> None:
        self._key = key
        self.revoked_jtis: set[str] = set()
        self.revoked_record_digests: set[str] = set()

    def issue(
        self,
        principal: AuthenticatedPrincipal,
        record: RegistryRecord,
        grant: CapabilityGrant,
        now: datetime,
        request_id: str,
    ) -> str:
        if grant.required_permission not in principal.permissions:
            raise GatewayDenied("PERMISSION_DENIED", grant.required_permission)
        jti = digest((request_id, record.record_digest, principal.audit_subject))[7:39]
        payload = {
            "iss": TOKEN_ISSUER,
            "aud": record.endpoint,
            "sub": principal.subject,
            "tenant": principal.tenant_id,
            "scope": grant.downstream_scope,
            "server": record.server_name,
            "registry_record": record.record_digest,
            "iat": int(now.timestamp()),
            "exp": int((now + TOKEN_LIFETIME).timestamp()),
            "jti": jti,
        }
        return jwt.encode(payload, self._key, algorithm="HS256")

    def revoke_record(self, record_digest: str) -> None:
        self.revoked_record_digests.add(record_digest)

    def revoke_jti(self, jti: str) -> None:
        self.revoked_jtis.add(jti)


class ResourceServerAuthorizer:
    """Validates downstream authority independently of the gateway decision."""

    def __init__(
        self,
        trust_view: ServerTrustView,
        token_broker: TokenBroker,
        key: bytes = TOKEN_SIGNING_KEY,
    ) -> None:
        self.trust_view = trust_view
        self.token_broker = token_broker
        self._key = key

    def validate(
        self,
        token: str | None,
        *,
        audience: str,
        required_scope: str,
        now: datetime,
    ) -> dict[str, Any]:
        if not token:
            raise ToolError("downstream authentication required")
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=["HS256"],
                audience=audience,
                issuer=TOKEN_ISSUER,
                options={"verify_exp": False, "verify_iat": False},
            )
        except InvalidTokenError as error:
            raise ToolError("downstream token invalid") from error
        required = {
            "sub",
            "tenant",
            "scope",
            "server",
            "registry_record",
            "iat",
            "exp",
            "jti",
        }
        if not required.issubset(claims):
            raise ToolError("downstream token claims incomplete")
        if self.trust_view.expires_at is None or now >= self.trust_view.expires_at:
            raise ToolError("registry view stale")
        if not isinstance(claims["iat"], int) or not isinstance(claims["exp"], int):
            raise ToolError("downstream token time invalid")
        if claims["iat"] > int(now.timestamp()) + 5 or claims["exp"] <= int(now.timestamp()):
            raise ToolError("downstream token expired or future-dated")
        scopes = frozenset(str(claims["scope"]).split())
        if required_scope not in scopes:
            raise ToolError("downstream scope denied")
        if claims["jti"] in self.token_broker.revoked_jtis:
            raise ToolError("downstream token revoked")
        if claims["server"] != SERVER_NAME or not isinstance(claims["tenant"], str):
            raise ToolError("downstream token target invalid")
        if claims["registry_record"] in self.token_broker.revoked_record_digests:
            raise ToolError("registry authority revoked")
        record = self.trust_view.active_records.get(str(claims["registry_record"]))
        if record is None:
            raise ToolError("registry record not active")
        if now >= record.expires_at:
            raise ToolError("registry review expired")
        if (
            record.endpoint != audience
            or record.server_name != claims["server"]
            or record.tenant_id != claims["tenant"]
            or record.workload_identity != WORKLOAD_ID
        ):
            raise ToolError("registry binding invalid")
        return claims


REQUEST_TOKEN: ContextVar[str | None] = ContextVar("request_token", default=None)
REQUEST_TIME: ContextVar[datetime | None] = ContextVar("request_time", default=None)


@dataclass(frozen=True)
class DeployedServer:
    mcp: MCPServer
    server_name: str
    server_version: str
    endpoint: str
    workload_identity: str
    artifact_digest: str
    calls: dict[str, int]


TICKETS = {
    "acme-7": TicketView(
        ticket_id="acme-7",
        status="open",
        summary="Payment is pending; customer-authored text remains untrusted.",
        content_trust="untrusted-customer-content",
    ),
    "globex-9": TicketView(
        ticket_id="globex-9",
        status="open",
        summary="Globex-only record.",
        content_trust="untrusted-customer-content",
    ),
}


def make_support_server(
    authorizer: ResourceServerAuthorizer, *, drifted_contract: bool = False
) -> DeployedServer:
    calls = {"ticket.read": 0}
    server = MCPServer(name="acme-support", version=SERVER_VERSION)

    @server.tool(
        name="ticket.read",
        description="Read one support ticket owned by the authenticated tenant.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    def read_ticket(ticket_id: TicketId) -> TicketReadOutput:
        now = REQUEST_TIME.get()
        if now is None:
            raise ToolError("trusted request time unavailable")
        claims = authorizer.validate(
            REQUEST_TOKEN.get(),
            audience=ENDPOINT,
            required_scope="ticket:read",
            now=now,
        )
        expected_prefix = f"{claims['tenant']}-"
        if not ticket_id.startswith(expected_prefix):
            raise ToolError("ticket tenant denied")
        ticket = TICKETS.get(ticket_id)
        if ticket is None:
            raise ToolError("ticket unavailable")
        calls["ticket.read"] += 1
        return TicketReadOutput(ticket=ticket, policy_version=POLICY_VERSION)

    if drifted_contract:

        @server.tool(
            name="filesystem.read",
            description="Unreviewed arbitrary filesystem capability.",
            annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        )
        def read_file(path: str) -> str:
            return f"not executed: {path}"

    return DeployedServer(
        server,
        SERVER_NAME,
        SERVER_VERSION,
        ENDPOINT,
        WORKLOAD_ID,
        ARTIFACT_DIGEST,
        calls,
    )


async def inspect_contract(server: MCPServer) -> tuple[str, tuple[str, ...]]:
    """Hash the complete SDK-returned tool contracts, not just display names."""

    async with Client(
        server,
        client_info=Implementation(name="course-17-reviewer", version="1.0.0"),
        mode="auto",
    ) as client:
        result = await client.list_tools()
    contracts = tuple(
        sorted(
            (
                tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                for tool in result.tools
            ),
            key=lambda item: item["name"],
        )
    )
    return digest(contracts), tuple(item["name"] for item in contracts)


@dataclass(frozen=True)
class GatewayRequest:
    request_id: str
    trace_id: str
    protocol_version: str
    method: str
    exposed_name: str
    arguments: dict[str, Any]
    claimed_tenant: str | None = None
    client_authorization: str | None = None


@dataclass(frozen=True)
class GatewayAuditEvent:
    request_id: str
    trace_id: str
    principal: str
    tenant_id: str
    server_name: str
    record_digest: str | None
    capability: str
    argument_digest: str
    decision: Decision
    reason_code: str
    outcome: Outcome
    occurred_at: datetime


@dataclass(frozen=True)
class GatewayResult:
    decision: Decision
    reason_code: str
    outcome: Outcome
    response: TicketReadOutput | None
    record_digest: str | None
    downstream_jti: str | None


class FixedWindowLimiter:
    def __init__(self) -> None:
        self._calls: dict[tuple[str, str, int], int] = {}

    def consume(
        self,
        subject: str,
        capability: str,
        now: datetime,
        maximum: int,
    ) -> None:
        minute = int(now.timestamp()) // 60
        key = subject, capability, minute
        count = self._calls.get(key, 0) + 1
        if count > maximum:
            raise GatewayDenied("RATE_LIMIT_EXCEEDED", capability)
        self._calls[key] = count


class EnterpriseGateway:
    """Policy enforcement point; does not trust caller or registry metadata."""

    def __init__(
        self,
        cache: HostTrustCache,
        token_broker: TokenBroker,
        *,
        environment: str = "prod",
    ) -> None:
        self.cache = cache
        self.token_broker = token_broker
        self.environment = environment
        self.audit: list[GatewayAuditEvent] = []
        self.limiter = FixedWindowLimiter()

    def _audit(
        self,
        request: GatewayRequest,
        principal: AuthenticatedPrincipal,
        decision: Decision,
        reason_code: str,
        outcome: Outcome,
        now: datetime,
        record: RegistryRecord | None = None,
    ) -> None:
        self.audit.append(
            GatewayAuditEvent(
                request.request_id,
                request.trace_id,
                principal.audit_subject,
                principal.tenant_id,
                SERVER_NAME,
                record.record_digest if record else None,
                request.exposed_name,
                digest(request.arguments),
                decision,
                reason_code,
                outcome,
                now,
            )
        )

    async def handle(
        self,
        request: GatewayRequest,
        principal: AuthenticatedPrincipal,
        target: DeployedServer,
        now: datetime,
    ) -> GatewayResult:
        record: RegistryRecord | None = None
        try:
            if TRACE_PATTERN.fullmatch(request.request_id) is None or TRACE_PATTERN.fullmatch(
                request.trace_id
            ) is None:
                raise GatewayDenied("REQUEST_ID_INVALID")
            if request.protocol_version != PROTOCOL_VERSION:
                raise GatewayDenied("PROTOCOL_VERSION_DENIED", request.protocol_version)
            if request.method != "tools/call":
                raise GatewayDenied("METHOD_DENIED", request.method)
            record = self.cache.resolve(
                tenant_id=principal.tenant_id,
                environment=self.environment,
                server_name=target.server_name,
                now=now,
            )
            if not record.gateway_required:
                raise GatewayDenied("GATEWAY_POLICY_INVALID")
            if record.server_version != target.server_version:
                raise GatewayDenied("SERVER_VERSION_DRIFT")
            if record.endpoint != target.endpoint:
                raise GatewayDenied("ENDPOINT_DRIFT")
            if record.workload_identity != target.workload_identity:
                raise GatewayDenied("WORKLOAD_IDENTITY_DRIFT")
            if record.artifact_digest != target.artifact_digest:
                raise GatewayDenied("ARTIFACT_DRIFT")
            grant = next(
                (item for item in record.grants if item.exposed_name == request.exposed_name),
                None,
            )
            if grant is None:
                raise GatewayDenied("CAPABILITY_NOT_EXPOSED", request.exposed_name)
            if grant.required_permission not in principal.permissions:
                raise GatewayDenied("PERMISSION_DENIED", grant.required_permission)
            try:
                validated_input = TicketReadInput.model_validate(request.arguments)
            except ValidationError as error:
                raise GatewayDenied("INVALID_TOOL_ARGUMENTS") from error
            live_contract_digest, live_tools = await inspect_contract(target.mcp)
            if live_contract_digest != record.contract_digest:
                raise GatewayDenied("CONTRACT_DRIFT", ",".join(live_tools))
            if grant.server_tool not in live_tools:
                raise GatewayDenied("GRANT_TARGET_MISSING", grant.server_tool)
            self.limiter.consume(
                principal.audit_subject,
                grant.exposed_name,
                now,
                grant.max_calls_per_minute,
            )
            token = self.token_broker.issue(principal, record, grant, now, request.request_id)
            claims = jwt.decode(
                token,
                TOKEN_SIGNING_KEY,
                algorithms=["HS256"],
                audience=record.endpoint,
                issuer=TOKEN_ISSUER,
                options={"verify_exp": False},
            )
            token_marker = REQUEST_TOKEN.set(token)
            time_marker = REQUEST_TIME.set(now)
            try:
                async with Client(
                    target.mcp,
                    client_info=Implementation(name="course-17-gateway", version="1.0.0"),
                    mode="auto",
                ) as client:
                    raw_result = await client.call_tool(
                        grant.server_tool,
                        validated_input.model_dump(mode="json"),
                    )
            finally:
                REQUEST_TIME.reset(time_marker)
                REQUEST_TOKEN.reset(token_marker)
            if raw_result.is_error or raw_result.structured_content is None:
                raise GatewayDenied("RESOURCE_SERVER_DENIED")
            try:
                response = TicketReadOutput.model_validate(raw_result.structured_content)
            except ValidationError as error:
                raise GatewayDenied("INVALID_TOOL_OUTPUT") from error
            self._audit(
                request,
                principal,
                Decision.ALLOW,
                "GATEWAY_AND_SERVER_POLICY_ALLOW",
                Outcome.COMPLETED,
                now,
                record,
            )
            return GatewayResult(
                Decision.ALLOW,
                "GATEWAY_AND_SERVER_POLICY_ALLOW",
                Outcome.COMPLETED,
                response,
                record.record_digest,
                str(claims["jti"]),
            )
        except GatewayDenied as error:
            self._audit(
                request,
                principal,
                Decision.DENY,
                error.code,
                Outcome.NOT_EXECUTED,
                now,
                record,
            )
            return GatewayResult(
                Decision.DENY,
                error.code,
                Outcome.NOT_EXECUTED,
                None,
                record.record_digest if record else None,
                None,
            )


async def direct_call_without_gateway(target: DeployedServer, now: datetime) -> bool:
    """Return True only if the protected server incorrectly allows bypass."""

    time_marker = REQUEST_TIME.set(now)
    token_marker = REQUEST_TOKEN.set(None)
    try:
        async with Client(
            target.mcp,
            client_info=Implementation(name="untrusted-direct-client", version="1.0.0"),
            mode="auto",
        ) as client:
            result = await client.call_tool("ticket.read", {"ticket_id": "acme-7"})
        return not result.is_error
    finally:
        REQUEST_TOKEN.reset(token_marker)
        REQUEST_TIME.reset(time_marker)


@dataclass
class Environment:
    now: datetime
    metadata: PublicServerMetadata
    evidence: ReviewEvidence
    registry: TrustRegistry
    record: RegistryRecord
    snapshot: RegistrySnapshot
    cache: HostTrustCache
    server_view: ServerTrustView
    broker: TokenBroker
    authorizer: ResourceServerAuthorizer
    target: DeployedServer
    gateway: EnterpriseGateway
    principal: AuthenticatedPrincipal


async def reviewed_environment(now: datetime | None = None) -> Environment:
    now = now or utc("2026-10-07T17:30:00Z")
    registry = TrustRegistry()
    cache = HostTrustCache()
    server_view = ServerTrustView()
    broker = TokenBroker()
    authorizer = ResourceServerAuthorizer(server_view, broker)
    target = make_support_server(authorizer)
    contract_digest, tools = await inspect_contract(target.mcp)
    assert tools == ("ticket.read",)
    grant = CapabilityGrant(
        "support.ticket.read",
        "ticket.read",
        "ticket:read",
        "ticket:read",
        Risk.READ,
        2,
    )
    metadata = PublicServerMetadata(
        SERVER_NAME,
        SERVER_VERSION,
        "active",
        "pypi",
        "acme-support-mcp",
        SERVER_VERSION,
        ARTIFACT_DIGEST,
        SOURCE_REPOSITORY_ID,
        ENDPOINT,
        now - timedelta(minutes=5),
    )
    evidence = ReviewEvidence(
        SERVER_NAME,
        SERVER_VERSION,
        ARTIFACT_DIGEST,
        contract_digest,
        PROVENANCE_DIGEST,
        SBOM_DIGEST,
        SCAN_DIGEST,
        SOURCE_REPOSITORY_ID,
        ENDPOINT,
        WORKLOAD_ID,
        "platform-security",
        "soc-oncall",
        "confidential",
        "remote-managed",
        (grant,),
        now - timedelta(days=1),
        now + timedelta(days=30),
    )
    record = registry.admit(
        metadata,
        evidence,
        tenant_id="acme",
        environment="prod",
        actor="reviewer-17",
        now=now,
    )
    snapshot = registry.snapshot(now)
    cache.sync(snapshot, now)
    server_view.sync(snapshot)
    gateway = EnterpriseGateway(cache, broker)
    principal = AuthenticatedPrincipal(
        "analyst-42", "acme", frozenset({"ticket:read"})
    )
    return Environment(
        now,
        metadata,
        evidence,
        registry,
        record,
        snapshot,
        cache,
        server_view,
        broker,
        authorizer,
        target,
        gateway,
        principal,
    )


def request(
    *,
    request_id: str = "req-safe-1",
    trace_id: str = "trace-safe-1",
    exposed_name: str = "support.ticket.read",
    arguments: dict[str, Any] | None = None,
    protocol_version: str = PROTOCOL_VERSION,
) -> GatewayRequest:
    return GatewayRequest(
        request_id,
        trace_id,
        protocol_version,
        "tools/call",
        exposed_name,
        arguments or {"ticket_id": "acme-7"},
        claimed_tenant="globex",
        client_authorization="Bearer attacker-controlled-token",
    )


@dataclass(frozen=True)
class ScenarioCase:
    case_id: str
    expected_allow: bool
    mutation: str


@dataclass(frozen=True)
class ScenarioResult:
    case_id: str
    expected_allow: bool
    actual_allow: bool
    reason_code: str
    effect_count: int


CASES = (
    ScenarioCase("approved-read", True, "none"),
    ScenarioCase("wrong-tenant-record", False, "wrong_tenant"),
    ScenarioCase("missing-permission", False, "missing_permission"),
    ScenarioCase("capability-not-exposed", False, "unknown_capability"),
    ScenarioCase("artifact-drift", False, "artifact_drift"),
    ScenarioCase("endpoint-swap", False, "endpoint_swap"),
    ScenarioCase("workload-identity-drift", False, "workload_identity_drift"),
    ScenarioCase("contract-drift", False, "contract_drift"),
    ScenarioCase("stale-cache", False, "stale_cache"),
    ScenarioCase("revoked-entry", False, "revoked"),
    ScenarioCase("invalid-arguments", False, "invalid_arguments"),
    ScenarioCase("resource-server-tenant-deny", False, "resource_tenant_deny"),
)


async def run_case(case: ScenarioCase) -> ScenarioResult:
    env = await reviewed_environment()
    principal = env.principal
    target = env.target
    call = request(request_id=f"req-{case.case_id}", trace_id=f"trace-{case.case_id}")
    now = env.now + timedelta(milliseconds=25)
    if case.mutation == "wrong_tenant":
        principal = replace(principal, tenant_id="globex")
    elif case.mutation == "missing_permission":
        principal = replace(principal, permissions=frozenset())
    elif case.mutation == "unknown_capability":
        call = replace(call, exposed_name="support.ticket.delete")
    elif case.mutation == "artifact_drift":
        target = replace(target, artifact_digest=digest("substituted-artifact"))
    elif case.mutation == "endpoint_swap":
        target = replace(target, endpoint="https://attacker.invalid/mcp")
    elif case.mutation == "workload_identity_drift":
        target = replace(
            target,
            workload_identity="spiffe://prod.acme.test/ns/attacker/sa/rogue",
        )
    elif case.mutation == "contract_drift":
        target = make_support_server(env.authorizer, drifted_contract=True)
    elif case.mutation == "stale_cache":
        now = env.now + MAX_CACHE_AGE + timedelta(milliseconds=1)
    elif case.mutation == "revoked":
        env.registry.transition(
            env.record.key,
            Lifecycle.REVOKED,
            expected_revision=env.record.revision,
            actor="soc-17",
            reason_code="INCIDENT_CONFIRMED",
            now=now,
        )
        snapshot = env.registry.snapshot(now)
        env.cache.sync(snapshot, now)
        env.server_view.sync(snapshot)
        env.broker.revoke_record(env.record.record_digest)
    elif case.mutation == "invalid_arguments":
        call = replace(call, arguments={"ticket_id": "globex-9", "tenant": "globex"})
    elif case.mutation == "resource_tenant_deny":
        call = replace(call, arguments={"ticket_id": "globex-9"})
    result = await env.gateway.handle(call, principal, target, now)
    return ScenarioResult(
        case.case_id,
        case.expected_allow,
        result.decision == Decision.ALLOW,
        result.reason_code,
        target.calls["ticket.read"],
    )


@dataclass(frozen=True)
class CampaignReport:
    results: tuple[ScenarioResult, ...]
    true_allow: int
    false_allow: int
    true_deny: int
    false_deny: int

    def metrics(self) -> dict[str, float]:
        allowed = self.true_allow + self.false_deny
        denied = self.true_deny + self.false_allow
        total = allowed + denied
        return {
            "decision_accuracy": (self.true_allow + self.true_deny) / total,
            "unsafe_allow_rate": self.false_allow / denied if denied else 0.0,
            "false_block_rate": self.false_deny / allowed if allowed else 0.0,
            "safe_task_completion_rate": self.true_allow / allowed if allowed else 0.0,
        }


async def run_campaign(cases: Iterable[ScenarioCase] = CASES) -> CampaignReport:
    materialized = tuple(cases)
    if not materialized or len(materialized) > 50:
        raise ValueError("campaign size must be between 1 and 50")
    if len({case.case_id for case in materialized}) != len(materialized):
        raise ValueError("scenario IDs must be unique")
    results = tuple([await run_case(case) for case in materialized])
    true_allow = sum(r.expected_allow and r.actual_allow for r in results)
    false_allow = sum(not r.expected_allow and r.actual_allow for r in results)
    true_deny = sum(not r.expected_allow and not r.actual_allow for r in results)
    false_deny = sum(r.expected_allow and not r.actual_allow for r in results)
    return CampaignReport(results, true_allow, false_allow, true_deny, false_deny)


async def revocation_exercise() -> dict[str, Any]:
    env = await reviewed_environment()
    first = await env.gateway.handle(request(), env.principal, env.target, env.now)
    revoked_at = env.now + timedelta(milliseconds=40)
    revoked = env.registry.transition(
        env.record.key,
        Lifecycle.REVOKED,
        expected_revision=env.record.revision,
        actor="soc-17",
        reason_code="INCIDENT_CONFIRMED",
        now=revoked_at,
    )
    propagated_at = revoked_at + timedelta(milliseconds=25)
    snapshot = env.registry.snapshot(propagated_at)
    env.cache.sync(snapshot, propagated_at)
    env.server_view.sync(snapshot)
    env.broker.revoke_record(env.record.record_digest)
    second = await env.gateway.handle(
        request(request_id="req-after-revoke", trace_id="trace-after-revoke"),
        env.principal,
        env.target,
        propagated_at,
    )
    return {
        "before_revocation": first.decision,
        "after_revocation": second.decision,
        "after_reason": second.reason_code,
        "registry_revision": revoked.revision,
        "registry_epoch": snapshot.epoch,
        "host_epoch": env.cache.epoch,
        "server_epoch": env.server_view.epoch,
        "propagation_ms": round(
            (propagated_at - revoked_at).total_seconds() * 1_000
        ),
        "effect_count": env.target.calls["ticket.read"],
    }


async def run_demo() -> dict[str, Any]:
    env = await reviewed_environment()
    approved = await env.gateway.handle(request(), env.principal, env.target, env.now)
    bypass_allowed = await direct_call_without_gateway(env.target, env.now)
    campaign = await run_campaign()
    revocation = await revocation_exercise()
    return {
        "registry": {
            "server": env.record.server_name,
            "version": env.record.server_version,
            "record_digest": env.record.record_digest,
            "status": env.record.status,
            "epoch": env.snapshot.epoch,
            "grants": [grant.exposed_name for grant in env.record.grants],
        },
        "approved_call": {
            "decision": approved.decision,
            "reason": approved.reason_code,
            "ticket": approved.response.ticket.ticket_id if approved.response else None,
            "downstream_token_issued": approved.downstream_jti is not None,
        },
        "direct_bypass_allowed": bypass_allowed,
        "campaign": {
            "metrics": campaign.metrics(),
            "results": [asdict(result) for result in campaign.results],
        },
        "revocation": revocation,
    }


def main() -> None:
    print(json.dumps(asyncio.run(run_demo()), indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
