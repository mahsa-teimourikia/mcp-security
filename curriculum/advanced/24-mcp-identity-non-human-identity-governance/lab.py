"""Course 24: governed non-human identity for an MCP estate.

This offline lab uses real Ed25519-signed JWTs through PyJWT/cryptography.
In-memory components stand in for an IdP, SPIFFE/SPIRE, policy engine,
approval service, inventory store, and telemetry backend. They demonstrate
control invariants; they are not production identity infrastructure.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
import json
from threading import Lock
from typing import Any, Iterable, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ISSUER = "https://identity.acme.test"
POLICY_VERSION = "nhi-policy-2026-10-30"
MAX_DELEGATION_DEPTH = 2


class IdentityKind(StrEnum):
    MCP_HOST = "mcp_host"
    MCP_CLIENT = "mcp_client"
    MCP_SERVER = "mcp_server"
    AGENT = "agent"
    GATEWAY = "gateway"
    CI_JOB = "ci_job"
    SERVICE_ACCOUNT = "service_account"


class LifecycleState(StrEnum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    DECOMMISSIONED = "decommissioned"


class GovernanceError(ValueError):
    """Fail-closed error with a stable, non-secret reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Mapping[str, Any]) -> str:
    return sha256(canonical_json(value)).hexdigest()


def _valid_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass(frozen=True)
class Owner:
    owner_id: str
    team: str
    active: bool
    roles: frozenset[str]


@dataclass(frozen=True)
class IdentityRecord:
    identity_id: str
    kind: IdentityKind
    tenant_id: str
    owner_id: str
    purpose: str
    environment: str
    trust_domain: str
    selectors: frozenset[str]
    artifact_digest: str
    allowed_audiences: frozenset[str]
    allowed_scopes: frozenset[str]
    max_ttl_seconds: int
    state: LifecycleState
    version: int
    revocation_epoch: int
    created_at: int
    review_due_at: int
    last_used_at: int | None = None
    credential_rotated_at: int | None = None
    shared: bool = False

    def proposal(self) -> dict[str, Any]:
        """All security-relevant registration fields, with no weak proxy."""
        return {
            "identity_id": self.identity_id,
            "kind": self.kind.value,
            "tenant_id": self.tenant_id,
            "owner_id": self.owner_id,
            "purpose": self.purpose,
            "environment": self.environment,
            "trust_domain": self.trust_domain,
            "selectors": sorted(self.selectors),
            "artifact_digest": self.artifact_digest,
            "allowed_audiences": sorted(self.allowed_audiences),
            "allowed_scopes": sorted(self.allowed_scopes),
            "max_ttl_seconds": self.max_ttl_seconds,
            "state": self.state.value,
            "version": self.version,
            "revocation_epoch": self.revocation_epoch,
            "created_at": self.created_at,
            "review_due_at": self.review_due_at,
            "shared": self.shared,
        }


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    proposal_digest: str
    requester_id: str
    approver_id: str
    policy_version: str
    expires_at: int


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    identity_id: str
    tenant_id: str
    decision: str
    reason: str
    timestamp: int
    correlation_id: str
    policy_version: str = POLICY_VERSION


class AuditLog:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(
        self,
        event_type: str,
        identity_id: str,
        tenant_id: str,
        decision: str,
        reason: str,
        timestamp: int,
        correlation_id: str,
    ) -> None:
        event_id = sha256(
            f"{len(self.events) + 1}|{event_type}|{identity_id}|{correlation_id}".encode()
        ).hexdigest()[:20]
        self.events.append(
            AuditEvent(
                event_id, event_type, identity_id, tenant_id, decision, reason,
                timestamp, correlation_id,
            )
        )


class ApprovalService:
    """Exact, short-lived, single-use, two-person approval receipts."""

    def __init__(self, owners: Mapping[str, Owner]) -> None:
        self.owners = owners
        self.receipts: dict[str, ApprovalReceipt] = {}
        self.consumed: set[str] = set()
        self._consume_lock = Lock()

    def issue(
        self,
        proposal: Mapping[str, Any],
        requester_id: str,
        approver_id: str,
        now: int,
        ttl_seconds: int = 300,
    ) -> ApprovalReceipt:
        approver = self.owners.get(approver_id)
        if requester_id == approver_id:
            raise GovernanceError("SEPARATION_OF_DUTIES")
        if approver is None or not approver.active or "identity-approver" not in approver.roles:
            raise GovernanceError("APPROVER_NOT_AUTHORIZED")
        if ttl_seconds <= 0 or ttl_seconds > 600:
            raise GovernanceError("APPROVAL_TTL_INVALID")
        proposal_digest = digest(proposal)
        receipt_id = sha256(
            f"{proposal_digest}|{requester_id}|{approver_id}|{now}".encode()
        ).hexdigest()[:24]
        receipt = ApprovalReceipt(
            receipt_id, proposal_digest, requester_id, approver_id,
            POLICY_VERSION, now + ttl_seconds,
        )
        self.receipts[receipt_id] = receipt
        return receipt

    def consume(
        self,
        receipt_id: str,
        proposal: Mapping[str, Any],
        requester_id: str,
        now: int,
    ) -> ApprovalReceipt:
        with self._consume_lock:
            receipt = self.receipts.get(receipt_id)
            if receipt is None:
                raise GovernanceError("APPROVAL_UNKNOWN")
            if receipt_id in self.consumed:
                raise GovernanceError("APPROVAL_REPLAY")
            if receipt.expires_at <= now:
                raise GovernanceError("APPROVAL_EXPIRED")
            if receipt.policy_version != POLICY_VERSION:
                raise GovernanceError("APPROVAL_POLICY_STALE")
            if receipt.requester_id != requester_id or receipt.proposal_digest != digest(proposal):
                raise GovernanceError("APPROVAL_BINDING_MISMATCH")
            self.consumed.add(receipt_id)
            return receipt


class IdentityRegistry:
    """Versioned source of lifecycle and authorization truth."""

    def __init__(self, owners: Iterable[Owner], audit: AuditLog) -> None:
        self.owners = {owner.owner_id: owner for owner in owners}
        self.records: dict[str, IdentityRecord] = {}
        self.audit = audit
        self.approvals = ApprovalService(self.owners)

    def _validate_candidate(self, record: IdentityRecord) -> None:
        if not record.identity_id.startswith(f"spiffe://{record.trust_domain}/"):
            raise GovernanceError("IDENTITY_TRUST_DOMAIN_MISMATCH")
        if not record.tenant_id or not record.owner_id or not record.purpose:
            raise GovernanceError("IDENTITY_METADATA_INCOMPLETE")
        owner = self.owners.get(record.owner_id)
        if owner is None or not owner.active:
            raise GovernanceError("OWNER_INACTIVE_OR_UNKNOWN")
        if not record.selectors or not record.allowed_audiences or not record.allowed_scopes:
            raise GovernanceError("IDENTITY_BOUNDARY_EMPTY")
        if any("*" in value for value in (*record.allowed_audiences, *record.allowed_scopes)):
            raise GovernanceError("WILDCARD_AUTHORITY")
        if not _valid_digest(record.artifact_digest):
            raise GovernanceError("ARTIFACT_DIGEST_INVALID")
        if not 60 <= record.max_ttl_seconds <= 3600:
            raise GovernanceError("CREDENTIAL_TTL_OUT_OF_POLICY")
        if record.review_due_at <= record.created_at:
            raise GovernanceError("REVIEW_WINDOW_INVALID")
        if record.version != 1 or record.revocation_epoch != 0:
            raise GovernanceError("INITIAL_VERSION_INVALID")
        if record.state is not LifecycleState.CANDIDATE:
            raise GovernanceError("INITIAL_STATE_INVALID")
        if record.shared:
            raise GovernanceError("SHARED_IDENTITY_FORBIDDEN")

    def register(
        self,
        record: IdentityRecord,
        receipt_id: str,
        requester_id: str,
        now: int,
    ) -> IdentityRecord:
        self._validate_candidate(record)
        if record.identity_id in self.records:
            raise GovernanceError("IDENTITY_ALREADY_EXISTS")
        self.approvals.consume(receipt_id, record.proposal(), requester_id, now)
        active = replace(record, state=LifecycleState.ACTIVE)
        self.records[active.identity_id] = active
        self.audit.emit(
            "identity.registered", active.identity_id, active.tenant_id, "allow",
            "approved_candidate_activated", now, receipt_id,
        )
        return active

    def get(self, identity_id: str) -> IdentityRecord:
        record = self.records.get(identity_id)
        if record is None:
            raise GovernanceError("IDENTITY_UNKNOWN")
        return record

    @staticmethod
    def change_proposal(
        identity_id: str, changes: Mapping[str, Any], expected_version: int
    ) -> dict[str, Any]:
        return {
            "operation": "identity.update",
            "identity_id": identity_id,
            "expected_version": expected_version,
            "changes": {
                key: sorted(value) if isinstance(value, frozenset) else value
                for key, value in sorted(changes.items())
            },
        }

    def replace_with_approval(
        self,
        identity_id: str,
        changes: Mapping[str, Any],
        expected_version: int,
        receipt_id: str,
        requester_id: str,
        now: int,
    ) -> IdentityRecord:
        current = self.get(identity_id)
        if current.version != expected_version:
            raise GovernanceError("STALE_IDENTITY_VERSION")
        allowed = {
            "owner_id", "purpose", "selectors", "artifact_digest",
            "allowed_audiences", "allowed_scopes", "max_ttl_seconds",
            "review_due_at",
        }
        if not changes or not set(changes) <= allowed:
            raise GovernanceError("IDENTITY_CHANGE_NOT_ALLOWED")
        proposal = self.change_proposal(identity_id, changes, expected_version)
        candidate = replace(current, **changes, version=current.version + 1)
        self._validate_update(candidate, now)
        # Validate before consuming the one-shot approval. A rejected mutation
        # must not burn the receipt while leaving the registry unchanged.
        self.approvals.consume(receipt_id, proposal, requester_id, now)
        if candidate.artifact_digest != current.artifact_digest:
            candidate = replace(candidate, credential_rotated_at=now)
        self.records[identity_id] = candidate
        self.audit.emit(
            "identity.updated", identity_id, candidate.tenant_id, "allow",
            "approved_version_change", now, receipt_id,
        )
        return candidate

    def _validate_update(self, record: IdentityRecord, now: int) -> None:
        owner = self.owners.get(record.owner_id)
        if owner is None or not owner.active:
            raise GovernanceError("OWNER_INACTIVE_OR_UNKNOWN")
        if record.review_due_at <= now:
            raise GovernanceError("REVIEW_ALREADY_DUE")
        if not record.selectors or not record.allowed_audiences or not record.allowed_scopes:
            raise GovernanceError("IDENTITY_BOUNDARY_EMPTY")
        if any("*" in value for value in (*record.allowed_audiences, *record.allowed_scopes)):
            raise GovernanceError("WILDCARD_AUTHORITY")
        if not _valid_digest(record.artifact_digest):
            raise GovernanceError("ARTIFACT_DIGEST_INVALID")
        if not 60 <= record.max_ttl_seconds <= 3600:
            raise GovernanceError("CREDENTIAL_TTL_OUT_OF_POLICY")

    def suspend(self, identity_id: str, expected_version: int, now: int, reason: str) -> IdentityRecord:
        return self._transition(identity_id, expected_version, LifecycleState.SUSPENDED, now, reason)

    def revoke(self, identity_id: str, expected_version: int, now: int, reason: str) -> IdentityRecord:
        return self._transition(
            identity_id, expected_version, LifecycleState.REVOKED, now, reason, True
        )

    def decommission(self, identity_id: str, expected_version: int, now: int, reason: str) -> IdentityRecord:
        return self._transition(
            identity_id, expected_version, LifecycleState.DECOMMISSIONED, now, reason, True
        )

    def _transition(
        self,
        identity_id: str,
        expected_version: int,
        target: LifecycleState,
        now: int,
        reason: str,
        increment_epoch: bool = False,
    ) -> IdentityRecord:
        current = self.get(identity_id)
        if current.version != expected_version:
            raise GovernanceError("STALE_IDENTITY_VERSION")
        allowed = {
            LifecycleState.ACTIVE: {LifecycleState.SUSPENDED, LifecycleState.REVOKED},
            LifecycleState.SUSPENDED: {
                LifecycleState.ACTIVE, LifecycleState.REVOKED,
                LifecycleState.DECOMMISSIONED,
            },
            LifecycleState.REVOKED: {LifecycleState.DECOMMISSIONED},
        }
        if target not in allowed.get(current.state, set()):
            raise GovernanceError("LIFECYCLE_TRANSITION_INVALID")
        if not reason.strip():
            raise GovernanceError("LIFECYCLE_REASON_REQUIRED")
        changed = replace(
            current,
            state=target,
            version=current.version + 1,
            revocation_epoch=current.revocation_epoch + int(increment_epoch),
        )
        self.records[identity_id] = changed
        self.audit.emit(
            f"identity.{target.value}", identity_id, changed.tenant_id, "allow",
            reason, now, f"lifecycle-{changed.version}",
        )
        return changed

    def mark_used(self, identity_id: str, when: int) -> None:
        self.records[identity_id] = replace(self.get(identity_id), last_used_at=when)


@dataclass(frozen=True)
class AttestationEvidence:
    workload_id: str
    tenant_id: str
    trust_domain: str
    selectors: frozenset[str]
    artifact_digest: str
    observed_at: int
    nonce: str

    def payload(self) -> dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "tenant_id": self.tenant_id,
            "trust_domain": self.trust_domain,
            "selectors": sorted(self.selectors),
            "artifact_digest": self.artifact_digest,
            "observed_at": self.observed_at,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class SignedAttestation:
    evidence: AttestationEvidence
    signature: bytes


class WorkloadAttestor:
    """Training analogue for a platform attestor and SPIFFE Workload API."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.used_nonces: set[str] = set()

    def issue(self, evidence: AttestationEvidence) -> SignedAttestation:
        return SignedAttestation(
            evidence, self._private_key.sign(canonical_json(evidence.payload()))
        )

    def verify(
        self,
        signed: SignedAttestation,
        record: IdentityRecord,
        now: int,
        consume_nonce: bool = True,
    ) -> str:
        evidence = signed.evidence
        try:
            self.public_key.verify(signed.signature, canonical_json(evidence.payload()))
        except Exception as exc:
            raise GovernanceError("ATTESTATION_SIGNATURE_INVALID") from exc
        if evidence.observed_at > now + 5 or now - evidence.observed_at > 60:
            raise GovernanceError("ATTESTATION_STALE")
        if consume_nonce and evidence.nonce in self.used_nonces:
            raise GovernanceError("ATTESTATION_REPLAY")
        if (
            evidence.workload_id != record.identity_id
            or evidence.tenant_id != record.tenant_id
            or evidence.trust_domain != record.trust_domain
        ):
            raise GovernanceError("ATTESTATION_IDENTITY_MISMATCH")
        if not record.selectors <= evidence.selectors:
            raise GovernanceError("ATTESTATION_SELECTOR_MISMATCH")
        if evidence.artifact_digest != record.artifact_digest:
            raise GovernanceError("ATTESTATION_ARTIFACT_MISMATCH")
        if consume_nonce:
            self.used_nonces.add(evidence.nonce)
        return digest(evidence.payload())


class CredentialIssuer:
    """Short-lived, sender-bound access credentials with exact verification."""

    def __init__(
        self,
        registry: IdentityRegistry,
        attestor: WorkloadAttestor,
        audit: AuditLog,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.registry = registry
        self.attestor = attestor
        self.audit = audit
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.revoked_jtis: set[str] = set()
        self.issuance_journal: dict[str, tuple[str, str]] = {}

    def _issuable(self, identity_id: str, now: int) -> IdentityRecord:
        record = self.registry.get(identity_id)
        owner = self.registry.owners.get(record.owner_id)
        if record.state is not LifecycleState.ACTIVE:
            raise GovernanceError("IDENTITY_NOT_ACTIVE")
        if owner is None or not owner.active:
            raise GovernanceError("OWNER_INACTIVE_OR_UNKNOWN")
        if record.review_due_at <= now:
            raise GovernanceError("IDENTITY_REVIEW_OVERDUE")
        return record

    @staticmethod
    def _validate_grant(
        record: IdentityRecord,
        audience: str,
        scopes: frozenset[str],
        purpose: str,
        ttl_seconds: int,
        sender_thumbprint: str,
    ) -> None:
        if audience not in record.allowed_audiences:
            raise GovernanceError("AUDIENCE_NOT_ALLOWED")
        if not scopes or not scopes <= record.allowed_scopes:
            raise GovernanceError("SCOPE_NOT_ALLOWED")
        if purpose != record.purpose:
            raise GovernanceError("PURPOSE_MISMATCH")
        if ttl_seconds <= 0 or ttl_seconds > record.max_ttl_seconds:
            raise GovernanceError("TOKEN_TTL_OUT_OF_POLICY")
        if len(sender_thumbprint) < 16:
            raise GovernanceError("SENDER_BINDING_INVALID")

    def issue(
        self,
        identity_id: str,
        audience: str,
        scopes: frozenset[str],
        purpose: str,
        ttl_seconds: int,
        sender_thumbprint: str,
        attestation: SignedAttestation,
        now: int,
        request_id: str,
        parent_jti: str | None = None,
        delegation_depth: int = 0,
    ) -> str:
        record = self._issuable(identity_id, now)
        self._validate_grant(record, audience, scopes, purpose, ttl_seconds, sender_thumbprint)
        # Inspect before the idempotency lookup so a retry can return the prior
        # result without consuming the same attestation nonce twice. A new
        # issuance consumes the nonce immediately before signing.
        attestation_digest = self.attestor.verify(
            attestation, record, now, consume_nonce=False
        )
        request = {
            "identity_id": identity_id,
            "audience": audience,
            "scopes": sorted(scopes),
            "purpose": purpose,
            "ttl_seconds": ttl_seconds,
            "sender_thumbprint": sender_thumbprint,
            "attestation_digest": attestation_digest,
            "parent_jti": parent_jti,
            "delegation_depth": delegation_depth,
        }
        request_digest = digest(request)
        prior = self.issuance_journal.get(request_id)
        if prior is not None:
            if prior[0] != request_digest:
                raise GovernanceError("ISSUANCE_IDEMPOTENCY_CONFLICT")
            return prior[1]
        self.attestor.verify(attestation, record, now, consume_nonce=True)
        jti = sha256(f"{request_id}|{request_digest}|{now}".encode()).hexdigest()[:32]
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": identity_id,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": jti,
            "tenant_id": record.tenant_id,
            "scope": " ".join(sorted(scopes)),
            "purpose": purpose,
            "identity_kind": record.kind.value,
            "identity_version": record.version,
            "revocation_epoch": record.revocation_epoch,
            "policy_version": POLICY_VERSION,
            "attestation_digest": attestation_digest,
            "delegation_depth": delegation_depth,
            "cnf": {"jkt": sender_thumbprint},
        }
        if parent_jti is not None:
            claims["parent_jti"] = parent_jti
        token = jwt.encode(
            claims,
            self._private_key,
            algorithm="EdDSA",
            headers={"kid": "course24-ephemeral-ed25519", "typ": "at+jwt"},
        )
        self.issuance_journal[request_id] = (request_digest, token)
        self.audit.emit(
            "credential.issued", identity_id, record.tenant_id, "allow",
            "attested_short_lived_grant", now, request_id,
        )
        return token

    def _decode(self, token: str, audience: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "EdDSA" or header.get("typ") != "at+jwt":
                raise GovernanceError("TOKEN_HEADER_INVALID")
            return jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                audience=audience,
                issuer=ISSUER,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "require": [
                        "iss", "sub", "aud", "iat", "nbf", "exp", "jti",
                        "tenant_id", "scope", "purpose", "identity_version",
                        "revocation_epoch", "policy_version", "cnf",
                    ],
                },
            )
        except GovernanceError:
            raise
        except jwt.InvalidAudienceError as exc:
            raise GovernanceError("TOKEN_AUDIENCE_INVALID") from exc
        except jwt.InvalidIssuerError as exc:
            raise GovernanceError("TOKEN_ISSUER_INVALID") from exc
        except jwt.InvalidTokenError as exc:
            raise GovernanceError("TOKEN_INVALID") from exc

    def verify(
        self,
        token: str,
        audience: str,
        required_scopes: frozenset[str],
        sender_thumbprint: str,
        tenant_id: str,
        purpose: str,
        now: int,
    ) -> dict[str, Any]:
        claims = self._decode(token, audience)
        if int(claims["nbf"]) > now or int(claims["iat"]) > now + 5:
            raise GovernanceError("TOKEN_NOT_YET_VALID")
        if int(claims["exp"]) <= now:
            raise GovernanceError("TOKEN_EXPIRED")
        if int(claims["exp"]) - int(claims["iat"]) > 3600:
            raise GovernanceError("TOKEN_LIFETIME_INVALID")
        if claims["jti"] in self.revoked_jtis:
            raise GovernanceError("TOKEN_REVOKED")
        if claims.get("policy_version") != POLICY_VERSION:
            raise GovernanceError("TOKEN_POLICY_STALE")
        if claims.get("tenant_id") != tenant_id:
            raise GovernanceError("TOKEN_TENANT_MISMATCH")
        if claims.get("purpose") != purpose:
            raise GovernanceError("TOKEN_PURPOSE_MISMATCH")
        if claims.get("cnf", {}).get("jkt") != sender_thumbprint:
            raise GovernanceError("TOKEN_SENDER_MISMATCH")
        record = self._issuable(str(claims["sub"]), now)
        if int(claims["identity_version"]) != record.version:
            raise GovernanceError("TOKEN_IDENTITY_VERSION_STALE")
        if int(claims["revocation_epoch"]) != record.revocation_epoch:
            raise GovernanceError("TOKEN_REVOCATION_EPOCH_STALE")
        granted = frozenset(str(claims["scope"]).split())
        if not granted <= record.allowed_scopes or not required_scopes <= granted:
            raise GovernanceError("TOKEN_SCOPE_INSUFFICIENT")
        self.registry.mark_used(record.identity_id, now)
        self.audit.emit(
            "credential.verified", record.identity_id, record.tenant_id, "allow",
            "current_identity_and_grant", now, str(claims["jti"]),
        )
        return claims

    def exchange(
        self,
        parent_token: str,
        parent_audience: str,
        child_audience: str,
        child_scopes: frozenset[str],
        sender_thumbprint: str,
        child_sender_thumbprint: str,
        tenant_id: str,
        purpose: str,
        ttl_seconds: int,
        attestation: SignedAttestation,
        now: int,
        request_id: str,
    ) -> str:
        parent = self.verify(
            parent_token, parent_audience, frozenset(), sender_thumbprint,
            tenant_id, purpose, now,
        )
        parent_scopes = frozenset(str(parent["scope"]).split())
        if not child_scopes <= parent_scopes:
            raise GovernanceError("DELEGATION_SCOPE_EXPANSION")
        depth = int(parent.get("delegation_depth", 0)) + 1
        if depth > MAX_DELEGATION_DEPTH:
            raise GovernanceError("DELEGATION_DEPTH_EXCEEDED")
        if ttl_seconds > int(parent["exp"]) - now:
            raise GovernanceError("DELEGATION_LIFETIME_EXPANSION")
        return self.issue(
            str(parent["sub"]), child_audience, child_scopes, purpose,
            ttl_seconds, child_sender_thumbprint, attestation, now, request_id,
            parent_jti=str(parent["jti"]), delegation_depth=depth,
        )

    def revoke_token(self, jti: str, now: int, reason: str) -> None:
        if not jti or not reason.strip():
            raise GovernanceError("TOKEN_REVOCATION_INVALID")
        self.revoked_jtis.add(jti)
        self.audit.emit(
            "credential.revoked", "unknown-until-introspection", "unknown",
            "allow", reason, now, jti,
        )


@dataclass(frozen=True)
class RuntimeObservation:
    identity_id: str
    tenant_id: str
    selectors: frozenset[str]
    artifact_digest: str
    observed_at: int


@dataclass(frozen=True)
class Finding:
    code: str
    identity_id: str
    severity: str
    detail: str


def reconcile_inventory(
    registry: IdentityRegistry,
    expected_identity_ids: frozenset[str],
    observations: Iterable[RuntimeObservation],
    now: int,
    stale_after_seconds: int = 86_400,
) -> list[Finding]:
    """Compare desired inventory, governance truth, and observed runtime."""
    findings: list[Finding] = []
    observed = {item.identity_id: item for item in observations}
    for identity_id in sorted(expected_identity_ids - registry.records.keys()):
        findings.append(Finding("EXPECTED_UNREGISTERED", identity_id, "critical", "no registry record"))
    for identity_id in sorted(observed.keys() - registry.records.keys()):
        findings.append(Finding("SHADOW_IDENTITY", identity_id, "critical", "runtime identity is unmanaged"))
    for identity_id in sorted(registry.records.keys() - expected_identity_ids):
        findings.append(Finding("UNDECLARED_REGISTRY_IDENTITY", identity_id, "high", "absent from desired inventory"))
    for identity_id, record in sorted(registry.records.items()):
        owner = registry.owners.get(record.owner_id)
        observation = observed.get(identity_id)
        if owner is None or not owner.active:
            findings.append(Finding("ORPHANED_OWNER", identity_id, "critical", record.owner_id))
        if record.review_due_at <= now:
            findings.append(Finding("REVIEW_OVERDUE", identity_id, "high", str(record.review_due_at)))
        if record.shared:
            findings.append(Finding("SHARED_IDENTITY", identity_id, "critical", "unique workload identity required"))
        if record.last_used_at is None or now - record.last_used_at > stale_after_seconds:
            findings.append(Finding("STALE_OR_NEVER_USED", identity_id, "medium", "confirm need or decommission"))
        if record.state is LifecycleState.ACTIVE and observation is None:
            findings.append(Finding("ACTIVE_NOT_OBSERVED", identity_id, "medium", "verify inventory and deployment"))
        if observation is not None:
            if record.state is not LifecycleState.ACTIVE:
                findings.append(Finding("INACTIVE_STILL_RUNNING", identity_id, "critical", record.state.value))
            if observation.tenant_id != record.tenant_id:
                findings.append(Finding("RUNTIME_TENANT_DRIFT", identity_id, "critical", observation.tenant_id))
            if not record.selectors <= observation.selectors:
                findings.append(Finding("RUNTIME_SELECTOR_DRIFT", identity_id, "critical", "selectors differ"))
            if observation.artifact_digest != record.artifact_digest:
                findings.append(Finding("RUNTIME_ARTIFACT_DRIFT", identity_id, "critical", observation.artifact_digest))
    return findings


def governance_metrics(
    registry: IdentityRegistry,
    expected_identity_ids: frozenset[str],
    observations: Iterable[RuntimeObservation],
    findings: Iterable[Finding],
) -> dict[str, float | int]:
    observations = list(observations)
    findings = list(findings)
    active = [record for record in registry.records.values() if record.state is LifecycleState.ACTIVE]
    owned = [
        record for record in active
        if (owner := registry.owners.get(record.owner_id)) is not None and owner.active
    ]
    known = [item for item in observations if item.identity_id in registry.records]
    return {
        "expected_identity_count": len(expected_identity_ids),
        "inventory_coverage": len(expected_identity_ids & registry.records.keys()) / len(expected_identity_ids) if expected_identity_ids else 1.0,
        "runtime_governance_coverage": len(known) / len(observations) if observations else 1.0,
        "active_owner_coverage": len(owned) / len(active) if active else 1.0,
        "short_lived_credential_coverage": sum(r.max_ttl_seconds <= 900 for r in active) / len(active) if active else 1.0,
        "critical_findings": sum(f.severity == "critical" for f in findings),
        "open_findings": len(findings),
    }


def make_candidate(now: int = 1_000) -> IdentityRecord:
    return IdentityRecord(
        identity_id="spiffe://acme.test/mcp/server/support-prod",
        kind=IdentityKind.MCP_SERVER,
        tenant_id="acme",
        owner_id="platform-team",
        purpose="support-ticket-triage",
        environment="production",
        trust_domain="acme.test",
        selectors=frozenset({"k8s:ns:support", "k8s:sa:mcp-support", "image:sha256:approved"}),
        artifact_digest="a" * 64,
        allowed_audiences=frozenset({"https://mcp.acme.test/support", "https://tickets.acme.test"}),
        allowed_scopes=frozenset({"ticket:read", "ticket:triage"}),
        max_ttl_seconds=600,
        state=LifecycleState.CANDIDATE,
        version=1,
        revocation_epoch=0,
        created_at=now,
        review_due_at=now + 30 * 86_400,
    )


def register_demo_identity(
    registry: IdentityRegistry, candidate: IdentityRecord, now: int = 1_000
) -> IdentityRecord:
    receipt = registry.approvals.issue(
        candidate.proposal(), "engineer-7", "security-approver", now
    )
    return registry.register(candidate, receipt.receipt_id, "engineer-7", now + 1)


def make_attestation(
    attestor: WorkloadAttestor, record: IdentityRecord, now: int, nonce: str
) -> SignedAttestation:
    return attestor.issue(
        AttestationEvidence(
            record.identity_id,
            record.tenant_id,
            record.trust_domain,
            record.selectors | frozenset({"node:pool:trusted"}),
            record.artifact_digest,
            now,
            nonce,
        )
    )


def build_demo(now: int = 1_000) -> tuple[
    IdentityRegistry, WorkloadAttestor, CredentialIssuer, IdentityRecord, AuditLog
]:
    audit = AuditLog()
    owners = [
        Owner("platform-team", "platform", True, frozenset({"identity-requester"})),
        Owner("security-approver", "security", True, frozenset({"identity-approver"})),
    ]
    registry = IdentityRegistry(owners, audit)
    record = register_demo_identity(registry, make_candidate(now), now)
    attestor = WorkloadAttestor()
    issuer = CredentialIssuer(registry, attestor, audit)
    return registry, attestor, issuer, record, audit


def main() -> None:
    now = 1_000
    registry, attestor, issuer, record, audit = build_demo(now)
    sender = "sha256:gateway-proof-key-2026"
    token = issuer.issue(
        record.identity_id,
        "https://mcp.acme.test/support",
        frozenset({"ticket:read", "ticket:triage"}),
        record.purpose,
        300,
        sender,
        make_attestation(attestor, record, now + 2, "issue-parent"),
        now + 2,
        "issue-support-001",
    )
    claims = issuer.verify(
        token, "https://mcp.acme.test/support", frozenset({"ticket:read"}),
        sender, "acme", record.purpose, now + 3,
    )
    child = issuer.exchange(
        token,
        "https://mcp.acme.test/support",
        "https://tickets.acme.test",
        frozenset({"ticket:read"}),
        sender,
        "sha256:ticket-api-proof-key",
        "acme",
        record.purpose,
        120,
        make_attestation(attestor, registry.get(record.identity_id), now + 4, "issue-child"),
        now + 4,
        "exchange-ticket-001",
    )
    child_claims = issuer.verify(
        child, "https://tickets.acme.test", frozenset({"ticket:read"}),
        "sha256:ticket-api-proof-key", "acme", record.purpose, now + 5,
    )
    observation = RuntimeObservation(
        record.identity_id, "acme", record.selectors, record.artifact_digest, now + 5
    )
    findings = reconcile_inventory(
        registry, frozenset({record.identity_id}), [observation], now + 5
    )
    report = {
        "parent_jti": claims["jti"],
        "child_parent_jti": child_claims["parent_jti"],
        "child_scopes": child_claims["scope"].split(),
        "metrics": governance_metrics(
            registry, frozenset({record.identity_id}), [observation], findings
        ),
        "audit_events": len(audit.events),
    }
    assert report["child_parent_jti"] == report["parent_jti"]
    assert report["child_scopes"] == ["ticket:read"]
    assert report["metrics"]["inventory_coverage"] == 1.0
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
