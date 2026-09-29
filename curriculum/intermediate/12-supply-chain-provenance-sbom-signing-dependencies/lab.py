"""Course 12: an evidence-bound software-supply-chain release gate.

The lab uses real Ed25519 verification from ``cryptography`` and strict
Pydantic contracts while keeping every fixture local and credential-free. It
models the verification semantics used around Sigstore, in-toto/SLSA,
CycloneDX, and vulnerability scanners; it does not reimplement those projects.
"""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator


UTC = timezone.utc
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
HEX_SHA256_PATTERN = r"^[0-9a-f]{64}$"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"


def utc(value: str) -> datetime:
    """Parse one ISO timestamp and require an explicit UTC offset."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must carry an explicit UTC offset")
    return parsed.astimezone(UTC)


def canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    """Return stable bytes for signatures and evidence digests."""

    if isinstance(value, BaseModel):
        data = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    else:
        data = value
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(payload: bytes) -> str:
    return f"sha256:{sha256(payload).hexdigest()}"


def document_digest(document: BaseModel) -> str:
    return digest_bytes(canonical_json(document))


def require_aware(*values: datetime) -> None:
    if any(value.tzinfo is None or value.utcoffset() is None for value in values):
        raise ValueError("security timestamps must be timezone-aware")


class SupplyChainDenied(PermissionError):
    """A fail-closed release or promotion decision with a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ArtifactRef(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    digest: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(gt=0, le=50_000_000)
    media_type: str = Field(min_length=1, max_length=120)


class DigestSet(StrictModel):
    sha256: str = Field(pattern=HEX_SHA256_PATTERN)


class ResourceDescriptor(StrictModel):
    uri: str = Field(min_length=1, max_length=500)
    digest: DigestSet


class ProvenanceSubject(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    digest: DigestSet


class BuildDefinition(StrictModel):
    build_type: str = Field(alias="buildType", min_length=1, max_length=300)
    external_parameters: dict[str, str] = Field(alias="externalParameters")
    internal_parameters: dict[str, str] = Field(alias="internalParameters")
    resolved_dependencies: tuple[ResourceDescriptor, ...] = Field(
        alias="resolvedDependencies", min_length=1
    )


class Builder(StrictModel):
    id: str = Field(min_length=1, max_length=300)


class BuildMetadata(StrictModel):
    invocation_id: str = Field(alias="invocationId", min_length=1, max_length=180)
    started_on: datetime = Field(alias="startedOn")
    finished_on: datetime = Field(alias="finishedOn")

    @model_validator(mode="after")
    def ordered_utc_times(self) -> "BuildMetadata":
        require_aware(self.started_on, self.finished_on)
        if self.started_on > self.finished_on:
            raise ValueError("build finishedOn must not precede startedOn")
        return self


class RunDetails(StrictModel):
    builder: Builder
    metadata: BuildMetadata


class BuildPredicate(StrictModel):
    build_definition: BuildDefinition = Field(alias="buildDefinition")
    run_details: RunDetails = Field(alias="runDetails")


class SlsaProvenance(StrictModel):
    statement_type: Literal[IN_TOTO_STATEMENT_V1] = Field(alias="_type")
    subject: tuple[ProvenanceSubject, ...] = Field(min_length=1)
    predicate_type: Literal[SLSA_PROVENANCE_V1] = Field(alias="predicateType")
    predicate: BuildPredicate


class ComponentHash(StrictModel):
    alg: Literal["SHA-256"]
    content: str = Field(pattern=HEX_SHA256_PATTERN)


class LicenseChoice(StrictModel):
    id: str = Field(min_length=1, max_length=100)


class CycloneDxComponent(StrictModel):
    component_type: Literal["application", "library", "container"] = Field(alias="type")
    bom_ref: str = Field(alias="bom-ref", min_length=1, max_length=300)
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    purl: str = Field(pattern=r"^pkg:[A-Za-z0-9.+_-]+/.+@.+$", max_length=500)
    hashes: tuple[ComponentHash, ...] = ()
    licenses: tuple[LicenseChoice, ...] = Field(min_length=1)


class BomTool(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=100)


class BomMetadata(StrictModel):
    timestamp: datetime
    tools: tuple[BomTool, ...] = Field(min_length=1)
    component: CycloneDxComponent

    @model_validator(mode="after")
    def aware_timestamp(self) -> "BomMetadata":
        require_aware(self.timestamp)
        return self


class DependencyEdge(StrictModel):
    ref: str = Field(min_length=1, max_length=300)
    depends_on: tuple[str, ...] = Field(alias="dependsOn")


class Composition(StrictModel):
    aggregate: Literal["complete", "incomplete", "unknown"]
    assemblies: tuple[str, ...] = Field(min_length=1)


class CycloneDxBom(StrictModel):
    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    spec_version: Literal["1.7"] = Field(alias="specVersion")
    serial_number: str = Field(alias="serialNumber", pattern=r"^urn:uuid:[0-9a-f-]{36}$")
    version: int = Field(ge=1)
    metadata: BomMetadata
    components: tuple[CycloneDxComponent, ...] = Field(min_length=1)
    dependencies: tuple[DependencyEdge, ...] = Field(min_length=1)
    compositions: tuple[Composition, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_references(self) -> "CycloneDxBom":
        refs = [self.metadata.component.bom_ref, *(c.bom_ref for c in self.components)]
        if len(refs) != len(set(refs)):
            raise ValueError("SBOM bom-ref values must be unique")
        purls = [c.purl for c in self.components]
        if len(purls) != len(set(purls)):
            raise ValueError("SBOM component PURLs must be unique")
        return self


class ScannerIdentity(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=100)


class AdvisoryDatabase(StrictModel):
    uri: str = Field(min_length=1, max_length=300)
    revision: str = Field(min_length=1, max_length=160)
    updated_at: datetime


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class VulnerabilityFinding(StrictModel):
    vulnerability_id: str = Field(min_length=1, max_length=100)
    purl: str = Field(pattern=r"^pkg:[A-Za-z0-9.+_-]+/.+@.+$", max_length=500)
    severity: Severity
    fixed_version: str | None = Field(default=None, max_length=100)
    exploitability: Literal["not_assessed", "not_affected", "affected"]


class VulnerabilityReport(StrictModel):
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    sbom_digest: str = Field(pattern=SHA256_PATTERN)
    scanner: ScannerIdentity
    database: AdvisoryDatabase
    scanned_at: datetime
    findings: tuple[VulnerabilityFinding, ...]

    @model_validator(mode="after")
    def aware_timestamps(self) -> "VulnerabilityReport":
        require_aware(self.scanned_at, self.database.updated_at)
        return self


class SignatureBundle(StrictModel):
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    signer_identity: str = Field(min_length=1, max_length=300)
    oidc_issuer: str = Field(min_length=1, max_length=300)
    signature: str = Field(min_length=40, max_length=200)
    signed_at: datetime
    integrated_at: datetime
    transparency_log_id: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def aware_timestamps(self) -> "SignatureBundle":
        require_aware(self.signed_at, self.integrated_at)
        return self


@dataclass(frozen=True)
class SignedDocument:
    document: BaseModel
    signature: SignatureBundle


@dataclass(frozen=True)
class ReleaseEvidence:
    artifact_signature: SignatureBundle
    provenance: SignedDocument
    sbom: SignedDocument
    vulnerability_report: SignedDocument


class ReleaseIntent(StrictModel):
    """Trusted application state created by the release orchestrator."""

    release_id: str = Field(min_length=1, max_length=120)
    artifact: ArtifactRef
    environment: Literal["staging", "production"]
    target_repository: str = Field(min_length=1, max_length=240)
    source_uri: str = Field(min_length=1, max_length=500)
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    lockfile_digest: str = Field(pattern=SHA256_PATTERN)
    base_image_digest: str = Field(pattern=SHA256_PATTERN)
    expected_components: frozenset[str] = Field(min_length=1)


class ExceptionRecord(StrictModel):
    exception_id: str = Field(min_length=1, max_length=120)
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    vulnerability_id: str = Field(min_length=1, max_length=100)
    purl: str = Field(min_length=1, max_length=500)
    environment: Literal["staging", "production"]
    owner: str = Field(min_length=1, max_length=160)
    ticket: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=20, max_length=1000)
    compensating_controls: tuple[str, ...] = Field(min_length=1)
    approved_by: str = Field(min_length=1, max_length=160)
    policy_version: str = Field(min_length=1, max_length=80)
    issued_at: datetime
    expires_at: datetime
    state: Literal["approved", "revoked"]

    @model_validator(mode="after")
    def valid_window(self) -> "ExceptionRecord":
        require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("exception expiry must follow issuance")
        return self


class ReleasePolicy(StrictModel):
    version: str = Field(min_length=1, max_length=80)
    trusted_builders: frozenset[str] = Field(min_length=1)
    allowed_build_types: frozenset[str] = Field(min_length=1)
    trusted_artifact_signers: frozenset[str] = Field(min_length=1)
    trusted_provenance_signers: frozenset[str] = Field(min_length=1)
    trusted_sbom_signers: frozenset[str] = Field(min_length=1)
    trusted_scanner_signers: frozenset[str] = Field(min_length=1)
    allowed_scanners: frozenset[str] = Field(min_length=1)
    denied_licenses: frozenset[str]
    max_provenance_age: timedelta
    max_scan_age: timedelta
    max_database_age: timedelta
    authorization_ttl: timedelta


class AuditEvent(StrictModel):
    event: str
    release_id: str
    artifact_digest: str
    decision: Literal["allow", "deny", "promoted"]
    reason_code: str
    policy_version: str
    evidence_digests: tuple[str, ...] = ()


class PromotionAuthorization(StrictModel):
    authorization_id: str = Field(min_length=1, max_length=160)
    release_id: str
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    environment: Literal["staging", "production"]
    target_repository: str
    evidence_digest: str = Field(pattern=SHA256_PATTERN)
    policy_version: str
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid_window(self) -> "PromotionAuthorization":
        require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must follow issuance")
        return self


@dataclass
class _StoredAuthorization:
    record: PromotionAuthorization
    state: Literal["issued", "consumed"] = "issued"


class TrustStore:
    """Preconfigured public keys and revocation state; evidence cannot add roots."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}
        self._revoked: set[tuple[str, str]] = set()

    def add(self, identity: str, issuer: str, key: Ed25519PublicKey) -> None:
        self._keys[(identity, issuer)] = key

    def revoke(self, identity: str, issuer: str) -> None:
        self._revoked.add((identity, issuer))

    def verify(
        self,
        payload: bytes,
        bundle: SignatureBundle,
        allowed_identities: frozenset[str],
        now: datetime,
    ) -> None:
        key_id = (bundle.signer_identity, bundle.oidc_issuer)
        if bundle.signer_identity not in allowed_identities:
            raise SupplyChainDenied("SIGNER_NOT_ALLOWED", "evidence signer is not allowed")
        if key_id in self._revoked:
            raise SupplyChainDenied("SIGNER_REVOKED", "evidence signer is revoked")
        public_key = self._keys.get(key_id)
        if public_key is None:
            raise SupplyChainDenied("TRUST_ROOT_MISSING", "no configured trust root for signer")
        if digest_bytes(payload) != bundle.payload_digest:
            raise SupplyChainDenied("PAYLOAD_DIGEST_MISMATCH", "signed payload digest differs")
        if bundle.integrated_at < bundle.signed_at or bundle.integrated_at > now:
            raise SupplyChainDenied("TRANSPARENCY_TIME_INVALID", "transparency time is invalid")
        try:
            signature = base64.b64decode(bundle.signature, validate=True)
            public_key.verify(signature, payload)
        except (ValueError, InvalidSignature) as exc:
            raise SupplyChainDenied("SIGNATURE_INVALID", "signature verification failed") from exc


class ExceptionStore:
    """Trusted exception registry; a scanner or artifact cannot mint exceptions."""

    def __init__(self, records: tuple[ExceptionRecord, ...] = ()) -> None:
        self._records = {record.exception_id: record for record in records}

    def add(self, record: ExceptionRecord) -> None:
        self._records[record.exception_id] = record

    def matching(
        self,
        finding: VulnerabilityFinding,
        intent: ReleaseIntent,
        policy_version: str,
        now: datetime,
    ) -> ExceptionRecord | None:
        for record in self._records.values():
            if (
                record.state == "approved"
                and record.artifact_digest == intent.artifact.digest
                and record.vulnerability_id == finding.vulnerability_id
                and record.purl == finding.purl
                and record.environment == intent.environment
                and record.policy_version == policy_version
                and record.issued_at <= now < record.expires_at
            ):
                return record
        return None


class AuthorizationStore:
    """Server-side state makes release authorizations non-forgeable and one-use."""

    def __init__(self) -> None:
        self._records: dict[str, _StoredAuthorization] = {}
        self._lock = threading.Lock()

    def issue(self, record: PromotionAuthorization) -> PromotionAuthorization:
        with self._lock:
            if record.authorization_id in self._records:
                raise RuntimeError("authorization ID collision")
            self._records[record.authorization_id] = _StoredAuthorization(record)
        return record

    def consume(self, presented: PromotionAuthorization, now: datetime) -> None:
        with self._lock:
            stored = self._records.get(presented.authorization_id)
            if stored is None or stored.record != presented:
                raise SupplyChainDenied(
                    "AUTHORIZATION_NOT_FOUND", "promotion authorization is not trusted"
                )
            if stored.state != "issued":
                raise SupplyChainDenied("AUTHORIZATION_REPLAYED", "authorization was already used")
            if now >= stored.record.expires_at:
                raise SupplyChainDenied("AUTHORIZATION_EXPIRED", "authorization has expired")
            stored.state = "consumed"


class ReleaseGate:
    def __init__(
        self,
        policy: ReleasePolicy,
        trust: TrustStore,
        exceptions: ExceptionStore,
        authorizations: AuthorizationStore,
    ) -> None:
        self.policy = policy
        self.trust = trust
        self.exceptions = exceptions
        self.authorizations = authorizations
        self.audit: list[AuditEvent] = []

    def _deny(self, intent: ReleaseIntent, code: str, message: str) -> None:
        self.audit.append(
            AuditEvent(
                event="release.verify",
                release_id=intent.release_id,
                artifact_digest=intent.artifact.digest,
                decision="deny",
                reason_code=code,
                policy_version=self.policy.version,
            )
        )
        raise SupplyChainDenied(code, message)

    def _verify_signed_document(
        self,
        signed: SignedDocument,
        allowed: frozenset[str],
        now: datetime,
    ) -> None:
        self.trust.verify(canonical_json(signed.document), signed.signature, allowed, now)

    def verify_and_authorize(
        self,
        intent: ReleaseIntent,
        artifact_bytes: bytes,
        evidence: ReleaseEvidence,
        now: datetime,
    ) -> PromotionAuthorization:
        """Verify the complete evidence set, then mint one exact promotion grant."""

        try:
            computed_digest = digest_bytes(artifact_bytes)
            if computed_digest != intent.artifact.digest or len(artifact_bytes) != intent.artifact.size:
                self._deny(intent, "ARTIFACT_MISMATCH", "artifact bytes differ from release intent")

            artifact_claim = canonical_json(
                {"name": intent.artifact.name, "digest": computed_digest}
            )
            self.trust.verify(
                artifact_claim,
                evidence.artifact_signature,
                self.policy.trusted_artifact_signers,
                now,
            )

            if not isinstance(evidence.provenance.document, SlsaProvenance):
                self._deny(intent, "PROVENANCE_SCHEMA_INVALID", "unexpected provenance type")
            self._verify_signed_document(
                evidence.provenance, self.policy.trusted_provenance_signers, now
            )
            self._verify_provenance(intent, evidence.provenance.document, now)

            if not isinstance(evidence.sbom.document, CycloneDxBom):
                self._deny(intent, "SBOM_SCHEMA_INVALID", "unexpected SBOM type")
            self._verify_signed_document(evidence.sbom, self.policy.trusted_sbom_signers, now)
            self._verify_sbom(intent, evidence.sbom.document)

            if not isinstance(evidence.vulnerability_report.document, VulnerabilityReport):
                self._deny(intent, "SCAN_SCHEMA_INVALID", "unexpected scan report type")
            self._verify_signed_document(
                evidence.vulnerability_report,
                self.policy.trusted_scanner_signers,
                now,
            )
            self._verify_vulnerabilities(
                intent,
                evidence.sbom.document,
                evidence.vulnerability_report.document,
                document_digest(evidence.sbom.document),
                now,
            )
        except SupplyChainDenied as denied:
            if not self.audit or self.audit[-1].reason_code != denied.code:
                self.audit.append(
                    AuditEvent(
                        event="release.verify",
                        release_id=intent.release_id,
                        artifact_digest=intent.artifact.digest,
                        decision="deny",
                        reason_code=denied.code,
                        policy_version=self.policy.version,
                    )
                )
            raise

        evidence_digests = (
            evidence.artifact_signature.payload_digest,
            document_digest(evidence.provenance.document),
            document_digest(evidence.sbom.document),
            document_digest(evidence.vulnerability_report.document),
        )
        evidence_digest = digest_bytes(canonical_json({"digests": evidence_digests}))
        authorization = PromotionAuthorization(
            authorization_id=f"auth-{intent.release_id}-{intent.artifact.digest[7:19]}",
            release_id=intent.release_id,
            artifact_digest=intent.artifact.digest,
            environment=intent.environment,
            target_repository=intent.target_repository,
            evidence_digest=evidence_digest,
            policy_version=self.policy.version,
            issued_at=now,
            expires_at=now + self.policy.authorization_ttl,
        )
        self.authorizations.issue(authorization)
        self.audit.append(
            AuditEvent(
                event="release.verify",
                release_id=intent.release_id,
                artifact_digest=intent.artifact.digest,
                decision="allow",
                reason_code="EVIDENCE_ACCEPTED",
                policy_version=self.policy.version,
                evidence_digests=evidence_digests,
            )
        )
        return authorization

    def _verify_provenance(
        self, intent: ReleaseIntent, provenance: SlsaProvenance, now: datetime
    ) -> None:
        subjects = {(item.name, f"sha256:{item.digest.sha256}") for item in provenance.subject}
        if (intent.artifact.name, intent.artifact.digest) not in subjects:
            self._deny(intent, "PROVENANCE_SUBJECT_MISMATCH", "provenance does not bind artifact")
        predicate = provenance.predicate
        if predicate.run_details.builder.id not in self.policy.trusted_builders:
            self._deny(intent, "BUILDER_NOT_TRUSTED", "provenance builder is not trusted")
        definition = predicate.build_definition
        if definition.build_type not in self.policy.allowed_build_types:
            self._deny(intent, "BUILD_TYPE_NOT_ALLOWED", "build type is not allowed")
        expected_parameters = {
            "source": intent.source_uri,
            "revision": intent.source_revision,
        }
        if definition.external_parameters.get("source") != intent.source_uri:
            self._deny(intent, "SOURCE_URI_MISMATCH", "provenance source URI differs")
        if definition.external_parameters.get("revision") != intent.source_revision:
            self._deny(intent, "SOURCE_REVISION_MISMATCH", "source revision differs")
        if definition.external_parameters != expected_parameters:
            self._deny(
                intent,
                "BUILD_PARAMETERS_MISMATCH",
                "unexpected external build parameters are present",
            )
        materials = {
            descriptor.uri: f"sha256:{descriptor.digest.sha256}"
            for descriptor in definition.resolved_dependencies
        }
        required = {
            f"{intent.source_uri}#lockfile": intent.lockfile_digest,
            "oci://registry.example/base/python": intent.base_image_digest,
        }
        if materials != required:
            self._deny(intent, "BUILD_MATERIAL_MISMATCH", "resolved build materials differ")
        finished = predicate.run_details.metadata.finished_on.astimezone(UTC)
        if finished > now or now - finished > self.policy.max_provenance_age:
            self._deny(intent, "PROVENANCE_STALE", "provenance is outside freshness policy")

    def _verify_sbom(self, intent: ReleaseIntent, sbom: CycloneDxBom) -> None:
        root = sbom.metadata.component
        root_hashes = {item.alg: f"sha256:{item.content}" for item in root.hashes}
        if root.name != intent.artifact.name.removesuffix(".tar") or root_hashes.get(
            "SHA-256"
        ) != intent.artifact.digest:
            self._deny(intent, "SBOM_SUBJECT_MISMATCH", "SBOM does not bind the artifact")
        if not any(
            composition.aggregate == "complete"
            and root.bom_ref in composition.assemblies
            for composition in sbom.compositions
        ):
            self._deny(intent, "SBOM_INCOMPLETE", "SBOM does not claim complete assembly")

        all_refs = {root.bom_ref, *(component.bom_ref for component in sbom.components)}
        edges = {edge.ref: set(edge.depends_on) for edge in sbom.dependencies}
        if len(edges) != len(sbom.dependencies) or root.bom_ref not in edges or any(
            ref not in all_refs or any(child not in all_refs for child in children)
            for ref, children in edges.items()
        ):
            self._deny(intent, "SBOM_GRAPH_INVALID", "SBOM dependency graph is invalid")
        reachable: set[str] = set()
        pending = list(edges[root.bom_ref])
        while pending:
            ref = pending.pop()
            if ref in reachable:
                continue
            reachable.add(ref)
            pending.extend(edges.get(ref, ()))
        component_refs = {component.bom_ref for component in sbom.components}
        if reachable != component_refs:
            self._deny(intent, "SBOM_GRAPH_INCOMPLETE", "SBOM omits dependency relationships")

        observed = frozenset(component.purl for component in sbom.components)
        if observed != intent.expected_components:
            self._deny(intent, "SBOM_INVENTORY_MISMATCH", "SBOM differs from locked inventory")
        for component in (root, *sbom.components):
            licenses = {choice.id for choice in component.licenses}
            if not licenses or "NOASSERTION" in licenses or licenses & self.policy.denied_licenses:
                self._deny(intent, "LICENSE_POLICY_DENIED", "component license violates policy")

    def _verify_vulnerabilities(
        self,
        intent: ReleaseIntent,
        sbom: CycloneDxBom,
        report: VulnerabilityReport,
        expected_sbom_digest: str,
        now: datetime,
    ) -> None:
        if report.artifact_digest != intent.artifact.digest:
            self._deny(intent, "SCAN_ARTIFACT_MISMATCH", "scan report names another artifact")
        if report.sbom_digest != expected_sbom_digest:
            self._deny(intent, "SCAN_SBOM_MISMATCH", "scan report names another SBOM")
        scanner_id = f"{report.scanner.name}@{report.scanner.version}"
        if scanner_id not in self.policy.allowed_scanners:
            self._deny(intent, "SCANNER_NOT_ALLOWED", "scanner version is not allowed")
        scanned_at = report.scanned_at.astimezone(UTC)
        db_updated = report.database.updated_at.astimezone(UTC)
        if scanned_at > now or now - scanned_at > self.policy.max_scan_age:
            self._deny(intent, "SCAN_STALE", "vulnerability scan is stale")
        if db_updated > scanned_at or scanned_at - db_updated > self.policy.max_database_age:
            self._deny(intent, "ADVISORY_DB_STALE", "advisory database is stale")

        component_purls = {component.purl for component in sbom.components}
        for finding in report.findings:
            if finding.purl not in component_purls:
                self._deny(intent, "FINDING_NOT_IN_SBOM", "finding is not bound to an SBOM component")
            if finding.exploitability == "not_affected":
                continue
            if finding.severity == "CRITICAL":
                self._deny(intent, "CRITICAL_VULNERABILITY", "critical vulnerability blocks release")
            if finding.severity == "HIGH" and self.exceptions.matching(
                finding, intent, self.policy.version, now
            ) is None:
                self._deny(intent, "HIGH_VULNERABILITY", "high vulnerability lacks valid exception")


class PromotionService:
    """Consume one exact authorization and publish immutable bytes by digest."""

    def __init__(
        self,
        policy: ReleasePolicy,
        authorizations: AuthorizationStore,
        environment: Literal["staging", "production"],
    ) -> None:
        self.policy = policy
        self.authorizations = authorizations
        self.environment = environment
        self.blobs: dict[tuple[str, str], bytes] = {}
        self.tags: dict[tuple[str, str], str] = {}
        self.audit: list[AuditEvent] = []
        self._lock = threading.Lock()

    def promote(
        self,
        authorization: PromotionAuthorization,
        artifact_bytes: bytes,
        repository: str,
        tag: str,
        now: datetime,
    ) -> str:
        computed = digest_bytes(artifact_bytes)
        if authorization.policy_version != self.policy.version:
            raise SupplyChainDenied("POLICY_CHANGED", "authorization uses another policy")
        if authorization.environment != self.environment:
            raise SupplyChainDenied("ENVIRONMENT_CHANGED", "promotion environment differs")
        if authorization.target_repository != repository:
            raise SupplyChainDenied("TARGET_CHANGED", "promotion target differs")
        if authorization.artifact_digest != computed:
            raise SupplyChainDenied("ARTIFACT_CHANGED", "promotion bytes differ")
        with self._lock:
            self.authorizations.consume(authorization, now)
            self.blobs[(repository, computed)] = artifact_bytes
            self.tags[(repository, tag)] = computed
            self.audit.append(
                AuditEvent(
                    event="registry.promote",
                    release_id=authorization.release_id,
                    artifact_digest=computed,
                    decision="promoted",
                    reason_code="PROMOTION_COMMITTED",
                    policy_version=self.policy.version,
                    evidence_digests=(authorization.evidence_digest,),
                )
            )
        return f"{repository}@{computed}"


@dataclass(frozen=True)
class DemoEnvironment:
    now: datetime
    artifact_bytes: bytes
    intent: ReleaseIntent
    evidence: ReleaseEvidence
    policy: ReleasePolicy
    trust: TrustStore
    exceptions: ExceptionStore
    authorizations: AuthorizationStore
    gate: ReleaseGate
    promotion: PromotionService
    signing_keys: dict[str, Ed25519PrivateKey]


ISSUER = "https://token.actions.example"
ARTIFACT_SIGNER = "https://github.com/acme/support-mcp/.github/workflows/release.yml@refs/heads/main"
PROVENANCE_SIGNER = "https://github.com/acme/build-platform/.github/workflows/build.yml@refs/heads/main"
SBOM_SIGNER = "https://github.com/acme/build-platform/.github/workflows/sbom.yml@refs/heads/main"
SCANNER_SIGNER = "https://github.com/acme/security/.github/workflows/osv.yml@refs/heads/main"
BUILDER_ID = "https://github.com/acme/build-platform/hosted-runner@v4"
BUILD_TYPE = "https://github.com/acme/build-platform/mcp-container@v2"
SOURCE_URI = "https://github.com/acme/support-mcp"
SOURCE_REVISION = "a" * 40
LOCKFILE_DIGEST = f"sha256:{'b' * 64}"
BASE_IMAGE_DIGEST = f"sha256:{'c' * 64}"
ROOT_REF = "pkg:oci/support-mcp@1.4.2"
COMPONENTS = frozenset(
    {
        "pkg:pypi/mcp@2.2.0",
        "pkg:pypi/pydantic@2.12.5",
        "pkg:pypi/httpx@0.28.1",
    }
)


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def sign_payload(
    payload: bytes,
    identity: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
) -> SignatureBundle:
    return SignatureBundle(
        payload_digest=digest_bytes(payload),
        signer_identity=identity,
        oidc_issuer=ISSUER,
        signature=base64.b64encode(private_key.sign(payload)).decode(),
        signed_at=now - timedelta(minutes=4),
        integrated_at=now - timedelta(minutes=3),
        transparency_log_id=f"rekor-demo-{sha256(identity.encode()).hexdigest()[:16]}",
    )


def sign_document(
    document: BaseModel,
    identity: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
) -> SignedDocument:
    return SignedDocument(document, sign_payload(canonical_json(document), identity, private_key, now))


def _component(name: str, version: str, license_id: str = "Apache-2.0") -> CycloneDxComponent:
    purl = f"pkg:pypi/{name}@{version}"
    return CycloneDxComponent(
        type="library",
        **{"bom-ref": purl},
        name=name,
        version=version,
        purl=purl,
        licenses=(LicenseChoice(id=license_id),),
    )


def build_demo_environment(
    *,
    findings: tuple[VulnerabilityFinding, ...] = (),
    builder: str = BUILDER_ID,
    scan_age: timedelta = timedelta(minutes=10),
    database_age_at_scan: timedelta = timedelta(hours=2),
) -> DemoEnvironment:
    """Create a coherent release bundle; callers may replace signed documents."""

    now = utc("2026-09-27T18:00:00Z")
    artifact_bytes = b"support-mcp-server:v1.4.2\nlocked-runtime\n"
    artifact_digest = digest_bytes(artifact_bytes)
    artifact = ArtifactRef(
        name="support-mcp-server.tar",
        digest=artifact_digest,
        size=len(artifact_bytes),
        media_type="application/vnd.oci.image.layer.v1.tar",
    )
    intent = ReleaseIntent(
        release_id="rel-2026-09-27-001",
        artifact=artifact,
        environment="production",
        target_repository="registry.example/acme/support-mcp",
        source_uri=SOURCE_URI,
        source_revision=SOURCE_REVISION,
        lockfile_digest=LOCKFILE_DIGEST,
        base_image_digest=BASE_IMAGE_DIGEST,
        expected_components=COMPONENTS,
    )
    keys = {
        ARTIFACT_SIGNER: _key("artifact"),
        PROVENANCE_SIGNER: _key("provenance"),
        SBOM_SIGNER: _key("sbom"),
        SCANNER_SIGNER: _key("scanner"),
    }
    trust = TrustStore()
    for identity, private_key in keys.items():
        trust.add(identity, ISSUER, private_key.public_key())

    policy = ReleasePolicy(
        version="supply-chain-policy/2026-09-01",
        trusted_builders=frozenset({BUILDER_ID}),
        allowed_build_types=frozenset({BUILD_TYPE}),
        trusted_artifact_signers=frozenset({ARTIFACT_SIGNER}),
        trusted_provenance_signers=frozenset({PROVENANCE_SIGNER}),
        trusted_sbom_signers=frozenset({SBOM_SIGNER}),
        trusted_scanner_signers=frozenset({SCANNER_SIGNER}),
        allowed_scanners=frozenset({"osv-scanner@2.1.0"}),
        denied_licenses=frozenset({"GPL-3.0-only", "AGPL-3.0-only"}),
        max_provenance_age=timedelta(days=7),
        max_scan_age=timedelta(hours=24),
        max_database_age=timedelta(hours=12),
        authorization_ttl=timedelta(minutes=10),
    )

    provenance = SlsaProvenance(
        _type=IN_TOTO_STATEMENT_V1,
        subject=(
            ProvenanceSubject(
                name=artifact.name,
                digest=DigestSet(sha256=artifact_digest.removeprefix("sha256:")),
            ),
        ),
        predicateType=SLSA_PROVENANCE_V1,
        predicate=BuildPredicate(
            buildDefinition=BuildDefinition(
                buildType=BUILD_TYPE,
                externalParameters={"source": SOURCE_URI, "revision": SOURCE_REVISION},
                internalParameters={"runner_pool": "isolated-linux"},
                resolvedDependencies=(
                    ResourceDescriptor(
                        uri=f"{SOURCE_URI}#lockfile",
                        digest=DigestSet(sha256=LOCKFILE_DIGEST.removeprefix("sha256:")),
                    ),
                    ResourceDescriptor(
                        uri="oci://registry.example/base/python",
                        digest=DigestSet(sha256=BASE_IMAGE_DIGEST.removeprefix("sha256:")),
                    ),
                ),
            ),
            runDetails=RunDetails(
                builder=Builder(id=builder),
                metadata=BuildMetadata(
                    invocationId="build-7842",
                    startedOn=now - timedelta(hours=1, minutes=4),
                    finishedOn=now - timedelta(hours=1),
                ),
            ),
        ),
    )
    root = CycloneDxComponent(
        type="application",
        **{"bom-ref": ROOT_REF},
        name="support-mcp-server",
        version="1.4.2",
        purl=ROOT_REF,
        hashes=(ComponentHash(alg="SHA-256", content=artifact_digest.removeprefix("sha256:")),),
        licenses=(LicenseChoice(id="Apache-2.0"),),
    )
    sbom = CycloneDxBom(
        bomFormat="CycloneDX",
        specVersion="1.7",
        serialNumber="urn:uuid:11111111-2222-4333-8444-555555555555",
        version=1,
        metadata=BomMetadata(
            timestamp=now - timedelta(minutes=50),
            tools=(BomTool(name="syft", version="1.42.3"),),
            component=root,
        ),
        components=(
            _component("mcp", "2.2.0"),
            _component("pydantic", "2.12.5", "MIT"),
            _component("httpx", "0.28.1", "BSD-3-Clause"),
        ),
        dependencies=(
            DependencyEdge(ref=ROOT_REF, dependsOn=tuple(sorted(COMPONENTS))),
            *(DependencyEdge(ref=purl, dependsOn=()) for purl in sorted(COMPONENTS)),
        ),
        compositions=(Composition(aggregate="complete", assemblies=(ROOT_REF,)),),
    )
    scan_time = now - scan_age
    report = VulnerabilityReport(
        artifact_digest=artifact_digest,
        sbom_digest=document_digest(sbom),
        scanner=ScannerIdentity(name="osv-scanner", version="2.1.0"),
        database=AdvisoryDatabase(
            uri="https://osv.dev",
            revision="osv-2026-09-27T15:00Z",
            updated_at=scan_time - database_age_at_scan,
        ),
        scanned_at=scan_time,
        findings=findings,
    )
    evidence = ReleaseEvidence(
        artifact_signature=sign_payload(
            canonical_json({"name": artifact.name, "digest": artifact.digest}),
            ARTIFACT_SIGNER,
            keys[ARTIFACT_SIGNER],
            now,
        ),
        provenance=sign_document(provenance, PROVENANCE_SIGNER, keys[PROVENANCE_SIGNER], now),
        sbom=sign_document(sbom, SBOM_SIGNER, keys[SBOM_SIGNER], now),
        vulnerability_report=sign_document(
            report, SCANNER_SIGNER, keys[SCANNER_SIGNER], now
        ),
    )
    exceptions = ExceptionStore()
    authorizations = AuthorizationStore()
    gate = ReleaseGate(policy, trust, exceptions, authorizations)
    promotion = PromotionService(policy, authorizations, intent.environment)
    return DemoEnvironment(
        now,
        artifact_bytes,
        intent,
        evidence,
        policy,
        trust,
        exceptions,
        authorizations,
        gate,
        promotion,
        keys,
    )


def replace_signed_document(
    env: DemoEnvironment,
    role: Literal["provenance", "sbom", "vulnerability_report"],
    document: BaseModel,
) -> ReleaseEvidence:
    """Resign a changed document as its legitimate producer for negative tests."""

    identities = {
        "provenance": PROVENANCE_SIGNER,
        "sbom": SBOM_SIGNER,
        "vulnerability_report": SCANNER_SIGNER,
    }
    identity = identities[role]
    signed = sign_document(document, identity, env.signing_keys[identity], env.now)
    values = {
        "artifact_signature": env.evidence.artifact_signature,
        "provenance": env.evidence.provenance,
        "sbom": env.evidence.sbom,
        "vulnerability_report": env.evidence.vulnerability_report,
    }
    values[role] = signed
    return ReleaseEvidence(**values)


def run_demo() -> dict[str, str]:
    env = build_demo_environment()
    authorization = env.gate.verify_and_authorize(
        env.intent, env.artifact_bytes, env.evidence, env.now
    )
    immutable_ref = env.promotion.promote(
        authorization,
        env.artifact_bytes,
        env.intent.target_repository,
        "v1.4.2",
        env.now + timedelta(minutes=1),
    )

    outcomes = {"safe_release": immutable_ref}
    try:
        env.promotion.promote(
            authorization,
            env.artifact_bytes,
            env.intent.target_repository,
            "latest",
            env.now + timedelta(minutes=2),
        )
    except SupplyChainDenied as denied:
        outcomes["replay"] = denied.code

    tampered = build_demo_environment()
    try:
        tampered.gate.verify_and_authorize(
            tampered.intent, tampered.artifact_bytes + b"malware", tampered.evidence, tampered.now
        )
    except SupplyChainDenied as denied:
        outcomes["tampered_artifact"] = denied.code

    finding = VulnerabilityFinding(
        vulnerability_id="GHSA-demo-critical",
        purl="pkg:pypi/httpx@0.28.1",
        severity="CRITICAL",
        fixed_version="0.28.2",
        exploitability="affected",
    )
    vulnerable = build_demo_environment(findings=(finding,))
    try:
        vulnerable.gate.verify_and_authorize(
            vulnerable.intent,
            vulnerable.artifact_bytes,
            vulnerable.evidence,
            vulnerable.now,
        )
    except SupplyChainDenied as denied:
        outcomes["critical_vulnerability"] = denied.code
    return outcomes


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
