"""Executable invariants for Course 12 supply-chain release evidence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/12-supply-chain-provenance-sbom-signing-dependencies/lab.py"
SPEC = importlib.util.spec_from_file_location("course_12_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


@pytest.fixture
def env():
    return lab.build_demo_environment()


def assert_code(call, code):
    with pytest.raises(lab.SupplyChainDenied) as denied:
        call()
    assert denied.value.code == code


def authorize(env, *, evidence=None, artifact_bytes=None, now=None):
    return env.gate.verify_and_authorize(
        env.intent,
        env.artifact_bytes if artifact_bytes is None else artifact_bytes,
        env.evidence if evidence is None else evidence,
        env.now if now is None else now,
    )


def mutate_and_resign(env, role, mutator):
    signed = getattr(env.evidence, role)
    data = signed.document.model_dump(mode="json", by_alias=True)
    mutator(data)
    model = {
        "provenance": lab.SlsaProvenance,
        "sbom": lab.CycloneDxBom,
        "vulnerability_report": lab.VulnerabilityReport,
    }[role]
    return lab.replace_signed_document(env, role, model.model_validate(data))


def finding(*, severity="HIGH", exploitability="affected", purl="pkg:pypi/httpx@0.28.1"):
    return lab.VulnerabilityFinding(
        vulnerability_id="GHSA-demo-1234",
        purl=purl,
        severity=severity,
        fixed_version="0.28.2",
        exploitability=exploitability,
    )


def exception_for(env, *, state="approved", expires_delta=timedelta(hours=2), **updates):
    values = {
        "exception_id": "exc-1042",
        "artifact_digest": env.intent.artifact.digest,
        "vulnerability_id": "GHSA-demo-1234",
        "purl": "pkg:pypi/httpx@0.28.1",
        "environment": env.intent.environment,
        "owner": "runtime-platform",
        "ticket": "RISK-1042",
        "rationale": "No fixed compatible version exists during the emergency release window.",
        "compensating_controls": ("disable outbound callbacks", "monitor affected route"),
        "approved_by": "security-approver@example.com",
        "policy_version": env.policy.version,
        "issued_at": env.now - timedelta(hours=1),
        "expires_at": env.now + expires_delta,
        "state": state,
    }
    values.update(updates)
    return lab.ExceptionRecord(**values)


def test_demo_proves_normal_tamper_vulnerability_and_replay_paths():
    assert lab.run_demo()["tampered_artifact"] == "ARTIFACT_MISMATCH"
    assert lab.run_demo()["critical_vulnerability"] == "CRITICAL_VULNERABILITY"
    assert lab.run_demo()["replay"] == "AUTHORIZATION_REPLAYED"
    assert "@sha256:" in lab.run_demo()["safe_release"]


def test_complete_evidence_mints_exact_short_lived_authorization(env):
    authorization = authorize(env)
    assert authorization.artifact_digest == env.intent.artifact.digest
    assert authorization.target_repository == env.intent.target_repository
    assert authorization.expires_at - authorization.issued_at == timedelta(minutes=10)
    assert authorization.evidence_digest.startswith("sha256:")


@pytest.mark.parametrize("payload", [b"", b"different bytes", b"support-mcp-server:v1.4.2\nlocked-runtime\nextra"])
def test_artifact_bytes_are_rehashed_not_trusted_from_metadata(env, payload):
    assert_code(lambda: authorize(env, artifact_bytes=payload), "ARTIFACT_MISMATCH")


def test_artifact_size_is_bound_even_when_digest_matches(env):
    artifact = env.intent.artifact.model_copy(update={"size": env.intent.artifact.size + 1})
    intent = env.intent.model_copy(update={"artifact": artifact})
    assert_code(
        lambda: env.gate.verify_and_authorize(intent, env.artifact_bytes, env.evidence, env.now),
        "ARTIFACT_MISMATCH",
    )


def test_signature_payload_digest_must_match(env):
    signature = env.evidence.artifact_signature.model_copy(
        update={"payload_digest": f"sha256:{'0' * 64}"}
    )
    evidence = lab.ReleaseEvidence(
        signature,
        env.evidence.provenance,
        env.evidence.sbom,
        env.evidence.vulnerability_report,
    )
    assert_code(lambda: authorize(env, evidence=evidence), "PAYLOAD_DIGEST_MISMATCH")


def test_invalid_ed25519_signature_fails_closed(env):
    signature = env.evidence.artifact_signature.model_copy(
        update={"signature": env.evidence.provenance.signature.signature}
    )
    evidence = lab.ReleaseEvidence(
        signature,
        env.evidence.provenance,
        env.evidence.sbom,
        env.evidence.vulnerability_report,
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SIGNATURE_INVALID")


def test_signer_identity_is_policy_selected_not_evidence_selected(env):
    signature = env.evidence.artifact_signature.model_copy(
        update={"signer_identity": "attacker@example.com"}
    )
    evidence = lab.ReleaseEvidence(
        signature,
        env.evidence.provenance,
        env.evidence.sbom,
        env.evidence.vulnerability_report,
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SIGNER_NOT_ALLOWED")


def test_revoked_signer_is_rejected(env):
    env.trust.revoke(lab.ARTIFACT_SIGNER, lab.ISSUER)
    assert_code(lambda: authorize(env), "SIGNER_REVOKED")


def test_future_transparency_time_is_rejected(env):
    signature = env.evidence.artifact_signature.model_copy(
        update={"integrated_at": env.now + timedelta(minutes=1)}
    )
    evidence = lab.ReleaseEvidence(
        signature,
        env.evidence.provenance,
        env.evidence.sbom,
        env.evidence.vulnerability_report,
    )
    assert_code(lambda: authorize(env, evidence=evidence), "TRANSPARENCY_TIME_INVALID")


def test_provenance_subject_binds_exact_artifact(env):
    evidence = mutate_and_resign(
        env, "provenance", lambda data: data["subject"][0]["digest"].update({"sha256": "0" * 64})
    )
    assert_code(lambda: authorize(env, evidence=evidence), "PROVENANCE_SUBJECT_MISMATCH")


def test_provenance_builder_must_be_preapproved_even_when_signed(env):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["runDetails"].update(
            {"builder": {"id": "https://attacker.example/builder"}}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "BUILDER_NOT_TRUSTED")


def test_provenance_build_type_is_policy_bound(env):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["buildDefinition"].update(
            {"buildType": "https://attacker.example/build"}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "BUILD_TYPE_NOT_ALLOWED")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("source", "https://github.com/attacker/fork", "SOURCE_URI_MISMATCH"),
        ("revision", "f" * 40, "SOURCE_REVISION_MISMATCH"),
    ],
)
def test_provenance_source_and_revision_are_exact(env, field, value, code):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["buildDefinition"]["externalParameters"].update(
            {field: value}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), code)


def test_unexpected_external_build_parameter_is_rejected(env):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["buildDefinition"]["externalParameters"].update(
            {"release_target": "debug-shell"}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "BUILD_PARAMETERS_MISMATCH")


def test_provenance_materials_bind_lockfile_and_base_image(env):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"
        ].update({"sha256": "d" * 64}),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "BUILD_MATERIAL_MISMATCH")


def test_unexpected_build_material_is_rejected(env):
    def mutate(data):
        data["predicate"]["buildDefinition"]["resolvedDependencies"].append(
            {"uri": "https://attacker.example/plugin", "digest": {"sha256": "e" * 64}}
        )

    evidence = mutate_and_resign(env, "provenance", mutate)
    assert_code(lambda: authorize(env, evidence=evidence), "BUILD_MATERIAL_MISMATCH")


def test_stale_provenance_is_rejected(env):
    evidence = mutate_and_resign(
        env,
        "provenance",
        lambda data: data["predicate"]["runDetails"]["metadata"].update(
            {
                "startedOn": "2026-09-01T17:00:00Z",
                "finishedOn": "2026-09-01T18:00:00Z",
            }
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "PROVENANCE_STALE")


def test_sbom_root_hash_binds_artifact(env):
    evidence = mutate_and_resign(
        env,
        "sbom",
        lambda data: data["metadata"]["component"]["hashes"][0].update(
            {"content": "0" * 64}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_SUBJECT_MISMATCH")


def test_sbom_completeness_claim_is_required(env):
    evidence = mutate_and_resign(
        env, "sbom", lambda data: data["compositions"][0].update({"aggregate": "incomplete"})
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_INCOMPLETE")


def test_sbom_graph_rejects_unknown_dependency_reference(env):
    evidence = mutate_and_resign(
        env,
        "sbom",
        lambda data: data["dependencies"][0]["dependsOn"].append("pkg:pypi/ghost@9.9"),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_GRAPH_INVALID")


def test_sbom_graph_rejects_duplicate_edge_records(env):
    evidence = mutate_and_resign(
        env, "sbom", lambda data: data["dependencies"].append(data["dependencies"][0])
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_GRAPH_INVALID")


def test_sbom_graph_requires_every_component_to_be_reachable(env):
    evidence = mutate_and_resign(
        env, "sbom", lambda data: data["dependencies"][0]["dependsOn"].pop()
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_GRAPH_INCOMPLETE")


def test_sbom_inventory_must_equal_trusted_lock_resolution(env):
    def mutate(data):
        old_ref = data["components"][0]["bom-ref"]
        new_ref = "pkg:pypi/unreviewed@9.9.9"
        data["components"][0].update(
            {"bom-ref": new_ref, "purl": new_ref, "name": "unreviewed", "version": "9.9.9"}
        )
        data["dependencies"][0]["dependsOn"] = [
            new_ref if value == old_ref else value
            for value in data["dependencies"][0]["dependsOn"]
        ]
        for edge in data["dependencies"][1:]:
            if edge["ref"] == old_ref:
                edge["ref"] = new_ref

    evidence = mutate_and_resign(env, "sbom", mutate)
    assert_code(lambda: authorize(env, evidence=evidence), "SBOM_INVENTORY_MISMATCH")


@pytest.mark.parametrize("license_id", ["GPL-3.0-only", "AGPL-3.0-only", "NOASSERTION"])
def test_license_policy_denies_forbidden_or_unknown_licenses(env, license_id):
    def mutate(data):
        data["components"][0]["licenses"] = [{"id": license_id}]

    evidence = mutate_and_resign(env, "sbom", mutate)
    assert_code(lambda: authorize(env, evidence=evidence), "LICENSE_POLICY_DENIED")


def test_license_policy_includes_root_component(env):
    evidence = mutate_and_resign(
        env,
        "sbom",
        lambda data: data["metadata"]["component"].update(
            {"licenses": [{"id": "AGPL-3.0-only"}]}
        ),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "LICENSE_POLICY_DENIED")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("artifact_digest", f"sha256:{'0' * 64}", "SCAN_ARTIFACT_MISMATCH"),
        ("sbom_digest", f"sha256:{'0' * 64}", "SCAN_SBOM_MISMATCH"),
    ],
)
def test_scan_report_is_bound_to_artifact_and_sbom(env, field, value, code):
    evidence = mutate_and_resign(
        env, "vulnerability_report", lambda data: data.update({field: value})
    )
    assert_code(lambda: authorize(env, evidence=evidence), code)


def test_scanner_name_and_version_are_allowlisted(env):
    evidence = mutate_and_resign(
        env,
        "vulnerability_report",
        lambda data: data.update({"scanner": {"name": "osv-scanner", "version": "1.0.0"}}),
    )
    assert_code(lambda: authorize(env, evidence=evidence), "SCANNER_NOT_ALLOWED")


def test_stale_scan_is_rejected():
    env = lab.build_demo_environment(scan_age=timedelta(hours=25))
    assert_code(lambda: authorize(env), "SCAN_STALE")


def test_stale_advisory_database_is_rejected():
    env = lab.build_demo_environment(database_age_at_scan=timedelta(hours=13))
    assert_code(lambda: authorize(env), "ADVISORY_DB_STALE")


def test_finding_must_name_a_component_in_bound_sbom():
    env = lab.build_demo_environment(findings=(finding(purl="pkg:pypi/ghost@9.9"),))
    assert_code(lambda: authorize(env), "FINDING_NOT_IN_SBOM")


def test_critical_vulnerability_is_not_exception_eligible():
    env = lab.build_demo_environment(findings=(finding(severity="CRITICAL"),))
    env.exceptions.add(exception_for(env))
    assert_code(lambda: authorize(env), "CRITICAL_VULNERABILITY")


def test_high_vulnerability_requires_trusted_exception():
    env = lab.build_demo_environment(findings=(finding(),))
    assert_code(lambda: authorize(env), "HIGH_VULNERABILITY")


def test_exact_high_vulnerability_exception_allows_release():
    env = lab.build_demo_environment(findings=(finding(),))
    env.exceptions.add(exception_for(env))
    assert authorize(env).artifact_digest == env.intent.artifact.digest


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_digest": f"sha256:{'0' * 64}"},
        {"purl": "pkg:pypi/pydantic@2.12.5"},
        {"policy_version": "old-policy"},
        {"state": "revoked"},
        {"expires_at": lab.utc("2026-09-27T17:30:00Z")},
    ],
)
def test_exception_binding_revocation_and_expiry_fail_closed(changes):
    env = lab.build_demo_environment(findings=(finding(),))
    env.exceptions.add(exception_for(env, **changes))
    assert_code(lambda: authorize(env), "HIGH_VULNERABILITY")


def test_not_affected_vex_like_status_does_not_count_as_unresolved():
    env = lab.build_demo_environment(
        findings=(finding(severity="HIGH", exploitability="not_affected"),)
    )
    assert authorize(env).artifact_digest == env.intent.artifact.digest


def test_hand_constructed_authorization_is_not_trusted(env):
    forged = lab.PromotionAuthorization(
        authorization_id="forged",
        release_id=env.intent.release_id,
        artifact_digest=env.intent.artifact.digest,
        environment=env.intent.environment,
        target_repository=env.intent.target_repository,
        evidence_digest=f"sha256:{'0' * 64}",
        policy_version=env.policy.version,
        issued_at=env.now,
        expires_at=env.now + timedelta(minutes=5),
    )
    assert_code(
        lambda: env.promotion.promote(
            forged, env.artifact_bytes, env.intent.target_repository, "v1", env.now
        ),
        "AUTHORIZATION_NOT_FOUND",
    )


def test_promotion_rechecks_target_before_consumption(env):
    authorization = authorize(env)
    assert_code(
        lambda: env.promotion.promote(
            authorization, env.artifact_bytes, "registry.example/other", "v1", env.now
        ),
        "TARGET_CHANGED",
    )
    assert "@sha256:" in env.promotion.promote(
        authorization,
        env.artifact_bytes,
        env.intent.target_repository,
        "v1.4.2",
        env.now,
    )


def test_promotion_rechecks_artifact_before_consumption(env):
    authorization = authorize(env)
    assert_code(
        lambda: env.promotion.promote(
            authorization,
            env.artifact_bytes + b"changed",
            env.intent.target_repository,
            "v1",
            env.now,
        ),
        "ARTIFACT_CHANGED",
    )


def test_promotion_is_bound_to_service_environment(env):
    authorization = authorize(env)
    staging = lab.PromotionService(env.policy, env.authorizations, "staging")
    assert_code(
        lambda: staging.promote(
            authorization,
            env.artifact_bytes,
            env.intent.target_repository,
            "v1",
            env.now,
        ),
        "ENVIRONMENT_CHANGED",
    )


def test_expired_authorization_is_rejected(env):
    authorization = authorize(env)
    assert_code(
        lambda: env.promotion.promote(
            authorization,
            env.artifact_bytes,
            env.intent.target_repository,
            "v1",
            authorization.expires_at,
        ),
        "AUTHORIZATION_EXPIRED",
    )


def test_authorization_replay_is_rejected(env):
    authorization = authorize(env)
    env.promotion.promote(
        authorization, env.artifact_bytes, env.intent.target_repository, "v1", env.now
    )
    assert_code(
        lambda: env.promotion.promote(
            authorization, env.artifact_bytes, env.intent.target_repository, "latest", env.now
        ),
        "AUTHORIZATION_REPLAYED",
    )


def test_concurrent_promotion_consumes_authorization_once(env):
    authorization = authorize(env)

    def promote(tag):
        try:
            return env.promotion.promote(
                authorization,
                env.artifact_bytes,
                env.intent.target_repository,
                tag,
                env.now,
            )
        except lab.SupplyChainDenied as denied:
            return denied.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(promote, ("v1", "latest")))
    assert sum(value.startswith("registry.example/") for value in outcomes) == 1
    assert outcomes.count("AUTHORIZATION_REPLAYED") == 1


def test_success_publishes_digest_addressed_blob_and_tag(env):
    authorization = authorize(env)
    immutable = env.promotion.promote(
        authorization,
        env.artifact_bytes,
        env.intent.target_repository,
        "v1.4.2",
        env.now,
    )
    key = (env.intent.target_repository, env.intent.artifact.digest)
    assert immutable.endswith(env.intent.artifact.digest)
    assert env.promotion.blobs[key] == env.artifact_bytes
    assert env.promotion.tags[(env.intent.target_repository, "v1.4.2")] == env.intent.artifact.digest


def test_audit_is_structured_and_does_not_store_artifact_or_signatures(env):
    authorization = authorize(env)
    env.promotion.promote(
        authorization, env.artifact_bytes, env.intent.target_repository, "v1", env.now
    )
    serialized = json.dumps(
        [event.model_dump(mode="json") for event in [*env.gate.audit, *env.promotion.audit]]
    )
    assert "support-mcp-server:v1.4.2" not in serialized
    assert env.evidence.artifact_signature.signature not in serialized
    assert "EVIDENCE_ACCEPTED" in serialized
    assert "PROMOTION_COMMITTED" in serialized


def test_strict_contracts_reject_unknown_fields():
    with pytest.raises(ValidationError):
        lab.ArtifactRef(
            name="server.tar",
            digest=f"sha256:{'0' * 64}",
            size=10,
            media_type="application/octet-stream",
            trusted=True,
        )


def test_security_contracts_reject_naive_timestamps(env):
    data = env.evidence.artifact_signature.model_dump(mode="python")
    data["signed_at"] = datetime(2026, 9, 27, 17, 56)
    with pytest.raises(ValidationError, match="timezone-aware"):
        lab.SignatureBundle.model_validate(data)
