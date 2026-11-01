"""Executable invariants for Course 29's architecture review capstone."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/29-mcp-security-architecture-review-workshop/lab.py"
SPEC = importlib.util.spec_from_file_location("course_29_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.NOW


def err(exc):
    return exc.value.code


def fixture(*, secure=True, omit_kind=None):
    return lab.demo_review(secure=secure, omit_kind=omit_kind)


def reseal_package(package, **changes):
    return lab.seal_package(replace(package, package_digest="", **changes))


def reseal_evidence(item, **changes):
    return lab.seal_evidence(replace(item, evidence_digest="", **changes))


def run_review(package, claims, evidence, threats, results):
    return lab.ArchitectureReviewer().review(package, claims, evidence, threats, results, NOW)


def finding_codes(report):
    return {item.code for item in report.findings}


def registered_fixture():
    package, _, _, _, _, report = fixture()
    registry = lab.ReviewRegistry()
    issued_at = NOW + timedelta(minutes=1)
    attestation = registry.attest(package, report, "reviewer:independent", "security_architect", issued_at)
    return package, report, registry, attestation, issued_at


def test_demo_separates_review_from_production_authority(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"flawed_state": "needs_remediation"' in output
    assert '"review_state": "eligible_for_risk_decision"' in output
    assert '"after_material_change": "invalidated"' in output
    assert '"production_authorized": false' in output


def test_canonical_json_sorts_unordered_scope():
    assert lab.canonical_json({"tenants": frozenset({"tenant:beta", "tenant:acme"})}) == b'{"tenants":["tenant:acme","tenant:beta"]}'


def test_demo_package_is_sealed_and_exactly_versioned():
    package = lab.demo_package()
    lab.validate_package(package)
    assert package.package_digest == lab.digest(package.unsigned())
    assert package.protocol_versions == ("MCP-2026-07-28", "OAuth-2.1", "OTel-1.x")


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"package_id": "bad value"}, "FIELD_INVALID"),
        ({"version": ""}, "FIELD_INVALID"),
        ({"title": ""}, "PACKAGE_INCOMPLETE"),
        ({"protocol_versions": ()}, "PACKAGE_INCOMPLETE"),
        ({"data_classes": frozenset()}, "PACKAGE_INCOMPLETE"),
        ({"assumptions": ()}, "PACKAGE_INCOMPLETE"),
        ({"non_goals": ()}, "PACKAGE_INCOMPLETE"),
        ({"change_ids": ()}, "PACKAGE_INCOMPLETE"),
        ({"entrypoints": frozenset()}, "PACKAGE_INCOMPLETE"),
        ({"protected_resources": frozenset()}, "PACKAGE_INCOMPLETE"),
        ({"entrypoints": frozenset({"component:unknown"})}, "PACKAGE_REFERENCE_INVALID"),
        ({"protected_resources": frozenset({"component:unknown"})}, "PACKAGE_REFERENCE_INVALID"),
    ],
)
def test_package_contract_rejects_incomplete_or_unknown_scope(changes, code):
    package = reseal_package(lab.demo_package(), **changes)
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(package)
    assert err(exc) == code


def test_package_digest_detects_unsealed_change():
    package = replace(lab.demo_package(), title="changed")
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(package)
    assert err(exc) == "PACKAGE_INTEGRITY_INVALID"


def test_package_requires_timezone_aware_preparation_time():
    package = reseal_package(lab.demo_package(), prepared_at=NOW.replace(tzinfo=None))
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(package)
    assert err(exc) == "TIME_INVALID"


def test_package_rejects_duplicate_component_and_flow_ids():
    package = lab.demo_package()
    for changes in (
        {"components": package.components + (package.components[0],)},
        {"flows": package.flows + (replace(package.flows[0], source="component:server", target="component:soc"),)},
    ):
        with pytest.raises(lab.ReviewError) as exc:
            lab.validate_package(reseal_package(package, **changes))
        assert err(exc) == "PACKAGE_IDENTITY_CONFLICT"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"artifact_digest": "latest"}, "COMPONENT_INVALID"),
        ({"tenant_scope": frozenset()}, "COMPONENT_INVALID"),
        ({"capabilities": frozenset()}, "COMPONENT_INVALID"),
        ({"owner": ""}, "FIELD_INVALID"),
        ({"tenant_scope": frozenset({"bad tenant"})}, "FIELD_INVALID"),
    ],
)
def test_component_contract_rejects_ambiguous_inventory(changes, code):
    package = lab.demo_package()
    components = (replace(package.components[0], **changes),) + package.components[1:]
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(reseal_package(package, components=components))
    assert err(exc) == code


@pytest.mark.parametrize("changes", [
    {"source": "component:unknown"}, {"target": "component:unknown"},
    {"protocol": ""}, {"data_classification": ""},
])
def test_flow_contract_rejects_unknown_or_untyped_edges(changes):
    package = lab.demo_package()
    flows = (replace(package.flows[0], **changes),) + package.flows[1:]
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(reseal_package(package, flows=flows))
    assert err(exc) == "FLOW_INVALID"


def test_parallel_flow_requires_explicit_intermediary():
    package = lab.demo_package()
    extra = replace(package.flows[0], flow_id="flow:parallel")
    with pytest.raises(lab.ReviewError) as exc:
        lab.validate_package(reseal_package(package, flows=package.flows + (extra,)))
    assert err(exc) == "FLOW_ENDPOINT_CONFLICT"


def test_review_rejects_empty_scope_and_future_review():
    package, claims, evidence, threats, results, _ = fixture()
    for claim_values, threat_values in (((), threats), (claims, ())):
        with pytest.raises(lab.ReviewError) as exc:
            run_review(package, claim_values, evidence, threat_values, results)
        assert err(exc) == "REVIEW_SCOPE_EMPTY"
    with pytest.raises(lab.ReviewError) as exc:
        lab.ArchitectureReviewer().review(package, claims, evidence, threats, results, package.prepared_at - timedelta(seconds=1))
    assert err(exc) == "TIME_INVALID"


@pytest.mark.parametrize("kind", ["claim", "evidence", "threat", "result"])
def test_review_rejects_duplicate_evidence_identities(kind):
    package, claims, evidence, threats, results, _ = fixture()
    values = {"claims": claims, "evidence": evidence, "threats": threats, "results": results}
    key = {"claim": "claims", "evidence": "evidence", "threat": "threats", "result": "results"}[kind]
    values[key] = values[key] + (values[key][0],)
    with pytest.raises(lab.ReviewError) as exc:
        run_review(package, values["claims"], values["evidence"], values["threats"], values["results"])
    assert err(exc) == "REVIEW_IDENTITY_CONFLICT"


@pytest.mark.parametrize("category", sorted(lab.REQUIRED_CATEGORIES))
def test_every_required_control_category_is_fail_closed(category):
    package, claims, evidence, threats, results, _ = fixture()
    report = run_review(package, tuple(item for item in claims if item.category != category), evidence, threats, results)
    assert "CONTROL_CATEGORY_MISSING" in finding_codes(report)
    assert report.state == lab.ReviewState.NEEDS_REMEDIATION


@pytest.mark.parametrize("changes", [
    {"subject_id": "component:unknown"}, {"owner": ""},
    {"statement": ""}, {"required_evidence_kinds": frozenset()},
])
def test_incomplete_control_claim_becomes_owned_finding(changes):
    package, claims, evidence, threats, results, _ = fixture()
    changed = (replace(claims[0], **changes),) + claims[1:]
    report = run_review(package, changed, evidence, threats, results)
    assert "CONTROL_CLAIM_INVALID" in finding_codes(report)
    assert report.state == lab.ReviewState.NEEDS_REMEDIATION


def test_missing_required_evidence_kind_reduces_exact_denominator():
    package, claims, evidence, threats, results, report = fixture(omit_kind="recovery_drill")
    assert "CONTROL_EVIDENCE_MISSING" in finding_codes(report)
    assert report.metrics.satisfied_evidence_slots == report.metrics.evidence_slots - 1
    assert report.metrics.evidence_coverage == (report.metrics.evidence_slots - 1) / report.metrics.evidence_slots


@pytest.mark.parametrize(
    "changes",
    [
        {"subject_id": "component:host"},
        {"subject_version": "old"},
        {"result": lab.EvidenceResult.FAIL},
        {"result": lab.EvidenceResult.INCONCLUSIVE},
        {"collected_at": NOW.replace(tzinfo=None)},
        {"expires_at": NOW},
        {"collected_at": NOW - timedelta(days=91)},
        {"artifact_digest": "bad"},
        {"producer": ""},
        {"source_locator": ""},
        {"test_ids": ()},
    ],
)
def test_invalid_evidence_never_satisfies_a_control_claim(changes):
    package, claims, evidence, threats, results, _ = fixture()
    changed = (reseal_evidence(evidence[0], **changes),) + evidence[1:]
    report = run_review(package, claims, changed, threats, results)
    assert {"EVIDENCE_INVALID", "CONTROL_EVIDENCE_MISSING"}.issubset(finding_codes(report))
    assert report.state == lab.ReviewState.NEEDS_REMEDIATION


def test_tampered_evidence_digest_is_not_trusted():
    package, claims, evidence, threats, results, _ = fixture()
    changed = (replace(evidence[0], producer="attacker"),) + evidence[1:]
    report = run_review(package, claims, changed, threats, results)
    assert "EVIDENCE_INVALID" in finding_codes(report)


def test_well_formed_but_untrusted_producer_and_wrong_artifact_are_rejected():
    package, claims, evidence, threats, results, _ = fixture()
    for changes in (
        {"producer": "producer:untrusted"},
        {"artifact_digest": "sha256:" + "0" * 64},
    ):
        changed = (reseal_evidence(evidence[0], **changes),) + evidence[1:]
        report = run_review(package, claims, changed, threats, results)
        assert {"EVIDENCE_INVALID", "CONTROL_EVIDENCE_MISSING", "ABUSE_TEST_MISSING"}.issubset(finding_codes(report))


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"authenticated": False}, "TRUST_BOUNDARY_UNPROTECTED"),
        ({"encrypted": False}, "TRUST_BOUNDARY_UNPROTECTED"),
        ({"authorized_at_target": False}, "RESOURCE_AUTHORIZATION_MISSING"),
        ({"tenant_bound": False}, "RESOURCE_AUTHORIZATION_MISSING"),
        ({"telemetry": False}, "EFFECT_TELEMETRY_MISSING"),
    ],
)
def test_flow_failures_are_found_from_architecture_not_claim_text(changes, code):
    package, claims, evidence, threats, results, _ = fixture()
    flows = package.flows[:2] + (replace(package.flows[2], **changes),) + package.flows[3:]
    changed_package = reseal_package(package, flows=flows)
    changed_results = tuple(replace(item, package_digest=changed_package.package_digest) for item in results)
    report = run_review(changed_package, claims, evidence, threats, changed_results)
    assert code in finding_codes(report)
    assert report.state == lab.ReviewState.NEEDS_REMEDIATION


def test_disjoint_component_tenants_cannot_be_joined():
    package, claims, evidence, threats, results, _ = fixture()
    tickets = replace(package.components[3], tenant_scope=frozenset({"tenant:beta"}))
    changed_package = reseal_package(package, components=package.components[:3] + (tickets,) + package.components[4:])
    changed_results = tuple(replace(item, package_digest=changed_package.package_digest) for item in results)
    report = run_review(changed_package, claims, evidence, threats, changed_results)
    assert "CROSS_TENANT_FLOW" in finding_codes(report)


def test_declared_resource_without_path_is_not_scored_clean():
    package, claims, evidence, threats, results, _ = fixture()
    changed_package = reseal_package(package, flows=tuple(item for item in package.flows if item.flow_id != "flow:server-tickets"))
    changed_results = tuple(replace(item, package_digest=changed_package.package_digest) for item in results)
    report = run_review(changed_package, claims, evidence, threats, changed_results)
    assert "ARCHITECTURE_PATH_MISSING" in finding_codes(report)
    assert report.metrics.protected_paths == 0
    assert report.metrics.critical_path_coverage is None


def test_protected_path_requires_independent_resource_enforcement():
    package, claims, evidence, threats, results, _ = fixture()
    components = tuple(replace(item, capabilities=frozenset({"system_of_record"})) if item.component_id == "component:tickets" else item for item in package.components)
    changed_package = reseal_package(package, components=components)
    changed_results = tuple(replace(item, package_digest=changed_package.package_digest) for item in results)
    report = run_review(changed_package, claims, evidence, threats, changed_results)
    assert "PROTECTED_PATH_INCOMPLETE" in finding_codes(report)
    assert report.metrics.critical_path_coverage == 0


@pytest.mark.parametrize("changes", [
    {"entrypoint": "component:unknown"}, {"target": "component:unknown"},
    {"attack_refs": ()}, {"violated_properties": frozenset()},
])
def test_incomplete_threat_scenario_cannot_claim_test_coverage(changes):
    package, claims, evidence, threats, results, _ = fixture()
    changed = (replace(threats[0], **changes),) + threats[1:]
    report = run_review(package, claims, evidence, changed, results)
    assert "THREAT_SCENARIO_INVALID" in finding_codes(report)
    assert report.metrics.threat_test_coverage == pytest.approx(2 / 3)


@pytest.mark.parametrize("changes", [
    {"package_digest": "sha256:" + "0" * 64},
    {"tenant_id": "tenant:beta"},
    {"executed_at": NOW + timedelta(seconds=1)},
    {"evidence_ids": ()},
    {"evidence_ids": ("evidence:unknown",)},
    {"observed_effect": ""},
])
def test_abuse_result_must_bind_exact_package_tenant_time_and_evidence(changes):
    package, claims, evidence, threats, results, _ = fixture()
    changed = (replace(results[0], **changes),) + results[1:]
    report = run_review(package, claims, evidence, threats, changed)
    assert "ABUSE_TEST_MISSING" in finding_codes(report)
    assert report.metrics.tested_threats == 2


@pytest.mark.parametrize(
    ("result", "effect", "severity"),
    [
        (lab.EvidenceResult.FAIL, "forbidden_effect_completed", lab.Severity.CRITICAL),
        (lab.EvidenceResult.INCONCLUSIVE, "outcome_unknown", lab.Severity.HIGH),
        (lab.EvidenceResult.PASS, "command_rejected_but_effect_unverified", lab.Severity.HIGH),
    ],
)
def test_abuse_test_needs_independent_blocked_effect_proof(result, effect, severity):
    package, claims, evidence, threats, results, _ = fixture()
    changed = (replace(results[0], result=result, observed_effect=effect),) + results[1:]
    report = run_review(package, claims, evidence, threats, changed)
    finding = next(item for item in report.findings if item.code == "ABUSE_TEST_FAILED")
    assert finding.severity == severity
    assert report.state == lab.ReviewState.NEEDS_REMEDIATION


def test_complete_review_reports_disclosed_populations_and_no_authority():
    _, claims, _, threats, _, report = fixture()
    assert report.state == lab.ReviewState.ELIGIBLE_FOR_RISK_DECISION
    assert report.findings == ()
    assert report.production_authorized is False
    assert report.report_digest == lab.digest(report.unsigned())
    assert report.metrics.claims == report.metrics.satisfied_claims == len(claims)
    assert report.metrics.threats == report.metrics.tested_threats == report.metrics.passed_abuse_tests == len(threats)
    assert report.metrics.evidence_coverage == report.metrics.threat_test_coverage == 1
    assert report.metrics.critical_path_coverage == 1


@pytest.mark.parametrize("role", ["developer", "model", "business_owner", "administrator"])
def test_attestation_requires_independent_review_role(role):
    package, _, _, _, _, report = fixture()
    with pytest.raises(lab.ReviewError) as exc:
        lab.ReviewRegistry().attest(package, report, "reviewer:x", role, NOW)
    assert err(exc) == "REVIEWER_ROLE_INVALID"


@pytest.mark.parametrize("owner", ["owner:business", "owner:platform", "owner:security"])
def test_package_owners_cannot_independently_attest_their_own_review(owner):
    package, _, _, _, _, report = fixture()
    with pytest.raises(lab.ReviewError) as exc:
        lab.ReviewRegistry().attest(package, report, owner, "security_architect", NOW)
    assert err(exc) == "REVIEWER_NOT_INDEPENDENT"


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), timedelta(hours=2)])
def test_attestation_ttl_is_bounded(ttl):
    package, _, _, _, _, report = fixture()
    with pytest.raises(lab.ReviewError) as exc:
        lab.ReviewRegistry().attest(package, report, "reviewer:x", "security_architect", NOW, ttl)
    assert err(exc) == "ATTESTATION_TTL_INVALID"


def test_attestation_and_record_times_must_be_timezone_aware():
    package, report, registry, attestation, issued_at = registered_fixture()
    with pytest.raises(lab.ReviewError) as exc:
        registry.attest(package, report, "reviewer:x", "security_architect", NOW.replace(tzinfo=None))
    assert err(exc) == "TIME_INVALID"
    with pytest.raises(lab.ReviewError) as exc:
        registry.record("operation:time", package, report, attestation, issued_at.replace(tzinfo=None))
    assert err(exc) == "TIME_INVALID"


def test_attestation_rejects_tampered_or_wrong_package_report():
    package, _, _, _, _, report = fixture()
    registry = lab.ReviewRegistry()
    for changed in (replace(report, package_digest="sha256:" + "0" * 64), replace(report, production_authorized=True)):
        with pytest.raises(lab.ReviewError) as exc:
            registry.attest(package, changed, "reviewer:x", "security_architect", NOW)
        assert err(exc) == "REPORT_INTEGRITY_INVALID"


def test_record_verifies_signature_scope_expiry_and_report_integrity():
    package, report, registry, attestation, issued_at = registered_fixture()
    changed_report = replace(report, state=lab.ReviewState.NEEDS_REMEDIATION, report_digest="")
    changed_report = replace(changed_report, report_digest=lab.digest(changed_report.unsigned()))
    cases = [
        (replace(attestation, signature="00" * 64), report, issued_at, "ATTESTATION_SIGNATURE_INVALID"),
        (replace(attestation, purpose="deploy"), report, issued_at, "ATTESTATION_SIGNATURE_INVALID"),
        (attestation, report, attestation.expires_at, "ATTESTATION_EXPIRED"),
        (attestation, changed_report, issued_at, "ATTESTATION_SCOPE_MISMATCH"),
    ]
    for changed_attestation, changed_report, at, code in cases:
        with pytest.raises(lab.ReviewError) as exc:
            registry.record("operation:test", package, changed_report, changed_attestation, at)
        assert err(exc) == code


def test_record_is_idempotent_for_same_operation_and_rejects_conflict():
    package, report, registry, attestation, issued_at = registered_fixture()
    first = registry.record("operation:review", package, report, attestation, issued_at)
    assert registry.record("operation:review", package, report, attestation, issued_at) == first
    other_package = reseal_package(package, version="29.2.0")
    with pytest.raises(lab.ReviewError) as exc:
        registry.record("operation:review", other_package, report, attestation, issued_at)
    assert err(exc) in {"ATTESTATION_SCOPE_MISMATCH", "REPORT_INTEGRITY_INVALID"}


def test_attestation_is_single_use_across_operations():
    package, report, registry, attestation, issued_at = registered_fixture()
    registry.record("operation:one", package, report, attestation, issued_at)
    with pytest.raises(lab.ReviewError) as exc:
        registry.record("operation:two", package, report, attestation, issued_at)
    assert err(exc) == "ATTESTATION_REPLAYED"


def test_concurrent_attestation_consumption_allows_one_effect():
    package, report, registry, attestation, issued_at = registered_fixture()

    def consume(index):
        try:
            return registry.record(f"operation:{index}", package, report, attestation, issued_at).state
        except lab.ReviewError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(consume, range(16)))
    assert results.count(lab.ReviewState.ELIGIBLE_FOR_RISK_DECISION) == 1
    assert results.count("ATTESTATION_REPLAYED") == 15


def test_recorded_review_still_never_authorizes_production():
    package, report, registry, attestation, issued_at = registered_fixture()
    record = registry.record("operation:review", package, report, attestation, issued_at)
    assert record.state == lab.ReviewState.ELIGIBLE_FOR_RISK_DECISION
    assert record.production_authorized is False


@pytest.mark.parametrize("dimensions", [frozenset(), frozenset({"unknown"})])
def test_change_dimensions_are_explicit_and_bounded(dimensions):
    package, report, registry, attestation, issued_at = registered_fixture()
    registry.record("operation:review", package, report, attestation, issued_at)
    with pytest.raises(lab.ReviewError) as exc:
        registry.invalidate("operation:review", lab.MaterialChange("change:x", package.package_id, package.package_digest, dimensions, issued_at))
    assert err(exc) == "CHANGE_INVALID"


@pytest.mark.parametrize("changes", [
    {"package_id": "package:other"},
    {"prior_package_digest": "sha256:" + "0" * 64},
    {"observed_at": NOW},
])
def test_change_must_bind_recorded_package_and_follow_record_time(changes):
    package, report, registry, attestation, issued_at = registered_fixture()
    registry.record("operation:review", package, report, attestation, issued_at)
    change = lab.MaterialChange("change:x", package.package_id, package.package_digest, frozenset({"artifact"}), issued_at + timedelta(seconds=1))
    with pytest.raises(lab.ReviewError) as exc:
        registry.invalidate("operation:review", replace(change, **changes))
    assert err(exc) == "REVIEW_RECORD_NOT_FOUND"


def test_material_change_invalidates_review_without_granting_authority():
    package, report, registry, attestation, issued_at = registered_fixture()
    registry.record("operation:review", package, report, attestation, issued_at)
    changed = registry.invalidate("operation:review", lab.MaterialChange(
        "change:capability", package.package_id, package.package_digest,
        frozenset({"capability", "protocol"}), issued_at + timedelta(seconds=1),
    ))
    assert changed.state == lab.ReviewState.INVALIDATED
    assert changed.production_authorized is False


def test_portfolio_metrics_disclose_population_and_denominators():
    *_, good = fixture()
    *_, flawed = fixture(secure=False)
    metrics = lab.review_portfolio_metrics([good, flawed])
    assert metrics["reviewed_packages"] == 2
    assert metrics["eligible_packages"] == 1
    assert metrics["needs_remediation_packages"] == 1
    assert metrics["critical_findings"] >= 1
    assert metrics["mean_evidence_coverage"] == 1
    assert metrics["mean_threat_test_coverage"] == 1
    assert 0 <= metrics["mean_critical_path_coverage"] <= 1
    with pytest.raises(ValueError):
        lab.review_portfolio_metrics([])
