"""Executable quality and honesty checks for Course 02's threat model."""

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/beginner/02-threat-modeling-mcp-agent-protocols/lab.py"
SPEC = importlib.util.spec_from_file_location("course_02_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def receipt(model, evidence_id, status, *, producer=None, locator=None):
    record = next(item for item in model.evidence if item.identifier == evidence_id)
    return lab.EvidenceReceipt(
        identifier=f"RCPT-{evidence_id}",
        evidence_id=evidence_id,
        model_version=model.version,
        producer=producer or lab.TRUSTED_PRODUCERS[record.kind],
        status=status,
        artifact_locator=locator or f"{lab.ARTIFACT_PREFIX[record.kind]}course-02/{evidence_id}",
        artifact_digest="a" * 64,
        observed_at="2026-09-20T12:00:00Z",
    )


def test_support_model_covers_all_stride_prompts_and_has_valid_references():
    model = lab.build_model()
    assert lab.lint_model(model) == ()
    assert {threat.stride for threat in model.threats} == lab.STRIDE
    assert len(model.components) == 8
    assert len(model.flows) == 8


def test_documentation_traceability_is_not_reported_as_control_verification():
    metrics = lab.coverage_metrics(lab.build_model())
    assert metrics["design_traceability_percent"] == 100
    assert metrics["verified_control_percent"] == 0
    assert metrics["verified_control_threats"] == 0


def test_one_threat_counts_verified_only_after_all_three_evidence_types_succeed():
    model = lab.build_model()
    model = lab.record_evidence(model, receipt(model, "EV-rogue-server-TEST", "passed"))
    model = lab.record_evidence(model, receipt(model, "EV-rogue-server-SIGNAL", "verified"))
    still_incomplete = lab.coverage_metrics(model)
    assert still_incomplete["verified_control_threats"] == 0

    model = lab.record_evidence(model, receipt(model, "EV-rogue-server-RUNBOOK", "exercised"))
    complete = lab.coverage_metrics(model)
    assert complete["verified_control_threats"] == 1
    assert complete["verified_control_percent"] == 17


def test_failed_evidence_never_counts_as_verified():
    model = lab.build_model()
    model = lab.record_evidence(model, receipt(model, "EV-cross-tenant-read-TEST", "failed"))
    assert lab.coverage_metrics(model)["verified_control_threats"] == 0


def test_wrong_artifact_scheme_cannot_be_relabelled_as_successful_evidence():
    model = lab.build_model()
    bad = receipt(model, "EV-audit-gap-TEST", "passed", locator="planned-test:audit-gap")
    with pytest.raises(ValueError, match="ci://"):
        lab.record_evidence(model, bad)


def test_untrusted_evidence_producer_is_rejected():
    model = lab.build_model()
    forged = receipt(
        model, "EV-audit-gap-SIGNAL", "verified", producer="model/self-report"
    )
    with pytest.raises(PermissionError, match="untrusted telemetry evidence producer"):
        lab.record_evidence(model, forged)


def test_receipt_for_old_model_version_is_rejected():
    model = lab.build_model()
    stale = replace(receipt(model, "EV-audit-gap-RUNBOOK", "exercised"), model_version="old")
    with pytest.raises(ValueError, match="different model version"):
        lab.record_evidence(model, stale)


def test_receipt_without_a_content_digest_is_rejected():
    model = lab.build_model()
    undigested = replace(receipt(model, "EV-audit-gap-TEST", "passed"), artifact_digest="")
    with pytest.raises(ValueError, match="64 lowercase hex"):
        lab.record_evidence(model, undigested)


def test_linter_detects_a_cross_zone_flow_without_a_named_boundary():
    model = lab.build_model()
    broken_flow = replace(model.flows[0], trust_boundary="")
    broken = replace(model, flows=(broken_flow, *model.flows[1:]))
    assert "F-01: cross-zone flow has no trust boundary" in lab.lint_model(broken)


def test_linter_detects_dangling_evidence_instead_of_inflating_coverage():
    model = lab.build_model()
    broken = replace(model, evidence=model.evidence[1:])
    findings = lab.lint_model(broken)
    assert any("TM-01: missing evidence EV-rogue-server-TEST" in finding for finding in findings)
    assert lab.coverage_metrics(broken)["design_complete_threats"] == 5


def test_supply_chain_path_reaches_downstream_data_boundary():
    paths = lab.find_attack_paths(lab.build_model(), "C-REGISTRY", "C-TICKET")
    assert ("C-REGISTRY", "C-HOST", "C-SERVER", "C-TICKET") in paths


def test_authenticated_state_not_model_text_is_the_identity_source():
    model = lab.build_model()
    user_flow = next(flow for flow in model.flows if flow.identifier == "F-01")
    tenant_threat = next(threat for threat in model.threats if threat.identifier == "TM-04")
    assert user_flow.identity_source == "authenticated host session"
    assert "authenticated" in tenant_threat.invariant.lower()
    assert any("model-controlled argument" in item for item in tenant_threat.preconditions)


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [(1, 1, "low"), (2, 3, "medium"), (3, 4, "high"), (4, 5, "critical")],
)
def test_ordinal_risk_matrix_has_explicit_boundaries(likelihood, impact, expected):
    assert lab.risk_band(likelihood, impact) == expected
