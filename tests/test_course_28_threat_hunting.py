"""Executable invariants for Course 28 threat hunting and anomaly detection."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
import math
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/28-mcp-threat-hunting-runtime-anomaly-detection/lab.py"
SPEC = importlib.util.spec_from_file_location("course_28_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.NOW


def components():
    return lab.demo_components()


def valid_events():
    return [
        lab.event_fixture(event_id="EV-GATEWAY", source_id="source:gateway"),
        lab.event_fixture(
            event_id="EV-NETWORK", source_id="source:network",
            kind=lab.EventKind.NETWORK, occurred_at=NOW + timedelta(seconds=2),
            observed_at=NOW + timedelta(seconds=3), ingested_at=NOW + timedelta(seconds=4),
        ),
    ]


def prepared(events=None, **quality):
    _, preparer, grant, hypothesis, engine = components()
    evidence = preparer.prepare(events or valid_events(), grant, hypothesis, NOW, **quality)
    return evidence, hypothesis, engine


def err(exc):
    return exc.value.code


def supported_finding():
    evidence, hypothesis, engine = prepared([
        lab.event_fixture(event_id="EV-GATEWAY", source_id="source:gateway"),
        lab.event_fixture(
            event_id="EV-EGRESS", source_id="source:network", kind=lab.EventKind.NETWORK,
            destination="evil.example", occurred_at=NOW + timedelta(seconds=2),
            observed_at=NOW + timedelta(seconds=3), ingested_at=NOW + timedelta(seconds=4),
        ),
    ])
    item = next(value for value in engine.invariant_hunt(evidence, hypothesis, NOW + timedelta(seconds=5)) if "UNAPPROVED_DESTINATION" in value.reason_codes)
    return lab.disposition_finding(
        item, "analyst:oncall", "threat_hunter", lab.Disposition.SUPPORTED,
        "trusted network event and inventory confirm unapproved egress", NOW + timedelta(seconds=6),
    )[0]


def candidate_for(item):
    return lab.DetectionCandidate(
        "DC-1", "MCP-HUNT-001", "1.0.0", "Unapproved MCP egress",
        item.hypothesis_id, (item.finding_id,), "network destination outside trusted inventory",
        ("tenant_id", "server_id", "destination", "event_id"), timedelta(minutes=5),
        ("tenant_id", "server_id", "destination"), None,
        ("approved emergency change",), "dataset:labelled-v1", 0.9, 0.8,
        "team:detection-engineering",
    )


def test_demo_keeps_hunt_promotion_separate_from_containment(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"data_ready": true' in output
    assert '"disposition": "supported"' in output
    assert '"detection_state": "test"' in output
    assert '"containment_authorized": false' in output


def test_event_fixture_binds_digest_to_exact_evidence():
    event = lab.event_fixture()
    unsigned = {key: value for key, value in lab.asdict(event).items() if key != "evidence_digest"}
    assert event.evidence_digest == lab.digest(unsigned)
    assert event.identity() == ("tenant:acme", "EV-001")


def test_canonical_json_sorts_unordered_authority_scope():
    payload = {
        "methods": frozenset({lab.EventKind.POLICY, lab.EventKind.NETWORK}),
        "scope": frozenset({"tenant:beta", "tenant:acme"}),
    }
    assert lab.canonical_json(payload) == (
        b'{"methods":["network","policy"],"scope":["tenant:acme","tenant:beta"]}'
    )


@pytest.mark.parametrize("role", ["model", "viewer", "administrator", "detection_reviewer"])
def test_only_hunt_roles_receive_read_grants(role):
    authority = lab.HuntAuthority()
    with pytest.raises(lab.HuntError) as exc:
        authority.issue("hunter:x", role, frozenset({"tenant:acme"}), frozenset(lab.EventKind), NOW, NOW + timedelta(hours=1), NOW)
    assert err(exc) == "HUNTER_ROLE_INVALID"


@pytest.mark.parametrize(
    ("tenants", "kinds", "start", "end", "ttl", "expected"),
    [
        (frozenset(), frozenset(lab.EventKind), NOW, NOW + timedelta(hours=1), timedelta(hours=1), "HUNT_SCOPE_EMPTY"),
        (frozenset({"tenant:acme"}), frozenset(), NOW, NOW + timedelta(hours=1), timedelta(hours=1), "HUNT_SCOPE_EMPTY"),
        (frozenset({"tenant:acme"}), frozenset(lab.EventKind), NOW, NOW, timedelta(hours=1), "HUNT_WINDOW_INVALID"),
        (frozenset({"tenant:acme"}), frozenset(lab.EventKind), NOW, NOW + timedelta(days=31), timedelta(hours=1), "HUNT_WINDOW_INVALID"),
        (frozenset({"tenant:acme"}), frozenset(lab.EventKind), NOW, NOW + timedelta(hours=1), timedelta(0), "GRANT_TTL_INVALID"),
        (frozenset({"tenant:acme"}), frozenset(lab.EventKind), NOW, NOW + timedelta(hours=1), timedelta(hours=9), "GRANT_TTL_INVALID"),
    ],
)
def test_grant_scope_time_and_ttl_are_bounded(tenants, kinds, start, end, ttl, expected):
    with pytest.raises(lab.HuntError) as exc:
        lab.HuntAuthority().issue("hunter:x", "threat_hunter", tenants, kinds, start, end, NOW, ttl)
    assert err(exc) == expected


def test_grant_signature_purpose_policy_and_expiry_are_verified():
    authority, _, grant, *_ = components()
    for changed, expected in [
        (replace(grant, signature="00" * 64), "GRANT_SIGNATURE_INVALID"),
        (replace(grant, purpose="containment"), "GRANT_SIGNATURE_INVALID"),
        (replace(grant, policy_version="old"), "GRANT_SIGNATURE_INVALID"),
    ]:
        with pytest.raises(lab.HuntError) as exc:
            authority.verify(changed, NOW)
        assert err(exc) == expected
    with pytest.raises(lab.HuntError) as exc:
        authority.verify(grant, grant.expires_at)
    assert err(exc) == "GRANT_EXPIRED"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"hypothesis_id": "bad id"}, "FIELD_INVALID"),
        ({"version": "bad version!"}, "FIELD_INVALID"),
        ({"owner": "bad owner!"}, "FIELD_INVALID"),
        ({"title": ""}, "HYPOTHESIS_INCOMPLETE"),
        ({"tenant_ids": frozenset()}, "HYPOTHESIS_INCOMPLETE"),
        ({"required_sources": frozenset()}, "HYPOTHESIS_INCOMPLETE"),
        ({"required_fields": frozenset()}, "HYPOTHESIS_INCOMPLETE"),
        ({"methods": frozenset()}, "HYPOTHESIS_INCOMPLETE"),
        ({"validation_steps": ()}, "HYPOTHESIS_INCOMPLETE"),
        ({"promotion_criteria": ()}, "HYPOTHESIS_INCOMPLETE"),
        ({"window_end": NOW - timedelta(hours=2)}, "HUNT_WINDOW_INVALID"),
    ],
)
def test_hypothesis_is_versioned_scoped_and_falsifiable(changes, expected):
    hypothesis = replace(lab.demo_hypothesis(), **changes)
    with pytest.raises(lab.HuntError) as exc:
        lab.validate_hypothesis(hypothesis)
    assert err(exc) == expected


def test_prepare_authorizes_tenant_and_time_before_querying():
    _, preparer, grant, hypothesis, _ = components()
    with pytest.raises(lab.HuntError) as exc:
        preparer.prepare([], grant, replace(hypothesis, tenant_ids=frozenset({"tenant:beta"})), NOW)
    assert err(exc) == "HUNT_TENANT_UNAUTHORIZED"
    with pytest.raises(lab.HuntError) as exc:
        preparer.prepare([], grant, replace(hypothesis, window_start=grant.window_start - timedelta(seconds=1)), NOW)
    assert err(exc) == "HUNT_WINDOW_UNAUTHORIZED"


def test_prepare_rejects_unknown_required_fields_and_bad_thresholds():
    _, preparer, grant, hypothesis, _ = components()
    with pytest.raises(lab.HuntError) as exc:
        preparer.prepare(valid_events(), grant, replace(hypothesis, required_fields=hypothesis.required_fields | {"raw_prompt"}), NOW)
    assert err(exc) == "REQUIRED_FIELD_UNKNOWN"
    for kwargs in ({"min_source_coverage": 0}, {"min_field_completeness": 1.1}):
        with pytest.raises(ValueError):
            preparer.prepare(valid_events(), grant, hypothesis, NOW, **kwargs)


@pytest.mark.parametrize(
    ("change", "expected_reason"),
    [
        ({"schema_version": "old"}, "INVALID_EVIDENCE_PRESENT"),
        ({"artifact_digest": "bad"}, "INVALID_EVIDENCE_PRESENT"),
        ({"trace_id": "bad"}, "INVALID_EVIDENCE_PRESENT"),
        ({"source_id": "source:unknown"}, "INVALID_EVIDENCE_PRESENT"),
        ({"tenant_id": "tenant:beta"}, "SOURCE_COVERAGE_INCOMPLETE"),
    ],
)
def test_data_gate_reports_invalid_or_out_of_scope_evidence(change, expected_reason):
    _, preparer, grant, hypothesis, _ = components()
    event = lab.event_fixture(**({"event_id": "EV-BAD", "source_id": "source:gateway"} | change))
    report = preparer.prepare([event], grant, hypothesis, NOW).report
    assert not report.ready
    assert expected_reason in report.reason_codes


def test_tampered_evidence_digest_is_invalid_not_searchable():
    _, preparer, grant, hypothesis, _ = components()
    event = replace(lab.event_fixture(source_id="source:gateway"), destination="evil.example")
    report = preparer.prepare([event], grant, hypothesis, NOW).report
    assert report.invalid_events == 1
    assert report.usable_events == 0


def test_missing_required_field_reduces_completeness_and_blocks_readiness():
    _, preparer, grant, hypothesis, _ = components()
    event = lab.event_fixture(source_id="source:gateway", operation_id="")
    result = preparer.prepare([event], grant, hypothesis, NOW)
    assert result.report.missing_required_fields == 1
    assert result.report.field_completeness == 0
    assert "FIELD_COMPLETENESS_LOW" in result.report.reason_codes


def test_exact_duplicate_is_counted_once_but_conflict_is_invalid():
    _, preparer, grant, hypothesis, _ = components()
    events = valid_events()
    result = preparer.prepare(events + [events[0]], grant, hypothesis, NOW)
    assert result.report.duplicate_events == 1
    assert result.report.usable_events == 2
    conflict = replace(events[0], evidence_digest="sha256:" + "f" * 64)
    report = preparer.prepare(events + [conflict], grant, hypothesis, NOW).report
    assert report.invalid_events == 1
    assert not report.ready


def test_late_events_are_measured_while_clock_errors_block_readiness():
    _, preparer, grant, hypothesis, _ = components()
    late = lab.event_fixture(
        event_id="EV-LATE", source_id="source:gateway",
        ingested_at=NOW + timedelta(minutes=11),
    )
    result = preparer.prepare([late] + valid_events()[1:], grant, hypothesis, NOW)
    assert result.report.late_event_rate > 0
    future = lab.event_fixture(
        event_id="EV-CLOCK", source_id="source:gateway",
        occurred_at=NOW + timedelta(seconds=30), observed_at=NOW,
    )
    result = preparer.prepare([future] + valid_events()[1:], grant, hypothesis, NOW)
    assert result.report.clock_error_rate > 0
    assert "CLOCK_QUALITY_LOW" in result.report.reason_codes


def test_required_source_coverage_prevents_false_clean_hunt():
    _, preparer, grant, hypothesis, _ = components()
    result = preparer.prepare([valid_events()[0]], grant, hypothesis, NOW)
    assert result.report.source_coverage == 0.5
    assert not result.report.ready
    with pytest.raises(lab.HuntError) as exc:
        components()[-1].invariant_hunt(result, hypothesis, NOW)
    assert err(exc) == "DATA_NOT_READY"


def test_out_of_window_evidence_is_filtered_before_analysis():
    _, preparer, grant, hypothesis, _ = components()
    outside = lab.event_fixture(
        event_id="EV-OLD", source_id="source:gateway",
        occurred_at=grant.window_start - timedelta(seconds=1),
        observed_at=grant.window_start, ingested_at=grant.window_start,
    )
    result = preparer.prepare(valid_events() + [outside], grant, hypothesis, NOW)
    assert result.report.total_events == 3
    assert result.report.usable_events == 2
    assert all(item.event_id != "EV-OLD" for item in result.events)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"artifact_digest": "sha256:" + "b" * 64}, "ARTIFACT_DRIFT"),
        ({"capability_version": "support-tools/8"}, "CAPABILITY_DRIFT"),
        ({"kind": lab.EventKind.NETWORK, "source_id": "source:network", "destination": "evil.example"}, "UNAPPROVED_DESTINATION"),
        ({"resource_tenant": "tenant:beta"}, "CROSS_TENANT_RESOURCE"),
        ({"delegation_depth": 3}, "DELEGATION_DEPTH_EXCEEDED"),
    ],
)
def test_invariant_hunts_preserve_exact_evidence(changes, reason):
    extra = lab.event_fixture(event_id="EV-ANOM", **changes)
    base = [event for event in valid_events() if event.source_id != extra.source_id]
    evidence, hypothesis, engine = prepared(base + [extra])
    item = next(value for value in engine.invariant_hunt(evidence, hypothesis, NOW + timedelta(seconds=5)) if reason in value.reason_codes)
    assert item.evidence_event_ids == ("EV-ANOM",)
    assert item.evidence_digest.startswith("sha256:")
    assert item.confidence == lab.Confidence.HIGH
    assert item.disposition == lab.Disposition.CANDIDATE


def baseline(**changes):
    value = lab.BaselineContract(
        "BASE-BYTES-1", "1.0.0", "tenant:acme", "server:support", "ticket.read",
        "bytes_out", NOW - timedelta(days=8), NOW - timedelta(days=1),
        (450, 480, 500, 510, 520, 540, 560), 5, 3.5, True,
    )
    return replace(value, **changes)


def test_robust_mad_hunt_reports_score_threshold_and_baseline_version():
    anomaly = lab.event_fixture(event_id="EV-BYTES", source_id="source:gateway", bytes_out=5000)
    evidence, hypothesis, engine = prepared([anomaly, valid_events()[1]])
    items = engine.robust_mad_hunt(evidence, hypothesis, baseline(), NOW + timedelta(seconds=5))
    assert len(items) == 1
    item = items[0]
    assert item.method == lab.HuntMethod.ROBUST_MAD
    assert item.score >= item.threshold
    assert item.baseline_id == "BASE-BYTES-1"
    assert item.baseline_version == "1.0.0"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"feature": "latency"}, "BASELINE_INVALID"),
        ({"threshold": 0}, "BASELINE_INVALID"),
        ({"values": (1, 2, 3), "minimum_samples": 5}, "BASELINE_INSUFFICIENT"),
        ({"minimum_samples": 4}, "BASELINE_INSUFFICIENT"),
        ({"training_end": NOW}, "BASELINE_TIME_INVALID"),
        ({"contamination_reviewed": False}, "BASELINE_CONTAMINATION_UNREVIEWED"),
        ({"values": (500, 500, 500, 500, 500)}, "BASELINE_ZERO_DISPERSION"),
        ({"values": (1, 2, 3, 4, math.nan)}, "BASELINE_INVALID"),
        ({"values": (1, 2, 3, 4, -1)}, "BASELINE_INVALID"),
    ],
)
def test_statistical_hunt_fails_closed_for_unusable_baselines(changes, expected):
    evidence, hypothesis, engine = prepared()
    with pytest.raises(lab.HuntError) as exc:
        engine.robust_mad_hunt(evidence, hypothesis, baseline(**changes), NOW)
    assert err(exc) == expected


def test_low_and_slow_hunt_finds_distributed_denials_below_bucket_threshold():
    events = [valid_events()[1]]
    for index in range(6):
        events.append(lab.event_fixture(
            event_id=f"EV-DENY-{index}", source_id="source:gateway",
            kind=lab.EventKind.POLICY, outcome=lab.Outcome.DENIED,
            policy_decision="deny", operation_id=f"OP-D{index}",
            occurred_at=NOW - timedelta(minutes=30) + timedelta(minutes=6 * index),
            observed_at=NOW - timedelta(minutes=30) + timedelta(minutes=6 * index, seconds=1),
            ingested_at=NOW - timedelta(minutes=30) + timedelta(minutes=6 * index, seconds=2),
        ))
    evidence, hypothesis, engine = prepared(events)
    items = engine.low_and_slow_hunt(evidence, hypothesis, NOW)
    assert len(items) == 1
    assert len(items[0].evidence_event_ids) == 6
    assert "DISTRIBUTED_DENIAL_PATTERN" in items[0].reason_codes


def test_bursty_denials_are_not_mislabeled_low_and_slow():
    events = valid_events()
    for index in range(6):
        events.append(lab.event_fixture(
            event_id=f"EV-BURST-{index}", source_id="source:gateway",
            kind=lab.EventKind.POLICY, outcome=lab.Outcome.DENIED,
            occurred_at=NOW + timedelta(seconds=index), observed_at=NOW + timedelta(seconds=index + 1),
            ingested_at=NOW + timedelta(seconds=index + 2),
        ))
    evidence, hypothesis, engine = prepared(events)
    assert engine.low_and_slow_hunt(evidence, hypothesis, NOW + timedelta(minutes=1)) == ()


def test_sequence_hunt_flags_unreviewed_operation_order_not_singletons():
    events = [
        lab.event_fixture(event_id="EV-S1", source_id="source:gateway", operation_id="OP-X", action="ticket.read"),
        lab.event_fixture(
            event_id="EV-S2", source_id="source:network", kind=lab.EventKind.NETWORK,
            operation_id="OP-X", action="ticket.export", occurred_at=NOW + timedelta(seconds=2),
            observed_at=NOW + timedelta(seconds=3), ingested_at=NOW + timedelta(seconds=4),
        ),
    ]
    evidence, hypothesis, engine = prepared(events)
    items = engine.sequence_hunt(evidence, hypothesis, NOW + timedelta(seconds=5))
    assert len(items) == 1
    assert items[0].entity_id == "OP-X"
    assert items[0].confidence == lab.Confidence.LOW


def test_graph_hunt_flags_unapproved_edges_without_cross_tenant_join():
    events = [
        lab.event_fixture(event_id="EV-G", source_id="source:gateway", principal_ref="principal:hmac:bob"),
        valid_events()[1],
    ]
    evidence, hypothesis, engine = prepared(events)
    items = engine.graph_hunt(evidence, hypothesis, NOW)
    assert any(item.entity_id == "principal:hmac:bob->server:support" for item in items)
    assert all(item.tenant_id == "tenant:acme" for item in items)


def test_finding_builder_rejects_empty_or_cross_tenant_evidence():
    hypothesis = lab.demo_hypothesis()
    with pytest.raises(lab.HuntError) as exc:
        lab.finding(hypothesis, lab.HuntMethod.INVARIANT, "tenant:acme", "server:x", "x", [], ["X"], NOW)
    assert err(exc) == "FINDING_EVIDENCE_INVALID"
    beta = lab.event_fixture(event_id="EV-B", tenant_id="tenant:beta")
    with pytest.raises(lab.HuntError) as exc:
        lab.finding(hypothesis, lab.HuntMethod.INVARIANT, "tenant:acme", "server:x", "x", [beta], ["X"], NOW)
    assert err(exc) == "FINDING_EVIDENCE_INVALID"


@pytest.mark.parametrize("role", ["model", "viewer", "detection_reviewer"])
def test_only_analyst_roles_can_disposition_findings(role):
    item = supported_finding()
    with pytest.raises(lab.HuntError) as exc:
        lab.disposition_finding(item, "analyst:x", role, lab.Disposition.BENIGN, "reviewed change", NOW)
    assert err(exc) == "ANALYST_ROLE_INVALID"


def test_disposition_requires_terminal_state_and_rationale_and_preserves_evidence():
    item = replace(supported_finding(), disposition=lab.Disposition.CANDIDATE)
    for state, rationale in ((lab.Disposition.CANDIDATE, "x"), (lab.Disposition.INCONCLUSIVE, "")):
        with pytest.raises(lab.HuntError) as exc:
            lab.disposition_finding(item, "analyst:x", "threat_hunter", state, rationale, NOW)
        assert err(exc) == "DISPOSITION_INVALID"
    updated, record = lab.disposition_finding(item, "analyst:x", "threat_hunter", lab.Disposition.BENIGN, "approved maintenance", NOW)
    assert updated.disposition == lab.Disposition.BENIGN
    assert record.evidence_event_ids == item.evidence_event_ids
    assert record.finding_digest == lab.digest(item)


@pytest.mark.parametrize("role", ["model", "threat_hunter", "administrator"])
def test_detection_promotion_requires_peer_reviewer(role):
    item = supported_finding()
    candidate = candidate_for(item)
    with pytest.raises(lab.HuntError) as exc:
        lab.DetectionRegistry().issue_promotion(candidate, "reviewer:x", role, NOW)
    assert err(exc) == "REVIEWER_ROLE_INVALID"


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), timedelta(hours=2)])
def test_promotion_ttl_is_bounded(ttl):
    item = supported_finding()
    with pytest.raises(lab.HuntError) as exc:
        lab.DetectionRegistry().issue_promotion(candidate_for(item), "reviewer:x", "detection_reviewer", NOW, ttl)
    assert err(exc) == "PROMOTION_TTL_INVALID"


def test_registry_requires_supported_source_findings():
    supported = supported_finding()
    candidate = candidate_for(supported)
    registry = lab.DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:x", "detection_reviewer", NOW)
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [])
    assert err(exc) == "PROMOTION_EVIDENCE_INVALID"
    candidate_finding = replace(supported, disposition=lab.Disposition.CANDIDATE)
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [candidate_finding])
    assert err(exc) == "PROMOTION_EVIDENCE_INVALID"
    wrong_hypothesis = replace(supported, hypothesis_id="HYP-OTHER")
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [wrong_hypothesis])
    assert err(exc) == "PROMOTION_EVIDENCE_INVALID"


def test_promotion_is_signed_exact_expiring_and_single_use():
    item = supported_finding()
    candidate = candidate_for(item)
    registry = lab.DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:x", "detection_reviewer", NOW)
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, replace(receipt, signature="00" * 64), NOW + timedelta(seconds=1), [item])
    assert err(exc) == "PROMOTION_SIGNATURE_INVALID"
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(replace(candidate, title="changed"), receipt, NOW + timedelta(seconds=1), [item])
    assert err(exc) == "PROMOTION_SCOPE_MISMATCH"
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, receipt.expires_at, [item])
    assert err(exc) == "PROMOTION_EXPIRED"
    promoted = registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [item])
    assert promoted.state == lab.DetectionState.TEST
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, NOW + timedelta(seconds=2), [item])
    assert err(exc) == "PROMOTION_REPLAYED"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"source_finding_ids": ()}, "CANDIDATE_INCOMPLETE"),
        ({"query_contract": ""}, "CANDIDATE_INCOMPLETE"),
        ({"required_fields": ()}, "CANDIDATE_INCOMPLETE"),
        ({"precision": -0.1}, "CANDIDATE_METRICS_INVALID"),
        ({"recall": 1.1}, "CANDIDATE_METRICS_INVALID"),
        ({"state": lab.DetectionState.TEST}, "CANDIDATE_STATE_INVALID"),
    ],
)
def test_detection_candidate_requires_evidence_query_metrics_and_state(changes, expected):
    item = supported_finding()
    candidate = replace(candidate_for(item), **changes)
    registry = lab.DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:x", "detection_reviewer", NOW)
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [item])
    assert err(exc) == expected


def test_detection_version_conflict_is_rejected():
    item = supported_finding()
    candidate = candidate_for(item)
    registry = lab.DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:x", "detection_reviewer", NOW)
    registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [item])
    changed = replace(candidate, title="different")
    changed_receipt = registry.issue_promotion(changed, "reviewer:y", "detection_reviewer", NOW + timedelta(seconds=2))
    with pytest.raises(lab.HuntError) as exc:
        registry.register_test(changed, changed_receipt, NOW + timedelta(seconds=3), [item])
    assert err(exc) == "DETECTION_VERSION_CONFLICT"


def test_concurrent_promotion_consumes_receipt_once():
    item = supported_finding()
    candidate = candidate_for(item)
    registry = lab.DetectionRegistry()
    receipt = registry.issue_promotion(candidate, "reviewer:x", "detection_reviewer", NOW)

    def promote(_):
        try:
            return registry.register_test(candidate, receipt, NOW + timedelta(seconds=1), [item]).state
        except lab.HuntError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(promote, range(16)))
    assert results.count(lab.DetectionState.TEST) == 1
    assert results.count("PROMOTION_REPLAYED") == 15


def test_hunt_metrics_disclose_population_workload_and_latency():
    episodes = [
        lab.LabelledEpisode("M1", True, ("F1",), NOW, NOW + timedelta(seconds=30), 10, 100),
        lab.LabelledEpisode("M2", True, (), NOW, None, 5, 100),
        lab.LabelledEpisode("V1", False, ("F2",), NOW, NOW + timedelta(seconds=5), 8, 400),
        lab.LabelledEpisode("V2", False, (), NOW, None, 2, 400),
    ]
    metrics = lab.hunt_metrics(episodes)
    assert metrics["population"] == 4
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["median_time_to_finding_seconds"] == 30
    assert metrics["findings_per_1000_events"] == 2
    assert metrics["analyst_minutes_per_detected_malicious_episode"] == 25


def test_hunt_metrics_do_not_fabricate_missing_denominators():
    metrics = lab.hunt_metrics([
        lab.LabelledEpisode("V", False, (), NOW, None, 0, 0)
    ])
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["median_time_to_finding_seconds"] is None
    assert metrics["findings_per_1000_events"] is None
    assert metrics["analyst_minutes_per_detected_malicious_episode"] is None
    with pytest.raises(ValueError):
        lab.hunt_metrics([])
