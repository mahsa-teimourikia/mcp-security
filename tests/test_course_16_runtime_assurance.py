"""Executable invariants for Course 16 runtime observability and assurance."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import sys

from hypothesis import given, settings, strategies as st
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/16-runtime-observability-continuous-assurance/lab.py"
SPEC = importlib.util.spec_from_file_location("course_16_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.utc("2026-10-04T18:30:00Z")
IDENTITY = lab.TrustedIdentity("analyst-42", "acme", frozenset({"ticket:read"}))
CASES = lab.scenarios()


def scenario(scenario_id):
    return next(item for item in CASES if item.scenario_id == scenario_id)


def events(scenario_id="safe-read"):
    return lab.build_scenario_events(scenario(scenario_id), NOW)


def collector_for(event=None):
    emitter = event.emitter_id if event else "support.host"
    return lab.SecureCollector(signing_keys={emitter: lab.SIGNING_KEY})


def ingest_all(items, observed_offset_ms=4):
    collector = collector_for(items[0])
    results = [
        collector.ingest(item, item.occurred_at + timedelta(milliseconds=observed_offset_ms))
        for item in items
    ]
    return collector, results


def config():
    return lab.AssuranceConfig(
        lab.REVIEWED_SERVER_DIGEST,
        lab.REVIEWED_CONTRACT_DIGEST,
        frozenset({lab.keyed_digest("mailto:buyer@acme.test")}),
    )


def test_demo_reports_perfect_labelled_detection_and_safe_completion():
    demo = lab.run_demo()
    assert demo["confusion_matrix"] == {
        "true_positive": 6,
        "false_positive": 0,
        "true_negative": 3,
        "false_negative": 0,
    }
    assert demo["metrics"]["precision"] == 1.0
    assert demo["metrics"]["recall"] == 1.0
    assert demo["metrics"]["safe_task_completion_rate"] == 1.0
    assert all(item["passed"] for item in demo["slo_results"])


def test_demo_uses_real_opentelemetry_sdk_without_network_export():
    otel = lab.run_demo()["otel"]
    assert otel["one_trace"] is True
    assert otel["parent_links_valid"] is True
    assert otel["traceparent_present"] is True
    assert set(otel["span_names"]) == {
        "support.request",
        "mcp.tools.call",
        "ticket.backend.read",
    }


def test_utc_requires_an_explicit_utc_offset():
    assert lab.utc("2026-10-04T18:30:00Z") == NOW
    with pytest.raises(ValueError, match="UTC"):
        lab.utc("2026-10-04T18:30:00")
    with pytest.raises(ValueError, match="UTC"):
        lab.utc("2026-10-04T11:30:00-07:00")


def test_canonical_json_and_digest_are_order_stable():
    left = {"b": 2, "a": 1}
    right = {"a": 1, "b": 2}
    assert lab.canonical_json(left) == lab.canonical_json(right)
    assert lab.digest(left) == lab.digest(right)


def test_pseudonyms_are_stable_but_key_separated():
    assert lab.keyed_digest("analyst-42") == lab.keyed_digest("analyst-42")
    assert lab.keyed_digest("analyst-42") != lab.keyed_digest("analyst-42", b"other")
    assert "analyst-42" not in lab.keyed_digest("analyst-42")


def test_emitter_minimizes_identity_destination_and_arguments():
    item = events("safe-message")[0]
    serialized = lab.canonical_json(item.__dict__).decode()
    assert item.principal_pseudonym == lab.keyed_digest("analyst-42")
    assert item.tenant_pseudonym == lab.keyed_digest("acme")
    assert item.destination_digest == lab.keyed_digest("mailto:buyer@acme.test")
    assert "analyst-42" not in serialized
    assert "buyer@acme.test" not in serialized
    assert "Your payment is confirmed" not in serialized
    assert "arguments" not in item.__dict__


def test_argument_body_is_hashed_not_exported():
    first = events("safe-message")[0]
    expected = lab.digest({
        "ticket_id": "acme-7",
        "recipient": "buyer@acme.test",
        "body": "Your payment is confirmed.",
    })
    assert first.argument_digest == expected


@pytest.mark.parametrize(
    "secret_key",
    ["token", "Authorization", "cookie", "api_key", "access-token", "client_secret"],
)
def test_secret_bearing_argument_keys_are_rejected(secret_key):
    emitter = lab.TelemetryEmitter("support.host", IDENTITY)
    template = replace(
        lab.EventTemplate(
            "evt-secret", NOW, "1" * 32, "2" * 16, None, lab.Phase.REQUEST,
            "op-secret", lab.REVIEWED_SERVER_DIGEST, "3.2.0", "ticket.read",
            lab.REVIEWED_CONTRACT_DIGEST, lab.Risk.READ, None,
            {"metadata": {secret_key: "secret"}}, lab.PolicyDecision.NOT_APPLICABLE,
            "REQUEST_RECEIVED", lab.Outcome.PENDING,
        )
    )
    with pytest.raises(ValueError, match="secret-bearing"):
        emitter.emit(template)


def test_non_object_arguments_are_rejected():
    emitter = lab.TelemetryEmitter("support.host", IDENTITY)
    template = lab.EventTemplate(
        "evt-bad-args", NOW, "1" * 32, "2" * 16, None, lab.Phase.REQUEST,
        "op-bad-args", lab.REVIEWED_SERVER_DIGEST, "3.2.0", "ticket.read",
        lab.REVIEWED_CONTRACT_DIGEST, lab.Risk.READ, None, [],
        lab.PolicyDecision.NOT_APPLICABLE, "REQUEST_RECEIVED", lab.Outcome.PENDING,
    )
    with pytest.raises(ValueError, match="object"):
        emitter.emit(template)


def test_argument_digest_budget_is_enforced():
    emitter = lab.TelemetryEmitter("support.host", IDENTITY)
    template = lab.EventTemplate(
        "evt-large", NOW, "1" * 32, "2" * 16, None, lab.Phase.REQUEST,
        "op-large", lab.REVIEWED_SERVER_DIGEST, "3.2.0", "ticket.read",
        lab.REVIEWED_CONTRACT_DIGEST, lab.Risk.READ, None, {"value": "x" * 3_000},
        lab.PolicyDecision.NOT_APPLICABLE, "REQUEST_RECEIVED", lab.Outcome.PENDING,
    )
    with pytest.raises(ValueError, match="budget"):
        emitter.emit(template)


def test_emitter_rejects_invalid_emitter_identity():
    with pytest.raises(ValueError, match="emitter"):
        lab.TelemetryEmitter("../../host", IDENTITY)


def test_event_chain_increments_sequence_and_binds_previous_hash():
    items = events()
    assert [item.sequence for item in items] == [1, 2, 3, 4]
    assert items[0].previous_event_hash is None
    for previous, current in zip(items, items[1:]):
        assert current.previous_event_hash == previous.event_hash


def test_every_emitted_event_hash_and_signature_are_valid():
    items = events()
    for item in items:
        assert lab.digest(item.unsigned()) == item.event_hash
        assert len(item.signature) == 64


def test_collector_accepts_a_complete_valid_chain():
    collector, results = ingest_all(events())
    assert all(result.status == lab.IngestStatus.ACCEPTED for result in results)
    assert len(collector.events) == 4
    assert not collector.rejections
    assert all(result.ingestion_delay_ms == 4 for result in results)


@pytest.mark.parametrize("field,value,reason", [
    ("schema_version", "mcp.security.event/9", "SCHEMA_VERSION_UNSUPPORTED"),
    ("occurred_at", "2026-10-04T18:30:00Z", "TIMESTAMP_INVALID"),
    ("event_id", "bad", "IDENTIFIER_INVALID"),
    ("emitter_id", "../../bad", "IDENTIFIER_INVALID"),
    ("trace_id", "abc", "TRACE_CONTEXT_INVALID"),
    ("span_id", "abc", "TRACE_CONTEXT_INVALID"),
    ("parent_span_id", "abc", "TRACE_CONTEXT_INVALID"),
    ("server_digest", "latest", "ARTIFACT_DIGEST_INVALID"),
    ("tool_contract_digest", "v8", "ARTIFACT_DIGEST_INVALID"),
    ("principal_pseudonym", "analyst-42", "PSEUDONYM_INVALID"),
    ("tenant_pseudonym", "acme", "PSEUDONYM_INVALID"),
    ("destination_digest", "mailto:test@example.test", "DESTINATION_DIGEST_INVALID"),
    ("argument_digest", "sha256:nope", "EVENT_INTEGRITY_FIELD_INVALID"),
    ("event_hash", "sha256:nope", "EVENT_INTEGRITY_FIELD_INVALID"),
    ("signature", "not-a-signature", "EVENT_INTEGRITY_FIELD_INVALID"),
    ("tool_name", "Ticket Read", "ATTRIBUTE_INVALID"),
    ("reason_code", "free form", "ATTRIBUTE_INVALID"),
    ("sequence", 0, "ATTRIBUTE_INVALID"),
    ("duration_ms", -1, "MEASUREMENT_INVALID"),
    ("input_tokens", -1, "MEASUREMENT_INVALID"),
    ("output_tokens", -1, "MEASUREMENT_INVALID"),
    ("cost_microusd", -1, "MEASUREMENT_INVALID"),
])
def test_collector_rejects_invalid_schema_fields(field, value, reason):
    item = replace(events()[1], **{field: value})
    result = collector_for(item).ingest(item, item.occurred_at)
    assert result.status == lab.IngestStatus.REJECTED
    assert result.reason_code == reason


def test_collector_rejects_duplicate_event_id():
    item = events()[0]
    collector = collector_for(item)
    assert collector.ingest(item, item.occurred_at).status == lab.IngestStatus.ACCEPTED
    replay = collector.ingest(item, item.occurred_at)
    assert replay.reason_code == "EVENT_REPLAY"


@pytest.mark.parametrize("offset,reason", [
    (timedelta(seconds=-6), "EVENT_FROM_FUTURE"),
    (timedelta(minutes=6), "EVENT_TOO_OLD"),
])
def test_collector_enforces_event_time_window(offset, reason):
    item = events()[0]
    result = collector_for(item).ingest(item, item.occurred_at + offset)
    assert result.reason_code == reason


def test_collector_rejects_untrusted_emitter():
    item = events()[0]
    result = lab.SecureCollector(signing_keys={}).ingest(item, item.occurred_at)
    assert result.reason_code == "EMITTER_NOT_TRUSTED"


def test_collector_rejects_changed_signed_content():
    item = replace(events()[0], tool_name="admin.run")
    result = collector_for(item).ingest(item, item.occurred_at)
    assert result.reason_code == "EVENT_HASH_INVALID"


def test_collector_rejects_bad_signature_even_with_valid_hash():
    item = replace(events()[0], signature="0" * 64)
    result = collector_for(item).ingest(item, item.occurred_at)
    assert result.reason_code == "EVENT_SIGNATURE_INVALID"


def test_collector_rejects_chain_starting_after_sequence_one():
    item = events()[1]
    result = collector_for(item).ingest(item, item.occurred_at)
    assert result.reason_code == "EVENT_CHAIN_INVALID"


def test_collector_rejects_gap_after_valid_first_event():
    first, _, third, _ = events()
    collector = collector_for(first)
    assert collector.ingest(first, first.occurred_at).status == lab.IngestStatus.ACCEPTED
    assert collector.ingest(third, third.occurred_at).reason_code == "EVENT_CHAIN_INVALID"


def test_collector_tracks_emitter_chains_independently():
    first = events()[0]
    other_identity = lab.TrustedIdentity("analyst-77", "globex", frozenset())
    template = lab.EventTemplate(
        "evt-other-request", NOW, "a" * 32, "b" * 16, None, lab.Phase.REQUEST,
        "op-other", lab.REVIEWED_SERVER_DIGEST, "3.2.0", "ticket.read",
        lab.REVIEWED_CONTRACT_DIGEST, lab.Risk.READ, None, {"ticket_id": "globex-9"},
        lab.PolicyDecision.NOT_APPLICABLE, "REQUEST_RECEIVED", lab.Outcome.PENDING,
    )
    other = lab.TelemetryEmitter("other.host", other_identity).emit(template)
    collector = lab.SecureCollector(
        signing_keys={"support.host": lab.SIGNING_KEY, "other.host": lab.SIGNING_KEY}
    )
    assert collector.ingest(first, NOW).status == lab.IngestStatus.ACCEPTED
    assert collector.ingest(other, NOW).status == lab.IngestStatus.ACCEPTED


def test_trace_verifier_accepts_complete_allowed_trace():
    finding = lab.TraceVerifier().review(events("safe-read"))
    assert finding.complete
    assert finding.violations == ()
    assert finding.duration_ms == 21


def test_trace_verifier_accepts_complete_denied_trace_without_effect():
    finding = lab.TraceVerifier().review(events("clean-denial"))
    assert finding.complete
    assert finding.violations == ()


def test_trace_verifier_rejects_empty_trace():
    finding = lab.TraceVerifier().review(())
    assert finding.violations == ("TRACE_EMPTY",)


def test_trace_verifier_detects_missing_policy_phase():
    finding = lab.TraceVerifier().review(events("missing-policy-event"))
    assert not finding.complete
    assert "TRACE_PHASE_ORDER_INVALID" in finding.violations


def test_trace_verifier_detects_effect_after_denial():
    finding = lab.TraceVerifier().review(events("effect-after-deny"))
    assert not finding.complete
    assert "EFFECT_AFTER_DENY" in finding.violations


def test_trace_verifier_detects_missing_effect_evidence():
    items = tuple(item for item in events("safe-read") if item.phase != lab.Phase.EFFECT)
    finding = lab.TraceVerifier().review(items)
    assert "EFFECT_EVIDENCE_MISSING" in finding.violations


def test_trace_verifier_detects_allow_block_mismatch():
    items = list(events("safe-read"))
    items[-1] = replace(items[-1], outcome=lab.Outcome.BLOCKED)
    finding = lab.TraceVerifier().review(items)
    assert "ALLOW_OUTCOME_MISMATCH" in finding.violations


def test_trace_verifier_detects_context_drift():
    items = list(events())
    items[-1] = replace(items[-1], tenant_pseudonym=lab.keyed_digest("globex"))
    finding = lab.TraceVerifier().review(items)
    assert "TRACE_CONTEXT_DRIFT" in finding.violations


@pytest.mark.parametrize(
    "field,value",
    [
        ("argument_digest", lab.digest({"ticket_id": "other"})),
        ("destination_digest", lab.keyed_digest("mailto:other@example.test")),
        ("risk", lab.Risk.ADMIN),
    ],
)
def test_trace_verifier_detects_action_context_drift(field, value):
    items = list(events("safe-message"))
    items[-1] = replace(items[-1], **{field: value})
    assert "TRACE_CONTEXT_DRIFT" in lab.TraceVerifier().review(items).violations


def test_trace_verifier_detects_root_parent():
    items = list(events())
    items[0] = replace(items[0], parent_span_id="f" * 16)
    assert "TRACE_ROOT_HAS_PARENT" in lab.TraceVerifier().review(items).violations


def test_trace_verifier_detects_invalid_child_parent():
    items = list(events())
    items[2] = replace(items[2], parent_span_id="f" * 16)
    assert "TRACE_PARENT_INVALID" in lab.TraceVerifier().review(items).violations


def test_trace_verifier_detects_mixed_trace_ids():
    items = list(events())
    items[-1] = replace(items[-1], trace_id="f" * 32)
    assert "MIXED_TRACE_IDS" in lab.TraceVerifier().review(items).violations


def test_trace_verifier_detects_duplicate_phase_cardinality():
    items = list(events())
    items.insert(1, replace(items[0], event_id="evt-duplicate-request"))
    finding = lab.TraceVerifier().review(items)
    assert "TRACE_CARDINALITY_INVALID" in finding.violations


def test_assurance_engine_does_not_signal_reviewed_baseline():
    engine = lab.AssuranceEngine(config())
    assert all(engine.assess_event(item, item.occurred_at) is None for item in events())


@pytest.mark.parametrize("scenario_id,action,reason", [
    ("artifact-drift", lab.ControlAction.QUARANTINE, "SERVER_ARTIFACT_DRIFT"),
    ("contract-drift", lab.ControlAction.QUARANTINE, "TOOL_CONTRACT_DRIFT"),
    ("unapproved-egress", lab.ControlAction.REVOKE, "DESTINATION_NOT_APPROVED"),
    ("effect-after-deny", lab.ControlAction.REVOKE, "EFFECT_AFTER_DENY"),
])
def test_assurance_engine_maps_deterministic_violation_to_bounded_control(
    scenario_id, action, reason
):
    result = lab.run_scenario(scenario(scenario_id), NOW)
    assert result.detected
    assert result.signal.action == action
    assert result.signal.reason_code == reason


def test_repeated_denials_create_review_only_at_threshold():
    engine = lab.AssuranceEngine(config())
    policy_event = next(item for item in events("clean-denial") if item.phase == lab.Phase.POLICY)
    assert engine.assess_event(policy_event, NOW) is None
    assert engine.assess_event(policy_event, NOW) is None
    signal = engine.assess_event(policy_event, NOW)
    assert signal.action == lab.ControlAction.REVIEW
    assert signal.reason_code == "REPEATED_POLICY_DENIAL"


def test_trace_gap_creates_review_not_authority():
    result = lab.run_scenario(scenario("missing-policy-event"), NOW)
    assert result.signal.action == lab.ControlAction.REVIEW
    assert result.control_result == "REVIEW_CREATED"


def test_tampered_event_quarantines_emitter():
    result = lab.run_scenario(scenario("tampered-event"), NOW)
    assert result.rejected_events == 1
    assert result.signal.reason_code == "EVENT_SIGNATURE_INVALID"
    assert result.signal.action == lab.ControlAction.QUARANTINE


def test_control_plane_applies_quarantine_and_revoke_as_state():
    control = lab.ControlPlane()
    quarantine = lab.Signal("s1", "t1", lab.Severity.CRITICAL,
                            lab.ControlAction.QUARANTINE, "DRIFT", "digest-1", NOW)
    revoke = replace(quarantine, signal_id="s2", action=lab.ControlAction.REVOKE,
                     target_digest="digest-2")
    assert control.apply(quarantine) == "TARGET_QUARANTINED"
    assert control.apply(revoke) == "TARGET_REVOKED"
    assert control.quarantined_digests == {"digest-1"}
    assert control.revoked_digests == {"digest-2"}


def test_control_plane_never_accepts_noop_as_authority():
    signal = lab.Signal("s", "t", lab.Severity.INFO, lab.ControlAction.NONE,
                        "NONE", None, NOW)
    with pytest.raises(ValueError, match="no-op"):
        lab.ControlPlane().apply(signal)


def test_control_plane_requires_target_for_deny_control():
    signal = lab.Signal("s", "t", lab.Severity.CRITICAL, lab.ControlAction.REVOKE,
                        "BAD", None, NOW)
    assert lab.ControlPlane().apply(signal) == "TARGET_REQUIRED"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.scenario_id)
def test_labelled_scenarios_match_detector_decision(case):
    result = lab.run_scenario(case, NOW)
    assert result.detected is case.expected_signal


@pytest.mark.parametrize("scenario_id", ["safe-read", "safe-message"])
def test_valid_safe_tasks_complete_without_signal(scenario_id):
    result = lab.run_scenario(scenario(scenario_id), NOW)
    assert result.safe_task_completed
    assert result.signal is None
    assert result.trace_finding.complete


def test_clean_policy_denial_is_not_a_false_positive_or_safe_task():
    result = lab.run_scenario(scenario("clean-denial"), NOW)
    assert not result.detected
    assert not result.safe_task_completed
    assert result.trace_finding.complete


def test_campaign_metrics_keep_detection_and_safe_completion_denominators_separate():
    report = lab.run_campaign(CASES, NOW)
    assert report.confusion == lab.ConfusionMatrix(6, 0, 3, 0)
    metrics = report.metrics()
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_review_rate"] == 0.0
    assert metrics["safe_task_completion_rate"] == 1.0


def test_campaign_rejects_empty_or_duplicate_case_set():
    with pytest.raises(ValueError, match="between"):
        lab.run_campaign((), NOW)
    case = scenario("safe-read")
    with pytest.raises(ValueError, match="unique"):
        lab.run_campaign((case, case), NOW)


def test_campaign_enforces_size_budget():
    seed = scenario("safe-read")
    cases = tuple(replace(seed, scenario_id=f"case-{index}") for index in range(101))
    with pytest.raises(ValueError, match="between"):
        lab.run_campaign(cases, NOW)


def test_slo_definitions_include_units_direction_and_threshold():
    metrics = lab.run_campaign(CASES, NOW).metrics()
    results = lab.evaluate_slos(metrics)
    assert {item.name for item in results} == {
        "recall", "false_review_rate", "safe_task_completion_rate",
        "mean_detection_delay_ms",
    }
    assert all(item.direction in {">=", "<="} for item in results)
    assert all(item.passed for item in results)


def test_slo_gate_fails_bad_detection_and_safe_task_metrics():
    bad = {
        "recall": 0.5,
        "false_review_rate": 0.5,
        "safe_task_completion_rate": 0.5,
        "mean_detection_delay_ms": 100.0,
    }
    assert not any(item.passed for item in lab.evaluate_slos(bad))


@pytest.mark.parametrize("successes,attempts", [(0, 10), (1, 10), (5, 10), (10, 10)])
def test_wilson_interval_contains_observed_rate(successes, attempts):
    low, high = lab.wilson_interval(successes, attempts)
    assert 0 <= low <= successes / attempts <= high <= 1


@pytest.mark.parametrize("successes,attempts", [(0, 0), (-1, 10), (11, 10)])
def test_wilson_interval_rejects_invalid_population(successes, attempts):
    with pytest.raises(ValueError, match="invalid"):
        lab.wilson_interval(successes, attempts)


def test_otel_probe_uses_one_trace_and_valid_parent_chain():
    evidence = lab.run_otel_probe()
    assert evidence.one_trace
    assert evidence.parent_links_valid
    assert evidence.traceparent.startswith("00-")
    assert len(evidence.traceparent) == 55


def test_otel_probe_uses_safe_bounded_attribute_set():
    evidence = lab.run_otel_probe()
    assert "mcp.tool.arguments.digest" in evidence.safe_attribute_keys
    forbidden_fragments = {"prompt", "content", "reasoning", "authorization", "token"}
    assert not any(
        fragment in key
        for key in evidence.safe_attribute_keys
        for fragment in forbidden_fragments
    )


@given(st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=64))
@settings(max_examples=40, deadline=None)
def test_property_message_body_never_appears_in_emitted_event(suffix):
    body = f"SENSITIVE-BODY-{suffix}"
    case = replace(
        scenario("safe-message"),
        arguments=(("ticket_id", "acme-7"), ("recipient", "buyer@acme.test"), ("body", body)),
    )
    item = lab.build_scenario_events(case, NOW)[0]
    serialized = json.dumps(lab._jsonable(item.__dict__), sort_keys=True)
    assert body not in serialized
    assert item.argument_digest == lab.digest(dict(case.arguments))


@given(st.integers(min_value=0, max_value=300_000))
@settings(max_examples=40, deadline=None)
def test_property_accepted_ingestion_delay_is_measured_from_event_time(delay_ms):
    item = events()[0]
    result = collector_for(item).ingest(
        item, item.occurred_at + timedelta(milliseconds=delay_ms)
    )
    assert result.status == lab.IngestStatus.ACCEPTED
    assert result.ingestion_delay_ms == delay_ms
