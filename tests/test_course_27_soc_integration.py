"""Executable security and pedagogy invariants for Course 27."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/27-mcp-security-observability-soc-integration/lab.py"
SPEC = importlib.util.spec_from_file_location("course_27_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.NOW


def components():
    return lab.demo_components()


def normalize(**changes):
    emitter, normalizer, *_ = components()
    signed = lab.event_fixture(emitter, **changes)
    return normalizer.normalize(signed, changes.get("observed_at", NOW + timedelta(seconds=1)) + timedelta(seconds=1))


def admitted_alert(**changes):
    emitter, normalizer, store, detector, router, approvals, controller = components()
    signed = lab.event_fixture(emitter, **changes)
    event = normalizer.normalize(signed, changes.get("observed_at", NOW + timedelta(seconds=1)) + timedelta(seconds=1))
    store.ingest(event)
    alerts = detector.evaluate(event, event.observed_at + timedelta(seconds=1))
    return event, alerts, router, approvals, controller


def response_fixture():
    event, alerts, router, approvals, controller = admitted_alert(
        event_id="EV-EGRESS", kind=lab.EventKind.NETWORK, action="ticket.export",
        destination="evil.example", outcome=lab.Outcome.SUCCEEDED,
    )
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-003")
    case = router.route(alert, NOW + timedelta(seconds=3))
    case = router.transition(case.case_id, lab.CaseState.OPEN, lab.CaseState.ACKNOWLEDGED)
    case = router.transition(case.case_id, lab.CaseState.ACKNOWLEDGED, lab.CaseState.RESPONSE_PENDING)
    proposal = lab.ResponseProposal(
        "PROP-1", case.case_id, "tenant:acme", lab.ActionKind.DISABLE_SERVER,
        "server:support", "verified unapproved egress", 7, "analyst:oncall",
        NOW + timedelta(seconds=4),
    )
    receipt = approvals.issue(proposal, "commander:oncall", "incident_commander", NOW + timedelta(seconds=5))
    return event, alert, case, router, approvals, controller, proposal, receipt


def code(exc):
    return exc.value.code


def test_demo_routes_evidence_and_verifies_containment(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"alert": "MCP-SOC-003"' in output
    assert '"case_state": "contained"' in output
    assert '"verified": true' in output
    assert '"otel_spans": 1' in output


def test_signed_event_round_trip_and_trusted_inventory_enrichment():
    event = normalize()
    assert event.owner == "team:support-platform"
    assert event.soc_route == "soc:acme"
    assert event.artifact_matches and event.capability_matches
    assert event.policy_matches
    assert event.action_approved and event.destination_approved


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda env: replace(env, schema_version="mcp.security.event/9"), "SCHEMA_UNSUPPORTED"),
        (lambda env: replace(env, emitter_id="unknown"), "EMITTER_UNKNOWN"),
        (lambda env: replace(env, signature="00" * 64), "SIGNATURE_INVALID"),
        (lambda env: replace(env, event=replace(env.event, action="ticket.delete")), "SIGNATURE_INVALID"),
    ],
)
def test_envelope_authentication_rejects_unknown_stale_or_tampered_content(mutation, expected):
    emitter, normalizer, *_ = components()
    envelope = mutation(lab.event_fixture(emitter))
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(envelope, NOW + timedelta(seconds=2))
    assert code(exc) == expected


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"event_id": "bad id"}, "EVENT_FIELD_INVALID"),
        ({"tenant_id": "bad tenant"}, "EVENT_FIELD_INVALID"),
        ({"resource_tenant": "bad tenant"}, "EVENT_FIELD_INVALID"),
        ({"principal_ref": "bad principal"}, "EVENT_FIELD_INVALID"),
        ({"workload_id": "bad workload"}, "EVENT_FIELD_INVALID"),
        ({"server_id": "bad server"}, "EVENT_FIELD_INVALID"),
        ({"operation_id": "bad operation"}, "EVENT_FIELD_INVALID"),
        ({"action": "bad action!"}, "EVENT_FIELD_INVALID"),
        ({"resource_id": "bad resource!"}, "EVENT_FIELD_INVALID"),
        ({"capability_version": "bad version!"}, "EVENT_FIELD_INVALID"),
        ({"policy_version": "bad version!"}, "EVENT_FIELD_INVALID"),
        ({"destination": "evil.example\nforged"}, "DESTINATION_INVALID"),
        ({"destination": "https://evil.example/path"}, "DESTINATION_INVALID"),
        ({"policy_decision": "maybe"}, "POLICY_DECISION_INVALID"),
        ({"sequence": 0}, "SEQUENCE_INVALID"),
        ({"trace_id": "1" * 31}, "TRACE_CONTEXT_INVALID"),
        ({"trace_id": "G" * 32}, "TRACE_CONTEXT_INVALID"),
        ({"span_id": "2" * 15}, "TRACE_CONTEXT_INVALID"),
        ({"artifact_digest": "sha256:nope"}, "ARTIFACT_DIGEST_INVALID"),
    ],
)
def test_event_contract_rejects_malformed_identifiers(changes, expected):
    emitter, normalizer, *_ = components()
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(lab.event_fixture(emitter, **changes), NOW + timedelta(seconds=2))
    assert code(exc) == expected


@pytest.mark.parametrize(
    ("changes", "received", "expected"),
    [
        ({"occurred_at": NOW + timedelta(seconds=30)}, NOW + timedelta(seconds=2), "CLOCK_SKEW_EXCEEDED"),
        ({"observed_at": NOW + timedelta(seconds=30)}, NOW + timedelta(seconds=2), "CLOCK_SKEW_EXCEEDED"),
        ({"observed_at": NOW}, NOW + timedelta(minutes=11), "INGEST_DELAY_EXCEEDED"),
        ({"occurred_at": NOW.replace(tzinfo=None)}, NOW + timedelta(seconds=2), "TIME_INVALID"),
    ],
)
def test_time_validation_distinguishes_event_observed_and_ingest_time(changes, received, expected):
    emitter, normalizer, *_ = components()
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(lab.event_fixture(emitter, **changes), received)
    assert code(exc) == expected


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        ((('access_token', 'abc'),), "SENSITIVE_ATTRIBUTE"),
        ((('raw_prompt', 'ignore prior instructions'),), "SENSITIVE_ATTRIBUTE"),
        ((('user.secret_hint', 'abc'),), "SENSITIVE_ATTRIBUTE"),
        ((('safe', 'line1\nline2'),), "ATTRIBUTE_INVALID"),
        ((('safe', 'x' * 257),), "ATTRIBUTE_INVALID"),
        ((('a', '1'), ('A', '2')), "ATTRIBUTE_DUPLICATE"),
        (tuple((f"k{i}", "v") for i in range(17)), "ATTRIBUTES_EXCESSIVE"),
    ],
)
def test_privacy_and_log_injection_gate_rejects_dangerous_attributes(attributes, expected):
    emitter, normalizer, *_ = components()
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(lab.event_fixture(emitter, attributes=attributes), NOW + timedelta(seconds=2))
    assert code(exc) == expected


def test_producer_binding_prevents_self_asserted_tenant_and_workload():
    emitter, normalizer, *_ = components()
    for changes in ({"tenant_id": "tenant:beta"}, {"workload_id": "workload:shadow"}):
        with pytest.raises(lab.SOCError) as exc:
            normalizer.normalize(lab.event_fixture(emitter, **changes), NOW + timedelta(seconds=2))
        assert code(exc) == "PRODUCER_SCOPE_MISMATCH"


def test_producer_cannot_attest_unapproved_event_kind():
    emitter, _, *_ = components()
    inventory = lab.TrustedInventory([
        lab.InventoryRecord(
            "server:support", "workload:support-prod", "sha256:" + "a" * 64,
            "support-tools/7", frozenset({"tenant:acme"}), frozenset({"ticket.read"}),
            frozenset({"tickets.example.com"}), "team:support-platform", "soc:acme",
        )
    ])
    normalizer = lab.EventNormalizer([
        lab.ProducerBinding(emitter.emitter_id, emitter.public_key, frozenset({"tenant:acme"}),
                            frozenset({"workload:support-prod"}), frozenset({lab.EventKind.POLICY}))
    ], inventory)
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(lab.event_fixture(emitter, kind=lab.EventKind.NETWORK), NOW + timedelta(seconds=2))
    assert code(exc) == "EVENT_KIND_FORBIDDEN"


def test_unknown_inactive_and_unbound_inventory_states_fail_closed():
    emitter = lab.EventEmitter("gateway:prod")
    for record, expected, changes in [
        (lab.InventoryRecord("server:other", "workload:support-prod", "sha256:" + "a" * 64,
                             "support-tools/7", frozenset({"tenant:acme"}), frozenset({"ticket.read"}),
                             frozenset({"tickets.example.com"}), "owner", "soc:acme"), "SERVER_UNKNOWN", {}),
        (lab.InventoryRecord("server:support", "workload:support-prod", "sha256:" + "a" * 64,
                             "support-tools/7", frozenset({"tenant:acme"}), frozenset({"ticket.read"}),
                             frozenset({"tickets.example.com"}), "owner", "soc:acme", False), "SERVER_INACTIVE", {}),
        (lab.InventoryRecord("server:support", "workload:support-prod", "sha256:" + "a" * 64,
                             "support-tools/7", frozenset({"tenant:beta"}), frozenset({"ticket.read"}),
                             frozenset({"tickets.example.com"}), "owner", "soc:beta"), "TENANT_NOT_IN_INVENTORY", {}),
    ]:
        normalizer = lab.EventNormalizer([
            lab.ProducerBinding(emitter.emitter_id, emitter.public_key, frozenset({"tenant:acme"}),
                                frozenset({"workload:support-prod"}), frozenset(lab.EventKind))
        ], lab.TrustedInventory([record]))
        with pytest.raises(lab.SOCError) as exc:
            normalizer.normalize(lab.event_fixture(emitter, **changes), NOW + timedelta(seconds=2))
        assert code(exc) == expected


def test_inventory_binds_server_to_the_observed_workload():
    emitter = lab.EventEmitter("gateway:prod")
    inventory = lab.TrustedInventory([
        lab.InventoryRecord(
            "server:support", "workload:support-prod", "sha256:" + "a" * 64,
            "support-tools/7", frozenset({"tenant:acme"}), frozenset({"ticket.read"}),
            frozenset({"tickets.example.com"}), "owner", "soc:acme",
        )
    ])
    normalizer = lab.EventNormalizer([
        lab.ProducerBinding(
            emitter.emitter_id, emitter.public_key, frozenset({"tenant:acme"}),
            frozenset({"workload:support-prod", "workload:shadow"}), frozenset(lab.EventKind),
        )
    ], inventory)
    with pytest.raises(lab.SOCError) as exc:
        normalizer.normalize(
            lab.event_fixture(emitter, workload_id="workload:shadow"),
            NOW + timedelta(seconds=2),
        )
    assert code(exc) == "WORKLOAD_INVENTORY_MISMATCH"


def test_normalization_exposes_stable_otel_and_explicit_ocsf_mapping_layers():
    event = normalize()
    otel = event.otel_log_projection()
    assert otel["Timestamp"] == NOW
    assert otel["ObservedTimestamp"] == NOW + timedelta(seconds=1)
    assert otel["TraceId"] == "1" * 32
    assert otel["Resource"]["service.name"] == "server:support"
    assert "access_token" not in str(otel)
    ocsf = event.ocsf_projection()
    assert ocsf["metadata"]["version"] == "deployment-selected"
    assert ocsf["cloud"]["account"]["uid"] == "tenant:acme"


def test_event_store_is_idempotent_but_rejects_conflicting_replay():
    event = normalize()
    store = lab.EventStore()
    assert store.ingest(event).status == "accepted"
    assert store.ingest(event).status == "duplicate"
    with pytest.raises(lab.SOCError) as exc:
        store.ingest(replace(event, event_digest="sha256:" + "f" * 64))
    assert code(exc) == "EVENT_ID_CONFLICT"


def test_event_store_is_tenant_partitioned_and_bounded():
    store = lab.EventStore(max_events=3)
    base = normalize()
    for index in range(4):
        store.ingest(replace(base, event_id=f"EV-{index}", event_digest=f"sha256:{index:064x}"))
    assert [item.event_id for item in store.partitions["tenant:acme"]] == ["EV-1", "EV-2", "EV-3"]
    assert len(store.identities) == 3
    assert not store.contains("tenant:acme", "EV-0")
    assert store.recent("tenant:beta", NOW) == ()


@pytest.mark.parametrize(
    ("changes", "rule_id", "reason"),
    [
        ({"artifact_digest": "sha256:" + "b" * 64}, "MCP-SOC-001", "ARTIFACT_NOT_APPROVED"),
        ({"capability_version": "support-tools/8"}, "MCP-SOC-002", "CAPABILITY_POLICY_OR_ACTION_DRIFT"),
        ({"policy_version": "mcp-soc-policy/old"}, "MCP-SOC-002", "CAPABILITY_POLICY_OR_ACTION_DRIFT"),
        ({"action": "ticket.delete"}, "MCP-SOC-002", "CAPABILITY_POLICY_OR_ACTION_DRIFT"),
        ({"kind": lab.EventKind.NETWORK, "destination": "evil.example"}, "MCP-SOC-003", "DESTINATION_NOT_APPROVED"),
        ({"kind": lab.EventKind.RESOURCE, "resource_tenant": "tenant:beta"}, "MCP-SOC-004", "RESOURCE_TENANT_MISMATCH"),
    ],
)
def test_single_event_rules_produce_versioned_evidence_linked_alerts(changes, rule_id, reason):
    event, alerts, *_ = admitted_alert(**changes)
    alert = next(item for item in alerts if item.rule_id == rule_id)
    assert alert.rule_version
    assert alert.evidence_event_ids == (event.event_id,)
    assert alert.evidence_digest.startswith("sha256:")
    assert reason in alert.reason_codes
    assert alert.playbook.startswith("PB-")


def test_policy_denial_plus_successful_effect_correlates_by_exact_operation():
    emitter, normalizer, store, detector, *_ = components()
    denied = normalizer.normalize(lab.event_fixture(
        emitter, event_id="EV-DENY", kind=lab.EventKind.POLICY,
        outcome=lab.Outcome.DENIED, policy_decision="deny",
    ), NOW + timedelta(seconds=2))
    effect = normalizer.normalize(lab.event_fixture(
        emitter, event_id="EV-EFFECT", sequence=2, occurred_at=NOW + timedelta(seconds=2),
        observed_at=NOW + timedelta(seconds=3), kind=lab.EventKind.RESOURCE,
        outcome=lab.Outcome.SUCCEEDED,
    ), NOW + timedelta(seconds=4))
    store.ingest(denied)
    store.ingest(effect)
    alerts = detector.evaluate(effect, NOW + timedelta(seconds=5))
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-005")
    assert alert.evidence_event_ids == ("EV-DENY", "EV-EFFECT")


def test_correlation_does_not_cross_operations_tenants_or_windows():
    emitter, normalizer, store, detector, *_ = components()
    denied = normalizer.normalize(lab.event_fixture(
        emitter, event_id="EV-DENY", operation_id="OP-A", kind=lab.EventKind.POLICY,
        outcome=lab.Outcome.DENIED,
    ), NOW + timedelta(seconds=2))
    effect = normalizer.normalize(lab.event_fixture(
        emitter, event_id="EV-EFFECT", operation_id="OP-B", kind=lab.EventKind.RESOURCE,
        outcome=lab.Outcome.SUCCEEDED,
    ), NOW + timedelta(seconds=2))
    store.ingest(denied)
    store.ingest(effect)
    assert all(item.rule_id != "MCP-SOC-005" for item in detector.evaluate(effect, NOW + timedelta(seconds=3)))


def test_three_recent_denials_trigger_threshold_once():
    emitter, normalizer, store, detector, *_ = components()
    last = None
    for index in range(3):
        signed = lab.event_fixture(
            emitter, event_id=f"EV-D{index}", sequence=index + 1,
            occurred_at=NOW + timedelta(seconds=index), observed_at=NOW + timedelta(seconds=index + 1),
            operation_id=f"OP-{index}", kind=lab.EventKind.POLICY,
            policy_decision="deny", outcome=lab.Outcome.DENIED,
        )
        last = normalizer.normalize(signed, NOW + timedelta(seconds=index + 2))
        store.ingest(last)
    alerts = detector.evaluate(last, NOW + timedelta(seconds=5))
    threshold = next(item for item in alerts if item.rule_id == "MCP-SOC-006")
    assert threshold.evidence_event_ids == ("EV-D0", "EV-D1", "EV-D2")
    assert detector.evaluate(last, NOW + timedelta(seconds=6)) == ()


def test_high_risk_allowed_call_without_outcome_waits_then_alerts():
    emitter, normalizer, store, detector, *_ = components()
    event = normalizer.normalize(lab.event_fixture(
        emitter, event_id="EV-EXPORT", kind=lab.EventKind.TOOL_CALL,
        action="ticket.export", outcome=lab.Outcome.ALLOWED,
    ), NOW + timedelta(seconds=2))
    store.ingest(event)
    assert all(item.rule_id != "MCP-SOC-007" for item in detector.evaluate(event, NOW + timedelta(seconds=20)))
    alerts = detector.evaluate(event, NOW + timedelta(seconds=31))
    assert any(item.rule_id == "MCP-SOC-007" for item in alerts)


def test_alert_builder_rejects_fabricated_or_cross_tenant_evidence():
    store = lab.EventStore()
    detector = lab.DetectionEngine(store)
    event = normalize()
    with pytest.raises(lab.SOCError) as exc:
        detector._alert(lab.RULES["artifact_drift"], event, [event], NOW, ["TEST"])
    assert code(exc) == "ALERT_EVIDENCE_MISSING"


def test_router_uses_trusted_route_and_is_idempotent():
    _, alerts, router, *_ = admitted_alert(kind=lab.EventKind.NETWORK, destination="evil.example")
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-003")
    first = router.route(alert, NOW + timedelta(seconds=3))
    second = router.route(alert, NOW + timedelta(seconds=4))
    assert first == second
    assert first.route == "soc:acme"
    with pytest.raises(lab.SOCError) as exc:
        router.route(replace(alert, alert_id="ALT-OTHER", route="soc:beta"), NOW + timedelta(seconds=5))
    assert code(exc) == "SOC_ROUTE_INVALID"


def test_noncritical_exact_fingerprint_suppresses_within_window_but_critical_does_not():
    _, alerts, router, *_ = admitted_alert(kind=lab.EventKind.NETWORK, destination="evil.example")
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-003")
    first = router.route(alert, NOW + timedelta(seconds=3))
    duplicate = replace(alert, alert_id="ALT-NEW", evidence_event_ids=("EV-NEW",))
    assert router.route(duplicate, NOW + timedelta(minutes=1)) == first
    assert router.route(duplicate, NOW + timedelta(minutes=30)) == first
    critical = replace(duplicate, alert_id="ALT-CRITICAL", severity=lab.Severity.CRITICAL)
    assert router.route(critical, NOW + timedelta(minutes=2)).case_id != first.case_id


def test_router_is_safe_under_concurrent_retry():
    _, alerts, router, *_ = admitted_alert(kind=lab.EventKind.NETWORK, destination="evil.example")
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-003")
    with ThreadPoolExecutor(max_workers=8) as pool:
        cases = list(pool.map(lambda _: router.route(alert, NOW + timedelta(seconds=3)), range(20)))
    assert len({item.case_id for item in cases}) == 1


def test_case_state_machine_requires_expected_state_and_valid_transition():
    _, _, case, router, *_ = response_fixture()
    assert case.state == lab.CaseState.RESPONSE_PENDING
    with pytest.raises(lab.SOCError) as exc:
        router.transition(case.case_id, lab.CaseState.OPEN, lab.CaseState.CLOSED)
    assert code(exc) == "CASE_TRANSITION_INVALID"


@pytest.mark.parametrize("role", ["analyst", "model", "owner", "administrator"])
def test_only_response_roles_can_approve_containment(role):
    *_, approvals, _, proposal, _ = response_fixture()
    with pytest.raises(lab.SOCError) as exc:
        approvals.issue(proposal, "person:x", role, NOW + timedelta(seconds=5))
    assert code(exc) == "APPROVER_ROLE_INVALID"


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), timedelta(minutes=16)])
def test_approval_ttl_is_positive_and_bounded(ttl):
    *_, approvals, _, proposal, _ = response_fixture()
    with pytest.raises(lab.SOCError) as exc:
        approvals.issue(proposal, "commander:x", "incident_commander", NOW, ttl)
    assert code(exc) == "APPROVAL_TTL_INVALID"


def test_approval_is_exact_expiring_signed_and_single_use():
    *_, approvals, _, proposal, receipt = response_fixture()
    with pytest.raises(lab.SOCError) as exc:
        approvals.consume(receipt, replace(proposal, target_id="server:other"), NOW + timedelta(seconds=6))
    assert code(exc) == "APPROVAL_SCOPE_MISMATCH"
    with pytest.raises(lab.SOCError) as exc:
        approvals.consume(replace(receipt, signature="00" * 64), proposal, NOW + timedelta(seconds=6))
    assert code(exc) == "APPROVAL_SIGNATURE_INVALID"
    with pytest.raises(lab.SOCError) as exc:
        approvals.consume(receipt, proposal, NOW + timedelta(minutes=6))
    assert code(exc) == "APPROVAL_EXPIRED"
    approvals.consume(receipt, proposal, NOW + timedelta(seconds=6))
    with pytest.raises(lab.SOCError) as exc:
        approvals.consume(receipt, proposal, NOW + timedelta(seconds=7))
    assert code(exc) == "APPROVAL_REPLAYED"


def test_containment_checks_tenant_version_and_owned_action():
    *_, approvals, controller, proposal, receipt = response_fixture()
    for candidate, expected in [
        (replace(proposal, tenant_id="tenant:beta"), "TARGET_SCOPE_INVALID"),
        (replace(proposal, expected_state_version=6), "STATE_VERSION_CONFLICT"),
        (replace(proposal, action=lab.ActionKind.BLOCK_DESTINATION), "ACTION_UNSUPPORTED"),
    ]:
        candidate_receipt = approvals.issue(candidate, "commander:x", "incident_commander", NOW + timedelta(seconds=5))
        with pytest.raises(lab.SOCError) as exc:
            controller.execute("EXEC-" + expected, candidate, candidate_receipt, NOW + timedelta(seconds=6))
        assert code(exc) == expected
        if expected == "ACTION_UNSUPPORTED":
            assert candidate_receipt.receipt_id not in approvals.used


def test_containment_is_idempotent_and_conflicting_retry_fails():
    *_, controller, proposal, receipt = response_fixture()
    first = controller.execute("EXEC-1", proposal, receipt, NOW + timedelta(seconds=6))
    second = controller.execute("EXEC-1", proposal, receipt, NOW + timedelta(seconds=7))
    assert first.status == lab.ExecutionStatus.APPLIED
    assert second.status == lab.ExecutionStatus.RECONCILED
    with pytest.raises(lab.SOCError) as exc:
        controller.execute("EXEC-1", replace(proposal, reason="different"), receipt, NOW + timedelta(seconds=8))
    assert code(exc) == "OPERATION_CONFLICT"


def test_independent_verification_not_execution_intent_proves_containment():
    *_, controller, proposal, receipt = response_fixture()
    execution = controller.execute("EXEC-1", proposal, receipt, NOW + timedelta(seconds=6))
    verification = lab.IndependentVerifier().verify_disabled(controller, execution.operation_id, execution.target_id, NOW + timedelta(seconds=7))
    assert verification.verified
    assert not verification.observed_enabled
    controller.states[execution.target_id] = replace(controller.states[execution.target_id], enabled=True)
    assert not lab.IndependentVerifier().verify_disabled(controller, "EXEC-1", execution.target_id, NOW + timedelta(seconds=8)).verified


def test_detection_metrics_name_population_denominators_and_event_time():
    episodes = [
        lab.LabelledEpisode("M1", True, 0, NOW, NOW + timedelta(seconds=10), True, True),
        lab.LabelledEpisode("M2", True, 0, NOW, None, False, False),
        lab.LabelledEpisode("V1", False, 500, NOW, NOW + timedelta(seconds=2), True, False),
        lab.LabelledEpisode("V2", False, 500, NOW, None, False, False),
    ]
    metrics = lab.detection_metrics(episodes)
    assert metrics["population"] == 4
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["false_positives_per_1000_valid_operations"] == 1.0
    assert metrics["median_detection_seconds"] == 10
    assert metrics["routing_rate"] == 0.5
    assert metrics["verified_containment_rate"] == 0.25


def test_detection_metrics_handle_zero_denominators_without_fabricated_numbers():
    metrics = lab.detection_metrics([
        lab.LabelledEpisode("V1", False, 0, NOW, None, False, False)
    ])
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["false_positives_per_1000_valid_operations"] is None
    assert metrics["median_detection_seconds"] is None
    with pytest.raises(ValueError):
        lab.detection_metrics([])


def test_real_opentelemetry_span_contains_low_cardinality_operational_fields():
    _, alerts, router, *_ = admitted_alert(kind=lab.EventKind.NETWORK, destination="evil.example")
    alert = next(item for item in alerts if item.rule_id == "MCP-SOC-003")
    exporter = lab.InMemorySpanExporter()
    provider = lab.TracerProvider(resource=lab.Resource.create({"service.name": "test"}))
    provider.add_span_processor(lab.SimpleSpanProcessor(exporter))
    lab.instrumented_route(router, alert, NOW + timedelta(seconds=3), provider.get_tracer("test"))
    provider.force_flush()
    span = exporter.get_finished_spans()[0]
    assert span.name == "mcp.soc.route"
    assert span.attributes["mcp.soc.rule_id"] == "MCP-SOC-003"
    assert span.attributes["mcp.soc.evidence_count"] == 1
    assert "tenant:acme" not in span.name
