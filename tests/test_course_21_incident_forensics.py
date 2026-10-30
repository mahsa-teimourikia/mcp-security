"""Executable invariants for Course 21 incident response and forensics."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import networkx as nx
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/21-incident-detection-containment-forensics/lab.py"
SPEC = importlib.util.spec_from_file_location("course_21_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def workflow():
    environment = lab.build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    alert = environment.detector.alert(findings, now=lab.NOW)
    assert alert is not None
    repository = lab.IncidentRepository()
    manager = lab.IncidentManager(environment.store, repository)
    tenants = frozenset({"acme", "beta"})
    case = manager.open_from_alert(
        alert, analyst_id="analyst", allowed_tenants=tenants
    )
    case = manager.declare(
        case,
        findings,
        responder_id="responder",
        responder_roles=frozenset({"incident_responder"}),
        now=lab.NOW + timedelta(seconds=1),
    )
    report = lab.ScopeEngine().scope(
        case,
        environment.store,
        analyst_tenants=tenants,
        started_at=lab.NOW - timedelta(minutes=2),
        ended_at=lab.NOW,
    )
    vault = lab.ForensicVault()
    package = vault.preserve(
        case,
        report,
        environment.store,
        actor_id="collector",
        actor_roles=frozenset({"forensic_collector"}),
        allowed_tenants=tenants,
        now=lab.NOW + timedelta(seconds=2),
        retention_until=lab.NOW + timedelta(days=365),
        legal_hold=True,
    )
    plan = lab.make_plan(
        case, report, requested_by="responder", now=lab.NOW + timedelta(seconds=3)
    )
    receipt = lab.approve_plan(
        plan,
        approver_id="commander",
        approver_role="incident_commander",
        now=lab.NOW + timedelta(seconds=4),
    )
    return SimpleNamespace(
        environment=environment,
        findings=findings,
        alert=alert,
        repository=repository,
        manager=manager,
        tenants=tenants,
        case=case,
        report=report,
        vault=vault,
        package=package,
        plan=plan,
        receipt=receipt,
    )


def new_event(emitter_id="registry.sensor", **changes):
    emitter = lab.EventEmitter(emitter_id, lab.EVENT_KEYS[emitter_id])
    values = {
        "event_id": "event-test",
        "occurred_at": lab.NOW - timedelta(seconds=2),
        "observed_at": lab.NOW - timedelta(seconds=1),
        "tenant_id": "acme",
        "resource_tenant": "acme",
        "principal_id": "user:acme:test",
        "server_id": "support-v2",
        "artifact_digest": lab.reviewed_digest("support-v2@test"),
        "workload_id": "spiffe://acme/mcp/support-v2",
        "trace_id": "d" * 32,
        "operation_id": "operation-test",
        "session_id": "session-test",
        "credential_id": "credential-test",
        "kind": lab.EventKind.REGISTRY,
        "action": "deployment.observe",
        "resource": "registry://acme/support-v2",
        "destination": "",
        "policy_decision": "not_applicable",
        "outcome": lab.Outcome.OBSERVED,
        "source_locator": "vault://test/event-test",
    }
    values.update(changes)
    return emitter.emit(lab.EventTemplate(**values))


def resign_event(event, **changes):
    """Produce an authentic event with deliberate signed-chain metadata."""

    unsigned_event = replace(event, **changes, event_hash="", signature="")
    event_hash = lab.digest(unsigned_event.unsigned())
    signature = lab.hmac.new(
        lab.EVENT_KEYS[event.emitter_id], event_hash.encode(), lab.sha256
    ).hexdigest()
    return replace(unsigned_event, event_hash=event_hash, signature=signature)


def test_demo_runs_complete_evidence_to_containment_vertical_slice():
    result = lab.run_demo()
    assert result["protocol_version"] == "2026-07-28"
    assert result["alert"].severity == lab.Severity.CRITICAL
    assert result["case"].state == lab.CaseState.CONTAINED
    assert result["case"].hypotheses[0].accepted_as_fact is False
    assert result["scope_metrics"].precision == 1.0
    assert result["scope_metrics"].recall == 1.0
    assert result["package_valid"] is True
    assert result["first_execution"].status == lab.ExecutionStatus.UNKNOWN
    assert result["reconciled_execution"].status == lab.ExecutionStatus.RECONCILED
    assert result["proof"].complete is True
    assert result["detection_metrics"].precision == 1.0
    assert result["detection_metrics"].recall == 1.0
    assert result["incident_metrics"].evidence_completeness == 1.0
    assert result["incident_metrics"].valid_service_disruption_rate == 0.0


def test_demo_uses_real_networkx_and_opentelemetry_without_network_export():
    result = lab.run_demo()
    assert nx.__version__
    assert result["otel"]["span_name"] == "incident.containment"
    assert result["otel"]["attributes"]["incident.outcome"] == "contained"
    assert result["otel"]["attributes"]["incident.policy.version"] == lab.POLICY_VERSION


def test_event_store_accepts_signed_chain_and_exact_duplicate_is_idempotent():
    event = new_event()
    store = lab.EvidenceStore()
    first = store.ingest(event)
    second = store.ingest(event)
    assert first.status == lab.IngestStatus.ACCEPTED
    assert second.status == lab.IngestStatus.DUPLICATE
    assert len(store.events) == 1


def test_conflicting_event_id_is_rejected_without_overwrite():
    event = new_event()
    store = lab.EvidenceStore()
    assert store.ingest(event).status == lab.IngestStatus.ACCEPTED
    conflict = replace(event, event_hash="sha256:" + "0" * 64)
    result = store.ingest(conflict)
    assert result.reason_code == "EVENT_ID_CONFLICT"
    assert store.events[event.event_id] == event
    content_conflict = replace(event, action="deployment.delete")
    assert store.ingest(content_conflict).reason_code == "EVENT_ID_CONFLICT"


def test_untrusted_emitter_and_unauthorized_tenant_are_rejected():
    event = new_event()
    untrusted = replace(event, emitter_id="unknown.sensor")
    assert lab.EvidenceStore().ingest(untrusted).reason_code == "EMITTER_UNTRUSTED"
    restricted = lab.EvidenceStore(
        signing_keys={"registry.sensor": lab.EVENT_KEYS["registry.sensor"]},
        emitter_tenants={"registry.sensor": frozenset({"acme"})},
    )
    assert restricted.ingest(replace(event, tenant_id="beta")).reason_code == "EMITTER_TENANT_UNAUTHORIZED"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"schema_version": "old"}, "SCHEMA_VERSION_UNSUPPORTED"),
        ({"event_id": "bad id"}, "IDENTIFIER_INVALID"),
        ({"trace_id": "short"}, "SEQUENCE_OR_TRACE_INVALID"),
        ({"artifact_digest": "latest"}, "ARTIFACT_DIGEST_INVALID"),
        ({"action": "bad action"}, "FIELD_INVALID"),
        ({"policy_decision": "maybe"}, "POLICY_DECISION_INVALID"),
    ],
)
def test_event_schema_fails_closed_before_persistence(change, reason):
    store = lab.EvidenceStore()
    result = store.ingest(replace(new_event(), **change))
    assert result.reason_code == reason
    assert store.events == {}


def test_event_time_bounds_reject_reverse_delay_excess_delay_and_future():
    event = new_event()
    store = lab.EvidenceStore()
    assert store.ingest(replace(event, observed_at=event.occurred_at - timedelta(seconds=1))).reason_code == "INGESTION_DELAY_INVALID"
    assert store.ingest(replace(event, observed_at=event.occurred_at + lab.MAX_INGESTION_DELAY + timedelta(seconds=1))).reason_code == "INGESTION_DELAY_INVALID"
    future = replace(
        event,
        occurred_at=lab.NOW + lab.MAX_CLOCK_SKEW + timedelta(seconds=1),
        observed_at=lab.NOW + lab.MAX_CLOCK_SKEW + timedelta(seconds=2),
    )
    assert store.ingest(future).reason_code == "EVENT_FROM_FUTURE"


def test_event_content_and_signature_tampering_are_rejected():
    event = new_event()
    assert lab.EvidenceStore().ingest(replace(event, action="deployment.delete")).reason_code == "INTEGRITY_INVALID"
    assert lab.EvidenceStore().ingest(replace(event, signature="0" * 64)).reason_code == "INTEGRITY_INVALID"


def test_event_chain_requires_contiguous_sequence_and_previous_hash():
    emitter = lab.EventEmitter("registry.sensor", lab.EVENT_KEYS["registry.sensor"])
    first_template = lab.EventTemplate(**{key: value for key, value in new_event().unsigned().items() if key not in {"schema_version", "emitter_id", "sequence", "previous_hash"}})
    first_template = replace(first_template, event_id="event-chain-1")
    second_template = replace(first_template, event_id="event-chain-2")
    first = emitter.emit(first_template)
    second = emitter.emit(second_template)
    store = lab.EvidenceStore()
    assert store.ingest(first).status == lab.IngestStatus.ACCEPTED
    assert store.ingest(resign_event(second, sequence=3)).reason_code == "CHAIN_DISCONTINUITY"
    assert store.ingest(
        resign_event(second, previous_hash="sha256:" + "0" * 64)
    ).reason_code == "CHAIN_DISCONTINUITY"


def test_evidence_authorization_precedes_retrieval_and_filtering():
    environment = lab.build_environment()
    beta_event = environment.store.events["event-beta-read"]
    with pytest.raises(PermissionError, match="outside"):
        environment.store.get(beta_event.event_id, allowed_tenants=frozenset({"acme"}))
    authorized = environment.store.query(
        allowed_tenants=frozenset({"acme"}),
        started_at=lab.NOW - timedelta(minutes=2),
        ended_at=lab.NOW,
    )
    assert beta_event not in authorized
    assert all(item.resource_tenant == "acme" for item in authorized)


def test_detector_emits_evidence_backed_rule_versioned_findings():
    environment = lab.build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    kinds = {item.kind for item in findings}
    assert kinds == set(lab.FindingKind)
    assert all(item.rule_id.startswith("mcp.") and item.rule_version == "1.0.0" for item in findings)
    assert all(set(item.evidence_ids).issubset(environment.store.events) for item in findings)


def test_detector_does_not_alert_on_valid_flow_or_successful_denial():
    environment = lab.build_environment()
    assert environment.detector.alert(environment.detector.detect(environment.benign_events), now=lab.NOW) is None
    denial_findings = environment.detector.detect(environment.safe_denial_events)
    assert {item.kind for item in denial_findings} == {lab.FindingKind.UNEXPECTED_EGRESS}
    assert environment.detector.alert(denial_findings, now=lab.NOW) is None


def test_correlated_finding_requires_independent_network_and_resource_evidence():
    environment = lab.build_environment()
    without_resource = tuple(item for item in environment.malicious_events if item.kind != lab.EventKind.RESOURCE)
    assert lab.FindingKind.CORRELATED_INTRUSION not in {item.kind for item in environment.detector.detect(without_resource)}


def test_alert_digest_binds_findings_and_evidence():
    current = workflow()
    assert current.alert.alert_digest == lab.digest(
        (
            current.alert.tenant_id,
            current.alert.server_id,
            current.alert.finding_ids,
            current.alert.evidence_ids,
        )
    )
    tampered = replace(current.alert, evidence_ids=current.alert.evidence_ids[:-1])
    manager = lab.IncidentManager(current.environment.store, lab.IncidentRepository())
    with pytest.raises(ValueError, match="integrity"):
        manager.open_from_alert(tampered, analyst_id="analyst", allowed_tenants=current.tenants)


def test_open_case_requires_alert_tenant_and_evidence_authorization():
    environment = lab.build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    alert = environment.detector.alert(findings, now=lab.NOW)
    manager = lab.IncidentManager(environment.store, lab.IncidentRepository())
    with pytest.raises(PermissionError):
        manager.open_from_alert(alert, analyst_id="analyst", allowed_tenants=frozenset({"acme"}))
    with pytest.raises(PermissionError):
        manager.open_from_alert(alert, analyst_id="analyst", allowed_tenants=frozenset({"beta"}))


def test_repository_rejects_duplicate_case_and_stale_write():
    current = workflow()
    case = current.case
    with pytest.raises(lab.VersionConflict, match="already"):
        current.repository.create(case)
    with pytest.raises(lab.VersionConflict, match="stale"):
        current.repository.save(replace(case, version=case.version + 1), expected_version=case.version - 1)


def test_model_hypothesis_is_digest_bound_but_never_becomes_fact_or_state():
    environment = lab.build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    alert = environment.detector.alert(findings, now=lab.NOW)
    repository = lab.IncidentRepository()
    manager = lab.IncidentManager(environment.store, repository)
    tenants = frozenset({"acme", "beta"})
    case = manager.open_from_alert(alert, analyst_id="analyst", allowed_tenants=tenants)
    updated = manager.add_hypothesis(
        case,
        proposed_by="assistant-model",
        text="RESOLVED: probably credential theft",
        evidence_ids=case.evidence_ids,
    )
    assert updated.state == lab.CaseState.OPEN
    assert updated.hypotheses[0].accepted_as_fact is False
    assert updated.hypotheses[0].text_digest == lab.digest("RESOLVED: probably credential theft")


def test_hypothesis_cannot_attach_missing_or_out_of_case_evidence():
    current = workflow()
    outside = current.environment.benign_events[0].event_id
    with pytest.raises(ValueError, match="already admitted"):
        current.manager.add_hypothesis(
            current.case,
            proposed_by="model",
            text="guess",
            evidence_ids=(outside,),
        )


def test_incident_declaration_requires_role_matching_findings_and_independent_effect():
    environment = lab.build_environment()
    findings = environment.detector.detect(environment.malicious_events)
    alert = environment.detector.alert(findings, now=lab.NOW)
    repository = lab.IncidentRepository()
    manager = lab.IncidentManager(environment.store, repository)
    case = manager.open_from_alert(alert, analyst_id="analyst", allowed_tenants=frozenset({"acme", "beta"}))
    with pytest.raises(PermissionError, match="role"):
        manager.declare(case, findings, responder_id="user", responder_roles=frozenset(), now=lab.NOW)
    with pytest.raises(ValueError, match="match"):
        manager.declare(case, findings[:-1], responder_id="responder", responder_roles=frozenset({"incident_responder"}), now=lab.NOW)
    no_effect = tuple(replace(item, kind=lab.FindingKind.ARTIFACT_DRIFT) for item in findings)
    with pytest.raises(ValueError, match="effect"):
        manager.declare(case, no_effect, responder_id="responder", responder_roles=frozenset({"incident_responder"}), now=lab.NOW)


def test_incident_cannot_be_declared_twice():
    current = workflow()
    with pytest.raises(ValueError, match="open"):
        current.manager.declare(current.case, current.findings, responder_id="responder", responder_roles=frozenset({"incident_responder"}), now=lab.NOW)


def test_scope_graph_authorizes_before_exact_relationship_expansion():
    current = workflow()
    restricted = lab.ScopeEngine().scope(
        current.case,
        current.environment.store,
        analyst_tenants=frozenset({"acme"}),
        started_at=lab.NOW - timedelta(minutes=2),
        ended_at=lab.NOW,
    )
    complete = current.report
    assert restricted.excluded_unauthorized_count == 2
    assert "beta" not in restricted.confirmed_tenants
    assert restricted.destinations == ("exfil.example",)
    assert set(complete.evidence_ids) == current.environment.actual_incident_evidence
    assert complete.confirmed_tenants == ("acme", "beta")


def test_scope_requires_incident_tenant_authorization():
    current = workflow()
    with pytest.raises(PermissionError, match="scope"):
        lab.ScopeEngine().scope(
            current.case,
            current.environment.store,
            analyst_tenants=frozenset({"beta"}),
            started_at=lab.NOW - timedelta(minutes=2),
            ended_at=lab.NOW,
        )


def test_scope_window_excludes_old_events():
    current = workflow()
    report = lab.ScopeEngine().scope(
        current.case,
        current.environment.store,
        analyst_tenants=current.tenants,
        started_at=lab.NOW - timedelta(seconds=26),
        ended_at=lab.NOW,
    )
    assert "event-registry-bad" not in report.evidence_ids


def test_scope_metrics_expose_counts_and_denominators():
    current = workflow()
    exact = lab.evaluate_scope(current.report, current.environment.actual_incident_evidence)
    partial = lab.evaluate_scope(
        replace(current.report, evidence_ids=current.report.evidence_ids[:-1]),
        current.environment.actual_incident_evidence,
    )
    empty = lab.evaluate_scope(replace(current.report, evidence_ids=()), frozenset())
    assert exact == lab.ScopeMetrics(5, 5, 5, 1.0, 1.0)
    assert partial.precision == 1.0 and partial.recall == 4 / 5
    assert empty.precision == 0.0 and empty.recall == 0.0


def test_forensic_package_is_redacted_signed_retained_and_held():
    current = workflow()
    package = current.package
    assert current.vault.verify(package)
    assert package.legal_hold is True
    assert package.retention_until > package.created_at
    serialized = lab.canonical_json(package)
    assert b"user:acme:42" not in serialized
    assert b"data://beta/customers" not in serialized
    assert b"exfil.example" not in serialized
    assert all(item.tenant_pseudonym.startswith("hmac-sha256:") for item in package.evidence)


def test_forensic_collection_requires_role_retention_and_tenant_access():
    current = workflow()
    kwargs = {
        "case": current.case,
        "report": current.report,
        "store": current.environment.store,
        "actor_id": "collector",
        "actor_roles": frozenset({"forensic_collector"}),
        "allowed_tenants": current.tenants,
        "now": lab.NOW,
        "retention_until": lab.NOW + timedelta(days=1),
        "legal_hold": False,
    }
    with pytest.raises(PermissionError, match="role"):
        current.vault.preserve(**{**kwargs, "actor_roles": frozenset()})
    with pytest.raises(ValueError, match="retention"):
        current.vault.preserve(**{**kwargs, "retention_until": lab.NOW})
    with pytest.raises(PermissionError, match="outside"):
        current.vault.preserve(**{**kwargs, "allowed_tenants": frozenset({"acme"})})


def test_package_verification_detects_manifest_evidence_signature_and_custody_tampering():
    current = workflow()
    package = current.package
    changed_evidence = replace(package.evidence[0], action="tampered")
    assert not current.vault.verify(replace(package, evidence=(changed_evidence,) + package.evidence[1:]))
    assert not current.vault.verify(replace(package, manifest_digest="sha256:" + "0" * 64))
    assert not current.vault.verify(replace(package, signature="0" * 64))
    changed_custody = replace(package.custody[0], reason="tampered")
    assert not current.vault.verify(replace(package, custody=(changed_custody,)))


def test_custody_transfer_is_append_only_verified_and_reasoned():
    current = workflow()
    transferred = current.vault.transfer(
        current.package,
        actor_id="custodian-1",
        actor_roles=frozenset({"forensic_custodian"}),
        new_custodian="legal-1",
        reason="legal review",
        now=lab.NOW + timedelta(minutes=1),
    )
    assert transferred.custodian == "legal-1"
    assert len(transferred.custody) == 2
    assert current.vault.verify(transferred)
    with pytest.raises(PermissionError):
        current.vault.transfer(current.package, actor_id="user", actor_roles=frozenset(), new_custodian="x", reason="x", now=lab.NOW)
    with pytest.raises(PermissionError):
        current.vault.transfer(current.package, actor_id="custodian", actor_roles=frozenset({"forensic_custodian"}), new_custodian="x", reason="", now=lab.NOW)


def test_invalid_package_cannot_be_transferred():
    current = workflow()
    with pytest.raises(ValueError, match="invalid"):
        current.vault.transfer(
            replace(current.package, signature="bad"),
            actor_id="custodian",
            actor_roles=frozenset({"forensic_custodian"}),
            new_custodian="legal",
            reason="review",
            now=lab.NOW,
        )


def test_containment_plan_covers_every_confirmed_session_credential_and_workload():
    current = workflow()
    actions = current.plan.actions
    assert {item.target for item in actions if item.kind == lab.ActionKind.TERMINATE_SESSION} == set(current.report.sessions)
    assert {item.target for item in actions if item.kind == lab.ActionKind.REVOKE_CREDENTIAL} == set(current.report.credentials)
    assert {item.target for item in actions if item.kind == lab.ActionKind.QUARANTINE_WORKLOAD} == set(current.report.workloads)
    assert all(item.tenant_id == current.case.tenant_id for item in actions)


def test_containment_plan_requires_declared_case_and_detects_mutation():
    current = workflow()
    with pytest.raises(ValueError, match="declared"):
        lab.make_plan(replace(current.case, state=lab.CaseState.OPEN), current.report, requested_by="responder", now=lab.NOW)
    assert lab.verify_plan(current.plan)
    assert not lab.verify_plan(replace(current.plan, expires_at=current.plan.expires_at + timedelta(minutes=1)))
    assert not lab.verify_plan(replace(current.plan, actions=()))


def test_approval_is_signed_exact_short_lived_and_role_gated():
    current = workflow()
    assert lab.verify_receipt(current.receipt)
    assert current.receipt.plan_digest == current.plan.plan_digest
    assert current.receipt.expires_at <= current.plan.expires_at
    with pytest.raises(PermissionError, match="role"):
        lab.approve_plan(current.plan, approver_id="analyst", approver_role="analyst", now=lab.NOW)
    assert not lab.verify_receipt(replace(current.receipt, tenant_id="other"))
    assert not lab.verify_receipt(replace(current.receipt, signature="0" * 64))


def test_execute_applies_all_controls_atomically_and_consumes_receipt():
    current = workflow()
    executor = lab.ContainmentExecutor()
    result = executor.execute("operation-1", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW + timedelta(seconds=5))
    assert result.status == lab.ExecutionStatus.APPLIED
    assert all(executor.controls.satisfied(action) for action in current.plan.actions)
    assert current.receipt.receipt_id in executor.consumed_receipts
    assert executor.controls.revision == 1


@pytest.mark.parametrize(
    "case_change,match",
    [
        ({"state": lab.CaseState.OPEN}, "state"),
        ({"incident_id": "incident-other"}, "state"),
        ({"tenant_id": "other"}, "state"),
    ],
)
def test_execute_requires_exact_declared_case_scope(case_change, match):
    current = workflow()
    with pytest.raises(PermissionError, match=match):
        lab.ContainmentExecutor().execute("operation", current.plan, current.receipt, current.package, current.vault, replace(current.case, **case_change), now=lab.NOW + timedelta(seconds=5))


def test_execute_rejects_stale_tampered_expired_or_cross_tenant_plan():
    current = workflow()
    with pytest.raises(ValueError, match="plan"):
        lab.ContainmentExecutor().execute("op-stale", replace(current.plan, case_version=current.plan.case_version - 1), current.receipt, current.package, current.vault, current.case, now=lab.NOW)
    with pytest.raises(ValueError, match="expired"):
        lab.ContainmentExecutor().execute("op-expired", current.plan, current.receipt, current.package, current.vault, current.case, now=current.plan.expires_at + timedelta(seconds=1))
    altered_action = replace(current.plan.actions[0], tenant_id="beta")
    actions = (altered_action,) + current.plan.actions[1:]
    unsigned = {
        "incident_id": current.plan.incident_id,
        "tenant_id": current.plan.tenant_id,
        "case_version": current.plan.case_version,
        "actions": actions,
        "requested_by": current.plan.requested_by,
        "policy_version": current.plan.policy_version,
        "created_at": current.plan.created_at,
        "expires_at": current.plan.expires_at,
    }
    cross = replace(current.plan, actions=actions, plan_digest=lab.digest(unsigned))
    cross_receipt = lab.approve_plan(cross, approver_id="commander", approver_role="incident_commander", now=lab.NOW)
    with pytest.raises(PermissionError, match="cross-tenant"):
        lab.ContainmentExecutor().execute("op-cross", cross, cross_receipt, current.package, current.vault, current.case, now=lab.NOW)


def test_execute_rejects_altered_expired_wrong_or_replayed_receipt():
    current = workflow()
    altered = replace(current.receipt, plan_digest="sha256:" + "0" * 64)
    with pytest.raises(PermissionError, match="receipt"):
        lab.ContainmentExecutor().execute("op-altered", current.plan, altered, current.package, current.vault, current.case, now=lab.NOW)
    expired = replace(current.receipt, expires_at=lab.NOW - timedelta(seconds=1))
    expired = replace(expired, signature=lab.hmac.new(lab.APPROVAL_KEY, lab.canonical_json(expired.unsigned()), lab.sha256).hexdigest())
    with pytest.raises(PermissionError, match="receipt"):
        lab.ContainmentExecutor().execute("op-expired", current.plan, expired, current.package, current.vault, current.case, now=lab.NOW)
    executor = lab.ContainmentExecutor()
    executor.execute("op-first", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW)
    with pytest.raises(ValueError, match="consumed"):
        executor.execute("op-second", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW)


def test_execute_requires_valid_preserved_evidence_before_mutation():
    current = workflow()
    executor = lab.ContainmentExecutor()
    with pytest.raises(ValueError, match="preserved"):
        executor.execute("operation", current.plan, current.receipt, replace(current.package, signature="bad"), current.vault, current.case, now=lab.NOW)
    assert executor.controls.revision == 0
    assert not executor.consumed_receipts


def test_unknown_outcome_reconciles_same_operation_without_duplicate_effects():
    current = workflow()
    executor = lab.ContainmentExecutor()
    first = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW, simulate_lost_response=True)
    second = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW + timedelta(seconds=1))
    assert first.status == lab.ExecutionStatus.UNKNOWN
    assert second.status == lab.ExecutionStatus.RECONCILED
    assert executor.controls.revision == 1


def test_restart_reuses_durable_operation_journal_for_reconciliation():
    current = workflow()
    first_executor = lab.ContainmentExecutor()
    first_executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW, simulate_lost_response=True)
    restarted = lab.ContainmentExecutor(first_executor.controls, first_executor.journal)
    result = restarted.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW + timedelta(seconds=1))
    assert result.status == lab.ExecutionStatus.RECONCILED
    assert restarted.controls.revision == 1


def test_operation_id_cannot_be_reused_for_a_different_request():
    current = workflow()
    executor = lab.ContainmentExecutor()
    executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW)
    with pytest.raises(ValueError, match="different request"):
        executor.execute("operation", current.plan, current.receipt, replace(current.package, manifest_digest="different"), current.vault, current.case, now=lab.NOW)


def test_control_plane_rejects_duplicate_or_empty_actions_before_revision():
    current = workflow()
    duplicate = (current.plan.actions[0], current.plan.actions[0])
    with pytest.raises(ValueError, match="duplicate"):
        lab.ControlPlane().apply(duplicate)
    empty = (replace(current.plan.actions[0], target=""),)
    with pytest.raises(ValueError, match="empty"):
        lab.ControlPlane().apply(empty)


def test_containment_proof_requires_every_effect_valid_package_and_no_late_effect():
    current = workflow()
    executor = lab.ContainmentExecutor()
    execution = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW + timedelta(seconds=5))
    complete = lab.prove_containment(current.plan, executor.controls, current.package, current.vault, current.environment.store, applied_at=execution.applied_at)
    assert complete.complete is True
    incomplete_controls = replace(executor.controls, terminated_sessions=frozenset())
    incomplete = lab.prove_containment(current.plan, incomplete_controls, current.package, current.vault, current.environment.store, applied_at=execution.applied_at)
    assert incomplete.complete is False
    invalid_package = lab.prove_containment(current.plan, executor.controls, replace(current.package, signature="bad"), current.vault, current.environment.store, applied_at=execution.applied_at)
    assert invalid_package.complete is False


def test_post_cut_effect_prevents_containment_proof():
    current = workflow()
    executor = lab.ContainmentExecutor()
    execution = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW + timedelta(seconds=5))
    late = new_event(
        emitter_id="control.audit",
        event_id="event-late-effect",
        occurred_at=lab.NOW + timedelta(seconds=6),
        observed_at=lab.NOW + timedelta(seconds=7),
        kind=lab.EventKind.CONTROL,
        action="customer.read",
        outcome=lab.Outcome.COMPLETED,
    )
    assert current.environment.store.ingest(late, now=lab.NOW + timedelta(seconds=7)).status == lab.IngestStatus.ACCEPTED
    proof = lab.prove_containment(current.plan, executor.controls, current.package, current.vault, current.environment.store, applied_at=execution.applied_at)
    assert proof.complete is False
    assert proof.post_cut_forbidden_effect_count == 1


def test_case_state_changes_only_after_verified_containment():
    current = workflow()
    executor = lab.ContainmentExecutor()
    execution = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW)
    proof = lab.prove_containment(current.plan, executor.controls, current.package, current.vault, current.environment.store, applied_at=execution.applied_at)
    with pytest.raises(PermissionError):
        current.manager.mark_contained(current.case, proof, execution, responder_roles=frozenset())
    with pytest.raises(ValueError, match="verified"):
        current.manager.mark_contained(current.case, replace(proof, complete=False), execution, responder_roles=frozenset({"incident_responder"}))
    with pytest.raises(ValueError, match="bound"):
        current.manager.mark_contained(
            current.case,
            replace(proof, incident_id="incident-other"),
            execution,
            responder_roles=frozenset({"incident_responder"}),
        )
    contained = current.manager.mark_contained(current.case, proof, execution, responder_roles=frozenset({"incident_responder"}))
    assert contained.state == lab.CaseState.CONTAINED
    assert current.repository.get(contained.incident_id) == contained


def test_detector_metrics_use_labelled_positive_and_negative_denominators():
    environment = lab.build_environment()
    metrics = lab.evaluate_detector(
        environment.detector,
        (
            lab.DetectionCase("malicious", environment.malicious_events, True),
            lab.DetectionCase("valid", environment.benign_events, False),
            lab.DetectionCase("denied", environment.safe_denial_events, False),
        ),
        now=lab.NOW,
    )
    assert metrics == lab.DetectionMetrics(1, 0, 2, 0, 1.0, 1.0)


def test_detector_metrics_define_empty_denominators():
    environment = lab.build_environment()
    metrics = lab.evaluate_detector(environment.detector, (), now=lab.NOW)
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0


def test_incident_metrics_report_units_counts_and_direction():
    result = lab.run_demo()
    metrics = result["incident_metrics"]
    assert metrics.time_to_detect_seconds == 30.0
    assert metrics.time_to_contain_seconds == 5.0
    assert metrics.evidence_present_count == 4
    assert metrics.evidence_required_count == 4
    assert metrics.evidence_completeness == 4 / 4
    assert metrics.scope_precision == 5 / 5
    assert metrics.scope_recall == 5 / 5
    assert metrics.valid_service_disruption_rate == 0 / 1


def test_incident_metrics_require_declared_time_and_define_zero_service_denominator():
    current = workflow()
    executor = lab.ContainmentExecutor()
    execution = executor.execute("operation", current.plan, current.receipt, current.package, current.vault, current.case, now=lab.NOW)
    scope_metrics = lab.evaluate_scope(current.report, current.environment.actual_incident_evidence)
    with pytest.raises(ValueError, match="declared"):
        lab.calculate_metrics(replace(current.case, declared_at=None), current.alert, execution, current.package, scope_metrics, valid_services_disrupted=0, valid_services_total=0)
    metrics = lab.calculate_metrics(current.case, current.alert, execution, current.package, scope_metrics, valid_services_disrupted=0, valid_services_total=0)
    assert metrics.valid_service_disruption_rate == 0.0


def test_utc_parser_requires_utc_and_digest_is_canonical():
    assert lab.utc("2026-10-30T16:00:00Z") == lab.NOW
    with pytest.raises(ValueError, match="UTC"):
        lab.utc("2026-10-30T16:00:00")
    assert lab.digest({"b": 2, "a": 1}) == lab.digest({"a": 1, "b": 2})
