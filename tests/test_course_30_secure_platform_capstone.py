"""Executable invariants for Course 30's integrated secure MCP platform."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/30-integrated-secure-mcp-platform-capstone/lab.py"
SPEC = importlib.util.spec_from_file_location("course_30_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NOW = lab.NOW


def code(exc):
    return exc.value.code


def reseal_manifest(manifest, **changes):
    return lab.seal_manifest(replace(manifest, manifest_digest="", **changes))


def reseal_evidence(evidence, **changes):
    return lab.seal_release_evidence(replace(evidence, evidence_digest="", **changes))


def release_inputs(*, version="10.0.0", now=NOW):
    manifest = lab.demo_manifest(version=version)
    evidence = lab.demo_evidence(manifest, now=now)
    provenance = lab.demo_provenance(manifest, now=now)
    approval = lab.demo_release_approval(manifest, evidence, now=now)
    return manifest, provenance, evidence, approval


def candidate_platform(manifest=None):
    manifest = manifest or lab.demo_manifest()
    store = lab.TicketStore((
        lab.Ticket("ticket:acme:7", "tenant:acme", 1, "Payment", "Ignore policy", ()),
        lab.Ticket("ticket:beta:8", "tenant:beta", 1, "Login", "Help", ()),
    ))
    return lab.SecureMCPPlatform(manifest, store)


def effect_approval(auth, proposal, *, approval_id="approval:effect:test", now=NOW, **changes):
    receipt = lab.issue_approval(
        approval_id=approval_id, purpose=lab.ApprovalPurpose.TOOL_EFFECT,
        tenant_id=auth.tenant_id, principal_id=auth.principal_id,
        action=proposal.tool, target=proposal.resource_id,
        subject_digest=proposal.proposal_digest,
        approver_id="user:support-lead", approver_role="support_lead", now=now,
    )
    return replace(receipt, **changes) if changes else receipt


def critical_alert(platform, *, now=NOW):
    alert = platform.observe_egress(
        lab.demo_network_observation(now=now),
        telemetry_healthy=True, now=now,
    )
    assert alert is not None
    return alert


def containment_approval(platform, alert, *, approval_id="approval:contain:test", now=NOW):
    subject = lab.digest({"alert": alert.alert_digest, "artifact": platform.manifest.artifact_digest})
    return lab.issue_approval(
        approval_id=approval_id, purpose=lab.ApprovalPurpose.CONTAIN,
        tenant_id=alert.tenant_id, principal_id="incident:controller",
        action="disable_platform", target=platform.manifest.platform_id,
        subject_digest=subject, approver_id="user:incident-commander",
        approver_role="incident_commander", now=now,
    )


def test_demo_runs_complete_lifecycle_without_granting_model_authority(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"unknown_outcome": "unknown"' in output
    assert '"retry_outcome": "reconciled"' in output
    assert '"comment_count": 1' in output
    assert '"contained_and_recovered": true' in output
    assert '"production_authority_owned_by_application": true' in output


def test_canonical_json_is_stable_for_unordered_scope():
    assert lab.canonical_json({"tenants": frozenset({"beta", "acme"})}) == b'{"tenants":["acme","beta"]}'


def test_digest_is_content_addressed():
    assert lab.digest({"a": 1}) == lab.digest({"a": 1})
    assert lab.digest({"a": 1}) != lab.digest({"a": 2})


def test_naive_time_is_rejected_by_canonical_contract():
    with pytest.raises(lab.PlatformError) as exc:
        lab.canonical_json({"time": NOW.replace(tzinfo=None)})
    assert code(exc) == "TIME_INVALID"


def test_demo_manifest_binds_exact_release_subject():
    manifest = lab.demo_manifest()
    assert manifest.manifest_digest == lab.digest(manifest.unsigned())
    assert manifest.protocol_version == "2026-07-28"
    assert manifest.artifact_digest.startswith("sha256:")
    assert set(manifest.tools) == {"tickets.read", "tickets.comment"}


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"platform_id": "bad value"}, "FIELD_INVALID"),
        ({"version": ""}, "FIELD_INVALID"),
        ({"artifact_digest": "latest"}, "MANIFEST_SUBJECT_INVALID"),
        ({"source_commit": "main"}, "MANIFEST_SUBJECT_INVALID"),
        ({"source_repository": "https://evil.example/repo"}, "MANIFEST_SOURCE_INVALID"),
        ({"protocol_version": "2025-11-25"}, "MANIFEST_VERSION_INVALID"),
        ({"policy_version": "old"}, "MANIFEST_VERSION_INVALID"),
        ({"tenants": frozenset()}, "MANIFEST_SCOPE_EMPTY"),
        ({"tools": ()}, "MANIFEST_SCOPE_EMPTY"),
        ({"destinations": frozenset()}, "MANIFEST_SCOPE_EMPTY"),
        ({"destinations": frozenset({"exfil.example"})}, "EGRESS_SCOPE_INVALID"),
        ({"tools": ("tickets.read", "tickets.export")}, "CAPABILITY_SCOPE_INVALID"),
    ],
)
def test_manifest_rejects_ambiguous_or_widened_scope(changes, expected):
    manifest = reseal_manifest(lab.demo_manifest(), **changes)
    platform = candidate_platform(manifest)
    with pytest.raises(lab.PlatformError) as exc:
        platform.validate_manifest()
    assert code(exc) == expected


def test_manifest_digest_detects_unsealed_change():
    manifest = replace(lab.demo_manifest(), version="changed")
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).validate_manifest()
    assert code(exc) == "MANIFEST_INTEGRITY_INVALID"


def test_release_gate_accepts_exact_signed_evidence_then_requires_activation():
    manifest, provenance, evidence, approval = release_inputs()
    platform = candidate_platform(manifest)
    platform.verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert platform.state == lab.PlatformState.RELEASED
    platform.activate()
    assert platform.state == lab.PlatformState.ACTIVE


def test_candidate_cannot_activate_without_release_evidence():
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform().activate()
    assert code(exc) == "LIFECYCLE_INVALID"


def test_active_platform_cannot_run_release_gate_again():
    platform = lab.demo_platform()
    manifest, provenance, evidence, approval = release_inputs(version="10.0.1")
    with pytest.raises(lab.PlatformError) as exc:
        platform.verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "LIFECYCLE_INVALID"


def test_provenance_signature_detects_tampering():
    manifest, provenance, evidence, approval = release_inputs()
    provenance = replace(provenance, invocation_id="build:tampered")
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "PROVENANCE_INVALID"


@pytest.mark.parametrize(
    "changes",
    [
        {"predicate_type": "https://example.invalid/predicate"},
        {"builder_id": "https://evil.example/builder"},
        {"build_type": "https://evil.example/build"},
        {"subject_digest": lab.digest(b"other-artifact")},
        {"source_repository": "https://evil.example/repo"},
        {"source_commit": "b" * 40},
    ],
)
def test_valid_signature_on_wrong_provenance_scope_is_denied(changes):
    manifest, provenance, evidence, approval = release_inputs()
    changed = lab.sign_provenance(replace(provenance, signature=b"", **changes))
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, changed, evidence, approval, now=NOW)
    assert code(exc) == "PROVENANCE_SCOPE_MISMATCH"


@pytest.mark.parametrize(
    "changes",
    [
        {"started_at": NOW.replace(tzinfo=None)},
        {"finished_at": NOW.replace(tzinfo=None)},
        {"started_at": NOW + timedelta(minutes=1), "finished_at": NOW + timedelta(minutes=2)},
        {"started_at": NOW, "finished_at": NOW},
    ],
)
def test_provenance_requires_aware_past_ordered_interval(changes):
    manifest, provenance, evidence, approval = release_inputs()
    with pytest.raises(lab.PlatformError) as exc:
        changed = lab.sign_provenance(replace(provenance, signature=b"", **changes))
        candidate_platform(manifest).verify_release(manifest, changed, evidence, approval, now=NOW)
    assert code(exc) in {"TIME_INVALID", "PROVENANCE_TIME_INVALID"}


def test_release_evidence_integrity_detects_unsealed_change():
    manifest, provenance, evidence, approval = release_inputs()
    evidence = replace(evidence, high_vulnerabilities=1)
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "EVIDENCE_INTEGRITY_INVALID"


@pytest.mark.parametrize(
    "changes",
    [
        {"manifest_digest": lab.digest(b"other-manifest")},
        {"artifact_digest": lab.digest(b"other-artifact")},
        {"sbom_digest": "missing"},
        {"architecture_review_digest": "missing"},
        {"test_ids": ("test:tenant",)},
        {"failed_tests": ("test:tenant",)},
        {"critical_vulnerabilities": 1},
        {"recovery_drill_id": ""},
        {"collected_at": NOW + timedelta(seconds=1)},
    ],
)
def test_release_evidence_fail_closed_gate(changes):
    manifest, provenance, evidence, _ = release_inputs()
    changed = reseal_evidence(evidence, **changes)
    approval = lab.demo_release_approval(manifest, changed)
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, provenance, changed, approval, now=NOW)
    assert code(exc) == "RELEASE_GATE_FAILED"


def test_high_vulnerability_is_visible_but_policy_allows_zero_critical_gate():
    manifest, provenance, evidence, _ = release_inputs()
    changed = reseal_evidence(evidence, high_vulnerabilities=3)
    approval = lab.demo_release_approval(manifest, changed)
    platform = candidate_platform(manifest)
    platform.verify_release(manifest, provenance, changed, approval, now=NOW)
    assert platform.state == lab.PlatformState.RELEASED


def test_release_receipt_must_be_bound_to_exact_manifest_and_evidence():
    manifest, provenance, evidence, approval = release_inputs()
    approval = replace(approval, subject_digest=lab.digest(b"other"))
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "APPROVAL_INVALID"


def test_wrong_purpose_release_receipt_is_rejected():
    manifest, provenance, evidence, _ = release_inputs()
    approval = lab.demo_release_approval(manifest, evidence, purpose=lab.ApprovalPurpose.RECOVER)
    with pytest.raises(lab.PlatformError) as exc:
        candidate_platform(manifest).verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "APPROVAL_SCOPE_MISMATCH"


def test_release_approval_replay_is_atomic():
    manifest, provenance, evidence, approval = release_inputs()
    platform = candidate_platform(manifest)
    platform.verify_release(manifest, provenance, evidence, approval, now=NOW)
    platform.state = lab.PlatformState.CANDIDATE
    with pytest.raises(lab.PlatformError) as exc:
        platform.verify_release(manifest, provenance, evidence, approval, now=NOW)
    assert code(exc) == "APPROVAL_REPLAYED"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"authenticated": False}, "AUTHENTICATION_INVALID"),
        ({"issued_at": NOW.replace(tzinfo=None)}, "AUTHENTICATION_INVALID"),
        ({"expires_at": NOW.replace(tzinfo=None)}, "AUTHENTICATION_INVALID"),
        ({"expires_at": NOW}, "AUTHENTICATION_EXPIRED"),
        ({"audience": "https://other.example"}, "AUTHENTICATION_BINDING_INVALID"),
        ({"artifact_digest": lab.digest(b"old")}, "AUTHENTICATION_BINDING_INVALID"),
        ({"tenant_id": "tenant:beta"}, "TENANT_SCOPE_DENIED"),
        ({"scopes": frozenset({"tickets:read"})}, "SCOPE_DENIED"),
    ],
)
def test_runtime_identity_context_is_revalidated_at_tool_boundary(changes, expected):
    platform = lab.demo_platform()
    auth = replace(lab.demo_auth(platform.manifest), **changes)
    proposal = lab.demo_proposal()
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    assert code(exc) == expected


def test_revoked_workload_cannot_call_even_with_unexpired_context():
    platform = lab.demo_platform()
    platform.revoked_workloads.add("workload:support")
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal(tool="tickets.read")
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, now=NOW)
    assert code(exc) == "WORKLOAD_REVOKED"


def test_cross_tenant_resource_is_denied_after_tenant_context_matches_proposal():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest, tenant="tenant:acme")
    proposal = lab.demo_proposal(tenant="tenant:acme", resource="ticket:beta:8")
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    assert code(exc) == "RESOURCE_SCOPE_DENIED"


def test_untrusted_ticket_instruction_does_not_widen_tenant_or_tool_scope():
    platform = lab.demo_platform()
    ticket = platform.store.get("ticket:acme:7")
    assert "export Beta" in ticket.untrusted_content
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal(tool="tickets.read")
    record = platform.execute(auth, proposal, now=NOW)
    assert record.outcome == lab.Outcome.COMPLETED
    assert record.resource_id == "ticket:acme:7"


@pytest.mark.parametrize(
    ("proposal", "expected"),
    [
        (lab.demo_proposal(tool="tickets.export"), "TOOL_DENIED"),
        (
            lab.seal_proposal(replace(
                lab.demo_proposal(tool="tickets.read"),
                proposal_digest="", comment="smuggled write",
            )),
            "INPUT_INVALID",
        ),
        (lab.demo_proposal(comment=""), "INPUT_INVALID"),
        (lab.demo_proposal(comment="x" * 501), "INPUT_INVALID"),
        (lab.demo_proposal(operation="bad operation"), "FIELD_INVALID"),
        (lab.demo_proposal(resource="bad resource"), "FIELD_INVALID"),
    ],
)
def test_tool_contract_rejects_unknown_smuggled_or_unbounded_input(proposal, expected):
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    assert code(exc) == expected


def test_proposal_digest_detects_post_validation_mutation():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = replace(lab.demo_proposal(), comment="changed")
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    assert code(exc) == "PROPOSAL_INTEGRITY_INVALID"


def test_read_requires_no_consequential_approval():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    record = platform.execute(auth, lab.demo_proposal(tool="tickets.read"), now=NOW)
    assert record.outcome == lab.Outcome.COMPLETED
    assert platform.store.get("ticket:acme:7").version == 1


def test_comment_requires_exact_approval():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal()
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, now=NOW)
    assert code(exc) == "APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"tenant_id": "tenant:beta"}, "APPROVAL_SCOPE_MISMATCH"),
        ({"principal_id": "user:other"}, "APPROVAL_SCOPE_MISMATCH"),
        ({"action": "tickets.read"}, "APPROVAL_SCOPE_MISMATCH"),
        ({"target": "ticket:beta:8"}, "APPROVAL_SCOPE_MISMATCH"),
        ({"subject_digest": lab.digest(b"other")}, "APPROVAL_SCOPE_MISMATCH"),
        ({"policy_version": "old"}, "APPROVAL_STALE"),
        ({"approver_role": "viewer"}, "APPROVER_INELIGIBLE"),
        ({"approver_id": "user:analyst"}, "APPROVER_INELIGIBLE"),
    ],
)
def test_effect_approval_is_exact_independent_and_current(changes, expected):
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal()
    receipt = effect_approval(auth, proposal)
    receipt = lab.issue_approval(
        approval_id=receipt.approval_id, purpose=receipt.purpose,
        tenant_id=changes.get("tenant_id", receipt.tenant_id),
        principal_id=changes.get("principal_id", receipt.principal_id),
        action=changes.get("action", receipt.action), target=changes.get("target", receipt.target),
        subject_digest=changes.get("subject_digest", receipt.subject_digest),
        approver_id=changes.get("approver_id", receipt.approver_id),
        approver_role=changes.get("approver_role", receipt.approver_role), now=NOW,
    )
    if "policy_version" in changes:
        receipt = replace(receipt, policy_version=changes["policy_version"])
        unsigned = receipt.unsigned()
        receipt = replace(receipt, signature=lab.hmac.new(lab.APPROVAL_KEY, lab.canonical_json(unsigned), lab.sha256).hexdigest())
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=receipt, now=NOW)
    assert code(exc) == expected


def test_expired_approval_is_denied():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal()
    receipt = effect_approval(auth, proposal, now=NOW - timedelta(hours=1))
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=receipt, now=NOW)
    assert code(exc) == "APPROVAL_EXPIRED"


def test_approval_replay_does_not_duplicate_effect():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal()
    receipt = effect_approval(auth, proposal)
    platform.execute(auth, proposal, approval=receipt, now=NOW)
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=receipt, now=NOW)
    assert code(exc) == "APPROVAL_REPLAYED"
    assert len(platform.store.get(proposal.resource_id).comments) == 1


def test_concurrent_approval_consumers_have_one_winner():
    registry = lab.ApprovalRegistry()
    auth = lab.demo_auth(lab.demo_manifest())
    proposal = lab.demo_proposal()
    receipt = effect_approval(auth, proposal)

    def consume():
        try:
            registry.consume(
                receipt, purpose=lab.ApprovalPurpose.TOOL_EFFECT,
                tenant_id=auth.tenant_id, principal_id=auth.principal_id,
                action=proposal.tool, target=proposal.resource_id,
                subject_digest=proposal.proposal_digest,
                eligible_roles=frozenset({"support_lead"}), now=NOW,
            )
            return "ok"
        except lab.PlatformError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(), range(8)))
    assert results.count("ok") == 1
    assert results.count("APPROVAL_REPLAYED") == 7


def test_timeout_after_commit_reconciles_without_duplicate_comment():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal()
    first = platform.execute(
        auth, proposal, approval=effect_approval(auth, proposal, approval_id="approval:first"),
        now=NOW, fail_after_commit=True,
    )
    second = platform.execute(
        auth, proposal, approval=effect_approval(auth, proposal, approval_id="approval:retry"),
        now=NOW,
    )
    assert first.outcome == lab.Outcome.UNKNOWN
    assert second.outcome == lab.Outcome.RECONCILED
    assert len(platform.store.get(proposal.resource_id).comments) == 1


def test_idempotency_key_cannot_be_reused_for_different_input():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    first = lab.demo_proposal()
    platform.execute(auth, first, approval=effect_approval(auth, first, approval_id="approval:first"), now=NOW)
    changed = lab.demo_proposal(comment="different")
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, changed, approval=effect_approval(auth, changed, approval_id="approval:second"), now=NOW)
    assert code(exc) == "IDEMPOTENCY_CONFLICT"


def test_stale_resource_version_denies_before_effect():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal(version=0)
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    assert code(exc) == "STALE_RESOURCE"
    assert not platform.store.get(proposal.resource_id).comments


def test_each_runtime_decision_emits_privacy_minimized_event_and_span():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal(tool="tickets.read")
    platform.execute(auth, proposal, now=NOW)
    event = platform.events[-1]
    assert event.event_digest == lab.digest(event.unsigned())
    assert event.reason_code == "POLICY_ALLOW"
    assert event.outcome == lab.Outcome.COMPLETED
    assert not ({name for name, _ in event.attributes} & lab.FORBIDDEN_EVENT_FIELDS)
    assert platform.spans[-1].attributes["mcp.protocol.version"] == "2026-07-28"


def test_denied_decision_is_observable_without_raw_content():
    platform = lab.demo_platform()
    auth = lab.demo_auth(platform.manifest)
    proposal = lab.demo_proposal(tenant="tenant:beta")
    with pytest.raises(lab.PlatformError):
        platform.execute(auth, proposal, approval=effect_approval(auth, proposal), now=NOW)
    event = platform.events[-1]
    assert event.policy_decision == "deny"
    assert event.outcome == lab.Outcome.DENIED
    assert event.reason_code == "TENANT_SCOPE_DENIED"


def test_visibility_gap_is_not_reported_as_clean_egress():
    platform = lab.demo_platform()
    with pytest.raises(lab.PlatformError) as exc:
        platform.observe_egress(
            lab.demo_network_observation(event_id="event:7"),
            telemetry_healthy=False, now=NOW,
        )
    assert code(exc) == "VISIBILITY_GAP"


def test_allowed_egress_creates_no_alert():
    platform = lab.demo_platform()
    result = platform.observe_egress(
        lab.demo_network_observation(
            destination="tickets.internal.example", event_id="event:7"
        ),
        telemetry_healthy=True, now=NOW,
    )
    assert result is None
    assert not platform.alerts


def test_unapproved_egress_creates_exact_critical_alert():
    platform = lab.demo_platform()
    alert = critical_alert(platform)
    assert alert.severity == lab.Severity.CRITICAL
    assert alert.tenant_id == "tenant:acme"
    assert alert.event_ids == ("event:egress:7",)
    assert alert.alert_digest == lab.digest(alert.unsigned())


def test_network_observation_integrity_is_verified_before_detection():
    platform = lab.demo_platform()
    observation = replace(lab.demo_network_observation(), destination="changed.example")
    with pytest.raises(lab.PlatformError) as exc:
        platform.observe_egress(observation, telemetry_healthy=True, now=NOW)
    assert code(exc) == "TELEMETRY_INTEGRITY_INVALID"


def test_valid_signature_from_untrusted_network_producer_is_denied():
    platform = lab.demo_platform()
    observation = lab.demo_network_observation(producer="sensor:unknown")
    with pytest.raises(lab.PlatformError) as exc:
        platform.observe_egress(observation, telemetry_healthy=True, now=NOW)
    assert code(exc) == "TELEMETRY_PRODUCER_INVALID"


@pytest.mark.parametrize(
    "changes",
    [
        {"occurred_at": NOW.replace(tzinfo=None)},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"occurred_at": NOW - timedelta(minutes=11), "observed_at": NOW - timedelta(minutes=10)},
        {"occurred_at": NOW + timedelta(minutes=1), "observed_at": NOW + timedelta(minutes=1)},
    ],
)
def test_network_observation_requires_current_aware_ordered_time(changes):
    platform = lab.demo_platform()
    observation = replace(lab.demo_network_observation(), signature="", **changes)
    if any(value.tzinfo is None for value in changes.values() if hasattr(value, "tzinfo")):
        with pytest.raises(lab.PlatformError) as exc:
            lab.sign_network_observation(observation)
        assert code(exc) == "TIME_INVALID"
        return
    observation = lab.sign_network_observation(observation)
    with pytest.raises(lab.PlatformError) as exc:
        platform.observe_egress(observation, telemetry_healthy=True, now=NOW)
    assert code(exc) == "TELEMETRY_TIME_INVALID"


@pytest.mark.parametrize(
    ("tenant", "event_id"),
    [("tenant:unknown", "event:7"), ("tenant:acme", "bad event")],
)
def test_detector_rejects_unadmitted_scope(tenant, event_id):
    platform = lab.demo_platform()
    with pytest.raises(lab.PlatformError) as exc:
        platform.observe_egress(
            lab.demo_network_observation(tenant=tenant, event_id=event_id),
            telemetry_healthy=True, now=NOW,
        )
    assert code(exc) == "DETECTION_SCOPE_INVALID"


def test_containment_requires_admitted_untampered_alert():
    platform = lab.demo_platform()
    alert = critical_alert(platform)
    tampered = replace(alert, event_ids=("event:other",))
    with pytest.raises(lab.PlatformError) as exc:
        platform.contain(tampered, containment_approval(platform, alert), now=NOW)
    assert code(exc) == "ALERT_INVALID"


def test_containment_consumes_exact_approval_and_revokes_authority():
    platform = lab.demo_platform()
    alert = critical_alert(platform)
    platform.contain(alert, containment_approval(platform, alert), now=NOW)
    assert platform.state == lab.PlatformState.CONTAINED
    assert platform.verify_containment()
    assert "workload:support" in platform.revoked_workloads


def test_containment_approval_for_different_artifact_is_denied():
    platform = lab.demo_platform()
    alert = critical_alert(platform)
    wrong_subject = lab.digest({"alert": alert.alert_digest, "artifact": lab.digest(b"other")})
    receipt = lab.issue_approval(
        approval_id="approval:wrong-containment", purpose=lab.ApprovalPurpose.CONTAIN,
        tenant_id=alert.tenant_id, principal_id="incident:controller",
        action="disable_platform", target=platform.manifest.platform_id,
        subject_digest=wrong_subject, approver_id="user:incident-commander",
        approver_role="incident_commander", now=NOW,
    )
    with pytest.raises(lab.PlatformError) as exc:
        platform.contain(alert, receipt, now=NOW)
    assert code(exc) == "APPROVAL_SCOPE_MISMATCH"


def test_recovery_cannot_begin_before_verified_containment():
    with pytest.raises(lab.PlatformError) as exc:
        lab.demo_platform().begin_recovery()
    assert code(exc) == "CONTAINMENT_UNVERIFIED"


def contained_platform():
    platform = lab.demo_platform()
    alert = critical_alert(platform)
    platform.contain(alert, containment_approval(platform, alert), now=NOW)
    platform.begin_recovery()
    return platform


def test_recovery_rejects_contained_artifact_even_with_fresh_version_label():
    platform = contained_platform()
    candidate = lab.demo_manifest(version="10.0.1", artifact=platform._compromised_digest)
    evidence = lab.demo_evidence(candidate)
    with pytest.raises(lab.PlatformError) as exc:
        platform.recover(
            candidate, lab.demo_provenance(candidate), evidence,
            lab.demo_release_approval(
                candidate, evidence, purpose=lab.ApprovalPurpose.RECOVER
            ), now=NOW,
        )
    assert code(exc) == "RECOVERY_CANDIDATE_INVALID"


def test_recovery_requires_same_exact_release_gate_and_fresh_approval():
    platform = contained_platform()
    candidate = lab.demo_manifest(version="10.0.1")
    evidence = reseal_evidence(lab.demo_evidence(candidate), critical_vulnerabilities=1)
    with pytest.raises(lab.PlatformError) as exc:
        platform.recover(
            candidate, lab.demo_provenance(candidate), evidence,
            lab.demo_release_approval(
                candidate, evidence, purpose=lab.ApprovalPurpose.RECOVER
            ), now=NOW,
        )
    assert code(exc) == "RELEASE_GATE_FAILED"


def test_recovery_rejects_ordinary_release_purpose_receipt():
    platform = contained_platform()
    candidate = lab.demo_manifest(version="10.0.1")
    evidence = lab.demo_evidence(candidate)
    with pytest.raises(lab.PlatformError) as exc:
        platform.recover(
            candidate, lab.demo_provenance(candidate), evidence,
            lab.demo_release_approval(candidate, evidence), now=NOW,
        )
    assert code(exc) == "APPROVAL_SCOPE_MISMATCH"


def test_successful_recovery_activates_new_artifact_and_clears_workload_revocation():
    platform = contained_platform()
    old_digest = platform.manifest.artifact_digest
    candidate = lab.demo_manifest(version="10.0.1")
    evidence = lab.demo_evidence(candidate)
    platform.recover(
        candidate, lab.demo_provenance(candidate), evidence,
        lab.demo_release_approval(
            candidate, evidence, purpose=lab.ApprovalPurpose.RECOVER
        ), now=NOW,
    )
    assert platform.state == lab.PlatformState.ACTIVE
    assert platform.manifest.artifact_digest != old_digest
    assert "workload:support" not in platform.revoked_workloads


def test_old_runtime_identity_does_not_survive_recovery():
    platform = lab.demo_platform()
    old_auth = lab.demo_auth(platform.manifest)
    alert = critical_alert(platform)
    platform.contain(alert, containment_approval(platform, alert), now=NOW)
    platform.begin_recovery()
    candidate = lab.demo_manifest(version="10.0.1")
    evidence = lab.demo_evidence(candidate)
    platform.recover(
        candidate, lab.demo_provenance(candidate), evidence,
        lab.demo_release_approval(
            candidate, evidence, purpose=lab.ApprovalPurpose.RECOVER
        ), now=NOW,
    )
    with pytest.raises(lab.PlatformError) as exc:
        platform.execute(old_auth, lab.demo_proposal(tool="tickets.read"), now=NOW)
    assert code(exc) == "AUTHENTICATION_BINDING_INVALID"


def test_new_runtime_identity_works_after_recovery():
    platform = contained_platform()
    candidate = lab.demo_manifest(version="10.0.1")
    evidence = lab.demo_evidence(candidate)
    platform.recover(
        candidate, lab.demo_provenance(candidate), evidence,
        lab.demo_release_approval(
            candidate, evidence, purpose=lab.ApprovalPurpose.RECOVER
        ), now=NOW,
    )
    auth = lab.demo_auth(candidate)
    record = platform.execute(auth, lab.demo_proposal(tool="tickets.read"), now=NOW)
    assert record.outcome == lab.Outcome.COMPLETED


def test_evaluation_requires_named_population():
    with pytest.raises(lab.PlatformError) as exc:
        lab.evaluate_cases(())
    assert code(exc) == "EVALUATION_EMPTY"


def test_evaluation_separates_blocks_forbidden_effects_and_valid_work():
    metrics = lab.evaluate_cases((
        (False, lab.Outcome.COMPLETED),
        (False, lab.Outcome.DENIED),
        (True, lab.Outcome.DENIED),
        (True, lab.Outcome.UNKNOWN),
    ))
    assert metrics.labelled_cases == 4
    assert metrics.adversarial_cases == 2
    assert metrics.blocked_adversarial_cases == 1
    assert metrics.forbidden_effects == 1
    assert metrics.adversarial_block_rate == 0.5
    assert metrics.forbidden_effect_rate == 0.5
    assert metrics.valid_work_block_rate == 0.5
    assert metrics.compliant_success_rate == 0.5


def test_evaluation_discloses_absent_adversarial_denominator():
    metrics = lab.evaluate_cases(((False, lab.Outcome.COMPLETED),))
    assert metrics.adversarial_block_rate is None
    assert metrics.forbidden_effect_rate is None
    assert metrics.valid_work_block_rate == 0.0


def test_evaluation_discloses_absent_valid_denominator():
    metrics = lab.evaluate_cases(((True, lab.Outcome.DENIED),))
    assert metrics.valid_work_block_rate is None
    assert metrics.adversarial_block_rate == 1.0
    assert metrics.forbidden_effect_rate == 0.0


def test_unknown_adversarial_outcome_counts_conservatively_as_forbidden():
    metrics = lab.evaluate_cases(((True, lab.Outcome.UNKNOWN),))
    assert metrics.forbidden_effects == 1
    assert metrics.forbidden_effect_rate == 1.0


def test_platform_state_enum_has_no_model_owned_success_state():
    assert {state.value for state in lab.PlatformState} == {
        "candidate", "released", "active", "contained", "recovering"
    }
