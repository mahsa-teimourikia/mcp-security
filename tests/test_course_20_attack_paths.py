"""Executable invariants for Course 20 attack-path analysis."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import networkx as nx
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/20-multi-agent-cross-server-attack-paths/lab.py"
SPEC = importlib.util.spec_from_file_location("course_20_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def env():
    return lab.build_environment()


def replace_credential(controls, credential_id, **changes):
    credentials = tuple(
        replace(item, **changes) if item.credential_id == credential_id else item
        for item in controls.credentials
    )
    return replace(controls, credentials=credentials)


def edge_decision(edge_id, controls=None, **edge_changes):
    environment = env()
    controls = controls or environment.unsafe_controls
    edge = replace(environment.graph.edges[edge_id], **edge_changes)
    return environment.graph.assess_edge(edge, controls)


def test_demo_proves_attack_surface_reduction_without_blocking_valid_work():
    result = lab.run_demo()
    assert tuple(int(part) for part in result["networkx_version"].split(".")[:2]) >= (3, 5)
    assert result["snapshot"] == {"epoch": 7, "verified": True}
    assert result["topological_paths_to_secret"] == 2
    assert result["unsafe_exposure"].reachable_sensitive_assets == (
        "customer-pii",
        "production-secret",
    )
    assert result["unsafe_exposure"].exposure_rate == 1.0
    assert result["hardened_exposure"].reachable_sensitive_assets == ()
    assert result["hardened_exposure"].exposure_rate == 0.0
    assert result["unsafe_evaluation"].unsafe_allow_count >= 2
    assert result["hardened_evaluation"].unsafe_allow_count == 0
    assert result["hardened_evaluation"].false_block_rate == 0.0
    assert result["outcome_oracle"] == {"before": True, "after": False}
    assert result["containment"].complete is True


def test_networkx_is_the_real_graph_engine():
    graph = env().graph
    assert isinstance(graph.graph, nx.DiGraph)
    assert nx.has_path(graph.graph, "analytics-server", "production-secret")


def test_topological_reachability_is_not_executability():
    environment = env()
    graph = environment.graph
    topology = graph.topological_paths("shared-memory", "customer-pii")
    executable = graph.executable_paths(
        "shared-memory", "customer-pii", environment.unsafe_controls
    )
    assert topology
    assert executable == ()
    assessment = graph.assess_path(topology[0], environment.unsafe_controls)
    assert assessment.first_denial == lab.DecisionCode.UNTRUSTED_SIGNAL_IS_NOT_AUTHORITY


def test_path_cutoff_bounds_combinatorial_search():
    environment = env()
    graph = environment.graph
    assert graph.topological_paths("analytics-server", "customer-pii", max_hops=3) == ()
    assert graph.topological_paths("analytics-server", "customer-pii", max_hops=4)


def test_missing_nodes_return_no_paths_without_disclosure():
    graph = env().graph
    assert graph.topological_paths("unknown", "customer-pii") == ()
    assert graph.topological_paths("analytics-server", "unknown") == ()


def test_invalid_or_singleton_path_is_rejected():
    environment = env()
    with pytest.raises(ValueError, match="at least one valid"):
        environment.graph.assess_path(("analytics-server",), environment.unsafe_controls)
    with pytest.raises(ValueError, match="at least one valid"):
        environment.graph.assess_path(
            ("analytics-server", "customer-pii"), environment.unsafe_controls
        )


def test_snapshot_signature_and_digest_are_verified():
    environment = env()
    snapshot = environment.graph.snapshot
    lab.verify_snapshot(snapshot, now=lab.NOW, highest_epoch=7)
    with pytest.raises(ValueError, match="digest"):
        lab.verify_snapshot(replace(snapshot, digest="sha256:tampered"), now=lab.NOW)
    with pytest.raises(ValueError, match="signature"):
        lab.verify_snapshot(replace(snapshot, signature="0" * 64), now=lab.NOW)


def test_snapshot_freshness_rollback_and_future_are_rejected():
    snapshot = env().graph.snapshot
    with pytest.raises(ValueError, match="rollback"):
        lab.verify_snapshot(snapshot, now=lab.NOW, highest_epoch=8)
    with pytest.raises(ValueError, match="stale"):
        lab.verify_snapshot(snapshot, now=lab.NOW + timedelta(hours=25))
    future = lab.sign_snapshot(
        "future",
        8,
        lab.NOW + timedelta(minutes=6),
        snapshot.assets,
        snapshot.edges,
        snapshot.evidence,
    )
    with pytest.raises(ValueError, match="future"):
        lab.verify_snapshot(future, now=lab.NOW)


def test_same_epoch_different_digest_is_equivocation():
    snapshot = env().graph.snapshot
    changed = lab.sign_snapshot(
        "different-state",
        snapshot.epoch,
        lab.NOW,
        snapshot.assets,
        snapshot.edges,
        snapshot.evidence,
    )
    with pytest.raises(ValueError, match="equivocation"):
        lab.verify_snapshot(
            changed,
            now=lab.NOW,
            highest_epoch=snapshot.epoch,
            accepted_digest=snapshot.digest,
        )


def test_evidence_cannot_be_newer_than_signed_snapshot():
    snapshot = env().graph.snapshot
    future_evidence = replace(
        snapshot.evidence[0], observed_at=snapshot.observed_at + timedelta(seconds=1)
    )
    changed = lab.sign_snapshot(
        "future-evidence",
        8,
        lab.NOW,
        snapshot.assets,
        snapshot.edges,
        (future_evidence,) + snapshot.evidence[1:],
    )
    with pytest.raises(ValueError, match="newer"):
        lab.verify_snapshot(changed, now=lab.NOW)


def test_graph_rejects_duplicate_assets_edges_and_evidence():
    snapshot = env().graph.snapshot
    duplicate_asset = lab.sign_snapshot(
        "duplicate-asset", 8, lab.NOW, snapshot.assets + (snapshot.assets[0],), snapshot.edges, snapshot.evidence
    )
    with pytest.raises(ValueError, match="duplicate asset"):
        lab.AttackGraph(duplicate_asset)
    duplicate_edge = lab.sign_snapshot(
        "duplicate-edge", 8, lab.NOW, snapshot.assets, snapshot.edges + (snapshot.edges[0],), snapshot.evidence
    )
    with pytest.raises(ValueError, match="duplicate edge"):
        lab.AttackGraph(duplicate_edge)
    duplicate_evidence = lab.sign_snapshot(
        "duplicate-evidence", 8, lab.NOW, snapshot.assets, snapshot.edges, snapshot.evidence + (snapshot.evidence[0],)
    )
    with pytest.raises(ValueError, match="duplicate evidence"):
        lab.AttackGraph(duplicate_evidence)


def test_graph_rejects_unknown_or_parallel_endpoint_edges():
    snapshot = env().graph.snapshot
    unknown = replace(snapshot.edges[0], edge_id="unknown", target="missing")
    invalid = lab.sign_snapshot("unknown", 8, lab.NOW, snapshot.assets, snapshot.edges + (unknown,), snapshot.evidence)
    with pytest.raises(ValueError, match="unknown endpoint"):
        lab.AttackGraph(invalid)
    parallel = replace(snapshot.edges[0], edge_id="parallel", action="other")
    invalid = lab.sign_snapshot("parallel", 8, lab.NOW, snapshot.assets, snapshot.edges + (parallel,), snapshot.evidence)
    with pytest.raises(ValueError, match="one edge"):
        lab.AttackGraph(invalid)


def test_graph_rejects_unknown_evidence_reference_during_ingestion():
    snapshot = env().graph.snapshot
    edge = replace(snapshot.edges[0], evidence_ids=("missing",))
    edges = (edge,) + snapshot.edges[1:]
    invalid = lab.sign_snapshot(
        "missing-evidence", 8, lab.NOW, snapshot.assets, edges, snapshot.evidence
    )
    with pytest.raises(ValueError, match="unknown evidence"):
        lab.AttackGraph(invalid)


def test_asset_edge_and_evidence_schema_validation():
    with pytest.raises(ValueError, match="identity"):
        lab.Asset("", lab.AssetKind.HOST, "acme", "zone")
    with pytest.raises(ValueError, match="criticality"):
        lab.Asset("host", lab.AssetKind.HOST, "acme", "zone", criticality=6)
    with pytest.raises(ValueError, match="provenance"):
        lab.Evidence("", "source", "kind", lab.NOW, "digest")
    with pytest.raises(ValueError, match="provenance"):
        lab.AttackEdge("edge", "a", "b", lab.Relation.CALLS, "read", "", "acme", ())


@pytest.mark.parametrize(
    "edge_id,controls_change,expected",
    [
        ("e-direct-secrets", {"blocked_edges": frozenset({"e-direct-secrets"})}, lab.DecisionCode.EDGE_DISABLED),
        ("e-direct-secrets", {"quarantined_assets": frozenset({"analytics-server"})}, lab.DecisionCode.ASSET_QUARANTINED),
        ("e-direct-secrets", {"allowed_routes": frozenset()}, lab.DecisionCode.ROUTE_DENIED),
        ("e-direct-secrets", {"require_gateway": True}, lab.DecisionCode.GATEWAY_REQUIRED),
        ("e-direct-secrets", {"revoked_credentials": frozenset({"cred-shared"})}, lab.DecisionCode.CREDENTIAL_REVOKED),
        ("e-direct-secrets", {"permit_wildcards": False}, lab.DecisionCode.WILDCARD_CREDENTIAL_DENIED),
    ],
)
def test_current_control_plane_gates_each_edge(edge_id, controls_change, expected):
    environment = env()
    controls = replace(environment.unsafe_controls, **controls_change)
    assert edge_decision(edge_id, controls).code == expected


def test_edge_requires_current_provenance_evidence():
    assert edge_decision("e-direct-secrets", evidence_ids=("missing",)).code == lab.DecisionCode.EVIDENCE_MISSING
    environment = env()
    decision = environment.graph.assess_edge(
        environment.graph.edges["e-direct-secrets"],
        environment.unsafe_controls,
        now=lab.NOW + timedelta(hours=25),
    )
    assert decision.code == lab.DecisionCode.EVIDENCE_STALE


def test_tenant_context_is_not_inferred_from_connectivity():
    assert edge_decision("e-direct-secrets", tenant="other").code == lab.DecisionCode.TENANT_MISMATCH


def test_registry_binding_checks_exact_artifact_workload_tenant_and_state():
    environment = env()
    edge = environment.graph.edges["e-gateway-support"]
    assert environment.graph.assess_edge(edge, environment.unsafe_controls).allowed
    for change in (
        {"active": False},
        {"tenant": "other"},
        {"artifact_digest": "sha256:wrong"},
        {"workload_id": "spiffe://evil/wrong"},
    ):
        bindings = tuple(
            replace(item, **change) if item.server_id == "support-server" else item
            for item in environment.unsafe_controls.registry_bindings
        )
        controls = replace(environment.unsafe_controls, registry_bindings=bindings)
        assert environment.graph.assess_edge(edge, controls).code == lab.DecisionCode.REGISTRY_BINDING_INVALID
    assert edge_decision("e-discover-rogue").code == lab.DecisionCode.REGISTRY_BINDING_INVALID


def test_missing_credential_is_denied():
    assert edge_decision("e-direct-secrets", credential_id="absent").code == lab.DecisionCode.CREDENTIAL_MISSING


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"expires_at": lab.NOW}, lab.DecisionCode.CREDENTIAL_EXPIRED),
        ({"tenant": "other"}, lab.DecisionCode.CREDENTIAL_TENANT_MISMATCH),
        ({"audiences": ("api://other",)}, lab.DecisionCode.CREDENTIAL_AUDIENCE_MISMATCH),
        ({"actions": ("ticket.read",)}, lab.DecisionCode.CREDENTIAL_ACTION_MISMATCH),
        ({"resources": ("secret://acme/other",)}, lab.DecisionCode.CREDENTIAL_RESOURCE_MISMATCH),
        ({"sender_bound": True, "presenter": "other"}, lab.DecisionCode.CREDENTIAL_PRESENTER_MISMATCH),
    ],
)
def test_credential_is_bound_to_current_context(changes, expected):
    environment = env()
    controls = replace_credential(environment.unsafe_controls, "cred-shared", **changes)
    assert edge_decision("e-direct-secrets", controls).code == expected


def test_sender_bound_valid_credential_allows_only_exact_presenter():
    environment = env()
    edge = environment.graph.edges["e-valid-agent-gateway"]
    assert environment.graph.assess_edge(edge, environment.unsafe_controls).allowed
    controls = replace_credential(environment.unsafe_controls, "cred-triage", presenter="other")
    assert environment.graph.assess_edge(edge, controls).code == lab.DecisionCode.CREDENTIAL_PRESENTER_MISMATCH


def test_approval_is_exact_current_and_single_use():
    environment = env()
    base = environment.graph.edges["e-direct-secrets"]
    edge = replace(base, approval_id="approval-1")
    assert environment.graph.assess_edge(edge, environment.unsafe_controls).code == lab.DecisionCode.APPROVAL_MISSING
    valid = lab.ApprovalReceipt("approval-1", "acme", edge.source, edge.target, edge.action, edge.resource, lab.NOW + timedelta(minutes=1))
    controls = replace(environment.unsafe_controls, approvals=(valid,))
    assert environment.graph.assess_edge(edge, controls).allowed
    for change in (
        {"consumed": True},
        {"expires_at": lab.NOW},
        {"tenant": "other"},
        {"source": "other"},
        {"target": "other"},
        {"action": "other"},
        {"resource": "other"},
    ):
        controls = replace(environment.unsafe_controls, approvals=(replace(valid, **change),))
        assert environment.graph.assess_edge(edge, controls).code == lab.DecisionCode.APPROVAL_INVALID


def test_hardened_controls_preserve_the_labelled_valid_path():
    environment = env()
    paths = environment.graph.executable_paths(
        "triage-agent", "customer-pii", environment.hardened_controls
    )
    assert len(paths) == 1
    assert all(item.code == lab.DecisionCode.ALLOW for item in paths[0].decisions)


def test_hardening_removes_all_compromised_server_sensitive_paths():
    environment = env()
    for target in ("customer-pii", "production-secret"):
        assert environment.graph.topological_paths("analytics-server", target)
        assert environment.graph.executable_paths(
            "analytics-server", target, environment.hardened_controls
        ) == ()


def test_exposure_metric_has_explicit_denominator_and_maximum_criticality():
    environment = env()
    unsafe = environment.graph.sensitive_exposure(
        "analytics-server", environment.unsafe_controls
    )
    hardened = environment.graph.sensitive_exposure(
        "analytics-server", environment.hardened_controls
    )
    assert len(unsafe.sensitive_assets) == 2
    assert len(unsafe.reachable_sensitive_assets) == 2
    assert unsafe.exposure_rate == 2 / 2
    assert unsafe.maximum_criticality == 5
    assert hardened.exposure_rate == 0 / 2
    assert hardened.maximum_criticality == 0


def test_evaluation_separates_unsafe_allows_from_false_blocks():
    environment = env()
    unsafe = lab.evaluate_cases(
        environment.graph, environment.unsafe_controls, environment.cases
    )
    hardened = lab.evaluate_cases(
        environment.graph, environment.hardened_controls, environment.cases
    )
    assert unsafe.total == 5
    assert unsafe.valid_case_count == 1
    assert unsafe.unsafe_allow_rate == unsafe.unsafe_allow_count / 4
    assert hardened.unsafe_allow_rate == 0 / 4
    assert hardened.false_block_rate == 0 / 1


def test_empty_evaluation_denominators_are_defined():
    environment = env()
    report = lab.evaluate_cases(environment.graph, environment.hardened_controls, ())
    assert report.total == 0
    assert report.unsafe_allow_rate == 0.0
    assert report.false_block_rate == 0.0


def test_resource_ledger_ignores_self_reported_claims_and_rechecks_current_state():
    environment = env()
    path = environment.graph.executable_paths(
        "analytics-server", "production-secret", environment.unsafe_controls
    )[0]
    ledger = lab.ResourceLedger()
    performed = ledger.attempt(
        "op-1", path, environment.graph, environment.unsafe_controls, adapter_claim="blocked"
    )
    blocked = ledger.attempt(
        "op-2", path, environment.graph, environment.hardened_controls, adapter_claim="allowed"
    )
    assert performed.performed is True
    assert performed.reason == "final resource recorded the effect"
    assert blocked.performed is False
    assert blocked.reason == environment.graph.assess_path(
        path.nodes, environment.hardened_controls
    ).first_denial.value


def test_non_data_target_cannot_be_reported_as_completed_effect():
    environment = env()
    path = environment.graph.executable_paths(
        "analytics-server", "mcp-gateway", environment.unsafe_controls
    )[0]
    record = lab.ResourceLedger().attempt(
        "op", path, environment.graph, environment.unsafe_controls
    )
    assert record.performed is False
    assert "not an effect resource" in record.reason


@pytest.mark.parametrize(
    "kind,target,field,value",
    [
        ("quarantine_asset", "analytics-server", "quarantined_assets", "analytics-server"),
        ("revoke_credential", "cred-shared", "revoked_credentials", "cred-shared"),
        ("block_edge", "e-direct-secrets", "blocked_edges", "e-direct-secrets"),
    ],
)
def test_containment_events_are_versioned_and_monotonic(kind, target, field, value):
    controls = env().unsafe_controls
    event = lab.ContainmentEvent(2, lab.NOW, kind, target)
    updated = lab.apply_containment_event(controls, event)
    assert updated.revision == 2
    assert value in getattr(updated, field)


def test_containment_events_enable_gateway_and_wildcard_controls():
    controls = env().unsafe_controls
    controls = lab.apply_containment_event(
        controls, lab.ContainmentEvent(2, lab.NOW, "require_gateway", "all")
    )
    assert controls.require_gateway is True
    controls = lab.apply_containment_event(
        controls, lab.ContainmentEvent(3, lab.NOW, "deny_wildcards", "all")
    )
    assert controls.permit_wildcards is False


def test_containment_event_rejects_gap_time_regression_and_unknown_kind():
    controls = env().unsafe_controls
    with pytest.raises(ValueError, match="contiguous"):
        lab.apply_containment_event(
            controls, lab.ContainmentEvent(3, lab.NOW, "block_edge", "edge")
        )
    with pytest.raises(ValueError, match="backwards"):
        lab.apply_containment_event(
            controls,
            lab.ContainmentEvent(
                2, controls.updated_at - timedelta(seconds=1), "block_edge", "edge"
            ),
        )
    with pytest.raises(ValueError, match="unknown"):
        lab.apply_containment_event(
            controls, lab.ContainmentEvent(2, lab.NOW, "invent", "edge")
        )


def test_containment_proof_fails_when_control_revision_has_not_propagated():
    environment = env()
    proof = lab.prove_containment(
        environment.graph,
        replace(environment.hardened_controls, revision=4),
        lab.ResourceLedger(),
        source="analytics-server",
        targets=("customer-pii", "production-secret"),
        required_revision=5,
        incident_started_at=lab.NOW - timedelta(minutes=4),
        now=lab.NOW,
    )
    assert proof.complete is False
    assert proof.observed_revision == 4
    assert proof.time_to_cut_seconds is None


def test_containment_proof_fails_on_residual_path():
    environment = env()
    proof = lab.prove_containment(
        environment.graph,
        replace(environment.unsafe_controls, revision=5),
        lab.ResourceLedger(),
        source="analytics-server",
        targets=("customer-pii", "production-secret"),
        required_revision=5,
        incident_started_at=lab.NOW - timedelta(minutes=4),
        now=lab.NOW,
    )
    assert proof.complete is False
    assert proof.residual_targets == ("customer-pii", "production-secret")


def test_containment_proof_fails_on_post_cut_forbidden_effect():
    environment = env()
    ledger = lab.ResourceLedger()
    ledger.records.append(
        lab.EffectRecord(
            "op-late",
            "analytics-server",
            "production-secret",
            True,
            lab.NOW,
            "observed",
        )
    )
    proof = lab.prove_containment(
        environment.graph,
        environment.hardened_controls,
        ledger,
        source="analytics-server",
        targets=("customer-pii", "production-secret"),
        required_revision=5,
        incident_started_at=lab.NOW - timedelta(minutes=4),
        now=lab.NOW,
    )
    assert proof.complete is False
    assert proof.forbidden_effect_count == 1


def test_containment_completion_has_measured_time_to_cut():
    environment = env()
    proof = lab.prove_containment(
        environment.graph,
        environment.hardened_controls,
        lab.ResourceLedger(),
        source="analytics-server",
        targets=("customer-pii", "production-secret"),
        required_revision=5,
        incident_started_at=lab.NOW - timedelta(minutes=4),
        now=lab.NOW,
    )
    assert proof.complete is True
    assert proof.time_to_cut_seconds == 240.0


def test_minimum_cut_is_only_a_topological_planning_hint():
    environment = env()
    hints = environment.graph.topological_choke_points(
        "analytics-server", "production-secret"
    )
    assert isinstance(hints, tuple)
    assert environment.graph.topological_choke_points("unknown", "production-secret") == ()
    assert environment.graph.topological_choke_points("ticket-api", "production-secret") == ()
    # A hint does not mutate current enforcement or remove executable paths.
    assert environment.graph.executable_paths(
        "analytics-server", "production-secret", environment.unsafe_controls
    )


def test_utc_parser_requires_timezone_and_normalizes_to_utc():
    assert lab.utc("2026-10-28T18:00:00Z") == lab.NOW
    with pytest.raises(ValueError, match="timezone"):
        lab.utc("2026-10-28T18:00:00")
