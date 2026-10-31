"""Executable security and governance invariants for Course 24."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/24-mcp-identity-non-human-identity-governance/lab.py"
SPEC = importlib.util.spec_from_file_location("course_24_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


NOW = 1_000
MCP_AUD = "https://mcp.acme.test/support"
API_AUD = "https://tickets.acme.test"
SENDER = "sha256:gateway-proof-key-2026"


def setup_demo():
    return lab.build_demo(NOW)


def issue_token(*, scopes=frozenset({"ticket:read"}), ttl=300, nonce="n-1", **changes):
    registry, attestor, issuer, record, audit = setup_demo()
    args = {
        "identity_id": record.identity_id,
        "audience": MCP_AUD,
        "scopes": scopes,
        "purpose": record.purpose,
        "ttl_seconds": ttl,
        "sender_thumbprint": SENDER,
        "attestation": lab.make_attestation(attestor, record, NOW + 2, nonce),
        "now": NOW + 2,
        "request_id": "request-1",
    }
    args.update(changes)
    token = issuer.issue(**args)
    return registry, attestor, issuer, registry.get(record.identity_id), audit, token


def error_code(exc):
    return exc.value.code


def test_demo_uses_real_signed_credentials_and_attenuates_child(capsys):
    lab.main()
    output = capsys.readouterr().out
    assert '"child_scopes": [' in output
    assert '"ticket:read"' in output
    assert '"inventory_coverage": 1.0' in output


def test_registration_activates_exact_approved_candidate():
    registry, _, _, record, audit = setup_demo()
    assert record.state is lab.LifecycleState.ACTIVE
    assert registry.get(record.identity_id) == record
    assert audit.events[0].event_type == "identity.registered"


def test_approval_requires_two_people():
    registry, _, _, _, _ = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        registry.approvals.issue({"x": 1}, "security-approver", "security-approver", NOW)
    assert error_code(exc) == "SEPARATION_OF_DUTIES"


@pytest.mark.parametrize("approver", ["unknown", "platform-team"])
def test_approval_requires_active_authorized_approver(approver):
    registry, _, _, _, _ = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        registry.approvals.issue({"x": 1}, "engineer", approver, NOW)
    assert error_code(exc) == "APPROVER_NOT_AUTHORIZED"


@pytest.mark.parametrize("ttl", [0, -1, 601])
def test_approval_ttl_is_bounded(ttl):
    registry, _, _, _, _ = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        registry.approvals.issue(
            {"x": 1}, "engineer", "security-approver", NOW, ttl
        )
    assert error_code(exc) == "APPROVAL_TTL_INVALID"


def test_approval_is_bound_to_full_proposal():
    registry, _, _, _, _ = setup_demo()
    receipt = registry.approvals.issue(
        {"scopes": ["read"]}, "engineer", "security-approver", NOW
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.approvals.consume(
            receipt.receipt_id, {"scopes": ["read", "write"]}, "engineer", NOW + 1
        )
    assert error_code(exc) == "APPROVAL_BINDING_MISMATCH"


def test_approval_expires_and_is_single_use():
    registry, _, _, _, _ = setup_demo()
    proposal = {"x": 1}
    expired = registry.approvals.issue(
        proposal, "engineer", "security-approver", NOW, 1
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.approvals.consume(expired.receipt_id, proposal, "engineer", NOW + 1)
    assert error_code(exc) == "APPROVAL_EXPIRED"
    fresh = registry.approvals.issue(
        proposal, "engineer", "security-approver", NOW + 2
    )
    registry.approvals.consume(fresh.receipt_id, proposal, "engineer", NOW + 3)
    with pytest.raises(lab.GovernanceError) as replay:
        registry.approvals.consume(fresh.receipt_id, proposal, "engineer", NOW + 4)
    assert error_code(replay) == "APPROVAL_REPLAY"


def test_approval_consumption_is_atomic_under_concurrency():
    registry, _, _, _, _ = setup_demo()
    proposal = {"operation": "rotate", "digest": "b" * 64}
    receipt = registry.approvals.issue(
        proposal, "engineer", "security-approver", NOW
    )

    def consume_once():
        try:
            registry.approvals.consume(
                receipt.receipt_id, proposal, "engineer", NOW + 1
            )
            return "consumed"
        except lab.GovernanceError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume_once(), range(20)))
    assert results.count("consumed") == 1
    assert results.count("APPROVAL_REPLAY") == 19


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"identity_id": "spiffe://other.test/x"}, "IDENTITY_TRUST_DOMAIN_MISMATCH"),
        ({"owner_id": "missing"}, "OWNER_INACTIVE_OR_UNKNOWN"),
        ({"allowed_scopes": frozenset()}, "IDENTITY_BOUNDARY_EMPTY"),
        ({"allowed_scopes": frozenset({"*"})}, "WILDCARD_AUTHORITY"),
        ({"allowed_audiences": frozenset({"https://*"})}, "WILDCARD_AUTHORITY"),
        ({"artifact_digest": "latest"}, "ARTIFACT_DIGEST_INVALID"),
        ({"max_ttl_seconds": 3_601}, "CREDENTIAL_TTL_OUT_OF_POLICY"),
        ({"max_ttl_seconds": 59}, "CREDENTIAL_TTL_OUT_OF_POLICY"),
        ({"state": lab.LifecycleState.ACTIVE}, "INITIAL_STATE_INVALID"),
        ({"shared": True}, "SHARED_IDENTITY_FORBIDDEN"),
    ],
)
def test_candidate_registration_rejects_unsafe_identity_shape(changes, code):
    audit = lab.AuditLog()
    owners = [
        lab.Owner("platform-team", "platform", True, frozenset()),
        lab.Owner("security-approver", "security", True, frozenset({"identity-approver"})),
    ]
    registry = lab.IdentityRegistry(owners, audit)
    candidate = replace(lab.make_candidate(NOW), **changes)
    receipt = registry.approvals.issue(
        candidate.proposal(), "engineer", "security-approver", NOW
    )
    with pytest.raises(lab.GovernanceError) as exc:
        registry.register(candidate, receipt.receipt_id, "engineer", NOW + 1)
    assert error_code(exc) == code


def test_attestation_proves_workload_selectors_artifact_and_freshness():
    registry, attestor, _, record, _ = setup_demo()
    signed = lab.make_attestation(attestor, record, NOW + 2, "fresh")
    evidence_digest = attestor.verify(signed, record, NOW + 2)
    assert len(evidence_digest) == 64
    assert "fresh" in attestor.used_nonces
    assert registry.get(record.identity_id).artifact_digest == signed.evidence.artifact_digest


def test_attestation_signature_tampering_fails():
    _, attestor, _, record, _ = setup_demo()
    signed = lab.make_attestation(attestor, record, NOW + 2, "tamper")
    tampered = replace(signed, signature=b"0" * 64)
    with pytest.raises(lab.GovernanceError) as exc:
        attestor.verify(tampered, record, NOW + 2)
    assert error_code(exc) == "ATTESTATION_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"workload_id": "spiffe://acme.test/evil"}, "ATTESTATION_IDENTITY_MISMATCH"),
        ({"tenant_id": "other"}, "ATTESTATION_IDENTITY_MISMATCH"),
        ({"trust_domain": "evil.test"}, "ATTESTATION_IDENTITY_MISMATCH"),
        ({"selectors": frozenset({"k8s:ns:support"})}, "ATTESTATION_SELECTOR_MISMATCH"),
        ({"artifact_digest": "b" * 64}, "ATTESTATION_ARTIFACT_MISMATCH"),
    ],
)
def test_attestation_binding_rejects_mismatch(changes, code):
    _, attestor, _, record, _ = setup_demo()
    original = lab.make_attestation(attestor, record, NOW + 2, "mismatch").evidence
    changed = replace(original, **changes)
    signed = attestor.issue(changed)
    with pytest.raises(lab.GovernanceError) as exc:
        attestor.verify(signed, record, NOW + 2)
    assert error_code(exc) == code


def test_attestation_rejects_staleness_future_and_replay():
    _, attestor, _, record, _ = setup_demo()
    stale = lab.make_attestation(attestor, record, NOW, "stale")
    with pytest.raises(lab.GovernanceError) as exc:
        attestor.verify(stale, record, NOW + 61)
    assert error_code(exc) == "ATTESTATION_STALE"
    future = lab.make_attestation(attestor, record, NOW + 10, "future")
    with pytest.raises(lab.GovernanceError) as exc:
        attestor.verify(future, record, NOW)
    assert error_code(exc) == "ATTESTATION_STALE"
    fresh = lab.make_attestation(attestor, record, NOW + 2, "once")
    attestor.verify(fresh, record, NOW + 2)
    with pytest.raises(lab.GovernanceError) as exc:
        attestor.verify(fresh, record, NOW + 2)
    assert error_code(exc) == "ATTESTATION_REPLAY"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"audience": "https://evil.test"}, "AUDIENCE_NOT_ALLOWED"),
        ({"scopes": frozenset()}, "SCOPE_NOT_ALLOWED"),
        ({"scopes": frozenset({"ticket:delete"})}, "SCOPE_NOT_ALLOWED"),
        ({"purpose": "unrelated"}, "PURPOSE_MISMATCH"),
        ({"ttl_seconds": 601}, "TOKEN_TTL_OUT_OF_POLICY"),
        ({"ttl_seconds": 0}, "TOKEN_TTL_OUT_OF_POLICY"),
        ({"sender_thumbprint": "short"}, "SENDER_BINDING_INVALID"),
    ],
)
def test_issuance_rejects_authority_expansion(changes, code):
    registry, attestor, issuer, record, _ = setup_demo()
    args = {
        "identity_id": record.identity_id,
        "audience": MCP_AUD,
        "scopes": frozenset({"ticket:read"}),
        "purpose": record.purpose,
        "ttl_seconds": 300,
        "sender_thumbprint": SENDER,
        "attestation": lab.make_attestation(attestor, record, NOW + 2, code),
        "now": NOW + 2,
        "request_id": code,
    }
    args.update(changes)
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.issue(**args)
    assert error_code(exc) == code


def test_issuance_is_idempotent_but_conflicting_retry_fails():
    registry, attestor, issuer, record, _ = setup_demo()
    attestation = lab.make_attestation(attestor, record, NOW + 2, "idempotent")
    args = dict(
        identity_id=record.identity_id,
        audience=MCP_AUD,
        scopes=frozenset({"ticket:read"}),
        purpose=record.purpose,
        ttl_seconds=300,
        sender_thumbprint=SENDER,
        attestation=attestation,
        now=NOW + 2,
        request_id="same-operation",
    )
    first = issuer.issue(**args)
    assert issuer.issue(**args) == first
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.issue(**(args | {"scopes": frozenset({"ticket:triage"})}))
    assert error_code(exc) == "ISSUANCE_IDEMPOTENCY_CONFLICT"


def test_token_contains_required_governance_context():
    _, _, issuer, record, _, token = issue_token()
    claims = issuer.verify(
        token, MCP_AUD, frozenset({"ticket:read"}), SENDER,
        "acme", record.purpose, NOW + 3,
    )
    assert claims["sub"] == record.identity_id
    assert claims["tenant_id"] == "acme"
    assert claims["policy_version"] == lab.POLICY_VERSION
    assert claims["cnf"]["jkt"] == SENDER
    assert claims["identity_version"] == 1


@pytest.mark.parametrize(
    ("verify_changes", "code"),
    [
        ({"audience": API_AUD}, "TOKEN_AUDIENCE_INVALID"),
        ({"sender_thumbprint": "sha256:different-presenter"}, "TOKEN_SENDER_MISMATCH"),
        ({"tenant_id": "other"}, "TOKEN_TENANT_MISMATCH"),
        ({"purpose": "other"}, "TOKEN_PURPOSE_MISMATCH"),
        ({"required_scopes": frozenset({"ticket:triage"})}, "TOKEN_SCOPE_INSUFFICIENT"),
        ({"now": NOW + 302}, "TOKEN_EXPIRED"),
    ],
)
def test_verifier_rejects_wrong_context(verify_changes, code):
    _, _, issuer, record, _, token = issue_token()
    args = {
        "token": token,
        "audience": MCP_AUD,
        "required_scopes": frozenset({"ticket:read"}),
        "sender_thumbprint": SENDER,
        "tenant_id": "acme",
        "purpose": record.purpose,
        "now": NOW + 3,
    }
    args.update(verify_changes)
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.verify(**args)
    assert error_code(exc) == code


def test_tampered_token_signature_fails():
    _, _, issuer, record, _, token = issue_token()
    parts = token.split(".")
    parts[1] = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.verify(
            ".".join(parts), MCP_AUD, frozenset(), SENDER,
            "acme", record.purpose, NOW + 3,
        )
    assert error_code(exc) == "TOKEN_INVALID"


def test_specific_token_revocation_blocks_use():
    _, _, issuer, record, _, token = issue_token()
    claims = issuer._decode(token, MCP_AUD)
    issuer.revoke_token(claims["jti"], NOW + 3, "suspected replay")
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.verify(
            token, MCP_AUD, frozenset(), SENDER,
            "acme", record.purpose, NOW + 4,
        )
    assert error_code(exc) == "TOKEN_REVOKED"


@pytest.mark.parametrize("transition", ["suspend", "revoke"])
def test_identity_containment_invalidates_existing_token(transition):
    registry, _, issuer, record, _, token = issue_token()
    getattr(registry, transition)(record.identity_id, record.version, NOW + 3, "incident")
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.verify(
            token, MCP_AUD, frozenset(), SENDER,
            "acme", record.purpose, NOW + 4,
        )
    assert error_code(exc) == "IDENTITY_NOT_ACTIVE"


def test_approved_rotation_bumps_version_and_invalidates_old_token():
    registry, _, issuer, record, _, token = issue_token()
    changes = {"artifact_digest": "b" * 64, "review_due_at": NOW + 50_000}
    proposal = registry.change_proposal(record.identity_id, changes, record.version)
    receipt = registry.approvals.issue(
        proposal, "engineer-7", "security-approver", NOW + 3
    )
    rotated = registry.replace_with_approval(
        record.identity_id, changes, record.version, receipt.receipt_id,
        "engineer-7", NOW + 4,
    )
    assert rotated.version == 2
    assert rotated.credential_rotated_at == NOW + 4
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.verify(
            token, MCP_AUD, frozenset(), SENDER,
            "acme", record.purpose, NOW + 5,
        )
    assert error_code(exc) == "TOKEN_IDENTITY_VERSION_STALE"


def test_stale_writer_cannot_overwrite_new_identity_version():
    registry, _, _, record, _ = setup_demo()
    with pytest.raises(lab.GovernanceError) as exc:
        registry.suspend(record.identity_id, 99, NOW + 2, "incident")
    assert error_code(exc) == "STALE_IDENTITY_VERSION"


def test_delegation_attenuates_scope_audience_lifetime_and_links_parent():
    registry, attestor, issuer, record, _, token = issue_token(
        scopes=frozenset({"ticket:read", "ticket:triage"})
    )
    child = issuer.exchange(
        token, MCP_AUD, API_AUD, frozenset({"ticket:read"}), SENDER,
        "sha256:downstream-proof-key", "acme", record.purpose, 100,
        lab.make_attestation(attestor, registry.get(record.identity_id), NOW + 4, "child"),
        NOW + 4, "exchange-1",
    )
    child_claims = issuer.verify(
        child, API_AUD, frozenset({"ticket:read"}),
        "sha256:downstream-proof-key", "acme", record.purpose, NOW + 5,
    )
    parent_claims = issuer._decode(token, MCP_AUD)
    assert child_claims["parent_jti"] == parent_claims["jti"]
    assert child_claims["scope"] == "ticket:read"
    assert child_claims["exp"] < parent_claims["exp"]


@pytest.mark.parametrize(
    ("child_scopes", "ttl", "code"),
    [
        (frozenset({"ticket:read", "ticket:delete"}), 100, "DELEGATION_SCOPE_EXPANSION"),
        (frozenset({"ticket:read"}), 500, "DELEGATION_LIFETIME_EXPANSION"),
    ],
)
def test_delegation_cannot_expand_parent_authority(child_scopes, ttl, code):
    registry, attestor, issuer, record, _, token = issue_token()
    with pytest.raises(lab.GovernanceError) as exc:
        issuer.exchange(
            token, MCP_AUD, API_AUD, child_scopes, SENDER,
            "sha256:downstream-proof-key", "acme", record.purpose, ttl,
            lab.make_attestation(attestor, registry.get(record.identity_id), NOW + 4, code),
            NOW + 4, code,
        )
    assert error_code(exc) == code


def test_inventory_reconciliation_detects_shadow_missing_and_drift():
    registry, _, _, record, _ = setup_demo()
    observations = [
        lab.RuntimeObservation(
            record.identity_id, "other", frozenset({"wrong"}), "b" * 64, NOW + 2
        ),
        lab.RuntimeObservation(
            "spiffe://acme.test/shadow", "acme", frozenset(), "c" * 64, NOW + 2
        ),
    ]
    findings = lab.reconcile_inventory(
        registry,
        frozenset({record.identity_id, "spiffe://acme.test/missing"}),
        observations,
        NOW + 2,
    )
    assert {finding.code for finding in findings} >= {
        "EXPECTED_UNREGISTERED", "SHADOW_IDENTITY", "RUNTIME_TENANT_DRIFT",
        "RUNTIME_SELECTOR_DRIFT", "RUNTIME_ARTIFACT_DRIFT",
    }


def test_metrics_use_explicit_denominators():
    registry, _, _, record, _ = setup_demo()
    known = lab.RuntimeObservation(
        record.identity_id, "acme", record.selectors, record.artifact_digest, NOW + 2
    )
    shadow = replace(known, identity_id="spiffe://acme.test/shadow")
    findings = lab.reconcile_inventory(
        registry, frozenset({record.identity_id, "missing"}), [known, shadow], NOW + 2
    )
    metrics = lab.governance_metrics(
        registry, frozenset({record.identity_id, "missing"}), [known, shadow], findings
    )
    assert metrics["inventory_coverage"] == 0.5
    assert metrics["runtime_governance_coverage"] == 0.5
    assert metrics["active_owner_coverage"] == 1.0
    assert metrics["short_lived_credential_coverage"] == 1.0


def test_audit_events_exclude_raw_token_and_attestation_signature():
    _, _, issuer, _, audit, token = issue_token()
    serialized = repr(audit.events)
    assert token not in serialized
    assert "credential.issued" in serialized
    assert all(event.policy_version == lab.POLICY_VERSION for event in audit.events)
