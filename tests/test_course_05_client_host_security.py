"""Executable security claims for Course 05's MCP host boundary."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from pydantic import BaseModel, ConfigDict


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/beginner/05-client-host-security-capability-negotiation/lab.py"
SPEC = importlib.util.spec_from_file_location("course_05_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def run(coroutine):
    return asyncio.run(coroutine)


def reviewed_environment(permissions=frozenset({"ticket:read", "ticket:search"})):
    installation = lab.reviewed_installation()
    snapshot = run(lab.inspect_candidate(lab.trusted_mcp))
    review = lab.make_review_record(installation, snapshot, now=NOW)
    registry = lab.HostRegistry()
    registry.approve(review)
    principal = lab.AuthenticatedPrincipal(
        subject="analyst-42",
        tenant_id="acme",
        permissions=permissions,
    )
    return installation, snapshot, review, registry, principal


def connection(
    *,
    target=None,
    installation=None,
    registry=None,
    principal=None,
    cache=None,
    audit=None,
    budget=None,
):
    defaults = None
    if installation is None or registry is None or principal is None:
        defaults = reviewed_environment()
    return lab.SecureHostConnection(
        target=target or lab.trusted_mcp,
        installation=installation or defaults[0],
        principal=principal or defaults[4],
        registry=registry or defaults[3],
        cache=cache or lab.CapabilityCache(),
        audit=audit if audit is not None else [],
        clock=lambda: NOW,
        budget=budget or lab.DiscoveryBudget(),
    )


def test_end_to_end_scenario_uses_real_modern_protocol_and_blocks_forbidden_work():
    evidence = run(lab.run_scenario())
    assert evidence.protocol_version == "2026-07-28"
    assert evidence.visible_tools == (
        "support.ticket.read",
        "support.ticket.search",
    )
    assert evidence.malicious_server_denied is True
    assert evidence.cross_permission_denied is True
    assert evidence.revocation_denied_active_connection is True
    assert evidence.cache_entries_after_revocation == 0
    assert evidence.server_calls == {"ticket.read": 1, "ticket.search": 0}


def test_snapshot_covers_every_protocol_surface_and_private_cache_hint():
    snapshot = run(lab.inspect_candidate(lab.trusted_mcp))
    assert snapshot.protocol_version == lab.PROTOCOL_VERSION
    assert snapshot.supported_versions == (lab.PROTOCOL_VERSION,)
    assert snapshot.advertised_name == "northstar-support"
    assert snapshot.advertised_version == lab.SERVER_VERSION
    assert snapshot.tool_names == ("ticket.read", "ticket.search")
    assert len(snapshot.resources) == 1
    assert snapshot.resource_templates == ()
    assert len(snapshot.prompts) == 1
    assert {hint.scope for hint in snapshot.cache_hints} == {"private"}
    assert {hint.method for hint in snapshot.cache_hints} == {
        "server/discover",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    }


def test_self_reported_name_and_version_do_not_establish_server_identity():
    trusted = run(lab.inspect_candidate(lab.trusted_mcp))
    attacker = run(lab.inspect_candidate(lab.drifted_mcp))
    assert attacker.advertised_name == trusted.advertised_name
    assert attacker.advertised_version == trusted.advertised_version
    assert attacker.digest != trusted.digest
    assert "filesystem.read" in attacker.tool_names


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ({"launch_spec": ("sh", "-c", "curl attacker")}, "LAUNCH_SPEC_DRIFT"),
        ({"artifact_digest": "sha256:unreviewed"}, "ARTIFACT_DIGEST_DRIFT"),
        ({"verifier": ""}, "MISSING_ARTIFACT_VERIFIER"),
    ],
)
def test_installation_drift_is_denied_before_protocol_connection(mutation, code):
    installation, _, _, registry, principal = reviewed_environment()
    audit = []
    changed = replace(installation, **mutation)

    async def attempt():
        async with connection(
            target=lab.drifted_mcp,
            installation=changed,
            registry=registry,
            principal=principal,
            audit=audit,
        ):
            pass

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == code
    assert audit[-1].capability_digest is None


def test_expired_review_is_denied_before_connection():
    installation, snapshot, review, registry, principal = reviewed_environment()
    expired = replace(review, expires_at=NOW)
    registry.approve(expired)

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
        ):
            pass

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "REVIEW_EXPIRED"


def test_capability_schema_resource_prompt_and_cache_drift_deny_whole_server():
    installation, snapshot, review, registry, principal = reviewed_environment()
    audit = []
    cache = lab.CapabilityCache()
    assert cache.put(installation, snapshot, review, principal, NOW) is not None

    async def attempt():
        async with connection(
            target=lab.drifted_mcp,
            installation=installation,
            registry=registry,
            principal=principal,
            cache=cache,
            audit=audit,
        ):
            pass

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "CAPABILITY_DRIFT"
    assert audit[-1].reason_code == "CAPABILITY_DRIFT"
    assert audit[-1].capability_digest is not None
    assert cache.count_for(lab.SERVER_ID) == 0


def test_unexposed_name_is_denied_before_server_handler():
    installation, _, _, registry, principal = reviewed_environment()
    lab.reset_runtime_evidence()

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
        ) as host:
            await host.call_tool(
                "ticket.read", {"ticket_id": "acme-7"}, trace_id="direct-name"
            )

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "CAPABILITY_NOT_EXPOSED"
    assert lab.SERVER_CALLS["ticket.read"] == 0


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"ticket_id": 7},
        {"ticket_id": "acme-7", "tenant_id": "globex"},
        {"ticket_id": "../secrets"},
    ],
)
def test_invalid_or_scope_shaping_arguments_are_denied_before_handler(arguments):
    installation, _, _, registry, principal = reviewed_environment()
    lab.reset_runtime_evidence()

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
        ) as host:
            await host.call_tool(
                "support.ticket.read", arguments, trace_id="bad-arguments"
            )

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "INVALID_TOOL_ARGUMENTS"
    assert lab.SERVER_CALLS["ticket.read"] == 0


def test_permission_is_derived_from_principal_and_denied_before_handler():
    installation, _, _, registry, principal = reviewed_environment(
        frozenset({"ticket:read"})
    )
    lab.reset_runtime_evidence()

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
        ) as host:
            await host.call_tool(
                "support.ticket.search",
                {"query": "payment", "limit": 5},
                trace_id="no-search-permission",
            )

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "PERMISSION_DENIED"
    assert lab.SERVER_CALLS["ticket.search"] == 0


def test_valid_call_is_output_validated_and_audit_is_redacted():
    installation, _, _, registry, principal = reviewed_environment()
    audit = []
    lab.reset_runtime_evidence()

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
            audit=audit,
        ) as host:
            return await host.call_tool(
                "support.ticket.read",
                {"ticket_id": "acme-7"},
                trace_id="valid-read",
            )

    result = run(attempt())
    assert isinstance(result, lab.TicketReadOutput)
    assert result.ticket.content_trust == "untrusted-server-content"
    assert lab.SERVER_CALLS["ticket.read"] == 1
    serialized = json.dumps([event.__dict__ for event in audit])
    assert "analyst-42" not in serialized
    assert "acme-7" not in serialized
    assert audit[-1].argument_digest == lab.canonical_digest({"ticket_id": "acme-7"})


def test_host_rejects_success_payload_that_fails_its_own_output_contract():
    class StricterOutput(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        impossible_required_field: str

    installation, _, review, registry, principal = reviewed_environment()
    read_grant = replace(review.grants[0], output_model=StricterOutput)
    registry.approve(replace(review, grants=(read_grant, *review.grants[1:])))

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
        ) as host:
            await host.call_tool(
                "support.ticket.read",
                {"ticket_id": "acme-7"},
                trace_id="bad-output",
            )

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "INVALID_TOOL_OUTPUT"


def test_cache_is_ttl_capped_and_partitioned_by_authorization_context():
    installation, snapshot, review, _, principal = reviewed_environment()
    cache = lab.CapabilityCache()
    entry = cache.put(installation, snapshot, review, principal, NOW)
    assert entry is not None
    assert entry.expires_at == NOW + timedelta(milliseconds=review.max_cache_ttl_ms)
    other = replace(principal, subject="analyst-99")
    assert cache.get(installation, snapshot, review, other, NOW) is None
    assert cache.get(installation, snapshot, review, principal, NOW) == entry
    assert cache.get(installation, snapshot, review, principal, entry.expires_at) is None


def test_public_server_hint_does_not_remove_host_private_partition():
    installation, snapshot, review, _, principal = reviewed_environment()
    public_hints = tuple(
        replace(hint, ttl_ms=60_000, scope="public") for hint in snapshot.cache_hints
    )
    public_snapshot = replace(snapshot, cache_hints=public_hints)
    public_review = replace(review, expected_snapshot=public_snapshot)
    cache = lab.CapabilityCache()
    entry = cache.put(installation, public_snapshot, public_review, principal, NOW)
    assert entry is not None
    other_tenant = replace(principal, subject="other", tenant_id="globex")
    assert cache.get(
        installation, public_snapshot, public_review, other_tenant, NOW
    ) is None


def test_revocation_blocks_active_connection_and_invalidates_cache_before_handler():
    installation, _, _, registry, principal = reviewed_environment()
    cache = lab.CapabilityCache()
    lab.reset_runtime_evidence()

    async def attempt():
        async with connection(
            installation=installation,
            registry=registry,
            principal=principal,
            cache=cache,
        ) as host:
            assert cache.count_for(lab.SERVER_ID) == 1
            registry.revoke(lab.SERVER_ID)
            await host.call_tool(
                "support.ticket.read",
                {"ticket_id": "acme-7"},
                trace_id="revoked",
            )

    with pytest.raises(lab.HostDenied) as denied:
        run(attempt())
    assert denied.value.code == "SERVER_REVOKED"
    assert cache.count_for(lab.SERVER_ID) == 0
    assert lab.SERVER_CALLS["ticket.read"] == 0


def test_discovery_budget_rejects_metadata_fanout():
    with pytest.raises(lab.DiscoveryDenied) as denied:
        run(
            lab.inspect_candidate(
                lab.trusted_mcp,
                lab.DiscoveryBudget(max_pages_per_method=8, max_items=1, max_metadata_bytes=64_000),
            )
        )
    assert denied.value.code == "DISCOVERY_ITEM_BUDGET"


def test_review_helper_never_auto_approves_changed_inventory():
    installation = lab.reviewed_installation()
    attacker = run(lab.inspect_candidate(lab.drifted_mcp))
    with pytest.raises(ValueError, match="needs review"):
        lab.make_review_record(installation, attacker, now=NOW)
