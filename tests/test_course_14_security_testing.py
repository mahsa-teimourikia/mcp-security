"""Executable invariants for Course 14 security testing and fuzzing."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import sys

from hypothesis import given, settings, strategies as st
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/advanced/14-mcp-security-testing-fuzzing/lab.py"
SPEC = importlib.util.spec_from_file_location("course_14_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


NOW = lab.utc("2026-09-29T04:00:00Z")
IDENTITY = lab.TrustedIdentity("analyst-42", "acme", frozenset({"ticket:read"}))


def case(
    raw,
    *,
    expected=lab.Decision.PROTOCOL_ERROR,
    reason="MALFORMED_JSON",
    effect_delta=0,
    request_headers=None,
    identity=IDENTITY,
    case_class=lab.CaseClass.ROBUSTNESS,
):
    return lab.SecurityCase(
        "generated",
        case_class,
        "test",
        14,
        raw,
        request_headers or lab.headers(),
        identity,
        expected,
        reason,
        effect_delta,
    )


def mutate_request(raw, mutator):
    data = json.loads(raw)
    mutator(data)
    return lab.canonical_json(data)


def observation(gateway, raw, *, request_headers=None, identity=IDENTITY, now=NOW):
    return gateway.handle(raw, request_headers or lab.headers(), identity, now)


def test_demo_finds_baseline_vulnerability_and_hardened_target_passes():
    result = lab.run_demo()
    assert result["vulnerable_metrics"]["attack_success_rate"] == 0.25
    assert result["hardened_metrics"] == {
        "oracle_pass_rate": 1.0,
        "safe_block_rate": 1.0,
        "attack_success_rate": 0.0,
        "false_block_rate": 0.0,
        "robustness_crash_rate": 0.0,
    }
    assert result["sdk_probe"]["protocol_version"] == lab.PROTOCOL_VERSION
    assert result["sdk_probe"]["schema_enforced_before_handler"] is True


def test_canonical_json_is_stable_across_key_order():
    assert lab.canonical_json({"b": 2, "a": 1}) == lab.canonical_json({"a": 1, "b": 2})


def test_modern_request_round_trips_through_parser():
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    parsed = lab.parse_request(raw, lab.headers())
    assert parsed["params"]["arguments"] == {"ticket_id": "acme-7"}


def test_valid_read_releases_one_authorized_record():
    result = lab.run_case(lab.McpGateway(), lab.base_cases()[0], NOW)
    assert result.oracle.passed
    assert result.observation.decision == lab.Decision.ALLOW
    assert result.effect_delta == 1


def test_cross_tenant_read_has_uniform_denial_and_no_release():
    target = lab.McpGateway()
    cross_tenant = next(item for item in lab.base_cases() if item.case_id == "cross-tenant-read")
    result = lab.run_case(target, cross_tenant, NOW)
    assert result.oracle.passed
    assert result.observation.reason_code == "NOT_FOUND_OR_FORBIDDEN"
    assert target.ledger.count() == 0


def test_missing_ticket_uses_same_reason_as_cross_tenant_ticket():
    target = lab.McpGateway()
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-404"})
    result = observation(target, raw)
    assert result.reason_code == "NOT_FOUND_OR_FORBIDDEN"
    assert target.ledger.count() == 0


def test_identity_scope_comes_from_trusted_context():
    identity = lab.TrustedIdentity("analyst-42", "acme", frozenset())
    result = observation(
        lab.McpGateway(),
        lab.modern_request("ticket.read", {"ticket_id": "acme-7"}),
        identity=identity,
    )
    assert result.decision == lab.Decision.DENY
    assert result.reason_code == "SCOPE_DENIED"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"ticket_id": "acme-7", "tenant_id": "acme"},
        {"ticket_id": "acme-7", "debug": True},
        {"ticket_id": ["acme-7"]},
        {"ticket_id": "../acme-7"},
        {"ticket_id": "a" * 41},
    ],
)
def test_argument_schema_mutations_are_denied_without_release(arguments):
    target = lab.McpGateway()
    result = observation(target, lab.modern_request("ticket.read", arguments))
    assert result.decision == lab.Decision.DENY
    assert result.reason_code == "ARGUMENT_SCHEMA_INVALID"
    assert target.ledger.count() == 0


def test_capability_widening_is_denied():
    raw = lab.modern_request("shell.exec", {"command": "id"})
    result = observation(lab.McpGateway(), raw, request_headers=lab.headers("shell.exec"))
    assert result.decision == lab.Decision.DENY
    assert result.reason_code == "TOOL_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("request_headers", "reason"),
    [
        (lab.RequestHeaders("2025-11-25", "tools/call", "ticket.read"), "PROTOCOL_VERSION_MISMATCH"),
        (lab.RequestHeaders(lab.PROTOCOL_VERSION, "tools/list", "ticket.read"), "HEADER_BODY_MISMATCH"),
        (lab.RequestHeaders(lab.PROTOCOL_VERSION, "tools/call", "ticket.reply"), "HEADER_BODY_MISMATCH"),
    ],
)
def test_routing_headers_must_match_body(request_headers, reason):
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    result = observation(lab.McpGateway(), raw, request_headers=request_headers)
    assert result.decision == lab.Decision.PROTOCOL_ERROR
    assert result.reason_code == reason


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda data: data.update({"jsonrpc": "1.0"}), "INVALID_JSONRPC_VERSION"),
        (lambda data: data.update({"id": True}), "INVALID_REQUEST_ID"),
        (lambda data: data.update({"method": "resources/read"}), "METHOD_NOT_ALLOWED"),
        (lambda data: data.update({"debug": True}), "INVALID_ENVELOPE"),
        (lambda data: data["params"].update({"extra": True}), "INVALID_PARAMS"),
        (lambda data: data["params"].update({"name": 7}), "INVALID_PARAMS"),
        (lambda data: data["params"].update({"arguments": []}), "INVALID_PARAMS"),
        (lambda data: data["params"].update({"_meta": []}), "INVALID_CLIENT_METADATA"),
    ],
)
def test_envelope_mutations_fail_closed(mutator, reason):
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    result = observation(lab.McpGateway(), mutate_request(raw, mutator))
    assert result.decision == lab.Decision.PROTOCOL_ERROR
    assert result.reason_code == reason


def test_missing_client_info_is_rejected():
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    changed = mutate_request(
        raw,
        lambda data: data["params"]["_meta"].pop("io.modelcontextprotocol/clientInfo"),
    )
    assert observation(lab.McpGateway(), changed).reason_code == "INVALID_CLIENT_METADATA"


def test_unknown_client_metadata_is_rejected():
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    changed = mutate_request(
        raw, lambda data: data["params"]["_meta"].update({"trusted": True})
    )
    assert observation(lab.McpGateway(), changed).reason_code == "INVALID_CLIENT_METADATA"


def test_malformed_utf8_is_a_protocol_error():
    result = observation(lab.McpGateway(), b"\xff\xfe")
    assert result.reason_code == "MALFORMED_JSON"


def test_duplicate_key_is_detected_before_dispatch():
    duplicate = next(item for item in lab.base_cases() if item.case_id == "duplicate-id")
    result = lab.run_case(lab.McpGateway(), duplicate, NOW)
    assert result.oracle.passed
    assert result.observation.reason_code == "DUPLICATE_JSON_KEY"


def test_byte_budget_is_enforced_before_parse():
    raw = b"{" + b"x" * lab.MAX_INPUT_BYTES + b"}"
    assert observation(lab.McpGateway(), raw).reason_code == "INPUT_TOO_LARGE"


def test_nesting_budget_is_enforced():
    value = "x"
    for _ in range(lab.MAX_DEPTH + 2):
        value = [value]
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7", "nested": value})
    assert observation(lab.McpGateway(), raw).reason_code == "NESTING_LIMIT"


def test_decoder_recursion_is_converted_to_bounded_protocol_error():
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        b'{"name":"ticket.read","arguments":{"ticket_id":"acme-7","nested":'
        + (b"[" * 1_100)
        + b"0"
        + (b"]" * 1_100)
        + b'},"_meta":{"io.modelcontextprotocol/clientInfo":'
        b'{"name":"h","version":"1"}}}}'
    )
    result = observation(lab.McpGateway(), raw)
    assert result.decision == lab.Decision.PROTOCOL_ERROR
    assert result.reason_code == "NESTING_LIMIT"


def test_key_budget_is_enforced():
    arguments = {f"k{i}": i for i in range(lab.MAX_KEYS + 1)}
    raw = lab.modern_request("ticket.read", arguments)
    assert observation(lab.McpGateway(), raw).reason_code == "KEY_LIMIT"


def test_string_budget_is_enforced():
    raw = lab.modern_request("ticket.read", {"ticket_id": "a" * (lab.MAX_STRING + 1)})
    assert observation(lab.McpGateway(), raw).reason_code == "STRING_LIMIT"


def test_semantic_json_reencoding_preserves_allow_decision():
    target = lab.McpGateway()
    raw = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    reencoded = json.dumps(json.loads(raw), indent=4).encode()
    assert observation(target, raw).decision == lab.Decision.ALLOW
    assert observation(lab.McpGateway(), reencoded).decision == lab.Decision.ALLOW


def test_optional_capabilities_do_not_change_authorization():
    without = lab.modern_request("ticket.read", {"ticket_id": "acme-7"})
    with_caps = lab.modern_request(
        "ticket.read", {"ticket_id": "acme-7"}, capabilities={"sampling": {}}
    )
    assert observation(lab.McpGateway(), without).reason_code == "TENANT_READ_ALLOWED"
    assert observation(lab.McpGateway(), with_caps).reason_code == "TENANT_READ_ALLOWED"


def test_generated_cases_are_seeded_reproducible_and_bounded():
    first = lab.generated_cases(seed=77, max_cases=6)
    second = lab.generated_cases(seed=77, max_cases=6)
    assert [item.case_id for item in first] == [item.case_id for item in second]
    assert len(first) == 6


@pytest.mark.parametrize("max_cases", [0, 101])
def test_generated_case_budget_is_validated(max_cases):
    with pytest.raises(ValueError):
        lab.generated_cases(max_cases=max_cases)


def test_hardened_campaign_passes_every_independent_oracle():
    report = lab.run_campaign(lab.McpGateway, lab.generated_cases(), NOW)
    assert report.oracle_passes == report.total_cases == 10
    assert report.unique_failure_signatures == 0
    assert report.metrics()["safe_block_rate"] == 1.0
    assert report.metrics()["attack_success_rate"] == 0.0


def test_vulnerable_campaign_detects_observable_cross_tenant_release():
    report = lab.run_campaign(lab.VulnerableMcpGateway, lab.generated_cases(), NOW)
    failure = next(result for result in report.results if not result.oracle.passed)
    assert failure.case.case_id == "cross-tenant-read"
    assert failure.effect_delta == 1
    assert "FORBIDDEN_EFFECT_COMPLETED" in failure.oracle.violations
    assert report.target_version == lab.VULNERABLE_TARGET_VERSION
    assert lab.failure_artifact(failure)["target_version"] == lab.VULNERABLE_TARGET_VERSION


def test_metric_denominators_are_explicit_populations():
    report = lab.run_campaign(lab.VulnerableMcpGateway, lab.generated_cases(), NOW)
    assert report.attack_attempts == 4
    assert report.valid_attempts == 2
    assert report.robustness_cases == 4
    assert report.completed_forbidden_effects == 1
    assert report.metrics()["attack_success_rate"] == 1 / 4


def test_oracle_rejects_correct_string_with_wrong_effect_delta():
    valid = lab.base_cases()[0]
    fake = lab.Observation(
        lab.Decision.ALLOW,
        "TENANT_READ_ALLOWED",
        "trace-fake",
        {"result": "claimed"},
        frozenset(),
    )
    checked = lab.SecurityOracle().evaluate(valid, fake, 0)
    assert not checked.passed
    assert checked.violations == ("EFFECT_MISMATCH",)


def test_oracle_rejects_forbidden_effect_even_when_target_says_deny():
    attack = next(item for item in lab.base_cases() if item.case_id == "cross-tenant-read")
    fake = lab.Observation(
        lab.Decision.DENY,
        "NOT_FOUND_OR_FORBIDDEN",
        "trace-fake",
        {},
        frozenset(),
    )
    checked = lab.SecurityOracle().evaluate(attack, fake, 1)
    assert "FORBIDDEN_EFFECT_COMPLETED" in checked.violations


def test_failure_artifact_is_reproducible_and_redacted():
    report = lab.run_campaign(lab.VulnerableMcpGateway, lab.generated_cases(), NOW)
    failure = next(result for result in report.results if not result.oracle.passed)
    artifact = lab.failure_artifact(failure)
    serialized = json.dumps(artifact, default=str)
    assert artifact["input_digest"].startswith("sha256:")
    assert artifact["seed"] == 1401
    assert artifact["protocol_version"] == lab.PROTOCOL_VERSION
    assert artifact["policy_version"] == lab.POLICY_VERSION
    assert artifact["trace_id"].startswith("trace-")
    assert "Private merger inquiry" not in serialized
    assert "other-7" not in serialized


def test_passing_case_does_not_create_failure_artifact():
    passing = lab.run_case(lab.McpGateway(), lab.base_cases()[0], NOW)
    with pytest.raises(ValueError):
        lab.failure_artifact(passing)


def test_shrinker_removes_optional_metadata_while_preserving_forbidden_effect():
    attack = next(item for item in lab.base_cases() if item.case_id == "cross-tenant-read")
    shrunk = lab.shrink_failure(
        attack,
        lambda candidate: lab.run_case(lab.VulnerableMcpGateway(), candidate, NOW).effect_delta > 0,
    )
    assert len(shrunk.raw) < len(attack.raw)
    assert lab.run_case(lab.VulnerableMcpGateway(), shrunk, NOW).effect_delta == 1


def test_approved_reply_executes_exactly_once():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)
    first = lab.run_case(target, approved, NOW)
    assert first.oracle.passed
    replay = replace(
        approved,
        case_id="replay",
        case_class=lab.CaseClass.ATTACK,
        expected_decision=lab.Decision.DENY,
        expected_reason="APPROVAL_REPLAYED",
        expected_effect_delta=0,
    )
    second = lab.run_case(target, replay, NOW)
    assert second.oracle.passed
    assert target.ledger.count() == 1


@pytest.mark.parametrize(
    ("approver_id", "approver_role"),
    [
        ("intern-1", "release-reviewer"),
        ("reviewer-9", "developer"),
        ("analyst-42", "release-reviewer"),
    ],
)
def test_approval_requires_eligible_independent_reviewer(approver_id, approver_role):
    target = lab.McpGateway()
    identity = lab.TrustedIdentity(
        "analyst-42", "acme", frozenset({"ticket:read", "ticket:reply"})
    )
    with pytest.raises(lab.InputRejected) as denied:
        target.issue_reply_approval(
            identity,
            "acme-7",
            "Use the verified payment link.",
            "op-reply-7",
            NOW,
            approver_id,
            approver_role,
        )
    assert denied.value.code == "APPROVER_NOT_ELIGIBLE"


def test_changed_reply_body_invalidates_approval():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)
    changed = mutate_request(
        approved.raw,
        lambda data: data["params"]["arguments"].update({"body": "Different body"}),
    )
    result = observation(
        target, changed, request_headers=lab.headers("ticket.reply"), identity=approved.identity
    )
    assert result.reason_code == "APPROVAL_BINDING_MISMATCH"
    assert target.ledger.count() == 0


def test_changed_operation_id_invalidates_approval():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)
    changed = mutate_request(
        approved.raw,
        lambda data: data["params"]["arguments"].update({"operation_id": "op-other"}),
    )
    result = observation(
        target, changed, request_headers=lab.headers("ticket.reply"), identity=approved.identity
    )
    assert result.reason_code == "APPROVAL_BINDING_MISMATCH"
    assert target.ledger.count() == 0


def test_changed_principal_invalidates_approval():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)
    other = lab.TrustedIdentity(
        "another-analyst", "acme", frozenset({"ticket:read", "ticket:reply"})
    )
    result = observation(
        target, approved.raw, request_headers=lab.headers("ticket.reply"), identity=other
    )
    assert result.reason_code == "APPROVAL_BINDING_MISMATCH"
    assert target.ledger.count() == 0


def test_expired_approval_is_denied_without_effect():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)
    result = observation(
        target,
        approved.raw,
        request_headers=lab.headers("ticket.reply"),
        identity=approved.identity,
        now=NOW + timedelta(minutes=11),
    )
    assert result.reason_code == "APPROVAL_EXPIRED"
    assert target.ledger.count() == 0


def test_concurrent_approval_consumption_has_one_winner():
    target = lab.McpGateway()
    approved, _ = lab.approved_reply_fixture(target, NOW)

    def invoke(_):
        return observation(
            target,
            approved.raw,
            request_headers=lab.headers("ticket.reply"),
            identity=approved.identity,
        ).reason_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        reasons = list(pool.map(invoke, range(2)))
    assert reasons.count("APPROVED_REPLY_EXECUTED") == 1
    assert reasons.count("APPROVAL_REPLAYED") == 1
    assert target.ledger.count() == 1


def test_effect_ledger_deduplicates_exact_operation():
    ledger = lab.EffectLedger()
    effect = lab.Effect("op-one", "ticket_reply", "acme", "acme-7", "sha256:" + "a" * 64)
    assert ledger.record(effect) is True
    assert ledger.record(effect) is False
    assert ledger.count() == 1


def test_effect_ledger_rejects_operation_id_rebinding():
    ledger = lab.EffectLedger()
    first = lab.Effect("op-one", "ticket_reply", "acme", "acme-7", "sha256:" + "a" * 64)
    second = replace(first, payload_digest="sha256:" + "b" * 64)
    ledger.record(first)
    with pytest.raises(lab.InputRejected, match="another effect"):
        ledger.record(second)


def test_official_sdk_probe_uses_real_protocol_and_exact_argument_middleware():
    evidence = asyncio.run(lab.run_sdk_probe())
    assert evidence.protocol_version == lab.PROTOCOL_VERSION
    assert evidence.tools == ("ticket.read",)
    assert evidence.valid_call_succeeded
    assert evidence.domain_denial_is_error
    assert evidence.extra_argument_is_error
    assert evidence.handler_skipped_for_schema_error


@settings(max_examples=100, derandomize=True, deadline=None)
@given(st.binary(max_size=5_000))
def test_arbitrary_bytes_never_escape_as_uncaught_gateway_exception(raw):
    result = observation(lab.McpGateway(), raw)
    assert isinstance(result, lab.Observation)
    assert result.decision != lab.Decision.CRASH


@settings(max_examples=100, derandomize=True, deadline=None)
@given(st.text(max_size=80))
def test_generated_ticket_ids_never_release_cross_tenant_data(ticket_id):
    target = lab.McpGateway()
    result = observation(
        target, lab.modern_request("ticket.read", {"ticket_id": ticket_id})
    )
    effects = target.ledger.snapshot()
    assert all(effect.tenant_id == "acme" for effect in effects)
    if ticket_id != "acme-7":
        assert result.decision != lab.Decision.ALLOW


@settings(max_examples=60, derandomize=True, deadline=None)
@given(st.dictionaries(st.text(min_size=1, max_size=12), st.integers(), min_size=1, max_size=5))
def test_any_extra_argument_set_is_denied(extra):
    extra.pop("ticket_id", None)
    if not extra:
        extra["x"] = 1
    arguments = {"ticket_id": "acme-7", **extra}
    target = lab.McpGateway()
    result = observation(target, lab.modern_request("ticket.read", arguments))
    assert result.decision == lab.Decision.DENY
    assert target.ledger.count() == 0


@settings(max_examples=50, derandomize=True, deadline=None)
@given(st.permutations(["jsonrpc", "id", "method", "params"]))
def test_json_object_key_order_does_not_change_semantics(order):
    original = json.loads(lab.modern_request("ticket.read", {"ticket_id": "acme-7"}))
    reordered = {key: original[key] for key in order}
    result = observation(lab.McpGateway(), json.dumps(reordered).encode())
    assert result.decision == lab.Decision.ALLOW
