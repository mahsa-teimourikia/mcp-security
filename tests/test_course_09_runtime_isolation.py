"""Executable isolation and sandbox-admission invariants for Course 09."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys

from mcp import Client
import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/09-runtime-isolation-sandboxing/lab.py"
SPEC = importlib.util.spec_from_file_location("course_09_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def environment():
    return lab.default_environment()


def admitted(environment, *, request_id="run-test-1"):
    admission, runtime, _ = environment
    request = lab.request_for(request_id=request_id)
    record = admission.require(request)
    return admission, runtime, request, record


def test_end_to_end_scenario_executes_real_process_and_blocks_attacks():
    evidence = run(lab.run_scenario())
    assert evidence["valid_mcp_call"] is True
    assert evidence["unknown_file_denied"] is True
    assert evidence["blocked_attempts"] == 5
    assert evidence["fixture_forbidden_effects"] == 0
    assert evidence["parent_secret_absent"] is True
    assert evidence["raw_document_absent_from_events"] is True


def test_valid_request_runs_pinned_worker_with_expected_result(environment):
    _, runtime, request, record = admitted(environment)
    result = runtime.execute(request, record)
    assert result["file_id"] == "file-support-policy"
    assert result["bytes"] == len(record.content)
    assert result["lines"] == 2
    assert result["sha256"] == lab.sha256(record.content).hexdigest()
    assert result["enforcement_mode"] == "bounded-local-subprocess"
    assert runtime.events[-1].terminal_state == "succeeded"
    assert runtime.events[-1].reason_code == "EXECUTION_SUCCEEDED"


def test_subprocess_receives_only_explicit_minimal_environment(environment, monkeypatch):
    _, runtime, request, record = admitted(environment)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross")
    result = runtime.execute(request, record)
    expected = set(lab.SAFE_ENVIRONMENT) | set(lab.PLATFORM_ENVIRONMENT_KEYS)
    assert set(result["environment_keys"]) == expected
    assert "OPENAI_API_KEY" not in result["environment_keys"]
    assert "AWS_SECRET_ACCESS_KEY" not in result["environment_keys"]


def test_admission_rejects_unregistered_file_before_execution(environment):
    admission, runtime, _ = environment
    with pytest.raises(lab.SandboxDenied) as denied:
        admission.require(lab.request_for(file_id="file-unknown"))
    assert denied.value.code == "FILE_NOT_REGISTERED"
    assert runtime.events == []


def test_admission_rejects_cross_tenant_record(environment):
    admission, _, _ = environment
    decision = admission.evaluate(lab.request_for(file_id="file-other-tenant"))
    assert decision.allowed is False
    assert decision.reason_code == "TENANT_MISMATCH"


def test_admission_rejects_unapproved_environment_key(environment):
    admission, _, _ = environment
    request = lab.request_for(env_keys=frozenset({"LANG", "GITHUB_TOKEN"}))
    decision = admission.evaluate(request)
    assert decision.reason_code == "ENVIRONMENT_KEY_DENIED"


def test_admission_rejects_any_network_destination(environment):
    admission, _, _ = environment
    request = lab.request_for(network_destination="https://tickets.example")
    decision = admission.evaluate(request)
    assert decision.reason_code == "NETWORK_DENIED"


def test_admission_rejects_worker_artifact_drift():
    policy = lab.LocalSandboxPolicy(worker_digest="sha256:" + "0" * 64)
    admission, runtime, _ = lab.default_environment(policy=policy)
    decision = admission.evaluate(lab.request_for())
    assert decision.reason_code == "ARTIFACT_DIGEST_MISMATCH"
    assert runtime.events == []


@pytest.mark.parametrize(
    "relative_path",
    ["../secrets.txt", "/etc/passwd", "policies/../../secrets.txt", "."],
)
def test_admission_rejects_registry_path_escape(relative_path):
    record = lab.DocumentRecord(
        file_id="file-escape",
        tenant_id="acme",
        relative_path=relative_path,
        content=b"x",
    )
    admission, _, _ = lab.default_environment(records=(record,))
    decision = admission.evaluate(lab.request_for(file_id="file-escape"))
    assert decision.reason_code == "PATH_OUTSIDE_SANDBOX"


def test_admission_rejects_oversized_input():
    policy = lab.LocalSandboxPolicy(max_input_bytes=8)
    record = lab.DocumentRecord(
        file_id="file-large",
        tenant_id="acme",
        relative_path="large.txt",
        content=b"123456789",
    )
    admission, _, _ = lab.default_environment(policy=policy, records=(record,))
    decision = admission.evaluate(lab.request_for(file_id="file-large"))
    assert decision.reason_code == "INPUT_LIMIT_EXCEEDED"


def test_request_schema_does_not_accept_arbitrary_operation():
    with pytest.raises(ValidationError):
        lab.ExecutionRequest(
            request_id="run-shell-1",
            tenant_id="acme",
            file_id="file-support-policy",
            operation="shell",
        )


def test_resolve_beneath_rejects_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = root / "link.txt"
    link.symlink_to(outside)
    with pytest.raises(lab.SandboxDenied) as denied:
        lab.resolve_beneath(root, link)
    assert denied.value.code == "PATH_OUTSIDE_SANDBOX"


def test_resolve_beneath_accepts_real_child(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child.txt"
    child.write_text("safe")
    assert lab.resolve_beneath(root, child) == child.resolve()


def test_wall_clock_timeout_terminates_process_group(environment):
    _, runtime, request, record = admitted(environment, request_id="run-timeout-1")
    with pytest.raises(lab.SandboxExecutionFailed) as failed:
        runtime.execute(request, record, trusted_fault="hang")
    assert failed.value.code == "WALL_CLOCK_TIMEOUT"
    event = runtime.events[-1]
    assert event.terminal_state == "terminated"
    assert event.timed_out is True
    assert event.exit_code is not None


def test_file_size_limit_blocks_oversized_output(environment):
    _, runtime, request, record = admitted(environment, request_id="run-output-1")
    with pytest.raises(lab.SandboxExecutionFailed) as failed:
        runtime.execute(request, record, trusted_fault="oversize")
    assert failed.value.code == "OUTPUT_LIMIT_EXCEEDED"
    assert runtime.events[-1].output_bytes <= runtime.policy.max_file_bytes


def test_nonzero_worker_exit_is_not_reported_as_success(environment):
    _, runtime, request, record = admitted(environment, request_id="run-fail-1")
    with pytest.raises(lab.SandboxExecutionFailed) as failed:
        runtime.execute(request, record, trusted_fault="fail")
    assert failed.value.code == "WORKER_NONZERO_EXIT"
    assert runtime.events[-1].terminal_state == "failed"


def test_invalid_worker_output_is_not_reported_as_success(environment):
    _, runtime, request, record = admitted(environment, request_id="run-json-1")
    with pytest.raises(lab.SandboxExecutionFailed) as failed:
        runtime.execute(request, record, trusted_fault="invalid-json")
    assert failed.value.code == "INVALID_WORKER_OUTPUT"
    assert runtime.events[-1].reason_code == "INVALID_WORKER_OUTPUT"


def test_events_are_redacted_and_carry_control_evidence(environment, monkeypatch):
    admission, runtime, request, record = admitted(environment)
    monkeypatch.setenv("PRIVATE_TOKEN", "super-secret-value")
    runtime.execute(request, record)
    serialized = lab.event_json(admission.events) + lab.event_json(runtime.events)
    assert "Refunds above" not in serialized
    assert "super-secret-value" not in serialized
    assert lab.WORKER_SOURCE not in serialized
    assert runtime.events[-1].evidence_id.startswith("evidence-")
    assert "exact-argv-without-shell" in runtime.events[-1].enforced_controls


def test_mcp_tool_schema_exposes_file_id_not_runtime_authority(environment):
    _, _, service = environment
    server = lab.build_mcp_server(service)

    async def inspect():
        async with Client(server) as client:
            tools = await client.list_tools()
        return tools

    tools = run(inspect())
    assert len(tools.tools) == 1
    schema = json.dumps(tools.tools[0].input_schema)
    assert "file_id" in schema
    for forbidden in ("command", "path", "environment", "destination", "tenant"):
        assert forbidden not in schema.lower()


def test_mcp_denial_is_generic_but_protected_event_has_reason(environment):
    admission, _, service = environment
    server = lab.build_mcp_server(service)

    async def invoke():
        async with Client(server, raise_exceptions=False) as client:
            return await client.call_tool("document.inspect", {"file_id": "file-unknown"})

    result = run(invoke())
    assert result.is_error is True
    assert "document is unavailable" in result.content[0].text
    assert "FILE_NOT_REGISTERED" not in result.content[0].text
    assert admission.events[-1].reason_code == "FILE_NOT_REGISTERED"


@pytest.mark.parametrize(
    "updates,code",
    [
        ({"image": "registry.example/support-inspector:latest"}, "IMAGE_NOT_DIGEST_PINNED"),
        ({"run_as_non_root": False}, "NON_ROOT_REQUIRED"),
        ({"read_only_root_filesystem": False}, "READ_ONLY_ROOT_REQUIRED"),
        ({"allow_privilege_escalation": True}, "PRIVILEGE_ESCALATION_FORBIDDEN"),
        ({"privileged": True}, "PRIVILEGED_FORBIDDEN"),
        ({"drop_capabilities": ("NET_BIND_SERVICE",)}, "DROP_ALL_CAPABILITIES_REQUIRED"),
        ({"host_network": True}, "HOST_NAMESPACES_FORBIDDEN"),
        ({"host_pid": True}, "HOST_NAMESPACES_FORBIDDEN"),
        ({"host_ipc": True}, "HOST_NAMESPACES_FORBIDDEN"),
        ({"automount_service_account_token": True}, "SERVICE_ACCOUNT_TOKEN_FORBIDDEN"),
        ({"network_default_deny": False}, "NETWORK_DEFAULT_DENY_REQUIRED"),
    ],
)
def test_production_profile_rejects_isolation_weakening(updates, code):
    with pytest.raises(ValidationError) as invalid:
        lab.ProductionIsolationProfile(**updates)
    assert code in str(invalid.value)


def test_production_profile_rejects_unknown_or_unconfined_security_profile():
    with pytest.raises(ValidationError):
        lab.ProductionIsolationProfile(seccomp_profile="Unconfined")
    with pytest.raises(ValidationError):
        lab.ProductionIsolationProfile(apparmor_profile="Unconfined")


def test_kubernetes_bundle_maps_restricted_profile_fields():
    profile = lab.ProductionIsolationProfile()
    bundle = lab.restricted_kubernetes_bundle(profile)
    pod = bundle["pod"]["spec"]
    container = pod["containers"][0]
    assert pod["runtimeClassName"] == "gvisor"
    assert pod["automountServiceAccountToken"] is False
    assert pod["hostNetwork"] is False
    assert pod["hostPID"] is False
    assert pod["hostIPC"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert container["image"] == lab.IMAGE_DIGEST
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["resources"]["limits"] == {
        "cpu": "250m",
        "memory": "128Mi",
        "ephemeral-storage": "32Mi",
    }


def test_network_policy_is_default_deny_not_claimed_domain_allowlist():
    bundle = lab.restricted_kubernetes_bundle(lab.ProductionIsolationProfile())
    policy = bundle["network_policy"]["spec"]
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert "egress" not in policy
    notes = " ".join(bundle["operator_notes"])
    assert "CNI" in notes
    assert "DNS/API egress" in notes


def test_reference_bundle_labels_profile_but_does_not_prove_runtime_enforcement():
    profile = lab.ProductionIsolationProfile()
    bundle = lab.restricted_kubernetes_bundle(profile)
    assert bundle["pod"]["metadata"]["labels"]["sandbox-profile"] == profile.profile_id
    assert any("Verify admission, runtime" in note for note in bundle["operator_notes"])


def test_local_evidence_explicitly_excludes_kernel_and_vm_guarantees():
    assert "network-namespace-or-egress-filter" in lab.LOCAL_NOT_ENFORCED
    assert "seccomp-apparmor-selinux-or-landlock" in lab.LOCAL_NOT_ENFORCED
    assert "cgroup-accounting-and-multi-tenant-kernel-separation" in lab.LOCAL_NOT_ENFORCED
    assert "network-namespace-or-egress-filter" not in lab.LOCAL_ENFORCED_CONTROLS


def test_strict_models_reject_extra_fields_and_coercion():
    with pytest.raises(ValidationError):
        lab.ExecutionRequest(
            request_id="run-extra-1",
            tenant_id="acme",
            file_id="file-support-policy",
            shell=True,
        )
    with pytest.raises(ValidationError):
        lab.LocalSandboxPolicy(timeout_ms="500")
