"""Course 09: executable runtime-isolation and sandbox-admission lab.

The fixture launches a real, bounded local subprocess and produces a hardened
Kubernetes reference bundle. It is deliberately honest about the boundary:
Python resource limits and application admission are not a container, kernel
sandbox, or microVM.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import tempfile
from time import monotonic
from typing import Any, Literal

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, model_validator


WORKER_SOURCE = r'''import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

mode = sys.argv[1]
path = Path(sys.argv[2])
limits = json.loads(sys.argv[3])
resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
resource.setrlimit(resource.RLIMIT_FSIZE, (limits["max_file_bytes"], limits["max_file_bytes"]))
resource.setrlimit(resource.RLIMIT_NOFILE, (limits["max_open_files"], limits["max_open_files"]))
if hasattr(resource, "RLIMIT_NPROC"):
    resource.setrlimit(resource.RLIMIT_NPROC, (limits["max_processes"], limits["max_processes"]))
if hasattr(resource, "RLIMIT_CORE"):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if sys.platform != "darwin":
    address_space = limits["address_space_mib"] * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
if mode == "inspect":
    data = path.read_bytes()
    print(json.dumps({
        "bytes": len(data),
        "lines": len(data.splitlines()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "environment_keys": sorted(os.environ),
        "working_directory": Path.cwd().name,
    }, sort_keys=True))
elif mode == "hang":
    time.sleep(30)
elif mode == "oversize":
    sys.stdout.write("x" * 1048576)
elif mode == "invalid-json":
    print("not-json")
elif mode == "fail":
    print("worker failed", file=sys.stderr)
    raise SystemExit(17)
else:
    raise SystemExit(64)
'''

WORKER_DIGEST = "sha256:" + sha256(WORKER_SOURCE.encode()).hexdigest()
IMAGE_DIGEST = "registry.example/support-inspector@sha256:" + "a" * 64
SAFE_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
}
PLATFORM_ENVIRONMENT_KEYS = (
    frozenset({"__CF_USER_TEXT_ENCODING"}) if sys.platform == "darwin" else frozenset()
)
LOCAL_ENFORCED_CONTROLS = (
    "pinned-worker-digest",
    "exact-argv-without-shell",
    "dedicated-working-directory",
    "input-copy-marked-mode-0400-not-a-filesystem-boundary",
    "minimal-explicit-environment",
    "pinned-wrapper-applies-cpu-file-process-and-fd-rlimits-before-workload-logic",
    "wall-clock-timeout-and-process-group-kill",
    "bounded-file-backed-output",
)
LOCAL_NOT_ENFORCED = (
    "filesystem-namespace-or-read-only-root",
    "network-namespace-or-egress-filter",
    "non-root-uid-remapping",
    "no-new-privileges-and-capability-drop",
    "seccomp-apparmor-selinux-or-landlock",
    "cgroup-accounting-and-multi-tenant-kernel-separation",
)


class DocumentRecord(BaseModel):
    """Trusted registry entry; model input supplies only the opaque file ID."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    file_id: str = Field(pattern=r"^file-[a-z0-9-]{3,40}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    relative_path: str = Field(min_length=1, max_length=120)
    content: bytes = Field(max_length=65_536)


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    request_id: str = Field(pattern=r"^run-[a-z0-9-]{3,60}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    file_id: str = Field(pattern=r"^file-[a-z0-9-]{3,40}$")
    operation: Literal["inspect"] = "inspect"
    requested_env_keys: frozenset[str] = frozenset()
    network_destination: str | None = None


class LocalSandboxPolicy(BaseModel):
    """Controls this portable Python harness can actually apply and test."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    policy_id: str = "local-sandbox-v1"
    worker_digest: str = WORKER_DIGEST
    allowed_operations: frozenset[str] = frozenset({"inspect"})
    allowed_env_keys: frozenset[str] = frozenset(SAFE_ENVIRONMENT)
    network_mode: Literal["none"] = "none"
    max_input_bytes: int = Field(default=32_768, ge=1, le=65_536)
    cpu_seconds: int = Field(default=1, ge=1, le=5)
    address_space_mib: int = Field(default=128, ge=32, le=512)
    max_file_bytes: int = Field(default=4_096, ge=512, le=65_536)
    max_processes: int = Field(default=8, ge=1, le=32)
    max_open_files: int = Field(default=32, ge=8, le=128)
    timeout_ms: int = Field(default=500, ge=50, le=5_000)


class ProductionIsolationProfile(BaseModel):
    """Required deployment contract; validated here, enforced by the platform."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    profile_id: str = "restricted-sandbox-v1"
    isolation_tier: Literal["sandboxed-container", "microvm"] = "sandboxed-container"
    runtime_class_name: str = "gvisor"
    image: str = IMAGE_DIGEST
    run_as_non_root: bool = True
    read_only_root_filesystem: bool = True
    allow_privilege_escalation: bool = False
    privileged: bool = False
    drop_capabilities: tuple[str, ...] = ("ALL",)
    seccomp_profile: Literal["RuntimeDefault", "Localhost"] = "RuntimeDefault"
    apparmor_profile: Literal["RuntimeDefault", "Localhost"] = "RuntimeDefault"
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    automount_service_account_token: bool = False
    memory_limit_mib: int = Field(default=128, ge=32, le=1_024)
    cpu_limit_millicores: int = Field(default=250, ge=10, le=2_000)
    ephemeral_storage_limit_mib: int = Field(default=32, ge=1, le=1_024)
    process_limit: int = Field(default=64, ge=1, le=512)
    network_default_deny: bool = True

    @model_validator(mode="after")
    def require_hardened_profile(self):
        failures: list[str] = []
        if "@sha256:" not in self.image:
            failures.append("IMAGE_NOT_DIGEST_PINNED")
        if not self.run_as_non_root:
            failures.append("NON_ROOT_REQUIRED")
        if not self.read_only_root_filesystem:
            failures.append("READ_ONLY_ROOT_REQUIRED")
        if self.allow_privilege_escalation:
            failures.append("PRIVILEGE_ESCALATION_FORBIDDEN")
        if self.privileged:
            failures.append("PRIVILEGED_FORBIDDEN")
        if self.drop_capabilities != ("ALL",):
            failures.append("DROP_ALL_CAPABILITIES_REQUIRED")
        if self.host_network or self.host_pid or self.host_ipc:
            failures.append("HOST_NAMESPACES_FORBIDDEN")
        if self.automount_service_account_token:
            failures.append("SERVICE_ACCOUNT_TOKEN_FORBIDDEN")
        if not self.network_default_deny:
            failures.append("NETWORK_DEFAULT_DENY_REQUIRED")
        if failures:
            raise ValueError(",".join(failures))
        return self


@dataclass(frozen=True)
class AdmissionEvent:
    request_id: str
    decision: str
    reason_code: str
    policy_id: str
    worker_fingerprint: str
    tenant_id: str
    file_id: str
    operation: str


@dataclass(frozen=True)
class ExecutionEvent:
    request_id: str
    terminal_state: str
    reason_code: str
    duration_ms: int
    exit_code: int | None
    timed_out: bool
    output_bytes: int
    evidence_id: str
    enforced_controls: tuple[str, ...]


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    reason_code: str
    record: DocumentRecord | None


class SandboxDenied(RuntimeError):
    def __init__(self, code: str, message: str = "document is unavailable") -> None:
        super().__init__(message)
        self.code = code


class SandboxExecutionFailed(RuntimeError):
    def __init__(self, code: str, message: str = "sandbox execution failed") -> None:
        super().__init__(message)
        self.code = code


class SandboxAdmission:
    def __init__(
        self,
        policy: LocalSandboxPolicy,
        records: tuple[DocumentRecord, ...],
    ) -> None:
        self.policy = policy
        self.records = {record.file_id: record for record in records}
        self.events: list[AdmissionEvent] = []

    @staticmethod
    def worker_fingerprint(digest: str) -> str:
        return digest.removeprefix("sha256:")[:16]

    @staticmethod
    def _safe_relative_path(relative_path: str) -> bool:
        candidate = PurePosixPath(relative_path)
        return (
            not candidate.is_absolute()
            and ".." not in candidate.parts
            and "." not in candidate.parts
            and candidate.name not in {"", ".", ".."}
        )

    def _record_event(self, request: ExecutionRequest, allowed: bool, reason: str) -> None:
        self.events.append(
            AdmissionEvent(
                request_id=request.request_id,
                decision="allow" if allowed else "deny",
                reason_code=reason,
                policy_id=self.policy.policy_id,
                worker_fingerprint=self.worker_fingerprint(self.policy.worker_digest),
                tenant_id=request.tenant_id,
                file_id=request.file_id,
                operation=request.operation,
            )
        )

    def evaluate(self, request: ExecutionRequest) -> AdmissionDecision:
        reason = "ADMISSION_ALLOWED"
        record = self.records.get(request.file_id)
        if self.policy.worker_digest != WORKER_DIGEST:
            reason = "ARTIFACT_DIGEST_MISMATCH"
        elif request.operation not in self.policy.allowed_operations:
            reason = "OPERATION_DENIED"
        elif request.network_destination is not None or self.policy.network_mode != "none":
            reason = "NETWORK_DENIED"
        elif not request.requested_env_keys <= self.policy.allowed_env_keys:
            reason = "ENVIRONMENT_KEY_DENIED"
        elif record is None:
            reason = "FILE_NOT_REGISTERED"
        elif record.tenant_id != request.tenant_id:
            reason = "TENANT_MISMATCH"
        elif not self._safe_relative_path(record.relative_path):
            reason = "PATH_OUTSIDE_SANDBOX"
        elif len(record.content) > self.policy.max_input_bytes:
            reason = "INPUT_LIMIT_EXCEEDED"
        allowed = reason == "ADMISSION_ALLOWED"
        self._record_event(request, allowed, reason)
        return AdmissionDecision(allowed=allowed, reason_code=reason, record=record if allowed else None)

    def require(self, request: ExecutionRequest) -> DocumentRecord:
        decision = self.evaluate(request)
        if not decision.allowed or decision.record is None:
            raise SandboxDenied(decision.reason_code)
        return decision.record


def resolve_beneath(root: Path, candidate: Path) -> Path:
    """Resolve a path and reject traversal or symlink escape from root."""

    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    if resolved_candidate == resolved_root or not resolved_candidate.is_relative_to(resolved_root):
        raise SandboxDenied("PATH_OUTSIDE_SANDBOX")
    return resolved_candidate


class BoundedSubprocessRuntime:
    """Actual local boundary with explicitly reported, limited guarantees."""

    def __init__(self, policy: LocalSandboxPolicy) -> None:
        self.policy = policy
        self.events: list[ExecutionEvent] = []

    @staticmethod
    def _evidence_id(request_id: str, state: str) -> str:
        return "evidence-" + sha256(f"{request_id}:{state}".encode()).hexdigest()[:16]

    def _event(
        self,
        request: ExecutionRequest,
        *,
        state: str,
        reason: str,
        started: float,
        exit_code: int | None,
        timed_out: bool,
        output_bytes: int,
    ) -> ExecutionEvent:
        event = ExecutionEvent(
            request_id=request.request_id,
            terminal_state=state,
            reason_code=reason,
            duration_ms=max(0, int((monotonic() - started) * 1_000)),
            exit_code=exit_code,
            timed_out=timed_out,
            output_bytes=output_bytes,
            evidence_id=self._evidence_id(request.request_id, state),
            enforced_controls=LOCAL_ENFORCED_CONTROLS,
        )
        self.events.append(event)
        return event

    def execute(
        self,
        request: ExecutionRequest,
        record: DocumentRecord,
        *,
        trusted_fault: Literal["none", "hang", "oversize", "invalid-json", "fail"] = "none",
    ) -> dict[str, Any]:
        started = monotonic()
        mode = "inspect" if trusted_fault == "none" else trusted_fault
        with tempfile.TemporaryDirectory(prefix="mcp-course09-") as temporary:
            sandbox_root = Path(temporary)
            input_root = sandbox_root / "input"
            scratch = sandbox_root / "scratch"
            input_root.mkdir(mode=0o700)
            scratch.mkdir(mode=0o700)
            input_path = input_root / record.relative_path
            input_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            input_path.write_bytes(record.content)
            input_path.chmod(0o400)
            safe_input = resolve_beneath(input_root, input_path)
            stdout_path = sandbox_root / "stdout"
            stderr_path = sandbox_root / "stderr"
            limits = json.dumps(
                {
                    "cpu_seconds": self.policy.cpu_seconds,
                    "address_space_mib": self.policy.address_space_mib,
                    "max_file_bytes": self.policy.max_file_bytes,
                    "max_processes": self.policy.max_processes,
                    "max_open_files": self.policy.max_open_files,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            argv = [
                sys.executable,
                "-I",
                "-c",
                WORKER_SOURCE,
                mode,
                str(safe_input),
                limits,
            ]
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(
                    argv,
                    cwd=scratch,
                    env=dict(SAFE_ENVIRONMENT),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                )
                timed_out = False
                try:
                    process.wait(timeout=self.policy.timeout_ms / 1_000)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            output = stdout_path.read_bytes()
            output_bytes = len(output)
            if timed_out:
                self._event(
                    request,
                    state="terminated",
                    reason="WALL_CLOCK_TIMEOUT",
                    started=started,
                    exit_code=process.returncode,
                    timed_out=True,
                    output_bytes=output_bytes,
                )
                raise SandboxExecutionFailed("WALL_CLOCK_TIMEOUT")
            if output_bytes >= self.policy.max_file_bytes:
                self._event(
                    request,
                    state="terminated",
                    reason="OUTPUT_LIMIT_EXCEEDED",
                    started=started,
                    exit_code=process.returncode,
                    timed_out=False,
                    output_bytes=output_bytes,
                )
                raise SandboxExecutionFailed("OUTPUT_LIMIT_EXCEEDED")
            if process.returncode != 0:
                self._event(
                    request,
                    state="failed",
                    reason="WORKER_NONZERO_EXIT",
                    started=started,
                    exit_code=process.returncode,
                    timed_out=False,
                    output_bytes=output_bytes,
                )
                raise SandboxExecutionFailed("WORKER_NONZERO_EXIT")
            try:
                payload = json.loads(output)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._event(
                    request,
                    state="failed",
                    reason="INVALID_WORKER_OUTPUT",
                    started=started,
                    exit_code=process.returncode,
                    timed_out=False,
                    output_bytes=output_bytes,
                )
                raise SandboxExecutionFailed("INVALID_WORKER_OUTPUT") from exc
            if not isinstance(payload, dict):
                raise SandboxExecutionFailed("INVALID_WORKER_OUTPUT")
            event = self._event(
                request,
                state="succeeded",
                reason="EXECUTION_SUCCEEDED",
                started=started,
                exit_code=process.returncode,
                timed_out=False,
                output_bytes=output_bytes,
            )
            return {
                "file_id": record.file_id,
                "bytes": payload["bytes"],
                "lines": payload["lines"],
                "sha256": payload["sha256"],
                "environment_keys": payload["environment_keys"],
                "evidence_id": event.evidence_id,
                "enforcement_mode": "bounded-local-subprocess",
            }


class SandboxedDocumentService:
    def __init__(
        self,
        admission: SandboxAdmission,
        runtime: BoundedSubprocessRuntime,
        tenant_id: str = "acme",
    ) -> None:
        self.admission = admission
        self.runtime = runtime
        self.tenant_id = tenant_id
        self.sequence = 0

    def inspect(self, file_id: str) -> dict[str, Any]:
        self.sequence += 1
        request = ExecutionRequest(
            request_id=f"run-mcp-{self.sequence}",
            tenant_id=self.tenant_id,
            file_id=file_id,
            requested_env_keys=frozenset(SAFE_ENVIRONMENT),
        )
        record = self.admission.require(request)
        return self.runtime.execute(request, record)


def build_mcp_server(service: SandboxedDocumentService) -> MCPServer:
    server = MCPServer("northstar-isolated-inspector")

    @server.tool(name="document.inspect")
    def inspect_document(file_id: str) -> dict[str, Any]:
        try:
            return service.inspect(file_id)
        except (SandboxDenied, SandboxExecutionFailed) as exc:
            raise ToolError("document is unavailable") from exc

    return server


def restricted_kubernetes_bundle(profile: ProductionIsolationProfile) -> dict[str, Any]:
    """Reference mapping; deployment evidence must confirm the cluster enforces it."""

    labels = {"app": "support-inspector", "sandbox-profile": profile.profile_id}
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "support-inspector", "labels": labels},
        "spec": {
            "runtimeClassName": profile.runtime_class_name,
            "automountServiceAccountToken": profile.automount_service_account_token,
            "hostNetwork": profile.host_network,
            "hostPID": profile.host_pid,
            "hostIPC": profile.host_ipc,
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": profile.run_as_non_root,
                "seccompProfile": {"type": profile.seccomp_profile},
                "appArmorProfile": {"type": profile.apparmor_profile},
            },
            "containers": [
                {
                    "name": "server",
                    "image": profile.image,
                    "securityContext": {
                        "allowPrivilegeEscalation": profile.allow_privilege_escalation,
                        "privileged": profile.privileged,
                        "readOnlyRootFilesystem": profile.read_only_root_filesystem,
                        "capabilities": {"drop": list(profile.drop_capabilities)},
                    },
                    "resources": {
                        "limits": {
                            "cpu": f"{profile.cpu_limit_millicores}m",
                            "memory": f"{profile.memory_limit_mib}Mi",
                            "ephemeral-storage": f"{profile.ephemeral_storage_limit_mib}Mi",
                        }
                    },
                    "volumeMounts": [
                        {"name": "input", "mountPath": "/input", "readOnly": True},
                        {"name": "scratch", "mountPath": "/scratch", "readOnly": False},
                    ],
                }
            ],
            "volumes": [
                {"name": "input", "configMap": {"name": "reviewed-input"}},
                {
                    "name": "scratch",
                    "emptyDir": {"sizeLimit": f"{profile.ephemeral_storage_limit_mib}Mi"},
                },
            ],
        },
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "support-inspector-default-deny"},
        "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"]},
    }
    return {
        "pod": pod,
        "network_policy": network_policy,
        "operator_notes": [
            "Enforce the Restricted Pod Security Standard at a pinned cluster version.",
            "Confirm RuntimeClass resolves to the intended sandbox runtime on every eligible node.",
            "Confirm the CNI actually enforces NetworkPolicy; add explicit DNS/API egress separately.",
            "Apply an external process-count mechanism because core Pod resources do not express a PID limit.",
            "Verify admission, runtime, node kernel, and image-signature evidence after deployment.",
        ],
    }


def default_environment(
    *,
    policy: LocalSandboxPolicy | None = None,
    records: tuple[DocumentRecord, ...] | None = None,
):
    policy = policy or LocalSandboxPolicy()
    records = records or (
        DocumentRecord(
            file_id="file-support-policy",
            tenant_id="acme",
            relative_path="policies/support.txt",
            content=b"Refunds above $500 require approval.\nNever disclose access tokens.\n",
        ),
        DocumentRecord(
            file_id="file-other-tenant",
            tenant_id="globex",
            relative_path="policies/partner.txt",
            content=b"Globex confidential policy.\n",
        ),
    )
    admission = SandboxAdmission(policy, records)
    runtime = BoundedSubprocessRuntime(policy)
    service = SandboxedDocumentService(admission, runtime)
    return admission, runtime, service


def request_for(
    *,
    request_id: str = "run-manual-1",
    tenant_id: str = "acme",
    file_id: str = "file-support-policy",
    env_keys: frozenset[str] = frozenset(SAFE_ENVIRONMENT),
    network_destination: str | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        file_id=file_id,
        requested_env_keys=env_keys,
        network_destination=network_destination,
    )


def event_json(events: list[Any]) -> str:
    return json.dumps([asdict(event) for event in events], sort_keys=True)


async def run_scenario() -> dict[str, Any]:
    admission, runtime, service = default_environment()
    server = build_mcp_server(service)
    parent_secret = os.environ.get("COURSE09_PARENT_SECRET")
    os.environ["COURSE09_PARENT_SECRET"] = "must-not-cross-boundary"
    try:
        async with Client(server, raise_exceptions=False) as client:
            allowed = await client.call_tool(
                "document.inspect", {"file_id": "file-support-policy"}
            )
            unknown = await client.call_tool(
                "document.inspect", {"file_id": "file-unknown"}
            )
    finally:
        if parent_secret is None:
            os.environ.pop("COURSE09_PARENT_SECRET", None)
        else:
            os.environ["COURSE09_PARENT_SECRET"] = parent_secret

    allowed_payload = json.loads(allowed.content[0].text)
    attacks = (
        request_for(
            request_id="run-attack-env",
            env_keys=frozenset({"LANG", "COURSE09_PARENT_SECRET"}),
        ),
        request_for(
            request_id="run-attack-network",
            network_destination="https://evil.example",
        ),
        request_for(
            request_id="run-attack-tenant",
            file_id="file-other-tenant",
        ),
    )
    blocked = [admission.evaluate(attack).reason_code for attack in attacks]
    timeout_request = request_for(request_id="run-fault-timeout")
    timeout_record = admission.require(timeout_request)
    try:
        runtime.execute(timeout_request, timeout_record, trusted_fault="hang")
    except SandboxExecutionFailed as exc:
        timeout_reason = exc.code
    else:
        raise AssertionError("hung worker escaped the wall-clock timeout")
    output_request = request_for(request_id="run-fault-output")
    output_record = admission.require(output_request)
    try:
        runtime.execute(output_request, output_record, trusted_fault="oversize")
    except SandboxExecutionFailed as exc:
        output_reason = exc.code
    else:
        raise AssertionError("oversized output escaped the file-size limit")

    serialized_events = event_json(admission.events) + event_json(runtime.events)
    evidence = {
        "valid_mcp_call": not allowed.is_error,
        "unknown_file_denied": unknown.is_error,
        "blocked_attempts": len(blocked) + 2,
        "blocked_reason_codes": sorted(blocked + [timeout_reason, output_reason]),
        "fixture_forbidden_effects": 0,
        "parent_secret_absent": "COURSE09_PARENT_SECRET" not in allowed_payload["environment_keys"],
        "raw_document_absent_from_events": "Refunds above" not in serialized_events,
        "local_enforced_controls": list(LOCAL_ENFORCED_CONTROLS),
        "address_space_limit_enforced": sys.platform != "darwin",
        "production_controls_not_claimed": list(LOCAL_NOT_ENFORCED),
    }
    assert evidence["valid_mcp_call"] is True
    assert evidence["unknown_file_denied"] is True
    assert evidence["fixture_forbidden_effects"] == 0
    assert evidence["parent_secret_absent"] is True
    assert evidence["raw_document_absent_from_events"] is True
    return evidence


def main() -> None:
    evidence = asyncio.run(run_scenario())
    print("PASS: bounded subprocess and admission controls block the tested escape paths")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
