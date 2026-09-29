"""Course 14: deterministic security testing and structure-aware fuzzing.

The lab is credential-free and never opens a network connection. It tests a
small MCP 2026-07-28 ingress boundary, uses the official SDK in memory, keeps
the oracle independent from the target, and measures observable disclosures or
effects rather than trusting a returned decision string.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
import json
import random
import re
import threading
from typing import Any, Callable

from mcp import Client
from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, Implementation, TextContent


UTC = timezone.utc
PROTOCOL_VERSION = "2026-07-28"
POLICY_VERSION = "mcp-test-policy/2026-09-29"
TARGET_VERSION = "secure-gateway/2.0.0"
VULNERABLE_TARGET_VERSION = "vulnerable-gateway/1.0.0"
ALLOWED_APPROVERS = frozenset({"reviewer-9", "security-reviewer-4"})
MAX_INPUT_BYTES = 4_096
MAX_DEPTH = 8
MAX_KEYS = 32
MAX_STRING = 512
TICKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
OPERATION_PATTERN = re.compile(r"^op-[a-z0-9-]{1,48}$")


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return parsed.astimezone(UTC)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes | dict[str, Any]) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value)
    return f"sha256:{sha256(payload).hexdigest()}"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    PROTOCOL_ERROR = "protocol_error"
    CRASH = "crash"


class CaseClass(StrEnum):
    VALID = "valid"
    ATTACK = "attack"
    ROBUSTNESS = "robustness"


class InputRejected(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class DuplicateKey(InputRejected):
    def __init__(self, key: str) -> None:
        super().__init__("DUPLICATE_JSON_KEY", f"duplicate JSON key: {key}")


@dataclass(frozen=True)
class TrustedIdentity:
    principal_id: str
    tenant_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class RequestHeaders:
    protocol_version: str
    method: str
    name: str


@dataclass(frozen=True)
class Effect:
    operation_id: str
    effect_type: str
    tenant_id: str
    resource_id: str
    payload_digest: str


class EffectLedger:
    """Observable state used by the oracle; it is not a target self-report."""

    def __init__(self) -> None:
        self._effects: dict[str, Effect] = {}
        self._lock = threading.Lock()

    def count(self) -> int:
        with self._lock:
            return len(self._effects)

    def record(self, effect: Effect) -> bool:
        with self._lock:
            prior = self._effects.get(effect.operation_id)
            if prior is not None and prior != effect:
                raise InputRejected("IDEMPOTENCY_CONFLICT", "operation ID binds another effect")
            if prior is not None:
                return False
            self._effects[effect.operation_id] = effect
            return True

    def snapshot(self) -> tuple[Effect, ...]:
        with self._lock:
            return tuple(self._effects.values())


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    principal_id: str
    tenant_id: str
    action_digest: str
    approver_id: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime


@dataclass
class _StoredApproval:
    receipt: ApprovalReceipt
    consumed: bool = False


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, _StoredApproval] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        identity: TrustedIdentity,
        action_digest: str,
        now: datetime,
        approver_id: str,
        approver_role: str,
    ) -> ApprovalReceipt:
        if (
            approver_id not in ALLOWED_APPROVERS
            or approver_role != "release-reviewer"
            or approver_id == identity.principal_id
        ):
            raise InputRejected("APPROVER_NOT_ELIGIBLE", "approver is not eligible")
        receipt = ApprovalReceipt(
            receipt_id=f"approval-{action_digest[7:23]}",
            principal_id=identity.principal_id,
            tenant_id=identity.tenant_id,
            action_digest=action_digest,
            approver_id=approver_id,
            approver_role=approver_role,
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
        )
        with self._lock:
            if receipt.receipt_id in self._records:
                raise InputRejected("APPROVAL_ALREADY_EXISTS", "approval already exists")
            self._records[receipt.receipt_id] = _StoredApproval(receipt)
        return receipt

    def consume(
        self,
        receipt_id: str,
        identity: TrustedIdentity,
        action_digest: str,
        now: datetime,
    ) -> None:
        with self._lock:
            stored = self._records.get(receipt_id)
            if stored is None:
                raise InputRejected("APPROVAL_NOT_FOUND", "approval is not trusted")
            if stored.consumed:
                raise InputRejected("APPROVAL_REPLAYED", "approval was already consumed")
            receipt = stored.receipt
            if now >= receipt.expires_at:
                raise InputRejected("APPROVAL_EXPIRED", "approval has expired")
            if (
                receipt.principal_id != identity.principal_id
                or receipt.tenant_id != identity.tenant_id
                or receipt.action_digest != action_digest
            ):
                raise InputRejected("APPROVAL_BINDING_MISMATCH", "approval binds another action")
            stored.consumed = True


@dataclass(frozen=True)
class Observation:
    decision: Decision
    reason_code: str
    trace_id: str
    response: dict[str, Any]
    coverage_features: frozenset[str]
    crash_type: str | None = None


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def _measure(value: Any, depth: int = 0) -> tuple[int, int]:
    if depth > MAX_DEPTH:
        raise InputRejected("NESTING_LIMIT", "JSON nesting exceeds policy")
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise InputRejected("STRING_LIMIT", "string exceeds policy")
        return 0, depth
    if isinstance(value, dict):
        keys = len(value)
        deepest = depth
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 100:
                raise InputRejected("KEY_INVALID", "JSON object key is invalid")
            child_keys, child_depth = _measure(child, depth + 1)
            keys += child_keys
            deepest = max(deepest, child_depth)
        return keys, deepest
    if isinstance(value, list):
        keys = 0
        deepest = depth
        for child in value:
            child_keys, child_depth = _measure(child, depth + 1)
            keys += child_keys
            deepest = max(deepest, child_depth)
        return keys, deepest
    return 0, depth


def parse_request(raw: bytes, headers: RequestHeaders) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise InputRejected("INPUT_TOO_LARGE", "request exceeds byte budget")
    try:
        request = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except DuplicateKey:
        raise
    except RecursionError as exc:
        raise InputRejected("NESTING_LIMIT", "JSON nesting exceeds policy") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InputRejected("MALFORMED_JSON", "request is not valid JSON") from exc
    if not isinstance(request, dict):
        raise InputRejected("INVALID_ENVELOPE", "request must be an object")
    try:
        key_count, _ = _measure(request)
    except RecursionError as exc:
        raise InputRejected("NESTING_LIMIT", "JSON nesting exceeds policy") from exc
    if key_count > MAX_KEYS:
        raise InputRejected("KEY_LIMIT", "request contains too many keys")
    if set(request) != {"jsonrpc", "id", "method", "params"}:
        raise InputRejected("INVALID_ENVELOPE", "JSON-RPC envelope fields differ")
    if request["jsonrpc"] != "2.0":
        raise InputRejected("INVALID_JSONRPC_VERSION", "jsonrpc must equal 2.0")
    if isinstance(request["id"], bool) or not isinstance(request["id"], (str, int)):
        raise InputRejected("INVALID_REQUEST_ID", "request ID must be a string or integer")
    if request["method"] != "tools/call":
        raise InputRejected("METHOD_NOT_ALLOWED", "only tools/call is in this harness")
    params = request["params"]
    if not isinstance(params, dict) or set(params) != {"name", "arguments", "_meta"}:
        raise InputRejected("INVALID_PARAMS", "tool params fields differ")
    if not isinstance(params["name"], str) or not isinstance(params["arguments"], dict):
        raise InputRejected("INVALID_PARAMS", "tool name and arguments have invalid types")
    metadata = params["_meta"]
    if not isinstance(metadata, dict):
        raise InputRejected("INVALID_CLIENT_METADATA", "client metadata must be an object")
    allowed_meta = {
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/clientCapabilities",
    }
    if "io.modelcontextprotocol/clientInfo" not in metadata or not set(metadata) <= allowed_meta:
        raise InputRejected("INVALID_CLIENT_METADATA", "client metadata fields differ")
    client_info = metadata["io.modelcontextprotocol/clientInfo"]
    if (
        not isinstance(client_info, dict)
        or set(client_info) != {"name", "version"}
        or not all(isinstance(value, str) and 0 < len(value) <= 64 for value in client_info.values())
    ):
        raise InputRejected("INVALID_CLIENT_METADATA", "client identity shape is invalid")
    if headers.protocol_version != PROTOCOL_VERSION:
        raise InputRejected("PROTOCOL_VERSION_MISMATCH", "protocol version header differs")
    if headers.method != request["method"] or headers.name != params["name"]:
        raise InputRejected("HEADER_BODY_MISMATCH", "routing headers differ from body")
    return request


def reply_action_digest(
    identity: TrustedIdentity,
    ticket_id: str,
    body: str,
    operation_id: str,
) -> str:
    return digest(
        {
            "principal_id": identity.principal_id,
            "tenant_id": identity.tenant_id,
            "tool": "ticket.reply",
            "ticket_id": ticket_id,
            "body": body,
            "operation_id": operation_id,
            "policy_version": POLICY_VERSION,
        }
    )


class McpGateway:
    """Small target under test. The oracle lives outside this implementation."""

    target_version = TARGET_VERSION

    def __init__(self, *, enforce_tenant: bool = True) -> None:
        self.enforce_tenant = enforce_tenant
        self.ledger = EffectLedger()
        self.approvals = ApprovalStore()
        self.tickets = {
            "acme-7": {"tenant_id": "acme", "summary": "Payment pending"},
            "other-7": {"tenant_id": "other", "summary": "Private merger inquiry"},
        }

    def issue_reply_approval(
        self,
        identity: TrustedIdentity,
        ticket_id: str,
        body: str,
        operation_id: str,
        now: datetime,
        approver_id: str = "reviewer-9",
        approver_role: str = "release-reviewer",
    ) -> ApprovalReceipt:
        return self.approvals.issue(
            identity,
            reply_action_digest(identity, ticket_id, body, operation_id),
            now,
            approver_id,
            approver_role,
        )

    def handle(
        self,
        raw: bytes,
        headers: RequestHeaders,
        identity: TrustedIdentity,
        now: datetime,
    ) -> Observation:
        trace_id = f"trace-{sha256(raw + identity.principal_id.encode()).hexdigest()[:16]}"
        features = {"request_received"}
        try:
            request = parse_request(raw, headers)
            features.add("protocol_valid")
            params = request["params"]
            name = params["name"]
            arguments = params["arguments"]
            if name == "ticket.read":
                return self._read(trace_id, identity, arguments, features)
            if name == "ticket.reply":
                return self._reply(trace_id, identity, arguments, now, features)
            raise InputRejected("TOOL_NOT_ALLOWED", "tool is not approved")
        except InputRejected as denied:
            decision = (
                Decision.PROTOCOL_ERROR
                if denied.code
                in {
                    "INPUT_TOO_LARGE",
                    "NESTING_LIMIT",
                    "STRING_LIMIT",
                    "KEY_INVALID",
                    "KEY_LIMIT",
                    "DUPLICATE_JSON_KEY",
                    "MALFORMED_JSON",
                    "INVALID_ENVELOPE",
                    "INVALID_JSONRPC_VERSION",
                    "INVALID_REQUEST_ID",
                    "METHOD_NOT_ALLOWED",
                    "INVALID_PARAMS",
                    "INVALID_CLIENT_METADATA",
                    "PROTOCOL_VERSION_MISMATCH",
                    "HEADER_BODY_MISMATCH",
                }
                else Decision.DENY
            )
            features.add(f"rejected:{denied.code}")
            return Observation(
                decision,
                denied.code,
                trace_id,
                {"jsonrpc": "2.0", "error": {"code": denied.code}},
                frozenset(features),
            )

    def _ticket(self, ticket_id: Any, identity: TrustedIdentity) -> dict[str, str]:
        if not isinstance(ticket_id, str) or not TICKET_PATTERN.fullmatch(ticket_id):
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "ticket ID shape is invalid")
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise InputRejected("NOT_FOUND_OR_FORBIDDEN", "ticket is unavailable")
        if self.enforce_tenant and ticket["tenant_id"] != identity.tenant_id:
            raise InputRejected("NOT_FOUND_OR_FORBIDDEN", "ticket is unavailable")
        return ticket

    def _read(
        self,
        trace_id: str,
        identity: TrustedIdentity,
        arguments: dict[str, Any],
        features: set[str],
    ) -> Observation:
        if set(arguments) != {"ticket_id"}:
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "read arguments differ")
        if "ticket:read" not in identity.scopes:
            raise InputRejected("SCOPE_DENIED", "read scope is missing")
        ticket_id = arguments["ticket_id"]
        ticket = self._ticket(ticket_id, identity)
        features.update({"tool:ticket.read", "release:ticket"})
        payload = {"ticket_id": ticket_id, "summary": ticket["summary"]}
        self.ledger.record(
            Effect(
                operation_id=f"read:{trace_id}",
                effect_type="data_release",
                tenant_id=ticket["tenant_id"],
                resource_id=ticket_id,
                payload_digest=digest(payload),
            )
        )
        return Observation(
            Decision.ALLOW,
            "TENANT_READ_ALLOWED",
            trace_id,
            {"jsonrpc": "2.0", "result": payload},
            frozenset(features),
        )

    def _reply(
        self,
        trace_id: str,
        identity: TrustedIdentity,
        arguments: dict[str, Any],
        now: datetime,
        features: set[str],
    ) -> Observation:
        required = {"ticket_id", "body", "approval_receipt", "operation_id"}
        if set(arguments) != required:
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "reply arguments differ")
        if "ticket:reply" not in identity.scopes:
            raise InputRejected("SCOPE_DENIED", "reply scope is missing")
        ticket_id = arguments["ticket_id"]
        self._ticket(ticket_id, identity)
        body = arguments["body"]
        operation_id = arguments["operation_id"]
        receipt_id = arguments["approval_receipt"]
        if not isinstance(body, str) or not 1 <= len(body) <= 500:
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "reply body is invalid")
        if not isinstance(operation_id, str) or not OPERATION_PATTERN.fullmatch(operation_id):
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "operation ID is invalid")
        if not isinstance(receipt_id, str):
            raise InputRejected("ARGUMENT_SCHEMA_INVALID", "approval receipt is invalid")
        action = reply_action_digest(identity, ticket_id, body, operation_id)
        self.approvals.consume(receipt_id, identity, action, now)
        features.update({"tool:ticket.reply", "approval_consumed", "effect:reply"})
        self.ledger.record(
            Effect(operation_id, "ticket_reply", identity.tenant_id, ticket_id, action)
        )
        return Observation(
            Decision.ALLOW,
            "APPROVED_REPLY_EXECUTED",
            trace_id,
            {"jsonrpc": "2.0", "result": {"operation_id": operation_id, "status": "sent"}},
            frozenset(features),
        )


class VulnerableMcpGateway(McpGateway):
    """Deliberately vulnerable baseline: resource ownership is not enforced."""

    target_version = VULNERABLE_TARGET_VERSION

    def __init__(self) -> None:
        super().__init__(enforce_tenant=False)


def modern_request(
    name: str,
    arguments: dict[str, Any],
    *,
    request_id: int | str = 1,
    capabilities: dict[str, Any] | None = None,
) -> bytes:
    return canonical_json(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "course-14-harness",
                        "version": "1.0.0",
                    },
                    "io.modelcontextprotocol/clientCapabilities": capabilities or {},
                },
            },
        }
    )


def headers(name: str = "ticket.read") -> RequestHeaders:
    return RequestHeaders(PROTOCOL_VERSION, "tools/call", name)


@dataclass(frozen=True)
class SecurityCase:
    case_id: str
    case_class: CaseClass
    mutation: str
    seed: int
    raw: bytes
    headers: RequestHeaders
    identity: TrustedIdentity
    expected_decision: Decision
    expected_reason: str
    expected_effect_delta: int


@dataclass(frozen=True)
class OracleResult:
    passed: bool
    violations: tuple[str, ...]
    signature: str | None


class SecurityOracle:
    """Expected behavior is specified by the test case, never by target output."""

    def evaluate(
        self,
        case: SecurityCase,
        observation: Observation,
        effect_delta: int,
    ) -> OracleResult:
        violations: list[str] = []
        if observation.decision != case.expected_decision:
            violations.append("DECISION_MISMATCH")
        if observation.reason_code != case.expected_reason:
            violations.append("REASON_MISMATCH")
        if effect_delta != case.expected_effect_delta:
            violations.append("EFFECT_MISMATCH")
        if case.expected_decision != Decision.ALLOW and effect_delta:
            violations.append("FORBIDDEN_EFFECT_COMPLETED")
        if observation.crash_type is not None:
            violations.append("TARGET_CRASHED")
        signature = None
        if violations:
            signature = digest(
                canonical_json(
                    {
                        "violations": sorted(set(violations)),
                        "mutation": case.mutation,
                        "decision": observation.decision,
                        "reason": observation.reason_code,
                    }
                )
            )
        return OracleResult(not violations, tuple(sorted(set(violations))), signature)


@dataclass(frozen=True)
class CaseResult:
    case: SecurityCase
    observation: Observation
    oracle: OracleResult
    effect_delta: int
    target_version: str


def run_case(gateway: McpGateway, case: SecurityCase, now: datetime) -> CaseResult:
    before = gateway.ledger.count()
    try:
        observation = gateway.handle(case.raw, case.headers, case.identity, now)
    except Exception as exc:  # the harness records a crash; it does not hide it
        observation = Observation(
            Decision.CRASH,
            "UNCAUGHT_EXCEPTION",
            f"trace-crash-{case.case_id}",
            {},
            frozenset({"request_received", "target_crash"}),
            type(exc).__name__,
        )
    delta = gateway.ledger.count() - before
    return CaseResult(
        case,
        observation,
        SecurityOracle().evaluate(case, observation, delta),
        delta,
        gateway.target_version,
    )


def base_cases(seed: int = 1401) -> tuple[SecurityCase, ...]:
    identity = TrustedIdentity("analyst-42", "acme", frozenset({"ticket:read"}))
    safe_raw = modern_request("ticket.read", {"ticket_id": "acme-7"})
    safe = SecurityCase(
        "valid-read", CaseClass.VALID, "seed", seed, safe_raw, headers(), identity,
        Decision.ALLOW, "TENANT_READ_ALLOWED", 1,
    )
    cases = [safe]

    def add(
        case_id: str,
        case_class: CaseClass,
        mutation: str,
        raw: bytes,
        expected: Decision,
        reason: str,
        effect_delta: int = 0,
        request_headers: RequestHeaders | None = None,
    ) -> None:
        cases.append(
            SecurityCase(
                case_id, case_class, mutation, seed, raw, request_headers or headers(),
                identity, expected, reason, effect_delta,
            )
        )

    add(
        "cross-tenant-read", CaseClass.ATTACK, "cross_tenant_identifier",
        modern_request("ticket.read", {"ticket_id": "other-7"}),
        Decision.DENY, "NOT_FOUND_OR_FORBIDDEN",
    )
    add(
        "extra-property", CaseClass.ATTACK, "extra_argument",
        modern_request("ticket.read", {"ticket_id": "acme-7", "tenant_id": "other"}),
        Decision.DENY, "ARGUMENT_SCHEMA_INVALID",
    )
    add(
        "wrong-type", CaseClass.ROBUSTNESS, "wrong_type",
        modern_request("ticket.read", {"ticket_id": ["acme-7"]}),
        Decision.DENY, "ARGUMENT_SCHEMA_INVALID",
    )
    add(
        "unknown-tool", CaseClass.ATTACK, "capability_widening",
        modern_request("shell.exec", {"command": "id"}),
        Decision.DENY, "TOOL_NOT_ALLOWED", request_headers=headers("shell.exec"),
    )
    add(
        "header-mismatch", CaseClass.ATTACK, "routing_header_mismatch", safe_raw,
        Decision.PROTOCOL_ERROR, "HEADER_BODY_MISMATCH",
        request_headers=RequestHeaders(PROTOCOL_VERSION, "tools/call", "ticket.reply"),
    )
    add(
        "old-version", CaseClass.ROBUSTNESS, "protocol_version", safe_raw,
        Decision.PROTOCOL_ERROR, "PROTOCOL_VERSION_MISMATCH",
        request_headers=RequestHeaders("2025-11-25", "tools/call", "ticket.read"),
    )
    add(
        "malformed-json", CaseClass.ROBUSTNESS, "truncated_json", b'{"jsonrpc":"2.0"',
        Decision.PROTOCOL_ERROR, "MALFORMED_JSON",
    )
    duplicate = (
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call",'
        b'"params":{"name":"ticket.read","arguments":{"ticket_id":"acme-7"},'
        b'"_meta":{"io.modelcontextprotocol/clientInfo":{"name":"h","version":"1"}}}}'
    )
    add(
        "duplicate-id", CaseClass.ROBUSTNESS, "duplicate_json_key", duplicate,
        Decision.PROTOCOL_ERROR, "DUPLICATE_JSON_KEY",
    )
    add(
        "oversized", CaseClass.ROBUSTNESS, "byte_limit", b"{" + b"x" * MAX_INPUT_BYTES + b"}",
        Decision.PROTOCOL_ERROR, "INPUT_TOO_LARGE",
    )
    reordered = json.dumps(json.loads(safe_raw), indent=2, sort_keys=False).encode()
    add(
        "semantic-reencoding", CaseClass.VALID, "whitespace_reencoding", reordered,
        Decision.ALLOW, "TENANT_READ_ALLOWED", 1,
    )
    return tuple(cases)


def generated_cases(seed: int = 1401, max_cases: int = 10) -> tuple[SecurityCase, ...]:
    if not 1 <= max_cases <= 100:
        raise ValueError("max_cases must be between 1 and 100")
    cases = list(base_cases(seed))
    random.Random(seed).shuffle(cases)
    return tuple(cases[:max_cases])


@dataclass(frozen=True)
class CampaignReport:
    target_version: str
    seed: int
    total_cases: int
    oracle_passes: int
    unique_failure_signatures: int
    attack_attempts: int
    safe_blocks: int
    completed_forbidden_effects: int
    valid_attempts: int
    false_blocks: int
    robustness_cases: int
    crashes: int
    results: tuple[CaseResult, ...]

    def metrics(self) -> dict[str, float]:
        return {
            "oracle_pass_rate": self.oracle_passes / self.total_cases if self.total_cases else 0.0,
            "safe_block_rate": self.safe_blocks / self.attack_attempts if self.attack_attempts else 0.0,
            "attack_success_rate": (
                self.completed_forbidden_effects / self.attack_attempts
                if self.attack_attempts
                else 0.0
            ),
            "false_block_rate": self.false_blocks / self.valid_attempts if self.valid_attempts else 0.0,
            "robustness_crash_rate": self.crashes / self.robustness_cases if self.robustness_cases else 0.0,
        }


def run_campaign(
    target_factory: Callable[[], McpGateway],
    cases: tuple[SecurityCase, ...],
    now: datetime,
) -> CampaignReport:
    results: list[CaseResult] = []
    for case in cases:
        results.append(run_case(target_factory(), case, now))
    attacks = [result for result in results if result.case.case_class == CaseClass.ATTACK]
    valid = [result for result in results if result.case.case_class == CaseClass.VALID]
    robustness = [result for result in results if result.case.case_class == CaseClass.ROBUSTNESS]
    signatures = {result.oracle.signature for result in results if result.oracle.signature}
    return CampaignReport(
        target_version=results[0].target_version if results else target_factory().target_version,
        seed=cases[0].seed if cases else 0,
        total_cases=len(results),
        oracle_passes=sum(result.oracle.passed for result in results),
        unique_failure_signatures=len(signatures),
        attack_attempts=len(attacks),
        safe_blocks=sum(
            result.oracle.passed and result.effect_delta == 0 for result in attacks
        ),
        completed_forbidden_effects=sum(result.effect_delta for result in attacks),
        valid_attempts=len(valid),
        false_blocks=sum(result.observation.decision != Decision.ALLOW for result in valid),
        robustness_cases=len(robustness),
        crashes=sum(result.observation.crash_type is not None for result in robustness),
        results=tuple(results),
    )


def failure_artifact(result: CaseResult) -> dict[str, Any]:
    if result.oracle.passed:
        raise ValueError("passing cases do not produce failure artifacts")
    return {
        "case_id": result.case.case_id,
        "case_class": result.case.case_class,
        "mutation": result.case.mutation,
        "seed": result.case.seed,
        "target_version": result.target_version,
        "protocol_version": PROTOCOL_VERSION,
        "policy_version": POLICY_VERSION,
        "input_digest": digest(result.case.raw),
        "trace_id": result.observation.trace_id,
        "expected_decision": result.case.expected_decision,
        "actual_decision": result.observation.decision,
        "reason_code": result.observation.reason_code,
        "violations": result.oracle.violations,
        "failure_signature": result.oracle.signature,
    }


def shrink_failure(
    case: SecurityCase,
    still_fails: Callable[[SecurityCase], bool],
) -> SecurityCase:
    """Tiny delta-debugging example; production campaigns should use Hypothesis/Atheris."""

    best = case
    try:
        request = json.loads(case.raw)
    except json.JSONDecodeError:
        return best
    metadata = request.get("params", {}).get("_meta", {})
    optional = "io.modelcontextprotocol/clientCapabilities"
    if optional in metadata:
        candidate_request = copy.deepcopy(request)
        del candidate_request["params"]["_meta"][optional]
        candidate = replace(case, raw=canonical_json(candidate_request))
        if still_fails(candidate):
            best = candidate
    return best


# The official SDK probe exercises real discovery and schema validation in memory.
SDK_CALLS = {"ticket.read": 0}


async def enforce_exact_sdk_arguments(
    context: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    """Close the top-level extra-property behavior of the pinned SDK line."""

    if context.method == "tools/call" and context.params is not None:
        if context.params.get("name") == "ticket.read":
            arguments = context.params.get("arguments") or {}
            if not isinstance(arguments, dict) or set(arguments) != {"ticket_id"}:
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text="Invalid arguments: exact declared fields required.",
                        )
                    ],
                    is_error=True,
                )
    return await call_next(context)


sdk_server = MCPServer(
    "course-14-fuzz-target",
    version="1.0.0",
    middleware=[enforce_exact_sdk_arguments],
)


@sdk_server.tool(name="ticket.read")
def sdk_ticket_read(ticket_id: str) -> dict[str, Any]:
    SDK_CALLS["ticket.read"] += 1
    if ticket_id != "acme-7":
        raise ToolError("ticket is unavailable")
    return {"ticket_id": ticket_id, "summary": "Payment pending"}


@dataclass(frozen=True)
class SdkProbeEvidence:
    protocol_version: str
    tools: tuple[str, ...]
    valid_call_succeeded: bool
    domain_denial_is_error: bool
    extra_argument_is_error: bool
    handler_skipped_for_schema_error: bool


async def run_sdk_probe() -> SdkProbeEvidence:
    SDK_CALLS["ticket.read"] = 0
    client_info = Implementation(name="course-14-test-host", version="1.0.0")
    async with asyncio.timeout(5):
        async with Client(
            sdk_server, client_info=client_info, read_timeout_seconds=3
        ) as client:
            listed = await client.list_tools()
            valid = await client.call_tool("ticket.read", {"ticket_id": "acme-7"})
            denied = await client.call_tool("ticket.read", {"ticket_id": "other-7"})
            before_extra = SDK_CALLS["ticket.read"]
            extra = await client.call_tool(
                "ticket.read", {"ticket_id": "acme-7", "debug": True}
            )
            return SdkProbeEvidence(
                protocol_version=str(client.protocol_version),
                tools=tuple(sorted(tool.name for tool in listed.tools)),
                valid_call_succeeded=not valid.is_error,
                domain_denial_is_error=bool(denied.is_error),
                extra_argument_is_error=bool(extra.is_error),
                handler_skipped_for_schema_error=SDK_CALLS["ticket.read"] == before_extra,
            )


def approved_reply_fixture(
    gateway: McpGateway,
    now: datetime,
    *,
    body: str = "Use the verified payment link.",
    operation_id: str = "op-reply-7",
) -> tuple[SecurityCase, ApprovalReceipt]:
    identity = TrustedIdentity(
        "analyst-42", "acme", frozenset({"ticket:read", "ticket:reply"})
    )
    receipt = gateway.issue_reply_approval(
        identity, "acme-7", body, operation_id, now
    )
    raw = modern_request(
        "ticket.reply",
        {
            "ticket_id": "acme-7",
            "body": body,
            "approval_receipt": receipt.receipt_id,
            "operation_id": operation_id,
        },
    )
    return (
        SecurityCase(
            "approved-reply",
            CaseClass.VALID,
            "stateful_approval",
            1401,
            raw,
            headers("ticket.reply"),
            identity,
            Decision.ALLOW,
            "APPROVED_REPLY_EXECUTED",
            1,
        ),
        receipt,
    )


def run_demo() -> dict[str, Any]:
    now = utc("2026-09-29T04:00:00Z")
    cases = generated_cases()
    vulnerable = run_campaign(VulnerableMcpGateway, cases, now)
    hardened = run_campaign(McpGateway, cases, now)
    failing = next(result for result in vulnerable.results if not result.oracle.passed)
    shrunk = shrink_failure(
        failing.case,
        lambda candidate: not run_case(VulnerableMcpGateway(), candidate, now).oracle.passed,
    )
    sdk = asyncio.run(run_sdk_probe())
    return {
        "vulnerable_metrics": vulnerable.metrics(),
        "hardened_metrics": hardened.metrics(),
        "unique_vulnerable_failures": vulnerable.unique_failure_signatures,
        "failure_artifact": failure_artifact(failing),
        "shrunk_input_bytes": len(shrunk.raw),
        "sdk_probe": {
            "protocol_version": sdk.protocol_version,
            "tools": sdk.tools,
            "schema_enforced_before_handler": sdk.handler_skipped_for_schema_error,
        },
    }


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
