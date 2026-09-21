"""Course 02: deterministic MCP threat-model workshop fixture."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Threat:
    identifier: str
    stride: str
    boundary: str
    abuse_case: str
    invariant: str
    control: str
    test: str
    telemetry: str
    incident_action: str


THREATS = (
    Threat("TM-01", "Spoofing", "host → client", "A rogue server uses a familiar name.", "Only reviewed server identity/digest may connect.", "Registry allow-list and digest pin", "unknown digest is denied", "server identity + digest", "revoke server and preserve traces"),
    Threat("TM-02", "Tampering", "client → server", "A tool contract gains arbitrary URL input.", "Tool schemas are narrow and reviewed.", "Schema allow-list and capability gate", "broad URL tool is denied", "capability diff + decision", "disable integration"),
    Threat("TM-03", "Information disclosure", "server → downstream API", "A server uses host authority for another tenant.", "Caller, tenant, audience, and resource must match.", "Delegated token and resource policy", "cross-tenant call is denied", "tenant + audience + policy decision", "revoke credential and investigate"),
    Threat("TM-04", "Elevation of privilege", "untrusted content → host", "Tool output tells the model to upload secrets.", "Untrusted content cannot grant an action.", "Reauthorize action outside model", "poisoned output has no side effect", "content-risk signal + tool decision", "quarantine server if malicious"),
)


def coverage(threats: tuple[Threat, ...]) -> dict[str, int]:
    required = ("invariant", "control", "test", "telemetry", "incident_action")
    complete = sum(all(getattr(t, field) for field in required) for t in threats)
    return {"total": len(threats), "complete": complete, "coverage_percent": round(100 * complete / len(threats))}


def residual_risk(threat: Threat, control_operational: bool) -> str:
    if not control_operational:
        return "high: control is missing or unverified"
    if threat.stride in {"Information disclosure", "Elevation of privilege"}:
        return "medium: verify continuously and retain containment evidence"
    return "low: review after material changes"


def main() -> None:
    result = coverage(THREATS)
    assert result == {"total": 4, "complete": 4, "coverage_percent": 100}
    assert residual_risk(THREATS[2], True).startswith("medium")
    assert residual_risk(THREATS[0], False).startswith("high")
    print("PASS: every threat maps to an invariant, control, test, telemetry, and incident action")
    print(result)


if __name__ == "__main__":
    main()
