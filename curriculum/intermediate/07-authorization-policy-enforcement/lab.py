"""Course 07: deterministic authorization decision point."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Request:
    principal: str; action: str; resource: str; tenant: str; purpose: str; risk: str; approved: bool=False

def decide(r: Request) -> tuple[str,str]:
    if not r.principal.startswith(f"user:{r.tenant}:"): return "DENY", "principal tenant mismatch"
    if not r.resource.startswith(f"{r.tenant}-"): return "DENY", "resource tenant mismatch"
    if r.action not in {"ticket.read","ticket.draft_reply"}: return "DENY", "action not allowed"
    if r.purpose != "support": return "DENY", "purpose not allowed"
    if r.action == "ticket.draft_reply" and (r.risk != "moderate" or not r.approved): return "DENY", "approval required"
    return "ALLOW", "policy invariant satisfied"

def main() -> None:
    base=Request("user:acme:42","ticket.read","acme-7","acme","support","low")
    assert decide(base)[0] == "ALLOW"
    assert decide(Request("user:acme:42","ticket.read","other-7","acme","support","low"))[0] == "DENY"
    assert decide(Request("user:acme:42","ticket.draft_reply","acme-7","acme","support","moderate"))[0] == "DENY"
    assert decide(Request("user:acme:42","ticket.draft_reply","acme-7","acme","support","moderate",True))[0] == "ALLOW"
    print("PASS: policy—not model selection—authorizes principal, action, resource, tenant, purpose, risk, and approval")
if __name__ == "__main__": main()
