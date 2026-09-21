"""Course 08: offline authority-narrowing and confused-deputy exercise."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Grant:
    subject: str; tenant: str; audience: str; actions: frozenset[str]; purpose: str; expires: int; depth: int; max_depth: int

def exchange(parent: Grant, *, audience: str, actions: set[str], tenant: str, purpose: str, now: int, ttl: int) -> Grant:
    if parent.depth >= parent.max_depth: raise ValueError("delegation depth exceeded")
    if audience != "mcp://support" or tenant != parent.tenant: raise ValueError("audience or tenant escalation")
    if not set(actions) <= parent.actions: raise ValueError("scope escalation")
    if purpose != parent.purpose or now + ttl > parent.expires: raise ValueError("purpose or lifetime escalation")
    return Grant(parent.subject,tenant,audience,frozenset(actions),purpose,now+ttl,parent.depth+1,parent.max_depth)

def authorize_downstream(g: Grant, ticket_id: str, action: str, now: int) -> tuple[bool,str]:
    if g.audience != "mcp://support" or now >= g.expires: return False,"invalid target or expired grant"
    if not ticket_id.startswith(g.tenant+"-") or action not in g.actions: return False,"caller-bound resource/action denied"
    return True,"delegated authority is narrow and valid"

def main() -> None:
    user=Grant("user:acme:42","acme","host://support",frozenset({"ticket.read"}),"support",100,0,1)
    child=exchange(user,audience="mcp://support",actions={"ticket.read"},tenant="acme",purpose="support",now=10,ttl=30)
    assert authorize_downstream(child,"acme-7","ticket.read",20)[0]
    assert not authorize_downstream(child,"other-7","ticket.read",20)[0]
    try: exchange(user,audience="mcp://support",actions={"ticket.draft_reply"},tenant="acme",purpose="support",now=10,ttl=30)
    except ValueError: pass
    else: raise AssertionError("scope escalation accepted")
    print("PASS: delegation intersects authority and blocks cross-tenant confused-deputy use")
if __name__ == "__main__": main()
