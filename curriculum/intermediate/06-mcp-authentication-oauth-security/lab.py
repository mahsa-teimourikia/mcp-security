"""Course 06: offline token-validation model; not a JWT implementation."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Token:
    issuer: str; subject: str; audience: str; scopes: frozenset[str]; expires_at: int; token_id: str

def validate(token: Token, *, issuer: str, audience: str, required_scope: str, now: int, revoked: set[str]) -> tuple[bool, str]:
    if token.token_id in revoked: return False, "token revoked"
    if token.issuer != issuer: return False, "issuer mismatch"
    if token.audience != audience: return False, "audience mismatch"
    if token.expires_at <= now: return False, "token expired"
    if required_scope not in token.scopes: return False, "scope missing"
    return True, "validated issuer, audience, expiry, and scope"

def main() -> None:
    token=Token("https://id.example","user:acme","mcp://support",frozenset({"ticket.read"}),100,"t-1")
    assert validate(token,issuer="https://id.example",audience="mcp://support",required_scope="ticket.read",now=10,revoked=set())[0]
    assert not validate(token,issuer="https://id.example",audience="https://tickets.example",required_scope="ticket.read",now=10,revoked=set())[0]
    assert not validate(token,issuer="https://id.example",audience="mcp://support",required_scope="ticket.read",now=100,revoked=set())[0]
    assert not validate(token,issuer="https://id.example",audience="mcp://support",required_scope="ticket.read",now=10,revoked={"t-1"})[0]
    print("PASS: bearer tokens are rejected when issuer, audience, expiry, scope, or revocation fails")
if __name__ == "__main__": main()
