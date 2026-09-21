"""Course 24: workload identity lifecycle gate."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Identity: id:str; owner:str; audience:str; expires:int; scopes:frozenset[str]; revoked:bool
def valid(i:Identity,now:int)->tuple[bool,str]:
    if not i.owner or i.revoked:return False,'missing owner or revoked identity'
    if i.expires<=now:return False,'expired identity'
    if i.audience!='mcp://support' or not i.scopes<= {'ticket.read','ticket.triage'}:return False,'audience or scope violates least privilege'
    return True,'governed workload identity'
def main()->None:
    assert valid(Identity('spiffe://support','platform','mcp://support',100,frozenset({'ticket.read'}),False),10)[0]
    assert not valid(Identity('x','', 'mcp://support',100,frozenset({'ticket.read'}),False),10)[0]
    assert not valid(Identity('x','platform','mcp://support',100,frozenset({'admin'}),False),10)[0]
    print('PASS: workload identity requires owner, target, narrow scope, expiry, and revocation state')
if __name__=='__main__':main()
