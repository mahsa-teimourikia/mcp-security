"""Course 17: offline registry onboarding and revocation policy."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Entry: server_id:str; owner:str; digest:str; capabilities:frozenset[str]; reviewed:bool; revoked:bool
def admit(e:Entry)->tuple[bool,str]:
    if e.revoked:return False,'registry entry revoked'
    if not e.reviewed or not e.owner:return False,'owner or review missing'
    if not e.digest.startswith('sha256:'):return False,'immutable digest required'
    if e.capabilities-{'ticket.read','ticket.list_open','ticket.draft_reply'}:return False,'capability set not approved'
    return True,'registry trust record approved'
def main()->None:
    good=Entry('support','platform','sha256:good',frozenset({'ticket.read'}),True,False)
    assert admit(good)[0]
    assert not admit(Entry('rogue','', 'latest',frozenset({'read_file'}),False,False))[0]
    assert not admit(Entry('support','platform','sha256:good',frozenset({'ticket.read'}),True,True))[0]
    print('PASS: registry admits only reviewed immutable approved servers and enforces revocation')
if __name__=='__main__':main()
