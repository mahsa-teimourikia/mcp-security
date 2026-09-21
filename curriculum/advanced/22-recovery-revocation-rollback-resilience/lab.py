"""Course 22: recovery decision and revocation propagation fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Recovery: compromised:str; known_good:str; registry_revoked:bool; sessions_closed:bool; grants_revoked:bool; verified:bool
def recover(r:Recovery)->tuple[bool,str]:
    if not all((r.registry_revoked,r.sessions_closed,r.grants_revoked)):return False,'revocation has not propagated'
    if not r.known_good.startswith('sha256:') or not r.verified:return False,'known-good artifact is not verified'
    return True,f'rollback from {r.compromised} to {r.known_good} approved'
def main()->None:
    assert recover(Recovery('sha256:bad','sha256:good',True,True,True,True))[0]
    assert not recover(Recovery('sha256:bad','sha256:good',True,False,True,True))[0]
    print('PASS: recovery requires propagated revocation and verified known-good rollback')
if __name__=='__main__':main()
