"""Course 13: deterministic promotion gate with rollback readiness."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Evidence:
    tests:bool; provenance:bool; sbom:bool; scan_clean:bool; policy:bool; rollback_digest:str|None
def promote(e:Evidence)->tuple[bool,str]:
    if not all((e.tests,e.provenance,e.sbom,e.scan_clean,e.policy)):return False,'required release evidence is incomplete'
    if not e.rollback_digest:return False,'known-good rollback digest is required'
    return True,'promotion approved with rollback readiness'
def main()->None:
    assert promote(Evidence(True,True,True,True,True,'sha256:known-good'))[0]
    assert not promote(Evidence(True,True,True,False,True,'sha256:known-good'))[0]
    assert not promote(Evidence(True,True,True,True,True,None))[0]
    print('PASS: promotion requires tests, provenance, SBOM, scan, policy, and rollback evidence')
if __name__=='__main__':main()
