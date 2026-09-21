"""Course 23: architecture-review invariant fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Architecture: registry:bool; identity:bool; policy:bool; isolation:bool; observability:bool; revocation:bool; tenant_boundary:bool
def review(a:Architecture)->tuple[bool,list[str]]:
    gaps=[name for name,value in a.__dict__.items() if not value]
    return not gaps,gaps
def main()->None:
    assert review(Architecture(True,True,True,True,True,True,True))[0]
    assert 'tenant_boundary' in review(Architecture(True,True,True,True,True,True,False))[1]
    print('PASS: enterprise architecture review exposes missing security control planes')
if __name__=='__main__':main()
