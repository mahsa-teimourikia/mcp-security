"""Course 29: architecture review rubric fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Review: threats:bool; identity:bool; policy:bool; provenance:bool; isolation:bool; telemetry:bool; recovery:bool; owner:str
def assess(r:Review)->tuple[bool,list[str]]:
    gaps=[k for k,v in r.__dict__.items() if k!='owner' and not v]
    if not r.owner:gaps.append('owner')
    return not gaps,gaps
def main()->None:
    assert assess(Review(True,True,True,True,True,True,True,'platform'))[0]
    assert 'recovery' in assess(Review(True,True,True,True,True,True,False,'platform'))[1]
    print('PASS: architecture workshop identifies evidence and ownership gaps')
if __name__=='__main__':main()
