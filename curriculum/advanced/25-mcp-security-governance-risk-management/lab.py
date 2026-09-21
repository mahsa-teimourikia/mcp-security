"""Course 25: risk acceptance decision record fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Risk: id:str; owner:str; control_tested:bool; residual:str; exception_expiry:int|None
def accept(r:Risk,now:int)->tuple[bool,str]:
    if not r.owner or not r.control_tested:return False,'owner or control evidence missing'
    if r.residual=='high' and (r.exception_expiry is None or r.exception_expiry<=now):return False,'high residual risk needs active exception'
    return True,'risk decision recorded'
def main()->None:
    assert accept(Risk('R-1','security',True,'medium',None),10)[0]
    assert not accept(Risk('R-2','security',True,'high',10),10)[0]
    print('PASS: risk acceptance needs ownership, tested control evidence, and active exceptions')
if __name__=='__main__':main()
