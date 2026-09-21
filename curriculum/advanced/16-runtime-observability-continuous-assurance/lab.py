"""Course 16: trace-to-risk decision fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Event:
    trace_id:str; digest:str; tool:str; destination:str; denied:int; untrusted_instruction:bool
def assess(e:Event)->tuple[str,str]:
    if e.digest!='sha256:reviewed':return 'QUARANTINE','artifact drift'
    if e.destination!='tickets.example.com':return 'BLOCK','unapproved destination'
    if e.untrusted_instruction or e.denied>=3:return 'REVIEW','content risk or repeated denial'
    return 'ALLOW','baseline behavior'
def main()->None:
    assert assess(Event('t1','sha256:reviewed','ticket.read','tickets.example.com',0,False))[0]=='ALLOW'
    assert assess(Event('t2','sha256:unknown','ticket.read','tickets.example.com',0,False))[0]=='QUARANTINE'
    assert assess(Event('t3','sha256:reviewed','ticket.read','evil.example',0,False))[0]=='BLOCK'
    print('PASS: traces turn artifact, destination, content, and denial drift into bounded decisions')
if __name__=='__main__':main()
