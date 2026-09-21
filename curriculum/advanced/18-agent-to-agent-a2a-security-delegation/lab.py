"""Course 18: offline peer/task authorization contract."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Task: sender:str; recipient:str; tenant:str; action:str; expires:int; parent_trace:str
def accept(t:Task, now:int, peers:set[str])->tuple[bool,str]:
    if t.sender not in peers or t.recipient not in peers:return False,'untrusted peer'
    if t.expires<=now:return False,'task expired'
    if t.action not in {'ticket.read','ticket.triage'}:return False,'task action not delegated'
    if not t.parent_trace:return False,'missing trace linkage'
    return True,'peer and bounded task accepted'
def main()->None:
    good=Task('triage-agent','support-agent','acme','ticket.read',100,'tr-1')
    assert accept(good,10,{'triage-agent','support-agent'})[0]
    assert not accept(Task('rogue','support-agent','acme','ticket.read',100,'tr-1'),10,{'triage-agent','support-agent'})[0]
    assert not accept(Task('triage-agent','support-agent','acme','ticket.draft_reply',100,'tr-1'),10,{'triage-agent','support-agent'})[0]
    print('PASS: A2A handoff verifies peer, expiry, task scope, and trace linkage')
if __name__=='__main__':main()
