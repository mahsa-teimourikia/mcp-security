"""Course 19: composition-invariant fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Envelope: protocol:str; subject:str; tenant:str; action:str; audience:str; trace:str
def bridge(e:Envelope,to:str)->tuple[bool,str]:
    if not all((e.subject,e.tenant,e.action,e.audience,e.trace)):return False,'security context incomplete'
    if e.protocol=='A2A' and to=='MCP' and e.audience!='mcp://support':return False,'audience lost at adapter'
    if e.action not in {'ticket.read','ticket.triage'}:return False,'adapter cannot broaden action'
    return True,'composition invariant preserved'
def main()->None:
    assert bridge(Envelope('A2A','user:acme:42','acme','ticket.read','mcp://support','tr-1'),'MCP')[0]
    assert not bridge(Envelope('A2A','user:acme:42','acme','ticket.read','host://x','tr-1'),'MCP')[0]
    print('PASS: protocol adapter preserves bounded security context')
if __name__=='__main__':main()
