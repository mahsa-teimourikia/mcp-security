"""Credential-free runtime risk gate for MCP tool calls."""
from dataclasses import dataclass
@dataclass(frozen=True)
class Event: tool:str; destination:str; denied_count:int; output_has_instruction:bool; digest_known:bool
def assess(e):
    if not e.digest_known:return 'quarantine','unknown artifact'
    if not e.destination.endswith('.example.com'):return 'block','unapproved destination'
    if e.output_has_instruction:return 'review','untrusted output instruction'
    if e.denied_count>=3:return 'review','repeated denials'
    return 'allow','baseline behavior'
if __name__=='__main__':
    assert assess(Event('ticket.read','api.example.com',0,False,True))[0]=='allow'
    assert assess(Event('ticket.read','evil.example',0,False,True))[0]=='block'
    assert assess(Event('ticket.read','api.example.com',0,True,True))[0]=='review'
    print('PASS: runtime policy detects destination, output, and artifact risk')
