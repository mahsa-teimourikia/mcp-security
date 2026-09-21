"""Credential-free capstone policy for a tenant-scoped support MCP server."""
from dataclasses import dataclass
@dataclass(frozen=True)
class Call: tool:str; tenant:str; ticket_id:str; approved:bool=False
def authorize(c):
    if c.tool not in {'ticket.read','ticket.draft_reply'}: return False,'tool not approved'
    if not c.ticket_id.startswith(c.tenant+'-'): return False,'cross-tenant ticket'
    if c.tool=='ticket.draft_reply' and not c.approved: return False,'approval required'
    return True,'allowed'
if __name__=='__main__':
    assert authorize(Call('ticket.read','acme','acme-7'))[0]
    assert not authorize(Call('shell.exec','acme','acme-7'))[0]
    assert not authorize(Call('ticket.read','acme','other-7'))[0]
    assert not authorize(Call('ticket.draft_reply','acme','acme-7'))[0]
    assert authorize(Call('ticket.draft_reply','acme','acme-7',True))[0]
    print('PASS: capstone policy gates tools, tenant, and approval')
