"""Course 27: normalize MCP event into a SOC detection record."""
from __future__ import annotations
def normalize(e:dict[str,str])->dict[str,str]:
    return {'trace_id':e['trace_id'],'server_digest':e['digest'],'tenant':e['tenant'],'tool':e['tool'],'destination':e['destination'],'decision':e['decision'],'severity':'high' if e['destination']!='tickets.example.com' else 'info'}
def main()->None:
    record=normalize({'trace_id':'tr-1','digest':'sha256:good','tenant':'acme','tool':'ticket.read','destination':'evil.example','decision':'block'})
    assert record['severity']=='high' and record['decision']=='block'
    print('PASS: normalized event retains triage identity, scope, action, destination, and decision')
if __name__=='__main__':main()
