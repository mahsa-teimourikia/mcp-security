from dataclasses import dataclass
@dataclass(frozen=True)
class Grant: audience:str; actions:frozenset; expires:int; depth:int; max_depth:int
def delegate(p,audience,actions,now,ttl):
    if p.depth>=p.max_depth or not actions<=p.actions or now+ttl>p.expires: raise ValueError('delegation exceeds parent')
    return Grant(audience,frozenset(actions),now+ttl,p.depth+1,p.max_depth)
if __name__=='__main__':
    p=Grant('orchestrator',frozenset({'read'}),100,0,1); c=delegate(p,'mcp-server',{'read'},10,30); assert c.expires==40
    try: delegate(p,'mcp-server',{'write'},10,30)
    except ValueError: pass
    else: raise AssertionError('escalation accepted')
    print('PASS: delegation contract')
