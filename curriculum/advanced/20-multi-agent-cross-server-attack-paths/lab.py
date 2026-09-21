"""Course 20: bounded attack-graph reachability fixture."""
from __future__ import annotations
GRAPH={'host':{'support'},'support':{'ticket-api'},'rogue':{'host','secret-api'},'ticket-api':set(),'secret-api':set()}
def reachable(start:str, blocked:set[str])->set[str]:
    seen={start}; frontier=[start]
    while frontier:
        for nxt in GRAPH.get(frontier.pop(),set())-blocked-seen: seen.add(nxt);frontier.append(nxt)
    return seen
def main()->None:
    assert reachable('host',set())=={'host','support','ticket-api'}
    assert 'secret-api' not in reachable('host',{'rogue'})
    assert reachable('rogue',{'host'})=={'rogue','secret-api'}
    print('PASS: attack graph makes lateral paths and containment boundaries explicit')
if __name__=='__main__':main()
