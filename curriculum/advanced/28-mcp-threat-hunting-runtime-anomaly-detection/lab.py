"""Course 28: deterministic hunt over runtime event fixtures."""
from __future__ import annotations
def hunt(events:list[dict[str,str]])->list[dict[str,str]]:
    return [e for e in events if e['destination']!='tickets.example.com' or e['digest']!='sha256:reviewed' or e['denied_count']=='3']
def main()->None:
    events=[{'trace':'t1','destination':'tickets.example.com','digest':'sha256:reviewed','denied_count':'0'},{'trace':'t2','destination':'evil.example','digest':'sha256:reviewed','denied_count':'0'},{'trace':'t3','destination':'tickets.example.com','digest':'sha256:unknown','denied_count':'0'}]
    assert [e['trace'] for e in hunt(events)]==['t2','t3']
    print('PASS: hunt finds destination and artifact anomalies for triage')
if __name__=='__main__':main()
