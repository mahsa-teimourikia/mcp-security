"""Course 21: containment preserves scoped trace evidence."""
from __future__ import annotations
def contain(events:list[dict[str,str]], server:str, revoked:set[str])->list[dict[str,str]]:
    revoked.add(server)
    return [e for e in events if e['server']==server]
def main()->None:
    events=[{'server':'support-v2','trace':'tr-1','digest':'sha256:bad','destination':'evil.example'},{'server':'support-v1','trace':'tr-2','digest':'sha256:good','destination':'tickets.example.com'}]
    revoked=set(); affected=contain(events,'support-v2',revoked)
    assert revoked=={'support-v2'} and affected==[events[0]]
    print('PASS: containment revokes the server and preserves affected forensic evidence')
if __name__=='__main__':main()
