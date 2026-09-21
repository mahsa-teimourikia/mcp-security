"""Contain a runtime anomaly and preserve affected trace IDs."""
def contain(events,server,revoked):
    revoked.add(server)
    return [e for e in events if e['server']==server]
if __name__=='__main__':
    events=[{'server':'mcp://v2','trace':'tr-1','destination':'evil.example'},{'server':'mcp://v1','trace':'tr-2','destination':'api.example.com'}]
    revoked=set(); affected=contain(events,'mcp://v2',revoked)
    assert revoked=={'mcp://v2'} and [e['trace'] for e in affected]==['tr-1']
    print('PASS: containment revokes server and preserves affected traces')
