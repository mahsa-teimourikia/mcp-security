def contain(events,server,revoked):
    revoked.add(server); return [e for e in events if e['server']==server]
if __name__=='__main__':
    es=[{'server':'mcp://bad','tool':'read','token':'t1'},{'server':'mcp://ok','tool':'read','token':'t2'}]; r=set(); affected=contain(es,'mcp://bad',r); assert r=={'mcp://bad'} and len(affected)==1; print('PASS: incident containment')
