ALLOWED={'ticket.read','ticket.comment'}
def review(manifest):
    findings=[]
    for tool in manifest.get('tools',[]):
        name=tool['name']; schema=tool.get('inputSchema',{})
        if name not in ALLOWED: findings.append((name,'not approved'))
        if schema.get('properties',{}).get('url'): findings.append((name,'unrestricted URL'))
        if not schema.get('required'): findings.append((name,'missing required fields'))
    return findings
if __name__=='__main__':
    m={'tools':[{'name':'ticket.read','inputSchema':{'required':['id'],'properties':{'id':{'type':'string'}}}},{'name':'shell.exec','inputSchema':{'properties':{'command':{'type':'string'}}}}]}; f=review(m)
    assert ('shell.exec','not approved') in f and ('shell.exec','missing required fields') in f; print('PASS: manifest review')
