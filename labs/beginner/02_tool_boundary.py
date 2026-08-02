def authorize(name,args,tenant):
    if name!='ticket.read': return False,'tool not allowed'
    if set(args)!= {'ticket_id'} or not isinstance(args['ticket_id'],str): return False,'invalid schema'
    if not args['ticket_id'].startswith(tenant+'-'): return False,'tenant boundary'
    return True,'allowed'
if __name__=='__main__':
    assert authorize('ticket.read',{'ticket_id':'acme-7'},'acme')[0] and not authorize('shell.exec',{'command':'cat .env'},'acme')[0] and not authorize('ticket.read',{'ticket_id':'other-7'},'acme')[0]; print('PASS: tool boundary')
