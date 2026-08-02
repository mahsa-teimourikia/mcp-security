def release(artifact,approved_digest,signature_ok,vulnerabilities):
    if artifact['digest']!=approved_digest:return False,'digest mismatch'
    if not signature_ok:return False,'signature invalid'
    if vulnerabilities:return False,'unresolved vulnerabilities'
    return True,'release approved'
if __name__=='__main__':
    a={'digest':'sha256:abc'}; assert release(a,'sha256:abc',True,[])[0] and not release(a,'sha256:def',True,[])[0] and not release(a,'sha256:abc',True,['CVE'])[0]; print('PASS: provenance gate')
