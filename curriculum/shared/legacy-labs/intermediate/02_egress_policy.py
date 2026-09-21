from urllib.parse import urlparse
ALLOWED={'api.example.com','tickets.example.com'}
def check(url):
    p=urlparse(url)
    if p.scheme!='https' or p.hostname not in ALLOWED:return False,'egress denied'
    return True,'allowed'
if __name__=='__main__':
    assert check('https://tickets.example.com/v1')[0] and not check('http://169.254.169.254/latest')[0] and not check('https://evil.example')[0]; print('PASS: egress policy')
