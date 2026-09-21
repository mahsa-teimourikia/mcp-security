"""Course 10: deterministic URL and filesystem policy fixture."""
from __future__ import annotations
from ipaddress import ip_address
from urllib.parse import urlparse

ALLOW = {"tickets.example.com", "docs.example.com"}
def check_url(url: str) -> tuple[bool,str]:
    p=urlparse(url)
    if p.scheme != "https" or not p.hostname: return False,"HTTPS destination required"
    try:
        if ip_address(p.hostname).is_private or ip_address(p.hostname).is_link_local: return False,"private/link-local address denied"
    except ValueError: pass
    if p.hostname not in ALLOW: return False,"host not allow-listed"
    return True,"approved logical destination; production must re-check redirects and resolved IP"
def check_path(path: str) -> tuple[bool,str]:
    if not path.startswith("/workspace/read-only/") or "/../" in path: return False,"path outside approved read-only root"
    return True,"approved path"
def main() -> None:
    assert check_url("https://tickets.example.com/v1")[0]
    assert not check_url("http://169.254.169.254/latest")[0]
    assert not check_url("https://evil.example")[0]
    assert not check_path("/workspace/read-only/../secret")[0]
    print("PASS: URL and path policy denies metadata, unapproved egress, and traversal")
if __name__ == "__main__": main()
