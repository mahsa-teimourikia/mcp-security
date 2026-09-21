"""Course 09: deterministic sandbox policy fixture; does not launch a sandbox."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Attempt:
    path: str; executable: str; destination: str; env_keys: frozenset[str]

def assess(a: Attempt) -> tuple[str,str]:
    if not a.path.startswith('/workspace/read-only/'): return 'DENY','filesystem path outside read-only mount'
    if a.executable not in {'/app/support-worker'}: return 'DENY','process is not allow-listed'
    if a.destination not in {'https://tickets.example.com'}: return 'DENY','egress destination is not allow-listed'
    if a.env_keys - {'LOG_LEVEL','TENANT'}: return 'DENY','environment contains unapproved values'
    return 'ALLOW','sandbox policy invariant satisfied'

def main() -> None:
    safe=Attempt('/workspace/read-only/policy.txt','/app/support-worker','https://tickets.example.com',frozenset({'LOG_LEVEL','TENANT'}))
    assert assess(safe)[0]=='ALLOW'
    assert assess(Attempt('/etc/passwd','/app/support-worker','https://tickets.example.com',frozenset()))[0]=='DENY'
    assert assess(Attempt('/workspace/read-only/x','/bin/sh','https://tickets.example.com',frozenset()))[0]=='DENY'
    assert assess(Attempt('/workspace/read-only/x','/app/support-worker','https://evil.example',frozenset()))[0]=='DENY'
    print('PASS: isolation policy blocks filesystem, process, egress, and environment escape attempts')
if __name__ == '__main__': main()
