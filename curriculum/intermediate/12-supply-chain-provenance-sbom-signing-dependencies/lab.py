"""Course 12: deterministic artifact-evidence release gate."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Artifact:
    digest:str; signer:str; sbom_digest:str; vulnerabilities:tuple[str,...]; provenance_builder:str
def release(a:Artifact, approved:set[str], builders:set[str]) -> tuple[bool,str]:
    if a.digest not in approved:return False,'digest is not approved'
    if not a.signer:return False,'signature evidence missing'
    if not a.sbom_digest:return False,'SBOM evidence missing'
    if a.provenance_builder not in builders:return False,'untrusted provenance builder'
    if a.vulnerabilities:return False,'unresolved vulnerabilities require remediation or exception'
    return True,'artifact evidence gate passed'
def main()->None:
    good=Artifact('sha256:good','sigstore:team','sha256:sbom',(), 'ci://trusted')
    assert release(good,{'sha256:good'},{'ci://trusted'})[0]
    assert not release(Artifact('sha256:good','','sha256:sbom',(),'ci://trusted'),{'sha256:good'},{'ci://trusted'})[0]
    assert not release(Artifact('sha256:good','sig','sha256:sbom',('CVE-demo',),'ci://trusted'),{'sha256:good'},{'ci://trusted'})[0]
    print('PASS: release needs approved digest, signature, SBOM, trusted provenance, and resolved findings')
if __name__=='__main__':main()
