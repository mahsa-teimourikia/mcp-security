"""Course 26: supplier/server risk-tier decision fixture."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Supplier: name:str; provenance:bool; sbom:bool; vuln_sla:bool; owner:str; critical:bool
def tier(s:Supplier)->tuple[str,str]:
    if not all((s.provenance,s.sbom,s.vuln_sla,s.owner)):return 'BLOCK','minimum supplier evidence missing'
    return ('HIGH_REVIEW' if s.critical else 'APPROVE'),'risk tier assigned'
def main()->None:
    assert tier(Supplier('support-sdk',True,True,True,'platform',False))[0]=='APPROVE'
    assert tier(Supplier('connector',True,True,True,'platform',True))[0]=='HIGH_REVIEW'
    assert tier(Supplier('unknown',False,False,False,'',False))[0]=='BLOCK'
    print('PASS: supply-chain intake requires evidence and risk-tier review')
if __name__=='__main__':main()
