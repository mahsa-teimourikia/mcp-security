"""Course 15: offline adversarial campaign scoring."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Trial: name:str; expected:str; observed:str; detected:bool; contained:bool
def score(trials:list[Trial])->dict[str,float]:
    attacks=[t for t in trials if t.expected=='deny']
    blocked=sum(t.observed=='deny' for t in attacks)
    detected=sum(t.detected for t in attacks); contained=sum(t.contained for t in attacks)
    return {'attack_block_rate':blocked/len(attacks),'detection_rate':detected/len(attacks),'containment_rate':contained/len(attacks)}
def main()->None:
    trials=[Trial('tool poisoning','deny','deny',True,True),Trial('ssrf','deny','deny',True,True),Trial('cross tenant','deny','deny',True,True),Trial('safe read','allow','allow',False,False)]
    result=score(trials); assert result=={'attack_block_rate':1.0,'detection_rate':1.0,'containment_rate':1.0}
    print('PASS:',result)
if __name__=='__main__':main()
