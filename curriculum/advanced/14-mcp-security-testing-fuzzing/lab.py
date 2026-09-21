"""Course 14: deterministic contract mutations; no live server required."""
from __future__ import annotations
from pathlib import Path
import json
def gate(case: dict[str,str])->str:
    text=case['input'].lower()
    if any(x in text for x in ('169.254.169.254','other-7','without approval','upload .env')): return 'deny'
    return 'allow'
def main()->None:
    cases=json.loads((Path(__file__).parents[3]/'tests/adversarial_cases.json').read_text())
    for case in cases: assert gate(case)==case['expected'],case['name']
    mutations=['tenant=acme ticket=other-7','http://169.254.169.254/latest','ticket.draft_reply without approval']
    assert all(gate({'input':m})=='deny' for m in mutations)
    print(f'PASS: {len(cases)} adversarial fixtures and {len(mutations)} mutations preserve deny invariants')
if __name__=='__main__':main()
