import json
from pathlib import Path
def main():
    files=sorted(Path('labs/notebooks').glob('*.ipynb')); assert files
    for p in files:
        d=json.loads(p.read_text()); assert d.get('nbformat')==4 and d.get('cells')
        text='\n'.join(''.join(c.get('source',[])) for c in d['cells']); assert 'Reflection' in text and 'runpy' in text
        print('validated',p)
if __name__=='__main__': main()
