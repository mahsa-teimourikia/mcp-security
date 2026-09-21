import json
from pathlib import Path


def main():
    root=Path(__file__).parents[1]
    files=[]
    for track in ('beginner', 'intermediate', 'advanced'):
        files.extend(sorted((root/'curriculum'/track).glob('*/*.ipynb')))
    assert files, 'no notebooks found'
    for p in files:
        d=json.loads(p.read_text()); assert d.get('nbformat')==4 and d.get('cells'), f'invalid notebook: {p}'
        assert all(c.get('id') for c in d['cells']), f'missing stable cell id: {p}'
        text='\n'.join(''.join(c.get('source',[])) for c in d['cells'])
        assert 'Reflection' in text and 'runpy' in text, f'missing reflection or reusable lab import: {p}'
        topic=p.parent
        assert (topic/'README.md').exists(), f'missing chapter: {topic}'
        assert (topic/'lab.py').exists(), f'missing reusable lab: {topic}'
        print('validated',p)
if __name__=='__main__': main()
