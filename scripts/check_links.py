"""Check local Markdown targets and required Hub/quiz assets."""
import re
from pathlib import Path
ROOT=Path(__file__).parents[1]
def main():
    missing=[]
    for path in [ROOT/'README.md',* (ROOT/'docs').glob('*.md')]:
        for target in re.findall(r'\]\(([^)#]+)',path.read_text()):
            if target.startswith(('http://','https://')): continue
            target=(path.parent/target).resolve()
            if not target.exists(): missing.append(f'{path}:{target}')
    for required in ['hub/index.html','hub/app.js','quiz/index.html','quiz/questions.js','assets/one-plus-i.png']:
        if not (ROOT/required).exists(): missing.append(required)
    if missing: raise SystemExit('\n'.join(missing))
    print('PASS: local links and Pages assets')
if __name__=='__main__': main()
