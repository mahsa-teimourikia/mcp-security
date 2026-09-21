"""Check local Markdown targets and required Learning Hub/quiz assets."""
import re
from pathlib import Path
ROOT=Path(__file__).parents[1]
def main():
    missing=[]
    markdown=[
        ROOT/'README.md', ROOT/'CONTRIBUTING.md', ROOT/'COURSE_MAP.md',
        ROOT/'LEARNING.md', ROOT/'ROADMAP.md', ROOT/'CURRICULUM_EVOLUTION_PLAN.md',
        *(ROOT/'docs').glob('*.md'), *(ROOT/'curriculum').glob('**/*.md'),
    ]
    for path in markdown:
        if not path.exists():
            missing.append(str(path.relative_to(ROOT)))
            continue
        for target in re.findall(r'\]\(([^)#]+)',path.read_text()):
            if target.startswith(('http://','https://')): continue
            target=(path.parent/target).resolve()
            if not target.exists(): missing.append(f'{path}:{target}')
    for required in [
        'app/index.html', 'app/page.tsx', 'app/package.json',
        'quiz/index.html', 'quiz/questions.mjs', 'quiz/grading.test.mjs',
        'assets/one-plus-i.png', 'COURSE_MAP.md', 'LEARNING.md', 'ROADMAP.md',
    ]:
        if not (ROOT/required).exists(): missing.append(required)
    if missing: raise SystemExit('\n'.join(missing))
    print(f'PASS: local links across {len(markdown)} Markdown files and required Pages assets')
if __name__=='__main__': main()
