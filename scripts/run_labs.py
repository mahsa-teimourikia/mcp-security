"""Execute every canonical credential-free lab with a bounded timeout."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def main() -> None:
    labs = []
    for track in ("beginner", "intermediate", "advanced"):
        labs.extend(sorted((ROOT / "curriculum" / track).glob("*/lab.py")))
    if len(labs) != 29:
        raise SystemExit(f"expected 29 canonical labs, found {len(labs)}")

    failures = []
    for lab in labs:
        result = subprocess.run(
            [sys.executable, str(lab)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
        relative = lab.relative_to(ROOT)
        if result.returncode:
            failures.append(f"{relative}\n{result.stdout}{result.stderr}")
        else:
            print(f"PASS {relative}")
    if failures:
        raise SystemExit("\n\n".join(failures))


if __name__ == "__main__":
    main()
