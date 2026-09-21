"""Execute canonical notebooks in their lesson directories without saving output."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import nbformat
from nbclient import NotebookClient


ROOT = Path(__file__).parents[1]


def discover(track: str | None) -> list[Path]:
    tracks = (track,) if track else ("beginner", "intermediate", "advanced")
    notebooks = []
    for name in tracks:
        notebooks.extend(sorted((ROOT / "curriculum" / name).glob("*/*.ipynb")))
    return notebooks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--track", choices=("beginner", "intermediate", "advanced"))
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    notebooks = discover(args.track)
    if not notebooks:
        raise SystemExit("no canonical notebooks found")
    with tempfile.TemporaryDirectory(prefix="mcp-security-kernel-") as temporary:
        kernel = Path(temporary) / "kernels" / "mcp-security-course"
        kernel.mkdir(parents=True)
        (kernel / "kernel.json").write_text(json.dumps({
            "argv": [sys.executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"],
            "display_name": "MCP Security Course",
            "language": "python",
        }))
        previous_path = os.environ.get("JUPYTER_PATH")
        os.environ["JUPYTER_PATH"] = temporary + (os.pathsep + previous_path if previous_path else "")

        for path in notebooks:
            notebook = nbformat.read(path, as_version=4)
            client = NotebookClient(
                notebook,
                timeout=args.timeout,
                kernel_name="mcp-security-course",
                resources={"metadata": {"path": str(path.parent)}},
            )
            client.execute()
            print(f"PASS {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
