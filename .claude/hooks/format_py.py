#!/usr/bin/env python3
"""Dev hook (PostToolUse on Edit/Write): format and lint the Python file just written.

Remaining lint errors are sent back to the agent (exit 2 → stderr goes to Claude),
so it fixes them in the same turn instead of leaving them for later.
"""

import json
import os
import shutil
import subprocess
import sys


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0

    path = (data.get("tool_input") or {}).get("file_path", "")
    if not path.endswith(".py") or not os.path.exists(path) or not shutil.which("uv"):
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or "."
    run = lambda *args: subprocess.run(  # noqa: E731
        ["uv", "run", "ruff", *args, path], cwd=cwd, capture_output=True, text=True, timeout=50
    )
    try:
        run("format")
        run("check", "--fix")
        result = run("check")
    except Exception:
        return 0

    if result.returncode != 0:
        print(f"ruff found issues in {path}:\n{result.stdout[-3000:]}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
