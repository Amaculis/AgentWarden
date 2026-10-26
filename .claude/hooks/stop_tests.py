#!/usr/bin/env python3
"""Dev hook (Stop): run fast tests before the agent is allowed to finish.

If tests fail, exit 2 sends the failure back to the agent and it keeps working.
`stop_hook_active` prevents an endless loop: on the second stop we let it finish.
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
    if data.get("stop_hook_active"):
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or "."
    if not os.path.isdir(os.path.join(cwd, "tests")) or not shutil.which("uv"):
        return 0

    try:
        result = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x", "-m", "not slow", "--no-header"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=170,
        )
    except Exception:
        return 0

    # 0 = passed, 5 = no tests collected yet
    if result.returncode in (0, 5):
        return 0

    print(
        "Fast tests are failing. Fix them before finishing:\n" + result.stdout[-4000:],
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
