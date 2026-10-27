#!/usr/bin/env python3
"""Dev hook (PreToolUse on Edit/Write): ask the human before an agent edits core files.

Core files are the judge prompt and the labelled eval set. An agent changing them
silently would make the metrics meaningless.
"""

import json
import sys

PROTECTED = ("prompts/", "eval/cases/", "eval/content/")


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # no decision; normal permission flow applies

    path = str((data.get("tool_input") or {}).get("file_path", "")).replace("\\", "/")
    if any(f"/{p}" in path or path.startswith(p) for p in PROTECTED):
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": (
                            f"{path} is a protected core file (judge prompt or labelled "
                            "eval set). Confirm this edit was explicitly requested."
                        ),
                    }
                }
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
