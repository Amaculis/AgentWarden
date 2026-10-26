#!/usr/bin/env python3
"""PreToolUse command hook — records the event, makes no decision.

Spec 001: no decisions yet. Always exit 0, print nothing, swallow every
error so a broken environment never blocks the tool call.
"""

import contextlib
import sys


def main() -> None:
    try:
        import _common
    except Exception:
        return
    try:
        raw = sys.stdin.read()
        event = _common.read_stdin_json(raw)
        if event is None:
            return
        _common.append_event(event)
    except Exception:
        pass


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        main()
    sys.exit(0)
