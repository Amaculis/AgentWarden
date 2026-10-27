#!/usr/bin/env python3
"""UserPromptSubmit command hook — records the prompt as the session task, makes no decision.

Spec 001: append to `.agentwarden/events.jsonl`. Spec 011: also POST the event to the
daemon's `/event` (loopback only, short deadline) so the judge knows the session task.
Always exit 0, print nothing, swallow every error so a broken environment never blocks the
prompt.
"""

import contextlib
import os
import sys

EVENT_DEADLINE_S = 2.0


def _send_to_daemon(raw: str) -> None:
    import on_tool  # same directory; reuses the loopback-only URL check and transport

    url = on_tool.decide_url()
    if url is None:
        return
    url = url[: -len("/decide")] + "/event"
    deadline = min(on_tool.hook_timeout_seconds(), EVENT_DEADLINE_S)
    on_tool.call_daemon(url, raw.encode("utf-8"), deadline)


def main() -> None:
    try:
        import _common
    except Exception:
        return
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        event = _common.read_stdin_json(raw)
        if event is None:
            return
        _common.append_event(event)
    except Exception:
        return
    with contextlib.suppress(Exception):
        _send_to_daemon(raw)


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        main()
    sys.stdout.flush()
    # os._exit: do not wait on a worker thread still stuck in a slow socket read.
    os._exit(0)
