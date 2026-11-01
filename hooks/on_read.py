#!/usr/bin/env python3
"""PostToolUse command hook for Read/WebFetch — injection scanner (spec 013).

Sends the tool result to the daemon's `/scan` and, if the content was flagged, prints a
factual `additionalContext` note for the agent. PostToolUse cannot block (the read already
happened), so every failure prints nothing and exits 0 -- never an "all clear". The payload
is not appended to events.jsonl: the content the agent read must not be stored.
"""

import contextlib
import json
import os
import sys

SCAN_DEADLINE_S = 21.0
MAX_WARNING = 400


def build_output(status: int, body: bytes, formatter=None) -> str | None:
    """The hook's stdout for a daemon response, or `None` to print nothing.

    `formatter`: hooks/formats/<agent>.py (spec 027); its `scan_output` replaces the Claude
    Code schema."""
    if status != 200:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    warning = data.get("warning")
    if not isinstance(warning, str) or not warning.strip():
        return None
    if formatter is not None:
        out = formatter.scan_output(warning[:MAX_WARNING])
        return out if isinstance(out, str) else None
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": warning[:MAX_WARNING],
        }
    }
    return json.dumps(output, ensure_ascii=True)


def run(stdin_bytes: bytes, agent: str | None = "claude_code") -> str | None:
    import on_tool  # same directory; loopback-only URL check and deadline-bounded transport

    if agent is None or not on_tool.AGENT_RE.match(agent):
        return None
    formatter = on_tool.load_formatter(agent)
    try:
        event = json.loads(stdin_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    # Some agents send no event name (Copilot CLI); the daemon's adapter supplies it (spec 027).
    if not isinstance(event, dict) or event.get("hook_event_name", "PostToolUse") != "PostToolUse":
        return None
    url = on_tool.decide_url()
    if url is None:
        return None
    url = url[: -len("/decide")] + "/scan"
    deadline = min(on_tool.hook_timeout_seconds(), SCAN_DEADLINE_S)
    response = on_tool.call_daemon(url, stdin_bytes, deadline, {on_tool.AGENT_HEADER: agent})
    if response is None:
        return None
    return build_output(*response, formatter)


def main() -> None:
    import on_tool

    output = run(sys.stdin.buffer.read(), on_tool.parse_agent(sys.argv[1:]))
    if output:
        sys.stdout.write(output)
        sys.stdout.flush()


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        main()
    # os._exit: do not wait on a worker thread still stuck in a slow socket read.
    os._exit(0)
