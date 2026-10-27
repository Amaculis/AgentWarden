"""Shared helpers for invoking the hook scripts as real subprocesses.

Not a test module itself (no `test_` prefix) — pytest will not collect it.
"""

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ON_TOOL = REPO_ROOT / "hooks" / "on_tool.py"
ON_PROMPT = REPO_ROOT / "hooks" / "on_prompt.py"

# A closed loopback port: nothing listens here, so any attempt to connect
# fails fast with "connection refused". Used as the default WARDEN_URL for
# every hook subprocess test, so a legacy test can never accidentally reach
# a developer's real daemon on 8765.
CLOSED_PORT_URL = "http://127.0.0.1:1"

SAMPLE_PRE_TOOL_USE = {
    "session_id": "abc123",
    "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
    "transcript_path": "/home/user/.claude/projects/x/transcript.jsonl",
    "cwd": "/home/user/my-project",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "npm test", "description": "Run test suite"},
    "tool_use_id": "toolu_01ABC123",
}

SAMPLE_USER_PROMPT_SUBMIT = {
    "session_id": "abc123",
    "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
    "transcript_path": "/home/user/.claude/projects/x/transcript.jsonl",
    "cwd": "/home/user/my-project",
    "permission_mode": "default",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "fix the failing login test",
}


def run_hook(
    script: Path,
    stdin_text: str,
    home: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess:
    """Run a hook script as a real subprocess with AGENTWARDEN_HOME set to `home`.

    `WARDEN_URL` defaults to a closed loopback port (see CLOSED_PORT_URL) so
    that no test can accidentally reach a real daemon. Pass `env` to point
    the hook at a stub daemon (or to override any other variable); entries
    in `env` take precedence over this default.
    """
    merged = os.environ.copy()
    merged["AGENTWARDEN_HOME"] = str(home)
    merged["WARDEN_URL"] = CLOSED_PORT_URL
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=merged,
        timeout=timeout,
    )
