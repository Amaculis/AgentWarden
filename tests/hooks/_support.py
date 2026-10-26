"""Shared helpers for invoking the hook scripts as real subprocesses.

Not a test module itself (no `test_` prefix) — pytest will not collect it.
"""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ON_TOOL = REPO_ROOT / "hooks" / "on_tool.py"
ON_PROMPT = REPO_ROOT / "hooks" / "on_prompt.py"

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


def run_hook(script: Path, stdin_text: str, home: Path) -> subprocess.CompletedProcess:
    """Run a hook script as a real subprocess with AGENTWARDEN_HOME set to `home`."""
    env = os.environ.copy()
    env["AGENTWARDEN_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
