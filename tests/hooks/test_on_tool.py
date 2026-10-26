"""Subprocess tests for hooks/on_tool.py (PreToolUse).

Runs the script as a real `python hooks/on_tool.py` process (not an in-process
import/call) so exit code and stdout are genuinely checked — this is what
Claude Code actually does.

hooks/on_tool.py does not exist yet. These tests are expected to fail (e.g.
FileNotFoundError from subprocess, or non-zero exit) until spec 001 ships.
"""

import json

from ._support import ON_TOOL, SAMPLE_PRE_TOOL_USE, run_hook


def test_on_tool_appends_event(tmp_path):
    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path)

    assert result.returncode == 0
    events_file = tmp_path / "events.jsonl"
    assert events_file.exists()
    lines = events_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["hook_event_name"] == "PreToolUse"
    assert record["tool_name"] == "Bash"
    assert record["tool_input"] == SAMPLE_PRE_TOOL_USE["tool_input"]
    assert "received_at" in record


def test_on_tool_makes_no_decision(tmp_path):
    # Spec 001 is out of scope for decisions: on_tool.py must print nothing
    # (not even a `{"hookSpecificOutput": ...}` passthrough) so the normal
    # Claude Code permission flow continues untouched.
    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path)

    assert result.stdout == ""
    assert result.returncode == 0


def test_invalid_json_is_ignored(tmp_path):
    result = run_hook(ON_TOOL, "not valid json {{{", tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert not (tmp_path / "events.jsonl").exists()


def test_unwritable_output_dir_exits_zero(tmp_path):
    blocker = tmp_path / "blocker_file"
    blocker.write_text("file blocking directory creation", encoding="utf-8")
    unwritable_home = blocker / "subdir"

    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), unwritable_home)

    assert result.returncode == 0
    assert result.stdout == ""
