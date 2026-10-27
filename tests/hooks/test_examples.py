"""Checks for examples/settings.agentwarden*.json (spec 005: Windows file added).

examples/settings.agentwarden.windows.json does not exist yet. These tests
are expected to fail (missing file / assertion) until spec 005 ships it.
"""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POSIX_SETTINGS_FILE = REPO_ROOT / "examples" / "settings.agentwarden.json"
WINDOWS_SETTINGS_FILE = REPO_ROOT / "examples" / "settings.agentwarden.windows.json"

# The hook's own WARDEN_HOOK_TIMEOUT clamp maxes out at 10s (spec 005); the
# settings timeout must stay comfortably above that.
HOOK_TIMEOUT_CLAMP_MAX = 10


def test_example_settings_is_valid_json():
    assert POSIX_SETTINGS_FILE.exists(), "examples/settings.agentwarden.json must exist"
    data = json.loads(POSIX_SETTINGS_FILE.read_text(encoding="utf-8"))

    assert "hooks" in data
    assert "UserPromptSubmit" in data["hooks"]
    assert "PreToolUse" in data["hooks"]

    prompt_command = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
    tool_command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "on_prompt.py" in prompt_command
    assert "on_tool.py" in tool_command


@pytest.mark.parametrize(
    "settings_file,expected_interpreter",
    [
        (POSIX_SETTINGS_FILE, "python3"),
        (WINDOWS_SETTINGS_FILE, "python"),
    ],
    ids=["posix", "windows"],
)
def test_example_settings_files(settings_file, expected_interpreter):
    assert settings_file.exists(), f"{settings_file} must exist"
    data = json.loads(settings_file.read_text(encoding="utf-8"))

    pre_tool_hook = data["hooks"]["PreToolUse"][0]["hooks"][0]
    prompt_hook = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]

    assert pre_tool_hook["command"].split()[0] == expected_interpreter
    assert prompt_hook["command"].split()[0] == expected_interpreter

    assert "on_tool.py" in pre_tool_hook["command"]
    assert "on_prompt.py" in prompt_hook["command"]

    assert pre_tool_hook["timeout"] == 15
    assert prompt_hook["timeout"] == 5

    # Sanity: the settings timeout budget must stay above the hook's own
    # maximum wall-clock deadline (Decision 2 / WARDEN_HOOK_TIMEOUT clamp).
    assert pre_tool_hook["timeout"] > HOOK_TIMEOUT_CLAMP_MAX


def test_windows_settings_uses_python_not_python3():
    # Guards specifically against copy-pasting the POSIX command verbatim:
    # plain Windows installs put `python` on PATH, not `python3`.
    assert WINDOWS_SETTINGS_FILE.exists(), "examples/settings.agentwarden.windows.json must exist"
    data = json.loads(WINDOWS_SETTINGS_FILE.read_text(encoding="utf-8"))

    tool_command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    prompt_command = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
    assert "python3" not in tool_command
    assert "python3" not in prompt_command
