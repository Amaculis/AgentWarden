"""Optional check for examples/settings.agentwarden.json (spec 001 interface section).

This file does not exist yet (examples/ only has .gitkeep). Expected to fail
until spec 001 ships it.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_FILE = REPO_ROOT / "examples" / "settings.agentwarden.json"


def test_example_settings_is_valid_json():
    assert SETTINGS_FILE.exists(), "examples/settings.agentwarden.json must exist"
    data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))

    assert "hooks" in data
    assert "UserPromptSubmit" in data["hooks"]
    assert "PreToolUse" in data["hooks"]

    prompt_command = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
    tool_command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "on_prompt.py" in prompt_command
    assert "on_tool.py" in tool_command
