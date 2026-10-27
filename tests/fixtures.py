"""Shared real hook payload fixtures for spec 002 (models/decide/store/daemon tests).

Not a test module itself (no `test_` prefix) — pytest will not collect it.

Payloads are copied from `.claude/skills/hook-protocol/SKILL.md` (real captures,
2026-10-26), with the extra fields (`scratchpad_dir`, `effort`, `transcript_path`)
intact so tests can assert they are ignored by the pydantic models.
"""

from __future__ import annotations

from typing import Any

_COMMON_EXTRAS = {
    "transcript_path": (
        "C:\\Users\\Artem\\.claude\\projects\\d--GITHUB-AgentWarden\\"
        "3d97e6f2-2818-4b71-955c-ff6310aeb5be.jsonl"
    ),
    "scratchpad_dir": (
        "C:\\Users\\Artem\\AppData\\Local\\Temp\\claude\\d--GITHUB-AgentWarden\\"
        "3d97e6f2-2818-4b71-955c-ff6310aeb5be\\scratchpad"
    ),
}


def _pre_tool_use(tool_name: str, tool_input: dict[str, Any], tool_use_id: str) -> dict[str, Any]:
    return {
        "session_id": "3d97e6f2-2818-4b71-955c-ff6310aeb5be",
        "prompt_id": "5daaca00-4922-43ca-80ec-def0e591efc6",
        "cwd": "D:\\GITHUB\\AgentWarden",
        "permission_mode": "auto",
        "effort": {"level": "medium"},
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
        **_COMMON_EXTRAS,
    }


BASH_PRE_TOOL_USE = _pre_tool_use(
    "Bash",
    {
        "command": "echo test-manual-capture",
        "description": "Run a sample Bash command to trigger PreToolUse hook",
    },
    "toolu_01FyVCvSNS9ZJkXzSUHKwhUh",
)

READ_PRE_TOOL_USE = _pre_tool_use(
    "Read",
    {"file_path": "D:\\GITHUB\\AgentWarden\\README.md", "limit": 5},
    "toolu_01ReadSampleAbCdEf01234",
)

WRITE_PRE_TOOL_USE = _pre_tool_use(
    "Write",
    {"file_path": "D:\\GITHUB\\AgentWarden\\scratch.txt", "content": "hello world"},
    "toolu_01WriteSampleAbCdEf0123",
)

EDIT_PRE_TOOL_USE = _pre_tool_use(
    "Edit",
    {
        "file_path": "D:\\GITHUB\\AgentWarden\\README.md",
        "old_string": "old",
        "new_string": "new",
        "replace_all": False,
    },
    "toolu_01EditSampleAbCdEf01234",
)

REAL_PRE_TOOL_USE_PAYLOADS = [
    BASH_PRE_TOOL_USE,
    READ_PRE_TOOL_USE,
    WRITE_PRE_TOOL_USE,
    EDIT_PRE_TOOL_USE,
]

USER_PROMPT_SUBMIT = {
    "session_id": "3d97e6f2-2818-4b71-955c-ff6310aeb5be",
    "prompt_id": "f471a566-a975-47a2-a19d-c28324bc918c",
    "cwd": "D:\\GITHUB\\AgentWarden",
    "permission_mode": "auto",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "<ide_opened_file>...</ide_opened_file>\nЧто проверить дальше?",
    **_COMMON_EXTRAS,
}
