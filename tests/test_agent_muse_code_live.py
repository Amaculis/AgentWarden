"""Spec 036: Muse Code adapter against payloads captured live (Muse Code 1.4.14, 2026-11-02)."""

from __future__ import annotations

import pytest

from agentwarden.agents import AdapterError, muse_code
from agentwarden.decide import decide
from agentwarden.models import PromptEvent, ToolEvent
from agentwarden.rules import evaluate

ADAPTER = muse_code.ADAPTER
CWD = "C:\\tmp\\muse-capture"


def _body(tool_name: str, tool_input: dict, cwd: str = CWD) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "call_01a19dc5a10974599fe53f6f64ebf63d",
        "session_id": "01a19dc4-1216-7162-a0e7-e2351539c7c8",
        "turn_id": "01a19dc4-20ab-7f41-bb03-73f7241a28fc",
        "cwd": cwd,
        "transcript_path": None,
        "model": "muse-spark-1.3",
        "permission_mode": "default",
        "model_provider": "meta",
    }


def _event(tool_name: str, tool_input: dict, cwd: str = CWD) -> ToolEvent:
    return ToolEvent.model_validate(ADAPTER.normalize("tool", _body(tool_name, tool_input, cwd)))


class _ExplodingProvider:
    name = "exploding"

    def complete(self, *args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the model must not be called")


@pytest.mark.parametrize(
    "tool,tool_input,canonical,expected",
    [
        (
            "powershell",
            {
                "command": "Get-ChildItem -Force",
                "description": "List workspace directory contents",
                "workdir": "\\\\?\\C:\\tmp\\muse-capture",
            },
            "PowerShell",
            {"command": "Get-ChildItem -Force", "description": "List workspace directory contents"},
        ),
        ("read_file", {"path": "README.md"}, "Read", {"file_path": "README.md"}),
        (
            "edit_file",
            {"find": "a", "path": "README.md", "replace": "b"},
            "Edit",
            {"file_path": "README.md", "old_string": "a", "new_string": "b"},
        ),
        (
            "search",
            {"output_mode": "text", "paths": ["."], "pattern": "fake"},
            "Grep",
            {"output_mode": "text", "path": ".", "pattern": "fake"},
        ),
    ],
)
def test_live_payloads_normalize(tool, tool_input, canonical, expected):
    out = ADAPTER.normalize("tool", _body(tool, tool_input))
    assert out["tool_name"] == canonical
    assert {k: v for k, v in out["tool_input"].items() if k != "workdir"} == expected
    assert out["agent_tool_name"] == tool


def test_live_powershell_rm_is_denied():
    verdict = evaluate(_event("powershell", {"command": "Remove-Item -Recurse -Force C:\\"}))
    assert verdict is not None and verdict.decision == "deny"


def test_live_env_read_is_denied():
    verdict = evaluate(_event("read_file", {"path": ".env"}))
    assert verdict is not None and verdict.decision == "deny"


def test_turn_id_becomes_prompt_id():
    assert _event("read_file", {"path": "README.md"}).prompt_id == (
        "01a19dc4-20ab-7f41-bb03-73f7241a28fc"
    )
    prompt = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "run dir",
        "session_id": "s",
        "turn_id": "t1",
        "cwd": CWD,
    }
    assert PromptEvent.model_validate(ADAPTER.normalize("prompt", prompt)).prompt_id == "t1"


def test_search_paths_mapping():
    assert "path" not in _event("search", {"pattern": "x", "paths": []}).tool_input
    assert _event("search", {"pattern": "x", "paths": ["src"]}).tool_input["path"] == "src"
    with pytest.raises(AdapterError):
        ADAPTER.normalize("tool", _body("search", {"pattern": "x", "paths": ["a", "b"]}))
    with pytest.raises(AdapterError):
        ADAPTER.normalize("tool", _body("search", {"pattern": "x", "paths": [1]}))


def test_search_outside_project_is_denied():
    verdict = evaluate(_event("search", {"pattern": "x", "paths": ["C:\\Users"]}))
    assert verdict is not None and verdict.decision == "deny"


@pytest.mark.parametrize(
    "workdir", ["C:\\Users\\Artem", "\\\\?\\D:\\other", "..", "C:\\tmp\\muse-capture\\..\\x", 5]
)
def test_workdir_outside_cwd_raises(workdir):
    with pytest.raises(AdapterError):
        ADAPTER.normalize("tool", _body("powershell", {"command": "dir", "workdir": workdir}))


@pytest.mark.parametrize(
    "workdir",
    ["\\\\?\\C:\\tmp\\muse-capture", "C:\\tmp\\muse-capture\\sub", "c:/TMP/muse-capture", "sub"],
)
def test_workdir_inside_cwd_ok(workdir):
    out = ADAPTER.normalize("tool", _body("powershell", {"command": "dir", "workdir": workdir}))
    assert out["tool_name"] == "PowerShell"


def test_internal_reminder_tool_is_allowed_without_model():
    event = _event(
        "submit_reminder_decision",
        {"advisory_text": "", "decision": "none", "reason": "no skill", "skill_id": "bundled:git"},
    )
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "allow"
    assert verdict.source == "rules"


def test_other_unmapped_tool_still_asks():
    verdict = decide(_event("browser_click", {"selector": "#x"}), provider=_ExplodingProvider())
    assert verdict.decision == "ask"


def test_internal_tool_of_one_agent_is_not_internal_for_another():
    from agentwarden.agents import get_adapter

    codex = get_adapter("codex")
    body = {**_body("submit_reminder_decision", {}), "hook_event_name": "PreToolUse"}
    try:
        event = ToolEvent.model_validate(codex.normalize("tool", body))
    except AdapterError:
        return
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision != "allow"
