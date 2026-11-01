"""Tests for the read-only policy profile (spec 024). No network, no real model."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from agentwarden import decide as decide_module
from agentwarden import policy as policy_module
from agentwarden.models import ToolEvent
from agentwarden.policy import load_policy
from agentwarden.providers.mock import MockProvider
from agentwarden.rules import evaluate


@pytest.fixture(autouse=True)
def _reset_warned_invalid():
    policy_module._warned_invalid = False
    yield
    policy_module._warned_invalid = False


def _event(tool_name: str, tool_input: dict, cwd: str) -> ToolEvent:
    return ToolEvent.model_validate(
        {
            "session_id": "s1",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
    )


def _write_policy(root: Path, text: str) -> None:
    folder = root / ".agentwarden"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "policy.yaml").write_text(text, encoding="utf-8")


def _read_only(tmp_path: Path, extra: str = "") -> str:
    _write_policy(tmp_path, f"version: 1\nmode: read_only\n{extra}")
    return str(tmp_path)


def _match(cwd: str, tool_name: str, tool_input: dict):
    return policy_module.match(load_policy(cwd), _event(tool_name, tool_input, cwd))


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "src/app.py"}),
        ("Grep", {"pattern": "TODO", "path": "src"}),
        ("Glob", {"pattern": "**/*.py"}),
        ("Grep", {"pattern": "TODO"}),
    ],
)
def test_read_only_allows_read_inside_project(tmp_path, tool, tool_input):
    verdict = _match(_read_only(tmp_path), tool, tool_input)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.source == "policy"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Edit", {"file_path": "src/app.py", "old_string": "a", "new_string": "b"}),
        ("Write", {"file_path": "src/new.py", "content": "x"}),
        ("MultiEdit", {"file_path": "src/app.py", "edits": []}),
        ("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": "x"}),
    ],
)
def test_read_only_asks_for_write_tools(tmp_path, tool, tool_input):
    verdict = _match(_read_only(tmp_path), tool, tool_input)
    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.source == "policy"
    assert "read-only" in verdict.reason


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Bash", {"command": "ls"}),
        ("Bash", {"command": "git status"}),
        ("PowerShell", {"command": "Get-ChildItem"}),
        ("WebFetch", {"url": "https://pypi.org/simple/requests/"}),
        ("mcp__server__do_thing", {"x": 1}),
        ("Task", {"prompt": "do it"}),
    ],
)
def test_read_only_asks_for_shell_and_network(tmp_path, tool, tool_input):
    verdict = _match(_read_only(tmp_path), tool, tool_input)
    assert verdict is not None
    assert verdict.decision == "ask"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "/etc/hosts"}),
        ("Read", {"file_path": "../other/file.txt"}),
        ("Read", {"file_path": "~/notes.txt"}),
        ("Grep", {"pattern": "x", "path": "/var/log"}),
        ("Read", {}),
        ("Read", {"file_path": 5}),
    ],
)
def test_read_only_asks_for_read_outside_project(tmp_path, tool, tool_input):
    verdict = _match(_read_only(tmp_path), tool, tool_input)
    assert verdict is not None
    assert verdict.decision == "ask"


def test_read_only_ignores_allow_lists(tmp_path):
    cwd = _read_only(
        tmp_path,
        "allow_commands: ['make test']\nallow_paths: ['src/']\nallow_domains: ['pypi.org']\n",
    )
    assert _match(cwd, "Bash", {"command": "make test"}).decision == "ask"
    edit = {"file_path": "src/app.py", "old_string": "a", "new_string": "b"}
    assert _match(cwd, "Edit", edit).decision == "ask"
    assert _match(cwd, "WebFetch", {"url": "https://pypi.org/x"}).decision == "ask"


def test_read_only_deny_and_ask_paths_still_apply(tmp_path):
    cwd = _read_only(tmp_path, "deny_paths: ['vault/']\nask_paths: ['docs/']\n")
    assert _match(cwd, "Read", {"file_path": "vault/a.txt"}).decision == "deny"
    assert _match(cwd, "Read", {"file_path": "docs/a.md"}).decision == "ask"
    assert _match(cwd, "Read", {"file_path": "src/a.py"}).decision == "allow"


def test_read_only_cannot_weaken_hard_denies(tmp_path):
    cwd = _read_only(tmp_path)
    assert evaluate(_event("Read", {"file_path": ".env"}, cwd)).decision == "deny"
    edit = {"file_path": ".agentwarden/policy.yaml", "old_string": "a", "new_string": "b"}
    assert evaluate(_event("Edit", edit, cwd)).decision == "deny"


def test_read_only_never_calls_judge(tmp_path):
    cwd = _read_only(tmp_path)
    provider = MockProvider(['{"decision": "allow", "risk": 0, "confidence": 1, "reason": "ok"}'])
    event = _event("Edit", {"file_path": "src/a.py", "old_string": "a", "new_string": "b"}, cwd)
    verdict = decide_module.decide(event, None, provider)
    assert verdict.decision == "ask"
    assert provider.calls == []


def test_normal_mode_unchanged(tmp_path):
    _write_policy(tmp_path, "version: 1\nmode: normal\n")
    cwd = str(tmp_path)
    assert load_policy(cwd).mode == "normal"
    assert _match(cwd, "Bash", {"command": "ls"}) is None
    assert _match(cwd, "Edit", {"file_path": "a.py", "old_string": "a", "new_string": "b"}) is None


def test_default_policy_mode_is_normal(tmp_path):
    assert load_policy(str(tmp_path)).mode == "normal"


def test_invalid_mode_uses_defaults_and_warns(tmp_path, caplog):
    _write_policy(tmp_path, "version: 1\nmode: readonly\ndeny_paths: ['vault/']\n")
    with caplog.at_level(logging.WARNING):
        policy = load_policy(str(tmp_path))
    assert policy.mode == "normal"
    assert policy.deny_paths == []
    assert "invalid" in caplog.text
