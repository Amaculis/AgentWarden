"""Home-relative paths are never "inside the project" (spec 019)."""

from __future__ import annotations

import pytest

from agentwarden.models import ToolEvent
from agentwarden.rules import _is_inside_project, evaluate


def _event(tool: str, cwd: str, **tool_input) -> ToolEvent:
    return ToolEvent(
        session_id="s", cwd=cwd, hook_event_name="PreToolUse", tool_name=tool, tool_input=tool_input
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "proj").mkdir(parents=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    return home


def test_tilde_path_is_not_inside_project(home):
    cwd = str(home / "proj")
    path = "~/.config/google-chrome/Default/Login Data"
    assert _is_inside_project(path, cwd) is False
    verdict = evaluate(_event("Read", cwd, file_path=path))
    assert verdict is None or verdict.decision != "allow"


@pytest.mark.parametrize(
    "path", ["$HOME/.aws/config", "${HOME}/.aws/config", "%USERPROFILE%/.aws/config"]
)
def test_env_var_home_paths_expanded(home, path):
    assert _is_inside_project(path, str(home / "proj")) is False
    assert _is_inside_project(path.replace(".aws/config", "proj/src/app.py"), str(home / "proj"))


@pytest.mark.parametrize("path", ["$NOT_SET_ANYWHERE_X/file.txt", "%NOT_SET_ANYWHERE_X%/file.txt"])
def test_unexpandable_prefix_not_inside_project(home, path, monkeypatch):
    monkeypatch.delenv("NOT_SET_ANYWHERE_X", raising=False)
    assert _is_inside_project(path, str(home / "proj")) is False


def test_tilde_path_to_project_hooks_still_protected(home):
    cwd = str(home / "proj")
    verdict = evaluate(
        _event("Edit", cwd, file_path="~/proj/hooks/on_tool.py", old_string="a", new_string="b")
    )
    assert verdict is not None and verdict.decision == "deny"


def test_plain_relative_paths_unchanged(home):
    cwd = str(home / "proj")
    assert _is_inside_project("src/app.py", cwd)
    verdict = evaluate(_event("Read", cwd, file_path="src/app.py"))
    assert verdict is not None and verdict.decision == "allow"
