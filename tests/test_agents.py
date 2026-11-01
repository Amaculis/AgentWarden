"""Tests for spec 027 (agent adapter layer): normalization, registry, unmapped tools and the
self-protection of every registered agent's hook config. No real model, no network."""

from __future__ import annotations

import os
import sys
import types

import pytest

from agentwarden import agents, links
from agentwarden.agents import Adapter, AdapterError
from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate

FAKE = Adapter(
    name="fakeagent",
    tool_map={"exec_command": "Bash", "write_file": "Write", "read_file": "Read"},
    input_map={
        "Bash": {"cmd": "command"},
        "Write": {"path": "file_path"},
        "Read": {"path": "file_path"},
    },
    config_paths=((".fake", "hooks.json"), (".fakedir", "hooks")),
)


@pytest.fixture(autouse=True)
def _fake_registry(monkeypatch):
    registry = {"claude_code": agents.get_adapter("claude_code"), "fakeagent": FAKE}
    monkeypatch.setattr(agents, "registry", lambda: registry)
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    links.clear_cache()
    yield
    links.clear_cache()


def _body(tool_name: str, tool_input, cwd: str) -> dict:
    return {
        "session_id": "s1",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def _foreign(tool_name: str, tool_input, cwd: str) -> ToolEvent:
    return ToolEvent.model_validate(FAKE.normalize("tool", _body(tool_name, tool_input, cwd)))


def _claude(tool_name: str, tool_input, cwd: str) -> ToolEvent:
    return ToolEvent.model_validate(_body(tool_name, tool_input, cwd))


class _ExplodingProvider:
    name = "exploding"

    def complete(self, *args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the model must not be called")


# ---------------------------------------------------------------------------
# Adapter and registry
# ---------------------------------------------------------------------------


def test_claude_code_is_identity():
    body = _body("Bash", {"command": "ls"}, "D:\\proj")
    adapter = agents.get_adapter("claude_code")
    assert adapter.normalize("tool", body) == body
    assert adapter.normalize("read", body) == body
    prompt = {
        "session_id": "s",
        "cwd": "D:\\p",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "x",
    }
    assert adapter.normalize("prompt", prompt) == prompt


def test_missing_name_means_claude_code():
    assert agents.get_adapter(None).name == "claude_code"
    assert agents.get_adapter("").name == "claude_code"


@pytest.mark.parametrize("name", ["nope", "Claude_Code", "../x", "a" * 40, "1abc", "fake agent"])
def test_get_adapter_rejects_unknown_and_malformed_names(name):
    with pytest.raises(AdapterError):
        agents.get_adapter(name)


def test_normalize_maps_tool_and_fields_and_keeps_original_name():
    out = FAKE.normalize("tool", _body("exec_command", {"cmd": "ls", "timeout": 5}, "D:\\p"))
    assert out["tool_name"] == "Bash"
    assert out["tool_input"] == {"command": "ls", "timeout": 5}
    assert out["agent_tool_name"] == "exec_command"


def test_normalize_does_not_mutate_input():
    body = _body("exec_command", {"cmd": "ls"}, "D:\\p")
    FAKE.normalize("tool", body)
    assert body["tool_name"] == "exec_command"
    assert body["tool_input"] == {"cmd": "ls"}


def test_normalize_conflicting_fields_raise():
    body = _body("exec_command", {"cmd": "ls", "command": "rm -rf /"}, "D:\\p")
    with pytest.raises(AdapterError):
        FAKE.normalize("tool", body)


def test_normalize_non_dict_tool_input_raises():
    with pytest.raises(AdapterError):
        FAKE.normalize("tool", _body("exec_command", "ls", "D:\\p"))


def test_unmapped_tool_is_prefixed():
    out = FAKE.normalize("tool", _body("Bash", {"command": "ls"}, "D:\\p"))
    assert out["tool_name"] == "fakeagent:Bash"


def test_discovery_registers_modules_with_adapter(monkeypatch):
    good = types.ModuleType("agentwarden.agents.goodagent")
    good.ADAPTER = Adapter(name="goodagent", tool_map={}, input_map={}, config_paths=())
    no_adapter = types.ModuleType("agentwarden.agents.helper")
    modules = {"goodagent": good, "helper": no_adapter}

    def fake_import(name: str):
        short = name.rsplit(".", 1)[-1]
        if short == "broken":
            raise ImportError("boom")
        return modules[short]

    monkeypatch.setattr(agents, "_module_names", lambda: ["broken", "goodagent", "helper"])
    monkeypatch.setattr(agents.importlib, "import_module", fake_import)
    found = agents.discover()
    assert set(found) == {"goodagent"}


def test_real_registry_has_claude_code():
    assert "claude_code" in agents.discover()


# ---------------------------------------------------------------------------
# Mapped tools hit the same rules as Claude tools
# ---------------------------------------------------------------------------


def test_mapped_shell_tool_hits_hard_deny(tmp_path):
    cwd = str(tmp_path)
    assert evaluate(_foreign("exec_command", {"cmd": "rm -rf /"}, cwd)).decision == "deny"
    verdict = evaluate(_foreign("exec_command", {"cmd": "cat .agentwarden/policy.yaml"}, cwd))
    assert verdict.decision == "deny"
    assert evaluate(_foreign("exec_command", {"cmd": "ls"}, cwd)).decision == "allow"


def test_mapped_file_tool_hits_secret_and_boundary_rules(tmp_path):
    cwd = str(tmp_path)
    assert evaluate(_foreign("read_file", {"path": ".env"}, cwd)).decision == "deny"
    assert evaluate(_foreign("read_file", {"path": "src/app.py"}, cwd)).decision == "allow"
    outside = evaluate(_foreign("write_file", {"path": "C:/Windows/x.txt"}, cwd))
    assert outside is not None and outside.decision in ("ask", "deny")


def test_unmapped_foreign_tool_asks_without_model(tmp_path):
    event = _foreign("browser_click", {"selector": "#ok"}, str(tmp_path))
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"
    assert verdict.source == "rules"
    assert "browser_click" in verdict.reason


# ---------------------------------------------------------------------------
# Self-protection of every agent's config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        lambda cwd: _claude("Write", {"file_path": ".fake/hooks.json", "content": "{}"}, cwd),
        lambda cwd: _claude(
            "Edit",
            {"file_path": "sub/../.fake/hooks.json", "old_string": "a", "new_string": "b"},
            cwd,
        ),
        lambda cwd: _claude("Write", {"file_path": ".fakedir/hooks/aw.json", "content": "{}"}, cwd),
        lambda cwd: _claude("Write", {"file_path": "C:\\Users\\x\\.FAKE\\hooks.json"}, cwd),
        lambda cwd: _claude("Bash", {"command": "echo {} > .fake/hooks.json"}, cwd),
        lambda cwd: _claude("Bash", {"command": "rm -rf .fakedir/hooks"}, cwd),
        lambda cwd: _claude("PowerShell", {"command": "Remove-Item -Recurse .fakedir"}, cwd),
        lambda cwd: _claude("Bash", {"command": "mv .fake /tmp/x"}, cwd),
        lambda cwd: _foreign("exec_command", {"cmd": "rm .fakedir/hook*"}, cwd),
        lambda cwd: _foreign("write_file", {"path": ".fake/hooks.json"}, cwd),
    ],
)
def test_agent_config_paths_are_hard_denied_for_every_agent(tmp_path, event):
    verdict = evaluate(event(str(tmp_path)))
    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "rules"


def test_agent_config_read_is_not_auto_allowed(tmp_path):
    verdict = evaluate(_claude("Read", {"file_path": ".fake/hooks.json"}, str(tmp_path)))
    assert verdict is None or verdict.decision != "allow"


def test_unrelated_paths_with_similar_names_unaffected(tmp_path):
    cwd = str(tmp_path)
    assert evaluate(_claude("Bash", {"command": "ls"}, cwd)).decision == "allow"
    write = evaluate(_claude("Write", {"file_path": "docs/fake/hooks.json", "content": "x"}, cwd))
    assert write is None or write.decision != "deny"
    write = evaluate(_claude("Write", {"file_path": "my.fakedir/hooks/a", "content": "x"}, cwd))
    assert write is None or write.decision != "deny"


@pytest.mark.parametrize(
    "command",
    ["rm .fakedir/workflows/old.yml", "git rm -r .fakedir/workflows", "mv .fakedir/a.txt b.txt"],
)
def test_removing_sibling_of_config_dir_is_not_hard_denied(tmp_path, command):
    verdict = evaluate(_claude("Bash", {"command": command}, str(tmp_path)))
    assert verdict is None or "hook config" not in verdict.reason


@pytest.mark.parametrize(
    "command", ["rm -rf .fakedir", "rm -rf .fakedir/", "rm .fakedir/*", "del .FAKEDIR\\hook?"]
)
def test_removing_config_parent_or_wildcard_is_denied(tmp_path, command):
    verdict = evaluate(_claude("Bash", {"command": command}, str(tmp_path)))
    assert verdict is not None and verdict.decision == "deny"
    assert "hook config" in verdict.reason


def test_agent_config_link_is_denied(tmp_path):
    if sys.platform != "win32":
        pytest.skip("junctions are Windows-only")
    import _winapi

    project = tmp_path / "proj"
    (project / ".fakedir" / "hooks").mkdir(parents=True)
    (project / ".fakedir" / "hooks" / "aw.json").write_text("{}", encoding="utf-8")
    try:
        _winapi.CreateJunction(str(project / ".fakedir"), str(project / "innocent"))
    except OSError as exc:
        pytest.skip(f"junction creation failed: {exc}")
    event = _claude("Write", {"file_path": "innocent/hooks/aw.json", "content": "{}"}, str(project))
    verdict = evaluate(event)
    assert verdict is not None and verdict.decision == "deny"


def test_agent_config_hardlink_is_denied(tmp_path):
    project = tmp_path / "proj"
    (project / ".fake").mkdir(parents=True)
    config = project / ".fake" / "hooks.json"
    config.write_text("{}", encoding="utf-8")
    try:
        os.link(config, project / "notes.txt")
    except OSError as exc:
        pytest.skip(f"hard links not supported here: {exc}")
    event = _claude("Write", {"file_path": "notes.txt", "content": "x"}, str(project))
    verdict = evaluate(event)
    assert verdict is not None and verdict.decision == "deny"


def test_broken_registry_fails_closed(tmp_path, monkeypatch):
    def boom():
        raise RuntimeError("registry broken")

    monkeypatch.setattr(agents, "registry", boom)
    event = _claude("Write", {"file_path": "src/x.py", "content": "x"}, str(tmp_path))
    verdict = evaluate(event)
    assert verdict is not None and verdict.decision == "ask"
