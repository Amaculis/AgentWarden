"""Tests for spec 029 (GitHub Copilot adapters): `copilot_vscode` and `copilot_cli`.

Unverified against a live Copilot -- see `integrations/copilot/README.md` for sources. Fixtures
below are DOC-DERIVED, not captured from a real Copilot session; each block says which shape it
assumes and whether that shape is verified-by-docs or guessed. No real model, no network except
the loopback uvicorn server used by the end-to-end test.
"""

from __future__ import annotations

import json
import threading
import time

import httpx
import pytest
import uvicorn

from agentwarden import agents
from agentwarden.agents import get_adapter
from agentwarden.agents.copilot_cli import ADAPTER as CLI_ADAPTER
from agentwarden.agents.copilot_vscode import ADAPTER as VSCODE_ADAPTER
from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate


class _ExplodingProvider:
    name = "exploding"

    def complete(self, *args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the model must not be called")


def _body(tool_name: str, tool_input: dict, cwd: str, **extra) -> dict:
    out = {
        "session_id": "s1",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    out.update(extra)
    return out


def _normalized(adapter, tool_name: str, tool_input: dict, cwd: str, **extra) -> ToolEvent:
    body = _body(tool_name, tool_input, cwd, **extra)
    return ToolEvent.model_validate(adapter.normalize("tool", body))


# ---------------------------------------------------------------------------
# Registry: both adapters are discovered under their own names (spec 027).
# ---------------------------------------------------------------------------


def test_both_copilot_adapters_are_registered():
    assert get_adapter("copilot_vscode").name == "copilot_vscode"
    assert get_adapter("copilot_cli").name == "copilot_cli"
    assert "copilot_vscode" in agents.discover()
    assert "copilot_cli" in agents.discover()


# ---------------------------------------------------------------------------
# copilot_vscode: VS Code's `PreToolUse` alias is already Claude-shaped
# (verified by docs: code.visualstudio.com/docs/copilot/customization/hooks
# -- "snake_case fields ... Claude-style tool names like Read, Write, Edit").
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch"])
def test_vscode_known_tools_normalize_to_themselves(tool):
    out = VSCODE_ADAPTER.normalize("tool", _body(tool, {"x": 1}, "D:\\p"))
    assert out["tool_name"] == tool
    assert out["agent_tool_name"] == tool


def test_vscode_rm_rf_deny():
    event = _normalized(VSCODE_ADAPTER, "Bash", {"command": "rm -rf /"}, "D:\\p")
    assert evaluate(event).decision == "deny"


def test_vscode_env_read_deny(tmp_path):
    event = _normalized(VSCODE_ADAPTER, "Read", {"file_path": ".env"}, str(tmp_path))
    assert evaluate(event).decision == "deny"


def test_vscode_ls_allow(tmp_path):
    event = _normalized(VSCODE_ADAPTER, "Bash", {"command": "ls"}, str(tmp_path))
    assert evaluate(event).decision == "allow"


def test_vscode_unmapped_tool_asks_without_model(tmp_path):
    # `Task`/`NotebookEdit`/anything not in the identity map: ask, never guess.
    event = _normalized(VSCODE_ADAPTER, "Task", {"description": "x"}, str(tmp_path))
    assert event.tool_name == "copilot_vscode:Task"
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"
    assert verdict.source == "rules"


# ---------------------------------------------------------------------------
# copilot_cli: native camelCase event + toolName/toolArgs, lower-case tool
# names. `bash`/`edit`/`view` as example tool names and `toolName`/`toolArgs`
# as field names are verified by docs.github.com (hooks reference pages,
# quoted repeatedly); `create`/`grep`/`glob`/`web_fetch` and the inner
# `path` field are GUESSED by analogy (see README) -- not directly quoted.
# ---------------------------------------------------------------------------


def _cli_body(tool_name: str, tool_args: dict, cwd: str) -> dict:
    return {
        "session_id": "s1",
        "cwd": cwd,
        "hookEventName": "preToolUse",
        "toolName": tool_name,
        "toolArgs": tool_args,
    }


def _cli_normalized(tool_name: str, tool_args: dict, cwd: str) -> ToolEvent:
    body = _cli_body(tool_name, tool_args, cwd)
    return ToolEvent.model_validate(CLI_ADAPTER.normalize("tool", body))


def test_cli_event_and_field_aliases_translate():
    out = CLI_ADAPTER.normalize("tool", _cli_body("bash", {"command": "ls"}, "D:\\p"))
    assert out["hook_event_name"] == "PreToolUse"
    assert out["tool_name"] == "Bash"
    assert out["tool_input"] == {"command": "ls"}
    assert out["agent_tool_name"] == "bash"


@pytest.mark.parametrize(
    ("tool", "args", "canonical"),
    [
        ("bash", {"command": "ls"}, "Bash"),
        ("view", {"path": "src/app.py"}, "Read"),
        ("create", {"path": "out.txt", "content": "x"}, "Write"),
        ("edit", {"path": "src/app.py"}, "Edit"),
        ("grep", {"pattern": "TODO", "path": "."}, "Grep"),
        ("glob", {"pattern": "**/*.py"}, "Glob"),
        ("web_fetch", {"url": "https://example.com"}, "WebFetch"),
    ],
)
def test_cli_known_tools_map_to_canonical(tool, args, canonical):
    out = CLI_ADAPTER.normalize("tool", _cli_body(tool, args, "D:\\p"))
    assert out["tool_name"] == canonical
    assert out["agent_tool_name"] == tool


def test_cli_rm_rf_deny():
    event = _cli_normalized("bash", {"command": "rm -rf /"}, "D:\\p")
    assert evaluate(event).decision == "deny"


def test_cli_env_read_deny(tmp_path):
    event = _cli_normalized("view", {"path": ".env"}, str(tmp_path))
    assert evaluate(event).decision == "deny"


def test_cli_ls_allow(tmp_path):
    event = _cli_normalized("bash", {"command": "ls"}, str(tmp_path))
    assert evaluate(event).decision == "allow"


@pytest.mark.parametrize("tool", ["ask_user", "task"])
def test_cli_unmapped_tool_asks_without_model(tmp_path, tool):
    # Undocumented payload shape: never guessed, always ask before the model runs.
    event = _cli_normalized(tool, {"anything": "goes"}, str(tmp_path))
    assert event.tool_name == f"copilot_cli:{tool}"
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"
    assert verdict.source == "rules"


# ---------------------------------------------------------------------------
# Self-protection of every Copilot hook config location, whatever agent runs.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        lambda cwd: _normalized(
            VSCODE_ADAPTER, "Write", {"file_path": ".github/hooks/aw.json", "content": "{}"}, cwd
        ),
        lambda cwd: _normalized(VSCODE_ADAPTER, "Bash", {"command": "rm -rf .github/hooks"}, cwd),
        lambda cwd: _normalized(
            VSCODE_ADAPTER, "Write", {"file_path": ".vscode/settings.json", "content": "{}"}, cwd
        ),
        lambda cwd: _normalized(
            VSCODE_ADAPTER,
            "Write",
            {"file_path": ".github/copilot/settings.json", "content": "{}"},
            cwd,
        ),
        lambda cwd: _cli_normalized("edit", {"path": ".github/hooks/aw.json"}, cwd),
        lambda cwd: _cli_normalized("bash", {"command": "rm .copilot/hooks/aw.json"}, cwd),
        lambda cwd: _cli_normalized("create", {"path": ".copilot/settings.json"}, cwd),
    ],
)
def test_copilot_config_paths_are_hard_denied(tmp_path, event):
    verdict = evaluate(event(str(tmp_path)))
    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "rules"


def test_copilot_config_paths_denied_even_running_claude_code(tmp_path):
    """The config-path hard deny applies to every registered agent, whatever is running (027)."""
    event = ToolEvent.model_validate(
        _body("Write", {"file_path": ".github/hooks/aw.json", "content": "{}"}, str(tmp_path))
    )
    verdict = evaluate(event)
    assert verdict is not None and verdict.decision == "deny"


@pytest.mark.parametrize(
    "command",
    ["rm .github/workflows/old.yml", "git rm -r .github/workflows"],
)
def test_github_workflows_sibling_not_hard_denied(tmp_path, command):
    event = ToolEvent.model_validate(_body("Bash", {"command": command}, str(tmp_path)))
    verdict = evaluate(event)
    assert verdict is None or "hook config" not in verdict.reason


def test_editing_workflows_ci_not_hard_denied(tmp_path):
    event = ToolEvent.model_validate(
        _body(
            "Edit",
            {"file_path": ".github/workflows/ci.yml", "old_string": "a", "new_string": "b"},
            str(tmp_path),
        )
    )
    verdict = evaluate(event)
    assert verdict is None or "hook config" not in verdict.reason


# ---------------------------------------------------------------------------
# End-to-end: a real daemon, real registry, `--agent copilot_cli` hook subprocess.
# ---------------------------------------------------------------------------


@pytest.fixture
def real_daemon(tmp_path):
    from agentwarden.daemon import create_app

    app = create_app(db_path=tmp_path / "audit.db")
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn server did not report started in time"
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_e2e_copilot_cli_hook_denies_rm_rf(tmp_path, real_daemon):
    import importlib.util
    import sys as _sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    on_tool_path = repo_root / "hooks" / "on_tool.py"
    spec = importlib.util.spec_from_file_location("agentwarden_on_tool_e2e", on_tool_path)
    on_tool = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = on_tool
    spec.loader.exec_module(on_tool)

    stdin = json.dumps(_cli_body("bash", {"command": "rm -rf /"}, str(tmp_path))).encode()
    output = on_tool.run(stdin, {"WARDEN_URL": real_daemon}, agent="copilot_cli")
    parsed = json.loads(output)
    hso = parsed["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"

    rows = httpx.get(f"{real_daemon}/log", params={"session_id": "s1"}).json()
    assert rows and rows[0]["tool_name"] == "Bash"
