"""Tests for the Muse Code adapter (spec 028): normalization, hard denies, self-protection,
and an end-to-end check that `on_tool.py --agent muse_code` emits the Claude Code hook
schema (no formatter -- spec 028 and `integrations/muse_code/README.md` found Muse Code's
`PreToolUse` wire schema already matches it). No real model, no network beyond the stub
daemon on loopback.

Fixture payloads below are UNVERIFIED guesses (see `agentwarden/agents/muse_code.py` and
`integrations/muse_code/README.md`) pending the live capture in
`integrations/muse_code/hook_logger.py`.
"""

from __future__ import annotations

import json

import pytest

from agentwarden.agents import muse_code
from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate
from tests.hooks._stub_daemon import StubDaemon
from tests.hooks._support import ON_TOOL, run_hook

ADAPTER = muse_code.ADAPTER


@pytest.fixture
def stub_daemon():
    """Local fixture: `tests/hooks/conftest.py`'s `stub_daemon` is scoped to that directory."""
    daemon = StubDaemon()
    try:
        yield daemon
    finally:
        daemon.shutdown()


def _body(tool_name: str, tool_input: dict, cwd: str) -> dict:
    return {
        "session_id": "s-muse",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def _event(tool_name: str, tool_input: dict, cwd: str) -> ToolEvent:
    return ToolEvent.model_validate(ADAPTER.normalize("tool", _body(tool_name, tool_input, cwd)))


class _ExplodingProvider:
    name = "exploding"

    def complete(self, *args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the model must not be called")


# ---------------------------------------------------------------------------
# Adapter identity / registration
# ---------------------------------------------------------------------------


def test_adapter_is_registered_under_muse_code():
    from agentwarden import agents

    assert agents.get_adapter("muse_code") is ADAPTER
    assert ADAPTER.name == "muse_code"


def test_adapter_is_not_passthrough():
    assert ADAPTER.passthrough is False


# ---------------------------------------------------------------------------
# Normalization: UNVERIFIED fixture payloads, each tool it maps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "foreign_tool,foreign_input,canonical_tool,canonical_input",
    [
        ("exec_command", {"cmd": "ls"}, "Bash", {"command": "ls"}),
        ("shell", {"command": "ls"}, "Bash", {"command": "ls"}),
        (
            "write_file",
            {"path": "a.txt", "content": "x"},
            "Write",
            {"file_path": "a.txt", "content": "x"},
        ),
        (
            "edit_file",
            {"path": "a.txt", "old_str": "a", "new_str": "b"},
            "Edit",
            {"file_path": "a.txt", "old_string": "a", "new_string": "b"},
        ),
        ("read_file", {"path": "a.txt"}, "Read", {"file_path": "a.txt"}),
        ("search_files", {"query": "TODO"}, "Grep", {"pattern": "TODO"}),
        ("glob_files", {"query": "**/*.py"}, "Glob", {"pattern": "**/*.py"}),
        ("fetch_url", {"url": "https://example.com"}, "WebFetch", {"url": "https://example.com"}),
    ],
)
def test_normalize_maps_each_tool(foreign_tool, foreign_input, canonical_tool, canonical_input):
    out = ADAPTER.normalize("tool", _body(foreign_tool, foreign_input, "D:\\proj"))
    assert out["tool_name"] == canonical_tool
    assert out["tool_input"] == canonical_input
    assert out["agent_tool_name"] == foreign_tool


def test_normalize_unmapped_tool_is_prefixed():
    out = ADAPTER.normalize("tool", _body("browser_click", {"selector": "#x"}, "D:\\proj"))
    assert out["tool_name"] == "muse_code:browser_click"


# ---------------------------------------------------------------------------
# Same rules as Claude Code tools
# ---------------------------------------------------------------------------


def test_rm_rf_via_exec_command_is_denied(tmp_path):
    cwd = str(tmp_path)
    verdict = evaluate(_event("exec_command", {"cmd": "rm -rf /"}, cwd))
    assert verdict is not None and verdict.decision == "deny"


def test_env_read_via_read_file_is_denied(tmp_path):
    cwd = str(tmp_path)
    verdict = evaluate(_event("read_file", {"path": ".env"}, cwd))
    assert verdict is not None and verdict.decision == "deny"


@pytest.mark.parametrize("tool", ["exec_command", "shell"])
def test_argv_list_command_hits_hard_deny(tmp_path, tool):
    for field in ("cmd", "command"):
        event = _event(tool, {field: ["bash", "-lc", "cat .env"]}, str(tmp_path))
        assert event.tool_input["command"] == "bash -lc 'cat .env'"
        assert evaluate(event).decision == "deny"


def test_argv_list_with_non_string_entry_raises():
    from agentwarden.agents import AdapterError

    body = {
        "session_id": "s",
        "cwd": "D:\\p",
        "hook_event_name": "PreToolUse",
        "tool_name": "shell",
        "tool_input": {"command": ["rm", 1]},
    }
    with pytest.raises(AdapterError):
        muse_code.ADAPTER.normalize("tool", body)


def test_ls_via_exec_command_is_allowed(tmp_path):
    cwd = str(tmp_path)
    verdict = evaluate(_event("exec_command", {"cmd": "ls"}, cwd))
    assert verdict is not None and verdict.decision == "allow"


def test_unmapped_tool_asks_without_model(tmp_path):
    event = ToolEvent.model_validate(
        ADAPTER.normalize("tool", _body("browser_click", {"selector": "#x"}, str(tmp_path)))
    )
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"
    assert verdict.source == "rules"
    assert "browser_click" in verdict.reason


# ---------------------------------------------------------------------------
# Self-protection: every config path muse_code declares is hard-denied
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        lambda cwd: ToolEvent.model_validate(
            {
                "session_id": "s",
                "cwd": cwd,
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": ".muse/hooks.json", "content": "{}"},
            }
        ),
        lambda cwd: ToolEvent.model_validate(
            {
                "session_id": "s",
                "cwd": cwd,
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {
                    "file_path": ".muse-plugin/plugin.json",
                    "content": "{}",
                },
            }
        ),
        lambda cwd: ToolEvent.model_validate(
            {
                "session_id": "s",
                "cwd": cwd,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf .muse"},
            }
        ),
        lambda cwd: _event("write_file", {"path": ".muse/hooks.json", "content": "{}"}, cwd),
        lambda cwd: _event("exec_command", {"cmd": "rm .muse-plugin/plugin.json"}, cwd),
        # A script the plugin manifest registers is as protected as the manifest itself.
        lambda cwd: _event("write_file", {"path": ".muse-plugin/hooks/pre.py", "content": ""}, cwd),
        lambda cwd: _event("exec_command", {"cmd": "echo exit 0 > .muse/hooks/pre.sh"}, cwd),
    ],
)
def test_muse_config_paths_are_hard_denied(tmp_path, event):
    verdict = evaluate(event(str(tmp_path)))
    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "rules"


def test_muse_user_settings_path_is_hard_denied(tmp_path):
    cwd = str(tmp_path)
    target = str(tmp_path / ".config" / "muse" / "settings.json")
    event = ToolEvent.model_validate(
        {
            "session_id": "s",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": target, "content": "{}"},
        }
    )
    verdict = evaluate(event)
    assert verdict is not None and verdict.decision == "deny"


def test_muse_config_read_is_not_auto_allowed(tmp_path):
    event = ToolEvent.model_validate(
        {
            "session_id": "s",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".muse/hooks.json"},
        }
    )
    verdict = evaluate(event)
    assert verdict is None or verdict.decision != "allow"


# ---------------------------------------------------------------------------
# End-to-end: on_tool.py --agent muse_code, no formatter, Claude Code schema out
# ---------------------------------------------------------------------------


def test_hook_e2e_uses_claude_schema_no_formatter(tmp_path, stub_daemon):
    stub_daemon.body = json.dumps(
        {"decision": "deny", "reason": "blocked", "source": "rules"}
    ).encode()
    body = {
        "session_id": "s-muse-e2e",
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "exec_command",
        "tool_input": {"cmd": "rm -rf /"},
    }
    result = run_hook(
        ON_TOOL,
        json.dumps(body),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
        args=["--agent", "muse_code"],
    )
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "blocked"
    headers = {k.lower(): v for k, v in stub_daemon.last_request.headers.items()}
    assert headers.get("x-agentwarden-agent") == "muse_code"
    # The payload bytes are forwarded unchanged -- the daemon normalizes, not the hook.
    assert json.loads(stub_daemon.last_request.body) == body
