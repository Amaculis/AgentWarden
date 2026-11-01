"""Tests for spec 030 (Codex adapter): normalization, rules parity, formatter safety.

UNVERIFIED fixtures: payload shapes are derived from OpenAI's docs/GitHub research recorded in
integrations/codex/README.md, not from a live Codex. No real model, no network.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from agentwarden import agents
from agentwarden.agents import AdapterError
from agentwarden.agents.codex import ADAPTER
from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
FORMATTER_PATH = REPO_ROOT / "hooks" / "formats" / "codex.py"


def _load_formatter():
    spec = importlib.util.spec_from_file_location("agentwarden_format_codex", FORMATTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FMT = _load_formatter()


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    registry = {"claude_code": agents.get_adapter("claude_code"), "codex": ADAPTER}
    monkeypatch.setattr(agents, "registry", lambda: registry)
    yield


def _body(tool_name, tool_input, cwd: str) -> dict:
    return {
        "session_id": "s1",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def _event(tool_name, tool_input, cwd: str, kind="tool") -> ToolEvent:
    return ToolEvent.model_validate(ADAPTER.normalize(kind, _body(tool_name, tool_input, cwd)))


class _ExplodingProvider:
    name = "exploding"

    def complete(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("the model must not be called")


# ---------------------------------------------------------------------------
# Adapter / normalize
# ---------------------------------------------------------------------------


def test_codex_is_registered():
    assert agents.get_adapter("codex").name == "codex"


@pytest.mark.parametrize("foreign", ["Bash", "shell", "exec_command", "unified_exec"])
def test_shell_tool_names_map_to_bash(foreign):
    out = ADAPTER.normalize("tool", _body(foreign, {"command": "ls"}, "D:\\p"))
    assert out["tool_name"] == "Bash"
    assert out["tool_input"]["command"] == "ls"
    assert out["agent_tool_name"] == foreign


def test_argv_list_command_is_shlex_joined():
    body = _body("Bash", {"command": ["bash", "-lc", "rm -rf /"]}, "D:\\p")
    out = ADAPTER.normalize("tool", body)
    assert out["tool_input"]["command"] == shlex_join_expectation()


def shlex_join_expectation() -> str:
    import shlex

    return shlex.join(["bash", "-lc", "rm -rf /"])


def test_argv_list_with_non_string_entry_raises():
    with pytest.raises(AdapterError):
        ADAPTER.normalize("tool", _body("Bash", {"command": ["bash", 5]}, "D:\\p"))


def test_string_command_is_left_alone():
    out = ADAPTER.normalize("tool", _body("Bash", {"command": "echo hi"}, "D:\\p"))
    assert out["tool_input"]["command"] == "echo hi"


def test_normalize_does_not_mutate_input():
    body = _body("Bash", {"command": ["ls", "-la"]}, "D:\\p")
    ADAPTER.normalize("tool", body)
    assert body["tool_input"]["command"] == ["ls", "-la"]


def test_apply_patch_is_unmapped():
    out = ADAPTER.normalize("tool", _body("apply_patch", {"command": "*** Begin Patch"}, "D:\\p"))
    assert out["tool_name"] == "codex:apply_patch"


def test_prompt_kind_is_passed_through():
    body = {
        "session_id": "s",
        "cwd": "D:\\p",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "fix the bug",
    }
    assert ADAPTER.normalize("prompt", body) == body


# ---------------------------------------------------------------------------
# Rules parity: mapped Codex shell hits the same hard denies as Claude's Bash
# ---------------------------------------------------------------------------


def test_mapped_shell_reading_dotenv_is_denied(tmp_path):
    verdict = evaluate(_event("exec_command", {"command": "cat .env"}, str(tmp_path)))
    assert verdict.decision == "deny"


def test_mapped_shell_hits_hard_deny(tmp_path):
    cwd = str(tmp_path)
    assert evaluate(_event("Bash", {"command": "rm -rf /"}, cwd)).decision == "deny"
    assert evaluate(_event("exec_command", {"command": "rm -rf /"}, cwd)).decision == "deny"
    verdict = evaluate(_event("shell", {"command": "cat .agentwarden/policy.yaml"}, cwd))
    assert verdict.decision == "deny"
    assert evaluate(_event("Bash", {"command": "ls"}, cwd)).decision == "allow"


def test_argv_rm_rf_is_denied(tmp_path):
    event = _event("exec_command", {"command": ["rm", "-rf", "/"]}, str(tmp_path))
    assert evaluate(event).decision == "deny"


def test_codex_config_dir_is_hard_denied_regardless_of_running_agent(tmp_path):
    cwd = str(tmp_path)
    write = evaluate(
        ToolEvent.model_validate(
            _body("Write", {"file_path": ".codex/config.toml", "content": "x"}, cwd)
        )
    )
    assert write is not None and write.decision == "deny"
    shell = evaluate(ToolEvent.model_validate(_body("Bash", {"command": "rm -rf .codex"}, cwd)))
    assert shell is not None and shell.decision == "deny"
    foreign_shell = evaluate(_event("exec_command", {"command": "echo x > .codex/hooks.json"}, cwd))
    assert foreign_shell.decision == "deny"


def test_apply_patch_touching_codex_dir_is_never_allow(tmp_path):
    """apply_patch is unmapped on purpose (027 cannot carry multiple patch targets); it must
    always ask rather than guess, so it can never allow even when the patch text clearly
    targets `.codex/` or `.agentwarden/`."""
    cwd = str(tmp_path)
    patch = "*** Begin Patch\n*** Update File: .codex/config.toml\n*** End Patch"
    event = _event("apply_patch", {"command": patch}, cwd)
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision in ("deny", "ask")
    assert verdict.decision != "allow"


# apply_patch shape from learn.chatgpt.com/docs/hooks: the envelope is in tool_input.command.
def _patch(*lines: str) -> str:
    return "\n".join(["*** Begin Patch", *lines, "*** End Patch"])


@pytest.mark.parametrize(
    ("header", "tool"),
    [("Update File: src/app.py", "Edit"), ("Add File: src/new.py", "Write")],
)
def test_single_file_patch_maps_to_file_tool(header, tool):
    patch = _patch(f"*** {header}", "@@", "-a", "+b")
    out = ADAPTER.normalize("tool", _body("apply_patch", {"command": patch}, "D:\\p"))
    assert out["tool_name"] == tool
    assert out["tool_input"]["file_path"] == header.split(": ", 1)[1]
    assert out["tool_input"]["patch"] == patch
    assert out["agent_tool_name"] == "apply_patch"


@pytest.mark.parametrize(
    "patch",
    [
        _patch("*** Update File: a.py", "+x", "*** Update File: .agentwarden/policy.yaml", "+y"),
        _patch("*** Update File: a.py", "*** Move to: .codex/hooks.json", "+x"),
        _patch("***  Update File: a.py", "+x"),  # spelling we do not parse
        _patch("*** Update File: a.py", "+x", "*** Update  File: b.py"),
        _patch("*** Add File: notes.md", "+***", "+text"),  # a `***` line in content
        "no envelope at all",
    ],
)
def test_ambiguous_patch_stays_unmapped(patch):
    out = ADAPTER.normalize("tool", _body("apply_patch", {"command": patch}, "D:\\p"))
    assert out["tool_name"] == "codex:apply_patch"


def test_single_file_patch_hits_hard_denies(tmp_path):
    cwd = str(tmp_path)
    for path in (".agentwarden/policy.yaml", ".codex/hooks.json", ".env"):
        patch = _patch(f"*** Update File: {path}", "+x")
        assert evaluate(_event("apply_patch", {"command": patch}, cwd)).decision == "deny", path
    ok = evaluate(_event("apply_patch", {"command": _patch("*** Update File: src/a.py")}, cwd))
    assert ok is None or ok.decision != "deny"


def test_exec_command_cmd_field_hits_hard_deny(tmp_path):
    cwd = str(tmp_path)
    for cmd in ("rm -rf .agentwarden", "cat .env", ["rm", "-rf", "/"]):
        assert evaluate(_event("exec_command", {"cmd": cmd}, cwd)).decision == "deny", cmd


def test_apply_patch_non_dict_input_raises():
    with pytest.raises(AdapterError):
        ADAPTER.normalize("tool", _body("apply_patch", "*** Begin Patch", "D:\\p"))


def test_unmapped_tool_asks_without_model(tmp_path):
    event = _event("browser_click", {"selector": "#ok"}, str(tmp_path))
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"
    assert verdict.source == "rules"


def test_mcp_tool_asks_without_model(tmp_path):
    event = _event("mcp__fs__read_file", {"path": ".env"}, str(tmp_path))
    verdict = decide(event, provider=_ExplodingProvider())
    assert verdict.decision == "ask"


# ---------------------------------------------------------------------------
# Formatter: PreToolUse / PostToolUse schema, and the "ask" -> "deny" mapping
# ---------------------------------------------------------------------------


def _hso(raw: str) -> dict:
    return json.loads(raw)["hookSpecificOutput"]


def test_decision_output_allow():
    hso = _hso(FMT.decision_output("allow", "looks fine", None))
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "allow"
    assert hso["permissionDecisionReason"] == "looks fine"


def test_decision_output_deny():
    hso = _hso(FMT.decision_output("deny", "hard deny", None))
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "hard deny"


def test_decision_output_ask_becomes_deny():
    """Codex has no working "ask" (openai/codex#28437): an unsupported decision value is
    treated as a failed hook run and the tool call continues, i.e. behaves like allow. This
    formatter must never emit "ask"."""
    hso = _hso(FMT.decision_output("ask", "needs confirmation", None))
    assert hso["permissionDecision"] == "deny"
    assert "needs confirmation" in hso["permissionDecisionReason"]


@pytest.mark.parametrize("weird", ["", "ALLOW", "Deny", "allowed", None, 42, object()])
def test_decision_output_unknown_value_defaults_to_deny(weird):
    hso = _hso(FMT.decision_output(weird, "reason", None))
    assert hso["permissionDecision"] == "deny"


def test_decision_output_includes_system_message_in_reason():
    hso = _hso(FMT.decision_output("deny", "hard deny", "stop and ask the user"))
    assert "hard deny" in hso["permissionDecisionReason"]
    assert "stop and ask the user" in hso["permissionDecisionReason"]


def test_decision_output_truncates_long_reason():
    long_reason = "x" * 10_000
    hso = _hso(FMT.decision_output("deny", long_reason, None))
    assert len(hso["permissionDecisionReason"]) <= FMT.MAX_REASON


def test_decision_output_never_raises_on_hostile_input():
    class Hostile:
        def __str__(self):
            raise RuntimeError("boom")

    out = FMT.decision_output("deny", Hostile(), None)
    assert isinstance(out, str)
    hso = _hso(out)
    assert hso["permissionDecision"] == "deny"


def test_scan_output_schema():
    hso = _hso(FMT.scan_output("looks like a prompt injection"))
    assert hso["hookEventName"] == "PostToolUse"
    assert hso["additionalContext"] == "looks like a prompt injection"


def test_scan_output_never_raises_on_hostile_input():
    class Hostile:
        def __str__(self):
            raise RuntimeError("boom")

    out = FMT.scan_output(Hostile())
    assert isinstance(out, str)


def test_scan_output_truncates():
    out = json.loads(FMT.scan_output("y" * 10_000))
    assert len(out["hookSpecificOutput"]["additionalContext"]) <= FMT.MAX_WARNING
