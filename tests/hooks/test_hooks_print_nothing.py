"""Cross-cutting check: each hook prints only what its spec allows.

`on_prompt.py` (spec 001, unchanged by spec 005): makes no decisions at all,
so stdout must always be empty, valid input or not.

`on_tool.py` (spec 005): now always makes a decision and fails closed. With
no stub daemon pointed at it (default closed-port WARDEN_URL from
`run_hook`), it must print the fail-closed ask JSON for both valid and
invalid stdin -- never silence, and never anything else.
"""

import json

import pytest

from ._support import ON_PROMPT, ON_TOOL, SAMPLE_PRE_TOOL_USE, SAMPLE_USER_PROMPT_SUBMIT, run_hook

FAILSAFE_REASON = "AgentWarden unavailable"


@pytest.mark.parametrize("stdin_kind", ["valid", "invalid"])
def test_hooks_print_nothing_on_prompt(tmp_path, stdin_kind):
    stdin_text = json.dumps(SAMPLE_USER_PROMPT_SUBMIT) if stdin_kind == "valid" else "{{{ not json"

    result = run_hook(ON_PROMPT, stdin_text, tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""


@pytest.mark.parametrize("stdin_kind", ["valid", "invalid"])
def test_on_tool_prints_only_failsafe_ask_without_daemon(tmp_path, stdin_kind):
    stdin_text = json.dumps(SAMPLE_PRE_TOOL_USE) if stdin_kind == "valid" else "{{{ not json"

    result = run_hook(ON_TOOL, stdin_text, tmp_path)  # default closed-port WARDEN_URL

    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "ask"
    assert hso["permissionDecisionReason"] == FAILSAFE_REASON
