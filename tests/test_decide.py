"""Tests for agentwarden.decide (spec 003: rules wired in, default ask otherwise)."""

import pytest

from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from tests.fixtures import BASH_PRE_TOOL_USE, EDIT_PRE_TOOL_USE, WRITE_PRE_TOOL_USE

# spec 003: no rule matches these (Bash "echo ..." is not in the safe-command
# allowlist; Write/Edit to a non-secret path inside the project is not covered
# by any built-in default) so `decide` must fall through to the new ask default.
NO_RULE_MATCH_PAYLOADS = [BASH_PRE_TOOL_USE, WRITE_PRE_TOOL_USE, EDIT_PRE_TOOL_USE]


@pytest.mark.parametrize(
    "payload",
    NO_RULE_MATCH_PAYLOADS,
    ids=["Bash", "Write", "Edit"],
)
def test_decide_default_is_ask(payload):
    event = ToolEvent.model_validate(payload)

    verdict = decide(event)

    assert verdict.decision == "ask"
    assert verdict.source == "default"
    assert verdict.reason == "No rule matched; judge not configured yet."


def test_decide_uses_rules():
    secret_read = ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": "D:\\proj",
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "D:\\proj\\.env"},
            "tool_use_id": "t1",
        }
    )
    no_match = ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": "D:\\proj",
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "tool_use_id": "t1",
        }
    )

    secret_verdict = decide(secret_read)
    assert secret_verdict.decision == "deny"
    assert secret_verdict.source == "rules"

    default_verdict = decide(no_match)
    assert default_verdict.decision == "ask"
    assert default_verdict.source == "default"
    assert default_verdict.reason == "No rule matched; judge not configured yet."
