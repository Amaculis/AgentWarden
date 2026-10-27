"""Tests for agentwarden.models (spec 002)."""

import pytest
from pydantic import ValidationError

from agentwarden.models import PromptEvent, ToolEvent, Verdict
from tests.fixtures import REAL_PRE_TOOL_USE_PAYLOADS, USER_PROMPT_SUBMIT


@pytest.mark.parametrize(
    "payload",
    REAL_PRE_TOOL_USE_PAYLOADS,
    ids=["Bash", "Read", "Write", "Edit"],
)
def test_tool_event_accepts_real_payloads(payload):
    event = ToolEvent.model_validate(payload)

    assert event.session_id == payload["session_id"]
    assert event.cwd == payload["cwd"]
    assert event.hook_event_name == "PreToolUse"
    assert event.tool_name == payload["tool_name"]
    assert event.tool_input == payload["tool_input"]
    assert event.tool_use_id == payload["tool_use_id"]

    # Extras present on real captures must be accepted and ignored, not raise.
    assert not hasattr(event, "scratchpad_dir")
    assert not hasattr(event, "effort")
    assert not hasattr(event, "transcript_path")


def test_prompt_event_accepts_real_payload():
    event = PromptEvent.model_validate(USER_PROMPT_SUBMIT)

    assert event.session_id == USER_PROMPT_SUBMIT["session_id"]
    assert event.hook_event_name == "UserPromptSubmit"
    assert event.prompt == USER_PROMPT_SUBMIT["prompt"]
    assert event.cwd == USER_PROMPT_SUBMIT["cwd"]

    # Extras (scratchpad_dir, transcript_path) must be ignored, not raise.
    assert not hasattr(event, "scratchpad_dir")
    assert not hasattr(event, "transcript_path")


@pytest.mark.parametrize("risk", [-0.1, 1.1])
def test_verdict_risk_bounds(risk):
    with pytest.raises(ValidationError):
        Verdict(decision="ask", reason="x", risk=risk, source="default")


@pytest.mark.parametrize("risk", [0.0, 0.5, 1.0, None])
def test_verdict_risk_bounds_allows_valid_values(risk):
    verdict = Verdict(decision="ask", reason="x", risk=risk, source="default")
    assert verdict.risk == risk
