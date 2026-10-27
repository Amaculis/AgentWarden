"""Tests for agentwarden.decide (spec 002: no policy yet, always ask/default)."""

import pytest

from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from tests.fixtures import REAL_PRE_TOOL_USE_PAYLOADS


@pytest.mark.parametrize(
    "payload",
    REAL_PRE_TOOL_USE_PAYLOADS,
    ids=["Bash", "Read", "Write", "Edit"],
)
def test_decide_default_is_ask(payload):
    event = ToolEvent.model_validate(payload)

    verdict = decide(event)

    assert verdict.decision == "ask"
    assert verdict.source == "default"
    assert verdict.reason == "No policy configured yet."
