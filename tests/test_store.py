"""Tests for agentwarden.store (spec 002: SQLite audit log)."""

from agentwarden.models import PromptEvent, ToolEvent, Verdict
from agentwarden.store import Store
from tests.fixtures import BASH_PRE_TOOL_USE, READ_PRE_TOOL_USE, USER_PROMPT_SUBMIT


def _tool_event(payload, **overrides):
    data = {**payload, **overrides}
    return ToolEvent.model_validate(data)


def _prompt_event(payload, **overrides):
    data = {**payload, **overrides}
    return PromptEvent.model_validate(data)


def test_store_roundtrip(tmp_path):
    store = Store(tmp_path / "audit.db")

    event_a = _tool_event(BASH_PRE_TOOL_USE, session_id="s1")
    verdict_a = Verdict(
        decision="ask", reason="No policy configured yet.", risk=None, source="default"
    )
    store.add_decision(event_a, verdict_a, latency_ms=1)

    event_b = _tool_event(READ_PRE_TOOL_USE, session_id="s2")
    verdict_b = Verdict(
        decision="ask", reason="No policy configured yet.", risk=0.3, source="default"
    )
    store.add_decision(event_b, verdict_b, latency_ms=2)

    all_rows = store.recent_decisions(limit=50)
    assert len(all_rows) == 2
    # Newest first.
    assert all_rows[0]["session_id"] == "s2"
    assert all_rows[1]["session_id"] == "s1"

    # tool_input decoded back to a dict, not a JSON string.
    assert all_rows[0]["tool_input"] == READ_PRE_TOOL_USE["tool_input"]
    assert isinstance(all_rows[0]["tool_input"], dict)

    # limit filter.
    limited = store.recent_decisions(limit=1)
    assert len(limited) == 1
    assert limited[0]["session_id"] == "s2"

    # session_id filter.
    filtered = store.recent_decisions(limit=50, session_id="s1")
    assert len(filtered) == 1
    assert filtered[0]["session_id"] == "s1"


def test_store_session_prompts(tmp_path):
    store = Store(tmp_path / "audit.db")

    store.add_prompt(_prompt_event(USER_PROMPT_SUBMIT, session_id="s1", prompt="first"))
    store.add_prompt(_prompt_event(USER_PROMPT_SUBMIT, session_id="s1", prompt="second"))
    store.add_prompt(_prompt_event(USER_PROMPT_SUBMIT, session_id="s2", prompt="other session"))

    prompts = store.session_prompts("s1")

    assert prompts == ["first", "second"]  # oldest first

    other = store.session_prompts("s2")
    assert other == ["other session"]

    empty = store.session_prompts("unknown-session")
    assert empty == []
