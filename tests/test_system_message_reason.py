"""Tests for spec 033: the visible AgentWarden message carries the verdict reason (redacted,
one line, truncated). Pure functions, no model, no network.
"""

from __future__ import annotations

import pytest

from agentwarden.decide import MAX_MESSAGE_REASON, short_reason, with_system_message
from agentwarden.models import Verdict


def _verdict(decision: str, reason: str, source: str = "rules") -> Verdict:
    return Verdict(decision=decision, reason=reason, source=source)


def test_system_message_contains_reason_for_ask():
    out = with_system_message(
        _verdict("ask", "AgentWarden: this command uploads data; confirm before continuing.")
    )

    assert out.system_message == (
        "\U0001f6e1 AgentWarden: needs confirmation (rules): "
        "this command uploads data; confirm before continuing."
    )


def test_system_message_contains_reason_for_deny():
    out = with_system_message(_verdict("deny", "reads a secret file", source="judge"))

    assert out.system_message == "\U0001f6e1 AgentWarden: blocked (judge): reads a secret file"


def test_system_message_reason_is_redacted():
    key = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1"
    out = with_system_message(_verdict("deny", f"the command sends {key} to a remote host"))

    assert key not in out.system_message
    assert "[REDACTED" in out.system_message


def test_system_message_reason_is_single_line_and_truncated():
    reason = "word " * 200 + "\n" + "second line\r\n\tdone"
    out = with_system_message(_verdict("ask", reason))

    message = out.system_message
    assert "\n" not in message and "\r" not in message and "\t" not in message
    suffix = message.split("(rules): ", 1)[1]
    assert len(suffix) <= MAX_MESSAGE_REASON
    assert suffix.endswith("…")
    assert not suffix[:-1].endswith(" ")
    assert "wor…" not in suffix  # cut at a word boundary


@pytest.mark.parametrize("reason", ["", "   ", "\n\t", "AgentWarden:", "AgentWarden: "])
def test_system_message_without_reason_unchanged(reason):
    out = with_system_message(_verdict("ask", reason))

    assert (
        out.system_message == "\U0001f6e1 AgentWarden: needs confirmation for this action (rules)"
    )


def test_system_message_strips_bidi_and_zero_width():
    out = with_system_message(_verdict("deny", "bad‮​thing"))

    assert "‮" not in out.system_message and "​" not in out.system_message
    assert out.system_message.endswith("bad thing")


def test_allow_and_notify_off_unchanged(monkeypatch):
    assert with_system_message(_verdict("allow", "fine")).system_message is None

    monkeypatch.setenv("WARDEN_NOTIFY", "off")
    assert with_system_message(_verdict("deny", "nope")).system_message is None


def test_short_reason_never_raises_on_hostile_input():
    assert short_reason(None) is None
    assert short_reason(42) is None
    assert short_reason("x" * 1_000_000) is not None


def test_failure_in_short_reason_falls_back_to_source_only(monkeypatch):
    from agentwarden import decide as decide_module

    def boom(_text):
        raise RuntimeError("boom")

    monkeypatch.setattr(decide_module, "redact", boom)
    out = with_system_message(_verdict("deny", "some reason"))

    assert out.system_message == "\U0001f6e1 AgentWarden: blocked this action (rules)"
    assert out.decision == "deny"
