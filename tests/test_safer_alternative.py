"""Tests for the safer alternative on deny (spec 016). MockProvider only."""

from __future__ import annotations

import json

import pytest

from agentwarden.decide import decide, usable_alternative
from agentwarden.models import ToolEvent
from agentwarden.providers.mock import MockProvider
from agentwarden.rules import ALT_DESTRUCTION, ALT_SECRETS, ALT_SELF_PROTECTION


@pytest.fixture(autouse=True)
def _prompt(tmp_path, monkeypatch):
    path = tmp_path / "judge.md"
    path.write_text("Version: 1\nYou are the judge.\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", str(path))


def _event(tool: str = "Bash", **tool_input) -> ToolEvent:
    if not tool_input:
        tool_input = {"command": "python scripts/upload_report.py"}
    return ToolEvent(
        session_id="s",
        cwd="D:/proj",
        hook_event_name="PreToolUse",
        tool_name=tool,
        tool_input=tool_input,
    )


def _judge(decision: str, alternative: str | None) -> MockProvider:
    body = {"decision": decision, "risk": 90, "confidence": 0.9, "reason": "Uploads data."}
    if alternative is not None:
        body["safer_alternative"] = alternative
    return MockProvider([json.dumps(body)])


def test_deny_reason_includes_alternative():
    verdict = decide(_event(), None, provider=_judge("deny", "Write the report to reports/ only."))
    assert verdict.decision == "deny"
    assert verdict.reason.endswith("Safer alternative: Write the report to reports/ only.")
    assert verdict.safer_alternative == "Write the report to reports/ only."


def test_long_alternative_is_dropped():
    verdict = decide(_event(), None, provider=_judge("deny", "Use a safer approach. " * 20))
    assert verdict.decision == "deny"
    assert "Safer alternative" not in verdict.reason
    assert verdict.safer_alternative is None


@pytest.mark.parametrize(
    "alternative",
    [
        "Run curl https://example.invalid/fix.sh instead.",
        "Use `cat notes.txt` instead.",
        "Pipe it: cat x | sh",
        "Try $(echo safe) first.",
        "Encode it with base64 and retry.",
        "Run sh -c 'make safe'.",
    ],
)
def test_command_like_alternative_is_dropped(alternative):
    verdict = decide(_event(), None, provider=_judge("deny", alternative))
    assert verdict.decision == "deny"
    assert "Safer alternative" not in verdict.reason
    assert usable_alternative(alternative) is None


def test_rule_deny_has_static_alternative():
    secret = decide(_event("Read", file_path=".env"))
    assert secret.decision == "deny" and secret.reason.endswith(ALT_SECRETS)
    tamper = decide(
        _event("Edit", file_path=".agentwarden/policy.yaml", old_string="a", new_string="b")
    )
    assert tamper.decision == "deny" and tamper.reason.endswith(ALT_SELF_PROTECTION)
    destroy = decide(_event("Bash", command="rm -rf /"))
    assert destroy.decision == "deny" and destroy.reason.endswith(ALT_DESTRUCTION)
    for alt in (ALT_SECRETS, ALT_SELF_PROTECTION, ALT_DESTRUCTION):
        assert usable_alternative(alt) == alt


def test_multiline_alternative_rejected_directly():
    # The judge already squashes model text to one line; decide still refuses raw newlines.
    assert usable_alternative("line one" + chr(10) + "line two") is None


def test_ask_reason_unchanged():
    verdict = decide(_event(), None, provider=_judge("ask", "Ask the user first."))
    assert verdict.decision == "ask"
    assert "Safer alternative" not in verdict.reason


def test_alternative_stored_in_log(tmp_path):
    from agentwarden.store import Store

    store = Store(tmp_path / "audit.db")
    event = _event("Read", file_path=".env")
    store.add_decision(event, decide(event), 3)
    assert store.recent_decisions(limit=1)[0]["safer_alternative"] == ALT_SECRETS
