"""Tests for agentwarden.decide (spec 003: rules wired in, default ask otherwise)."""

import pytest

from agentwarden.decide import decide
from agentwarden.models import ToolEvent
from agentwarden.providers.mock import MockProvider
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


# ---------------------------------------------------------------------------
# system_message (spec 004): deny/ask verdicts get a "AgentWarden: ... (source)"
# message for the hook to surface; allow verdicts never get one; WARDEN_NOTIFY=off
# suppresses it. `Verdict.system_message` does not exist yet, so these fail with
# an AttributeError/ValidationError until spec 004 is implemented.
# ---------------------------------------------------------------------------


def _secret_read_event() -> ToolEvent:
    return ToolEvent.model_validate(
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


def _secret_write_event() -> ToolEvent:
    return ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": "D:\\proj",
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "D:\\proj\\.env", "content": "X=1"},
            "tool_use_id": "t1",
        }
    )


def _safe_read_event() -> ToolEvent:
    return ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": "D:\\proj",
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "D:\\proj\\src\\app.py"},
            "tool_use_id": "t1",
        }
    )


def test_deny_and_ask_include_system_message():
    deny_verdict = decide(_secret_read_event())
    ask_verdict = decide(_secret_write_event())

    assert deny_verdict.decision == "deny"
    assert deny_verdict.source == "rules"
    assert deny_verdict.system_message is not None
    assert "AgentWarden" in deny_verdict.system_message
    assert deny_verdict.system_message.endswith("(rules)")

    assert ask_verdict.decision == "ask"
    assert ask_verdict.source == "rules"
    assert ask_verdict.system_message is not None
    assert "AgentWarden" in ask_verdict.system_message
    assert ask_verdict.system_message.endswith("(rules)")


def test_allow_verdict_has_no_system_message():
    verdict = decide(_safe_read_event())

    assert verdict.decision == "allow"
    assert verdict.system_message is None


def test_system_message_suppressed_when_warden_notify_off(monkeypatch):
    monkeypatch.setenv("WARDEN_NOTIFY", "off")

    verdict = decide(_secret_read_event())

    assert verdict.decision == "deny"
    assert verdict.system_message is None


def test_policy_sourced_system_message_has_policy_label(tmp_path, monkeypatch):
    policy_dir = tmp_path / ".agentwarden"
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.yaml"
    policy_file.write_text('version: 1\nask_paths:\n  - "migrations/*"\n', encoding="utf-8")
    monkeypatch.setenv("WARDEN_POLICY", str(policy_file))

    event = ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": str(tmp_path),
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(tmp_path / "migrations" / "001.sql")},
            "tool_use_id": "t1",
        }
    )

    verdict = decide(event)

    assert verdict.decision == "ask"
    assert verdict.source == "policy"
    assert verdict.system_message is not None
    assert verdict.system_message.endswith("(policy)")


# ---------------------------------------------------------------------------
# spec 009: judge thresholds and provider wiring.
# ---------------------------------------------------------------------------


def _unsettled_event() -> ToolEvent:
    return ToolEvent.model_validate(BASH_PRE_TOOL_USE)


def _write_real_judge_prompt(tmp_path) -> str:
    path = tmp_path / "judge.md"
    path.write_text(
        "version: 1\n\nYou are the AgentWarden judge. Decide carefully.\n",
        encoding="utf-8",
    )
    return str(path)


def test_judge_allow_above_risk_threshold_is_ask(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    provider = MockProvider(['{"decision": "allow", "risk": 50, "reason": "borderline"}'])

    verdict = decide(_unsettled_event(), None, provider)

    assert verdict.decision == "ask"


def test_judge_allow_low_confidence_is_ask(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    provider = MockProvider(
        ['{"decision": "allow", "risk": 10, "confidence": 0.3, "reason": "not sure"}']
    )

    verdict = decide(_unsettled_event(), None, provider)

    assert verdict.decision == "ask"


def test_judge_allow_low_risk_high_confidence_is_allow(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    provider = MockProvider(
        ['{"decision": "allow", "risk": 10, "confidence": 0.9, "reason": "looks fine"}']
    )

    verdict = decide(_unsettled_event(), None, provider)

    assert verdict.decision == "allow"


def test_rules_hard_deny_never_reaches_judge_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    provider = MockProvider(['{"decision": "allow", "risk": 1, "reason": "n/a"}'])

    verdict = decide(_secret_read_event(), None, provider)

    assert verdict.decision == "deny"
    assert verdict.source == "rules"
    assert provider.calls == []


def test_unconfigured_judge_keeps_default_ask(monkeypatch):
    monkeypatch.delenv("WARDEN_JUDGE", raising=False)

    verdict = decide(_unsettled_event(), None, None)

    assert verdict.decision == "ask"
    assert verdict.source == "default"


def test_policy_verdict_never_reaches_judge(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text('version: 1\ndeny_commands: ["terraform apply"]\n', encoding="utf-8")
    monkeypatch.setenv("WARDEN_POLICY", str(policy))
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    provider = MockProvider(['{"decision": "allow", "risk": 0, "reason": "x"}'])
    event = ToolEvent.model_validate(
        {**BASH_PRE_TOOL_USE, "tool_input": {"command": "terraform apply -auto-approve"}}
    )
    verdict = decide(event, None, provider=provider)
    assert verdict.decision == "deny"
    assert verdict.source == "policy"
    assert provider.calls == []


@pytest.mark.parametrize("bad", ["nan", "inf", "-5"])
def test_non_finite_threshold_env_falls_back(tmp_path, monkeypatch, bad):
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", _write_real_judge_prompt(tmp_path))
    monkeypatch.setenv("WARDEN_ALLOW_MAX_RISK", bad)
    provider = MockProvider(['{"decision": "allow", "risk": 50, "confidence": 0.9, "reason": "x"}'])
    assert decide(_unsettled_event(), None, provider=provider).decision == "ask"
