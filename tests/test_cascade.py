"""Tests for agentwarden.cascade (spec 010). MockProvider only, no network."""

from __future__ import annotations

import json

import pytest

from agentwarden.cascade import decide_with_cascade
from agentwarden.models import ToolEvent
from agentwarden.providers.base import ProviderResult
from agentwarden.providers.mock import MockProvider


@pytest.fixture(autouse=True)
def _prompt(tmp_path, monkeypatch):
    path = tmp_path / "judge.md"
    path.write_text("Version: 1\nYou are the judge.\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", str(path))
    for name in (
        "WARDEN_CASCADE",
        "WARDEN_ESCALATE_CONFIDENCE",
        "WARDEN_ESCALATE_RISK_LOW",
        "WARDEN_ESCALATE_RISK_HIGH",
        "WARDEN_CONFIRM_DENY",
        "WARDEN_DECISION_BUDGET",
        "WARDEN_LOCAL_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)


def _event() -> ToolEvent:
    return ToolEvent(
        session_id="s1",
        cwd="D:/proj",
        hook_event_name="PreToolUse",
        tool_name="Bash",
        tool_input={"command": "python scripts/report.py"},
    )


def _out(decision: str, risk: float, confidence: float | None = None) -> str:
    data = {"decision": decision, "risk": risk, "reason": f"{decision} verdict"}
    if confidence is not None:
        data["confidence"] = confidence
    return json.dumps(data)


def test_confident_local_verdict_is_final():
    local, spark = MockProvider([_out("allow", 5, 0.95)]), MockProvider([_out("deny", 90, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decision == "allow"
    assert verdict.decided_by == "local"
    assert verdict.escalated is False
    assert spark.calls == []


def test_low_confidence_escalates_to_spark():
    local, spark = MockProvider([_out("allow", 5, 0.4)]), MockProvider([_out("deny", 90, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decision == "deny"
    assert verdict.decided_by == "spark"
    assert verdict.escalated is True
    assert verdict.local_decision == "allow"


def test_missing_confidence_escalates():
    local, spark = MockProvider([_out("allow", 5)]), MockProvider([_out("allow", 5, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decided_by == "spark"
    assert len(spark.calls) == 1


def test_mid_risk_escalates_to_spark():
    local, spark = MockProvider([_out("ask", 50, 0.9)]), MockProvider([_out("allow", 10, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decided_by == "spark"
    assert verdict.decision == "allow"


def test_confirm_deny_escalates_deny(monkeypatch):
    local = MockProvider([_out("deny", 95, 0.95)])
    spark = MockProvider([_out("ask", 60, 0.8)])
    assert decide_with_cascade(_event(), None, local, spark).decided_by == "local"
    monkeypatch.setenv("WARDEN_CONFIRM_DENY", "true")
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decided_by == "spark"
    assert verdict.local_decision == "deny"


@pytest.mark.parametrize("local_response", ["!timeout", "!connection", "!http", "not json"])
def test_local_down_escalates_to_spark(local_response):
    local, spark = MockProvider([local_response]), MockProvider([_out("allow", 5, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decision == "allow"
    assert verdict.decided_by == "spark"
    assert verdict.escalated is True
    assert verdict.local_decision is None


def test_local_unparsable_escalates():
    local = MockProvider(['{"decision": "allow", "risk": 500, "reason": "x"}'])
    spark = MockProvider([_out("ask", 40, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decided_by == "spark"


@pytest.mark.parametrize("spark_response", ["!timeout", "!connection", "garbage"])
def test_both_down_returns_ask(spark_response):
    local, spark = MockProvider(["!timeout"]), MockProvider([spark_response])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decision == "ask"
    assert verdict.source == "failsafe"


def test_no_providers_returns_ask():
    verdict = decide_with_cascade(_event(), None, None, None)
    assert verdict.decision == "ask"
    assert verdict.source == "failsafe"


def test_local_missing_goes_to_spark():
    spark = MockProvider([_out("allow", 5, 0.9)])
    verdict = decide_with_cascade(_event(), None, None, spark)
    assert verdict.decided_by == "spark"
    assert verdict.escalated is False


def test_local_only_never_calls_spark(monkeypatch):
    monkeypatch.setenv("WARDEN_CASCADE", "local_only")
    local, spark = MockProvider([_out("allow", 5, 0.3)]), MockProvider([_out("allow", 5, 0.9)])
    verdict = decide_with_cascade(_event(), None, local, spark)
    assert verdict.decision == "ask"
    assert spark.calls == []


class _SlowProvider:
    def __init__(self, clock: list[float], cost_s: float, response: str) -> None:
        self.clock, self.cost_s, self.response = clock, cost_s, response
        self.calls = 0

    def complete(self, messages, *, timeout, max_tokens):
        self.calls += 1
        self.clock[0] += self.cost_s
        return ProviderResult(text=self.response)


def test_budget_exceeded_returns_ask(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("agentwarden.cascade.time.monotonic", lambda: clock[0])
    local = _SlowProvider(clock, 6.5, _out("allow", 5, 0.2))
    spark = _SlowProvider(clock, 0.1, _out("allow", 5, 0.9))
    verdict = decide_with_cascade(_event(), None, local, spark, budget_s=7.0)
    assert verdict.decision == "ask"
    assert verdict.source == "failsafe"
    assert spark.calls == 0


def test_spark_overrunning_budget_is_ask(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("agentwarden.cascade.time.monotonic", lambda: clock[0])
    local = _SlowProvider(clock, 1.0, _out("allow", 5, 0.2))
    spark = _SlowProvider(clock, 9.0, _out("allow", 5, 0.9))
    verdict = decide_with_cascade(_event(), None, local, spark, budget_s=7.0)
    assert verdict.decision == "ask"


def test_spark_timeout_capped_by_remaining_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("agentwarden.cascade.time.monotonic", lambda: clock[0])
    seen: list[float] = []

    class _Recording(_SlowProvider):
        def complete(self, messages, *, timeout, max_tokens):
            seen.append(timeout)
            return super().complete(messages, timeout=timeout, max_tokens=max_tokens)

    local = _Recording(clock, 4.0, _out("allow", 5, 0.2))
    spark = _Recording(clock, 0.1, _out("allow", 5, 0.9))
    decide_with_cascade(_event(), None, local, spark, budget_s=7.0)
    assert seen[0] == pytest.approx(3.0)  # WARDEN_LOCAL_TIMEOUT default
    assert seen[1] == pytest.approx(3.0)  # 7 s budget - 4 s spent locally


def test_decided_by_recorded_in_log(tmp_path):
    import sqlite3

    from agentwarden.models import Verdict
    from agentwarden.store import Store

    db = tmp_path / "old.sqlite"
    conn = sqlite3.connect(db)  # a spec-002 database without the new columns
    conn.executescript(
        "CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,"
        " session_id TEXT NOT NULL, prompt_id TEXT, tool_use_id TEXT, tool_name TEXT NOT NULL,"
        " tool_input_json TEXT NOT NULL, cwd TEXT NOT NULL, decision TEXT NOT NULL,"
        " reason TEXT NOT NULL, risk REAL, source TEXT NOT NULL, latency_ms INTEGER NOT NULL);"
    )
    conn.close()
    store = Store(db)
    verdict = Verdict(
        decision="deny",
        reason="r",
        risk=0.9,
        confidence=0.8,
        source="judge",
        decided_by="spark",
        escalated=True,
        local_decision="allow",
    )
    store.add_decision(_event(), verdict, 12)
    row = store.recent_decisions(limit=1)[0]
    assert row["decided_by"] == "spark"
    assert row["escalated"] == 1
    assert row["local_decision"] == "allow"
    assert row["confidence"] == 0.8
