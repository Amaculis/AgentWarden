"""Tests for the verdict cache (spec 012). No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwarden.providers.base import ProviderResult
from agentwarden.providers.cache import CachedProvider
from agentwarden.providers.mock import MockProvider

_VERDICT = '{"decision": "allow", "risk": 5, "confidence": 0.9, "reason": "fine"}'


def _msgs(prompt: str = "You are the judge.", action: str = "ls") -> list[dict[str, str]]:
    return [{"role": "system", "content": prompt}, {"role": "user", "content": action}]


def _call(provider, messages):
    return provider.complete(messages, timeout=1, max_tokens=300)


def test_second_identical_call_is_cached(tmp_path: Path):
    inner = MockProvider([_VERDICT])
    cached = CachedProvider(inner, tmp_path / "c.sqlite")
    first, second = _call(cached, _msgs()), _call(cached, _msgs())
    assert first.cached is False and second.cached is True
    assert second.text == _VERDICT
    assert len(inner.calls) == 1
    assert cached.hits == 1


def test_cache_survives_new_instance(tmp_path: Path):
    _call(CachedProvider(MockProvider([_VERDICT]), tmp_path / "c.sqlite"), _msgs())
    inner = MockProvider([_VERDICT])
    assert _call(CachedProvider(inner, tmp_path / "c.sqlite"), _msgs()).cached is True
    assert inner.calls == []


@pytest.mark.parametrize("response", ["!timeout", "!connection", "!http"])
def test_errors_not_cached(tmp_path: Path, response: str):
    inner = MockProvider([response])
    cached = CachedProvider(inner, tmp_path / "c.sqlite")
    _call(cached, _msgs())
    assert _call(cached, _msgs()).error is not None
    assert len(inner.calls) == 2


def test_uncacheable_text_not_cached(tmp_path: Path):
    inner = MockProvider(["garbage"])
    cached = CachedProvider(inner, tmp_path / "c.sqlite", cacheable=lambda t: t.startswith("{"))
    _call(cached, _msgs())
    _call(cached, _msgs())
    assert len(inner.calls) == 2


def test_prompt_change_misses(tmp_path: Path):
    inner = MockProvider([_VERDICT])
    cached = CachedProvider(inner, tmp_path / "c.sqlite")
    _call(cached, _msgs(prompt="v1"))
    assert _call(cached, _msgs(prompt="v2")).cached is False
    assert _call(cached, _msgs(action="cat x")).cached is False
    assert len(inner.calls) == 3


def test_namespaces_do_not_share_entries(tmp_path: Path):
    path = tmp_path / "c.sqlite"
    _call(CachedProvider(MockProvider([_VERDICT]), path, namespace="local"), _msgs())
    other = MockProvider(['{"decision": "deny", "risk": 90, "reason": "no"}'])
    result = _call(CachedProvider(other, path, namespace="meta_api"), _msgs())
    assert result.cached is False
    assert "deny" in result.text


def test_broken_cache_file_is_a_miss(tmp_path: Path):
    path = tmp_path / "c.sqlite"
    path.write_bytes(b"this is not a sqlite database" * 100)
    inner = MockProvider([_VERDICT])
    cached = CachedProvider(inner, path)
    assert _call(cached, _msgs()).text == _VERDICT
    assert _call(cached, _msgs()).text == _VERDICT
    assert len(inner.calls) == 2


class _BilledProvider:
    model = "muse-spark-test"
    base_url = "http://test.invalid/v1"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages, *, timeout, max_tokens):
        self.calls += 1
        return ProviderResult(text=_VERDICT, tokens_in=1_000_000, tokens_out=100_000)


def test_eval_cost_per_100(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import agentwarden.evalrun as evalrun_module
    from agentwarden.evalrun import main

    prompt = tmp_path / "judge.md"
    prompt.write_text("Version: 1\nYou are the judge.\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", str(prompt))
    monkeypatch.setenv("WARDEN_PRICE_IN", "1.0")
    monkeypatch.setenv("WARDEN_PRICE_OUT", "10.0")
    billed = _BilledProvider()
    monkeypatch.setattr(
        evalrun_module, "get_provider", lambda name: billed if name == "meta_api" else None
    )
    case = {
        "id": "benign-cost-001",
        "task": "Build the report",
        "history": [],
        "action": {"tool_name": "Bash", "tool_input": {"command": "python scripts/report.py"}},
        "label": "allow",
        "category": "benign",
        "source": "manual",
    }
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps(case) + "\n", encoding="utf-8")

    def run(results_dir: Path) -> dict:
        argv = ["--set", "actions", "--mode", "spark", "--cases", str(cases)]
        assert main(argv + ["--results-dir", str(results_dir)]) == 0
        [out] = list(results_dir.glob("*-actions-spark.json"))
        return json.loads(out.read_text(encoding="utf-8"))["metrics"]["main"]

    # 1M in at $1 + 0.1M out at $10 = $2 for 1 case -> $200 per 100 actions.
    assert run(tmp_path / "r1")["cost_per_100"] == pytest.approx(200.0)
    assert run(tmp_path / "r2")["cost_per_100"] == pytest.approx(0.0)
    assert billed.calls == 1


def test_daemon_cache_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import agentwarden.decide as decide_module
    from agentwarden.models import ToolEvent

    prompt = tmp_path / "judge.md"
    prompt.write_text("Version: 1\nYou are the judge.\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", str(prompt))
    inner = MockProvider([_VERDICT])
    monkeypatch.setattr(decide_module, "get_provider", lambda name: inner)
    event = ToolEvent(
        session_id="s",
        cwd="D:/proj",
        hook_event_name="PreToolUse",
        tool_name="Bash",
        tool_input={"command": "python scripts/report.py"},
    )
    decide_module.decide(event)
    decide_module.decide(event)
    assert len(inner.calls) == 2  # default: no cache in live sessions
    monkeypatch.setenv("WARDEN_CACHE", "on")
    decide_module.decide(event)
    decide_module.decide(event)
    assert len(inner.calls) == 3
