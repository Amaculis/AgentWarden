"""Tests for agentwarden.daemon (spec 002: /event, /decide, /log, /health)."""

import pytest
from fastapi.testclient import TestClient

from tests.fixtures import BASH_PRE_TOOL_USE, USER_PROMPT_SUBMIT


def _make_app(tmp_path):
    from agentwarden.daemon import create_app

    return create_app(db_path=tmp_path / "audit.db")


def test_health(tmp_path):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_decide_endpoint_returns_ask_and_logs(tmp_path):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/decide", json=BASH_PRE_TOOL_USE)

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ask"
        assert body["source"] == "default"

        log_response = client.get("/log", params={"session_id": BASH_PRE_TOOL_USE["session_id"]})
        assert log_response.status_code == 200
        rows = log_response.json()
        assert len(rows) == 1
        assert rows[0]["decision"] == "ask"
        assert rows[0]["tool_name"] == BASH_PRE_TOOL_USE["tool_name"]


def test_decide_invalid_json_is_ask(tmp_path):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/decide",
            content=b"not json at all {{{",
            headers={"content-type": "application/json"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ask"
        assert body["source"] == "failsafe"

        log_response = client.get("/log")
        assert log_response.json() == []


# ---------------------------------------------------------------------------
# spec 005: every /decide failsafe (deny/ask) must carry a system_message,
# via decide.py's renamed public `with_system_message`. These fail now
# (ImportError on the rename, or a bare failsafe() with no system_message)
# until spec 005 wires daemon.py's error branches through it.
# ---------------------------------------------------------------------------


def test_decide_failsafe_has_system_message(tmp_path):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/decide",
            content=b"not json at all {{{",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ask"
    assert body["source"] == "failsafe"
    assert body["system_message"] is not None
    assert body["system_message"].startswith("\U0001f6e1 AgentWarden")


def test_decide_failsafe_notify_off(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_NOTIFY", "off")
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/decide",
            content=b"not json at all {{{",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ask"
    assert body["source"] == "failsafe"
    assert body["system_message"] is None


def test_with_system_message_is_public_on_decide_module():
    import agentwarden.decide as decide_module

    assert hasattr(decide_module, "with_system_message")


def test_decide_invalid_event_is_ask(tmp_path):
    app = _make_app(tmp_path)
    payload = {**BASH_PRE_TOOL_USE}
    del payload["tool_name"]

    with TestClient(app) as client:
        response = client.post("/decide", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ask"
    assert body["source"] == "failsafe"


def test_decide_exception_is_ask(tmp_path, monkeypatch):
    import agentwarden.daemon as daemon_module

    def boom(event):
        raise RuntimeError("secret internal exception detail")

    monkeypatch.setattr(daemon_module, "decide", boom)

    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/decide", json=BASH_PRE_TOOL_USE)

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ask"
        assert body["source"] == "failsafe"
        assert "secret internal exception detail" not in body["reason"]
        assert "RuntimeError" not in body["reason"]

        log_response = client.get("/log")
        rows = log_response.json()
        assert len(rows) == 1
        assert rows[0]["source"] == "failsafe"


def test_store_failure_is_ask(tmp_path, monkeypatch):
    import agentwarden.daemon as daemon_module
    from agentwarden.models import Verdict
    from agentwarden.store import Store

    def fake_decide(event):
        return Verdict(decision="allow", reason="looks fine", risk=0.0, source="default")

    def failing_add_decision(self, event, verdict, latency_ms):
        raise OSError("disk full")

    monkeypatch.setattr(daemon_module, "decide", fake_decide)
    monkeypatch.setattr(Store, "add_decision", failing_add_decision)

    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/decide", json=BASH_PRE_TOOL_USE)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ask"
    assert body["source"] == "failsafe"


def test_event_endpoint_stores_prompt(tmp_path):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/event", json=USER_PROMPT_SUBMIT)
        assert response.status_code == 204

    from agentwarden.store import Store

    store = Store(tmp_path / "audit.db")
    prompts = store.session_prompts(USER_PROMPT_SUBMIT["session_id"])
    assert USER_PROMPT_SUBMIT["prompt"] in prompts


def test_event_invalid_is_422(tmp_path):
    app = _make_app(tmp_path)
    payload = {**USER_PROMPT_SUBMIT}
    del payload["prompt"]

    with TestClient(app) as client:
        response = client.post("/event", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize("limit", [0, 501])
def test_log_limit_bounds(tmp_path, limit):
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/log", params={"limit": limit})

    assert response.status_code == 422


def test_app_import_has_no_side_effects(tmp_path, monkeypatch):
    db_path = tmp_path / "side_effect_check" / "audit.db"
    monkeypatch.setenv("AGENTWARDEN_DB", str(db_path))

    import importlib

    import agentwarden.daemon as daemon_module

    importlib.reload(daemon_module)

    assert not db_path.exists()
    assert not db_path.parent.exists()

    with TestClient(daemon_module.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert db_path.exists()


# ---------------------------------------------------------------------------
# spec 009: the daemon builds a `SessionContext` (last prompts, last actions)
# and runs `decide()` with it in a worker thread.
# ---------------------------------------------------------------------------


def test_daemon_passes_session_context(tmp_path, monkeypatch):
    import agentwarden.decide as decide_module
    from agentwarden.providers.mock import MockProvider

    prompt_path = tmp_path / "judge.md"
    prompt_path.write_text(
        "version: 1\n\nYou are the AgentWarden judge. Decide carefully.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WARDEN_JUDGE_PROMPT", str(prompt_path))
    monkeypatch.setenv("WARDEN_JUDGE", "mock")

    held_provider = MockProvider(
        [
            '{"decision": "ask", "risk": 20, "reason": "first action"}',
            '{"decision": "ask", "risk": 20, "reason": "second action"}',
        ]
    )
    monkeypatch.setattr(decide_module, "get_provider", lambda name: held_provider)

    session_id = "session-ctx-test-1"
    prompt_payload = {
        **USER_PROMPT_SUBMIT,
        "session_id": session_id,
        "prompt": "Please build the quarterly report, distinctive-prompt-marker-xyz",
    }
    first_action = {
        **BASH_PRE_TOOL_USE,
        "session_id": session_id,
        "tool_input": {"command": "echo distinctive-first-action-marker"},
        "tool_use_id": "tool-use-1",
    }
    second_action = {
        **BASH_PRE_TOOL_USE,
        "session_id": session_id,
        "tool_input": {"command": "python scripts/build_report.py"},
        "tool_use_id": "tool-use-2",
    }

    app = _make_app(tmp_path)
    with TestClient(app) as client:
        event_response = client.post("/event", json=prompt_payload)
        assert event_response.status_code == 204

        first_response = client.post("/decide", json=first_action)
        assert first_response.status_code == 200

        second_response = client.post("/decide", json=second_action)
        assert second_response.status_code == 200

    assert len(held_provider.calls) == 2

    import json as _json

    last_call_text = _json.dumps(held_provider.calls[-1])
    assert "distinctive-prompt-marker-xyz" in last_call_text
    assert "distinctive-first-action-marker" in last_call_text


def test_context_failure_keeps_rules_deny(tmp_path, monkeypatch):
    import agentwarden.daemon as daemon_module

    def _broken(store, session_id):
        raise RuntimeError("db locked")

    monkeypatch.setattr(daemon_module, "session_context", _broken)
    event = {**BASH_PRE_TOOL_USE, "tool_name": "Read", "tool_input": {"file_path": ".env"}}
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/decide", json=event)
    assert response.status_code == 200
    assert response.json()["decision"] == "deny"
