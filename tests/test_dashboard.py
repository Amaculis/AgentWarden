"""Tests for the dashboard backend (spec 015): token-gated policy writes, feed filters."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from agentwarden import policy as policy_module
from agentwarden.policy import PolicyWriteError, append_rule
from tests.fixtures import BASH_PRE_TOOL_USE


def _app(tmp_path: Path):
    from agentwarden.daemon import create_app

    return create_app(db_path=tmp_path / "home" / "audit.db")


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    root = tmp_path / "proj"
    (root / ".agentwarden").mkdir(parents=True)
    return root


# ---------------------------------------------------------------------------
# append_rule
# ---------------------------------------------------------------------------


def test_append_rule_creates_file(project):
    path = project / ".agentwarden" / "policy.yaml"
    assert append_rule(path, "deny_commands", "terraform apply") is True
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data == {"version": 1, "deny_commands": ["terraform apply"]}


def test_append_rule_validates_and_preserves_file(project):
    path = project / ".agentwarden" / "policy.yaml"
    path.write_text("# team policy\n# reviewed weekly\nversion: 1\nask_commands: [npm publish]\n")
    assert append_rule(path, "ask_commands", "npm publish") is False
    assert append_rule(path, "allow_paths", "docs/") is True
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# team policy\n# reviewed weekly\n")
    data = yaml.safe_load(text)
    assert data["ask_commands"] == ["npm publish"] and data["allow_paths"] == ["docs/"]
    for kind, value in [
        ("allow_everything", "x"),
        ("deny_commands", ""),
        ("deny_commands", "a\nb"),
        ("deny_commands", "x" * 201),
    ]:
        with pytest.raises(PolicyWriteError):
            append_rule(path, kind, value)
    assert path.read_text(encoding="utf-8") == text


@pytest.mark.parametrize("bad", ["version: [unclosed\n", "- just a list\n", "deny_paths: 5\n"])
def test_append_rule_refuses_invalid_existing_file(project, bad):
    path = project / ".agentwarden" / "policy.yaml"
    path.write_text(bad, encoding="utf-8")
    with pytest.raises(PolicyWriteError):
        append_rule(path, "deny_commands", "terraform apply")
    assert path.read_text(encoding="utf-8") == bad


def test_appended_rule_takes_effect(project):
    from agentwarden.models import ToolEvent

    path = policy_module.policy_file(str(project))
    event = ToolEvent.model_validate(
        {**BASH_PRE_TOOL_USE, "cwd": str(project), "tool_input": {"command": "make deploy"}}
    )
    assert policy_module.match(policy_module.load_policy(str(project)), event) is None
    append_rule(path, "deny_commands", "make deploy")
    verdict = policy_module.match(policy_module.load_policy(str(project)), event)
    assert verdict is not None and verdict.decision == "deny"


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------


def test_ui_url_written_with_token(tmp_path):
    app = _app(tmp_path)
    with TestClient(app):
        url = (tmp_path / "home" / "ui_url").read_text(encoding="utf-8").strip()
        assert url == f"http://127.0.0.1:8765/#token={app.state.ui_token}"
        assert len(app.state.ui_token) >= 40


def test_root_serves_html_without_token(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert app.state.ui_token not in response.text


def test_policy_rules_endpoint_requires_token(tmp_path, project):
    path = project / ".agentwarden" / "policy.yaml"
    body = {"cwd": str(project), "kind": "allow_commands", "value": "rm -rf /"}
    app = _app(tmp_path)
    with TestClient(app) as client:
        assert client.post("/policy/rules", json=body).status_code == 403
        wrong = {"X-Warden-Token": "guess"}
        assert client.post("/policy/rules", json=body, headers=wrong).status_code == 403
    assert not path.exists()


def test_policy_rules_appends_and_dedups(tmp_path, project):
    body = {"cwd": str(project), "kind": "deny_commands", "value": "terraform apply"}
    app = _app(tmp_path)
    with TestClient(app) as client:
        headers = {"X-Warden-Token": app.state.ui_token}
        first = client.post("/policy/rules", json=body, headers=headers)
        second = client.post("/policy/rules", json=body, headers=headers)
        bad = client.post("/policy/rules", json={**body, "kind": "nope"}, headers=headers)
        current = client.get("/policy", params={"cwd": str(project)}).json()
    assert first.json()["added"] is True and second.json()["added"] is False
    assert bad.status_code == 400
    assert current["exists"] is True
    assert current["policy"]["deny_commands"] == ["terraform apply"]


def test_log_filter_by_decision_and_source(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as client:
        for command in ("cat .env", "python scripts/report.py", "ls"):
            event = {**BASH_PRE_TOOL_USE, "tool_input": {"command": command}}
            client.post("/decide", json=event)
        all_rows = client.get("/log").json()
        denies = client.get("/log", params={"decision": "deny"}).json()
        rules = client.get("/log", params={"source": "rules"}).json()
        newest_id = all_rows[0]["id"]
        since = client.get("/log", params={"since_id": newest_id - 1}).json()
        none_newer = client.get("/log", params={"since_id": newest_id}).json()
    assert len(all_rows) == 3
    assert {r["decision"] for r in denies} == {"deny"} and len(denies) >= 1
    assert all(r["source"] == "rules" for r in rules)
    assert [r["id"] for r in since] == [newest_id]
    assert none_newer == []


def test_scans_listing(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as client:
        app.state.store.add_scan("s1", "Read", "README.md", True, 0.9, None, 12)
        rows = client.get("/scans", params={"session_id": "s1"}).json()
    assert rows[0]["source"] == "README.md" and rows[0]["flagged"] == 1
