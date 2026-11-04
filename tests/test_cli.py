"""`agentwarden` CLI: init / uninstall / status (spec 037)."""

from __future__ import annotations

import json
import os

import pytest

from agentwarden import cli, resources


def _settings(project, name="settings.local.json"):
    return json.loads((project / ".claude" / name).read_text(encoding="utf-8"))


def _commands(data):
    return [h["command"] for groups in data["hooks"].values() for g in groups for h in g["hooks"]]


def test_init_creates_local_settings(tmp_path):
    assert cli.main(["init", str(tmp_path)]) == 0
    data = _settings(tmp_path)
    assert set(data["hooks"]) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
    assert data["hooks"]["PreToolUse"][0]["matcher"] == "*"
    assert data["hooks"]["PostToolUse"][0]["matcher"] == "Read|WebFetch"
    hooks = resources.hooks_dir().as_posix()
    commands = _commands(data)
    assert len(commands) == 3
    for script in ("on_prompt.py", "on_tool.py", "on_read.py"):
        assert any(f'"{hooks}/{script}"' in c for c in commands)
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_init_is_idempotent(tmp_path):
    cli.main(["init", str(tmp_path)])
    first = (tmp_path / ".claude" / "settings.local.json").read_bytes()
    cli.main(["init", str(tmp_path)])
    assert (tmp_path / ".claude" / "settings.local.json").read_bytes() == first


def test_init_keeps_other_settings_and_hooks(tmp_path):
    existing = {
        "permissions": {"allow": ["Bash(make:*)"]},
        "hooks": {
            "PreToolUse": [
                {"matcher": "Edit", "hooks": [{"type": "command", "command": "lint.sh"}]}
            ],
            "Stop": [{"hooks": [{"type": "command", "command": "notify.sh"}]}],
        },
    }
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text(json.dumps(existing), encoding="utf-8")
    cli.main(["init", str(tmp_path)])
    data = _settings(tmp_path)
    assert data["permissions"] == existing["permissions"]
    assert data["hooks"]["Stop"] == existing["hooks"]["Stop"]
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "lint.sh"
    assert len(data["hooks"]["PreToolUse"]) == 2


def test_init_replaces_old_repo_style_entries(tmp_path):
    old = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": 'python "${CLAUDE_PROJECT_DIR}/hooks/on_tool.py"',
                        }
                    ],
                }
            ]
        }
    }
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text(json.dumps(old), encoding="utf-8")
    cli.main(["init", str(tmp_path)])
    assert len(_settings(tmp_path)["hooks"]["PreToolUse"]) == 1


def test_init_shared_writes_settings_json(tmp_path):
    assert cli.main(["init", str(tmp_path), "--shared"]) == 0
    assert len(_commands(_settings(tmp_path, "settings.json"))) == 3
    assert not (tmp_path / ".claude" / "settings.local.json").exists()


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '{"hooks": []}'])
def test_init_invalid_json_untouched(tmp_path, content, capsys):
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text(content, encoding="utf-8")
    assert cli.main(["init", str(tmp_path)]) == 1
    assert path.read_text(encoding="utf-8") == content
    assert "left unchanged" in capsys.readouterr().err


def test_init_missing_project(tmp_path):
    assert cli.main(["init", str(tmp_path / "nope")]) == 1


def test_init_missing_hook_scripts(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, "hooks_dir", lambda: tmp_path / "empty")
    assert cli.main(["init", str(tmp_path)]) == 1
    assert not (tmp_path / ".claude").exists()


def test_uninstall_removes_only_agentwarden(tmp_path):
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    foreign = {"matcher": "Edit", "hooks": [{"type": "command", "command": "lint.sh"}]}
    path.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [foreign]}}), "utf-8")
    cli.main(["init", str(tmp_path)])
    assert cli.main(["uninstall", str(tmp_path)]) == 0
    assert _settings(tmp_path) == {"model": "x", "hooks": {"PreToolUse": [foreign]}}


def test_uninstall_drops_empty_hooks(tmp_path):
    cli.main(["init", str(tmp_path)])
    cli.main(["uninstall", str(tmp_path)])
    assert _settings(tmp_path) == {}


def test_status_daemon_down(monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("WARDEN_JUDGE", "cascade")
    monkeypatch.setenv("META_API_KEY", "sk-very-secret-value")
    monkeypatch.setenv("WARDEN_LOCAL_BASE", "http://127.0.0.1:11434/v1")
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "not running" in out
    assert "META_API_KEY: set" in out
    assert "sk-very-secret-value" not in out
    assert "11434" not in out


def test_status_cascade_without_key_explains_ask(monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("WARDEN_JUDGE", "cascade")
    monkeypatch.delenv("META_API_KEY", raising=False)
    cli.main(["status"])
    assert "unsure local verdicts become ask" in capsys.readouterr().out


@pytest.mark.skipif(os.name != "nt", reason="backslash is a path separator only on Windows")
def test_hook_command_uses_forward_slashes(tmp_path):
    command = cli.hook_command("on_tool.py", tmp_path, "C:\\Py\\python.exe")
    assert command == f'"C:/Py/python.exe" "{tmp_path.as_posix()}/on_tool.py"'


def test_prompt_path_prefers_package_then_repo(tmp_path, monkeypatch):
    package, repo = tmp_path / "pkg", tmp_path / "repo"
    (repo / "prompts").mkdir(parents=True)
    (repo / "prompts" / "judge.md").write_text("repo", encoding="utf-8")
    monkeypatch.setattr(resources, "PACKAGE_DIR", package)
    monkeypatch.setattr(resources, "REPO_ROOT", repo)
    assert resources.prompt_path("judge.md") == repo / "prompts" / "judge.md"
    (package / "prompts").mkdir(parents=True)
    (package / "prompts" / "judge.md").write_text("pkg", encoding="utf-8")
    assert resources.prompt_path("judge.md") == package / "prompts" / "judge.md"


def test_checkout_prompts_found():
    assert resources.prompt_path("judge.md").is_file()
    assert resources.prompt_path("scanner.md").is_file()
    assert (resources.hooks_dir() / "on_tool.py").is_file()


@pytest.mark.parametrize(
    "url",
    ["http://evil.example:8765", "https://127.0.0.1:8765", "http://127.0.0.1:8765/x?y=1", "::bad"],
)
def test_daemon_url_only_loopback(monkeypatch, url):
    monkeypatch.setenv("WARDEN_URL", url)
    assert cli.daemon_url() == cli.DEFAULT_URL


def test_daemon_url_custom_loopback_port(monkeypatch):
    monkeypatch.setenv("WARDEN_URL", "http://127.0.0.1:8799/")
    assert cli.daemon_url() == "http://127.0.0.1:8799"
