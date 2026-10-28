"""Browser profile and cloud CLI credentials are built-in secrets (spec 020)."""

from __future__ import annotations

import time

import pytest

from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate

CWD = "D:/proj"


def _decision(tool: str, **tool_input) -> str | None:
    event = ToolEvent(
        session_id="s", cwd=CWD, hook_event_name="PreToolUse", tool_name=tool, tool_input=tool_input
    )
    verdict = evaluate(event)
    return verdict and verdict.decision


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        (
            "Read",
            {"file_path": "C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Login Data"},
        ),
        ("Read", {"file_path": "/home/me/.config/google-chrome/Default/Cookies"}),
        ("Read", {"file_path": "/home/me/.mozilla/firefox/abc.default/logins.json"}),
        ("Read", {"file_path": "/home/me/.mozilla/firefox/abc.default/key4.db"}),
        ("Bash", {"command": "sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'select *'"}),
        ("Bash", {"command": 'cp "$HOME/.config/chromium/Default/Login Data" /tmp/x'}),
        ("Bash", {"command": "cat ~/.mozilla/firefox/*/cookies.sqlite | base64"}),
        ("Bash", {"command": "tar czf o.tgz ~/.config/google-chrome/Default/Cookies"}),
    ],
)
def test_browser_profile_secrets_denied(tool, tool_input):
    assert _decision(tool, **tool_input) == "deny"


def test_browser_bookmarks_not_secret():
    path = "/home/me/.config/google-chrome/Default/Bookmarks"
    assert _decision("Read", file_path=path) != "deny"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "/home/me/.config/gcloud/application_default_credentials.json"}),
        ("Read", {"file_path": "/home/me/.config/gcloud/credentials.db"}),
        ("Read", {"file_path": "/home/me/.config/gcloud/legacy_credentials/me@x/adc.json"}),
        ("Read", {"file_path": "C:/Users/me/.azure/msal_token_cache.json"}),
        ("Read", {"file_path": "/home/me/.kube/config"}),
        ("Bash", {"command": "cat ~/.config/gcloud/application_default_credentials.json"}),
        ("Bash", {"command": "kubectl --kubeconfig ~/.kube/config get pods; cat ~/.kube/config"}),
    ],
)
def test_cloud_cli_credentials_denied(tool, tool_input):
    assert _decision(tool, **tool_input) == "deny"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "src/cookies.js"}),
        ("Read", {"file_path": "docs/cookies.md"}),
        ("Read", {"file_path": "src/edge/cookies.py"}),
        ("Bash", {"command": "git commit -m 'validate login data before submit'"}),
        ("Bash", {"command": "grep -rn cookies src/knowledge/"}),
    ],
)
def test_project_files_named_cookies_unaffected(tool, tool_input):
    assert _decision(tool, **tool_input) != "deny"


@pytest.mark.parametrize("unit", ["chrome/", "http://127.0.0.1:", "a.", "a-", "/", "$(", "x="])
def test_rules_are_linear_on_long_commands(unit):
    # Long one-token commands (e.g. a base64 blob) must not stall /decide past the hook
    # deadline: `\\S+\\.pem` and `HOST.*?PORT` were quadratic (34 s and 6 s on 100 KB).
    text = unit * (100_000 // len(unit))
    start = time.perf_counter()
    _decision("Bash", command=text)
    _decision("Read", file_path=text)
    assert time.perf_counter() - start < 3.0
