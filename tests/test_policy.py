"""Tests for agentwarden.policy (spec 004: user policy file).

Written against the interface the spec defines before `policy.py` exists, so the whole
module fails to collect right now (ImportError on `agentwarden.policy`) -- that is the
correct failure mode until the module is implemented. No real model, no network.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pytest

from agentwarden import policy as policy_module
from agentwarden.models import ToolEvent
from agentwarden.policy import load_policy, match
from agentwarden.rules import evaluate


@pytest.fixture(autouse=True)
def _reset_warned_invalid():
    """The "warn once per session" flag is global state; reset it per test so
    test order doesn't affect which test sees the warning."""
    policy_module._warned_invalid = False
    yield
    policy_module._warned_invalid = False


# ---------------------------------------------------------------------------
# Helpers (same shape as tests/test_rules.py)
# ---------------------------------------------------------------------------


def _event(tool_name: str, tool_input: dict, cwd: str) -> ToolEvent:
    return ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": cwd,
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "t1",
        }
    )


def _read(path: str, cwd: str) -> ToolEvent:
    return _event("Read", {"file_path": path}, cwd=cwd)


def _bash(command: str, cwd: str) -> ToolEvent:
    return _event("Bash", {"command": command}, cwd=cwd)


def _webfetch(url: str, cwd: str = "D:\\proj") -> ToolEvent:
    return _event("WebFetch", {"url": url}, cwd=cwd)


def _write_policy(root: Path, text: str) -> Path:
    policy_dir = root / ".agentwarden"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_file = policy_dir / "policy.yaml"
    policy_file.write_text(text, encoding="utf-8")
    return policy_file


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------


def test_policy_deny_path_blocks(tmp_path):
    _write_policy(tmp_path, 'version: 1\ndeny_paths:\n  - "secrets/*"\n')
    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "policy"


def test_policy_ask_path_asks(tmp_path):
    _write_policy(tmp_path, 'version: 1\nask_paths:\n  - "migrations/*"\n')
    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "migrations" / "001.sql"), cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.source == "policy"


def test_policy_allow_path_allows(tmp_path):
    _write_policy(tmp_path, 'version: 1\nallow_paths:\n  - "docs/*"\n')
    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "docs" / "readme.md"), cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.source == "policy"


def test_policy_path_not_matched_returns_none(tmp_path):
    _write_policy(tmp_path, 'version: 1\ndeny_paths:\n  - "secrets/*"\n')
    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "src" / "app.py"), cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is None


# ---------------------------------------------------------------------------
# Command matching (prefix, after whitespace normalisation)
# ---------------------------------------------------------------------------


def test_policy_deny_command_denies(tmp_path):
    _write_policy(tmp_path, 'version: 1\ndeny_commands:\n  - "terraform apply"\n')
    policy = load_policy(str(tmp_path))

    event = _bash("terraform apply -auto-approve", cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "policy"


def test_policy_deny_command_matches_after_whitespace_normalisation(tmp_path):
    _write_policy(tmp_path, 'version: 1\ndeny_commands:\n  - "terraform apply"\n')
    policy = load_policy(str(tmp_path))

    event = _bash("terraform   apply   -auto-approve", cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "deny"


def test_policy_ask_command_asks(tmp_path):
    _write_policy(tmp_path, 'version: 1\nask_commands:\n  - "npm publish"\n')
    policy = load_policy(str(tmp_path))

    event = _bash("npm publish --access public", cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.source == "policy"


def test_policy_allow_command_allows(tmp_path):
    _write_policy(tmp_path, 'version: 1\nallow_commands:\n  - "make test"\n')
    policy = load_policy(str(tmp_path))

    event = _bash("make test -v", cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.source == "policy"


def test_policy_command_not_matched_returns_none(tmp_path):
    _write_policy(tmp_path, 'version: 1\ndeny_commands:\n  - "terraform apply"\n')
    policy = load_policy(str(tmp_path))

    event = _bash("terraform plan", cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is None


# ---------------------------------------------------------------------------
# Domain matching -- WebFetch `url` only
# ---------------------------------------------------------------------------


def test_policy_allow_domain_matches_exact_host(tmp_path):
    _write_policy(tmp_path, 'version: 1\nallow_domains:\n  - "github.com"\n')
    policy = load_policy(str(tmp_path))

    verdict = match(policy, _webfetch("https://github.com/org/repo"))

    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.source == "policy"


def test_policy_allow_domain_matches_subdomain(tmp_path):
    _write_policy(tmp_path, 'version: 1\nallow_domains:\n  - "github.com"\n')
    policy = load_policy(str(tmp_path))

    verdict = match(policy, _webfetch("https://api.github.com/repos"))

    assert verdict is not None
    assert verdict.decision == "allow"


def test_policy_allow_domain_does_not_match_unrelated_host(tmp_path):
    _write_policy(tmp_path, 'version: 1\nallow_domains:\n  - "github.com"\n')
    policy = load_policy(str(tmp_path))

    verdict = match(policy, _webfetch("https://notgithub.com/org/repo"))

    assert verdict is None


def test_policy_allow_domain_not_applied_to_bash(tmp_path):
    """allow_domains only applies to WebFetch's `url` field, not Bash commands."""
    _write_policy(tmp_path, 'version: 1\nallow_domains:\n  - "pypi.org"\n')
    policy = load_policy(str(tmp_path))

    verdict = match(policy, _bash("curl https://pypi.org/simple", cwd=str(tmp_path)))

    assert verdict is None


# ---------------------------------------------------------------------------
# Missing / invalid policy files
# ---------------------------------------------------------------------------


def test_policy_missing_file_uses_defaults(tmp_path):
    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "anything.txt"), cwd=str(tmp_path))
    verdict = match(policy, event)

    assert verdict is None


def test_policy_unreadable_file_uses_defaults(tmp_path):
    """A file that exists (so `getmtime` succeeds) but can't be read as text --
    e.g. a permissions issue or a race -- falls back to defaults, never allow-all."""
    policy_dir = tmp_path / ".agentwarden"
    policy_dir.mkdir()
    # A directory where the policy file is expected: `open()` raises OSError.
    (policy_dir / "policy.yaml").mkdir()

    policy = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))
    assert match(policy, event) is None


def test_invalid_policy_uses_defaults_and_warns(tmp_path, caplog):
    _write_policy(tmp_path, "deny_paths: not_a_list\nallow_commands: 42\n:::not yaml:::\n")

    with caplog.at_level(logging.WARNING):
        policy = load_policy(str(tmp_path))

    # Falls back to an empty/default policy -- never allow-all, never crashes.
    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))
    assert match(policy, event) is None

    assert len(caplog.records) >= 1
    assert any(
        "invalid" in r.message.lower() or "policy" in r.message.lower() for r in caplog.records
    )

    # A second load (mtime changed, content still invalid) must not warn again
    # in the same session.
    caplog.clear()
    time.sleep(0.05)
    os.utime(tmp_path / ".agentwarden" / "policy.yaml", None)
    with caplog.at_level(logging.WARNING):
        load_policy(str(tmp_path))

    assert len(caplog.records) == 0


# ---------------------------------------------------------------------------
# Reload on change
# ---------------------------------------------------------------------------


def test_policy_reload_on_change(tmp_path):
    policy_file = _write_policy(tmp_path, "version: 1\ndeny_paths: []\n")
    policy_before = load_policy(str(tmp_path))

    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))
    assert match(policy_before, event) is None

    time.sleep(0.05)
    policy_file.write_text('version: 1\ndeny_paths:\n  - "secrets/*"\n', encoding="utf-8")
    future = time.time() + 5
    os.utime(policy_file, (future, future))

    policy_after = load_policy(str(tmp_path))
    verdict = match(policy_after, event)

    assert verdict is not None
    assert verdict.decision == "deny"


# ---------------------------------------------------------------------------
# WARDEN_POLICY env override and path_override argument
# ---------------------------------------------------------------------------


def test_load_policy_path_override_argument(tmp_path):
    custom = tmp_path / "custom-policy.yaml"
    custom.write_text('version: 1\ndeny_paths:\n  - "secrets/*"\n', encoding="utf-8")

    policy = load_policy(str(tmp_path), path_override=str(custom))
    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))

    assert match(policy, event) is not None
    assert match(policy, event).decision == "deny"


def test_load_policy_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom-policy.yaml"
    custom.write_text('version: 1\ndeny_paths:\n  - "secrets/*"\n', encoding="utf-8")
    monkeypatch.setenv("WARDEN_POLICY", str(custom))

    policy = load_policy(str(tmp_path))
    event = _read(str(tmp_path / "secrets" / "api_key.txt"), cwd=str(tmp_path))

    verdict = match(policy, event)
    assert verdict is not None
    assert verdict.decision == "deny"


# ---------------------------------------------------------------------------
# Policy can never weaken hard denies (integration with rules.evaluate)
# ---------------------------------------------------------------------------


def test_policy_allow_cannot_override_builtin_secret_deny(tmp_path, monkeypatch):
    policy_file = _write_policy(
        tmp_path,
        'version: 1\nallow_paths:\n  - ".env"\n  - "*.env"\nallow_commands:\n  - "cat"\n',
    )
    monkeypatch.setenv("WARDEN_POLICY", str(policy_file))

    read_verdict = evaluate(_read(str(tmp_path / ".env"), cwd=str(tmp_path)))
    bash_verdict = evaluate(_bash("cat .env", cwd=str(tmp_path)))

    assert read_verdict is not None
    assert read_verdict.decision == "deny"
    assert read_verdict.source == "rules"

    assert bash_verdict is not None
    assert bash_verdict.decision == "deny"
    assert bash_verdict.source == "rules"


def test_policy_allow_cannot_override_self_protection(tmp_path, monkeypatch):
    policy_file = _write_policy(
        tmp_path,
        'version: 1\nallow_paths:\n  - ".agentwarden/"\nallow_commands:\n  - "curl"\n',
    )
    monkeypatch.setenv("WARDEN_POLICY", str(policy_file))

    edit_policy_verdict = evaluate(
        _read(str(tmp_path / ".agentwarden" / "policy.yaml"), cwd=str(tmp_path))
    )
    curl_daemon_verdict = evaluate(_bash("curl http://127.0.0.1:8765/decide", cwd=str(tmp_path)))

    assert edit_policy_verdict is not None
    assert edit_policy_verdict.decision == "deny"
    assert edit_policy_verdict.source == "rules"

    assert curl_daemon_verdict is not None
    assert curl_daemon_verdict.decision == "deny"
    assert curl_daemon_verdict.source == "rules"


# ---------------------------------------------------------------------------
# Policy stage sits between hard denies and built-in defaults
# ---------------------------------------------------------------------------


def test_policy_deny_wins_via_evaluate(tmp_path, monkeypatch):
    policy_file = _write_policy(tmp_path, 'version: 1\ndeny_paths:\n  - "infra/*"\n')
    monkeypatch.setenv("WARDEN_POLICY", str(policy_file))

    verdict = evaluate(_read(str(tmp_path / "infra" / "prod.tf"), cwd=str(tmp_path)))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "policy"
