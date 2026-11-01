"""Tests for spec 025 (project boundary and directory grants).

Written against the interface the spec defines before the implementation exists:
`rules.evaluate(event, extra_roots=())`, `rules.command_path_tokens`,
`policy.match_deny` / `policy.match_rest`, `Policy.extra_roots`, `Verdict.grant_dir`,
`decide.decide(..., extra_roots=())`. No real model, no network -- rules/policy are
pure functions, no filesystem access beyond reading a policy.yaml the test itself wrote.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from agentwarden import policy as policy_module
from agentwarden.models import ToolEvent
from agentwarden.policy import Policy, load_policy, match, match_deny, match_rest
from agentwarden.rules import command_path_tokens, evaluate

PROJECT = "D:\\proj"


@pytest.fixture(autouse=True)
def _reset_warned_invalid():
    """Mirrors tests/test_policy.py: the warn-once flag is global state."""
    policy_module._warned_invalid = False
    yield
    policy_module._warned_invalid = False


# ---------------------------------------------------------------------------
# Helpers (same shape as tests/test_rules.py)
# ---------------------------------------------------------------------------


def _event(tool_name: str, tool_input: dict, cwd: str = PROJECT) -> ToolEvent:
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


def _read(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Read", {"file_path": path}, cwd=cwd)


def _write(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Write", {"file_path": path}, cwd=cwd)


def _edit(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}, cwd=cwd)


def _bash(command: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Bash", {"command": command}, cwd=cwd)


def _grep(path: str | None = None, glob: str | None = None, cwd: str = PROJECT) -> ToolEvent:
    tool_input: dict = {"pattern": "x"}
    if path is not None:
        tool_input["path"] = path
    if glob is not None:
        tool_input["glob"] = glob
    return _event("Grep", tool_input, cwd=cwd)


def _glob(path: str | None = None, pattern: str = "*", cwd: str = PROJECT) -> ToolEvent:
    tool_input: dict = {"pattern": pattern}
    if path is not None:
        tool_input["path"] = path
    return _event("Glob", tool_input, cwd=cwd)


def _write_policy(root: Path, text: str) -> Path:
    policy_dir = root / ".agentwarden"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_file = policy_dir / "policy.yaml"
    policy_file.write_text(text, encoding="utf-8")
    return policy_file


def _norm(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").lower()


# ---------------------------------------------------------------------------
# Boundary stage -- Grep/Glob (deny)
# ---------------------------------------------------------------------------


def test_glob_absolute_pattern_outside_denied():
    verdict = evaluate(_glob(pattern="C:/Users/**/*.docx"))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert "outside the project" in verdict.reason
    assert verdict.grant_dir is not None
    assert "c:/users" in _norm(verdict.grant_dir)


def test_grep_path_outside_denied():
    verdict = evaluate(_grep(path="C:\\Users\\other"))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.grant_dir is not None
    assert _norm(verdict.grant_dir) == _norm("C:\\Users\\other")


def test_glob_relative_pattern_inside_allowed():
    verdict = evaluate(_glob(pattern="src/**/*.py"))

    assert verdict is not None
    assert verdict.decision == "allow"


# ---------------------------------------------------------------------------
# Boundary stage -- Read/Write/Edit (ask)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["~/.gitconfig", "../other/x"])
@pytest.mark.parametrize("builder", [_read, _write, _edit])
def test_read_write_edit_outside_ask(builder, path):
    verdict = builder(path)
    verdict = evaluate(verdict)

    assert verdict is not None
    assert verdict.decision == "ask"
    assert "outside the project" in verdict.reason
    assert verdict.grant_dir is not None


# ---------------------------------------------------------------------------
# Boundary stage -- Bash / PowerShell
# ---------------------------------------------------------------------------

BASH_LISTING_OUTSIDE_DENIED = [
    "ls C:/Users",
    "find /etc -name x",
    "Get-ChildItem C:\\Users -Recurse",
    "rg foo ../other",
]


@pytest.mark.parametrize("command", BASH_LISTING_OUTSIDE_DENIED)
def test_bash_listing_outside_denied(command):
    verdict = evaluate(_bash(command))

    assert verdict is not None
    assert verdict.decision == "deny"


BASH_PATH_OUTSIDE_ASK = [
    "cat ../other/x.py",
    "cp a.txt /tmp/a.txt",
]


@pytest.mark.parametrize("command", BASH_PATH_OUTSIDE_ASK)
def test_bash_path_outside_ask(command):
    verdict = evaluate(_bash(command))

    assert verdict is not None
    assert verdict.decision == "ask"


BASH_UNCHANGED_EXPECTED = {
    "ls src": "allow",
    "pytest tests/": "allow",
    "cmd 2>/dev/null": None,
    "git log origin/main": "allow",
    "C:/Python312/python.exe x.py": None,
}


@pytest.mark.parametrize("command", list(BASH_UNCHANGED_EXPECTED))
def test_bash_inside_and_device_tokens_unchanged(command):
    verdict = evaluate(_bash(command))
    expected = BASH_UNCHANGED_EXPECTED[command]

    if expected is None:
        assert verdict is None
    else:
        assert verdict is not None
        assert verdict.decision == expected


def test_bash_unresolved_variable_path_outside():
    for command in ("cat $FOO/x", "cat /tmp/$X/y"):
        verdict = evaluate(_bash(command))
        assert verdict is not None, command
        assert verdict.decision == "ask", command
        assert verdict.grant_dir is None, command


# ---------------------------------------------------------------------------
# grant_dir <-> reason agreement
# ---------------------------------------------------------------------------


def test_boundary_reason_names_dashboard_grant():
    verdict = evaluate(_read("C:\\Users\\a\\file.txt"))

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.grant_dir is not None
    assert _norm(verdict.grant_dir) in _norm(verdict.reason)
    assert "ask the user to grant" in verdict.reason
    assert "AgentWarden dashboard" in verdict.reason

    unresolved = evaluate(_bash("cat $FOO/x"))
    assert unresolved is not None
    assert unresolved.grant_dir is None


# ---------------------------------------------------------------------------
# command_path_tokens -- (command_word, token) pairs
# ---------------------------------------------------------------------------


def test_command_path_tokens_pairs_exclude_command_word():
    pairs = command_path_tokens("C:/Python312/python.exe x.py")

    assert ("C:/Python312/python.exe", "x.py") in pairs or any(
        token == "x.py" for _cmd, token in pairs
    )
    assert all(token != "C:/Python312/python.exe" for _cmd, token in pairs)


# ---------------------------------------------------------------------------
# policy.match == match_deny or match_rest
# ---------------------------------------------------------------------------

_SPLIT_POLICY = Policy(
    deny_paths=["secrets/", "*.pem"],
    ask_paths=["migrations/", "infra/"],
    allow_paths=["docs/"],
    deny_commands=["terraform apply"],
    ask_commands=["npm publish"],
    allow_commands=["make test"],
    allow_domains=["github.com"],
)

_SPLIT_READ_ONLY_POLICY = Policy(mode="read_only")


@pytest.mark.parametrize(
    "event",
    [
        _read("secrets/api_key.txt"),
        _read("migrations/001.sql"),
        _read("docs/readme.md"),
        _read("src/app.py"),
        _bash("terraform apply -auto-approve"),
        _bash("npm publish --access public"),
        _bash("make test -v"),
        _bash("echo hi"),
        _event("WebFetch", {"url": "https://github.com/org/repo"}),
        _event("WebFetch", {"url": "https://notgithub.com/org/repo"}),
    ],
)
def test_policy_match_split_equivalent(event):
    combined = match(_SPLIT_POLICY, event)
    split = match_deny(_SPLIT_POLICY, event) or match_rest(_SPLIT_POLICY, event)

    assert combined == split


@pytest.mark.parametrize(
    "event",
    [
        _read("src/app.py"),
        _edit("src/app.py"),
        _bash("ls"),
    ],
)
def test_policy_match_split_equivalent_read_only(event):
    combined = match(_SPLIT_READ_ONLY_POLICY, event)
    split = match_deny(_SPLIT_READ_ONLY_POLICY, event) or match_rest(_SPLIT_READ_ONLY_POLICY, event)

    assert combined == split


# ---------------------------------------------------------------------------
# extra_roots from the policy file
# ---------------------------------------------------------------------------


def test_extra_roots_from_policy_allow_inside(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    project = tmp_path / "proj"
    shared = tmp_path / "shared"
    _write_policy(project, f'version: 1\nextra_roots:\n  - "{shared.as_posix()}"\n')

    event = _read(str(shared / "file.txt"), cwd=str(project))
    verdict = evaluate(event)

    assert verdict is not None
    assert verdict.decision == "allow"


def test_extra_roots_rejects_relative_and_fs_root(tmp_path, caplog):
    shared = tmp_path / "shared"
    _write_policy(
        tmp_path,
        "version: 1\nextra_roots:\n"
        '  - "relative/dir"\n'
        '  - "/"\n'
        '  - "C:\\\\"\n'
        f'  - "{shared.as_posix()}"\n',
    )

    with caplog.at_level(logging.WARNING):
        policy = load_policy(str(tmp_path))

    assert len(policy.extra_roots) == 1
    assert _norm(policy.extra_roots[0]) == _norm(str(shared))
    assert any("root" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# extra_roots passed directly to evaluate() (session grants)
# ---------------------------------------------------------------------------


def test_session_root_widens_boundary(tmp_path):
    granted = tmp_path / "shared"
    event = _read(str(granted / "file.txt"))

    before = evaluate(event)
    after = evaluate(event, extra_roots=[str(granted)])

    assert before is not None
    assert before.decision == "ask"
    assert after is not None
    assert after.decision == "allow"


def test_granted_root_keeps_hard_denies(tmp_path):
    granted = tmp_path / "shared"

    ssh_key = evaluate(_read(str(granted / ".ssh" / "id_rsa")), extra_roots=[str(granted)])
    env_file = evaluate(_read(str(granted / ".env")), extra_roots=[str(granted)])

    assert ssh_key is not None
    assert ssh_key.decision == "deny"
    assert env_file is not None
    assert env_file.decision == "deny"


# ---------------------------------------------------------------------------
# Order: hard deny -> boundary deny -> policy deny -> boundary ask -> rest -> defaults
# ---------------------------------------------------------------------------


def test_policy_allow_cannot_cross_boundary(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    _write_policy(tmp_path, 'version: 1\nallow_commands:\n  - "ls"\n')

    verdict = evaluate(_bash("ls C:/Users", cwd=str(tmp_path)))

    assert verdict is not None
    assert verdict.decision == "deny"


def test_policy_deny_beats_boundary_ask(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    _write_policy(tmp_path, 'version: 1\ndeny_commands:\n  - "cp"\n')

    verdict = evaluate(_bash("cp a.txt /tmp/a.txt", cwd=str(tmp_path)))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.source == "policy"


def test_read_only_mode_outside_read(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    _write_policy(tmp_path, "version: 1\nmode: read_only\n")

    verdict = evaluate(_read("C:\\Users\\a\\file.txt", cwd=str(tmp_path)))

    assert verdict is not None
    assert verdict.decision == "ask"
    assert "outside the project" in verdict.reason


# ---------------------------------------------------------------------------
# Boundary ask is a ceiling: the judge still runs and may only tighten it
# ---------------------------------------------------------------------------


def _judge_out(decision: str, risk: int) -> str:
    import json

    return json.dumps({"decision": decision, "risk": risk, "confidence": 0.9, "reason": "r"})


def test_boundary_ask_judge_deny_wins(monkeypatch):
    from agentwarden import decide as decide_module
    from agentwarden.providers.mock import MockProvider

    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    provider = MockProvider([_judge_out("deny", 90)])
    verdict = decide_module.decide(_edit("~/.bashrc"), None, provider)

    assert verdict.decision == "deny"
    assert len(provider.calls) == 1


@pytest.mark.parametrize("judge_reply", [_judge_out("allow", 5), "!timeout", "not json"])
def test_boundary_ask_judge_cannot_loosen(monkeypatch, judge_reply):
    from agentwarden import decide as decide_module
    from agentwarden.providers.mock import MockProvider

    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    provider = MockProvider([judge_reply])
    verdict = decide_module.decide(_edit("~/.bashrc"), None, provider)

    assert verdict.decision == "ask"
    assert "outside the project" in verdict.reason
    assert verdict.grant_dir is not None


def test_boundary_ask_without_judge_stays_ask(monkeypatch):
    from agentwarden import decide as decide_module

    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    monkeypatch.delenv("WARDEN_JUDGE", raising=False)
    verdict = decide_module.decide(_read("C:/Users/a/file.txt"))

    assert verdict.decision == "ask"


def test_boundary_deny_does_not_call_judge(monkeypatch):
    from agentwarden import decide as decide_module
    from agentwarden.providers.mock import MockProvider

    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    provider = MockProvider([_judge_out("allow", 5)])
    verdict = decide_module.decide(_glob(pattern="C:/Users/**/*.docx"), None, provider)

    assert verdict.decision == "deny"
    assert provider.calls == []


def test_bash_wildcard_grant_dir_has_no_wildcard():
    verdict = evaluate(_bash("cat /var/log/audit/*"))

    assert verdict is not None
    assert verdict.grant_dir is not None
    assert "*" not in verdict.grant_dir
    assert _norm(verdict.grant_dir).endswith("/var/log/audit")


# ---------------------------------------------------------------------------
# Reviewer findings: wildcard traversal, PowerShell -Path:value, shell variables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "**/../../../Windows/System32/drivers/etc/hosts",
        "*/../../x",
        "src/*/../../../etc/shadow",
        "**\\..\\..\\x",
    ],
)
def test_glob_pattern_dotdot_after_wildcard_denied(pattern):
    verdict = evaluate(_glob(pattern=pattern))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert verdict.grant_dir is None


def test_grep_glob_field_dotdot_after_wildcard_denied():
    verdict = evaluate(_grep(glob="**/../../secret-project/*.py"))

    assert verdict is not None
    assert verdict.decision == "deny"


def test_bash_wildcard_dotdot_token_outside():
    verdict = evaluate(_bash("cat */../../x.txt"))

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.grant_dir is None


def test_dotdot_before_wildcard_inside_is_fine():
    verdict = evaluate(_glob(pattern="src/../tests/**/*.py"))

    assert verdict is not None
    assert verdict.decision == "allow"


def test_powershell_colon_parameter_listing_denied():
    event = _event("PowerShell", {"command": "Get-ChildItem -Path:C:/Users -Recurse"})

    verdict = evaluate(event)

    assert verdict is not None
    assert verdict.decision == "deny"
    assert ("Get-ChildItem", "C:/Users") in command_path_tokens(
        "Get-ChildItem -Path:C:/Users -Recurse"
    )


def test_daemon_env_variable_is_not_trusted(monkeypatch):
    # The daemon's env may define FOO pointing inside the project; the agent's shell may not.
    monkeypatch.setenv("FOO", PROJECT)
    verdict = evaluate(_bash("cat $FOO/x.txt"))

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.grant_dir is None


def test_unexpandable_home_is_outside(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setattr("os.path.expanduser", lambda p: p)
    monkeypatch.setattr("os.path.expandvars", lambda p: p)

    verdict = evaluate(_bash("cat $HOME/.bashrc"))

    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.grant_dir is None
