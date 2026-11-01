"""Hook side of spec 027: `--agent` flag, `X-AgentWarden-Agent` header, per-agent formatters."""

import json
import sys

import pytest

from ._support import (
    ON_PROMPT,
    ON_READ,
    ON_TOOL,
    REPO_ROOT,
    SAMPLE_PRE_TOOL_USE,
    SAMPLE_USER_PROMPT_SUBMIT,
    run_hook,
)

sys.path.insert(0, str(REPO_ROOT / "hooks"))

HEADER = "x-agentwarden-agent"
DENY = json.dumps({"decision": "deny", "reason": "blocked", "source": "rules"}).encode()
POST_READ = {
    "session_id": "s-read",
    "cwd": "D:\\proj",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "README.md"},
    "tool_response": {"file": {"filePath": "README.md", "content": "# Project\nrun it"}},
}


def _header(stub) -> str | None:
    headers = {k.lower(): v for k, v in stub.last_request.headers.items()}
    return headers.get(HEADER)


def _tool(tmp_path, stub, args=None):
    stub.body = DENY
    return run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub.url},
        args=args,
    )


def _assert_failsafe(stdout: str) -> None:
    hso = json.loads(stdout)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert hso["permissionDecisionReason"] == "AgentWarden unavailable"


# ---------------------------------------------------------------------------
# on_tool.py subprocess
# ---------------------------------------------------------------------------


def test_default_agent_header_is_claude_code(tmp_path, stub_daemon):
    result = _tool(tmp_path, stub_daemon)
    assert result.returncode == 0
    assert _header(stub_daemon) == "claude_code"
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("args", [["--agent", "muse_code"], ["--agent=muse_code"]])
def test_agent_flag_sends_header(tmp_path, stub_daemon, args):
    result = _tool(tmp_path, stub_daemon, args)
    assert _header(stub_daemon) == "muse_code"
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(stub_daemon.last_request.body) == SAMPLE_PRE_TOOL_USE


@pytest.mark.parametrize(
    "args",
    [["--agent"], ["--agent", "../x"], ["--agent", "Muse"], ["--agent="], ["--bogus"], ["x"]],
)
def test_malformed_agent_flag_is_failsafe_without_call(tmp_path, stub_daemon, args):
    result = _tool(tmp_path, stub_daemon, args)
    assert result.returncode == 0
    _assert_failsafe(result.stdout)
    assert stub_daemon.request_count == 0


# ---------------------------------------------------------------------------
# on_tool.py formatters (in-process, FORMATS_DIR pointed at tmp_path)
# ---------------------------------------------------------------------------

GOOD_FORMATTER = """
import json
def decision_output(decision, reason, system_message):
    return json.dumps({"fmt": "fake", "decision": decision, "reason": reason})
def scan_output(warning):
    return json.dumps({"fmt": "fake", "warning": warning})
"""


def _formats(tmp_path, source: str):
    formats = tmp_path / "formats"
    formats.mkdir(exist_ok=True)
    (formats / "fakeagent.py").write_text(source, encoding="utf-8")
    return formats


def _run_in_process(monkeypatch, formats, agent="fakeagent", url="http://127.0.0.1:1"):
    from hooks import on_tool

    monkeypatch.setattr(on_tool, "FORMATS_DIR", formats)
    stdin = json.dumps(SAMPLE_PRE_TOOL_USE).encode()
    return on_tool.run(stdin, {"WARDEN_URL": url}, agent=agent)


def test_formatter_used_for_failsafe(tmp_path, monkeypatch):
    out = json.loads(_run_in_process(monkeypatch, _formats(tmp_path, GOOD_FORMATTER)))
    assert out == {"fmt": "fake", "decision": "ask", "reason": "AgentWarden unavailable"}


def test_formatter_used_for_daemon_verdict(tmp_path, monkeypatch, stub_daemon):
    stub_daemon.body = DENY
    formats = _formats(tmp_path, GOOD_FORMATTER)
    out = json.loads(_run_in_process(monkeypatch, formats, url=stub_daemon.url))
    assert out == {"fmt": "fake", "decision": "deny", "reason": "blocked"}


def test_missing_formatter_uses_claude_schema(tmp_path, monkeypatch):
    formats = tmp_path / "formats"
    formats.mkdir()
    _assert_failsafe(_run_in_process(monkeypatch, formats))


@pytest.mark.parametrize(
    "source",
    [
        "raise RuntimeError('broken import')",
        "def decision_output(d, r, s):\n    raise RuntimeError('boom')\n",
        "def decision_output(d, r, s):\n    return 42\n",
        "x = 1\n",
    ],
)
def test_broken_formatter_is_claude_failsafe(tmp_path, monkeypatch, stub_daemon, source):
    stub_daemon.body = DENY
    formats = _formats(tmp_path, source)
    _assert_failsafe(_run_in_process(monkeypatch, formats, url=stub_daemon.url))


def test_malformed_agent_in_run_is_failsafe(tmp_path, monkeypatch):
    formats = _formats(tmp_path, GOOD_FORMATTER)
    _assert_failsafe(_run_in_process(monkeypatch, formats, agent=None))
    _assert_failsafe(_run_in_process(monkeypatch, formats, agent="../formats/fakeagent"))


# ---------------------------------------------------------------------------
# on_read.py / on_prompt.py
# ---------------------------------------------------------------------------


def test_on_read_forwards_header(tmp_path, stub_daemon):
    stub_daemon.body = json.dumps({"warning": None}).encode()
    run_hook(
        ON_READ,
        json.dumps(POST_READ),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
        args=["--agent", "muse_code"],
    )
    assert stub_daemon.last_request.path == "/scan"
    assert _header(stub_daemon) == "muse_code"


def test_on_read_malformed_agent_prints_nothing_and_no_call(tmp_path, stub_daemon):
    result = run_hook(
        ON_READ, json.dumps(POST_READ), tmp_path, env={"WARDEN_URL": stub_daemon.url}, args=["x"]
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert stub_daemon.request_count == 0


def test_on_read_formatter_used(tmp_path, monkeypatch):
    from hooks import on_read, on_tool

    monkeypatch.setattr(on_tool, "FORMATS_DIR", _formats(tmp_path, GOOD_FORMATTER))
    body = json.dumps({"warning": "careful"}).encode()
    out = on_read.build_output(200, body, on_tool.load_formatter("fakeagent"))
    assert json.loads(out) == {"fmt": "fake", "warning": "careful"}


def test_on_prompt_forwards_header(tmp_path, stub_daemon):
    stub_daemon.status, stub_daemon.body = 204, b""
    run_hook(
        ON_PROMPT,
        json.dumps(SAMPLE_USER_PROMPT_SUBMIT),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
        args=["--agent", "muse_code"],
    )
    assert stub_daemon.last_request.path == "/event"
    assert _header(stub_daemon) == "muse_code"
