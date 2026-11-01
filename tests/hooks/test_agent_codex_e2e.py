"""End-to-end: `--agent codex` through the real daemon and the Codex formatter (spec 030).

Proves the whole chain the README promises: a foreign shell tool name is normalized to `Bash`,
hits the same hard deny as Claude Code, and renders in Codex's PreToolUse schema -- and that the
027 fail-safe, which is `ask` in Claude's schema, comes out as `deny` for Codex (030's formatter
maps it there because Codex has no working "ask", see hooks/formats/codex.py).
"""

import json
import threading
import time

import pytest
import uvicorn

from ._support import CLOSED_PORT_URL, ON_TOOL, run_hook

EXEC_RM_RF = {
    "session_id": "codex-e2e",
    "cwd": "/home/user/project",
    "hook_event_name": "PreToolUse",
    "tool_name": "exec_command",
    "tool_input": {"command": "rm -rf /"},
}

EXEC_LS = {
    "session_id": "codex-e2e-2",
    "cwd": "/home/user/project",
    "hook_event_name": "PreToolUse",
    "tool_name": "exec_command",
    "tool_input": {"command": "ls"},
}


@pytest.fixture
def real_daemon(tmp_path_factory):
    from agentwarden.daemon import create_app

    db_path = tmp_path_factory.mktemp("codex-e2e") / "audit.db"
    app = create_app(db_path=db_path)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn server did not report started in time"
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_mapped_shell_deny_renders_in_codex_schema(tmp_path, real_daemon):
    result = run_hook(
        ON_TOOL,
        json.dumps(EXEC_RM_RF),
        tmp_path,
        env={"WARDEN_URL": real_daemon},
        args=["--agent", "codex"],
    )
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "systemMessage" not in parsed  # Codex schema has no documented equivalent


def test_mapped_shell_allow_prints_nothing_by_default(tmp_path, real_daemon):
    result = run_hook(
        ON_TOOL,
        json.dumps(EXEC_LS),
        tmp_path,
        env={"WARDEN_URL": real_daemon},
        args=["--agent", "codex"],
    )
    assert result.returncode == 0
    assert result.stdout == ""


def test_daemon_down_failsafe_is_deny_not_ask(tmp_path):
    """The universal 027 fail-safe is `ask`; Codex cannot be trusted with "ask" (see
    hooks/formats/codex.py), so the Codex formatter must turn it into `deny`."""
    result = run_hook(
        ON_TOOL,
        json.dumps(EXEC_RM_RF),
        tmp_path,
        env={"WARDEN_URL": CLOSED_PORT_URL},
        args=["--agent", "codex"],
    )
    assert result.returncode == 0
    hso = json.loads(result.stdout)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


def test_unmapped_tool_ask_renders_as_deny(tmp_path, real_daemon):
    event = {
        "session_id": "codex-e2e-3",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "browser_click",
        "tool_input": {"selector": "#ok"},
    }
    result = run_hook(
        ON_TOOL,
        json.dumps(event),
        tmp_path,
        env={"WARDEN_URL": real_daemon},
        args=["--agent", "codex"],
    )
    assert result.returncode == 0
    hso = json.loads(result.stdout)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
