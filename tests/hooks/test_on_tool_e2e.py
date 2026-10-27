"""End-to-end test: on_tool.py against the real daemon app (spec 005).

Not `slow` (no network beyond loopback, no model calls): `create_app` runs
the rules stage only, same as the rest of this spec's tests.

Uses a real uvicorn server in a background thread, on a free loopback port,
so the hook subprocess talks to the actual FastAPI `/decide` endpoint rather
than a stub.
"""

import json
import threading
import time

import httpx
import pytest
import uvicorn

from ._support import ON_TOOL, run_hook

READ_SSH_KEY_EVENT = {
    "session_id": "e2e-session",
    "prompt_id": "e2e-prompt",
    "cwd": "/home/user/project",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/home/user/.ssh/id_rsa"},
    "tool_use_id": "toolu_e2e_001",
}


@pytest.fixture
def real_daemon(tmp_path):
    from agentwarden.daemon import create_app

    db_path = tmp_path / "audit.db"
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
    url = f"http://127.0.0.1:{port}"

    try:
        yield url, db_path
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_e2e_real_daemon_denies_ssh_key(tmp_path, real_daemon):
    url, db_path = real_daemon

    result = run_hook(
        ON_TOOL,
        json.dumps(READ_SSH_KEY_EVENT),
        tmp_path,
        env={"WARDEN_URL": url},
    )

    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "systemMessage" in parsed
    assert "\U0001f6e1" in parsed["systemMessage"]

    response = httpx.get(f"{url}/log", params={"session_id": "e2e-session"})
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["decision"] == "deny"
