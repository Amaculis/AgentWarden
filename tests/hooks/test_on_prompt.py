"""Subprocess tests for hooks/on_prompt.py (UserPromptSubmit).

Runs the script as a real `python hooks/on_prompt.py` process (not an in-process
import/call) so exit code and stdout are genuinely checked.

hooks/on_prompt.py does not exist yet. These tests are expected to fail until
spec 001 ships.
"""

import json

from ._support import ON_PROMPT, SAMPLE_USER_PROMPT_SUBMIT, run_hook


def test_on_prompt_appends_event(tmp_path):
    result = run_hook(ON_PROMPT, json.dumps(SAMPLE_USER_PROMPT_SUBMIT), tmp_path)

    assert result.returncode == 0
    events_file = tmp_path / "events.jsonl"
    assert events_file.exists()
    lines = events_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["hook_event_name"] == "UserPromptSubmit"
    assert record["prompt"] == SAMPLE_USER_PROMPT_SUBMIT["prompt"]
    assert "received_at" in record


def test_on_prompt_makes_no_decision(tmp_path):
    result = run_hook(ON_PROMPT, json.dumps(SAMPLE_USER_PROMPT_SUBMIT), tmp_path)

    assert result.stdout == ""
    assert result.returncode == 0


def test_invalid_json_is_ignored(tmp_path):
    result = run_hook(ON_PROMPT, "not valid json {{{", tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert not (tmp_path / "events.jsonl").exists()


def test_unwritable_output_dir_exits_zero(tmp_path):
    blocker = tmp_path / "blocker_file"
    blocker.write_text("file blocking directory creation", encoding="utf-8")
    unwritable_home = blocker / "subdir"

    result = run_hook(ON_PROMPT, json.dumps(SAMPLE_USER_PROMPT_SUBMIT), unwritable_home)

    assert result.returncode == 0
    assert result.stdout == ""


def test_on_prompt_posts_to_event(tmp_path, stub_daemon):
    stub_daemon.status = 204
    stub_daemon.body = b""
    result = run_hook(
        ON_PROMPT,
        json.dumps(SAMPLE_USER_PROMPT_SUBMIT),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert stub_daemon.last_request is not None
    assert stub_daemon.last_request.path == "/event"
    sent = json.loads(stub_daemon.last_request.body)
    assert sent["prompt"] == SAMPLE_USER_PROMPT_SUBMIT["prompt"]


def test_on_prompt_slow_daemon_bounded(tmp_path, stub_daemon):
    import time

    stub_daemon.delay_s = 6.0
    start = time.monotonic()
    result = run_hook(
        ON_PROMPT,
        json.dumps(SAMPLE_USER_PROMPT_SUBMIT),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )
    assert time.monotonic() - start < 5.0
    assert result.returncode == 0
    assert result.stdout == ""


def test_on_prompt_non_loopback_url_not_called(tmp_path, stub_daemon):
    url = stub_daemon.url.replace("127.0.0.1", "example.invalid")
    result = run_hook(
        ON_PROMPT, json.dumps(SAMPLE_USER_PROMPT_SUBMIT), tmp_path, env={"WARDEN_URL": url}
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert stub_daemon.request_count == 0
