"""Subprocess and unit tests for hooks/on_tool.py (PreToolUse, spec 005).

Runs the script as a real `python hooks/on_tool.py` process (house style,
`tests/hooks/_support.py`) against a stub daemon (`tests/hooks/_stub_daemon.py`)
so the real network code path (urllib, threading, wall-clock deadline,
encoding, exit code) runs end to end. `WARDEN_URL` always points either at a
stub or at a deliberately closed loopback port -- no test can reach a real
daemon.

hooks/on_tool.py is still spec-001 event-recording only (no `/decide` call,
no `parse_verdict`/`decide_url`/`call_daemon`/`build_output`/`failsafe_output`,
no wired `run()`). Every test below that depends on that wiring is expected
to fail now (empty stdout instead of a fail-closed ask JSON, ImportError on
the pure functions, etc.) until spec 005 is implemented.
"""

import json
import os
import sys

import pytest

from ._support import ON_TOOL, REPO_ROOT, SAMPLE_PRE_TOOL_USE, run_hook

FAILSAFE_REASON = "AgentWarden unavailable"


def _verdict_body(**overrides) -> bytes:
    """A canned /decide response body, built from the real Verdict model
    (per the spec's contract-test requirement: if Verdict's shape changes,
    these tests must catch it)."""
    from agentwarden.models import Verdict

    fields = {
        "decision": "ask",
        "reason": "AgentWarden: needs confirmation (rules).",
        "risk": None,
        "source": "rules",
        "system_message": None,
    }
    fields.update(overrides)
    return Verdict(**fields).model_dump_json().encode("utf-8")


def _parse_stdout_json(stdout: str) -> dict:
    return json.loads(stdout)


def _assert_is_failsafe_ask(stdout: str) -> dict:
    parsed = _parse_stdout_json(stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "ask"
    assert hso["permissionDecisionReason"] == FAILSAFE_REASON
    return parsed


# ---------------------------------------------------------------------------
# Spec 001 tests, kept / updated per spec 005's explicit behaviour changes.
# ---------------------------------------------------------------------------


def test_on_tool_appends_event(tmp_path):
    # Recording still happens regardless of the (now fail-closed, no stub
    # configured) decision outcome -- see also test_still_records_event.
    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path)

    assert result.returncode == 0
    events_file = tmp_path / "events.jsonl"
    assert events_file.exists()
    lines = events_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["hook_event_name"] == "PreToolUse"
    assert record["tool_name"] == "Bash"
    assert record["tool_input"] == SAMPLE_PRE_TOOL_USE["tool_input"]
    assert "received_at" in record


def test_on_tool_makes_no_decision(tmp_path):
    # Spec 005 changes this: on_tool.py now always makes a decision. With no
    # stub daemon configured, WARDEN_URL defaults (via run_hook) to a closed
    # port, so the hook must fail closed to an "ask" -- never silent, never
    # an allow.
    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path)

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_invalid_json_is_ignored(tmp_path):
    # Spec 005 changes this: invalid stdin now fails closed to "ask" instead
    # of printing nothing, and no request is sent to the daemon because the
    # hook never got a parseable event.
    result = run_hook(ON_TOOL, "not valid json {{{", tmp_path)

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)
    assert not (tmp_path / "events.jsonl").exists()


def test_unwritable_output_dir_exits_zero(tmp_path):
    blocker = tmp_path / "blocker_file"
    blocker.write_text("file blocking directory creation", encoding="utf-8")
    unwritable_home = blocker / "subdir"

    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), unwritable_home)

    assert result.returncode == 0
    # Recording is best-effort; with no stub daemon, the decision still
    # fails closed to ask rather than printing nothing.
    _assert_is_failsafe_ask(result.stdout)


# ---------------------------------------------------------------------------
# Hook, happy paths
# ---------------------------------------------------------------------------


def test_deny_verdict_maps_to_deny_output(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="deny",
        reason="AgentWarden: blocked -- secret file.",
        source="rules",
        system_message="\U0001f6e1 AgentWarden: blocked this action (rules)",
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )

    assert result.returncode == 0
    parsed = _parse_stdout_json(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "AgentWarden: blocked -- secret file."
    assert parsed["systemMessage"] == "\U0001f6e1 AgentWarden: blocked this action (rules)"


def test_ask_verdict_maps_to_ask_output(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="ask",
        reason="AgentWarden: needs confirmation.",
        source="rules",
        system_message="\U0001f6e1 AgentWarden: needs confirmation for this action (rules)",
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )

    assert result.returncode == 0
    parsed = _parse_stdout_json(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert hso["permissionDecisionReason"] == "AgentWarden: needs confirmation."
    assert (
        parsed["systemMessage"]
        == "\U0001f6e1 AgentWarden: needs confirmation for this action (rules)"
    )


def test_system_message_omitted_when_null(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="deny", reason="AgentWarden: blocked.", source="rules", system_message=None
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )

    parsed = _parse_stdout_json(result.stdout)
    assert "systemMessage" not in parsed


def test_allow_passthrough_prints_nothing(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="allow", reason="AgentWarden: looks fine.", source="rules", system_message=None
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )

    assert result.returncode == 0
    assert result.stdout == ""


def test_allow_explicit_mode(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="allow", reason="AgentWarden: looks fine.", source="rules", system_message=None
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url, "WARDEN_ALLOW": "explicit"},
    )

    assert result.returncode == 0
    parsed = _parse_stdout_json(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "allow"
    assert hso["permissionDecisionReason"] == "AgentWarden: looks fine."
    assert "systemMessage" not in parsed


def test_stdout_is_ascii_only(tmp_path, stub_daemon):
    reason = "AgentWarden: blocked -- secret file żółw.env"
    stub_daemon.body = _verdict_body(
        decision="deny",
        reason=reason,
        source="rules",
        system_message="\U0001f6e1 AgentWarden: blocked this action (rules)",
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url},
    )

    raw_stdout_bytes = result.stdout.encode("ascii")  # raises if non-ASCII leaked through
    assert raw_stdout_bytes.decode("ascii") == result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == reason
    assert parsed["systemMessage"] == "\U0001f6e1 AgentWarden: blocked this action (rules)"


def test_forwards_original_bytes(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(decision="allow", reason="ok", source="rules")
    stdin_text = json.dumps(SAMPLE_PRE_TOOL_USE)

    run_hook(ON_TOOL, stdin_text, tmp_path, env={"WARDEN_URL": stub_daemon.url})

    assert stub_daemon.last_request is not None
    assert stub_daemon.last_request.method == "POST"
    assert stub_daemon.last_request.path == "/decide"
    assert stub_daemon.last_request.body == stdin_text.encode("utf-8")


def test_non_ascii_stdin_forwarded_intact(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(decision="allow", reason="ok", source="rules")
    payload = dict(SAMPLE_PRE_TOOL_USE)
    payload["tool_input"] = {"file_path": "/home/user/café/жизнь.txt"}
    stdin_text = json.dumps(payload, ensure_ascii=False)

    run_hook(ON_TOOL, stdin_text, tmp_path, env={"WARDEN_URL": stub_daemon.url})

    assert stub_daemon.last_request is not None
    received = json.loads(stub_daemon.last_request.body.decode("utf-8"))
    assert received["tool_input"]["file_path"] == "/home/user/café/жизнь.txt"


def test_still_records_event(tmp_path, stub_daemon):
    stub_daemon.body = _verdict_body(decision="deny", reason="blocked", source="rules")

    run_hook(
        ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path, env={"WARDEN_URL": stub_daemon.url}
    )

    events_file = tmp_path / "events.jsonl"
    assert events_file.exists()
    record = json.loads(events_file.read_text(encoding="utf-8").splitlines()[0])
    assert record["tool_name"] == "Bash"


# ---------------------------------------------------------------------------
# Hook, fail-closed paths
# ---------------------------------------------------------------------------


def test_daemon_unreachable_asks(tmp_path):
    result = run_hook(ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path)  # default closed port

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_daemon_timeout_asks(tmp_path, stub_daemon):
    stub_daemon.delay_s = 2.0
    stub_daemon.body = _verdict_body(decision="allow", reason="ok", source="rules")

    import time

    start = time.monotonic()
    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url, "WARDEN_HOOK_TIMEOUT": "0.5"},
    )
    elapsed = time.monotonic() - start

    assert elapsed < 1.5
    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_slow_drip_body_asks(tmp_path, stub_daemon):
    # Headers arrive, then one byte every 0.2s for up to 3s: urllib's
    # per-socket-operation timeout would never fire on this, only the
    # hook's own wall-clock deadline (Decision 2) can catch it.
    stub_daemon.body = _verdict_body(decision="allow", reason="ok", source="rules")
    stub_daemon.slow_drip = (1, 0.2, 3.0)

    import time

    start = time.monotonic()
    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url, "WARDEN_HOOK_TIMEOUT": "0.5"},
    )
    elapsed = time.monotonic() - start

    assert elapsed < 1.5
    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


@pytest.mark.parametrize("status", [302, 404, 500])
def test_non_200_asks(tmp_path, stub_daemon, status):
    stub_daemon.status = status
    stub_daemon.body = _verdict_body(decision="allow", reason="ok", source="rules")

    result = run_hook(
        ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path, env={"WARDEN_URL": stub_daemon.url}
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_non_json_body_asks(tmp_path, stub_daemon):
    stub_daemon.body = b"not json at all {{{"

    result = run_hook(
        ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path, env={"WARDEN_URL": stub_daemon.url}
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_oversized_body_asks(tmp_path, stub_daemon):
    big_reason = "x" * (70 * 1024)
    stub_daemon.body = _verdict_body(decision="allow", reason=big_reason, source="rules")

    result = run_hook(
        ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path, env={"WARDEN_URL": stub_daemon.url}
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


@pytest.mark.parametrize(
    "bad_body",
    [
        b'{"reason": "no decision field", "source": "rules"}',
        b'{"decision": "Allow", "reason": "bad case", "source": "rules"}',
        b'{"decision": "maybe", "reason": "bad value", "source": "rules"}',
        b'{"decision": "allow", "reason": 123, "source": "rules"}',
        b'{"decision": "allow", "reason": "ok", "source": "rules", "system_message": ["x"]}',
        b"[1, 2, 3]",
    ],
    ids=[
        "missing_decision",
        "wrong_case",
        "invalid_value",
        "reason_not_str",
        "sysmsg_not_str_or_null",
        "array_body",
    ],
)
def test_invalid_verdict_shape_asks(tmp_path, stub_daemon, bad_body):
    stub_daemon.body = bad_body

    result = run_hook(
        ON_TOOL, json.dumps(SAMPLE_PRE_TOOL_USE), tmp_path, env={"WARDEN_URL": stub_daemon.url}
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)


def test_non_loopback_url_asks_without_request(tmp_path, stub_daemon):
    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": "http://example.com:8765"},
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)
    assert stub_daemon.last_request is None


def test_proxy_env_ignored(tmp_path, stub_daemon, second_stub_daemon):
    stub_daemon.body = _verdict_body(
        decision="deny", reason="blocked via real stub", source="rules"
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_URL": stub_daemon.url, "HTTP_PROXY": second_stub_daemon.url},
    )

    assert result.returncode == 0
    parsed = _parse_stdout_json(result.stdout)
    assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == "blocked via real stub"
    assert stub_daemon.last_request is not None
    assert second_stub_daemon.last_request is None


@pytest.mark.parametrize(
    "stdin_text",
    ["not valid json {{{", "", "[1, 2]"],
    ids=["garbage", "empty", "json_array"],
)
def test_invalid_stdin_asks(tmp_path, stub_daemon, stdin_text):
    result = run_hook(ON_TOOL, stdin_text, tmp_path, env={"WARDEN_URL": stub_daemon.url})

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout)
    assert stub_daemon.last_request is None


def test_invalid_utf8_stdin_asks(tmp_path, stub_daemon):
    # Invalid stdin must not reach the stub, and the hook still exits 0 with
    # the fail-closed ask JSON on stdout. Raw (non-text) subprocess call,
    # since text=True stdin can't carry invalid UTF-8 bytes.
    import subprocess

    env = os.environ.copy()
    env["AGENTWARDEN_HOME"] = str(tmp_path)
    env["WARDEN_URL"] = stub_daemon.url

    result = subprocess.run(
        [sys.executable, str(ON_TOOL)],
        input=b"\xff\xfe not utf-8 \x80",
        capture_output=True,
        env=env,
        timeout=10,
    )

    assert result.returncode == 0
    _assert_is_failsafe_ask(result.stdout.decode("ascii"))
    assert stub_daemon.last_request is None


def test_unwritable_home_still_decides(tmp_path, stub_daemon):
    blocker = tmp_path / "blocker_file"
    blocker.write_text("file blocking directory creation", encoding="utf-8")
    unwritable_home = blocker / "subdir"

    stub_daemon.body = _verdict_body(
        decision="deny",
        reason="AgentWarden: blocked -- secret file.",
        source="rules",
        system_message="\U0001f6e1 AgentWarden: blocked this action (rules)",
    )

    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        unwritable_home,
        env={"WARDEN_URL": stub_daemon.url},
    )

    assert result.returncode == 0
    parsed = _parse_stdout_json(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "AgentWarden: blocked -- secret file."


def test_failsafe_respects_notify_off(tmp_path):
    result = run_hook(
        ON_TOOL,
        json.dumps(SAMPLE_PRE_TOOL_USE),
        tmp_path,
        env={"WARDEN_NOTIFY": "off"},  # default closed-port WARDEN_URL -> daemon down
    )

    assert result.returncode == 0
    parsed = _assert_is_failsafe_ask(result.stdout)
    assert "systemMessage" not in parsed


# ---------------------------------------------------------------------------
# Unit tests for the pure functions (in-process import).
# ---------------------------------------------------------------------------

sys.path.insert(0, str(REPO_ROOT / "hooks"))


class TestParseVerdict:
    def test_valid_deny_is_accepted(self):
        from hooks import on_tool

        body = _verdict_body(decision="deny", reason="blocked", source="rules")
        result = on_tool.parse_verdict(200, body)

        assert result is not None
        assert result["decision"] == "deny"
        assert result["reason"] == "blocked"

    def test_non_200_status_is_rejected(self):
        from hooks import on_tool

        body = _verdict_body(decision="allow", reason="ok", source="rules")
        assert on_tool.parse_verdict(404, body) is None

    def test_oversized_body_is_rejected(self):
        from hooks import on_tool

        big = b'{"decision": "allow", "reason": "' + b"x" * (65 * 1024) + b'", "source": "rules"}'
        assert on_tool.parse_verdict(200, big) is None

    def test_non_utf8_body_is_rejected(self):
        from hooks import on_tool

        assert on_tool.parse_verdict(200, b"\xff\xfe\x00\x01") is None

    def test_json_array_is_rejected(self):
        from hooks import on_tool

        assert on_tool.parse_verdict(200, b"[1, 2, 3]") is None

    @pytest.mark.parametrize(
        "body",
        [
            b'{"reason": "x", "source": "rules"}',
            b'{"decision": "Allow", "reason": "x", "source": "rules"}',
            b'{"decision": "maybe", "reason": "x", "source": "rules"}',
            b'{"decision": "allow", "reason": 1, "source": "rules"}',
            b'{"decision": "allow", "reason": "x", "source": "rules", "system_message": 1}',
        ],
    )
    def test_invalid_shapes_are_rejected(self, body):
        from hooks import on_tool

        assert on_tool.parse_verdict(200, body) is None

    def test_null_system_message_is_accepted(self):
        from hooks import on_tool

        body = _verdict_body(decision="allow", reason="ok", source="rules", system_message=None)
        result = on_tool.parse_verdict(200, body)

        assert result is not None
        assert result.get("system_message") is None


class TestDecideUrl:
    def test_default_is_local_daemon(self, monkeypatch):
        from hooks import on_tool

        monkeypatch.delenv("WARDEN_URL", raising=False)
        assert on_tool.decide_url() == "http://127.0.0.1:8765/decide"

    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "localhost", "[::1]"],
    )
    def test_loopback_hosts_are_accepted(self, monkeypatch, host):
        from hooks import on_tool

        monkeypatch.setenv("WARDEN_URL", f"http://{host}:9000")
        assert on_tool.decide_url() == f"http://{host}:9000/decide"

    @pytest.mark.parametrize(
        "url",
        ["http://example.com:8765", "https://127.0.0.1:8765", "not a url", ""],
    )
    def test_non_loopback_or_unparsable_is_rejected(self, monkeypatch, url):
        from hooks import on_tool

        monkeypatch.setenv("WARDEN_URL", url)
        assert on_tool.decide_url() is None


class TestHookTimeoutClamp:
    @pytest.mark.parametrize("raw", ["0", "-1", "abc", "", "nan"])
    def test_invalid_or_nonpositive_falls_back_to_default(self, monkeypatch, raw):
        from hooks import on_tool

        monkeypatch.setenv("WARDEN_HOOK_TIMEOUT", raw)
        assert on_tool.hook_timeout_seconds() == 8.0

    def test_unset_defaults_to_8(self, monkeypatch):
        from hooks import on_tool

        monkeypatch.delenv("WARDEN_HOOK_TIMEOUT", raising=False)
        assert on_tool.hook_timeout_seconds() == 8.0

    def test_too_large_is_clamped_to_10(self, monkeypatch):
        from hooks import on_tool

        monkeypatch.setenv("WARDEN_HOOK_TIMEOUT", "99")
        assert on_tool.hook_timeout_seconds() == 10.0

    def test_within_range_passes_through(self, monkeypatch):
        from hooks import on_tool

        monkeypatch.setenv("WARDEN_HOOK_TIMEOUT", "3.5")
        assert on_tool.hook_timeout_seconds() == 3.5


class TestBuildOutput:
    def test_deny_has_hook_specific_output_and_system_message(self):
        from hooks import on_tool

        verdict = {
            "decision": "deny",
            "reason": "blocked",
            "system_message": "\U0001f6e1 AgentWarden: blocked this action (rules)",
        }
        out = on_tool.build_output(verdict, "passthrough")
        parsed = json.loads(out)

        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == "blocked"
        assert parsed["systemMessage"] == "\U0001f6e1 AgentWarden: blocked this action (rules)"

    def test_allow_passthrough_is_empty_string(self):
        from hooks import on_tool

        verdict = {"decision": "allow", "reason": "ok", "system_message": None}
        assert on_tool.build_output(verdict, "passthrough") == ""

    def test_allow_explicit_has_permission_decision(self):
        from hooks import on_tool

        verdict = {"decision": "allow", "reason": "ok", "system_message": None}
        out = on_tool.build_output(verdict, "explicit")
        parsed = json.loads(out)

        assert parsed["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert "systemMessage" not in parsed

    def test_null_system_message_is_omitted_not_null(self):
        from hooks import on_tool

        verdict = {"decision": "ask", "reason": "needs confirmation", "system_message": None}
        out = on_tool.build_output(verdict, "passthrough")
        parsed = json.loads(out)

        assert "systemMessage" not in parsed

    def test_empty_system_message_is_omitted(self):
        from hooks import on_tool

        verdict = {"decision": "ask", "reason": "needs confirmation", "system_message": ""}
        out = on_tool.build_output(verdict, "passthrough")
        parsed = json.loads(out)

        assert "systemMessage" not in parsed

    def test_output_is_ascii_only(self):
        from hooks import on_tool

        verdict = {
            "decision": "deny",
            "reason": "blocked żółw",
            "system_message": "\U0001f6e1 AgentWarden",
        }
        out = on_tool.build_output(verdict, "passthrough")

        out.encode("ascii")  # raises if non-ASCII leaked through


class TestFailsafeOutput:
    def test_notify_on_has_system_message(self):
        from hooks import on_tool

        out = on_tool.failsafe_output(notify=True)
        parsed = json.loads(out)

        assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == FAILSAFE_REASON
        assert "systemMessage" in parsed
        assert parsed["systemMessage"]

    def test_notify_off_has_no_system_message(self):
        from hooks import on_tool

        out = on_tool.failsafe_output(notify=False)
        parsed = json.loads(out)

        assert "systemMessage" not in parsed

    def test_output_is_ascii_only(self):
        from hooks import on_tool

        out = on_tool.failsafe_output(notify=True)
        out.encode("ascii")  # raises if non-ASCII leaked through


class TestRunTopLevelExceptionSafety:
    def test_unexpected_exception_still_fails_closed(self, monkeypatch, tmp_path):
        from hooks import on_tool

        monkeypatch.setenv("AGENTWARDEN_HOME", str(tmp_path))
        monkeypatch.setenv("WARDEN_URL", "http://127.0.0.1:9999")

        def boom(*args, **kwargs):
            raise RuntimeError("unexpected failure deep inside the pipeline")

        monkeypatch.setattr(on_tool, "call_daemon", boom)

        stdin_bytes = json.dumps(SAMPLE_PRE_TOOL_USE).encode("utf-8")
        result = on_tool.run(stdin_bytes, dict(os.environ))

        parsed = json.loads(result)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == FAILSAFE_REASON
