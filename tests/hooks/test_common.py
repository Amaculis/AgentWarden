"""Tests for hooks/_common.py — shared stdlib-only helpers used by the hooks.

These exercise the presumed API (spec 001, interface section):

- resolve_output_dir() -> Path          default <cwd>/.agentwarden, or $AGENTWARDEN_HOME if set.
- append_event(event: dict) -> None     appends one JSON line to <output_dir>/events.jsonl,
                                         stamping `received_at` (UTC ISO 8601); creates the dir
                                         if missing; never raises, even if the dir is unwritable.
- read_stdin_json(raw: str) -> dict | None   parses JSON text, returns None (not an exception)
                                              on anything that isn't valid JSON.

hooks/_common.py does not exist yet, so every test below is expected to fail at collection
(ModuleNotFoundError) until spec 001 is implemented. That failure mode is expected at this
stage of the workflow.
"""

import json
from datetime import UTC, datetime

from hooks import _common


class TestResolveOutputDir:
    def test_default_is_cwd_slash_dot_agentwarden(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AGENTWARDEN_HOME", raising=False)

        result = _common.resolve_output_dir()

        assert result == tmp_path / ".agentwarden"

    def test_agentwarden_home_env_overrides_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        custom_home = tmp_path / "custom_home"
        monkeypatch.setenv("AGENTWARDEN_HOME", str(custom_home))

        result = _common.resolve_output_dir()

        assert result == custom_home


class TestAppendEvent:
    def test_writes_one_valid_jsonl_line(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTWARDEN_HOME", str(tmp_path))

        _common.append_event({"hook_event_name": "PreToolUse", "tool_name": "Bash"})

        events_file = tmp_path / "events.jsonl"
        assert events_file.exists()
        lines = events_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["tool_name"] == "Bash"

    def test_adds_received_at_as_utc_iso8601(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTWARDEN_HOME", str(tmp_path))
        before = datetime.now(UTC)

        _common.append_event({"hook_event_name": "UserPromptSubmit"})

        after = datetime.now(UTC)
        record = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
        assert "received_at" in record
        parsed = datetime.fromisoformat(record["received_at"].replace("Z", "+00:00"))
        assert parsed.tzinfo is not None
        assert before <= parsed <= after

    def test_creates_output_dir_if_missing(self, tmp_path, monkeypatch):
        target = tmp_path / "does" / "not" / "exist"
        monkeypatch.setenv("AGENTWARDEN_HOME", str(target))

        _common.append_event({"hook_event_name": "PreToolUse"})

        assert (target / "events.jsonl").exists()

    def test_multiple_calls_append_rather_than_overwrite(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTWARDEN_HOME", str(tmp_path))

        _common.append_event({"n": 1})
        _common.append_event({"n": 2})

        lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["n"] == 1
        assert json.loads(lines[1])["n"] == 2

    def test_silent_on_unwritable_output_dir(self, tmp_path, monkeypatch):
        # A regular file in the path where a directory is expected makes the
        # target location impossible to create / write to on every OS.
        blocker = tmp_path / "blocker_file"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        unwritable = blocker / "subdir"
        monkeypatch.setenv("AGENTWARDEN_HOME", str(unwritable))

        # Must not raise — failures here must be swallowed, not propagated.
        _common.append_event({"hook_event_name": "PreToolUse"})


class TestReadStdinJson:
    def test_valid_json_is_parsed(self):
        assert _common.read_stdin_json('{"a": 1}') == {"a": 1}

    def test_invalid_json_returns_none_not_raises(self):
        assert _common.read_stdin_json("not json at all {{{") is None

    def test_empty_input_returns_none(self):
        assert _common.read_stdin_json("") is None
