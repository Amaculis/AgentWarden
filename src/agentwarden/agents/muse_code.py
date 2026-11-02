"""Muse Code (Meta's CLI coding agent) adapter (spec 028).

Research summary (full sources and verification status in
`integrations/muse_code/README.md`): Muse Code is reported to speak Claude Code's wire
schema for hook payloads (snake_case `hook_event_name` / `tool_name` / `tool_input` in,
camelCase `hookSpecificOutput` with `permissionDecision` out for `PreToolUse`), so no
`hooks/formats/muse_code.py` is added here -- the Claude Code schema is used as-is.

Nothing below is verified by a live Muse Code session yet. `exec_command` (with a `shell`
alias and possibly a `write_stdin` tool) is confirmed to exist in the shipped binary by a
third-party issue tracker, but its payload field (`cmd` vs `command`) was never actually
observed -- the mapping here is a guess pending `integrations/muse_code/hook_logger.py`'s
live capture. The write/edit/read/search/fetch tool names are not confirmed anywhere and are
guessed from common Codex/Claude-style naming; treat every mapping as UNVERIFIED until the
live check replaces it.
"""

import shlex
from typing import Any

from agentwarden.agents import Adapter, AdapterError, EventKind


class MuseCodeAdapter(Adapter):
    """Codex-style payloads (reported) may carry the shell command as an argv list; the rules
    only read a string `command`, so a list would skip every shell hard deny."""

    def normalize(self, kind: EventKind, body: dict[str, Any]) -> dict[str, Any]:
        out = super().normalize(kind, body)
        tool_input = out.get("tool_input")
        if out.get("tool_name") == "Bash" and isinstance(tool_input, dict):
            command = tool_input.get("command")
            if isinstance(command, list):
                if not all(isinstance(part, str) for part in command):
                    raise AdapterError(f"{self.name}: command list has a non-string entry")
                out["tool_input"] = {**tool_input, "command": shlex.join(command)}
        return out


ADAPTER = MuseCodeAdapter(
    name="muse_code",
    tool_map={
        # Confirmed to exist in the 1.4.7 binary (destructive_command_guard issue #572);
        # exact field name unconfirmed (no payload was actually captured).
        "exec_command": "Bash",
        "shell": "Bash",
        # UNVERIFIED: guessed Codex/Claude-style names; replace from the live capture.
        "write_file": "Write",
        "edit_file": "Edit",
        "read_file": "Read",
        "search_files": "Grep",
        "glob_files": "Glob",
        "fetch_url": "WebFetch",
    },
    input_map={
        "Bash": {"cmd": "command"},
        "Write": {"path": "file_path"},
        "Edit": {"path": "file_path", "old_str": "old_string", "new_str": "new_string"},
        "Read": {"path": "file_path"},
        "Grep": {"query": "pattern"},
        "Glob": {"query": "pattern"},
    },
    # Whole directories, not single files: a plugin manifest points at scripts next to it, and
    # replacing one of those switches AgentWarden off as surely as editing the manifest.
    config_paths=(
        # Project hooks file (public reports disagree on whether it is honoured, see README).
        (".muse",),
        # Plugin manifest and the hook scripts it registers.
        (".muse-plugin",),
        # User-level settings (XDG default on POSIX); its `hooks` block is a third config
        # source. Windows home equivalent and `managed_hooks_path` are unconfirmed -- see README.
        (".config", "muse"),
    ),
)
