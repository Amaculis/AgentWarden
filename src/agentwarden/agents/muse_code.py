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

from agentwarden.agents import Adapter

ADAPTER = Adapter(
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
    config_paths=(
        # Project hooks file. Public reports disagree on whether it is honoured (see README).
        (".muse", "hooks.json"),
        # The plugin manifest, which third-party reports say is where hooks actually register.
        (".muse-plugin", "plugin.json"),
        # User-level settings (XDG default on POSIX); its `hooks` block is a third config
        # source. Windows home equivalent is unconfirmed -- see README.
        (".config", "muse", "settings.json"),
    ),
)
