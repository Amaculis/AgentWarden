"""Muse Code (Meta's CLI coding agent) adapter (specs 028, 036).

Tool names and fields below come from a live capture (Muse Code 1.4.14 on Windows,
2026-11-02; details in `integrations/muse_code/README.md`): Claude Code wire schema with Muse's
own tool names and a `turn_id` instead of `prompt_id`. `exec_command`, `shell`, `write_file`,
`glob_files` and `fetch_url` were not seen in the capture and stay mapped as guesses.
"""

import shlex
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from agentwarden.agents import Adapter, AdapterError, EventKind

_SHELLS = ("Bash", "PowerShell")
_LONG_PATH_PREFIXES = ("\\\\?\\", "//?/")


def _strip_long_prefix(path: str) -> str:
    for prefix in _LONG_PATH_PREFIXES:
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _workdir_inside(workdir: object, cwd: object) -> bool:
    """`workdir` is `cwd` or below it; the rules resolve relative paths against `cwd` only."""
    if not isinstance(workdir, str) or not isinstance(cwd, str) or not workdir:
        return False
    base_text = _strip_long_prefix(cwd)
    flavour = PureWindowsPath if (len(base_text) > 1 and base_text[1] == ":") else PurePosixPath
    base = flavour(base_text)
    path = flavour(_strip_long_prefix(workdir))
    if not path.is_absolute():
        if path.drive or path.root:
            return False
        path = base / path
    if ".." in path.parts:
        return False
    base_parts = [p.lower() for p in base.parts]
    path_parts = [p.lower() for p in path.parts]
    return path_parts[: len(base_parts)] == base_parts


class MuseCodeAdapter(Adapter):
    def normalize(self, kind: EventKind, body: dict[str, Any]) -> dict[str, Any]:
        out = super().normalize(kind, body)
        tool_input = out.get("tool_input")
        tool = out.get("tool_name")
        if not isinstance(tool_input, dict):
            return out
        if tool in _SHELLS:
            command = tool_input.get("command")
            if isinstance(command, list):
                # Codex-style argv lists would skip every shell hard deny (they read a string).
                if not all(isinstance(part, str) for part in command):
                    raise AdapterError(f"{self.name}: command list has a non-string entry")
                tool_input = {**tool_input, "command": shlex.join(command)}
            if "workdir" in tool_input and not _workdir_inside(
                tool_input["workdir"], out.get("cwd")
            ):
                raise AdapterError(f"{self.name}: shell workdir outside the project")
        elif tool == "Grep" and "paths" in tool_input:
            paths = tool_input["paths"]
            rest = {k: v for k, v in tool_input.items() if k != "paths"}
            if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
                raise AdapterError(f"{self.name}: search paths is not a list of strings")
            if len(paths) > 1:
                raise AdapterError(f"{self.name}: search over several paths")
            if paths:
                if "path" in rest and rest["path"] != paths[0]:
                    raise AdapterError(f"{self.name}: both 'paths' and 'path' given")
                rest["path"] = paths[0]
            tool_input = rest
        out["tool_input"] = tool_input
        return out


ADAPTER = MuseCodeAdapter(
    name="muse_code",
    tool_map={
        # Seen live (1.4.14, Windows).
        "powershell": "PowerShell",
        "read_file": "Read",
        "edit_file": "Edit",
        "search": "Grep",
        # Not seen live: `exec_command`/`shell` exist in the binary (third-party report);
        # the rest are guesses.
        "exec_command": "Bash",
        "shell": "Bash",
        "write_file": "Write",
        "search_files": "Grep",
        "glob_files": "Glob",
        "fetch_url": "WebFetch",
    },
    input_map={
        "Bash": {"cmd": "command"},
        "Write": {"path": "file_path"},
        "Edit": {
            "path": "file_path",
            "find": "old_string",
            "replace": "new_string",
            "old_str": "old_string",
            "new_str": "new_string",
        },
        "Read": {"path": "file_path"},
        "Grep": {"query": "pattern"},
        "Glob": {"query": "pattern"},
    },
    field_aliases={"turn_id": "prompt_id"},
    # Skill-reminder bookkeeping: most of Muse's tool calls in the capture, no side effects.
    internal_tools=frozenset({"submit_reminder_decision"}),
    # Whole directories, not single files: a plugin manifest points at scripts next to it, and
    # replacing one of those switches AgentWarden off as surely as editing the manifest.
    config_paths=(
        # Project hooks file (`.muse/hooks.json`, honoured in a trusted folder; seen live).
        (".muse",),
        # Plugin manifest and the hook scripts it registers.
        (".muse-plugin",),
        # User-level settings and trust decisions (`~/.config/muse/` on Windows too, seen live).
        (".config", "muse"),
    ),
)
