"""OpenAI Codex (CLI + IDE extension) adapter (spec 030).

UNVERIFIED against a live Codex: no Codex install was available to the team. Everything here is
derived from OpenAI's published docs and the `openai/codex` GitHub repository (issues, PRs and
source), recorded with sources in `integrations/codex/README.md`. Treat every detail below as a
best-effort reading of those sources, not a confirmed fact.

What the research found (see the README for exact sources and dates):

- Codex's `PreToolUse` hook can block a tool call before it runs, via
  `hookSpecificOutput.permissionDecision` in {"allow", "deny"} (`openai/codex` hooks docs, PR
  #17563). The documented shell tool name is `Bash` with `tool_input.command`; Codex's own
  `shell`/`exec_command`/`unified_exec` surfaces are also plausible foreign names for the same
  tool depending on version (community sources, not the primary docs), so all are mapped here.
- `tool_input.command` can be a string *or* an argv list (`["bash", "-lc", "echo hi"]`); Codex's
  own code shell-quotes an argv list with the Rust equivalent of `shlex.join` before running it
  (`openai/codex` issue #20875, PR #17563 context). This adapter does the same so the canonical
  `command` string is what rules.py and the judge actually see.
- `apply_patch` carries a unified-diff envelope that can touch several files in one call
  (`***** Begin Patch` / multiple `Update File:` blocks). The 027 canonical event has one
  `file_path`-shaped target, so a multi-file patch cannot be mapped losslessly; `apply_patch` is
  therefore left unmapped here on purpose (see `integrations/codex/README.md` for the 027 change
  this would need). An unmapped tool always `ask`s before any model call (rules.py
  `_unknown_agent_tool_rule`), so a patch touching `.agentwarden/` or `.codex/` is never `allow`ed
  -- it is always at least `ask`, satisfying this spec's acceptance criterion without guessing at
  the patch's targets.
- Codex's `PreToolUse` hook currently treats an unsupported `permissionDecision` value (such as
  `"ask"`) as a *failed hook run* and **continues the tool call** -- i.e. an unsupported decision
  behaves like `allow` (`openai/codex` issue #28437, open). Codex has no working "stop and ask"
  state today. `hooks/formats/codex.py` therefore never emits `"ask"`; it maps the 027 fail-safe
  and every `ask` verdict to `"deny"` and says so loudly in the README.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from agentwarden.agents import Adapter, AdapterError, EventKind

# Every plausible foreign name for Codex's shell tool (UNVERIFIED which ones a given Codex
# version actually sends); all map to the canonical `Bash`.
_SHELL_TOOLS = ("Bash", "shell", "exec_command", "unified_exec")


# learn.chatgpt.com/docs/hooks: `apply_patch` fires PreToolUse with the patch envelope in
# `tool_input.command`. Its file headers name every path the patch touches.
_PATCH_FILE_RE = re.compile(r"^\*\*\* (Add|Update|Delete) File: (\S.*?)\s*$")
_PATCH_MARKERS = ("*** Begin Patch", "*** End Patch", "*** End of File")


def _patch_event(tool_input: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """`(canonical tool, tool_input)` for a patch touching exactly one file, else `None`.

    One canonical event carries one path (027), so a multi-file patch, a move, or any `***`
    line this parser does not recognise (a header Codex might accept in another spelling)
    stays an unmapped tool: rules `ask`, the formatter prints `deny`."""
    patch = tool_input.get("command")
    if not isinstance(patch, str):
        return None
    files: list[tuple[str, str]] = []
    for line in patch.splitlines():
        stripped = line.strip()
        if "***" not in stripped[:8]:
            continue
        if line.rstrip() in _PATCH_MARKERS:
            continue
        match = _PATCH_FILE_RE.match(line)
        if match is None:
            return None  # Move to:, odd spacing, unknown header: do not guess
        files.append((match.group(1), match.group(2)))
    if len(files) != 1:
        return None
    action, path = files[0]
    tool = "Edit" if action == "Update" else "Write"
    return tool, {"file_path": path, "patch": patch}


class CodexAdapter(Adapter):
    """Adds two things the declarative map cannot do: an argv-list `command` becomes the
    canonical string, and a single-file `apply_patch` becomes a Write/Edit of that file."""

    def normalize(self, kind: EventKind, body: dict[str, Any]) -> dict[str, Any]:
        if kind != "prompt" and body.get("tool_name") == "apply_patch":
            tool_input = body.get("tool_input")
            if not isinstance(tool_input, dict):
                raise AdapterError(f"{self.name}: tool_input is not an object")
            mapped = _patch_event(tool_input)
            if mapped is not None:
                tool, translated = mapped
                return {
                    **body,
                    "tool_name": tool,
                    "tool_input": translated,
                    "agent_tool_name": "apply_patch",
                }
        out = super().normalize(kind, body)
        tool_input = out.get("tool_input")
        if out.get("tool_name") == "Bash" and isinstance(tool_input, dict):
            command = tool_input.get("command")
            if isinstance(command, list):
                if not all(isinstance(part, str) for part in command):
                    raise AdapterError(f"{self.name}: command list has a non-string entry")
                out["tool_input"] = {**tool_input, "command": shlex.join(command)}
        return out


ADAPTER = CodexAdapter(
    name="codex",
    tool_map={name: "Bash" for name in _SHELL_TOOLS},
    # Documented shape is `command`; `cmd` is what unified exec's `exec_command` takes.
    input_map={"Bash": {"cmd": "command"}},
    # Whole `.codex` directory (config.toml, hooks.json, any other file in it), project-relative,
    # whichever agent is actually running (027 self-protection). No AGENTS.md-adjacent hook file
    # was found in the research; see the README.
    config_paths=((".codex",),),
)
