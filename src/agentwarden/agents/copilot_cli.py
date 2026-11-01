"""Copilot CLI (and cloud/coding agent) adapter (spec 029).

Unverified against a live Copilot -- built from docs only (sources and confidence levels in
`integrations/copilot/README.md`). Native Copilot CLI hooks fire camelCase events (`preToolUse`,
`postToolUse`, ...) with `toolName`/`toolArgs` fields, unlike VS Code's Claude-style alias (see
`copilot_vscode.py`). docs.github.com repeatedly gives `bash`, `edit`, `view` as example tool
names and `.github/hooks/*.json` (repo) / `~/.copilot/hooks/*.json` (user, `$COPILOT_HOME`
overridable) as config locations -- these are treated as verified. `create`, `grep`, `glob`,
`web_fetch` and the inner `tool_input` field names below (e.g. `path` for a file tool) are
GUESSED by analogy with other agent CLIs (Claude Code, Codex, Muse Code) -- not directly quoted
in any page we found. `ask_user` and `task` are left unmapped on purpose: their payload shape is
undocumented, so they `ask` rather than being guessed.

Known CLI bug (github/copilot-cli#2647, #4237, #3042): a `preToolUse` `ask` decision is not
surfaced to the agent as steering text and does not suppress the native trust prompt, so the user
sees two prompts and the agent never sees *why* AgentWarden asked. This is a CLI display bug, not
a reason to turn our `ask` into `deny` -- `ask` is still the correct fail-safe (029 explicitly
says not to change it without a spec); the gap is UX, not a dropped decision. See the README.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentwarden.agents import Adapter, EventKind
from agentwarden.agents._copilot_common import SHARED_CONFIG_PATHS

# `$COPILOT_HOME` is an env var and cannot be expressed as a fixed path component; the default
# `~/.copilot/` is covered whole (hooks, inline settings hooks, plugin-contributed hooks).
# Documented gaps: a custom `COPILOT_HOME`, and policy files under /etc/github-copilot/ (root-
# owned on POSIX). See the README.
_CONFIG_PATHS = SHARED_CONFIG_PATHS + ((".copilot",),)

# docs.github.com hooks-configuration reference: command hooks get `sessionId`, `timestamp`,
# `cwd`, `toolName`, `toolArgs` (an object) and, for postToolUse, `toolResult` -- and no event
# name at all. The hook script is wired to one event, so the daemon endpoint names it.
_EVENT_BY_KIND = {"tool": "PreToolUse", "read": "PostToolUse", "prompt": "UserPromptSubmit"}

# The same `.github/hooks/*.json` is read by VS Code too, whose payload uses Claude-style names:
# accept them as-is so one config file works for both surfaces.
_CLAUDE_STYLE = ("Bash", "PowerShell", "Read", "Write", "Edit", "MultiEdit", "Grep", "Glob")


@dataclass(frozen=True)
class CopilotCliAdapter(Adapter):
    def normalize(self, kind: EventKind, body: dict[str, Any]) -> dict[str, Any]:
        out = super().normalize(kind, body)
        out.setdefault("hook_event_name", _EVENT_BY_KIND[kind])
        return out


ADAPTER = CopilotCliAdapter(
    name="copilot_cli",
    tool_map={
        "bash": "Bash",
        "powershell": "PowerShell",
        "view": "Read",
        "create": "Write",
        "edit": "Edit",
        "grep": "Grep",
        "glob": "Glob",
        "web_fetch": "WebFetch",
        **{t: t for t in _CLAUDE_STYLE},
        "WebFetch": "WebFetch",
    },
    input_map={
        "Read": {"path": "file_path"},
        "Write": {"path": "file_path"},
        "Edit": {"path": "file_path"},
        "Grep": {"path": "path"},
        "Glob": {"path": "path"},
    },
    config_paths=_CONFIG_PATHS,
    field_aliases={
        "sessionId": "session_id",
        "toolName": "tool_name",
        "toolArgs": "tool_input",
        "toolResult": "tool_response",
        "hookEventName": "hook_event_name",
    },
    event_names={
        "preToolUse": "PreToolUse",
        "postToolUse": "PostToolUse",
        "userPromptSubmitted": "UserPromptSubmit",
        "sessionStart": "SessionStart",
        "sessionEnd": "Stop",
    },
)
