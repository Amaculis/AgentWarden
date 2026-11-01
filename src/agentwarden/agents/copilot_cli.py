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

from agentwarden.agents import Adapter
from agentwarden.agents._copilot_common import SHARED_CONFIG_PATHS

# `$COPILOT_HOME` is an env var and cannot be expressed as a fixed path component; the default
# `~/.copilot/...` location is covered below. Documented gap: a custom `COPILOT_HOME` elsewhere
# on disk is not caught by this path-component check. See the README.
_CONFIG_PATHS = SHARED_CONFIG_PATHS + (
    (".copilot", "hooks"),
    (".copilot", "settings.json"),
    (".copilot", "settings.local.json"),
)

ADAPTER = Adapter(
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
        "toolName": "tool_name",
        "toolArgs": "tool_input",
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
