"""VS Code Copilot agent-mode adapter (spec 029).

Unverified against a live Copilot -- built from docs only (sources and confidence levels in
`integrations/copilot/README.md`). code.visualstudio.com/docs/copilot/customization/hooks
describes a `PreToolUse` alias event that already carries snake_case fields (`tool_name`,
`tool_input`) and Claude-style tool names (`Read`, `Write`, `Edit`, ...), unlike Copilot CLI's
native camelCase event (see `copilot_cli.py`). No event-name or field aliasing is needed here.

The tool map below is a (near-)identity map on purpose: it is what lets a tool that really is
`Bash`/`Read`/... hit the same rules as Claude Code, while anything we did not list --
including a native lower-case name that leaks through under this alias -- falls through to
`_unknown_agent_tool_rule` and `ask`s instead of being guessed.
"""

from __future__ import annotations

from agentwarden.agents import Adapter
from agentwarden.agents._copilot_common import SHARED_CONFIG_PATHS

# Not `.vscode/settings.json`: no doc names a hooks key there, and config paths are protected for
# every agent, so it would hard-deny ordinary VS Code settings edits for Claude Code users too.
_CONFIG_PATHS = SHARED_CONFIG_PATHS

_TOOLS = ("Bash", "PowerShell", "Read", "Write", "Edit", "MultiEdit", "Grep", "Glob", "WebFetch")

ADAPTER = Adapter(
    name="copilot_vscode",
    tool_map={t: t for t in _TOOLS},
    input_map={},
    config_paths=_CONFIG_PATHS,
)
