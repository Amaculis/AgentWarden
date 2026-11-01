"""Claude Code: payloads are already canonical (spec 027).

`.claude/settings*.json` keeps its own dedicated rule in rules.py, so no `config_paths` here.
"""

from agentwarden.agents import Adapter

ADAPTER = Adapter(name="claude_code", tool_map={}, input_map={}, config_paths=(), passthrough=True)
