"""Shared constants for the two Copilot adapters (spec 029).

Leading underscore: `agents.discover()` skips modules named `_*`, so this helper is never
registered as an adapter on its own -- only `copilot_vscode.py` and `copilot_cli.py` are.
"""

from __future__ import annotations

# Self-protection targets shared by both surfaces (spec 027 `config_paths`): wherever VS Code or
# Copilot CLI load or can disable hooks from. See `integrations/copilot/README.md` for the
# confidence of each path.
SHARED_CONFIG_PATHS: tuple[tuple[str, ...], ...] = (
    (".github", "hooks"),  # repo-level hook config, both surfaces (verified: docs.github.com)
    (".github", "copilot", "settings.json"),  # inline repo hooks (verified)
    (".github", "copilot", "settings.local.json"),  # inline repo hooks, local override (verified)
)
